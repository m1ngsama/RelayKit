use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use relaykit_platform::{current_platform, PlatformProfile};
use relaykit_protocol::{
    decode_wire, encode_wire, SessionCode, StreamId, TunnelOffer, WireMessage, PROTOCOL_VERSION,
};
use relaykit_tunnel::{
    connect_relay_websocket, RelayFingerprint, TunnelEndpoint, TunnelKind, TunnelSpec,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    time::timeout,
};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};
use url::{Host, Url};

const AGENT_CHANNEL_CAPACITY: usize = 256;
const PREFLIGHT_TIMEOUT: Duration = Duration::from_millis(800);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub server: String,
    pub session: SessionCode,
    pub relay_fingerprint: Option<RelayFingerprint>,
    pub device: Option<String>,
    pub exposes: Vec<ExposeRequest>,
    pub foreground: bool,
    pub preflight: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposeRequest {
    pub name: String,
    pub target: TunnelEndpoint,
}

impl FromStr for ExposeRequest {
    type Err = AgentError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, target) = value
            .split_once('=')
            .ok_or_else(|| AgentError::InvalidExpose(value.to_owned()))?;
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| AgentError::InvalidExpose(value.to_owned()))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| AgentError::InvalidExpose(value.to_owned()))?;

        if name.is_empty() || host.is_empty() {
            return Err(AgentError::InvalidExpose(value.to_owned()));
        }

        Ok(Self {
            name: name.to_owned(),
            target: TunnelEndpoint {
                host: host.to_owned(),
                port,
            },
        })
    }
}

impl From<ExposeRequest> for TunnelSpec {
    fn from(request: ExposeRequest) -> Self {
        let kind = match request.name.as_str() {
            "ssh" => TunnelKind::Ssh,
            "rdp" => TunnelKind::Rdp,
            _ => TunnelKind::Tcp,
        };

        Self {
            name: request.name,
            kind,
            target: request.target,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPlan {
    pub server: String,
    pub session: String,
    pub relay_fingerprint: Option<RelayFingerprint>,
    pub device: Option<String>,
    pub foreground: bool,
    pub preflight: bool,
    pub platform: PlatformProfile,
    pub exposes: Vec<TunnelSpec>,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPreflight {
    pub name: String,
    pub target: TunnelEndpoint,
    pub reachable: bool,
    pub error: Option<String>,
}

pub fn plan_join(request: JoinRequest) -> AgentPlan {
    let exposes = if request.exposes.is_empty() {
        default_exposes()
    } else {
        request.exposes.into_iter().map(Into::into).collect()
    };

    AgentPlan {
        server: request.server,
        session: request.session.to_string(),
        relay_fingerprint: request.relay_fingerprint,
        device: request.device,
        foreground: request.foreground,
        preflight: request.preflight,
        platform: current_platform(),
        exposes,
        status: "ready",
    }
}

pub async fn run_join(request: JoinRequest) -> Result<()> {
    let plan = plan_join(request);
    if plan.foreground {
        print_foreground_session_status(&plan);
    }
    let exposes = plan
        .exposes
        .iter()
        .map(TunnelOffer::from)
        .collect::<Vec<_>>();
    let expose_map = plan
        .exposes
        .iter()
        .map(|spec| (spec.name.clone(), spec.target.clone()))
        .collect::<HashMap<_, _>>();

    if plan.preflight {
        log_preflight_results(preflight_exposes(&plan.exposes).await);
    }

    let url = agent_ws_url(&plan.server)?;

    let (ws, _) = connect_relay_websocket(url.as_str(), plan.relay_fingerprint.as_ref())
        .await
        .with_context(|| format!("failed to connect agent websocket {url}"))?;
    let (mut ws_writer, mut ws_reader) = ws.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<WireMessage>(AGENT_CHANNEL_CAPACITY);
    let streams: Arc<Mutex<HashMap<StreamId, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    outbound_tx
        .send(WireMessage::AgentHello {
            protocol: PROTOCOL_VERSION.to_owned(),
            code: SessionCode::new(plan.session.clone())?,
            device: plan.device.clone(),
            exposes,
        })
        .await?;

    let send_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            ws_writer
                .send(Message::Binary(encode_wire(&message)?))
                .await?;
        }

        Ok::<(), anyhow::Error>(())
    });

    info!(
        server = %plan.server,
        session = %plan.session,
        "relaykit agent joined session"
    );

    let loop_result = async {
        while let Some(frame) = ws_reader.next().await {
            let frame = frame?;
            let Message::Binary(bytes) = frame else {
                continue;
            };

            match decode_wire(&bytes)? {
                WireMessage::AgentReady { session } => {
                    info!(%session, "relay accepted agent");
                }
                WireMessage::OpenStream { stream_id, target } => {
                    let Some(endpoint) = expose_map.get(&target).cloned() else {
                        outbound_tx
                            .send(WireMessage::StreamError {
                                stream_id,
                                message: format!("target `{target}` is not exposed by this agent"),
                            })
                            .await?;
                        continue;
                    };

                    if let Err(err) = open_local_stream(
                        stream_id,
                        target,
                        endpoint,
                        outbound_tx.clone(),
                        Arc::clone(&streams),
                    )
                    .await
                    {
                        outbound_tx
                            .send(WireMessage::StreamError {
                                stream_id,
                                message: err.to_string(),
                            })
                            .await?;
                    }
                }
                WireMessage::StreamData { stream_id, bytes } => {
                    let stream = streams
                        .lock()
                        .map_err(|_| anyhow!("agent stream map poisoned"))?
                        .get(&stream_id)
                        .cloned();
                    if let Some(stream) = stream {
                        stream.send(bytes).await?;
                    }
                }
                WireMessage::StreamClose { stream_id }
                | WireMessage::StreamError { stream_id, .. } => {
                    streams
                        .lock()
                        .map_err(|_| anyhow!("agent stream map poisoned"))?
                        .remove(&stream_id);
                }
                WireMessage::Error { message } => return Err(anyhow!(message)),
                WireMessage::AgentHello { .. } => {}
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Ok(mut streams) = streams.lock() {
        streams.clear();
    }
    send_task.abort();
    loop_result
}

async fn open_local_stream(
    stream_id: StreamId,
    target_name: String,
    endpoint: TunnelEndpoint,
    outbound_tx: mpsc::Sender<WireMessage>,
    streams: Arc<Mutex<HashMap<StreamId, mpsc::Sender<Vec<u8>>>>>,
) -> Result<()> {
    let address = format!("{}:{}", endpoint.host, endpoint.port);
    let socket = TcpStream::connect(&address)
        .await
        .with_context(|| format!("failed to connect local target {target_name} at {address}"))?;
    let (mut reader, mut writer) = socket.into_split();
    let (to_tcp_tx, mut to_tcp_rx) = mpsc::channel::<Vec<u8>>(AGENT_CHANNEL_CAPACITY);
    streams
        .lock()
        .map_err(|_| anyhow!("agent stream map poisoned"))?
        .insert(stream_id, to_tcp_tx);

    debug!(%stream_id, target = %target_name, %address, "opened local target stream");

    let _write_task = tokio::spawn(async move {
        while let Some(bytes) = to_tcp_rx.recv().await {
            writer.write_all(&bytes).await?;
        }
        writer.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    });

    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let read = match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => read,
                Err(err) => {
                    let _ = outbound_tx
                        .send(WireMessage::StreamError {
                            stream_id,
                            message: err.to_string(),
                        })
                        .await;
                    break;
                }
            };

            if outbound_tx
                .send(WireMessage::StreamData {
                    stream_id,
                    bytes: buffer[..read].to_vec(),
                })
                .await
                .is_err()
            {
                break;
            }
        }

        let _ = outbound_tx
            .send(WireMessage::StreamClose { stream_id })
            .await;
    });
    Ok(())
}

async fn preflight_exposes(exposes: &[TunnelSpec]) -> Vec<TargetPreflight> {
    let mut results = Vec::with_capacity(exposes.len());
    for expose in exposes {
        results.push(preflight_target(expose).await);
    }
    results
}

async fn preflight_target(expose: &TunnelSpec) -> TargetPreflight {
    let address = target_address(&expose.target);
    match timeout(PREFLIGHT_TIMEOUT, TcpStream::connect(&address)).await {
        Ok(Ok(_stream)) => TargetPreflight {
            name: expose.name.clone(),
            target: expose.target.clone(),
            reachable: true,
            error: None,
        },
        Ok(Err(err)) => TargetPreflight {
            name: expose.name.clone(),
            target: expose.target.clone(),
            reachable: false,
            error: Some(err.to_string()),
        },
        Err(_) => TargetPreflight {
            name: expose.name.clone(),
            target: expose.target.clone(),
            reachable: false,
            error: Some(format!("timeout after {}ms", PREFLIGHT_TIMEOUT.as_millis())),
        },
    }
}

fn log_preflight_results(results: Vec<TargetPreflight>) {
    for result in results {
        let address = target_address(&result.target);
        if result.reachable {
            info!(
                target = %result.name,
                %address,
                "local target preflight ok"
            );
        } else {
            warn!(
                target = %result.name,
                %address,
                error = %result.error.as_deref().unwrap_or("unknown error"),
                "local target preflight failed"
            );
        }
    }
}

fn print_foreground_session_status(plan: &AgentPlan) {
    println!("relaykit: starting visible assisted session");
    println!("relaykit: relay {}", plan.server);
    println!("relaykit: session {}", plan.session);
    if let Some(device) = &plan.device {
        println!("relaykit: label {device}");
    }
    for expose in &plan.exposes {
        println!(
            "relaykit: exposing {}={}:{}",
            expose.name, expose.target.host, expose.target.port
        );
    }
    println!("relaykit: leave this terminal open during support");
    println!("relaykit: press Ctrl+C or close this terminal to stop assistance");
}

fn target_address(target: &TunnelEndpoint) -> String {
    format!("{}:{}", target.host, target.port)
}

fn agent_ws_url(server: &str) -> Result<Url> {
    let mut url = Url::parse(server).with_context(|| format!("invalid relay URL {server}"))?;
    validate_relay_transport(&url)?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        "ws" => "ws",
        "wss" => "wss",
        other => return Err(anyhow!("unsupported relay URL scheme: {other}")),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow!("failed to set websocket URL scheme"))?;
    url.set_path("/ws/agent");
    url.set_query(None);
    Ok(url)
}

fn validate_relay_transport(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" | "wss" => Ok(()),
        "http" | "ws" if url_uses_loopback_host(url) => Ok(()),
        "http" | "ws" => Err(anyhow!(
            "non-local relay URLs must use https or wss; use http/ws only for loopback development"
        )),
        other => Err(anyhow!("unsupported relay URL scheme: {other}")),
    }
}

fn url_uses_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn default_exposes() -> Vec<TunnelSpec> {
    let mut exposes = vec![TunnelSpec::ssh()];
    if cfg!(windows) {
        exposes.push(TunnelSpec::rdp());
    }
    exposes
}

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("invalid expose value `{0}`; expected name=host:port, for example ssh=127.0.0.1:22")]
    InvalidExpose(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_expose_request() {
        let expose = ExposeRequest::from_str("ssh=127.0.0.1:22").unwrap();
        assert_eq!(expose.name, "ssh");
        assert_eq!(expose.target.host, "127.0.0.1");
        assert_eq!(expose.target.port, 22);
    }

    #[test]
    fn plan_join_preserves_preflight_setting() {
        let plan = plan_join(JoinRequest {
            server: "http://127.0.0.1:18080".to_owned(),
            session: SessionCode::new("RK-ABCD").unwrap(),
            relay_fingerprint: None,
            device: Some("local".to_owned()),
            exposes: vec![ExposeRequest::from_str("web=127.0.0.1:19090").unwrap()],
            foreground: true,
            preflight: false,
        });

        assert!(!plan.preflight);
        assert_eq!(plan.exposes.len(), 1);
        assert_eq!(plan.exposes[0].name, "web");
    }

    #[test]
    fn foreground_status_includes_session_and_exposed_targets() {
        let plan = plan_join(JoinRequest {
            server: "http://127.0.0.1:18080".to_owned(),
            session: SessionCode::new("RK-ABCD").unwrap(),
            relay_fingerprint: None,
            device: Some("ticket-1234".to_owned()),
            exposes: vec![ExposeRequest::from_str("ssh=127.0.0.1:22").unwrap()],
            foreground: true,
            preflight: true,
        });

        assert!(plan.foreground);
        assert_eq!(plan.session, "RK-ABCD");
        assert_eq!(plan.device.as_deref(), Some("ticket-1234"));
        assert_eq!(plan.exposes[0].name, "ssh");
    }

    #[test]
    fn target_address_formats_host_port() {
        let target = TunnelEndpoint {
            host: "127.0.0.1".to_owned(),
            port: 22,
        };

        assert_eq!(target_address(&target), "127.0.0.1:22");
    }

    #[test]
    fn agent_ws_url_requires_tls_for_non_local_relays() {
        let local = agent_ws_url("http://127.0.0.1:18080").expect("loopback http is allowed");
        assert_eq!(local.as_str(), "ws://127.0.0.1:18080/ws/agent");

        let local = agent_ws_url("ws://localhost:18080").expect("loopback ws is allowed");
        assert_eq!(local.as_str(), "ws://localhost:18080/ws/agent");

        let remote =
            agent_ws_url("https://relay.example.com/base").expect("remote https is allowed");
        assert_eq!(remote.as_str(), "wss://relay.example.com/ws/agent");

        let err = agent_ws_url("http://relay.example.com")
            .expect_err("remote plaintext relay URL should fail");
        assert!(
            err.to_string().contains("non-local relay URLs must use"),
            "{err}"
        );
    }
}
