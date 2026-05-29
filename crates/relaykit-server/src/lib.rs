use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State,
    },
    http::{header, HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use relaykit_protocol::{
    decode_wire, encode_wire, Capability, SessionCode, SessionId, StreamId, TunnelOffer,
    WireMessage, PROTOCOL_VERSION,
};
use relaykit_tunnel::{RelayFingerprint, TunnelSpec};
use rustls::{
    crypto::ring as rustls_ring,
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig as RustlsServerConfig,
};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tower::{Layer, ServiceExt};
use tracing::{debug, info, warn};
use url::{Host, Url};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub public_url: Option<String>,
    pub operator_token: Option<String>,
    pub insecure_no_operator_auth: bool,
    pub artifact_dir: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPlan {
    pub listen: String,
    pub public_url: Option<String>,
    pub operator_auth_enabled: bool,
    pub insecure_no_operator_auth: bool,
    pub artifact_server_enabled: bool,
    pub tls_enabled: bool,
    pub protocol: &'static str,
    pub status: &'static str,
}

pub fn plan_server(config: ServerConfig) -> ServerPlan {
    let operator_auth_enabled = operator_token_present(config.operator_token.as_deref());
    let tls_enabled = server_tls_enabled(&config);
    let config_valid = validate_server_config(&config).is_ok();
    ServerPlan {
        listen: config.listen,
        public_url: config.public_url,
        operator_auth_enabled,
        insecure_no_operator_auth: config.insecure_no_operator_auth,
        artifact_server_enabled: config.artifact_dir.is_some(),
        tls_enabled,
        protocol: PROTOCOL_VERSION,
        status: if config_valid { "ready" } else { "blocked" },
    }
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    validate_server_config(&config)?;
    let listen_addr = config
        .listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid listen address {}", config.listen))?;
    let public_url = effective_public_url(&config);
    let state = AppState {
        inner: Arc::new(RelayState {
            public_url,
            operator_token: config.operator_token.clone(),
            artifact_dir: config.artifact_dir.clone(),
            sessions: Mutex::new(HashMap::new()),
            next_stream: AtomicU64::new(1),
        }),
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/api/sessions", post(create_session).get(list_sessions))
        .route("/api/sessions/:session", delete(end_session))
        .route("/join/:code", get(join_script))
        .route("/artifacts/:file", get(artifact_file))
        .route("/ws/agent", get(agent_ws))
        .route("/ws/operator", get(operator_ws))
        .with_state(state);

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind relay server on {listen_addr}"))?;
    if let Some((cert_path, key_path)) = server_tls_paths(&config)? {
        let tls_config = load_tls_config(cert_path, key_path)?;
        info!(listen = %listen_addr, "relaykitd listening with tls");
        serve_tls(listener, app, tls_config).await?;
    } else {
        info!(listen = %listen_addr, "relaykitd listening");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

fn validate_server_config(config: &ServerConfig) -> Result<()> {
    let operator_auth_enabled = operator_token_present(config.operator_token.as_deref());
    if config
        .operator_token
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(anyhow!("RELAYKIT_OPERATOR_TOKEN must not be empty"));
    }
    if operator_auth_enabled && config.insecure_no_operator_auth {
        return Err(anyhow!(
            "cannot combine operator token authentication with --insecure-no-operator-auth"
        ));
    }
    if !operator_auth_enabled && !config.insecure_no_operator_auth {
        return Err(anyhow!(
            "missing operator token; set RELAYKIT_OPERATOR_TOKEN or pass --operator-token, or use --insecure-no-operator-auth for local development only"
        ));
    }
    if config.insecure_no_operator_auth {
        validate_insecure_dev_scope(config)?;
    }
    server_tls_paths(config)?;
    validate_public_transport(config)?;
    Ok(())
}

fn operator_token_present(token: Option<&str>) -> bool {
    token.is_some_and(|value| !value.trim().is_empty())
}

fn validate_insecure_dev_scope(config: &ServerConfig) -> Result<()> {
    let listen_addr = config
        .listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid listen address {}", config.listen))?;
    if !listen_addr.ip().is_loopback() {
        return Err(anyhow!(
            "--insecure-no-operator-auth requires a loopback --listen address"
        ));
    }

    if let Some(public_url) = &config.public_url {
        let url =
            Url::parse(public_url).with_context(|| format!("invalid public URL {public_url}"))?;
        if !url_uses_loopback_host(&url) {
            return Err(anyhow!(
                "--insecure-no-operator-auth requires a loopback --public-url"
            ));
        }
    }

    Ok(())
}

fn url_uses_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        None => false,
    }
}

fn validate_public_transport(config: &ServerConfig) -> Result<()> {
    let public_url = effective_public_url(config);
    let url =
        Url::parse(&public_url).with_context(|| format!("invalid public URL {public_url}"))?;
    if server_tls_enabled(config) && url.scheme() != "https" {
        return Err(anyhow!(
            "relay TLS is enabled, so the relay public URL must use https"
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if url_uses_loopback_host(&url) => Ok(()),
        "http" => Err(anyhow!(
            "non-local relay public URLs must use https; use http only for loopback development"
        )),
        other => Err(anyhow!("unsupported relay public URL scheme: {other}")),
    }
}

fn server_tls_enabled(config: &ServerConfig) -> bool {
    config.tls_cert.is_some() || config.tls_key.is_some()
}

fn server_tls_paths(config: &ServerConfig) -> Result<Option<(&FsPath, &FsPath)>> {
    match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Ok(Some((cert.as_path(), key.as_path()))),
        (Some(_), None) => Err(anyhow!("--tls-cert requires --tls-key")),
        (None, Some(_)) => Err(anyhow!("--tls-key requires --tls-cert")),
        (None, None) => Ok(None),
    }
}

fn effective_public_url(config: &ServerConfig) -> String {
    config.public_url.clone().unwrap_or_else(|| {
        let scheme = if server_tls_enabled(config) {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}", config.listen)
    })
}

fn load_tls_config(cert_path: &FsPath, key_path: &FsPath) -> Result<RustlsServerConfig> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("failed to read TLS certificate {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read TLS private key {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> = pem_blocks(&cert_pem, "CERTIFICATE")?
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if certs.is_empty() {
        return Err(anyhow!(
            "TLS certificate file contains no CERTIFICATE blocks: {}",
            cert_path.display()
        ));
    }

    let key_der = first_pem_block(
        &key_pem,
        &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
    )?;
    let key: PrivateKeyDer<'static> = PrivateKeyDer::try_from(key_der)
        .map_err(|err| anyhow!("unsupported TLS private key format: {err}"))?;

    let provider = Arc::new(rustls_ring::default_provider());
    let mut config = RustlsServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .context("failed to configure relay TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| {
            format!(
                "failed to configure relay TLS certificate {}",
                cert_path.display()
            )
        })?;
    config.alpn_protocols.push(b"http/1.1".to_vec());
    Ok(config)
}

fn pem_blocks(input: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut rest = input;
    let mut blocks = Vec::new();

    while let Some(begin_index) = rest.find(&begin) {
        let after_begin = &rest[begin_index + begin.len()..];
        let end_index = after_begin
            .find(&end)
            .ok_or_else(|| anyhow!("unterminated PEM block: {label}"))?;
        let body = &after_begin[..end_index];
        let encoded: String = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.contains(':'))
            .collect();
        let der = BASE64_STANDARD
            .decode(encoded.as_bytes())
            .with_context(|| format!("invalid PEM base64 for {label}"))?;
        blocks.push(der);
        rest = &after_begin[end_index + end.len()..];
    }

    Ok(blocks)
}

fn first_pem_block(input: &str, labels: &[&str]) -> Result<Vec<u8>> {
    for label in labels {
        if let Some(block) = pem_blocks(input, label)?.into_iter().next() {
            return Ok(block);
        }
    }
    Err(anyhow!(
        "TLS private key file contains no supported private key block"
    ))
}

async fn serve_tls(
    listener: TcpListener,
    app: Router,
    tls_config: RustlsServerConfig,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                if !is_connection_error(&err) {
                    warn!(error = %err, "relay TLS accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
        };

        if let Err(err) = tcp_stream.set_nodelay(true) {
            debug!(remote = %remote_addr, error = %err, "failed to set TCP_NODELAY");
        }

        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_tls_connection(acceptor, app, tcp_stream, remote_addr).await {
                debug!(remote = %remote_addr, error = %err, "relay TLS connection closed");
            }
        });
    }
}

async fn serve_tls_connection(
    acceptor: TlsAcceptor,
    app: Router,
    tcp_stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<()> {
    let tls_stream = acceptor
        .accept(tcp_stream)
        .await
        .with_context(|| format!("TLS handshake failed for {remote_addr}"))?;
    let service = Extension(ConnectInfo(remote_addr))
        .layer(app)
        .map_request(|request: Request<Incoming>| request.map(Body::new));
    let hyper_service = TowerToHyperService::new(service);
    let builder = HyperBuilder::new(TokioExecutor::new());
    builder
        .serve_connection_with_upgrades(TokioIo::new(tls_stream), hyper_service)
        .await
        .map_err(|err| anyhow!("failed to serve TLS relay connection: {err}"))?;
    Ok(())
}

fn is_connection_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCreateRequest {
    pub server: String,
    pub device: Option<String>,
    pub capabilities: Vec<Capability>,
    pub allowed_tunnels: Vec<TunnelSpec>,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPlan {
    pub server: String,
    pub device: Option<String>,
    pub capabilities: Vec<Capability>,
    pub allowed_tunnels: Vec<TunnelSpec>,
    pub ttl_seconds: u64,
    pub status: &'static str,
}

pub fn plan_session(request: SessionCreateRequest) -> SessionPlan {
    SessionPlan {
        server: request.server,
        device: request.device,
        capabilities: request.capabilities,
        allowed_tunnels: request.allowed_tunnels,
        ttl_seconds: request.ttl_seconds,
        status: "ready",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub device: Option<String>,
    pub capabilities: Vec<Capability>,
    pub allowed_tunnels: Vec<TunnelSpec>,
    pub ttl_seconds: u64,
    #[serde(default)]
    pub relay_fingerprint: Option<RelayFingerprint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session: SessionId,
    pub code: SessionCode,
    #[serde(default)]
    pub relay_fingerprint: Option<RelayFingerprint>,
    pub device: Option<String>,
    pub capabilities: Vec<Capability>,
    pub allowed_tunnels: Vec<TunnelSpec>,
    pub ttl_seconds: u64,
    pub join_command: String,
    pub agent_command: String,
    pub install_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session: SessionId,
    pub device: Option<String>,
    pub agent_remote_addr: Option<String>,
    pub capabilities: Vec<Capability>,
    pub allowed_tunnels: Vec<TunnelSpec>,
    pub ttl_seconds: u64,
    pub expires_in_seconds: u64,
    pub agent_connected: bool,
    pub active_streams: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReference {
    pub server: String,
    pub session: Option<SessionId>,
    pub status: &'static str,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<RelayState>,
}

struct RelayState {
    public_url: String,
    operator_token: Option<String>,
    artifact_dir: Option<PathBuf>,
    sessions: Mutex<HashMap<String, SessionState>>,
    next_stream: AtomicU64,
}

struct SessionState {
    session: SessionId,
    code: SessionCode,
    relay_fingerprint: Option<RelayFingerprint>,
    device: Option<String>,
    capabilities: Vec<Capability>,
    allowed_tunnels: Vec<TunnelSpec>,
    ttl_seconds: u64,
    expires_at: Instant,
    code_consumed: bool,
    agent: Option<PeerSender>,
    agent_remote_addr: Option<String>,
    streams: HashMap<StreamId, PeerSender>,
}

#[derive(Clone)]
struct PeerSender {
    tx: mpsc::Sender<WireMessage>,
}

struct JoinSessionDetails {
    code: SessionCode,
    relay_fingerprint: Option<RelayFingerprint>,
    device: Option<String>,
    allowed_tunnels: Vec<TunnelSpec>,
}

const RELAY_CHANNEL_CAPACITY: usize = 256;

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, ApiError> {
    authorize_operator(&state, &headers)?;

    let session = SessionId::new(format!("rk-{}", Uuid::new_v4().simple()))?;
    let code = SessionCode::new(format!(
        "RK-{}",
        &Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase()
    ))?;
    let ttl_seconds = request.ttl_seconds.max(60);
    validate_allowed_tunnels(&request.allowed_tunnels)?;
    let allowed_tunnels = request.allowed_tunnels;
    let relay_fingerprint = request.relay_fingerprint.clone();
    let capabilities = if request.capabilities.is_empty() {
        vec![Capability::Ssh, Capability::Tcp]
    } else {
        request.capabilities
    };

    let agent_command = agent_command(
        &state.inner.public_url,
        &code,
        request.device.as_deref(),
        &allowed_tunnels,
        relay_fingerprint.as_ref(),
    );
    let install_command = state
        .inner
        .artifact_dir
        .as_ref()
        .filter(|_| relay_fingerprint.is_none())
        .map(|_| install_command(&state.inner.public_url, &code));
    let response = CreateSessionResponse {
        session: session.clone(),
        code: code.clone(),
        relay_fingerprint: relay_fingerprint.clone(),
        device: request.device.clone(),
        capabilities: capabilities.clone(),
        allowed_tunnels: allowed_tunnels.clone(),
        ttl_seconds,
        join_command: install_command
            .clone()
            .unwrap_or_else(|| agent_command.clone()),
        agent_command,
        install_command,
    };

    let session_state = SessionState {
        session: session.clone(),
        code,
        relay_fingerprint,
        device: request.device,
        capabilities,
        allowed_tunnels,
        ttl_seconds,
        expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
        code_consumed: false,
        agent: None,
        agent_remote_addr: None,
        streams: HashMap::new(),
    };

    state
        .inner
        .sessions
        .lock()
        .map_err(|_| ApiError::internal("session store poisoned"))?
        .insert(session.as_str().to_owned(), session_state);

    audit_session_created(&state, &session, &response);

    Ok(Json(response))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionSummary>>, ApiError> {
    authorize_operator(&state, &headers)?;

    let now = Instant::now();
    let sessions = state
        .inner
        .sessions
        .lock()
        .map_err(|_| ApiError::internal("session store poisoned"))?
        .values()
        .map(|session| session_summary(session, now))
        .collect();
    Ok(Json(sessions))
}

fn session_summary(session: &SessionState, now: Instant) -> SessionSummary {
    SessionSummary {
        session: session.session.clone(),
        device: session.device.clone(),
        agent_remote_addr: session.agent_remote_addr.clone(),
        capabilities: session.capabilities.clone(),
        allowed_tunnels: session.allowed_tunnels.clone(),
        ttl_seconds: session.ttl_seconds,
        expires_in_seconds: session
            .expires_at
            .checked_duration_since(now)
            .unwrap_or_default()
            .as_secs(),
        agent_connected: session.agent.is_some(),
        active_streams: session.streams.len(),
    }
}

async fn end_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session): Path<String>,
) -> Result<StatusCode, ApiError> {
    authorize_operator(&state, &headers)?;

    let removed = state
        .inner
        .sessions
        .lock()
        .map_err(|_| ApiError::internal("session store poisoned"))?
        .remove(&session);

    if let Some(session) = removed {
        audit_session_ended(&state, &session, "operator");
        notify_session_closed(session, "session ended by operator");
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("session not found"))
    }
}

async fn join_script(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<axum::response::Response, ApiError> {
    if state.inner.artifact_dir.is_none() {
        return Err(ApiError::not_found("agent artifact server is disabled"));
    }

    if code.ends_with(".ps1") {
        let details = join_session_details(&state, &code, ".ps1")?;
        let script = powershell_join_script(
            &state.inner.public_url,
            &details.code,
            details.device.as_deref(),
            &details.allowed_tunnels,
            details.relay_fingerprint.as_ref(),
        );
        return Ok((
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            script,
        )
            .into_response());
    }

    let details = join_session_details(&state, &code, ".sh")?;
    let script = linux_join_script(
        &state.inner.public_url,
        &details.code,
        details.device.as_deref(),
        &details.allowed_tunnels,
        details.relay_fingerprint.as_ref(),
    );
    Ok((
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        script,
    )
        .into_response())
}

fn join_session_details(
    state: &AppState,
    raw_code: &str,
    suffix: &str,
) -> Result<JoinSessionDetails, ApiError> {
    let code = raw_code.strip_suffix(suffix).unwrap_or(raw_code);
    let code = SessionCode::new(code)?;
    let (relay_fingerprint, device, allowed_tunnels) = {
        let sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| ApiError::internal("session store poisoned"))?;
        let session = sessions
            .values()
            .find(|session| session.code == code)
            .ok_or_else(|| ApiError::not_found("session code not found"))?;
        if session.expires_at <= Instant::now() {
            return Err(ApiError::not_found("session has expired"));
        }
        (
            session.relay_fingerprint.clone(),
            session.device.clone(),
            session.allowed_tunnels.clone(),
        )
    };

    Ok(JoinSessionDetails {
        code,
        relay_fingerprint,
        device,
        allowed_tunnels,
    })
}

async fn artifact_file(
    State(state): State<AppState>,
    Path(file): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if !is_safe_artifact_name(&file) {
        return Err(ApiError::not_found("artifact not found"));
    }

    let Some(artifact_dir) = &state.inner.artifact_dir else {
        return Err(ApiError::not_found("artifact server is disabled"));
    };
    let path = artifact_dir.join(&file);
    let bytes = fs::read(&path)
        .await
        .map_err(|_| ApiError::not_found("artifact not found"))?;

    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes))
}

async fn agent_ws(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_agent_socket(state, socket, peer_addr))
}

async fn operator_ws(
    State(state): State<AppState>,
    Query(query): Query<OperatorStreamQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    if let Err(err) = authorize_operator(&state, &headers) {
        return err.into_response();
    }

    ws.on_upgrade(move |socket| handle_operator_socket(state, query, socket))
        .into_response()
}

#[derive(Debug, Deserialize)]
struct OperatorStreamQuery {
    session: String,
    target: String,
}

async fn handle_agent_socket(state: AppState, socket: WebSocket, peer_addr: SocketAddr) {
    if let Err(err) = handle_agent_socket_inner(state, socket, peer_addr).await {
        if is_unclean_websocket_close(&err) {
            debug!(error = %err, "agent websocket closed without close handshake");
        } else {
            warn!(error = %err, "agent websocket closed with error");
        }
    }
}

async fn handle_agent_socket_inner(
    state: AppState,
    mut socket: WebSocket,
    peer_addr: SocketAddr,
) -> Result<()> {
    let Some(first) = socket.recv().await else {
        return Err(anyhow!("agent disconnected before hello"));
    };
    let Message::Binary(bytes) = first? else {
        return Err(anyhow!("agent hello must be a binary wire frame"));
    };
    let WireMessage::AgentHello {
        protocol,
        code,
        device,
        exposes,
    } = decode_wire(&bytes)?
    else {
        return Err(anyhow!("agent first message must be agent hello"));
    };
    if protocol != PROTOCOL_VERSION {
        return Err(anyhow!("unsupported protocol {protocol}"));
    }
    let offered_device = device.clone();

    let session_id_result = register_agent_session(&state, &code, device, &exposes);
    let session_id = match session_id_result {
        Ok(session_id) => session_id,
        Err(err) => {
            audit_agent_join_rejected(
                peer_addr,
                offered_device.as_deref(),
                &exposes,
                &err.to_string(),
            );
            send_agent_error(&mut socket, err.to_string()).await;
            return Err(err);
        }
    };

    let (mut writer, mut reader) = socket.split();
    let (tx, mut rx) = mpsc::channel::<WireMessage>(RELAY_CHANNEL_CAPACITY);
    tx.send(WireMessage::AgentReady {
        session: session_id.clone(),
    })
    .await?;
    {
        let mut sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("session store poisoned"))?;
        let session = sessions
            .get_mut(session_id.as_str())
            .ok_or_else(|| anyhow!("session not found after agent registration"))?;
        session.agent = Some(PeerSender { tx: tx.clone() });
        session.agent_remote_addr = Some(peer_addr.to_string());
        audit_agent_connected(session, peer_addr);
    }

    info!(session = %session_id, remote = %peer_addr, "agent connected");

    let outbound = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            writer.send(Message::Binary(encode_wire(&message)?)).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let loop_result = async {
        while let Some(frame) = reader.next().await {
            let frame = frame?;
            let bytes = match frame {
                Message::Binary(bytes) => bytes,
                Message::Close(_) => break,
                _ => continue,
            };
            match decode_wire(&bytes)? {
                WireMessage::StreamData { stream_id, bytes } => {
                    send_to_operator(
                        &state,
                        stream_id,
                        WireMessage::StreamData { stream_id, bytes },
                    )
                    .await?;
                }
                WireMessage::StreamClose { stream_id } => {
                    send_to_operator(&state, stream_id, WireMessage::StreamClose { stream_id })
                        .await?;
                    remove_stream(&state, stream_id)?;
                }
                WireMessage::StreamError { stream_id, message } => {
                    send_to_operator(
                        &state,
                        stream_id,
                        WireMessage::StreamError { stream_id, message },
                    )
                    .await?;
                    remove_stream(&state, stream_id)?;
                }
                other => debug!(?other, "ignored agent control message"),
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    outbound.abort();
    clear_agent(&state, &session_id)?;
    audit_agent_disconnected(&session_id);
    info!(session = %session_id, "agent disconnected");
    loop_result
}

async fn send_agent_error(socket: &mut WebSocket, message: String) {
    if let Ok(bytes) = encode_wire(&WireMessage::Error { message }) {
        socket.send(Message::Binary(bytes)).await.ok();
    }
    socket.send(Message::Close(None)).await.ok();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn handle_operator_socket(state: AppState, query: OperatorStreamQuery, socket: WebSocket) {
    if let Err(err) = handle_operator_socket_inner(state, query, socket).await {
        if is_unclean_websocket_close(&err) {
            debug!(error = %err, "operator websocket closed without close handshake");
        } else {
            warn!(error = %err, "operator websocket closed with error");
        }
    }
}

async fn handle_operator_socket_inner(
    state: AppState,
    query: OperatorStreamQuery,
    socket: WebSocket,
) -> Result<()> {
    let stream_id = StreamId::new(state.inner.next_stream.fetch_add(1, Ordering::Relaxed))?;
    let agent = {
        let mut sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("session store poisoned"))?;
        let session = sessions
            .get_mut(&query.session)
            .ok_or_else(|| anyhow!("session not found"))?;
        if session.expires_at <= Instant::now() {
            return Err(anyhow!("session has expired"));
        }
        if !session
            .allowed_tunnels
            .iter()
            .any(|tunnel| tunnel.name == query.target)
        {
            return Err(anyhow!(
                "target `{}` is not allowed for this session",
                query.target
            ));
        }
        session
            .agent
            .clone()
            .ok_or_else(|| anyhow!("agent is not connected"))?
    };

    let (mut writer, mut reader) = socket.split();
    let (tx, mut rx) = mpsc::channel::<WireMessage>(RELAY_CHANNEL_CAPACITY);
    {
        let mut sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("session store poisoned"))?;
        let session = sessions
            .get_mut(&query.session)
            .ok_or_else(|| anyhow!("session disappeared"))?;
        session.streams.insert(stream_id, PeerSender { tx });
    }

    agent
        .tx
        .send(WireMessage::OpenStream {
            stream_id,
            target: query.target.clone(),
        })
        .await?;
    audit_operator_stream_opened(&state, &query.session, &query.target, stream_id);
    info!(
        session = %query.session,
        %stream_id,
        target = %query.target,
        "operator stream opened"
    );

    let outbound = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            writer.send(Message::Binary(encode_wire(&message)?)).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let loop_result = async {
        while let Some(frame) = reader.next().await {
            let frame = frame?;
            let bytes = match frame {
                Message::Binary(bytes) => bytes,
                Message::Close(_) => break,
                _ => continue,
            };
            match decode_wire(&bytes)? {
                WireMessage::StreamData { bytes, .. } => {
                    agent
                        .tx
                        .send(WireMessage::StreamData { stream_id, bytes })
                        .await?;
                }
                WireMessage::StreamClose { .. } => {
                    agent
                        .tx
                        .send(WireMessage::StreamClose { stream_id })
                        .await?;
                }
                WireMessage::StreamError { message, .. } => {
                    agent
                        .tx
                        .send(WireMessage::StreamError { stream_id, message })
                        .await?;
                    break;
                }
                other => debug!(?other, "ignored operator control message"),
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    outbound.abort();
    agent
        .tx
        .try_send(WireMessage::StreamClose { stream_id })
        .ok();
    remove_stream(&state, stream_id)?;
    audit_operator_stream_closed(&state, &query.session, &query.target, stream_id);
    info!(
        session = %query.session,
        %stream_id,
        target = %query.target,
        "operator stream closed"
    );
    loop_result
}

fn is_unclean_websocket_close(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .to_string()
            .contains("Connection reset without closing handshake")
    })
}

fn authorize_operator(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(expected) = state.inner.operator_token.as_deref() else {
        return Ok(());
    };
    let Some(actual) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return Err(ApiError::unauthorized("missing operator token"));
    };

    if actual == expected {
        Ok(())
    } else {
        Err(ApiError::unauthorized("invalid operator token"))
    }
}

fn audit_timestamp_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn operator_auth_mode(state: &AppState) -> &'static str {
    if operator_token_present(state.inner.operator_token.as_deref()) {
        "token-auth"
    } else {
        "loopback-insecure-dev"
    }
}

fn audit_session_created(state: &AppState, session: &SessionId, response: &CreateSessionResponse) {
    info!(
        audit = true,
        audit_event = "session.created",
        audit_timestamp_unix = audit_timestamp_unix(),
        session = %session,
        device = response.device.as_deref().unwrap_or(""),
        ttl_seconds = response.ttl_seconds,
        capabilities = ?response.capabilities,
        allowed_tunnels = ?response.allowed_tunnels,
        operator_identity = operator_auth_mode(state),
        "relaykit audit event"
    );
}

fn audit_session_ended(state: &AppState, session: &SessionState, reason: &str) {
    info!(
        audit = true,
        audit_event = "session.ended",
        audit_timestamp_unix = audit_timestamp_unix(),
        session = %session.session,
        device = session.device.as_deref().unwrap_or(""),
        agent_remote_addr = session.agent_remote_addr.as_deref().unwrap_or(""),
        active_streams = session.streams.len(),
        capabilities = ?session.capabilities,
        allowed_tunnels = ?session.allowed_tunnels,
        reason,
        operator_identity = operator_auth_mode(state),
        "relaykit audit event"
    );
}

fn audit_agent_join_rejected(
    peer_addr: SocketAddr,
    device: Option<&str>,
    exposes: &[TunnelOffer],
    reason: &str,
) {
    warn!(
        audit = true,
        audit_event = "agent.join_rejected",
        audit_timestamp_unix = audit_timestamp_unix(),
        source_addr = %peer_addr,
        device = device.unwrap_or(""),
        exposes = ?exposes,
        reason,
        "relaykit audit event"
    );
}

fn audit_agent_connected(session: &SessionState, peer_addr: SocketAddr) {
    info!(
        audit = true,
        audit_event = "agent.connected",
        audit_timestamp_unix = audit_timestamp_unix(),
        session = %session.session,
        device = session.device.as_deref().unwrap_or(""),
        source_addr = %peer_addr,
        capabilities = ?session.capabilities,
        allowed_tunnels = ?session.allowed_tunnels,
        "relaykit audit event"
    );
}

fn audit_agent_disconnected(session: &SessionId) {
    info!(
        audit = true,
        audit_event = "agent.disconnected",
        audit_timestamp_unix = audit_timestamp_unix(),
        session = %session,
        "relaykit audit event"
    );
}

fn audit_operator_stream_opened(
    state: &AppState,
    session: &str,
    target: &str,
    stream_id: StreamId,
) {
    info!(
        audit = true,
        audit_event = "operator.stream_opened",
        audit_timestamp_unix = audit_timestamp_unix(),
        session,
        target,
        stream_id = %stream_id,
        operator_identity = operator_auth_mode(state),
        "relaykit audit event"
    );
}

fn audit_operator_stream_closed(
    state: &AppState,
    session: &str,
    target: &str,
    stream_id: StreamId,
) {
    info!(
        audit = true,
        audit_event = "operator.stream_closed",
        audit_timestamp_unix = audit_timestamp_unix(),
        session,
        target,
        stream_id = %stream_id,
        operator_identity = operator_auth_mode(state),
        "relaykit audit event"
    );
}

async fn send_to_operator(
    state: &AppState,
    stream_id: StreamId,
    message: WireMessage,
) -> Result<()> {
    let operator = {
        let sessions = state
            .inner
            .sessions
            .lock()
            .map_err(|_| anyhow!("session store poisoned"))?;
        sessions
            .values()
            .find_map(|session| session.streams.get(&stream_id))
            .cloned()
    };
    let Some(operator) = operator else {
        return Ok(());
    };
    operator.tx.send(message).await?;
    Ok(())
}

fn remove_stream(state: &AppState, stream_id: StreamId) -> Result<()> {
    let mut sessions = state
        .inner
        .sessions
        .lock()
        .map_err(|_| anyhow!("session store poisoned"))?;
    for session in sessions.values_mut() {
        session.streams.remove(&stream_id);
    }
    Ok(())
}

fn clear_agent(state: &AppState, session_id: &SessionId) -> Result<()> {
    let mut sessions = state
        .inner
        .sessions
        .lock()
        .map_err(|_| anyhow!("session store poisoned"))?;
    if let Some(session) = sessions.get_mut(session_id.as_str()) {
        session.agent = None;
        session.agent_remote_addr = None;
        for (stream_id, operator) in &session.streams {
            operator
                .tx
                .try_send(WireMessage::StreamError {
                    stream_id: *stream_id,
                    message: "agent disconnected".to_owned(),
                })
                .ok();
        }
        session.streams.clear();
    }
    Ok(())
}

fn notify_session_closed(session: SessionState, message: &str) {
    if let Some(agent) = session.agent {
        agent
            .tx
            .try_send(WireMessage::Error {
                message: message.to_owned(),
            })
            .ok();
    }

    for (stream_id, operator) in session.streams {
        operator
            .tx
            .try_send(WireMessage::StreamError {
                stream_id,
                message: message.to_owned(),
            })
            .ok();
    }
}

fn register_agent_session(
    state: &AppState,
    code: &SessionCode,
    device: Option<String>,
    exposes: &[TunnelOffer],
) -> Result<SessionId> {
    let mut sessions = state
        .inner
        .sessions
        .lock()
        .map_err(|_| anyhow!("session store poisoned"))?;
    let session = sessions
        .values_mut()
        .find(|session| session.code == *code)
        .ok_or_else(|| anyhow!("session code not found"))?;
    if session.expires_at <= Instant::now() {
        return Err(anyhow!("session has expired"));
    }
    if session.code_consumed {
        return Err(anyhow!("session code has already been used"));
    }
    validate_agent_exposes(&session.allowed_tunnels, exposes)?;
    session.device = device.or_else(|| session.device.clone());
    session.code_consumed = true;
    Ok(session.session.clone())
}

fn validate_agent_exposes(allowed_tunnels: &[TunnelSpec], exposes: &[TunnelOffer]) -> Result<()> {
    for (index, expose) in exposes.iter().enumerate() {
        if exposes[..index].iter().any(|seen| seen.name == expose.name) {
            return Err(anyhow!("agent offered duplicate tunnel `{}`", expose.name));
        }

        let allowed = allowed_tunnels
            .iter()
            .find(|tunnel| tunnel.name == expose.name)
            .ok_or_else(|| anyhow!("agent offered unauthorized tunnel `{}`", expose.name))?;

        if allowed.target.host != expose.host || allowed.target.port != expose.port {
            return Err(anyhow!(
                "agent tunnel `{}` target {}:{} does not match authorized target {}:{}",
                expose.name,
                expose.host,
                expose.port,
                allowed.target.host,
                allowed.target.port
            ));
        }
    }

    Ok(())
}

fn validate_allowed_tunnels(allowed_tunnels: &[TunnelSpec]) -> Result<(), ApiError> {
    if allowed_tunnels.is_empty() {
        Err(ApiError::bad_request(
            "at least one allowed tunnel target is required",
        ))
    } else {
        Ok(())
    }
}

fn install_command(public_url: &str, code: &SessionCode) -> String {
    let url = format!("{}/join/{}.sh", public_url.trim_end_matches('/'), code);
    format!(
        "sh -c 'u=$1; curl -fsSL --connect-timeout 10 --max-time 120 --noproxy \"*\" \"$u\" || curl -fsSL --connect-timeout 10 --max-time 120 \"$u\"' sh {} | sh",
        shell_quote(&url)
    )
}

fn agent_command(
    public_url: &str,
    code: &SessionCode,
    device: Option<&str>,
    allowed_tunnels: &[TunnelSpec],
    relay_fingerprint: Option<&RelayFingerprint>,
) -> String {
    let mut command = format!(
        "relaykit-agent join --relay {} --code {}",
        shell_quote(public_url),
        shell_quote(&code.to_string())
    );
    if let Some(relay_fingerprint) = relay_fingerprint {
        command.push_str(&format!(
            " --relay-fingerprint {}",
            shell_quote(&relay_fingerprint.to_string())
        ));
    }
    if let Some(device) = device {
        command.push_str(&format!(" --device {}", shell_quote(device)));
    }
    for tunnel in allowed_tunnels {
        command.push_str(&format!(
            " --tcp {}",
            shell_quote(&format!(
                "{}={}:{}",
                tunnel.name, tunnel.target.host, tunnel.target.port
            ))
        ));
    }
    command
}

fn linux_join_script(
    public_url: &str,
    code: &SessionCode,
    device: Option<&str>,
    allowed_tunnels: &[TunnelSpec],
    relay_fingerprint: Option<&RelayFingerprint>,
) -> String {
    let mut command = format!(
        "\"$bin\" -v join --relay {} --code {}",
        shell_quote(public_url),
        shell_quote(&code.to_string())
    );
    if let Some(relay_fingerprint) = relay_fingerprint {
        command.push_str(&format!(
            " --relay-fingerprint {}",
            shell_quote(&relay_fingerprint.to_string())
        ));
    }
    if let Some(device) = device {
        command.push_str(&format!(" --device {}", shell_quote(device)));
    }
    for tunnel in allowed_tunnels {
        command.push_str(&format!(
            " --tcp {}",
            shell_quote(&format!(
                "{}={}:{}",
                tunnel.name, tunnel.target.host, tunnel.target.port
            ))
        ));
    }

    format!(
        r#"#!/bin/sh
set -eu

base_url={base_url}
session_code={session_code}
workdir="${{TMPDIR:-/tmp}}/relaykit-agent/$session_code"
mkdir -p "$workdir"

echo "relaykit: preparing assisted session" >&2

os="$(uname -s)"
arch="$(uname -m)"
case "$os:$arch" in
  Linux:x86_64|Linux:amd64)
    asset="relaykit-agent-linux-x86_64"
    ;;
  Linux:aarch64|Linux:arm64)
    asset="relaykit-agent-linux-aarch64"
    ;;
  *)
    echo "relaykit: unsupported platform $os/$arch" >&2
    exit 1
    ;;
esac

bin="$workdir/relaykit-agent"
url="$base_url/artifacts/$asset"
checksum_url="$url.sha256"
checksum_file="$bin.sha256"

echo "relaykit: downloading $asset" >&2

proxy_env_present() {{
  [ -n "${{http_proxy:-}}${{https_proxy:-}}${{HTTP_PROXY:-}}${{HTTPS_PROXY:-}}${{ALL_PROXY:-}}${{all_proxy:-}}" ]
}}

download_with_curl() {{
  download_url=$1
  output=$2
  if proxy_env_present; then
    echo "relaykit: proxy settings detected; trying direct connection" >&2
    if curl -fsSL --connect-timeout 10 --max-time 120 --noproxy '*' "$download_url" -o "$output"; then
      return 0
    fi
    echo "relaykit: direct download failed; retrying configured proxy" >&2
  fi
  if curl -fsSL --connect-timeout 10 --max-time 120 "$download_url" -o "$output"; then
    return 0
  fi
  return 1
}}

download_with_wget() {{
  download_url=$1
  output=$2
  if proxy_env_present; then
    echo "relaykit: proxy settings detected; trying direct connection" >&2
    if http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= all_proxy= \
      wget -q -T 120 -O "$output" "$download_url"; then
      return 0
    fi
    echo "relaykit: direct download failed; retrying configured proxy" >&2
  fi
  if wget -q -T 120 -O "$output" "$download_url"; then
    return 0
  fi
  return 1
}}

download_to() {{
  download_url=$1
  output=$2
  if command -v curl >/dev/null 2>&1; then
    download_with_curl "$download_url" "$output"
  elif command -v wget >/dev/null 2>&1; then
    download_with_wget "$download_url" "$output"
  else
    echo "relaykit: curl or wget is required" >&2
    return 127
  fi
}}

sha256_of() {{
  if command -v sha256sum >/dev/null 2>&1; then
    set -- $(sha256sum "$1")
    printf '%s\n' "$1"
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    set -- $(shasum -a 256 "$1")
    printf '%s\n' "$1"
    return 0
  fi
  echo "relaykit: sha256sum or shasum is required to verify $asset" >&2
  return 1
}}

if command -v curl >/dev/null 2>&1; then
  :
elif command -v wget >/dev/null 2>&1; then
  :
else
  echo "relaykit: curl or wget is required" >&2
  exit 1
fi

if ! download_to "$url" "$bin"; then
  echo "relaykit: failed to download $asset from $url" >&2
  exit 1
fi

if download_to "$checksum_url" "$checksum_file"; then
  expected_sha256=""
  read -r expected_sha256 _ < "$checksum_file" || true
  actual_sha256="$(sha256_of "$bin")" || exit 1
  if [ -z "$expected_sha256" ]; then
    echo "relaykit: checksum file for $asset is empty or invalid" >&2
    exit 1
  fi
  if [ "$actual_sha256" != "$expected_sha256" ]; then
    echo "relaykit: checksum mismatch for $asset" >&2
    echo "relaykit: expected $expected_sha256" >&2
    echo "relaykit: actual   $actual_sha256" >&2
    exit 1
  fi
  echo "relaykit: verified $asset sha256=$actual_sha256" >&2
else
  echo "relaykit: checksum was not served for $asset" >&2
  echo "relaykit: refusing to run a hosted artifact without a SHA-256 sidecar" >&2
  exit 1
fi

chmod 700 "$bin"
echo "relaykit: starting agent; leave this terminal open, press Ctrl-C to stop" >&2
{command}
"#,
        base_url = shell_quote(public_url.trim_end_matches('/')),
        session_code = shell_quote(&code.to_string()),
        command = command,
    )
}

fn powershell_join_script(
    public_url: &str,
    code: &SessionCode,
    device: Option<&str>,
    allowed_tunnels: &[TunnelSpec],
    relay_fingerprint: Option<&RelayFingerprint>,
) -> String {
    let expose_args = allowed_tunnels
        .iter()
        .map(|tunnel| {
            format!(
                "{}={}:{}",
                tunnel.name, tunnel.target.host, tunnel.target.port
            )
        })
        .collect::<Vec<_>>();
    let exposes = powershell_array(&expose_args);
    let device_label = device
        .map(powershell_quote)
        .unwrap_or_else(|| "$null".to_owned());
    let relay_fingerprint = relay_fingerprint
        .map(|fingerprint| powershell_quote(&fingerprint.to_string()))
        .unwrap_or_else(|| "$null".to_owned());

    format!(
        r#"# RelayKit assisted-session join script.
# Review before running. This downloads relaykit-agent.exe from this relay and runs it in this PowerShell window.
# To stop assistance, press Ctrl+C or close this window.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$baseUrl = {base_url}
$relayUrl = {relay_url}
$relayFingerprint = {relay_fingerprint}
$sessionCode = {session_code}
$deviceLabel = {device_label}
$exposes = @(
{exposes}
)

$arch = if ($env:PROCESSOR_ARCHITEW6432) {{ $env:PROCESSOR_ARCHITEW6432 }} else {{ $env:PROCESSOR_ARCHITECTURE }}
if ([string]::IsNullOrWhiteSpace($arch)) {{
  throw 'relaykit: unable to detect Windows processor architecture'
}}

switch ($arch.ToUpperInvariant()) {{
  'AMD64' {{
    $asset = 'relaykit-agent-windows-x86_64.exe'
  }}
  'ARM64' {{
    $asset = 'relaykit-agent-windows-aarch64.exe'
  }}
  default {{
    throw "relaykit: unsupported Windows processor architecture $arch"
  }}
}}

$workRoot = Join-Path ([System.IO.Path]::GetTempPath()) 'relaykit-agent'
$workDir = Join-Path $workRoot $sessionCode
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$bin = Join-Path $workDir 'relaykit-agent.exe'
$url = "$baseUrl/artifacts/$asset"
$checksumUrl = "$url.sha256"
$checksumFile = "$bin.sha256"

Write-Host "relaykit: preparing assisted session $sessionCode"
Write-Host "relaykit: relay $relayUrl"
if ($null -ne $deviceLabel -and $deviceLabel.Length -gt 0) {{
  Write-Host "relaykit: label $deviceLabel"
}}
foreach ($expose in $exposes) {{
  Write-Host "relaykit: exposing $expose"
}}
Write-Host "relaykit: downloading $asset"

try {{
  Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing -MaximumRedirection 3 -TimeoutSec 120
}} catch {{
  throw "relaykit: failed to download $asset from $url. $($_.Exception.Message)"
}}

try {{
  Invoke-WebRequest -Uri $checksumUrl -OutFile $checksumFile -UseBasicParsing -MaximumRedirection 3 -TimeoutSec 120
  $checksumLine = (Get-Content -LiteralPath $checksumFile -TotalCount 1)
  $expectedSha256 = ($checksumLine -split '\s+')[0].ToLowerInvariant()
  if ([string]::IsNullOrWhiteSpace($expectedSha256)) {{
    throw "relaykit: checksum file for $asset is empty or invalid"
  }}
  $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $bin).Hash.ToLowerInvariant()
  if ($actualSha256 -ne $expectedSha256) {{
    throw "relaykit: checksum mismatch for $asset. expected $expectedSha256 actual $actualSha256"
  }}
  Write-Host "relaykit: verified $asset sha256=$actualSha256"
}} catch [System.Management.Automation.CommandNotFoundException] {{
  throw "relaykit: Get-FileHash is required to verify $asset"
}} catch {{
  if ($_.Exception.Message -like '*failed to download*' -or $_.Exception.Message -like '*404*' -or $_.Exception.Message -like '*Not Found*') {{
    throw "relaykit: refusing to run $asset because no SHA-256 sidecar was served"
  }} else {{
    throw
  }}
}}

$agentArgs = @(
  '-v'
  'join'
  '--relay'
  $relayUrl
  '--code'
  $sessionCode
)

if ($null -ne $relayFingerprint -and $relayFingerprint.Length -gt 0) {{
  $agentArgs += @('--relay-fingerprint', $relayFingerprint)
}}
if ($null -ne $deviceLabel -and $deviceLabel.Length -gt 0) {{
  $agentArgs += @('--device', $deviceLabel)
}}
foreach ($expose in $exposes) {{
  $agentArgs += @('--tcp', $expose)
}}

Write-Host 'relaykit: starting visible foreground agent'
Write-Host 'relaykit: leave this PowerShell window open; press Ctrl+C or close this window to stop assistance'
& $bin @agentArgs
"#,
        base_url = powershell_quote(public_url.trim_end_matches('/')),
        relay_url = powershell_quote(public_url),
        relay_fingerprint = relay_fingerprint,
        session_code = powershell_quote(&code.to_string()),
        device_label = device_label,
        exposes = exposes,
    )
}

fn powershell_array(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("  {}", powershell_quote(value)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_safe_artifact_name(file: &str) -> bool {
    !file.is_empty()
        && file
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, self.message).into_response()
    }
}

impl From<relaykit_protocol::ProtocolError> for ApiError {
    fn from(value: relaykit_protocol::ProtocolError) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relaykit_tunnel::{TunnelEndpoint, TunnelKind};

    fn test_code() -> SessionCode {
        SessionCode::new("RK-ABCD1234").expect("valid test session code")
    }

    fn ssh_spec() -> TunnelSpec {
        TunnelSpec {
            name: "ssh".to_owned(),
            kind: TunnelKind::Ssh,
            target: TunnelEndpoint::localhost(22),
        }
    }

    fn server_config(
        operator_token: Option<&str>,
        insecure_no_operator_auth: bool,
    ) -> ServerConfig {
        server_config_with_scope(
            operator_token,
            insecure_no_operator_auth,
            "127.0.0.1:18080",
            Some("http://127.0.0.1:18080"),
        )
    }

    fn server_config_with_scope(
        operator_token: Option<&str>,
        insecure_no_operator_auth: bool,
        listen: &str,
        public_url: Option<&str>,
    ) -> ServerConfig {
        ServerConfig {
            listen: listen.to_owned(),
            public_url: public_url.map(str::to_owned),
            operator_token: operator_token.map(str::to_owned),
            insecure_no_operator_auth,
            artifact_dir: None,
            tls_cert: None,
            tls_key: None,
        }
    }

    fn app_state(operator_token: Option<&str>) -> AppState {
        AppState {
            inner: Arc::new(RelayState {
                public_url: "http://127.0.0.1:18080".to_owned(),
                operator_token: operator_token.map(str::to_owned),
                artifact_dir: None,
                sessions: Mutex::new(HashMap::new()),
                next_stream: AtomicU64::new(1),
            }),
        }
    }

    #[test]
    fn server_config_requires_operator_token_by_default() {
        let config = server_config(None, false);

        let err = validate_server_config(&config).expect_err("config should fail");

        assert!(err.to_string().contains("missing operator token"), "{err}");
        assert_eq!(plan_server(config).status, "blocked");
    }

    #[test]
    fn server_config_allows_explicit_insecure_dev_mode() {
        let config = server_config(None, true);

        validate_server_config(&config).expect("explicit insecure dev mode should pass");
        let plan = plan_server(config);

        assert!(!plan.operator_auth_enabled);
        assert!(plan.insecure_no_operator_auth);
        assert!(!plan.tls_enabled);
        assert_eq!(plan.status, "ready");
    }

    #[test]
    fn server_config_limits_insecure_dev_mode_to_loopback() {
        let err = validate_server_config(&server_config_with_scope(
            None,
            true,
            "0.0.0.0:18080",
            Some("http://127.0.0.1:18080"),
        ))
        .expect_err("insecure dev mode should reject non-loopback listen addresses");
        assert!(err.to_string().contains("loopback --listen"), "{err}");

        let config = server_config_with_scope(
            None,
            true,
            "127.0.0.1:18080",
            Some("https://relay.example.com"),
        );
        let err = validate_server_config(&config)
            .expect_err("insecure dev mode should reject public URLs");
        assert!(err.to_string().contains("loopback --public-url"), "{err}");
        assert_eq!(plan_server(config).status, "blocked");

        validate_server_config(&server_config_with_scope(
            None,
            true,
            "[::1]:18080",
            Some("http://[::1]:18080"),
        ))
        .expect("insecure dev mode should allow IPv6 loopback");
    }

    #[test]
    fn server_config_requires_tls_for_non_local_public_urls() {
        let err = validate_server_config(&server_config_with_scope(
            Some("secret"),
            false,
            "0.0.0.0:18080",
            Some("http://relay.example.com"),
        ))
        .expect_err("remote plaintext public URL should fail");
        assert!(
            err.to_string()
                .contains("non-local relay public URLs must use https"),
            "{err}"
        );

        validate_server_config(&server_config_with_scope(
            Some("secret"),
            false,
            "0.0.0.0:18080",
            Some("https://relay.example.com"),
        ))
        .expect("remote https public URL should pass");

        let err = validate_server_config(&server_config_with_scope(
            Some("secret"),
            false,
            "0.0.0.0:18080",
            None,
        ))
        .expect_err("default non-loopback http public URL should fail");
        assert!(
            err.to_string()
                .contains("non-local relay public URLs must use https"),
            "{err}"
        );
    }

    #[test]
    fn server_config_requires_tls_cert_and_key_together() {
        let mut config = server_config_with_scope(
            Some("secret"),
            false,
            "0.0.0.0:18443",
            Some("https://relay.example.com:18443"),
        );
        config.tls_cert = Some(PathBuf::from("/etc/relaykit/relay.crt"));

        let err = validate_server_config(&config).expect_err("TLS cert without key should fail");
        assert!(err.to_string().contains("--tls-cert requires --tls-key"));

        let mut config = server_config_with_scope(
            Some("secret"),
            false,
            "0.0.0.0:18443",
            Some("https://relay.example.com:18443"),
        );
        config.tls_key = Some(PathBuf::from("/etc/relaykit/relay.key"));

        let err = validate_server_config(&config).expect_err("TLS key without cert should fail");
        assert!(err.to_string().contains("--tls-key requires --tls-cert"));
    }

    #[test]
    fn server_config_uses_https_default_public_url_when_tls_enabled() {
        let mut config = server_config_with_scope(Some("secret"), false, "0.0.0.0:18443", None);
        config.tls_cert = Some(PathBuf::from("/etc/relaykit/relay.crt"));
        config.tls_key = Some(PathBuf::from("/etc/relaykit/relay.key"));

        validate_server_config(&config).expect("built-in TLS should default to https public URL");
        assert_eq!(effective_public_url(&config), "https://0.0.0.0:18443");

        let plan = plan_server(config);
        assert!(plan.tls_enabled);
        assert_eq!(plan.status, "ready");
    }

    #[test]
    fn server_config_rejects_http_public_url_when_tls_enabled() {
        let mut config = server_config_with_scope(
            Some("secret"),
            false,
            "127.0.0.1:18443",
            Some("http://127.0.0.1:18443"),
        );
        config.tls_cert = Some(PathBuf::from("/etc/relaykit/relay.crt"));
        config.tls_key = Some(PathBuf::from("/etc/relaykit/relay.key"));

        let err = validate_server_config(&config)
            .expect_err("TLS listener advertised as HTTP should fail");
        assert!(
            err.to_string().contains("relay public URL must use https"),
            "{err}"
        );
    }

    #[test]
    fn pem_blocks_decode_base64_sections() {
        let pem = "\
-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
BAUG
-----END CERTIFICATE-----
";

        let blocks = pem_blocks(pem, "CERTIFICATE").expect("PEM should decode");

        assert_eq!(blocks, vec![vec![1, 2, 3], vec![4, 5, 6]]);
    }

    #[test]
    fn server_config_rejects_empty_or_conflicting_auth() {
        let err = validate_server_config(&server_config(Some(""), false))
            .expect_err("empty token should fail");
        assert!(err.to_string().contains("must not be empty"), "{err}");

        let err = validate_server_config(&server_config(Some("  "), false))
            .expect_err("blank token should fail");
        assert!(err.to_string().contains("must not be empty"), "{err}");

        let err = validate_server_config(&server_config(Some("secret"), true))
            .expect_err("conflicting auth modes should fail");
        assert!(
            err.to_string()
                .contains("cannot combine operator token authentication"),
            "{err}"
        );
    }

    #[test]
    fn operator_auth_uses_bearer_authorization_header() {
        let state = app_state(Some("secret-token"));
        let mut headers = HeaderMap::new();

        let err = authorize_operator(&state, &headers).expect_err("auth should be required");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(err.message.contains("missing operator token"));

        headers.insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer wrong-token"),
        );
        let err = authorize_operator(&state, &headers).expect_err("wrong token should fail");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(err.message.contains("invalid operator token"));

        headers.insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer secret-token"),
        );
        authorize_operator(&state, &headers).expect("matching bearer token should pass");
    }

    fn tunnel_offer(name: &str, host: &str, port: u16) -> TunnelOffer {
        TunnelOffer {
            name: name.to_owned(),
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn validate_agent_exposes_accepts_authorized_target() {
        let allowed = vec![ssh_spec()];
        let exposes = vec![tunnel_offer("ssh", "127.0.0.1", 22)];

        validate_agent_exposes(&allowed, &exposes).expect("authorized expose should pass");
    }

    #[test]
    fn validate_agent_exposes_rejects_unauthorized_tunnel() {
        let allowed = vec![ssh_spec()];
        let exposes = vec![tunnel_offer("postgres", "127.0.0.1", 5432)];

        let err = validate_agent_exposes(&allowed, &exposes).expect_err("expose should fail");

        assert!(
            err.to_string().contains("unauthorized tunnel `postgres`"),
            "{err}"
        );
    }

    #[test]
    fn validate_agent_exposes_rejects_target_mismatch() {
        let allowed = vec![ssh_spec()];
        let exposes = vec![tunnel_offer("ssh", "127.0.0.1", 2222)];

        let err = validate_agent_exposes(&allowed, &exposes).expect_err("expose should fail");

        assert!(
            err.to_string().contains("does not match authorized target"),
            "{err}"
        );
    }

    #[test]
    fn validate_agent_exposes_rejects_duplicate_names() {
        let allowed = vec![ssh_spec()];
        let exposes = vec![
            tunnel_offer("ssh", "127.0.0.1", 22),
            tunnel_offer("ssh", "127.0.0.1", 22),
        ];

        let err = validate_agent_exposes(&allowed, &exposes).expect_err("expose should fail");

        assert!(err.to_string().contains("duplicate tunnel `ssh`"), "{err}");
    }

    #[test]
    fn validate_allowed_tunnels_requires_explicit_targets() {
        let err = validate_allowed_tunnels(&[]).expect_err("empty target list should fail");

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(
            err.message
                .contains("at least one allowed tunnel target is required"),
            "{}",
            err.message
        );
        validate_allowed_tunnels(&[ssh_spec()]).expect("explicit target should pass");
    }

    #[test]
    fn install_command_uses_join_script_url() {
        let command = install_command("https://relay.example.com/", &test_code());

        assert_eq!(
            command,
            "sh -c 'u=$1; curl -fsSL --connect-timeout 10 --max-time 120 --noproxy \"*\" \"$u\" || curl -fsSL --connect-timeout 10 --max-time 120 \"$u\"' sh 'https://relay.example.com/join/RK-ABCD1234.sh' | sh"
        );
    }

    #[test]
    fn agent_command_quotes_shell_arguments() {
        let tunnels = vec![TunnelSpec {
            name: "ssh access".to_owned(),
            kind: TunnelKind::Tcp,
            target: TunnelEndpoint {
                host: "127.0.0.1".to_owned(),
                port: 22,
            },
        }];

        let command = agent_command(
            "https://relay.example.com/path",
            &test_code(),
            Some("User's laptop"),
            &tunnels,
            Some(
                &"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .parse()
                    .unwrap(),
            ),
        );

        assert_eq!(
            command,
            "relaykit-agent join --relay 'https://relay.example.com/path' --code 'RK-ABCD1234' --relay-fingerprint 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' --device 'User'\\''s laptop' --tcp 'ssh access=127.0.0.1:22'"
        );
    }

    #[test]
    fn linux_join_script_downloads_platform_artifact_and_execs_agent() {
        let tunnels = vec![ssh_spec()];

        let script = linux_join_script(
            "https://relay.example.com/",
            &test_code(),
            Some("assisted-linux"),
            &tunnels,
            None,
        );

        assert!(script.contains("base_url='https://relay.example.com'"));
        assert!(script.contains("session_code='RK-ABCD1234'"));
        assert!(script.contains("workdir=\"${TMPDIR:-/tmp}/relaykit-agent/$session_code\""));
        assert!(script.contains("Linux:x86_64|Linux:amd64)"));
        assert!(script.contains("asset=\"relaykit-agent-linux-x86_64\""));
        assert!(script.contains("Linux:aarch64|Linux:arm64)"));
        assert!(script.contains("asset=\"relaykit-agent-linux-aarch64\""));
        assert!(script.contains("url=\"$base_url/artifacts/$asset\""));
        assert!(script.contains("checksum_url=\"$url.sha256\""));
        assert!(script.contains("echo \"relaykit: downloading $asset\" >&2"));
        assert!(script.contains("curl -fsSL --connect-timeout 10 --max-time 120"));
        assert!(script.contains("proxy settings detected; trying direct connection"));
        assert!(script.contains("direct download failed; retrying configured proxy"));
        assert!(script.contains("return 1"));
        assert!(script.contains("download_to \"$url\" \"$bin\""));
        assert!(script.contains("curl -fsSL --connect-timeout 10 --max-time 120 --noproxy '*' \"$download_url\" -o \"$output\""));
        assert!(script.contains("wget -q -T 120 -O \"$output\" \"$download_url\""));
        assert!(script.contains("sha256sum \"$1\""));
        assert!(script.contains("shasum -a 256 \"$1\""));
        assert!(script.contains("checksum mismatch for $asset"));
        assert!(script.contains("checksum was not served for $asset"));
        assert!(script.contains("refusing to run a hosted artifact without a SHA-256 sidecar"));
        assert!(script.contains("starting agent; leave this terminal open"));
        assert!(script.contains(
            "\"$bin\" -v join --relay 'https://relay.example.com/' --code 'RK-ABCD1234' --device 'assisted-linux' --tcp 'ssh=127.0.0.1:22'"
        ));
        assert!(!script.contains("operator_token"));
    }

    #[test]
    fn powershell_join_script_downloads_windows_artifact_and_execs_agent() {
        let tunnels = vec![TunnelSpec::rdp()];

        let script = powershell_join_script(
            "https://relay.example.com/",
            &test_code(),
            Some("User's laptop"),
            &tunnels,
            None,
        );

        assert!(script.contains("$baseUrl = 'https://relay.example.com'"));
        assert!(script.contains("$relayUrl = 'https://relay.example.com/'"));
        assert!(script.contains("$sessionCode = 'RK-ABCD1234'"));
        assert!(script.contains("$deviceLabel = 'User''s laptop'"));
        assert!(script.contains("'rdp=127.0.0.1:3389'"));
        assert!(script.contains("relaykit-agent-windows-x86_64.exe"));
        assert!(script.contains("relaykit-agent-windows-aarch64.exe"));
        assert!(script.contains("Invoke-WebRequest -Uri $url -OutFile $bin"));
        assert!(script.contains("$checksumUrl = \"$url.sha256\""));
        assert!(script.contains("Get-FileHash -Algorithm SHA256"));
        assert!(script.contains("checksum mismatch for $asset"));
        assert!(script.contains("refusing to run $asset because no SHA-256 sidecar was served"));
        assert!(script.contains("$agentArgs += @('--tcp', $expose)"));
        assert!(script.contains("& $bin @agentArgs"));
        assert!(script.contains("press Ctrl+C or close this window to stop assistance"));
        assert!(!script.contains("operator_token"));
        assert!(!script.contains("secret-token"));
    }

    #[test]
    fn session_summary_includes_agent_remote_address() {
        let now = Instant::now();
        let session = SessionState {
            session: SessionId::new("rk-testsession").expect("valid session id"),
            code: test_code(),
            relay_fingerprint: None,
            device: Some("customer-203.0.113.10".to_owned()),
            capabilities: vec![Capability::Ssh],
            allowed_tunnels: vec![ssh_spec()],
            ttl_seconds: 900,
            expires_at: now + Duration::from_secs(300),
            code_consumed: true,
            agent: None,
            agent_remote_addr: Some("198.51.100.24:53000".to_owned()),
            streams: HashMap::new(),
        };

        let summary = session_summary(&session, now);

        assert_eq!(summary.device.as_deref(), Some("customer-203.0.113.10"));
        assert_eq!(
            summary.agent_remote_addr.as_deref(),
            Some("198.51.100.24:53000")
        );
        assert_eq!(summary.expires_in_seconds, 300);
    }

    #[test]
    fn artifact_names_reject_paths_and_shell_metacharacters() {
        assert!(is_safe_artifact_name("relaykit-agent-linux-x86_64"));
        assert!(is_safe_artifact_name("relaykit-agent.v0.1.0"));

        assert!(!is_safe_artifact_name(""));
        assert!(!is_safe_artifact_name("../relaykit-agent"));
        assert!(!is_safe_artifact_name("nested/relaykit-agent"));
        assert!(!is_safe_artifact_name("relaykit agent"));
        assert!(!is_safe_artifact_name("relaykit-agent;rm"));
    }
}
