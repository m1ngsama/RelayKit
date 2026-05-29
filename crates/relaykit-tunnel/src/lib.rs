use std::{fmt, str::FromStr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use futures_util::{SinkExt, StreamExt};
use relaykit_protocol::{decode_wire, encode_wire, SessionId, StreamId, TunnelOffer, WireMessage};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring as rustls_ring, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        handshake::client::Response,
        http::{
            header::{HeaderValue, AUTHORIZATION},
            Request,
        },
        Message,
    },
    Connector, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, info, warn};
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelEndpoint {
    pub host: String,
    pub port: u16,
}

impl TunnelEndpoint {
    pub fn localhost(port: u16) -> Self {
        Self {
            host: "127.0.0.1".to_owned(),
            port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelKind {
    Tcp,
    Ssh,
    Rdp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub name: String,
    pub kind: TunnelKind,
    pub target: TunnelEndpoint,
}

impl TunnelSpec {
    pub fn ssh() -> Self {
        Self {
            name: "ssh".to_owned(),
            kind: TunnelKind::Ssh,
            target: TunnelEndpoint::localhost(22),
        }
    }

    pub fn rdp() -> Self {
        Self {
            name: "rdp".to_owned(),
            kind: TunnelKind::Rdp,
            target: TunnelEndpoint::localhost(3389),
        }
    }
}

impl From<&TunnelSpec> for TunnelOffer {
    fn from(spec: &TunnelSpec) -> Self {
        Self {
            name: spec.name.clone(),
            host: spec.target.host.clone(),
            port: spec.target.port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OperatorTunnelConfig {
    pub server: String,
    pub session: SessionId,
    pub target: String,
    pub listen: String,
    pub operator_token: Option<String>,
    pub relay_fingerprint: Option<RelayFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFingerprint {
    sha256_hex: String,
}

impl RelayFingerprint {
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }
}

impl fmt::Display for RelayFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", self.sha256_hex)
    }
}

impl FromStr for RelayFingerprint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        let digest = trimmed
            .strip_prefix("sha256:")
            .or_else(|| trimmed.strip_prefix("SHA256:"))
            .unwrap_or(trimmed);
        let compact = digest
            .bytes()
            .filter(|byte| *byte != b':')
            .collect::<Vec<_>>();
        if compact.len() != 64 || !compact.iter().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "relay fingerprint must be a SHA-256 hex digest, for example sha256:<64 hex chars>"
            ));
        }
        let sha256_hex = compact
            .into_iter()
            .map(|byte| (byte as char).to_ascii_lowercase())
            .collect();
        Ok(Self { sha256_hex })
    }
}

impl Serialize for RelayFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for RelayFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

pub fn certificate_sha256_hex(certificate_der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, certificate_der);
    lower_hex(digest.as_ref())
}

pub fn relay_fingerprint_client_config(fingerprint: &RelayFingerprint) -> Result<ClientConfig> {
    let provider = Arc::new(rustls_ring::default_provider());
    let verifier = Arc::new(PinnedServerCertVerifier {
        fingerprint: fingerprint.clone(),
        provider: Arc::clone(&provider),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to configure relay TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

pub async fn connect_relay_websocket<R>(
    request: R,
    relay_fingerprint: Option<&RelayFingerprint>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response)>
where
    R: IntoClientRequest + Unpin,
{
    let request = request.into_client_request()?;
    if relay_fingerprint.is_some() && request.uri().scheme_str() != Some("wss") {
        return Err(anyhow!(
            "--relay-fingerprint requires an https or wss relay URL"
        ));
    }
    let connector = relay_fingerprint
        .map(|fingerprint| {
            relay_fingerprint_client_config(fingerprint)
                .map(|config| Connector::Rustls(Arc::new(config)))
        })
        .transpose()?;
    connect_async_tls_with_config(request, None, false, connector)
        .await
        .context("failed to connect relay websocket")
}

#[derive(Debug)]
struct PinnedServerCertVerifier {
    fingerprint: RelayFingerprint,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let actual = certificate_sha256_hex(end_entity.as_ref());
        if actual == self.fingerprint.sha256_hex() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(format!(
                "relay certificate fingerprint mismatch: expected {}, got sha256:{actual}",
                self.fingerprint
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn run_operator_tunnel(config: OperatorTunnelConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| {
            format!(
                "failed to bind local listener {}; choose another --listen address or use --listen 127.0.0.1:0 for a dynamic port",
                config.listen
            )
        })?;
    let listen_addr = listener.local_addr()?;
    println!("local tunnel listening on {listen_addr}");
    info!(
        session = %config.session,
        target = %config.target,
        listen = %listen_addr,
        "operator tunnel listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let server = config.server.clone();
        let session = config.session.clone();
        let target = config.target.clone();
        let operator_token = config.operator_token.clone();
        let relay_fingerprint = config.relay_fingerprint.clone();
        debug!(%peer, %target, "accepted local tunnel connection");

        tokio::spawn(async move {
            if let Err(err) = bridge_operator_stream(
                server,
                session,
                target,
                operator_token,
                relay_fingerprint,
                socket,
            )
            .await
            {
                warn!(%peer, error = %err, "operator stream ended with error");
            }
        });
    }
}

async fn bridge_operator_stream(
    server: String,
    session: SessionId,
    target: String,
    operator_token: Option<String>,
    relay_fingerprint: Option<RelayFingerprint>,
    local: TcpStream,
) -> Result<()> {
    let request = operator_ws_request(&server, &session, &target, operator_token.as_deref())?;
    let uri = request.uri().clone();
    let (ws, _) = connect_relay_websocket(request, relay_fingerprint.as_ref())
        .await
        .with_context(|| format!("failed to connect operator stream websocket {uri}"))?;
    let (mut ws_writer, mut ws_reader) = ws.split();
    let (mut tcp_reader, mut tcp_writer) = local.into_split();

    let to_relay = async {
        let mut buffer = vec![0_u8; 16 * 1024];
        loop {
            let read = tcp_reader.read(&mut buffer).await?;
            if read == 0 {
                ws_writer
                    .send(Message::Binary(encode_wire(&WireMessage::StreamClose {
                        stream_id: StreamId::new(1)?,
                    })?))
                    .await?;
                break;
            }

            ws_writer
                .send(Message::Binary(encode_wire(&WireMessage::StreamData {
                    stream_id: StreamId::new(1)?,
                    bytes: buffer[..read].to_vec(),
                })?))
                .await?;
        }

        Ok::<(), anyhow::Error>(())
    };

    let from_relay = async {
        while let Some(frame) = ws_reader.next().await {
            let frame = frame?;
            match frame {
                Message::Binary(bytes) => match decode_wire(&bytes)? {
                    WireMessage::StreamData { bytes, .. } => {
                        tcp_writer.write_all(&bytes).await?;
                    }
                    WireMessage::StreamClose { .. } => break,
                    WireMessage::StreamError { message, .. } | WireMessage::Error { message } => {
                        return Err(anyhow!(message));
                    }
                    _ => {}
                },
                Message::Close(_) => break,
                _ => {}
            }
        }

        tcp_writer.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };

    tokio::pin!(to_relay);
    tokio::pin!(from_relay);

    tokio::select! {
        result = &mut from_relay => result,
        result = &mut to_relay => {
            result?;
            from_relay.await
        }
    }
}

fn operator_ws_request(
    server: &str,
    session: &SessionId,
    target: &str,
    operator_token: Option<&str>,
) -> Result<Request<()>> {
    let url = operator_ws_url(server, session, target)?;
    let mut request = url.as_str().into_client_request()?;
    if let Some(operator_token) = operator_token {
        let mut value = HeaderValue::from_str(&format!("Bearer {operator_token}"))
            .context("operator token cannot be used as an HTTP authorization header")?;
        value.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, value);
    }
    Ok(request)
}

fn operator_ws_url(server: &str, session: &SessionId, target: &str) -> Result<Url> {
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
    url.set_path("/ws/operator");
    let mut query = url.query_pairs_mut();
    query
        .clear()
        .append_pair("session", session.as_str())
        .append_pair("target", target);
    drop(query);
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

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> SessionId {
        SessionId::new("rk-test-session").expect("valid session id")
    }

    #[test]
    fn operator_ws_url_never_contains_operator_token() {
        let url = operator_ws_url("https://relay.example.com/base", &test_session(), "ssh")
            .expect("valid operator websocket URL");

        assert_eq!(url.scheme(), "wss");
        assert_eq!(url.path(), "/ws/operator");
        assert_eq!(url.query(), Some("session=rk-test-session&target=ssh"));
        assert!(!url.as_str().contains("secret-token"));
        assert!(!url.query_pairs().any(|(name, _)| name == "operator_token"));
    }

    #[test]
    fn operator_ws_request_sends_operator_token_in_authorization_header() {
        let request = operator_ws_request(
            "https://relay.example.com",
            &test_session(),
            "ssh",
            Some("secret-token"),
        )
        .expect("valid authorized operator websocket request");
        let uri = request.uri().to_string();

        assert_eq!(
            uri,
            "wss://relay.example.com/ws/operator?session=rk-test-session&target=ssh"
        );
        assert!(!uri.contains("secret-token"));
        assert_eq!(
            request.headers().get(AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer secret-token"))
        );
    }

    #[test]
    fn relay_fingerprint_accepts_common_sha256_formats() {
        let digest = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
        let fingerprint: RelayFingerprint = digest.parse().expect("valid colon hex");

        assert_eq!(
            fingerprint.to_string(),
            "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
        assert_eq!(
            "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                .parse::<RelayFingerprint>()
                .unwrap(),
            fingerprint
        );
    }

    #[test]
    fn relay_fingerprint_rejects_invalid_values() {
        assert!("sha256:not-hex".parse::<RelayFingerprint>().is_err());
        assert!("sha256:abcd".parse::<RelayFingerprint>().is_err());
        assert!("".parse::<RelayFingerprint>().is_err());
    }

    #[test]
    fn certificate_sha256_uses_lower_hex() {
        assert_eq!(
            certificate_sha256_hex(b"relaykit"),
            "dbef861c5d9dff19a4dfe36522f3b1caf5b34ec7a13e9439bcde8ee05691e0a8"
        );
    }

    #[test]
    fn operator_ws_url_requires_tls_for_non_local_relays() {
        let local = operator_ws_url("http://127.0.0.1:18080", &test_session(), "ssh")
            .expect("loopback http is allowed");
        assert_eq!(
            local.as_str(),
            "ws://127.0.0.1:18080/ws/operator?session=rk-test-session&target=ssh"
        );

        let remote = operator_ws_url("wss://relay.example.com", &test_session(), "ssh")
            .expect("remote wss is allowed");
        assert_eq!(
            remote.as_str(),
            "wss://relay.example.com/ws/operator?session=rk-test-session&target=ssh"
        );

        let err = operator_ws_url("http://relay.example.com", &test_session(), "ssh")
            .expect_err("remote plaintext relay URL should fail");
        assert!(
            err.to_string().contains("non-local relay URLs must use"),
            "{err}"
        );
    }
}
