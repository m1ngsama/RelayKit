use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: &str = "relaykit.v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCode(String);

impl SessionCode {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        let valid_len = (4..=64).contains(&value.len());
        let valid_chars = value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_');

        if valid_len && valid_chars {
            Ok(Self(value))
        } else {
            Err(ProtocolError::InvalidSessionCode)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SessionCode {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProtocolError::InvalidSessionId);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SessionId {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamId(u64);

impl StreamId {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 {
            return Err(ProtocolError::InvalidStreamId);
        }

        Ok(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Ssh,
    Rdp,
    Tcp,
    Diagnostics,
    FileTransfer,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Tcp => "tcp",
            Self::Diagnostics => "diagnostics",
            Self::FileTransfer => "file-transfer",
        };
        f.write_str(value)
    }
}

impl FromStr for Capability {
    type Err = ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ssh" => Ok(Self::Ssh),
            "rdp" => Ok(Self::Rdp),
            "tcp" => Ok(Self::Tcp),
            "diagnostics" => Ok(Self::Diagnostics),
            "file-transfer" => Ok(Self::FileTransfer),
            _ => Err(ProtocolError::UnknownCapability(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelOffer {
    pub name: String,
    pub host: String,
    pub port: u16,
}

impl TunnelOffer {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, ProtocolError> {
        let name = name.into();
        let host = host.into();
        if name.is_empty() || host.is_empty() {
            return Err(ProtocolError::InvalidTunnelOffer);
        }

        Ok(Self { name, host, port })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireMessage {
    AgentHello {
        protocol: String,
        code: SessionCode,
        device: Option<String>,
        exposes: Vec<TunnelOffer>,
    },
    AgentReady {
        session: SessionId,
    },
    OpenStream {
        stream_id: StreamId,
        target: String,
    },
    StreamData {
        stream_id: StreamId,
        bytes: Vec<u8>,
    },
    StreamClose {
        stream_id: StreamId,
    },
    StreamError {
        stream_id: StreamId,
        message: String,
    },
    Error {
        message: String,
    },
}

pub fn encode_wire(message: &WireMessage) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(message).map_err(|err| ProtocolError::Codec(err.to_string()))
}

pub fn decode_wire(bytes: &[u8]) -> Result<WireMessage, ProtocolError> {
    serde_json::from_slice(bytes).map_err(|err| ProtocolError::Codec(err.to_string()))
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("session code must be 4-64 ASCII letters, numbers, hyphens, or underscores")]
    InvalidSessionCode,
    #[error("session id cannot be empty")]
    InvalidSessionId,
    #[error("stream id must be non-zero")]
    InvalidStreamId,
    #[error("unknown capability: {0}")]
    UnknownCapability(String),
    #[error("tunnel offer must include a non-empty name and host")]
    InvalidTunnelOffer,
    #[error("wire message codec error: {0}")]
    Codec(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_short_lived_session_codes() {
        let code = SessionCode::new("ABCD-1234").unwrap();
        assert_eq!(code.as_str(), "ABCD-1234");
    }

    #[test]
    fn rejects_codes_with_shell_metacharacters() {
        assert!(SessionCode::new("ABCD;rm").is_err());
    }

    #[test]
    fn encodes_wire_messages_as_binary_frames() {
        let message = WireMessage::StreamData {
            stream_id: StreamId::new(7).unwrap(),
            bytes: b"hello".to_vec(),
        };
        let bytes = encode_wire(&message).unwrap();
        assert_eq!(decode_wire(&bytes).unwrap(), message);
    }

    #[test]
    fn rejects_trailing_bytes_after_wire_message() {
        let message = WireMessage::StreamClose {
            stream_id: StreamId::new(7).unwrap(),
        };
        let mut bytes = encode_wire(&message).unwrap();
        bytes.push(0);

        assert!(decode_wire(&bytes).is_err());
    }
}
