//! Shared JSON-line protocol and bounded synchronous client.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
pub const MAX_LINE: usize = 4096;
pub const DEFAULT_SOCKET: &str = "/run/omamori/omamori.sock";
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Input {
    Request {
        kind: RequestKind,
        user: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        command: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tty: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
    },
    Status {},
    PairBegin {},
    PairConfirm {
        accept: bool,
    },
    Unpair {},
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestKind {
    Lock,
    Sudo,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ev", rename_all = "kebab-case")]
pub enum Event {
    Queued {
        id: String,
    },
    Approved,
    Unavailable {
        reason: String,
    },
    Denied {
        reason: String,
    },
    PairCode {
        code: String,
        watch_name: String,
    },
    PairDone,
    PairFailed {
        reason: String,
    },
    Status {
        #[serde(flatten)]
        fields: serde_json::Map<String, serde_json::Value>,
    },
}
pub fn send(stream: &mut UnixStream, input: &Input) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(input)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_LINE {
        return Err(io::Error::other("IPC line too large"));
    }
    stream.write_all(&bytes)
}
pub fn receive(stream: &mut UnixStream) -> io::Result<Event> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > MAX_LINE {
            return Err(io::Error::other("IPC line too large"));
        }
        if byte[0] == b'\n' {
            return Ok(serde_json::from_slice(&bytes)?);
        }
    }
}
pub fn decode_event(bytes: &[u8]) -> serde_json::Result<Event> {
    serde_json::from_slice(bytes)
}

impl Event {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Approved
                | Self::Unavailable { .. }
                | Self::Denied { .. }
                | Self::PairDone
                | Self::PairFailed { .. }
        )
    }
}
