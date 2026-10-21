//! Strict v1 wire codec. Encoding strings truncates to 255 UTF-8 bytes.
use crate::framing::MAX_MESSAGE;

pub type RequestId = [u8; 8];
pub type HostId = [u8; 16];
pub type Nonce = [u8; 16];
pub type Mac = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Version,
    Type,
    Truncated,
    Trailing,
    Utf8,
    Value,
    Oversize,
    Closed,
    State,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Lock = 1,
    Sudo = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub req_id: RequestId,
    pub kind: Kind,
    pub needs_confirm: bool,
    pub age_s: u16,
    pub title: String,
    pub detail: String,
}
impl Entry {
    /// Canonical contents actually displayed by a v1 peer.
    pub fn canonicalize(&mut self) {
        self.title = truncate_to(&self.title, 48).to_owned();
        self.detail = truncate_to(&self.detail, 160).to_owned();
    }
    pub(crate) fn same_request(&self, other: &Self) -> bool {
        self.req_id == other.req_id
            && self.kind == other.kind
            && self.needs_confirm == other.needs_confirm
            && self.title == other.title
            && self.detail == other.detail
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    AuthHello {
        watch_nonce: Nonce,
    },
    Approve {
        req_id: RequestId,
        mac: Mac,
    },
    PairCommit {
        commit: Mac,
    },
    PairReveal {
        watch_pub: [u8; 65],
        watch_nonce: Nonce,
        watch_name: String,
    },
    PairConfirm {
        accepted: bool,
        mac: Mac,
    },
    Pending {
        host_id: HostId,
        host_name: String,
        more: bool,
        entries: Vec<Entry>,
        mac: Mac,
    },
    Result {
        req_id: RequestId,
        status: u8,
        mac: Mac,
    },
    PairHost {
        host_pub: [u8; 65],
        host_nonce: Nonce,
        host_id: HostId,
        host_name: String,
    },
    PairResult {
        accepted: bool,
        mac: Mac,
    },
    Error {
        code: u8,
    },
}

pub fn truncate_str(value: &str) -> &str {
    truncate_to(value, 255)
}

pub fn truncate_to(value: &str, limit: usize) -> &str {
    let mut len = value.len().min(limit);
    while !value.is_char_boundary(len) {
        len -= 1;
    }
    &value[..len]
}

pub fn encode_str(value: &str, out: &mut Vec<u8>) {
    let value = truncate_str(value);
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let value = self.0.get(..N).ok_or(Error::Truncated)?;
        self.0 = &self.0[N..];
        Ok(value.try_into().expect("fixed slice length"))
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.bytes::<1>()?[0])
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Value),
        }
    }
    fn limited_string(&mut self, max: usize) -> Result<String, Error> {
        let value = self.string()?;
        if value.len() > max {
            return Err(Error::Value);
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<String, Error> {
        let len = usize::from(self.byte()?);
        let bytes = self.0.get(..len).ok_or(Error::Truncated)?;
        self.0 = &self.0[len..];
        Ok(std::str::from_utf8(bytes)
            .map_err(|_| Error::Utf8)?
            .to_owned())
    }
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![1];
        match self {
            Self::AuthHello { watch_nonce } => {
                out.push(0x01);
                out.extend_from_slice(watch_nonce);
            }
            Self::Approve { req_id, mac } => {
                out.push(0x02);
                out.extend_from_slice(req_id);
                out.extend_from_slice(mac);
            }
            Self::PairCommit { commit } => {
                out.push(0x10);
                out.extend_from_slice(commit);
            }
            Self::PairReveal {
                watch_pub,
                watch_nonce,
                watch_name,
            } => {
                out.push(0x11);
                out.extend_from_slice(watch_pub);
                out.extend_from_slice(watch_nonce);
                encode_str(watch_name, &mut out);
            }
            Self::PairConfirm { accepted, mac } => {
                out.extend_from_slice(&[0x12, u8::from(*accepted)]);
                out.extend_from_slice(mac);
            }
            Self::Pending {
                host_id,
                host_name,
                more,
                entries,
                mac,
            } => {
                out.push(0x81);
                out.extend_from_slice(host_id);
                encode_str(host_name, &mut out);
                out.push(u8::from(*more));
                out.push(u8::try_from(entries.len()).map_err(|_| Error::Value)?);
                for entry in entries {
                    out.extend_from_slice(&entry.req_id);
                    out.push(entry.kind as u8);
                    out.push(u8::from(entry.needs_confirm));
                    out.extend_from_slice(&entry.age_s.to_be_bytes());
                    encode_str(truncate_to(&entry.title, 48), &mut out);
                    encode_str(truncate_to(&entry.detail, 160), &mut out);
                }
                out.extend_from_slice(mac);
            }
            Self::Result {
                req_id,
                status,
                mac,
            } => {
                if *status > 2 {
                    return Err(Error::Value);
                }
                out.push(0x82);
                out.extend_from_slice(req_id);
                out.push(*status);
                out.extend_from_slice(mac);
            }
            Self::PairHost {
                host_pub,
                host_nonce,
                host_id,
                host_name,
            } => {
                out.push(0x90);
                out.extend_from_slice(host_pub);
                out.extend_from_slice(host_nonce);
                out.extend_from_slice(host_id);
                encode_str(host_name, &mut out);
            }
            Self::PairResult { accepted, mac } => {
                out.extend_from_slice(&[0x91, u8::from(*accepted)]);
                out.extend_from_slice(mac);
            }
            Self::Error { code } => {
                if !(1..=4).contains(code) {
                    return Err(Error::Value);
                }
                out.extend_from_slice(&[0xff, *code]);
            }
        }
        if out.len() > MAX_MESSAGE {
            return Err(Error::Oversize);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_MESSAGE {
            return Err(Error::Oversize);
        }
        let mut r = Reader(bytes);
        if r.byte()? != 1 {
            return Err(Error::Version);
        }
        let message = match r.byte()? {
            0x01 => Self::AuthHello {
                watch_nonce: r.bytes()?,
            },
            0x02 => Self::Approve {
                req_id: r.bytes()?,
                mac: r.bytes()?,
            },
            0x10 => Self::PairCommit { commit: r.bytes()? },
            0x11 => Self::PairReveal {
                watch_pub: r.bytes()?,
                watch_nonce: r.bytes()?,
                watch_name: r.string()?,
            },
            0x12 => Self::PairConfirm {
                accepted: r.boolean()?,
                mac: r.bytes()?,
            },
            0x81 => {
                let host_id = r.bytes()?;
                let host_name = r.string()?;
                let more = r.boolean()?;
                let count = r.byte()?;
                let mut entries = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    entries.push(Entry {
                        req_id: r.bytes()?,
                        kind: match r.byte()? {
                            1 => Kind::Lock,
                            2 => Kind::Sudo,
                            _ => return Err(Error::Value),
                        },
                        needs_confirm: r.boolean()?,
                        age_s: u16::from_be_bytes(r.bytes()?),
                        title: r.limited_string(48)?,
                        detail: r.limited_string(160)?,
                    });
                }
                Self::Pending {
                    host_id,
                    host_name,
                    more,
                    entries,
                    mac: r.bytes()?,
                }
            }
            0x82 => {
                let req_id = r.bytes()?;
                let status = r.byte()?;
                if status > 2 {
                    return Err(Error::Value);
                }
                Self::Result {
                    req_id,
                    status,
                    mac: r.bytes()?,
                }
            }
            0x90 => Self::PairHost {
                host_pub: r.bytes()?,
                host_nonce: r.bytes()?,
                host_id: r.bytes()?,
                host_name: r.string()?,
            },
            0x91 => Self::PairResult {
                accepted: r.boolean()?,
                mac: r.bytes()?,
            },
            0xff => {
                let code = r.byte()?;
                if !(1..=4).contains(&code) {
                    return Err(Error::Value);
                }
                Self::Error { code }
            }
            _ => return Err(Error::Type),
        };
        if !r.0.is_empty() {
            return Err(Error::Trailing);
        }
        Ok(message)
    }
}
