//! Readable watch reference implementation. The caller renders `Show` entries,
//! invokes `tap` for one chosen entry, and owns scanning, timeouts and storage.
use crate::{
    Output, PairFailure,
    crypto::{self, Key, KeyPair},
    wire::{self, Entry, HostId, Message, Nonce, RequestId},
};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub enum Event {
    Show(Vec<Entry>),
    Result {
        req_id: RequestId,
        status: u8,
    },
    PairCode(String, String),
    Paired {
        key: Key,
        host_id: HostId,
        host_name: String,
    },
    PairFailed(PairFailure),
}

struct Pairing {
    ephemeral: Option<KeyPair>,
    watch_name: String,
    commit_message: Vec<u8>,
    derived: Option<(Key, [u8; 32], HostId, String)>,
    accepted: Option<bool>,
}

pub struct Session {
    host_id: HostId,
    key: Option<Key>,
    nonce: Nonce,
    pairing: Option<Pairing>,
    entries: Vec<Entry>,
    sent: BTreeSet<RequestId>,
    inflight: BTreeMap<RequestId, Nonce>,
    waiting_pending: bool,
    closed: bool,
    more: bool,
}

impl Session {
    pub fn authenticated(
        host_id: HostId,
        key: Key,
        rng: &mut impl CryptoRng,
    ) -> (Self, Output<Event>) {
        let mut nonce = [0; 16];
        rng.fill_bytes(&mut nonce);
        let session = Self {
            host_id,
            key: Some(key),
            nonce,
            pairing: None,
            entries: Vec::new(),
            sent: BTreeSet::new(),
            inflight: BTreeMap::new(),
            waiting_pending: true,
            closed: false,
            more: false,
        };
        let out = Output {
            messages: vec![
                Message::AuthHello { watch_nonce: nonce }
                    .encode()
                    .expect("fixed size"),
            ],
            events: Vec::new(),
        };
        (session, out)
    }

    pub fn pairing(watch_name: &str, rng: &mut impl CryptoRng) -> (Self, Output<Event>) {
        let ephemeral = KeyPair::random(rng);
        let mut nonce = [0; 16];
        rng.fill_bytes(&mut nonce);
        let commit_message = Message::PairCommit {
            commit: crypto::commitment(&ephemeral.public(), &nonce),
        }
        .encode()
        .expect("fixed size");
        let out = Output {
            messages: vec![commit_message.clone()],
            events: Vec::new(),
        };
        let session = Self {
            host_id: [0; 16],
            key: None,
            nonce,
            pairing: Some(Pairing {
                ephemeral: Some(ephemeral),
                watch_name: wire::truncate_str(watch_name).to_owned(),
                commit_message,
                derived: None,
                accepted: None,
            }),
            entries: Vec::new(),
            sent: BTreeSet::new(),
            inflight: BTreeMap::new(),
            waiting_pending: false,
            closed: false,
            more: false,
        };
        (session, out)
    }

    pub fn more(&self) -> bool {
        self.more
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn receive(&mut self, bytes: &[u8]) -> Result<Output<Event>, wire::Error> {
        if self.closed {
            return Err(wire::Error::Closed);
        }
        let result = Message::decode(bytes).and_then(|message| {
            if self.pairing.is_some() {
                self.receive_pair(message, bytes)
            } else {
                self.receive_auth(message, bytes)
            }
        });
        if result.is_err() {
            if self.pairing.is_some() {
                return Ok(self.fail_pair(PairFailure::Protocol));
            }
            self.close();
        }
        result
    }

    fn close(&mut self) {
        self.closed = true;
        self.key = None;
        self.pairing = None;
        self.entries.clear();
        self.inflight.clear();
    }

    fn receive_auth(
        &mut self,
        message: Message,
        bytes: &[u8],
    ) -> Result<Output<Event>, wire::Error> {
        let mut out = Output::default();
        let key = self.key.as_ref().ok_or(wire::Error::State)?;
        match message {
            Message::Pending {
                host_id,
                entries,
                more,
                mac,
                ..
            } if self.waiting_pending => {
                if host_id != self.host_id
                    || !crypto::constant_time_eq(
                        &mac,
                        &crypto::pending_mac(key, &self.nonce, &bytes[..bytes.len() - 32]),
                    )
                {
                    return Err(wire::Error::Value);
                }
                let mut ids = BTreeSet::new();
                if entries.iter().any(|entry| !ids.insert(entry.req_id)) {
                    return Err(wire::Error::Value);
                }
                self.more = more;
                self.waiting_pending = false;
                self.entries = entries
                    .into_iter()
                    .filter(|entry| !self.sent.contains(&entry.req_id))
                    .collect();
                // Largest age = oldest. Wire order breaks equal-age ties.
                let oldest = self
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| !entry.needs_confirm)
                    .max_by_key(|(index, entry)| (entry.age_s, std::cmp::Reverse(*index)))
                    .map(|(_, entry)| entry.req_id);
                if let Some(req_id) = oldest {
                    self.approve(req_id, &mut out)?;
                }
                out.events.push(Event::Show(
                    self.entries
                        .iter()
                        .filter(|entry| entry.needs_confirm)
                        .cloned()
                        .collect(),
                ));
            }
            Message::Result {
                req_id,
                status,
                mac,
            } => {
                let nonce = self.inflight.remove(&req_id).ok_or(wire::Error::State)?;
                if !crypto::constant_time_eq(
                    &mac,
                    &crypto::result_mac(key, &nonce, &req_id, status),
                ) {
                    return Err(wire::Error::Value);
                }
                out.events.push(Event::Result { req_id, status });
            }
            Message::Error { .. } => {
                self.close();
            }
            _ => return Err(wire::Error::State),
        }
        Ok(out)
    }

    fn approve(&mut self, req_id: RequestId, out: &mut Output<Event>) -> Result<(), wire::Error> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.req_id == req_id)
            .ok_or(wire::Error::State)?;
        let key = self.key.as_ref().ok_or(wire::Error::State)?;
        let entry = &self.entries[index];
        out.send(Message::Approve {
            req_id,
            mac: crypto::approve_mac(key, &self.host_id, &self.nonce, entry),
        })?;
        self.entries.remove(index);
        self.sent.insert(req_id);
        self.inflight.insert(req_id, self.nonce);
        Ok(())
    }

    /// Each call represents one explicit user tap on a displayed request.
    pub fn tap(&mut self, req_id: RequestId) -> Result<Output<Event>, wire::Error> {
        if self.closed {
            return Err(wire::Error::Closed);
        }
        if self.pairing.is_some()
            || !self
                .entries
                .iter()
                .any(|entry| entry.req_id == req_id && entry.needs_confirm)
        {
            return Err(wire::Error::State);
        }
        let mut out = Output::default();
        self.approve(req_id, &mut out)?;
        out.events.push(Event::Show(
            self.entries
                .iter()
                .filter(|entry| entry.needs_confirm)
                .cloned()
                .collect(),
        ));
        Ok(out)
    }

    /// Refresh only after all outstanding Result messages have arrived.
    pub fn refresh(&mut self, rng: &mut impl CryptoRng) -> Result<Output<Event>, wire::Error> {
        if self.closed {
            return Err(wire::Error::Closed);
        }
        if self.pairing.is_some() || self.waiting_pending || !self.inflight.is_empty() {
            return Err(wire::Error::State);
        }
        let mut nonce = [0; 16];
        rng.fill_bytes(&mut nonce);
        if nonce == self.nonce {
            return Err(wire::Error::Value);
        }
        self.nonce = nonce;
        self.entries.clear();
        self.waiting_pending = true;
        let mut out = Output::default();
        out.send(Message::AuthHello { watch_nonce: nonce })?;
        Ok(out)
    }

    fn fail_pair(&mut self, reason: PairFailure) -> Output<Event> {
        self.close();
        Output {
            messages: Vec::new(),
            events: vec![Event::PairFailed(reason)],
        }
    }

    fn receive_pair(
        &mut self,
        message: Message,
        bytes: &[u8],
    ) -> Result<Output<Event>, wire::Error> {
        let mut out = Output::default();
        let pair = self.pairing.as_mut().ok_or(wire::Error::State)?;
        match message {
            Message::PairHost {
                host_pub,
                host_nonce,
                host_id,
                host_name,
            } if pair.derived.is_none() => {
                let ephemeral = pair.ephemeral.take().ok_or(wire::Error::State)?;
                let key = match ephemeral.derive_key(&host_pub, &host_nonce, &self.nonce, &host_id)
                {
                    Ok(key) => key,
                    Err(_) => return Ok(self.fail_pair(PairFailure::InvalidKey)),
                };
                let reveal = Message::PairReveal {
                    watch_pub: ephemeral.public(),
                    watch_nonce: self.nonce,
                    watch_name: pair.watch_name.clone(),
                }
                .encode()?;
                let th = crypto::transcript(&pair.commit_message, bytes, &reveal);
                out.events
                    .push(Event::PairCode(crypto::sas(&key, &th), host_name.clone()));
                out.messages.push(reveal);
                pair.derived = Some((key, th, host_id, host_name));
            }
            Message::PairResult {
                accepted: false, ..
            } => return Ok(self.fail_pair(PairFailure::Rejected)),
            Message::PairResult {
                accepted: true,
                mac,
            } if pair.accepted == Some(true) => {
                let (key, th, _, _) = pair.derived.as_ref().ok_or(wire::Error::State)?;
                if !crypto::constant_time_eq(&mac, &crypto::host_confirm_mac(key, th)) {
                    return Ok(self.fail_pair(PairFailure::BadMac));
                }
                let (key, _, host_id, host_name) = self
                    .pairing
                    .take()
                    .and_then(|p| p.derived)
                    .ok_or(wire::Error::State)?;
                out.events.push(Event::Paired {
                    key,
                    host_id,
                    host_name,
                });
                self.close();
            }
            _ => return Err(wire::Error::State),
        }
        Ok(out)
    }

    pub fn confirm_pairing(&mut self, accept: bool) -> Result<Output<Event>, wire::Error> {
        if self.closed {
            return Err(wire::Error::Closed);
        }
        let pair = self.pairing.as_mut().ok_or(wire::Error::State)?;
        let (key, th, _, _) = pair.derived.as_ref().ok_or(wire::Error::State)?;
        if pair.accepted.is_some() {
            return Err(wire::Error::State);
        }
        let mut out = Output::default();
        out.send(Message::PairConfirm {
            accepted: accept,
            mac: crypto::watch_confirm_mac(key, th, accept),
        })?;
        pair.accepted = Some(accept);
        if !accept {
            self.close();
            out.events.push(Event::PairFailed(PairFailure::Rejected));
        }
        Ok(out)
    }
}
