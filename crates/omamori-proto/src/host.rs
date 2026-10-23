//! PC session. `set_pending` supplies the authoritative current queue; call it
//! before processing incoming messages when requests are cancelled or changed.
use crate::{
    Output, PairFailure,
    crypto::{self, Key, KeyPair},
    wire::{self, Entry, HostId, Message, Nonce, RequestId},
};
use rand_core::CryptoRng;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub enum Event {
    Approved(RequestId),
    PairCode(String, String),
    Paired { key: Key, watch_name: String },
    PairFailed(PairFailure),
}

struct Pairing {
    commit: Option<([u8; 32], Vec<u8>)>,
    ephemeral: Option<KeyPair>,
    host_nonce: Nonce,
    host_message: Vec<u8>,
    derived: Option<(Key, [u8; 32], String)>,
    local_accept: Option<bool>,
    watch_accept: Option<bool>,
}

pub struct Session {
    host_id: HostId,
    host_name: String,
    key: Option<Key>,
    pairing: Option<Pairing>,
    nonce: Option<Nonce>,
    seen_nonces: BTreeSet<Nonce>,
    pending: BTreeMap<RequestId, Entry>,
    listed: BTreeMap<RequestId, Entry>,
    approved: BTreeSet<RequestId>,
    closed: bool,
}

impl Session {
    pub fn authenticated(host_id: HostId, host_name: &str, key: Key) -> Self {
        let mut session = Self::pairing(host_id, host_name);
        session.pairing = None;
        session.key = Some(key);
        session
    }

    pub fn pairing(host_id: HostId, host_name: &str) -> Self {
        Self {
            host_id,
            host_name: wire::truncate_str(host_name).to_owned(),
            key: None,
            pairing: Some(Pairing {
                commit: None,
                ephemeral: None,
                host_nonce: [0; 16],
                host_message: Vec::new(),
                derived: None,
                local_accept: None,
                watch_accept: None,
            }),
            nonce: None,
            seen_nonces: BTreeSet::new(),
            pending: BTreeMap::new(),
            listed: BTreeMap::new(),
            approved: BTreeSet::new(),
            closed: false,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Replaces the current snapshot. Duplicate IDs are a caller error.
    /// Changes invalidate prior listings permanently until a new Pending is sent.
    /// Keep original strings so even changes beyond the wire truncation boundary
    /// invalidate an approval for the previously listed request.
    pub fn set_pending(&mut self, entries: Vec<Entry>) -> Result<(), wire::Error> {
        let mut pending = BTreeMap::new();
        for entry in entries {
            if pending.insert(entry.req_id, entry).is_some() {
                return Err(wire::Error::Value);
            }
        }
        self.listed
            .retain(|id, old| pending.get(id).is_some_and(|new| old.same_request(new)));
        self.pending = pending;
        Ok(())
    }

    pub fn receive(
        &mut self,
        bytes: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Output<Event>, wire::Error> {
        if self.closed {
            return Err(wire::Error::Closed);
        }
        let result = Message::decode(bytes).and_then(|message| {
            if self.pairing.is_some() {
                self.receive_pair(message, bytes, rng)
            } else {
                self.receive_auth(message)
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
        self.nonce = None;
        self.listed.clear();
    }

    fn receive_auth(&mut self, message: Message) -> Result<Output<Event>, wire::Error> {
        let mut out = Output::default();
        let key = self.key.as_ref().ok_or(wire::Error::State)?;
        match message {
            Message::AuthHello { watch_nonce } => {
                // A refresh must use a fresh nonce, otherwise old approvals replay.
                if !self.seen_nonces.insert(watch_nonce) {
                    return Err(wire::Error::State);
                }
                self.nonce = Some(watch_nonce);
                let mut entries: Vec<_> = self
                    .pending
                    .values()
                    .filter(|e| !self.approved.contains(&e.req_id))
                    .cloned()
                    .collect();
                entries.sort_by_key(|e| (std::cmp::Reverse(e.age_s), e.req_id));
                let mut size = 2 + 16 + 1 + self.host_name.len() + 2 + 32;
                let count = entries
                    .iter()
                    .take_while(|e| {
                        let len = 14
                            + wire::truncate_to(&e.title, 48).len()
                            + wire::truncate_to(&e.detail, 160).len();
                        if size + len > crate::framing::MAX_MESSAGE {
                            return false;
                        }
                        size += len;
                        true
                    })
                    .count();
                let more = count < entries.len();
                entries.truncate(count);
                let mut message = Message::Pending {
                    host_id: self.host_id,
                    host_name: self.host_name.clone(),
                    more,
                    entries: entries.clone(),
                    mac: [0; 32],
                };
                let encoded = message.encode()?;
                if let Message::Pending { mac, .. } = &mut message {
                    *mac = crypto::pending_mac(key, &watch_nonce, &encoded[..encoded.len() - 32]);
                }
                out.send(message)?;
                // Prior listings remain valid within this connection, but must
                // still match the current queue when an approval arrives.
                for entry in entries {
                    self.listed.insert(entry.req_id, entry);
                }
            }
            Message::Approve { req_id, mac } => {
                let nonce = self.nonce.ok_or(wire::Error::State)?;
                let entry = self.pending.get(&req_id).filter(|entry| {
                    !self.approved.contains(&req_id)
                        && self
                            .listed
                            .get(&req_id)
                            .is_some_and(|listed| listed.same_request(entry))
                });
                let status = if let Some(entry) = entry {
                    if !crypto::constant_time_eq(
                        &mac,
                        &crypto::approve_mac(key, &self.host_id, &nonce, entry),
                    ) {
                        out.send(Message::Result {
                            req_id,
                            status: 2,
                            mac: crypto::result_mac(key, &nonce, &req_id, 2),
                        })?;
                        self.close();
                        return Ok(out);
                    }
                    self.approved.insert(req_id);
                    out.events.push(Event::Approved(req_id));
                    0
                } else {
                    1
                };
                out.send(Message::Result {
                    req_id,
                    status,
                    mac: crypto::result_mac(key, &nonce, &req_id, status),
                })?;
            }
            _ => return Err(wire::Error::State),
        }
        Ok(out)
    }

    fn fail_pair(&mut self, reason: PairFailure) -> Output<Event> {
        self.close();
        Output {
            messages: vec![
                Message::PairResult {
                    accepted: false,
                    mac: [0; 32],
                }
                .encode()
                .expect("fixed size"),
            ],
            events: vec![Event::PairFailed(reason)],
        }
    }

    fn receive_pair(
        &mut self,
        message: Message,
        bytes: &[u8],
        rng: &mut impl CryptoRng,
    ) -> Result<Output<Event>, wire::Error> {
        let mut out = Output::default();
        let pair = self.pairing.as_mut().ok_or(wire::Error::State)?;
        match message {
            Message::PairCommit { commit } if pair.commit.is_none() => {
                let ephemeral = KeyPair::random(rng);
                rng.fill_bytes(&mut pair.host_nonce);
                let host = Message::PairHost {
                    host_pub: ephemeral.public(),
                    host_nonce: pair.host_nonce,
                    host_id: self.host_id,
                    host_name: self.host_name.clone(),
                }
                .encode()?;
                pair.ephemeral = Some(ephemeral);
                pair.commit = Some((commit, bytes.to_vec()));
                pair.host_message = host.clone();
                out.messages.push(host);
            }
            Message::PairReveal {
                watch_pub,
                watch_nonce,
                watch_name,
            } if pair.commit.is_some() && pair.derived.is_none() => {
                let (commit, commit_bytes) = pair.commit.as_ref().ok_or(wire::Error::State)?;
                if !crypto::constant_time_eq(commit, &crypto::commitment(&watch_pub, &watch_nonce))
                {
                    return Ok(self.fail_pair(PairFailure::Commitment));
                }
                let ephemeral = pair.ephemeral.take().ok_or(wire::Error::State)?;
                let key = match ephemeral.derive_key(
                    &watch_pub,
                    &pair.host_nonce,
                    &watch_nonce,
                    &self.host_id,
                ) {
                    Ok(key) => key,
                    Err(_) => return Ok(self.fail_pair(PairFailure::InvalidKey)),
                };
                let th = crypto::transcript(commit_bytes, &pair.host_message, bytes);
                out.events
                    .push(Event::PairCode(crypto::sas(&key, &th), watch_name.clone()));
                pair.derived = Some((key, th, watch_name));
            }
            Message::PairConfirm { accepted, mac }
                if pair.derived.is_some() && pair.watch_accept.is_none() =>
            {
                let (key, th, _) = pair.derived.as_ref().ok_or(wire::Error::State)?;
                if !crypto::constant_time_eq(&mac, &crypto::watch_confirm_mac(key, th, accepted)) {
                    return Ok(self.fail_pair(PairFailure::BadMac));
                }
                if !accepted {
                    return Ok(self.fail_pair(PairFailure::Rejected));
                }
                pair.watch_accept = Some(true);
                return self.finish_pair();
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
        if pair.derived.is_none() || pair.local_accept.is_some() {
            return Err(wire::Error::State);
        }
        if !accept {
            return Ok(self.fail_pair(PairFailure::Rejected));
        }
        pair.local_accept = Some(true);
        self.finish_pair()
    }

    fn finish_pair(&mut self) -> Result<Output<Event>, wire::Error> {
        let pair = self.pairing.as_ref().ok_or(wire::Error::State)?;
        if pair.local_accept != Some(true) || pair.watch_accept != Some(true) {
            return Ok(Output::default());
        }
        let (key, th, watch_name) = self
            .pairing
            .take()
            .and_then(|p| p.derived)
            .ok_or(wire::Error::State)?;
        let mut out = Output::default();
        out.send(Message::PairResult {
            accepted: true,
            mac: crypto::host_confirm_mac(&key, &th),
        })?;
        out.events.push(Event::Paired { key, watch_name });
        self.close();
        Ok(out)
    }
}
