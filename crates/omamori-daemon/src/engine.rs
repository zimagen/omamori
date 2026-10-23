use crate::{
    config::{Approval, Config},
    ipc::Policy,
    state::{Pairing, State, Store},
    transport::{Event, Transport},
};
use anyhow::Result;
use getrandom::SysRng;
use omamori_proto::{
    Output,
    crypto::Key,
    framing::{self, Reassembler},
    host,
    wire::{self, Entry, Kind, RequestId},
};
use rand_core::{Rng, UnwrapErr};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use tokio::{sync::mpsc, time::Instant};

use omamori_ipc::{Input, RequestKind};
pub(crate) enum Command {
    Ipc {
        id: u64,
        uid: u32,
        name: String,
        input: Input,
        reply: mpsc::Sender<Value>,
    },
    Disconnect(u64),
}
struct Request {
    conn: u64,
    uid: u32,
    entry: Entry,
    created: Instant,
    reply: mpsc::Sender<Value>,
}
struct PairOwner {
    conn: u64,
    started: Instant,
    reply: mpsc::Sender<Value>,
}
pub(crate) struct Engine<T> {
    config: Config,
    store: Store,
    state: State,
    transport: T,
    policy: Policy,
    requests: BTreeMap<RequestId, Request>,
    pairing: Option<PairOwner>,
    session: Option<host::Session>,
    reassembler: Reassembler,
    connected: bool,
    advertising: Option<[u8; 9]>,
    boost_until: Option<Instant>,
    advertising_fast: bool,
    last_activity: Instant,
    connected_at: Option<Instant>,
    // Retain the queue origin through removal of the final approved request.
    timing_queued_at: Option<Instant>,
}
fn emit(reply: &mpsc::Sender<Value>, value: Value) {
    let _ = reply.try_send(value);
}
fn unavailable(reply: &mpsc::Sender<Value>, reason: &str) {
    emit(reply, json!({"ev":"unavailable","reason":reason}));
}
fn denied(reply: &mpsc::Sender<Value>, reason: &str) {
    emit(reply, json!({"ev":"denied","reason":reason}));
}
fn hex(id: &RequestId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

impl<T: Transport> Engine<T> {
    pub(crate) fn new(
        config: Config,
        store: Store,
        state: State,
        transport: T,
        policy: Policy,
    ) -> Self {
        Self {
            config,
            store,
            state,
            transport,
            policy,
            requests: BTreeMap::new(),
            pairing: None,
            session: None,
            reassembler: Reassembler::new(20).expect("valid chunk size"),
            connected: false,
            advertising: None,
            boost_until: None,
            advertising_fast: false,
            last_activity: Instant::now(),
            connected_at: None,
            timing_queued_at: None,
        }
    }
    fn boost(&mut self) {
        self.boost_until =
            Some(Instant::now() + Duration::from_secs(self.config.adv_boost_secs.into()));
    }
    fn queued_at(&self) -> Option<Instant> {
        self.requests.values().map(|r| r.created).min()
    }
    fn log_timing(&self, message: &'static str, queued_at: Option<Instant>, count: Option<usize>) {
        let since_queued_ms = queued_at.map(|t| t.elapsed().as_millis() as u64);
        let since_connect_ms = self.connected_at.map(|t| t.elapsed().as_millis() as u64);
        let mode = self
            .advertising
            .map(|data| if data[8] & 1 != 0 { "pairing" } else { "auth" });
        tracing::info!(since_queued_ms, since_connect_ms, count, mode, "{message}");
    }
    fn log_session_timing(&self, message: &'static str, count: Option<usize>) {
        self.log_timing(message, self.queued_at().or(self.timing_queued_at), count);
    }
    async fn reset(&mut self) {
        self.session = None;
        self.reassembler.reset();
        self.connected = false;
        self.connected_at = None;
        if let Err(e) = self.transport.disconnect().await {
            tracing::warn!(error = %e, "BLE disconnect failed");
        }
    }
    fn fail_pair(&mut self, reason: &str) {
        if let Some(owner) = self.pairing.take() {
            tracing::info!(result = "failed", reason, "pairing session ended");
            emit(&owner.reply, json!({"ev":"pair-failed","reason":reason}));
        }
    }
    fn prune(&mut self) {
        self.requests.retain(|_, r| !r.reply.is_closed());
    }
    async fn command(&mut self, command: Command) -> Result<()> {
        match command {
            Command::Disconnect(id) => {
                self.requests.retain(|_, r| r.conn != id);
                if self.pairing.as_ref().is_some_and(|p| p.conn == id) {
                    self.fail_pair("client-disconnected");
                    self.reset().await;
                }
            }
            Command::Ipc {
                id,
                uid,
                name,
                input,
                reply,
            } => {
                let root = self.policy.is_root(uid);
                match input {
                    Input::Boost {} => {
                        if self.requests.values().any(|r| root || r.uid == uid) {
                            self.boost();
                            emit(&reply, json!({"ev":"boosted"}));
                        } else {
                            denied(&reply, "no-request");
                        }
                    }
                    Input::Status {} => {
                        let pending: Vec<_> = self
                            .requests
                            .values()
                            .filter(|r| root || r.uid == uid)
                            .map(|r| {
                                json!({"id":hex(&r.entry.req_id),"uid":r.uid,
                                "kind":if r.entry.kind == Kind::Lock {"lock"} else {"sudo"},
                                "title":r.entry.title,"detail":r.entry.detail})
                            })
                            .collect();
                        emit(
                            &reply,
                            json!({"ev":"status","paired":self.state.pairing.is_some(),
                            "watch_name":self.state.pairing.as_ref().map(|p| &p.watch_name),
                            "host_name":self.config.host_name,"adapter_powered":self.transport.powered(),
                            "advertising":self.advertising.is_some(),"pending":pending}),
                        );
                    }
                    Input::Request {
                        kind,
                        user,
                        command,
                        tty,
                        pid,
                    } => {
                        let kind = match kind {
                            RequestKind::Sudo if root => Kind::Sudo,
                            RequestKind::Lock if !root && user == name => Kind::Lock,
                            _ => {
                                denied(&reply, "identity");
                                return Ok(());
                            }
                        };
                        if kind == Kind::Sudo
                            && (command.is_none() || tty.is_none() || pid.is_none())
                        {
                            denied(&reply, "missing-fields");
                            return Ok(());
                        }
                        if kind == Kind::Lock
                            && (command.is_some() || tty.is_some() || pid.is_some())
                        {
                            denied(&reply, "unexpected-fields");
                            return Ok(());
                        }
                        if self.requests.values().any(|r| r.conn == id) {
                            denied(&reply, "one-request-per-connection");
                            return Ok(());
                        }
                        if (kind == Kind::Sudo && !self.config.sudo)
                            || (kind == Kind::Lock && !self.config.lock)
                        {
                            unavailable(&reply, "disabled");
                            return Ok(());
                        }
                        if self.state.pairing.is_none() {
                            unavailable(&reply, "not-paired");
                            return Ok(());
                        }
                        if !self.transport.powered() {
                            unavailable(&reply, "no-adapter");
                            return Ok(());
                        }
                        if self.requests.len() >= 16
                            || self.requests.values().filter(|r| r.uid == uid).count() >= 4
                        {
                            unavailable(&reply, "busy");
                            return Ok(());
                        }
                        let mut req_id = [0; 8];
                        loop {
                            UnwrapErr(SysRng).fill_bytes(&mut req_id);
                            if !self.requests.contains_key(&req_id) {
                                break;
                            }
                        }
                        let command = wire::truncate_to(command.as_deref().unwrap_or(""), 256);
                        let tty = wire::truncate_to(tty.as_deref().unwrap_or(""), 32);
                        tracing::debug!(command, tty, "request received");
                        let entry = Entry {
                            req_id,
                            kind,
                            age_s: 0,
                            needs_confirm: kind == Kind::Sudo
                                && self.config.approval == Approval::PerType,
                            title: format!(
                                "{user}: {}",
                                if kind == Kind::Lock { "unlock" } else { "sudo" }
                            ),
                            detail: if kind == Kind::Sudo {
                                format!("{tty}: {command}")
                            } else {
                                String::new()
                            },
                        };
                        emit(&reply, json!({"ev":"queued","id":hex(&req_id)}));
                        self.boost();
                        let created = Instant::now();
                        let since_connect_ms =
                            self.connected_at.map(|t| t.elapsed().as_millis() as u64);
                        tracing::info!(
                            kind = if kind == Kind::Lock { "lock" } else { "sudo" },
                            since_queued_ms = 0_u64,
                            since_connect_ms,
                            "request queued"
                        );
                        self.requests.insert(
                            req_id,
                            Request {
                                conn: id,
                                uid,
                                entry,
                                created,
                                reply,
                            },
                        );
                    }
                    Input::PairBegin {} => {
                        if !root {
                            denied(&reply, "root-required");
                        } else if self.pairing.is_some() {
                            unavailable(&reply, "busy");
                        } else if !self.transport.powered() {
                            unavailable(&reply, "no-adapter");
                        } else {
                            self.reset().await;
                            self.boost();
                            tracing::info!("pairing session started");
                            self.pairing = Some(PairOwner {
                                conn: id,
                                started: Instant::now(),
                                reply,
                            });
                        }
                    }
                    Input::PairConfirm { accept } => {
                        if !root {
                            denied(&reply, "root-required");
                        } else if !self.pairing.as_ref().is_some_and(|p| p.conn == id) {
                            denied(&reply, "not-pairing-owner");
                        } else if let Some(session) = self.session.as_mut() {
                            match session.confirm_pairing(accept) {
                                Ok(out) => self.output(out).await?,
                                Err(_) => {
                                    self.fail_pair("protocol");
                                    self.reset().await;
                                }
                            }
                        } else {
                            self.fail_pair("no-code");
                            self.reset().await;
                        }
                    }
                    Input::Unpair {} => {
                        if !root {
                            denied(&reply, "root-required");
                        } else {
                            let mut state = self.state.clone();
                            state.pairing = None;
                            self.store.save(&state)?;
                            self.state = state;
                            self.fail_pair("unpaired");
                            self.reset().await;
                            for (_, r) in std::mem::take(&mut self.requests) {
                                unavailable(&r.reply, "not-paired");
                            }
                            emit(&reply, json!({"ev":"status","paired":false}));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn snapshot(&self) -> Vec<Entry> {
        self.requests
            .values()
            .map(|r| Entry {
                age_s: r.created.elapsed().as_secs().min(u64::from(u16::MAX)) as u16,
                ..r.entry.clone()
            })
            .collect()
    }
    async fn output(&mut self, out: Output<host::Event>) -> Result<()> {
        // Persist a new pairing before exposing its success to either peer.
        let mut completed_pair = false;
        for event in out.events {
            match event {
                host::Event::Approved(id) => {
                    if let Some(r) = self.requests.remove(&id)
                        && r.reply.try_send(json!({"ev":"approved"})).is_ok()
                    {
                        self.log_timing("approval delivered to IPC client", Some(r.created), None);
                    }
                }
                host::Event::PairCode(code, watch_name) => {
                    if let Some(owner) = &self.pairing {
                        emit(
                            &owner.reply,
                            json!({"ev":"pair-code","code":code,"watch_name":watch_name}),
                        );
                    }
                }
                host::Event::Paired { key, watch_name } => {
                    let mut state = self.state.clone();
                    state.pairing = Some(Pairing::new(watch_name, key));
                    self.store.save(&state)?;
                    self.state = state;
                    completed_pair = true;
                }
                host::Event::PairFailed(reason) => self.fail_pair(&format!("{reason:?}")),
            }
        }
        for message in out.messages {
            let decoded = wire::Message::decode(&message);
            if matches!(decoded, Ok(wire::Message::Result { status: 2, .. })) {
                tracing::warn!("bad approval MAC; closing BLE session");
            }
            for chunk in framing::chunk(&message, 20)
                .map_err(|e| anyhow::anyhow!("outgoing frame: {e:?}"))?
            {
                self.transport.send(chunk).await?;
            }
            if let Ok(wire::Message::Pending { entries, .. }) = decoded {
                self.log_session_timing("Pending sent", Some(entries.len()));
            }
        }
        if completed_pair && let Some(owner) = self.pairing.take() {
            tracing::info!(result = "success", "pairing session ended");
            emit(&owner.reply, json!({"ev":"pair-done"}));
        }
        if self.session.as_ref().is_some_and(|s| s.is_closed()) {
            self.reset().await;
        }
        Ok(())
    }
    async fn transport_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Connected => {
                if self.connected {
                    return Ok(());
                }
                if self.requests.is_empty() && self.pairing.is_none() {
                    self.reset().await;
                    return Ok(());
                }
                self.connected = true;
                self.connected_at = Some(Instant::now());
                self.timing_queued_at = self.queued_at();
                self.log_session_timing("central connected", None);
                self.reassembler.reset();
                self.session = if self.pairing.is_some() {
                    Some(host::Session::pairing(
                        self.state.host_id,
                        &self.config.host_name,
                    ))
                } else {
                    self.state.pairing.as_ref().map(|p| {
                        host::Session::authenticated(
                            self.state.host_id,
                            &self.config.host_name,
                            Key::new(p.key),
                        )
                    })
                };
                self.last_activity = Instant::now();
            }
            Event::Disconnected => {
                self.fail_pair("disconnected");
                self.reset().await;
            }
            Event::Powered(false) => {
                self.fail_pair("no-adapter");
                self.reset().await;
                for (_, r) in std::mem::take(&mut self.requests) {
                    unavailable(&r.reply, "no-adapter");
                }
            }
            Event::Powered(true) => {}
            Event::Bytes(chunk) => {
                if !self.connected {
                    return Ok(());
                }
                self.last_activity = Instant::now();
                let bytes = match self.reassembler.receive(&chunk) {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => return Ok(()),
                    Err(_) => {
                        self.fail_pair("framing");
                        self.reset().await;
                        return Ok(());
                    }
                };
                match wire::Message::decode(&bytes) {
                    Ok(wire::Message::AuthHello { .. }) => {
                        self.log_session_timing("AuthHello received", None);
                    }
                    Ok(wire::Message::Approve { req_id, .. }) => {
                        self.log_timing(
                            "Approve received",
                            self.requests.get(&req_id).map(|r| r.created),
                            None,
                        );
                    }
                    _ => {}
                }
                let snapshot = self.snapshot();
                if let Some(session) = self.session.as_mut() {
                    session.set_pending(snapshot)?;
                    match session.receive(&bytes, &mut UnwrapErr(SysRng)) {
                        Ok(out) => self.output(out).await?,
                        Err(_) => {
                            self.fail_pair("protocol");
                            self.reset().await;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn log_advertising_stopped(&mut self) {
        if self.advertising.is_some() {
            self.log_session_timing("advertising stopped", None);
            self.advertising = None;
            self.timing_queued_at = None;
        }
    }
    async fn update_advertising(&mut self) {
        // The existing registration is inactive while connected. Defer all
        // changes until disconnect so interval transitions cannot disrupt it.
        if self.connected {
            return;
        }
        let fast =
            self.pairing.is_some() || self.boost_until.is_some_and(|until| Instant::now() < until);
        let interval_ms = if fast {
            self.config.adv_interval_ms
        } else {
            self.config.adv_slow_interval_ms
        };
        let wanted =
            if self.transport.powered() && (!self.requests.is_empty() || self.pairing.is_some()) {
                let mut data = [0; 9];
                data[..8].copy_from_slice(&self.state.host_id[..8]);
                data[8] = u8::from(self.pairing.is_some());
                Some(data)
            } else {
                None
            };
        if wanted != self.advertising || (wanted.is_some() && fast != self.advertising_fast) {
            // BlueZ drops the previous registration before replacing it.
            self.log_advertising_stopped();
            if let Err(e) = self.transport.advertise(wanted, interval_ms).await {
                tracing::warn!(error = %e, "BLE advertisement registration failed");
                if let Some(owner) = self.pairing.take() {
                    tracing::info!(
                        result = "failed",
                        reason = "advertise-failed",
                        "pairing session ended"
                    );
                    unavailable(&owner.reply, "advertise-failed");
                }
                for (_, r) in std::mem::take(&mut self.requests) {
                    unavailable(&r.reply, "advertise-failed");
                }
                self.reset().await;
                return;
            }
            self.advertising = wanted;
            self.advertising_fast = fast;
            if wanted.is_some() {
                let [min_ms, max_ms] = interval_ms;
                if fast {
                    tracing::info!(min_ms, max_ms, "advertising interval fast");
                } else {
                    tracing::info!(min_ms, max_ms, "advertising interval slow");
                }
                self.timing_queued_at = self.queued_at();
                self.log_session_timing("advertising started", None);
            }
        }
    }
    pub(crate) async fn run(mut self, mut commands: mpsc::Receiver<Command>) -> Result<()> {
        let mut timer = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                biased;
                command = commands.recv() => {
                    let Some(command) = command else { break; };
                    self.prune();
                    self.command(command).await?;
                }
                event = self.transport.recv() => {
                    let Some(event) = event else { break; };
                    self.prune();
                    if self.pairing.as_ref().is_some_and(|p| p.reply.is_closed()) {
                        self.fail_pair("client-disconnected"); self.reset().await;
                    }
                    if let Err(e) = self.transport_event(event).await {
                        tracing::warn!(error = %e, "BLE session failed");
                        self.fail_pair("io"); self.reset().await;
                    }
                }
                _ = timer.tick() => {
                    self.prune();
                    if self.pairing.as_ref().is_some_and(|p| p.reply.is_closed() || p.started.elapsed() >= Duration::from_secs(120)) {
                        self.fail_pair("timeout"); self.reset().await;
                    } else if self.connected && self.pairing.is_none() && self.last_activity.elapsed() >= Duration::from_secs(60) {
                        self.reset().await;
                    }
                }
            }
            self.update_advertising().await;
        }
        let _ = self
            .transport
            .advertise(None, self.config.adv_slow_interval_ms)
            .await;
        self.log_advertising_stopped();
        self.fail_pair("shutdown");
        self.reset().await;
        Ok(())
    }
}

#[cfg(all(test, feature = "test-harness"))]
mod tests {
    use super::*;
    use crate::transport::fake;
    use tokio::sync::mpsc;

    fn engine() -> (tempfile::TempDir, Engine<fake::Fake>, fake::Peer) {
        let temp = tempfile::tempdir().unwrap();
        let (store, mut state) = Store::open(&temp.path().join("state")).unwrap();
        state.pairing = Some(Pairing::new("Watch".into(), Key::new([7; 32])));
        let (transport, peer) = fake::pair();
        (
            temp,
            Engine::new(
                Config::default(),
                store,
                state,
                transport,
                Policy::default(),
            ),
            peer,
        )
    }
    async fn input(
        engine: &mut Engine<fake::Fake>,
        id: u64,
        uid: u32,
        input: Input,
    ) -> mpsc::Receiver<Value> {
        let (reply, events) = mpsc::channel(32);
        engine
            .command(Command::Ipc {
                id,
                uid,
                name: format!("user{uid}"),
                input,
                reply,
            })
            .await
            .unwrap();
        events
    }

    fn lock_request() -> Input {
        Input::Request {
            kind: RequestKind::Lock,
            user: "user1000".into(),
            command: None,
            tty: None,
            pid: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn request_boost_window_and_uid_authorization() {
        let (_temp, mut engine, mut peer) = engine();
        let _client = input(&mut engine, 1, 1000, lock_request()).await;
        let (tx, rx) = mpsc::channel(16);
        let task = tokio::spawn(engine.run(rx));
        assert_eq!(peer.intervals.recv().await.unwrap(), Some([20, 30]));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(peer.intervals.recv().await.unwrap(), Some([1000, 1200]));
        for (uid, expected) in [
            (1001, json!({"ev":"denied","reason":"no-request"})),
            (1000, json!({"ev":"boosted"})),
        ] {
            let (reply, mut events) = mpsc::channel(8);
            tx.send(Command::Ipc {
                id: 2,
                uid,
                name: format!("user{uid}"),
                input: Input::Boost {},
                reply,
            })
            .await
            .unwrap();
            assert_eq!(events.recv().await.unwrap(), expected);
            if uid == 1001 {
                assert!(peer.intervals.try_recv().is_err());
            }
        }
        assert_eq!(peer.intervals.recv().await.unwrap(), Some([20, 30]));
        // Extending an active window must not re-register the advertisement.
        tokio::time::advance(Duration::from_secs(20)).await;
        let (reply, mut events) = mpsc::channel(8);
        tx.send(Command::Ipc {
            id: 3,
            uid: 0,
            name: "root".into(),
            input: Input::Boost {},
            reply,
        })
        .await
        .unwrap();
        assert_eq!(events.recv().await.unwrap(), json!({"ev":"boosted"}));
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        assert!(peer.intervals.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(peer.intervals.recv().await.unwrap(), Some([1000, 1200]));
        drop(tx);
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pairing_stays_fast_past_boost_window() {
        let (_temp, mut engine, mut peer) = engine();
        let _client = input(&mut engine, 1, 0, Input::PairBegin {}).await;
        let (tx, rx) = mpsc::channel(16);
        let task = tokio::spawn(engine.run(rx));
        assert_eq!(peer.intervals.recv().await.unwrap(), Some([20, 30]));
        tokio::time::advance(Duration::from_secs(119)).await;
        tokio::task::yield_now().await;
        assert!(peer.intervals.try_recv().is_err());
        assert_eq!(peer.advertising.borrow().unwrap()[8], 1);
        drop(tx);
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn connected_central_defers_interval_changes_until_disconnect() {
        let (_temp, mut engine, mut peer) = engine();
        let _client = input(&mut engine, 1, 1000, lock_request()).await;
        engine.update_advertising().await;
        assert_eq!(peer.intervals.try_recv().unwrap(), Some([20, 30]));
        engine.transport_event(Event::Connected).await.unwrap();
        tokio::time::advance(Duration::from_secs(30)).await;
        engine.update_advertising().await;
        assert!(peer.intervals.try_recv().is_err());
        let mut boosted = input(&mut engine, 2, 1000, Input::Boost {}).await;
        assert_eq!(boosted.recv().await.unwrap(), json!({"ev":"boosted"}));
        engine.update_advertising().await;
        assert!(peer.intervals.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(30)).await;
        engine.transport_event(Event::Disconnected).await.unwrap();
        engine.update_advertising().await;
        assert_eq!(peer.intervals.try_recv().unwrap(), Some([1000, 1200]));
        engine.command(Command::Disconnect(1)).await.unwrap();
        let mut denied = input(&mut engine, 3, 0, Input::Boost {}).await;
        assert_eq!(
            denied.recv().await.unwrap(),
            json!({"ev":"denied","reason":"no-request"})
        );
    }

    #[tokio::test]
    async fn status_uid_filter_root_view_and_total_limit() {
        let (_temp, mut engine, _peer) = engine();
        let mut clients = Vec::new();
        for id in 0..16u64 {
            let uid = (id / 4) as u32 + 1000;
            let mut events = input(
                &mut engine,
                id,
                uid,
                Input::Request {
                    kind: RequestKind::Lock,
                    user: format!("user{uid}"),
                    command: None,
                    tty: None,
                    pid: None,
                },
            )
            .await;
            assert_eq!(events.recv().await.unwrap()["ev"], "queued");
            clients.push(events);
        }
        let mut overflow = input(
            &mut engine,
            99,
            2000,
            Input::Request {
                kind: RequestKind::Lock,
                user: "user2000".into(),
                command: None,
                tty: None,
                pid: None,
            },
        )
        .await;
        assert_eq!(
            overflow.recv().await.unwrap(),
            json!({"ev":"unavailable","reason":"busy"})
        );
        for (uid, count) in [(1000, 4), (1001, 4), (2000, 0), (0, 16)] {
            let mut response = input(&mut engine, 100, uid, Input::Status {}).await;
            let status = response.recv().await.unwrap();
            let pending = status["pending"].as_array().unwrap();
            assert_eq!(pending.len(), count);
            if uid != 0 {
                assert!(pending.iter().all(|r| r["uid"] == uid));
            }
        }
    }

    #[tokio::test]
    async fn advertisement_failure_replies_to_all_callers_and_allows_retry() {
        for pairing in [false, true] {
            let (_temp, mut engine, peer) = engine();
            let mut clients = Vec::new();
            for id in 1..=2 {
                let mut events = input(
                    &mut engine,
                    id,
                    1000,
                    Input::Request {
                        kind: RequestKind::Lock,
                        user: "user1000".into(),
                        command: None,
                        tty: None,
                        pid: None,
                    },
                )
                .await;
                assert_eq!(events.recv().await.unwrap()["ev"], "queued");
                clients.push(events);
            }
            if pairing {
                // Also cover failure when replacing an active auth advertisement.
                engine.update_advertising().await;
                assert!(peer.advertising.borrow().is_some());
                clients.push(input(&mut engine, 3, 0, Input::PairBegin {}).await);
            }
            engine.transport.fail_advertise = true;
            engine.update_advertising().await;
            for mut events in clients {
                assert_eq!(
                    events.recv().await.unwrap(),
                    json!({"ev":"unavailable","reason":"advertise-failed"})
                );
                assert!(events.recv().await.is_none());
            }
            assert!(engine.requests.is_empty());
            assert!(engine.pairing.is_none());
            assert!(engine.advertising.is_none());
            assert!(engine.session.is_none());
            assert!(!engine.connected);
            assert!(peer.advertising.borrow().is_none());

            engine.transport.fail_advertise = false;
            let _events = input(&mut engine, 4, 0, Input::PairBegin {}).await;
            engine.update_advertising().await;
            assert_eq!(engine.advertising.unwrap()[8], 1);
            assert_eq!(peer.advertising.borrow().unwrap()[8], 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pairing_timeout_releases_owner_and_stops_advertising() {
        let (_temp, engine, mut peer) = engine();
        let (tx, rx) = mpsc::channel(16);
        let task = tokio::spawn(engine.run(rx));
        let (reply, mut events) = mpsc::channel(8);
        tx.send(Command::Ipc {
            id: 1,
            uid: 0,
            name: "root".into(),
            input: Input::PairBegin {},
            reply,
        })
        .await
        .unwrap();
        peer.advertising.changed().await.unwrap();
        assert_eq!(peer.advertising.borrow_and_update().unwrap()[8], 1);
        tokio::time::advance(Duration::from_secs(121)).await;
        let event = events.recv().await.unwrap();
        assert_eq!(event, json!({"ev":"pair-failed","reason":"timeout"}));
        tokio::task::yield_now().await;
        assert!(peer.advertising.borrow().is_none());
        drop(tx);
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn idle_session_expires_and_a_new_connection_can_authenticate() {
        let (_temp, mut engine, mut peer) = engine();
        let _client = input(
            &mut engine,
            1,
            1000,
            Input::Request {
                kind: RequestKind::Lock,
                user: "user1000".into(),
                command: None,
                tty: None,
                pid: None,
            },
        )
        .await;
        let (tx, rx) = mpsc::channel(16);
        let task = tokio::spawn(engine.run(rx));
        peer.incoming.send(Event::Connected).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        let hello = wire::Message::AuthHello {
            watch_nonce: [9; 16],
        }
        .encode()
        .unwrap();
        for chunk in framing::chunk(&hello, 20).unwrap() {
            peer.incoming.send(Event::Bytes(chunk)).await.unwrap();
        }
        tokio::task::yield_now().await;
        assert!(peer.outgoing.try_recv().is_err());
        peer.incoming.send(Event::Connected).await.unwrap();
        for chunk in framing::chunk(&hello, 20).unwrap() {
            peer.incoming.send(Event::Bytes(chunk)).await.unwrap();
        }
        assert!(peer.outgoing.recv().await.is_some());
        drop(tx);
        task.await.unwrap().unwrap();
    }
}
