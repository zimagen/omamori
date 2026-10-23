#![cfg(feature = "test-harness")]
use nix::unistd::{Uid, User};
use omamori_daemon::{
    Daemon,
    config::Config,
    ipc::Policy,
    start,
    state::{Pairing, State, Store},
    transport::{
        Event,
        fake::{self, Peer},
    },
};
use omamori_proto::{
    Output,
    crypto::Key,
    framing::{self, Reassembler},
    watch,
    wire::{Kind, Message},
};
use rand_core::OsRng;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    time::timeout,
};

struct Client {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
}
impl Client {
    async fn open(path: &std::path::Path) -> Self {
        let (read, write) = UnixStream::connect(path).await.unwrap().into_split();
        Self {
            read: BufReader::new(read),
            write,
        }
    }
    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.write.write_all(&bytes).await.unwrap();
    }
    async fn event(&mut self) -> Value {
        let mut line = String::new();
        assert!(
            timeout(Duration::from_secs(3), self.read.read_line(&mut line))
                .await
                .unwrap()
                .unwrap()
                > 0,
            "expected event"
        );
        serde_json::from_str(&line).unwrap()
    }
    async fn eof(&mut self) {
        let mut line = String::new();
        assert_eq!(
            timeout(Duration::from_secs(3), self.read.read_line(&mut line))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}
struct Harness {
    _temp: TempDir,
    socket: PathBuf,
    state_dir: PathBuf,
    daemon: Daemon,
    peer: Peer,
}
fn uid() -> u32 {
    Uid::effective().as_raw()
}
fn username() -> String {
    User::from_uid(Uid::effective()).unwrap().unwrap().name
}
fn lock() -> Value {
    json!({"op":"request","kind":"lock","user":username()})
}
fn sudo() -> Value {
    json!({"op":"request","kind":"sudo","user":username(),"command":"pacman -Syu","tty":"/dev/pts/1","pid":123})
}
impl Harness {
    async fn new(paired: bool, root: bool) -> Self {
        Self::configured(paired, root, Config::default()).await
    }
    async fn configured(paired: bool, root: bool, config: Config) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let (store, mut state) = Store::open(&state_dir).unwrap();
        if paired {
            state.pairing = Some(Pairing::new("Venu".into(), Key::new([7; 32])));
            store.save(&state).unwrap();
        }
        drop(store);
        let socket = temp.path().join("run/omamori.sock");
        let (transport, peer) = fake::pair();
        let policy = if root {
            Policy::with_root_uid(uid())
        } else {
            Policy::default()
        };
        let daemon = start(config, &state_dir, &socket, transport, policy).unwrap();
        Self {
            _temp: temp,
            socket,
            state_dir,
            daemon,
            peer,
        }
    }
    fn state(&self) -> State {
        serde_json::from_slice(&fs::read(self.state_dir.join("state.json")).unwrap()).unwrap()
    }
    async fn client(&self) -> Client {
        Client::open(&self.socket).await
    }
    async fn status(&self) -> Value {
        let mut c = self.client().await;
        c.send(json!({"op":"status"})).await;
        c.event().await
    }
    async fn pending_count(&self, n: usize) {
        timeout(Duration::from_secs(3), async {
            loop {
                if self.status().await["pending"].as_array().unwrap().len() == n {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    async fn advertising(&mut self, pairing: bool) {
        timeout(Duration::from_secs(3), async {
            loop {
                let data = *self.peer.advertising.borrow_and_update();
                if data.is_some_and(|d| d[8] == u8::from(pairing)) {
                    break;
                }
                self.peer.advertising.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
    }
    async fn connect(&mut self) {
        self.peer.incoming.send(Event::Connected).await.unwrap();
    }
    async fn send(&mut self, out: Output<watch::Event>) {
        for message in out.messages {
            for chunk in framing::chunk(&message, 20).unwrap() {
                self.peer.incoming.send(Event::Bytes(chunk)).await.unwrap();
            }
        }
    }
    async fn receive(&mut self) -> Vec<u8> {
        let mut framing = Reassembler::new(20).unwrap();
        timeout(Duration::from_secs(3), async {
            loop {
                let chunk = self.peer.outgoing.recv().await.unwrap();
                if let Some(message) = framing.receive(&chunk).unwrap() {
                    return message;
                }
            }
        })
        .await
        .unwrap()
    }
    async fn authenticate(&mut self, key: [u8; 32]) -> (watch::Session, Output<watch::Event>) {
        self.advertising(false).await;
        self.connect().await;
        let (mut watch, hello) =
            watch::Session::authenticated(self.state().host_id, Key::new(key), &mut OsRng);
        self.send(hello).await;
        let out = watch.receive(&self.receive().await).unwrap();
        (watch, out)
    }
    async fn stop(self) {
        let _ = self.daemon.shutdown.send(());
        timeout(Duration::from_secs(3), self.daemon.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!self.socket.exists());
    }
}

#[tokio::test]
async fn lock_auto_approval_and_private_state_and_socket_modes() {
    let mut h = Harness::new(true, false).await;
    assert_eq!(fs::metadata(&h.state_dir).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(h.state_dir.join("state.json")).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::metadata(&h.socket).unwrap().mode() & 0o777, 0o666);
    assert_eq!(
        fs::metadata(h.socket.parent().unwrap()).unwrap().mode() & 0o777,
        0o755
    );
    let mut c = h.client().await;
    c.send(lock()).await;
    assert_eq!(c.event().await["ev"], "queued");
    let (mut watch, out) = h.authenticate([7; 32]).await;
    assert_eq!(out.messages.len(), 1);
    h.send(out).await;
    assert_eq!(c.event().await["ev"], "approved");
    c.eof().await;
    let result = watch.receive(&h.receive().await).unwrap();
    assert!(matches!(
        result.events[0],
        watch::Event::Result { status: 0, .. }
    ));
    h.pending_count(0).await;
    h.stop().await;
}

#[tokio::test]
async fn sudo_needs_a_tap_and_is_approved_once() {
    let mut h = Harness::new(true, true).await;
    let mut c = h.client().await;
    c.send(sudo()).await;
    assert_eq!(c.event().await["ev"], "queued");
    let (mut watch, out) = h.authenticate([7; 32]).await;
    assert!(out.messages.is_empty());
    let watch::Event::Show(entries) = &out.events[0] else {
        panic!()
    };
    assert_eq!(entries[0].kind, Kind::Sudo);
    assert!(entries[0].needs_confirm);
    assert!(entries[0].detail.contains("pacman -Syu"));
    assert!(timeout(Duration::from_millis(50), c.event()).await.is_err());
    h.send(watch.tap(entries[0].req_id).unwrap()).await;
    assert_eq!(c.event().await["ev"], "approved");
    c.eof().await;
    watch.receive(&h.receive().await).unwrap();
    assert!(watch.tap(entries[0].req_id).is_err());
    h.stop().await;
}

#[tokio::test]
async fn identity_rules_root_permissions_and_request_limits() {
    let h = Harness::new(true, false).await;
    for input in [
        sudo(),
        json!({"op":"request","kind":"lock","user":"definitely-not-the-peer"}),
        json!({"op":"pair-begin"}),
        json!({"op":"pair-confirm","accept":true}),
        json!({"op":"unpair"}),
    ] {
        let mut c = h.client().await;
        c.send(input).await;
        assert_eq!(c.event().await["ev"], "denied");
        c.eof().await;
    }
    let mut clients = Vec::new();
    for _ in 0..4 {
        let mut c = h.client().await;
        c.send(lock()).await;
        assert_eq!(c.event().await["ev"], "queued");
        clients.push(c);
    }
    let mut fifth = h.client().await;
    fifth.send(lock()).await;
    assert_eq!(
        fifth.event().await,
        json!({"ev":"unavailable","reason":"busy"})
    );
    assert_eq!(h.status().await["pending"].as_array().unwrap().len(), 4);
    drop(clients);
    h.pending_count(0).await;
    h.stop().await;
    let h = Harness::new(true, true).await;
    let mut c = h.client().await;
    c.send(lock()).await;
    assert_eq!(c.event().await["ev"], "denied");
    h.stop().await;
}

#[tokio::test]
async fn disconnect_cancels_and_later_valid_approval_is_refused() {
    let mut h = Harness::new(true, true).await;
    let mut c = h.client().await;
    c.send(sudo()).await;
    c.event().await;
    let (mut watch, out) = h.authenticate([7; 32]).await;
    let watch::Event::Show(entries) = &out.events[0] else {
        panic!()
    };
    let approval = watch.tap(entries[0].req_id).unwrap();
    drop(c);
    h.pending_count(0).await;
    h.send(approval).await;
    let result = watch.receive(&h.receive().await).unwrap();
    assert!(matches!(
        result.events[0],
        watch::Event::Result { status: 1, .. }
    ));
    h.stop().await;
}

#[tokio::test]
async fn not_paired_disabled_and_no_adapter_are_immediate() {
    let h = Harness::new(false, false).await;
    let mut c = h.client().await;
    c.send(lock()).await;
    assert_eq!(
        c.event().await,
        json!({"ev":"unavailable","reason":"not-paired"})
    );
    h.stop().await;
    let h = Harness::configured(
        true,
        false,
        Config {
            lock: false,
            ..Config::default()
        },
    )
    .await;
    let mut c = h.client().await;
    c.send(lock()).await;
    assert_eq!(
        c.event().await,
        json!({"ev":"unavailable","reason":"disabled"})
    );
    h.stop().await;
    let h = Harness::new(true, false).await;
    h.peer.incoming.send(Event::Powered(false)).await.unwrap();
    timeout(Duration::from_secs(3), async {
        while h.status().await["adapter_powered"] != false {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut c = h.client().await;
    c.send(lock()).await;
    assert_eq!(
        c.event().await,
        json!({"ev":"unavailable","reason":"no-adapter"})
    );
    h.stop().await;
}

async fn pair_watch(h: &mut Harness, host_first: bool) -> ([u8; 32], [u8; 16]) {
    let mut c = h.client().await;
    c.send(json!({"op":"pair-begin"})).await;
    h.advertising(true).await;
    let mut competing = h.client().await;
    competing.send(json!({"op":"pair-begin"})).await;
    assert_eq!(
        competing.event().await,
        json!({"ev":"unavailable","reason":"busy"})
    );
    competing = h.client().await;
    competing
        .send(json!({"op":"pair-confirm","accept":true}))
        .await;
    assert_eq!(competing.event().await["ev"], "denied");
    let (mut watch, commit) = watch::Session::pairing("New Venu", &mut OsRng);
    h.connect().await;
    h.send(commit).await;
    let reveal = watch.receive(&h.receive().await).unwrap();
    let watch::Event::PairCode(watch_code, _) = &reveal.events[0] else {
        panic!()
    };
    let watch_code = watch_code.clone();
    h.send(reveal).await;
    let code = c.event().await;
    assert_eq!(code["ev"], "pair-code");
    assert_eq!(code["code"], watch_code);
    if host_first {
        c.send(json!({"op":"pair-confirm","accept":true})).await;
    }
    h.send(watch.confirm_pairing(true).unwrap()).await;
    if !host_first {
        c.send(json!({"op":"pair-confirm","accept":true})).await;
    }
    let done = watch.receive(&h.receive().await).unwrap();
    let watch::Event::Paired { key, host_id, .. } = &done.events[0] else {
        panic!()
    };
    assert_eq!(c.event().await["ev"], "pair-done");
    c.eof().await;
    assert_eq!(h.state().pairing.as_ref().unwrap().key, *key.as_bytes());
    (*key.as_bytes(), *host_id)
}

#[tokio::test]
async fn ipc_pairing_persists_and_repair_replaces_key_preserving_host_id() {
    let mut h = Harness::new(false, true).await;
    let original_id = h.state().host_id;
    let (old_key, id) = pair_watch(&mut h, true).await;
    assert_eq!(original_id, id);
    let (new_key, new_id) = pair_watch(&mut h, false).await;
    assert_eq!(new_id, id);
    assert_ne!(old_key, new_key);
    let mut c = h.client().await;
    c.send(sudo()).await;
    c.event().await;
    let (mut watch, out) = h.authenticate(new_key).await;
    let watch::Event::Show(entries) = &out.events[0] else {
        panic!()
    };
    h.send(watch.tap(entries[0].req_id).unwrap()).await;
    assert_eq!(c.event().await["ev"], "approved");
    watch.receive(&h.receive().await).unwrap();
    h.stop().await;
}

#[tokio::test]
async fn malformed_oversize_unknown_fields_close_and_cancel() {
    let h = Harness::new(true, false).await;
    for bytes in [
        b"not json\n".to_vec(),
        b"{\"op\":\"status\",\"uid\":0}\n".to_vec(),
        vec![b'x'; 4097],
        b"{\"op\":\"unknown\"}\n".to_vec(),
    ] {
        let mut c = h.client().await;
        c.send(lock()).await;
        assert_eq!(c.event().await["ev"], "queued");
        c.write.write_all(&bytes).await.unwrap();
        c.eof().await;
        h.pending_count(0).await;
    }
    h.stop().await;
}

#[tokio::test]
async fn rejects_public_state_and_unknown_config_keys() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("state");
    let (store, _) = Store::open(&dir).unwrap();
    drop(store);
    fs::set_permissions(dir.join("state.json"), fs::Permissions::from_mode(0o644)).unwrap();
    let (transport, _peer) = fake::pair();
    let result = start(
        Config::default(),
        &dir,
        &temp.path().join("run/sock"),
        transport,
        Policy::default(),
    );
    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(err.contains("group/world accessible"), "{err}");
    fs::set_permissions(dir.join("state.json"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Store::open(&dir).is_err());
    assert!(Config::load(&temp.path().join("missing.toml")).is_ok());
    let path = temp.path().join("config.toml");
    fs::write(&path, "sduo = true\n").unwrap();
    assert!(Config::load(&path).is_err());
    fs::write(
        &path,
        "approval = 'auto'\nlock = false\nhost_name = 'Test'\n",
    )
    .unwrap();
    let config = Config::load(&path).unwrap();
    assert!(!config.lock);
    assert_eq!(config.host_name, "Test");
}

#[tokio::test]
async fn auto_policy_also_approves_sudo_without_a_tap() {
    let mut h = Harness::configured(
        true,
        true,
        Config {
            approval: omamori_daemon::config::Approval::Auto,
            ..Config::default()
        },
    )
    .await;
    let mut c = h.client().await;
    c.send(sudo()).await;
    c.event().await;
    let (mut watch, out) = h.authenticate([7; 32]).await;
    assert_eq!(out.messages.len(), 1);
    h.send(out).await;
    assert_eq!(c.event().await["ev"], "approved");
    watch.receive(&h.receive().await).unwrap();
    h.stop().await;
}

#[tokio::test]
async fn disconnect_resets_authentication_and_unpair_cancels_requests() {
    let mut h = Harness::new(true, true).await;
    let mut c = h.client().await;
    c.send(sudo()).await;
    c.event().await;
    let (mut old_watch, out) = h.authenticate([7; 32]).await;
    let watch::Event::Show(entries) = &out.events[0] else {
        panic!()
    };
    let stale = old_watch.tap(entries[0].req_id).unwrap();
    h.peer.incoming.send(Event::Disconnected).await.unwrap();
    h.connect().await;
    let (_, hello) =
        watch::Session::authenticated(h.state().host_id, Key::new([7; 32]), &mut OsRng);
    h.send(hello).await;
    let _ = h.receive().await;
    h.send(stale).await;
    assert!(matches!(
        Message::decode(&h.receive().await).unwrap(),
        Message::Result { status: 2, .. }
    ));
    assert!(timeout(Duration::from_millis(50), c.event()).await.is_err());
    let mut admin = h.client().await;
    admin.send(json!({"op":"unpair"})).await;
    assert_eq!(admin.event().await["paired"], false);
    assert_eq!(
        c.event().await,
        json!({"ev":"unavailable","reason":"not-paired"})
    );
    assert!(h.state().pairing.is_none());
    h.stop().await;
}

#[tokio::test]
async fn fragmented_ipc_lines_survive_outgoing_status_events() {
    let h = Harness::new(true, false).await;
    let mut c = h.client().await;
    c.write
        .write_all(b"{\"op\":\"status\"}\n{\"op\":\"sta")
        .await
        .unwrap();
    assert_eq!(c.event().await["ev"], "status");
    c.write.write_all(b"tus\"}\n").await.unwrap();
    assert_eq!(c.event().await["ev"], "status");
    h.stop().await;
}

#[tokio::test]
async fn stale_socket_is_replaced_but_live_listener_and_regular_file_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("run/socket");
    fs::create_dir(socket.parent().unwrap()).unwrap();
    let stale = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    drop(stale);
    let listener = omamori_daemon::ipc::bind(&socket).unwrap();
    assert!(omamori_daemon::ipc::bind(&socket).is_err());
    drop(listener);
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, "preserve").unwrap();
    assert!(omamori_daemon::ipc::bind(&socket).is_err());
    assert_eq!(fs::read_to_string(&socket).unwrap(), "preserve");
}

#[tokio::test]
async fn state_rejects_symlinks_and_second_daemon() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("state");
    let (store, state) = Store::open(&dir).unwrap();
    assert!(Store::open(&dir).is_err());
    drop(store);
    let (store, loaded) = Store::open(&dir).unwrap();
    assert_eq!(state.host_id, loaded.host_id);
    drop(store);
    fs::remove_file(dir.join("state.json")).unwrap();
    symlink(temp.path().join("missing"), dir.join("state.json")).unwrap();
    assert!(Store::open(&dir).is_err());
    let alias = temp.path().join("alias");
    symlink(&dir, &alias).unwrap();
    assert!(Store::open(&alias).is_err());
    assert!(Store::open(std::path::Path::new("/tmp")).is_err());
}

#[tokio::test(start_paused = true)]
async fn boost_ipc_preserves_request_and_switches_interval() {
    let mut h = Harness::new(true, true).await;
    let mut boost = h.client().await;
    boost.send(json!({"op":"boost"})).await;
    assert_eq!(
        boost.event().await,
        json!({"ev":"denied","reason":"no-request"})
    );
    boost.eof().await;
    let mut request = h.client().await;
    request.send(sudo()).await;
    assert_eq!(request.event().await["ev"], "queued");
    assert_eq!(h.peer.intervals.recv().await.unwrap(), Some([20, 30]));
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(h.peer.intervals.recv().await.unwrap(), Some([1000, 1200]));
    let mut boost = h.client().await;
    boost.send(json!({"op":"boost"})).await;
    assert_eq!(boost.event().await, json!({"ev":"boosted"}));
    boost.eof().await;
    assert_eq!(h.peer.intervals.recv().await.unwrap(), Some([20, 30]));
    h.pending_count(1).await;
    h.stop().await;
}
