//! Real libpam loading the cdylib; daemon traffic goes through its fake BLE
//! transport and the reference watch, while passwords are entered through a PTY.
use libc::{c_char, c_int, c_void};
use omamori_daemon::{
    Daemon,
    config::Config,
    ipc::Policy,
    state::{Pairing, Store},
    transport::{Event, fake},
};
use omamori_proto::{
    Output,
    crypto::Key,
    framing::{self, Reassembler},
    watch,
};
use std::{
    ffi::{CStr, CString},
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::time::timeout;
#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const c_void,
        dir: *const c_char,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_getenv(handle: *mut c_void, name: *const c_char) -> *const c_char;
}
#[repr(C)]
struct Conv {
    callback: Option<
        unsafe extern "C" fn(c_int, *const *const c_void, *mut *mut c_void, *mut c_void) -> c_int,
    >,
    data: *mut c_void,
}
fn module() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let so = exe.parent().unwrap().join("libpam_omamori.so");
    assert!(so.exists(), "build cdylib first: {}", so.display());
    so
}
fn username() -> String {
    // SAFETY: libc returns a valid passwd for this test user's uid.
    unsafe {
        CStr::from_ptr((*libc::getpwuid(libc::geteuid())).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}
fn run_pam(dir: &Path, service: &str) -> (i32, String) {
    let service = CString::new(service).unwrap();
    let user = CString::new(username()).unwrap();
    let dir = CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let conv = Conv {
        callback: None,
        data: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    // SAFETY: all pointers refer to live ABI-compatible data; PAM owns handle until pam_end.
    unsafe {
        assert_eq!(
            pam_start_confdir(
                service.as_ptr(),
                user.as_ptr(),
                (&conv as *const Conv).cast(),
                dir.as_ptr(),
                &mut handle
            ),
            0
        );
        let result = pam_authenticate(handle, 0);
        let token = pam_getenv(handle, c"OMAMORI_TEST_TOKEN".as_ptr());
        let token = if token.is_null() {
            String::new()
        } else {
            CStr::from_ptr(token).to_string_lossy().into_owned()
        };
        pam_end(handle, result);
        (result, token)
    }
}
struct Pty {
    master: fs::File,
    slave: fs::File,
    path: String,
    before: libc::termios,
}
impl Pty {
    fn new() -> Self {
        // SAFETY: openpty initializes both fds and the name on success.
        unsafe {
            let (mut master, mut slave) = (0, 0);
            let mut name = [0 as c_char; 256];
            assert_eq!(
                libc::openpty(
                    &mut master,
                    &mut slave,
                    name.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null()
                ),
                0
            );
            let master = fs::File::from_raw_fd(master);
            let slave = fs::File::from_raw_fd(slave);
            let mut before = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave.as_raw_fd(), &mut before), 0);
            Self {
                master,
                slave,
                path: CStr::from_ptr(name.as_ptr()).to_str().unwrap().into(),
                before,
            }
        }
    }
    fn restored(&self) {
        // SAFETY: slave fd is open, termios output is writable.
        unsafe {
            let mut after: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(self.slave.as_raw_fd(), &mut after), 0);
            assert_eq!(after.c_iflag, self.before.c_iflag);
            assert_eq!(after.c_oflag, self.before.c_oflag);
            assert_eq!(after.c_cflag, self.before.c_cflag);
            assert_eq!(after.c_lflag, self.before.c_lflag);
            assert_eq!(after.c_cc, self.before.c_cc);
            assert_eq!(libc::cfgetispeed(&after), libc::cfgetispeed(&self.before));
            assert_eq!(libc::cfgetospeed(&after), libc::cfgetospeed(&self.before));
        }
    }
    fn prompt(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut out = Vec::new();
        loop {
            assert!(Instant::now() < deadline, "missing password prompt");
            let mut fd = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd entry.
            if unsafe { libc::poll(&mut fd, 1, 100) } > 0 {
                let mut b = [0; 512];
                let n = self.master.read(&mut b).unwrap();
                out.extend_from_slice(&b[..n]);
                if out.ends_with(b": ") {
                    break;
                }
            }
        }
    }
}
struct Harness {
    temp: tempfile::TempDir,
    socket: PathBuf,
    daemon: Daemon,
    peer: fake::Peer,
    host_id: [u8; 16],
}
impl Harness {
    fn new(paired: bool, root: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let (store, mut state) = Store::open(&state_dir).unwrap();
        if paired {
            state.pairing = Some(Pairing::new("Test watch".into(), Key::new([7; 32])));
            store.save(&state).unwrap();
        }
        drop(store);
        let socket = temp.path().join("run/socket");
        let (transport, peer) = fake::pair();
        // SAFETY: geteuid has no preconditions.
        let policy = if root {
            Policy::with_root_uid(unsafe { libc::geteuid() })
        } else {
            Policy::default()
        };
        let daemon =
            omamori_daemon::start(Config::default(), &state_dir, &socket, transport, policy)
                .unwrap();
        Self {
            temp,
            socket,
            daemon,
            peer,
            host_id: state.host_id,
        }
    }
    fn config(&self, pty: &Pty, mode: &str, service: &str) -> PathBuf {
        let dir = self.temp.path().join(format!("pam-{service}"));
        fs::create_dir_all(&dir).unwrap();
        // PAM clears AUTHTOK when returning to an application. A tiny test-only
        // module captures it inside the stack, after the fingerprint stand-in.
        let capture = self.temp.path().join("capture.so");
        if !capture.exists() {
            let source = self.temp.path().join("capture.c");
            fs::write(
                &source,
                r#"#include <security/pam_modules.h>
#include <stdio.h>
int pam_sm_authenticate(pam_handle_t *p,int f,int n,const char **v) {
const void *token=0; char value[4200];
if (pam_get_item(p,PAM_AUTHTOK,&token)==PAM_SUCCESS && token) {
snprintf(value,sizeof(value),"OMAMORI_TEST_TOKEN=%s",(const char *)token);pam_putenv(p,value);
}
return PAM_IGNORE;
}
int pam_sm_setcred(pam_handle_t *p,int f,int n,const char **v){return PAM_IGNORE;}
"#,
            )
            .unwrap();
            assert!(
                std::process::Command::new("cc")
                    .args(["-shared", "-fPIC"])
                    .arg(&source)
                    .arg("-o")
                    .arg(&capture)
                    .arg("-lpam")
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let content = if mode == "sudo" {
            format!(
                "auth [success=done new_authtok_reqd=done cred_insufficient=1 default=ignore] {} mode=sudo socket={} tty={}\nauth required pam_deny.so\nauth optional {}\nauth required pam_permit.so\n",
                module().display(),
                self.socket.display(),
                pty.path,
                capture.display()
            )
        } else {
            format!(
                "auth required {} mode=lock socket={}\n",
                module().display(),
                self.socket.display()
            )
        };
        fs::write(dir.join(service), content).unwrap();
        dir
    }
    async fn pending(&self, n: usize) {
        let path = self.socket.clone();
        timeout(Duration::from_secs(3), async {
            loop {
                let path = path.clone();
                let count = tokio::task::spawn_blocking(move || {
                    let mut socket = std::os::unix::net::UnixStream::connect(path).unwrap();
                    omamori_ipc::send(&mut socket, &omamori_ipc::Input::Status {}).unwrap();
                    let omamori_ipc::Event::Status { fields } =
                        omamori_ipc::receive(&mut socket).unwrap()
                    else {
                        panic!()
                    };
                    fields["pending"].as_array().unwrap().len()
                })
                .await
                .unwrap();
                if count == n {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    async fn send(&mut self, out: Output<watch::Event>) {
        for message in out.messages {
            for chunk in framing::chunk(&message, 20).unwrap() {
                self.peer.incoming.send(Event::Bytes(chunk)).await.unwrap();
            }
        }
    }
    async fn approve(&mut self, lock: bool) {
        self.pending(1).await;
        self.peer.incoming.send(Event::Connected).await.unwrap();
        let (mut watch, hello) = watch::Session::authenticated(
            self.host_id,
            Key::new([7; 32]),
            &mut rand_core::UnwrapErr(getrandom::SysRng),
        );
        self.send(hello).await;
        let mut framing = Reassembler::new(20).unwrap();
        let bytes = timeout(Duration::from_secs(3), async {
            loop {
                let chunk = self.peer.outgoing.recv().await.unwrap();
                if let Some(bytes) = framing.receive(&chunk).unwrap() {
                    break bytes;
                }
            }
        })
        .await
        .unwrap();
        let out = watch.receive(&bytes).unwrap();
        if lock {
            self.send(out).await;
        } else {
            let watch::Event::Show(entries) = &out.events[0] else {
                panic!()
            };
            self.send(watch.tap(entries[0].req_id).unwrap()).await;
        }
    }
    async fn stop(self) {
        let _ = self.daemon.shutdown.send(());
        self.daemon.task.await.unwrap().unwrap();
    }
}
async fn result(task: tokio::task::JoinHandle<(i32, String)>) -> (i32, String) {
    timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sudo_watch_approval_restores_terminal() {
    let mut h = Harness::new(true, true);
    let mut pty = Pty::new();
    let dir = h.config(&pty, "sudo", "sudo");
    let task = tokio::task::spawn_blocking(move || run_pam(&dir, "sudo"));
    pty.prompt();
    h.approve(false).await;
    assert_eq!(result(task).await.0, 0);
    pty.restored();
    h.stop().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_editing_and_disconnect_cancel() {
    for (typed, expected) in [
        (b"secret\n".as_slice(), "secret"),
        (b"secrX\x7fet\n", "secret"),
        (b"bad\x15secret\n", "secret"),
        (b"secret bad\x17\n", "secret "),
    ] {
        let h = Harness::new(true, true);
        let mut pty = Pty::new();
        let dir = h.config(&pty, "sudo", "sudo");
        let task = tokio::task::spawn_blocking(move || run_pam(&dir, "sudo"));
        pty.prompt();
        pty.master.write_all(typed).unwrap();
        assert_eq!(result(task).await, (0, expected.into()));
        pty.restored();
        h.pending(0).await;
        h.stop().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn immediate_fallback_and_service_check() {
    for scenario in ["not-paired", "missing", "login"] {
        let h = Harness::new(scenario != "not-paired", true);
        let pty = Pty::new();
        let service = if scenario == "login" { "login" } else { "sudo" };
        let dir = h.config(&pty, "sudo", service);
        if scenario == "missing" {
            fs::remove_file(&h.socket).unwrap();
        }
        let start = Instant::now();
        let result = tokio::task::spawn_blocking(move || run_pam(&dir, service))
            .await
            .unwrap();
        assert_eq!(result.0, 7);
        assert!(start.elapsed() < Duration::from_millis(200));
        pty.restored();
        h.stop().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_approval_and_daemon_disconnect() {
    for approve in [true, false] {
        let mut h = Harness::new(true, false);
        let pty = Pty::new();
        let dir = h.config(&pty, "lock", "lock");
        let task = tokio::task::spawn_blocking(move || run_pam(&dir, "lock"));
        if approve {
            h.approve(true).await;
            assert_eq!(result(task).await.0, 0);
            h.stop().await;
        } else {
            h.pending(1).await;
            h.stop().await;
            assert_eq!(result(task).await.0, 9);
        }
        pty.restored();
    }
}
#[test]
#[ignore = "child process entry point for SIGINT test"]
fn sigint_child() {
    let dir = std::env::var_os("OMAMORI_TEST_PAM_DIR").unwrap();
    run_pam(Path::new(&dir), "sudo");
    panic!("SIGINT should terminate child");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_restores_before_raising_sigint() {
    let h = Harness::new(true, true);
    let mut pty = Pty::new();
    let dir = h.config(&pty, "sudo", "sudo");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "sigint_child"])
        .env("OMAMORI_TEST_PAM_DIR", dir)
        .spawn()
        .unwrap();
    pty.prompt();
    pty.master.write_all(&[3]).unwrap();
    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGINT));
    pty.restored();
    h.pending(0).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_loss_keeps_password_fallback() {
    let h = Harness::new(true, true);
    let mut pty = Pty::new();
    let dir = h.config(&pty, "sudo", "sudo");
    let task = tokio::task::spawn_blocking(move || run_pam(&dir, "sudo"));
    pty.prompt();
    h.stop().await;
    pty.master.write_all(b"secret\n").unwrap();
    assert_eq!(result(task).await, (0, "secret".into()));
    pty.restored();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eof_and_timeout_restore_terminal_and_cancel() {
    for eof in [true, false] {
        let h = Harness::new(true, true);
        let mut pty = Pty::new();
        let dir = h.config(&pty, "sudo", "sudo");
        if !eof {
            let path = dir.join("sudo");
            let content = fs::read_to_string(&path)
                .unwrap()
                .replace("mode=sudo", "mode=sudo timeout=0");
            fs::write(path, content).unwrap();
        }
        let task = tokio::task::spawn_blocking(move || run_pam(&dir, "sudo"));
        pty.prompt();
        if eof {
            pty.master
                .write_all(&[pty.before.c_cc[libc::VEOF]])
                .unwrap();
        }
        assert_eq!(result(task).await.0, 7);
        pty.restored();
        h.pending(0).await;
        h.stop().await;
    }
}
