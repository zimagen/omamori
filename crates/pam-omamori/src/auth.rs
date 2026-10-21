//! Safe authentication policy and the terminal/socket input loop.
use crate::ffi::{self, Terminal};
use crate::ffi::{ABORT, IGNORE, UNAVAILABLE};
use omamori_ipc::{Event, Input, RequestKind};
use std::{
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
pub(crate) struct Options {
    lock: bool,
    socket: String,
    tty: String,
    timeout: Duration,
    debug: bool,
}
impl Options {
    pub(crate) fn parse(args: &[String]) -> Option<Self> {
        let mut o = Self {
            lock: false,
            socket: omamori_ipc::DEFAULT_SOCKET.into(),
            tty: "/dev/tty".into(),
            timeout: Duration::from_secs(300),
            debug: false,
        };
        let mut mode = false;
        for arg in args {
            match arg.as_str() {
                "mode=sudo" => {
                    o.lock = false;
                    mode = true;
                }
                "mode=lock" => {
                    o.lock = true;
                    mode = true;
                }
                "debug" => o.debug = true,
                _ => {
                    if let Some(v) = arg.strip_prefix("socket=") {
                        o.socket = v.into();
                    } else if let Some(v) = arg.strip_prefix("tty=") {
                        o.tty = v.into();
                    } else if let Some(v) = arg.strip_prefix("timeout=") {
                        o.timeout = Duration::from_secs(v.parse().ok()?);
                    }
                    // Unknown arguments intentionally ignored.
                }
            }
        }
        mode.then_some(o)
    }
    pub(crate) fn failure(&self) -> i32 {
        if self.lock { UNAVAILABLE } else { IGNORE }
    }
}
pub(crate) fn authenticate(handle: ffi::Handle, o: &Options) -> io::Result<i32> {
    if o.debug {
        ffi::log_attempt();
    }
    let user = handle.user()?;
    let mut terminal = None;
    let request = if o.lock {
        Input::Request {
            kind: RequestKind::Lock,
            user: user.clone(),
            command: None,
            tty: None,
            pid: None,
        }
    } else {
        if !matches!(handle.service().as_str(), "sudo" | "sudo-i") {
            return Ok(IGNORE);
        }
        let args = std::fs::read("/proc/self/cmdline")?
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect::<Vec<_>>();
        let (skip, command) = crate::sudo_arguments(&args);
        if skip {
            return Ok(IGNORE);
        }
        terminal = Some(Terminal::open(&o.tty)?);
        Input::Request {
            kind: RequestKind::Sudo,
            user: user.clone(),
            command: Some(command.join(" ")),
            tty: Some(handle.tty()),
            pid: Some(std::process::id()),
        }
    };
    let mut socket = UnixStream::connect(&o.socket)?;
    socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    omamori_ipc::send(&mut socket, &request)?;
    if !matches!(omamori_ipc::receive(&mut socket)?, Event::Queued { .. }) {
        return Ok(o.failure());
    }
    if o.lock {
        socket.set_read_timeout(None)?;
        return Ok(
            if matches!(omamori_ipc::receive(&mut socket)?, Event::Approved) {
                0
            } else {
                UNAVAILABLE
            },
        );
    }
    let mut terminal = terminal.expect("sudo opened terminal");
    let prompt = handle
        .prompt()
        .unwrap_or_else(|| format!("[sudo] password for {user}: "));
    terminal.raw()?;
    write!(
        terminal.file,
        "[omamori] Approve on your watch, or type the password.\r\n{prompt}"
    )?;
    let deadline = Instant::now()
        .checked_add(o.timeout)
        .ok_or_else(|| io::Error::other("timeout too large"))?;
    // Reserve the complete bounded buffer, including the terminating NUL.
    // Growing a Vec could leave an unzeroized old allocation behind.
    let mut password = Zeroizing::new(Vec::<u8>::with_capacity(4097));
    let mut socket = Some(socket);
    let mut incoming = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(IGNORE);
        }
        let mut fds = [
            libc::pollfd {
                fd: terminal.file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: socket.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = ffi::poll(&mut fds, remaining.as_millis().min(i32::MAX as u128) as i32);
        if ready < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let mut byte = Zeroizing::new([0u8]);
            terminal.file.read_exact(&mut *byte)?;
            let b = byte[0];
            let cc = &terminal.original.c_cc;
            if b == b'\n' || b == b'\r' {
                drop(socket.take()); // Disconnect cancels before passing the password to PAM.
                password.push(0);
                let result = handle.set_token(&password);
                writeln!(terminal.file)?;
                return Ok(if result == 0 { IGNORE } else { o.failure() });
            } else if cc[libc::VINTR] != 0 && b == cc[libc::VINTR] {
                writeln!(terminal.file)?;
                drop(password);
                drop(socket.take());
                drop(terminal);
                ffi::raise_interrupt();
                return Ok(ABORT);
            } else if cc[libc::VEOF] != 0 && b == cc[libc::VEOF] {
                if password.is_empty() {
                    return Ok(ABORT);
                }
            } else if cc[libc::VERASE] != 0 && b == cc[libc::VERASE] {
                erase(&mut password);
            } else if cc[libc::VKILL] != 0 && b == cc[libc::VKILL] {
                password.fill(0);
                password.clear();
            } else if cc[libc::VWERASE] != 0 && b == cc[libc::VWERASE] {
                while password.last().is_some_and(u8::is_ascii_whitespace) {
                    erase(&mut password);
                }
                while password.last().is_some_and(|b| !b.is_ascii_whitespace()) {
                    erase(&mut password);
                }
            } else if b != 0 {
                if password.len() == 4096 {
                    return Ok(IGNORE);
                }
                password.push(b);
            }
        } else if fds[0].revents != 0 {
            return Ok(IGNORE);
        }
        if fds[1].revents != 0 {
            let mut b = [0];
            match socket.as_mut().expect("polled socket").read(&mut b) {
                Ok(1) => {
                    incoming.push(b[0]);
                    if incoming.len() > omamori_ipc::MAX_LINE {
                        socket.take();
                    } else if b[0] == b'\n' {
                        if matches!(omamori_ipc::decode_event(&incoming), Ok(Event::Approved)) {
                            writeln!(terminal.file, "\r\napproved by watch")?;
                            return Ok(0);
                        }
                        socket.take();
                    }
                }
                _ => {
                    socket.take();
                }
            }
        }
    }
}
fn erase(password: &mut Vec<u8>) {
    if let Some(b) = password.last_mut() {
        *b = 0;
    }
    password.pop();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arguments_require_mode_and_ignore_unknown_options() {
        assert!(Options::parse(&[]).is_none());
        let args = ["mode=lock", "unknown=ignored", "debug", "timeout=12"].map(str::to_owned);
        let options = Options::parse(&args).unwrap();
        assert_eq!(options.failure(), UNAVAILABLE);
        assert!(options.debug);
        assert_eq!(options.timeout, std::time::Duration::from_secs(12));
    }
}
