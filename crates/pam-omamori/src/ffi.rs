//! Linux PAM ABI and terminal operations. PAM owns the handle and item pointers
//! for each call; no borrowed pointer is retained after the exported call.
use crate::auth::Options;
use libc::{c_char, c_int, c_void};
use std::{
    ffi::CStr,
    fs::{File, OpenOptions},
    io,
    os::fd::AsRawFd,
    panic::{AssertUnwindSafe, catch_unwind},
};
pub(crate) const IGNORE: c_int = 25;
pub(crate) const UNAVAILABLE: c_int = 9;
pub(crate) const ABORT: c_int = 26;
#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_item(handle: *mut c_void, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_set_item(handle: *mut c_void, item: c_int, value: *const c_void) -> c_int;
    fn pam_get_user(handle: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_getenv(handle: *mut c_void, name: *const c_char) -> *const c_char;
}
fn item(handle: *mut c_void, which: c_int) -> String {
    let mut ptr = std::ptr::null();
    // SAFETY: PAM supplies a live handle; successful string items are NUL terminated.
    unsafe {
        if pam_get_item(handle, which, &mut ptr) != 0 || ptr.is_null() {
            return String::new();
        }
        CStr::from_ptr(ptr.cast()).to_string_lossy().into_owned()
    }
}
/// Constructed only by the PAM entry point from its live handle.
pub(crate) struct Handle(*mut c_void);
impl Handle {
    pub(crate) fn service(&self) -> String {
        item(self.0, 1)
    }
    pub(crate) fn tty(&self) -> String {
        item(self.0, 3)
    }
    pub(crate) fn user(&self) -> io::Result<String> {
        let mut user = std::ptr::null();
        // SAFETY: the entry point guarantees a live handle; PAM owns the output string.
        unsafe {
            if pam_get_user(self.0, &mut user, std::ptr::null()) != 0 || user.is_null() {
                return Err(io::Error::other("PAM user unavailable"));
            }
            Ok(CStr::from_ptr(user).to_string_lossy().into_owned())
        }
    }
    pub(crate) fn prompt(&self) -> Option<String> {
        // SAFETY: PAM returns a borrowed NUL terminated environment string or null.
        unsafe {
            let value = pam_getenv(self.0, c"SUDO_PROMPT".as_ptr());
            if value.is_null() {
                None
            } else {
                Some(CStr::from_ptr(value).to_string_lossy().into_owned())
            }
        }
    }
    pub(crate) fn set_token(&self, token: &[u8]) -> c_int {
        if token.last() != Some(&0) {
            return IGNORE;
        }
        // SAFETY: slice is NUL terminated; PAM copies the token synchronously.
        unsafe { pam_set_item(self.0, 6, token.as_ptr().cast()) }
    }
}
pub(crate) fn log_attempt() {
    // SAFETY: static format has no substitutions and never includes the password.
    unsafe {
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_DEBUG,
            c"pam_omamori: authentication attempt".as_ptr(),
        );
    }
}
pub(crate) fn poll(fds: &mut [libc::pollfd], timeout: c_int) -> c_int {
    // SAFETY: the slice supplies exactly fds.len initialized, writable entries.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) }
}
pub(crate) fn raise_interrupt() {
    // SAFETY: SIGINT is valid. The caller restores its terminal before calling.
    unsafe {
        libc::raise(libc::SIGINT);
    }
}
pub(crate) struct Terminal {
    pub(crate) file: File,
    pub(crate) original: libc::termios,
}
impl Terminal {
    pub(crate) fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        // SAFETY: fd is live and termios storage is valid. Only assume initialized on success.
        let original = unsafe {
            let mut t = std::mem::MaybeUninit::uninit();
            if libc::tcgetattr(file.as_raw_fd(), t.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            t.assume_init()
        };
        Ok(Self { file, original })
    }
    pub(crate) fn raw(&self) -> io::Result<()> {
        let mut t = self.original;
        t.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHONL | libc::ISIG);
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        // SAFETY: live terminal fd and initialized termios.
        if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        // SAFETY: the file outlives this call; original came from tcgetattr.
        loop {
            // SAFETY: the file remains open and original is initialized.
            if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSANOW, &self.original) } == 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
}
/// # Safety
/// The caller must supply a live PAM handle and `argc` NUL terminated arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    handle: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let mut failure = IGNORE;
    catch_unwind(AssertUnwindSafe(|| {
        if argc < 0 || (argc > 0 && argv.is_null()) || handle.is_null() {
            return failure;
        }
        let mut args = Vec::new();
        for i in 0..argc as usize {
            // SAFETY: PAM supplies argc pointers to NUL terminated module arguments.
            let arg = unsafe { *argv.add(i) };
            if arg.is_null() {
                return failure;
            }
            // SAFETY: validated PAM argument pointer.
            let arg = unsafe { CStr::from_ptr(arg) }
                .to_string_lossy()
                .into_owned();
            if arg == "mode=lock" {
                failure = UNAVAILABLE;
            } else if arg == "mode=sudo" {
                failure = IGNORE;
            }
            args.push(arg);
        }
        let Some(options) = Options::parse(&args) else {
            return failure;
        };
        failure = options.failure();
        crate::auth::authenticate(Handle(handle), &options).unwrap_or(failure)
    }))
    .unwrap_or(failure)
}
/// # Safety
/// Called by PAM with its standard module ABI; arguments are unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _handle: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    catch_unwind(|| IGNORE).unwrap_or(IGNORE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    #[test]
    fn panic_unwinds_terminal_guard() {
        // SAFETY: openpty initializes both file descriptors and the slave name.
        let (master, slave, path) = unsafe {
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
            (
                File::from_raw_fd(master),
                File::from_raw_fd(slave),
                CStr::from_ptr(name.as_ptr()).to_str().unwrap().to_owned(),
            )
        };
        let original = Terminal::open(&path).unwrap().original;
        let result = catch_unwind(|| {
            let terminal = Terminal::open(&path).unwrap();
            terminal.raw().unwrap();
            panic!("exercise restoration during unwind");
        });
        assert!(result.is_err());
        let restored = Terminal::open(&path).unwrap().original;
        assert_eq!(original.c_lflag, restored.c_lflag);
        assert_eq!(original.c_iflag, restored.c_iflag);
        assert_eq!(original.c_oflag, restored.c_oflag);
        assert_eq!(original.c_cflag, restored.c_cflag);
        assert_eq!(original.c_cc, restored.c_cc);
        drop((master, slave));
    }
}
