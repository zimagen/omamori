use anyhow::{Context, Result, bail};
use getrandom::SysRng;
use nix::{libc, unistd::geteuid};
use omamori_proto::{crypto::Key, wire::HostId};
use rand_core::{Rng, UnwrapErr};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pairing {
    pub watch_name: String,
    pub key: [u8; 32],
    pub time: u64,
}
impl Pairing {
    pub fn new(watch_name: String, key: Key) -> Self {
        Self {
            watch_name,
            key: *key.as_bytes(),
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}
impl Drop for Pairing {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub host_id: HostId,
    pub pairing: Option<Pairing>,
}
pub struct Store {
    dir: PathBuf,
    // Held for the daemon lifetime; prevents two processes sharing state/socket.
    _lock: nix::fcntl::Flock<File>,
}
fn check(path: &Path, directory: bool) -> Result<()> {
    let m = fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if m.file_type().is_symlink() || (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        bail!(
            "{} must be a {} (no symlinks)",
            path.display(),
            if directory {
                "directory"
            } else {
                "regular file"
            }
        );
    }
    if m.uid() != geteuid().as_raw() {
        bail!(
            "{} is not owned by daemon euid {}",
            path.display(),
            geteuid()
        );
    }
    if m.mode() & 0o077 != 0 {
        bail!(
            "{} is group/world accessible (mode {:o})",
            path.display(),
            m.mode() & 0o777
        );
    }
    Ok(())
}
impl Store {
    pub fn open(dir: &Path) -> Result<(Self, State)> {
        if !dir.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .context("create state dir")?;
        }
        check(dir, true)?;
        let lock_path = dir.join(".daemon.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        check(&lock_path, false)?;
        let lock = nix::fcntl::Flock::lock(lock, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| anyhow::anyhow!("another daemon owns the state directory: {e}"))?;
        let store = Self {
            dir: dir.to_owned(),
            _lock: lock,
        };
        let path = dir.join("state.json");
        let exists = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let state = if exists {
            check(&path, false)?;
            let mut text = zeroize::Zeroizing::new(String::new());
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?
                .read_to_string(&mut text)?;
            serde_json::from_str(&text).map_err(|_| anyhow::anyhow!("invalid state.json; expected host_id and optional pairing (watch_name, key, time)"))?
        } else {
            let mut host_id = [0; 16];
            UnwrapErr(SysRng).fill_bytes(&mut host_id);
            let state = State {
                host_id,
                pairing: None,
            };
            store.save(&state)?;
            state
        };
        Ok((store, state))
    }
    pub fn save(&self, state: &State) -> Result<()> {
        let mut random = [0; 8];
        UnwrapErr(SysRng).fill_bytes(&mut random);
        let temp = self
            .dir
            .join(format!(".state-{:016x}.tmp", u64::from_be_bytes(random)));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)?;
            let bytes = zeroize::Zeroizing::new(serde_json::to_vec(state)?);
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temp, self.dir.join("state.json"))?;
            File::open(&self.dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result.context("persist state")
    }
}
