use crate::engine::{Command, Input};
use anyhow::{Context, Result, bail};
use nix::unistd::{Uid, User};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt},
    path::Path,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::mpsc,
};

/// Real kernel credentials are always used. Only the root policy is injectable.
#[derive(Clone, Default)]
pub struct Policy {
    #[cfg(feature = "test-harness")]
    root_uids: std::collections::BTreeSet<u32>,
}
impl Policy {
    pub fn is_root(&self, uid: u32) -> bool {
        #[cfg(feature = "test-harness")]
        if self.root_uids.contains(&uid) {
            return true;
        }
        uid == 0
    }
    #[cfg(feature = "test-harness")]
    pub fn with_root_uid(uid: u32) -> Self {
        Self {
            root_uids: [uid].into_iter().collect(),
        }
    }
}
pub fn bind(path: &Path) -> Result<UnixListener> {
    let dir = path.parent().context("socket needs parent directory")?;
    if !dir.exists() {
        fs::DirBuilder::new().mode(0o755).create(dir)?;
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != nix::unistd::geteuid().as_raw()
    {
        bail!("socket directory must be owned by daemon and must not be a symlink");
    }
    if meta.permissions().mode() & 0o022 != 0 {
        bail!("socket directory is writable by group/world");
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                bail!("socket path is not a socket");
            }
            // Never unlink an active listener.
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => bail!("socket already has a live listener"),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?
                }
                Err(e) => return Err(e).context("probe stale socket"),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}
use std::os::unix::fs::MetadataExt;

/// Bounded line reader: no allocation proportional to an untrusted line.
async fn line(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    out: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if out.is_empty() {
                return Ok(None);
            }
            bail!("unterminated IPC line");
        }
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |n| n + 1);
        if out.len() + n > 4096 {
            bail!("IPC line exceeds 4 KiB");
        }
        out.extend_from_slice(&buf[..n]);
        reader.consume(n);
        if out.last() == Some(&b'\n') {
            return Ok(Some(std::mem::take(out)));
        }
    }
}
pub(crate) async fn connection(stream: UnixStream, id: u64, commands: mpsc::Sender<Command>) {
    let result = serve(stream, id, commands.clone()).await;
    if result.is_err() {
        tracing::debug!(connection = id, "IPC connection closed");
    }
    let _ = commands.send(Command::Disconnect(id)).await;
}
async fn serve(stream: UnixStream, id: u64, commands: mpsc::Sender<Command>) -> Result<()> {
    let uid = stream.peer_cred()?.uid();
    let name = User::from_uid(Uid::from_raw(uid))?
        .context("peer uid has no user name")?
        .name;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let (reply, mut events) = mpsc::channel::<Value>(32);
    let mut input_buffer = Vec::new();
    loop {
        tokio::select! {
            data = line(&mut reader, &mut input_buffer) => {
                let Some(data) = data? else { break; };
                let input: Input = serde_json::from_slice(&data)?;
                commands.send(Command::Ipc { id, uid, name: name.clone(), input, reply: reply.clone() }).await?;
            }
            event = events.recv() => {
                let Some(event) = event else { break; };
                let terminal = matches!(event["ev"].as_str(), Some("approved" | "unavailable" | "denied" | "pair-done" | "pair-failed"));
                let mut bytes = serde_json::to_vec(&event)?;
                bytes.push(b'\n');
                tokio::time::timeout(std::time::Duration::from_secs(5), write.write_all(&bytes)).await??;
                if terminal { break; }
            }
        }
    }
    Ok(())
}
