use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use omamori_ipc::{Event, Input};
use std::{
    fs,
    io::{self, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = omamori_ipc::DEFAULT_SOCKET, global = true)]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Status {
        #[arg(long)]
        json: bool,
    },
    Pair,
    Unpair,
    SetupPam {
        #[arg(long)]
        undo: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, hide = true)]
        skip_module_check: bool,
    },
}
fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes" | "YES"))
}
fn main() -> Result<()> {
    let args = Args::parse();
    if let Command::SetupPam {
        undo,
        yes,
        file,
        skip_module_check,
    } = args.command
    {
        return setup(file.as_deref(), undo, yes, skip_module_check);
    }
    let json_status = matches!(args.command, Command::Status { json: true });
    let mut socket = match UnixStream::connect(args.socket) {
        Ok(socket) => socket,
        Err(_) if json_status => {
            println!("{{\"daemon\":false}}");
            return Ok(());
        }
        Err(error) => return Err(error).context("connect to omamorid"),
    };
    let input = match args.command {
        Command::Status { .. } => Input::Status {},
        Command::Pair => Input::PairBegin {},
        Command::Unpair => Input::Unpair {},
        _ => unreachable!(),
    };
    omamori_ipc::send(&mut socket, &input)?;
    loop {
        match omamori_ipc::receive(&mut socket)? {
            Event::Status { fields } => {
                if json_status {
                    println!("{}", serde_json::to_string(&fields)?);
                    return Ok(());
                }
                for (key, value) in fields {
                    println!("{key}: {value}");
                }
                return Ok(());
            }
            Event::PairCode { code, watch_name } => {
                println!("Pairing with {watch_name}: {code}");
                let accept = confirm("Do the codes match? [y/N] ")?;
                omamori_ipc::send(&mut socket, &Input::PairConfirm { accept })?;
            }
            Event::PairDone => {
                println!("Paired.");
                return Ok(());
            }
            Event::Denied { reason }
            | Event::Unavailable { reason }
            | Event::PairFailed { reason } => bail!("{reason}"),
            event => bail!("unexpected daemon event: {event:?}"),
        }
    }
}
const MARKED: &str = "-auth sufficient pam_omamori.so mode=sudo   # omamori\n";
fn patch(original: &str, undo: bool) -> String {
    let marked = |line: &str| line.trim_end().ends_with("# omamori");
    if undo {
        return original
            .split_inclusive('\n')
            .filter(|line| !marked(line))
            .collect();
    }
    if original.lines().any(marked) {
        return original.into();
    }
    // Insert after the last pam_howdy.so auth line (face recognition is quick
    // and should run first), otherwise before the first auth line.
    let is_auth = |line: &str| matches!(line.split_whitespace().next(), Some("auth" | "-auth"));
    let lines: Vec<&str> = original.split_inclusive('\n').collect();
    let at = lines
        .iter()
        .rposition(|l| is_auth(l) && l.split_whitespace().any(|w| w.ends_with("pam_howdy.so")))
        .map(|i| i + 1)
        .or_else(|| lines.iter().position(|l| is_auth(l)));
    let mut result = String::new();
    let mut inserted = false;
    for (i, line) in lines.iter().enumerate() {
        if Some(i) == at {
            result.push_str(MARKED);
            inserted = true;
        }
        result.push_str(line);
    }
    if !inserted {
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(MARKED);
    }
    result
}
/// Line diff for single-line inserts/removals: prints only changed lines with
/// their line numbers (old for '-', new for '+').
fn diff_lines(original: &str, updated: &str) -> Vec<String> {
    let old: Vec<&str> = original.lines().collect();
    let new: Vec<&str> = updated.lines().collect();
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < old.len() || j < new.len() {
        if i < old.len() && j < new.len() && old[i] == new[j] {
            i += 1;
            j += 1;
        } else if j < new.len() && (i >= old.len() || !old[i..].contains(&new[j])) {
            out.push(format!("+{:>3}: {}", j + 1, new[j]));
            j += 1;
        } else {
            out.push(format!("-{:>3}: {}", i + 1, old[i]));
            i += 1;
        }
    }
    out
}
fn print_diff(path: &Path, original: &str, updated: &str) {
    println!("--- {}\n+++ {}", path.display(), path.display());
    for line in diff_lines(original, updated) {
        println!("{line}");
    }
}
fn setup(explicit: Option<&Path>, undo: bool, yes: bool, skip_module_check: bool) -> Result<()> {
    let path = explicit.unwrap_or(Path::new("/etc/pam.d/sudo"));
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 && explicit.is_none() {
        bail!("setup-pam requires root, or an explicit writable --file");
    }
    if !skip_module_check && !Path::new("/usr/lib/security/pam_omamori.so").is_file() {
        bail!("/usr/lib/security/pam_omamori.so is missing");
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        bail!("PAM configuration must be a regular file");
    }
    // Opening for writing verifies the explicit-file exception without changing it.
    let _writable = fs::OpenOptions::new().write(true).open(path)?;
    let original = fs::read_to_string(path)?;
    let updated = patch(&original, undo);
    if updated == original {
        println!("No changes needed.");
        return Ok(());
    }
    print_diff(path, &original, &updated);
    io::stdout().flush()?;
    if !yes && !confirm("Apply this change? [y/N] ")? {
        return Ok(());
    }
    // Prepare a same-directory replacement and backup, preserving owner and mode.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut replacement = tempfile::NamedTempFile::new_in(parent)?;
    replacement.write_all(updated.as_bytes())?;
    preserve(replacement.as_file(), &metadata)?;
    replacement.as_file().sync_all()?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let mut backup_name = path.as_os_str().to_owned();
    backup_name.push(format!(".omamori-bak.{timestamp}"));
    let mut backup = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(PathBuf::from(backup_name))?;
    backup.write_all(original.as_bytes())?;
    preserve(&backup, &metadata)?;
    backup.sync_all()?;
    // Avoid overwriting a concurrent administrator's edit after the prompt.
    if fs::read_to_string(path)? != original {
        bail!("PAM configuration changed while preparing the edit");
    }
    replacement.persist(path).map_err(|e| e.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
fn preserve(file: &fs::File, metadata: &fs::Metadata) -> Result<()> {
    let current = file.metadata()?;
    if current.uid() != metadata.uid() || current.gid() != metadata.gid() {
        // SAFETY: file fd is live; uid/gid come from the target metadata.
        if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    file.set_permissions(fs::Permissions::from_mode(metadata.mode()))?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    const HOWDY_SUDO: &str = "auth      sufficient pam_howdy.so\nauth      [success=1 default=ignore] pam_exec.so quiet /usr/bin/omarchy-hw-laptop-closed\nauth      sufficient pam_fprintd.so\n#%PAM-1.0\nauth           include         system-auth\naccount                include         system-auth\n";
    #[test]
    fn inserted_after_howdy_before_fprintd() {
        let out = patch(HOWDY_SUDO, false);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("pam_howdy.so"));
        assert_eq!(lines[1], MARKED.trim_end());
        assert!(lines[2].contains("pam_exec.so"));
        assert_eq!(patch(&out, false), out, "idempotent");
        assert_eq!(patch(&out, true), HOWDY_SUDO, "undo restores");
    }
    #[test]
    fn diff_shows_only_the_inserted_line() {
        let out = patch(HOWDY_SUDO, false);
        assert_eq!(
            diff_lines(HOWDY_SUDO, &out),
            vec![format!("+  2: {}", MARKED.trim_end())]
        );
        assert_eq!(
            diff_lines(&out, HOWDY_SUDO),
            vec![format!("-  2: {}", MARKED.trim_end())]
        );
    }
    #[test]
    fn arch_default_and_idempotence() {
        let original = "#%PAM-1.0\n\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\n";
        let updated = patch(original, false);
        assert_eq!(
            updated,
            original.replacen("auth\t", &format!("{MARKED}auth\t"), 1)
        );
        assert_eq!(patch(&updated, false), updated);
        assert_eq!(patch(&updated, true), original);
        assert_eq!(
            patch("# auth\n-auth required x\n", false),
            format!("# auth\n{MARKED}-auth required x\n")
        );
    }
    #[test]
    fn undo_only_marker_at_end() {
        assert_eq!(
            patch("auth x # omamori other\nauth y # omamori\n# keep\n", true),
            "auth x # omamori other\n# keep\n"
        );
    }
    #[test]
    fn atomic_setup_preserves_mode_and_backup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("sudo");
        fs::write(&path, "auth required pam_deny.so\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&path).unwrap();
        setup(Some(&path), false, true, true).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(
            (after.mode(), after.uid(), after.gid()),
            (before.mode(), before.uid(), before.gid())
        );
        setup(Some(&path), false, true, true).unwrap();
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
        let backup = fs::read_dir(temp.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p != &path)
            .unwrap();
        assert_eq!(
            fs::read_to_string(backup).unwrap(),
            "auth required pam_deny.so\n"
        );
        setup(Some(&path), true, true, true).unwrap();
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "auth required pam_deny.so\n"
        );
    }
}
