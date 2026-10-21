//! PAM authentication with a password fallback. All FFI is confined to `ffi`.
mod auth;
mod ffi;

/// Return (skip watch authentication, command arguments). Values belonging to
/// sudo options are consumed before inspecting the command's own arguments.
pub fn sudo_arguments(args: &[String]) -> (bool, Vec<String>) {
    const LONG_VALUES: &[&str] = &[
        "user",
        "group",
        "host",
        "prompt",
        "close-from",
        "chdir",
        "chroot",
        "command-timeout",
        "other-user",
        "role",
        "type",
    ];
    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, false), |(n, _)| (n, true));
            if matches!(name, "stdin" | "askpass" | "non-interactive") {
                return (true, vec![]);
            }
            if LONG_VALUES.contains(&name) && !value {
                i += 1;
            }
        } else {
            for (offset, c) in arg[1..].char_indices() {
                if matches!(c, 'S' | 'A' | 'n') {
                    return (true, vec![]);
                }
                if "ughpCDRTUrt".contains(c) {
                    if offset + c.len_utf8() == arg.len() - 1 {
                        i += 1;
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    (false, args[i.min(args.len())..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sudo_option_table() {
        for (line, skip, command) in [
            ("sudo -u root -S ls", true, ""),
            ("sudo -nS", true, ""),
            ("sudo -- -S", false, "-S"),
            ("sudo ls -S", false, "ls -S"),
            ("sudo --stdin", true, ""),
            ("sudo -A", true, ""),
            ("sudo -p -S ls", false, "ls"),
            ("sudo -uroot -n ls", true, ""),
            ("sudo --prompt=-S --user root ls", false, "ls"),
        ] {
            let args = line
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let result = sudo_arguments(&args);
            assert_eq!(
                result,
                (
                    skip,
                    command.split_whitespace().map(str::to_owned).collect()
                ),
                "{line}"
            );
        }
        for flag in [
            "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t",
        ] {
            assert_eq!(
                sudo_arguments(&["sudo".into(), flag.into(), "-S".into(), "ls".into()]),
                (false, vec!["ls".into()])
            );
        }
    }
}
