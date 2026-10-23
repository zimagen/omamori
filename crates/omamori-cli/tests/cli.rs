use omamori_ipc::{Event, Input};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    process::{Command, Stdio},
};

#[test]
fn status_and_unpair_use_ipc() {
    for unpair in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(socket.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let input: Input = serde_json::from_str(&line).unwrap();
            assert!(if unpair {
                matches!(input, Input::Unpair {})
            } else {
                matches!(input, Input::Status {})
            });
            socket
                .write_all(b"{\"ev\":\"status\",\"paired\":false}\n")
                .unwrap();
        });
        let output = Command::new(env!("CARGO_BIN_EXE_omamori"))
            .arg("--socket")
            .arg(socket)
            .arg(if unpair { "unpair" } else { "status" })
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(output.status.success());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("paired: false")
        );
    }
}

#[test]
fn pair_displays_code_and_requires_explicit_acceptance() {
    for (answer, accepted) in [("y\n", true), ("\n", false)] {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(matches!(
                serde_json::from_str::<Input>(&line).unwrap(),
                Input::PairBegin {}
            ));
            let event = Event::PairCode {
                code: "123456".into(),
                watch_name: "Venu".into(),
            };
            socket
                .write_all(&serde_json::to_vec(&event).unwrap())
                .unwrap();
            socket.write_all(b"\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert!(
                matches!(serde_json::from_str::<Input>(&line).unwrap(), Input::PairConfirm {accept} if accept == accepted)
            );
            socket
                .write_all(if accepted {
                    b"{\"ev\":\"pair-done\"}\n"
                } else {
                    b"{\"ev\":\"pair-failed\",\"reason\":\"rejected\"}\n"
                })
                .unwrap();
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_omamori"))
            .arg("--socket")
            .arg(socket)
            .arg("pair")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(answer.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        server.join().unwrap();
        assert_eq!(output.status.success(), accepted);
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("123456")
                && text.contains("Venu")
                && text.contains("Do the codes match? [y/N]")
        );
    }
}

#[test]
fn json_status_preserves_daemon_fields() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("socket");
    let listener = UnixListener::bind(&path).unwrap();
    let fields = serde_json::json!({
        "paired": true, "watch_name": "Venu <4>", "host_name": "desktop",
        "adapter_powered": true, "advertising": true,
        "pending": [{"id": "0123456789abcdef", "uid": 1000, "kind": "sudo",
                     "title": "sudo pacman", "detail": "tty1"}],
        "future_field": {"preserved": true}
    });
    let expected = fields.clone();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(socket.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(matches!(
            serde_json::from_str::<Input>(&line).unwrap(),
            Input::Status {}
        ));
        let mut event = fields;
        event["ev"] = "status".into();
        writeln!(socket, "{event}").unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_omamori"))
        .arg("--socket")
        .arg(path)
        .args(["status", "--json"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(output.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        expected
    );
}

#[test]
fn unreachable_daemon_is_success_only_for_json_status() {
    let temp = tempfile::tempdir().unwrap();
    for json in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_omamori"));
        command
            .arg("--socket")
            .arg(temp.path().join("missing"))
            .arg("status");
        if json {
            command.arg("--json");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(if json { 0 } else { 1 }));
        if json {
            assert_eq!(output.stdout, b"{\"daemon\":false}\n");
            assert!(output.stderr.is_empty());
        } else {
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("connect to omamorid")
            );
        }
    }
}
