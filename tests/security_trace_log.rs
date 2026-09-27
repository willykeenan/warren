//! SR8: no WARREN_LOG setting writes enrollment codes or published traffic to
//! the log.
//!
//! `WARREN_LOG` applies to warren's own log targets only. Libraries that log
//! whole protocol messages at debug and trace level (the WebSocket library
//! logs every message it reads or writes) stay at `warn` whatever it says.

use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_warren");

fn cmd(root: &std::path::Path, home: &str, log: &str) -> Command {
    let mut c = Command::new(BIN);
    c.env("HOME", root.join("fakehome"))
        .env("WARREN_HOME", root.join(home))
        .env("WARREN_LOG", log)
        .env("WARREN_LAUNCHD_DIR", root.join("launchd"))
        .env("WARREN_SYSTEMD_DIR", root.join("systemd"))
        .env_remove("XDG_CONFIG_HOME")
        .kill_on_drop(true);
    c
}

async fn run(root: &std::path::Path, home: &str, args: &[&str]) -> (i32, String) {
    let o = cmd(root, home, "warn")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trace_level_relay_log_contains_no_enrollment_codes() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    std::fs::create_dir_all(root.join("fakehome")).unwrap();
    let state = root.join("relay-state");
    let state_s = state.to_str().unwrap();
    let relay_log = root.join("relay.log");

    let mut relay = cmd(root, "relayhome", "trace")
        .args([
            "--json",
            "relay",
            "--self-signed",
            "--listen",
            "127.0.0.1:0",
            "--domain",
            "127.0.0.1",
            "--state",
            state_s,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(std::fs::File::create(&relay_log).unwrap()))
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(relay.stdout.take().unwrap());
    let mut first = String::new();
    loop {
        let mut l = String::new();
        let n = tokio::time::timeout(Duration::from_secs(20), lines.read_line(&mut l))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "relay exited");
        first.push_str(&l);
        if l.starts_with('}') {
            break;
        }
    }
    let ev: serde_json::Value = serde_json::from_str(&first).unwrap();
    let port: u16 = ev["addr"]
        .as_str()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let pin = ev["cert_sha256"].as_str().unwrap().to_string();
    let url = format!("https://127.0.0.1:{port}");

    let invite = || async {
        let (code, out) = run(
            root,
            "relayhome",
            &["--json", "relay", "invite", "--state", state_s],
        )
        .await;
        assert_eq!(code, 0, "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        v["code"].as_str().unwrap().to_string()
    };
    let join = |home: &'static str, code: String, name: &'static str| {
        let url = url.clone();
        let pin = pin.clone();
        async move {
            run(
                root,
                home,
                &[
                    "--json",
                    "join",
                    &code,
                    "--relay",
                    &url,
                    "--name",
                    name,
                    "--insecure-relay-cert-sha256",
                    &pin,
                ],
            )
            .await
        }
    };

    // A normal enrollment as "a".
    let c1 = invite().await;
    let (rc, out) = join("a", c1.clone(), "a").await;
    assert_eq!(rc, 0, "{out}");
    // A second machine asks for a taken name: refused, code not consumed.
    let c2 = invite().await;
    let (rc, out) = join("b", c2.clone(), "a").await;
    assert_ne!(rc, 0, "{out}");
    assert!(out.contains("name_taken"), "{out}");

    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = std::fs::read_to_string(&relay_log).unwrap();

    let leaked: Vec<&String> = [&c1, &c2]
        .into_iter()
        .filter(|c| log.contains(c.as_str()))
        .collect();
    if leaked.contains(&&c2) {
        // Whoever reads the log can still enroll with the leaked code.
        let (rc, out) = join("mallory", c2.clone(), "mallory").await;
        let _ = relay.start_kill();
        panic!(
            "the relay log at WARREN_LOG=trace contains enrollment codes {leaked:?}; \
             the unconsumed one enrolled another machine: exit {rc}, {out}"
        );
    }
    let _ = relay.start_kill();
    let _ = relay.wait().await;
    assert!(
        leaked.is_empty(),
        "codes {leaked:?} appear in the relay log"
    );
}
