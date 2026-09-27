//! The real binary against the documented exit codes and the "every command
//! supports --json" promise. Nothing here contacts a network host: every case
//! fails before a connection would be attempted (and the only relay URLs used
//! point at loopback port 1).

use std::path::Path;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_warren");

fn run(root: &Path, args: &[&str]) -> (i32, String, String) {
    run_home(root, &root.join("w"), args)
}

fn run_home(root: &Path, home: &Path, args: &[&str]) -> (i32, String, String) {
    std::fs::create_dir_all(root.join("fakehome")).unwrap();
    let o = Command::new(BIN)
        .env("HOME", root.join("fakehome"))
        .env("WARREN_HOME", home)
        .env("WARREN_LAUNCHD_DIR", root.join("launchd"))
        .env("WARREN_SYSTEMD_DIR", root.join("systemd"))
        .env_remove("XDG_CONFIG_HOME")
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into(),
        String::from_utf8_lossy(&o.stderr).into(),
    )
}

/// README "Exit codes": 2 = usage error, 5 = "not connected to the relay (or
/// the relay is unreachable during `join`)". An invalid `--name` or a
/// non-https `--relay` is a usage error found before any connection: exit 2,
/// not 5 with code `relay_unreachable`.
#[test]
fn join_usage_errors_are_usage_errors_not_relay_unreachable() {
    let t = tempfile::tempdir().unwrap();

    let (code, out, err) = run(
        t.path(),
        &[
            "--json",
            "join",
            "ABCDEFGHJK",
            "--relay",
            "https://127.0.0.1:1",
            "--name",
            "Bad_Name",
        ],
    );
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|_| panic!("not JSON: {out:?} / {err:?}"));
    assert_ne!(
        v["code"], "relay_unreachable",
        "an invalid --name is not an unreachable relay: {v}"
    );
    assert_eq!(
        code, 2,
        "invalid --name must exit 2 (usage), got {code}: {v}"
    );

    let (code, out, _) = run(
        t.path(),
        &[
            "--json",
            "join",
            "ABCDEFGHJK",
            "--relay",
            "http://127.0.0.1:1",
            "--name",
            "a",
        ],
    );
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        code, 2,
        "a non-https --relay must exit 2 (usage), got {code}: {v}"
    );
}

/// "every command supports `--json`": argument errors detected by the parser
/// are a JSON object on stdout with exit 2, like the usage errors the CLI
/// detects itself (e.g. `share 0`), so a script can tell them from a crash.
#[test]
fn json_flag_also_covers_argument_errors() {
    let t = tempfile::tempdir().unwrap();

    // Baseline: a usage error detected by the CLI itself is JSON.
    let (code, out, _) = run(t.path(), &["--json", "share", "0"]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["ok"], false);

    // The same kind of mistake caught by argument parsing.
    let (code, out, err) = run(t.path(), &["--json", "forward", "abc", "b:22"]);
    assert_eq!(code, 2);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&out);
    assert!(
        parsed.is_ok_and(|v| v["ok"] == false),
        "with --json a usage error must be a JSON object on stdout; stdout={out:?} stderr={err:?}"
    );
}

/// A WARREN_HOME too long to hold the control socket is refused before
/// enrolling (so the code is not used up), and other commands explain it.
#[test]
fn too_long_warren_home_is_explained() {
    let t = tempfile::tempdir().unwrap();
    let home = t.path().join("h".repeat(120));
    let (code, out, err) = run_home(
        t.path(),
        &home,
        &[
            "--json",
            "join",
            "ABCDEFGHJK",
            "--relay",
            "https://127.0.0.1:1",
            "--name",
            "a",
        ],
    );
    let v: serde_json::Value =
        serde_json::from_str(&out).unwrap_or_else(|_| panic!("not JSON: {out:?} / {err:?}"));
    assert_eq!(code, 2, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("use a shorter WARREN_HOME"),
        "{v}"
    );
    let (code, out, _) = run_home(t.path(), &home, &["--json", "status"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (code, v["code"].as_str()),
        (1, Some("home_too_long")),
        "{v}"
    );
}
