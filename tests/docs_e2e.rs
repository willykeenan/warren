//! Documented user flows exercised against a real relay and node daemons on
//! loopback.

mod common;

use common::*;
use std::time::Duration;
use warren::node::control::ControlRequest;
use warren::relay::db::JoinOutcome;

/// docs/relay.md: "To replace a machine's keys (e.g. a reinstall), revoke it,
/// create an invite with `--name` for the same name and run
/// `warren join --force` on the machine." On a machine where `warren up` (or
/// the login service) is running, `join --force` succeeds and prints
/// "next: `warren up`", but the running daemon keeps authenticating with the
/// revoked identity forever (`warren up` then says it is already running).
/// Either `join` must refuse while the daemon runs, or the daemon must pick
/// up the new identity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_force_while_daemon_runs_leaves_it_on_revoked_keys() {
    let relay = start_relay().await;
    let mut b = enroll_started(&relay, "b").await;
    let old_fp = b.ident().fingerprint();

    assert!(relay.h().inner.db.revoke("b", warren::now_secs()).unwrap());
    wait_for("b to be disconnected", Duration::from_secs(10), || {
        !relay.online().contains(&"b".to_string())
    })
    .await;
    let code = relay.invite(Some("b"));
    let joined =
        warren::node::join(&b.paths, &code, &relay.url(), None, Some(relay.pin), true).await;
    match joined {
        Err(e) => {
            // Acceptable behaviour: refuse and say why.
            assert!(
                e.to_string().contains("running"),
                "join --force failed for another reason: {e}"
            );
        }
        Ok(f) => {
            let new_fp = f.fingerprint();
            assert_ne!(old_fp, new_fp);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                let st = b.ctl_ok(ControlRequest::Status).await;
                if st["node"]["fingerprint"] == new_fp.as_str()
                    && st["connection"]["state"] == "connected"
                {
                    break;
                }
                if tokio::time::Instant::now() > deadline {
                    panic!(
                        "15 s after `join --force` the running daemon still uses the revoked \
                         identity {old_fp} (new {new_fp}); status: {st}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    b.stop().await;
}

/// `warren devices` must work on a relay with a few hundred machines. The
/// relay answers with one CTRL frame whose payload is limited to 65535 bytes
/// (`Frame::ctrl` never checks the size), so past roughly 230 enrolled nodes
/// the reply is a malformed frame: the asking node's whole relay connection
/// is dropped (resetting every forward and ssh session on it) and `devices`
/// fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn devices_with_a_few_hundred_enrolled_machines() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let db = &relay.h().inner.db;
    let now = warren::now_secs();
    for i in 0..300u32 {
        let code = db
            .create_invite(None, Duration::from_secs(600), now)
            .unwrap();
        let mut sign = [7u8; 32];
        sign[..4].copy_from_slice(&i.to_be_bytes());
        let mut stat = [9u8; 32];
        stat[..4].copy_from_slice(&i.to_be_bytes());
        let name = format!("machine-{i:03}-{}", "x".repeat(20));
        assert_eq!(name.len(), 32);
        assert!(matches!(
            db.join(&code, Some(&name), &sign, &stat, now).unwrap(),
            JoinOutcome::Joined(_)
        ));
    }
    relay.h().inner.reload().unwrap();

    let before = a.ctl_ok(ControlRequest::Status).await["connection"]["connects"].clone();
    let r = a.ctl(ControlRequest::Devices).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = a.ctl_ok(ControlRequest::Status).await["connection"]["connects"].clone();
    let n = r.result.as_array().map(|v| v.len()).unwrap_or(0);
    assert!(
        r.ok && n == 301 && before == after,
        "devices with 301 machines: ok={} code={:?} error={:?} entries={n}; \
         relay connections before/after: {before}/{after}",
        r.ok,
        r.code,
        r.error
    );
}

/// README: "`warren down` | stop the running daemon", and `down` makes the
/// daemon exit with status 0. The login service `warren install` writes
/// restarts it unconditionally (launchd `KeepAlive` = true, systemd
/// `Restart=always`), so on an installed machine `warren down` is undone
/// within seconds.
#[test]
fn installed_service_does_not_undo_warren_down() {
    use warren::install::{launchd_plist, systemd_unit, Flavor, InstallOptions};
    let o = InstallOptions {
        flavor: Flavor::Launchd,
        exe: "/usr/local/bin/warren".into(),
        warren_home: "/home/me/.warren".into(),
        custom_home: false,
        dir: None,
        start: false,
    };
    let plist = launchd_plist(&o);
    assert!(
        !plist.contains("<key>KeepAlive</key>\n    <true/>"),
        "launchd restarts a job with KeepAlive=true even after a clean exit:\n{plist}"
    );
    let unit = systemd_unit(&InstallOptions {
        flavor: Flavor::Systemd,
        ..o
    });
    assert!(
        !unit.contains("Restart=always"),
        "systemd restarts a Restart=always unit even after a clean exit:\n{unit}"
    );
}
