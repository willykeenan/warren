//! Documented user flows exercised against a real relay and node daemons on
//! loopback.

mod common;

use common::*;
use std::time::Duration;
use warren::node::control::ControlRequest;
use warren::relay::db::JoinOutcome;

/// docs/relay.md: to replace a machine's keys, revoke it, create an invite
/// with `--name` for the same name, stop the daemon and run
/// `warren join --force`. A running daemon loaded the old identity and would
/// keep authenticating with the revoked keys, so `join --force` refuses while
/// it runs and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_force_refuses_while_the_daemon_runs() {
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
    let e = joined.expect_err("join --force must refuse while the daemon runs");
    assert!(
        e.to_string().contains("running"),
        "join --force failed for another reason: {e}"
    );
    assert_eq!(b.ident().fingerprint(), old_fp, "the identity is unchanged");
    // Stopped, the same code enrolls new keys.
    b.stop().await;
    let f = warren::node::join(&b.paths, &code, &relay.url(), None, Some(relay.pin), true)
        .await
        .unwrap();
    assert_ne!(f.fingerprint(), old_fp);
    b.start_connected().await;
    let st = b.ctl_ok(ControlRequest::Status).await;
    assert_eq!(st["node"]["fingerprint"], f.fingerprint().as_str());
    b.stop().await;
}

/// A WARREN_HOME too long for a Unix socket path is refused with an
/// explanation, by the daemon and by the CLI's control requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_long_home_is_explained() {
    let relay = start_relay().await;
    let a = enroll(&relay, "a").await;
    let deep = a.dir.path().join("d".repeat(120));
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::copy(a.paths.identity(), deep.join("identity.json")).unwrap();
    let paths = warren::node::NodePaths::new(&deep);
    let cfg = warren::node::daemon::DaemonConfig::new(paths.clone());
    let e = warren::node::daemon::start(cfg)
        .await
        .err()
        .expect("the daemon cannot bind its control socket");
    assert!(
        format!("{e:#}").contains("use a shorter WARREN_HOME"),
        "{e:#}"
    );
    let e = warren::node::control::request(&paths, &ControlRequest::Status)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("use a shorter WARREN_HOME"), "{e}");
}

/// `warren devices` works on a relay with a few hundred machines: the answer
/// is paged, so no CTRL frame exceeds the 65535-byte payload limit, and the
/// asking node's relay connection (with every forward and ssh session on it)
/// stays up.
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
/// restarts the daemon only after a failure (launchd `KeepAlive` on
/// unsuccessful exit, systemd `Restart=on-failure`), so `warren down` is not
/// undone on an installed machine.
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
