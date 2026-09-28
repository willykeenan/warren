mod common;
use common::*;
use std::time::Duration;
use warren::node::{
    daemon::{self, DaemonConfig},
    embedded::{self, EmbeddedClient},
    Forward, ForwardsFile, NodePaths, Publish, PublishesFile, SharesFile,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn long_app_path_enrolls_without_ipc_and_ignores_malformed_desktop_policy() {
    let relay = start_relay().await;
    let dir = tempfile::tempdir().unwrap();
    // Exceed the platform socket limit even when the runner uses a short /tmp root.
    // This remains a valid filesystem component on each supported platform.
    let paths = NodePaths::new(
        dir.path()
            .join("s".repeat(warren::node::MAX_SOCKET_PATH + 1)),
    );
    #[cfg(unix)]
    assert!(paths.check_control().is_err());
    let code = relay.invite(None);
    let identity = embedded::join(
        &paths.home,
        &code,
        &relay.url(),
        Some("phone"),
        Some(relay.pin),
    )
    .await
    .unwrap();
    let original = std::fs::read(paths.identity()).unwrap();
    assert!(embedded::join(
        &paths.home,
        &code,
        &relay.url(),
        Some("phone"),
        Some(relay.pin)
    )
    .await
    .is_err());
    assert_eq!(std::fs::read(paths.identity()).unwrap(), original);
    for file in [paths.shares(), paths.forwards(), paths.publishes()] {
        std::fs::write(file, b"{").unwrap();
    }
    #[cfg(unix)]
    std::fs::write(paths.socket(), b"unrelated sentinel; never remove").unwrap();
    let client = EmbeddedClient::start(&paths.home).await.unwrap();
    assert!(client.wait_connected(Duration::from_secs(5)).await);
    assert!(EmbeddedClient::start(&paths.home).await.is_err());
    assert!(daemon::start(DaemonConfig::new(paths.clone()))
        .await
        .is_err());
    assert!(embedded::join(
        &paths.home,
        &relay.invite(None),
        &relay.url(),
        None,
        Some(relay.pin)
    )
    .await
    .is_err());
    client.shutdown().await;
    wait_for("embedded disconnect", Duration::from_secs(3), || {
        !relay.online().contains(&identity.name)
    })
    .await;
    #[cfg(unix)]
    assert_eq!(
        std::fs::read(paths.socket()).unwrap(),
        b"unrelated sentinel; never remove"
    );
    let restarted = EmbeddedClient::start(&paths.home).await.unwrap();
    restarted.shutdown().await;
    #[cfg(unix)]
    {
        let other = NodePaths::new(paths.home.join("desktop"));
        assert!(warren::node::join(
            &other,
            &relay.invite(None),
            &relay.url(),
            None,
            Some(relay.pin),
            false
        )
        .await
        .is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn seeded_inbound_shares_forwards_and_publishes_never_activate() {
    let relay = start_relay().await;
    let phone = enroll(&relay, "phone").await;
    let peer = enroll_started(&relay, "peer").await;
    let (port, accepts) = echo_server().await;
    let mut shares = SharesFile::default();
    shares.set(port, None);
    shares.save(&phone.paths).unwrap();
    let local = free_port().await;
    ForwardsFile {
        forwards: vec![Forward {
            local,
            node: "peer".into(),
            port,
            share: None,
        }],
    }
    .save(&phone.paths)
    .unwrap();
    PublishesFile {
        publishes: vec![Publish {
            name: "phone-pub".into(),
            port,
            url: "https://unused.invalid".into(),
            allow: vec![],
        }],
    }
    .save(&phone.paths)
    .unwrap();
    let client = EmbeddedClient::start(&phone.paths.home).await.unwrap();
    assert!(client.wait_connected(Duration::from_secs(5)).await);
    assert!(tokio::net::TcpListener::bind(("127.0.0.1", local))
        .await
        .is_ok());
    #[cfg(unix)]
    assert!(!phone.paths.socket().exists());
    assert!(peer.d().inner.open_private("phone", port).await.is_err());
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    {
        let captures = relay.captures.lock().unwrap();
        for (dir, bytes) in captures.iter() {
            if !matches!(dir, warren::mux::TapDir::In) {
                continue;
            }
            let frame = warren::proto::Frame::decode(bytes.clone().into()).unwrap();
            if frame.ty == warren::proto::FrameType::Ctrl {
                if let Ok(request) =
                    serde_json::from_slice::<warren::proto::CtrlRequest>(&frame.payload)
                {
                    assert!(!matches!(request.op, warren::proto::CtrlOp::Publish { .. }));
                }
            }
        }
    }
    drop(client);
    wait_for("drop disconnect", Duration::from_secs(3), || {
        !relay.online().contains(&"phone".into())
    })
    .await;
}

#[tokio::test]
async fn corrupt_existing_identity_and_relative_root_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(dir.path().join("home"));
    paths.ensure().unwrap();
    std::fs::write(paths.identity(), b"{").unwrap();
    assert!(
        embedded::join(&paths.home, "bad", "https://invalid.invalid", None, None)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(paths.identity()).unwrap(), b"{");
    assert!(EmbeddedClient::start(std::path::Path::new("relative-home"))
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "subprocess fixture entry, explicitly invoked by its parent test"]
async fn lease_holder_child() {
    let root = std::env::var_os("WARREN_EMBEDDED_TEST_ROOT").expect("parent supplied fixture root");
    let client = EmbeddedClient::start(std::path::Path::new(&root))
        .await
        .unwrap();
    std::fs::write(std::path::Path::new(&root).join("lease-ready"), b"ready").unwrap();
    tokio::time::sleep(Duration::from_secs(30)).await;
    client.shutdown().await;
}

#[tokio::test]
#[ignore = "subprocess fixture entry, explicitly invoked by its parent test"]
async fn lease_probe_child() {
    let root = std::env::var_os("WARREN_EMBEDDED_TEST_ROOT").expect("parent supplied fixture root");
    let expected = std::env::var("WARREN_EMBEDDED_EXPECT_ACQUIRED").unwrap() == "true";
    let result = EmbeddedClient::start(std::path::Path::new(&root)).await;
    assert_eq!(result.is_ok(), expected, "external ownership result");
    if let Ok(client) = result {
        client.shutdown().await;
    }
}

async fn assert_external_ownership(root: &std::path::Path, acquired: bool) {
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lease_probe_child", "--ignored", "--nocapture"])
        .env("WARREN_EMBEDDED_TEST_ROOT", root)
        .env("WARREN_EMBEDDED_EXPECT_ACQUIRED", acquired.to_string())
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(10), output)
        .await
        .expect("external ownership probe bounded")
        .unwrap();
    assert!(
        output.status.success(),
        "external ownership probe: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn aliased_parent_enrolls_and_shares_exact_ownership_with_canonical_root() {
    let relay = start_relay().await;
    let dir = tempfile::tempdir().unwrap();
    let real_parent = dir.path().canonicalize().unwrap().join("real");
    std::fs::create_dir(&real_parent).unwrap();
    let alias_parent = dir.path().join("alias");
    std::os::unix::fs::symlink(&real_parent, &alias_parent).unwrap();
    let alias = alias_parent.join("phone");
    let canonical = real_parent.join("phone");
    embedded::join(
        &alias,
        &relay.invite(None),
        &relay.url(),
        Some("phone"),
        Some(relay.pin),
    )
    .await
    .unwrap();
    assert_eq!(alias.canonicalize().unwrap(), canonical);
    let identity = std::fs::read(canonical.join("identity.json")).unwrap();

    // Both spellings must contend for one inode, even after failed local opens
    // that used to release a live owner's POSIX lock in an earlier implementation.
    for (owner, contender) in [(&alias, &canonical), (&canonical, &alias)] {
        let client = EmbeddedClient::start(owner).await.unwrap();
        assert!(client.wait_connected(Duration::from_secs(5)).await);
        assert_external_ownership(contender, false).await;
        assert!(EmbeddedClient::start(contender).await.is_err());
        assert_external_ownership(owner, false).await;
        assert!(EmbeddedClient::start(owner).await.is_err());
        assert_external_ownership(contender, false).await;
        assert!(embedded::join(
            contender,
            &relay.invite(None),
            &relay.url(),
            None,
            Some(relay.pin),
        )
        .await
        .is_err());
        assert_external_ownership(contender, false).await;
        assert_eq!(
            std::fs::read(alias.join("identity.json")).unwrap(),
            identity
        );
        client.shutdown().await;
        assert_external_ownership(contender, true).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn failed_local_contenders_preserve_live_owners_cross_process_lock() {
    let relay = start_relay().await;
    let phone = enroll(&relay, "phone").await;
    let client = EmbeddedClient::start(&phone.paths.home).await.unwrap();
    assert_external_ownership(&phone.paths.home, false).await;
    assert!(EmbeddedClient::start(&phone.paths.home).await.is_err());
    assert_external_ownership(&phone.paths.home, false).await;
    assert!(daemon::start(DaemonConfig::new(phone.paths.clone()))
        .await
        .is_err());
    assert_external_ownership(&phone.paths.home, false).await;
    assert!(embedded::join(
        &phone.paths.home,
        &relay.invite(None),
        &relay.url(),
        None,
        Some(relay.pin)
    )
    .await
    .is_err());
    assert_external_ownership(&phone.paths.home, false).await;
    client.shutdown().await;
    assert_external_ownership(&phone.paths.home, true).await;
}

#[cfg(unix)]
#[tokio::test]
async fn ownership_file_rejects_insecure_mode_symlink_and_hardlink() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let relay = start_relay().await;
    let phone = enroll(&relay, "phone").await;
    let alias_dir = tempfile::tempdir().unwrap();
    let alias = alias_dir.path().join("home-alias");
    symlink(&phone.paths.home, &alias).unwrap();
    let lock = phone.paths.home.join(".warren-owner.sqlite3");
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(EmbeddedClient::start(&phone.paths.home).await.is_err());
    assert!(EmbeddedClient::start(&alias).await.is_err());
    assert_eq!(
        std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let lock_alias = phone.paths.home.join("lock-alias");
    std::fs::hard_link(&lock, &lock_alias).unwrap();
    assert!(EmbeddedClient::start(&phone.paths.home).await.is_err());
    assert!(EmbeddedClient::start(&alias).await.is_err());
    std::fs::remove_file(&lock).unwrap();
    symlink(&lock_alias, &lock).unwrap();
    assert!(EmbeddedClient::start(&phone.paths.home).await.is_err());
    assert!(EmbeddedClient::start(&alias).await.is_err());
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    assert!(EmbeddedClient::start(&phone.paths.home).await.is_err());
    assert!(EmbeddedClient::start(&alias).await.is_err());
    std::fs::remove_dir(&lock).unwrap();
    std::fs::rename(&lock_alias, &lock).unwrap();
    EmbeddedClient::start(&alias)
        .await
        .unwrap()
        .shutdown()
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn process_ownership_survives_contention_and_releases_after_abrupt_exit() {
    let relay = start_relay().await;
    let phone = enroll(&relay, "phone").await;
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lease_holder_child", "--ignored", "--nocapture"])
        .env("WARREN_EMBEDDED_TEST_ROOT", &phone.paths.home)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait_for("child ownership acquired", Duration::from_secs(5), || {
        phone.paths.home.join("lease-ready").exists()
    })
    .await;
    assert!(EmbeddedClient::start(&phone.paths.home).await.is_err());
    assert!(daemon::start(DaemonConfig::new(phone.paths.clone()))
        .await
        .is_err());
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    let client = EmbeddedClient::start(&phone.paths.home).await.unwrap();
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn concurrent_enrollment_has_one_owner_and_does_not_consume_losing_invite() {
    let relay = start_relay().await;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("phone");
    let first = relay.invite(None);
    let second = relay.invite(None);
    let url = relay.url();
    let (a, b) = tokio::join!(
        embedded::join(&root, &first, &url, Some("first"), Some(relay.pin)),
        embedded::join(&root, &second, &url, Some("second"), Some(relay.pin)),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let losing_invite = if a.is_ok() { &second } else { &first };
    embedded::join(
        &dir.path().join("other"),
        losing_invite,
        &url,
        Some("other"),
        Some(relay.pin),
    )
    .await
    .unwrap();
}
