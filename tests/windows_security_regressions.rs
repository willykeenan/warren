//! Windows runtime security regressions; portable builds do not execute these.
#![cfg(windows)]
use warren::{
    fsutil,
    node::{KnownPeers, NodePaths, SharesFile},
    sys::{sddl, windows as win},
};

fn loose_protected(path: &std::path::Path) {
    let me = win::current_user_sid().unwrap();
    fsutil::set_security_for_test(
        path,
        &format!("O:{me}D:P(A;;FA;;;{me})(A;;FA;;;SY)(A;;FRFW;;;BU)"),
    )
    .unwrap();
}
fn protected_private(path: &std::path::Path) -> bool {
    let me = win::current_user_sid().unwrap();
    let a = sddl::assess(
        &fsutil::security_of(path).unwrap(),
        &me,
        &win::default_owner_sid().unwrap(),
    )
    .unwrap();
    a.is_private() && a.protected
}
#[test]
fn policy_load_must_not_accept_an_other_account_writable_file() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(tmp.path().join("home"));
    paths.ensure().unwrap();
    fsutil::write_json(
        &paths.shares(),
        &serde_json::json!({"shares":[{"port":54321,"to":null}]}),
    )
    .unwrap();
    loose_protected(&paths.shares());
    paths.ensure().unwrap(); // Protected explicit child ACL must not be assumed repaired.
    let loaded = SharesFile::load(&paths);
    assert!(
        loaded.is_err(),
        "policy accepted while another account retains explicit write access"
    );
}
#[test]
fn pin_load_must_not_accept_an_other_account_writable_file() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(tmp.path().join("home"));
    paths.ensure().unwrap();
    fsutil::write_json(
        &paths.known_peers(),
        &serde_json::json!({"relay":"https://example.invalid","peers":{}}),
    )
    .unwrap();
    loose_protected(&paths.known_peers());
    paths.ensure().unwrap();
    let loaded = KnownPeers::load(&paths);
    assert!(
        loaded.is_err(),
        "pin file accepted while another account retains explicit write access"
    );
}
#[test]
fn existing_key_must_be_protected_from_future_inheritance() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(tmp.path().join("home"));
    paths.ensure().unwrap();
    let key = paths.home.join("synthetic.key");
    fsutil::write_private(&key, b"synthetic").unwrap();
    let me = win::current_user_sid().unwrap();
    fsutil::set_security_for_test(&key, &format!("O:{me}D:AI(A;;FA;;;{me})(A;;FA;;;SY)")).unwrap();
    fsutil::ensure_private_file(&key).unwrap();
    assert!(protected_private(&key), "existing key remains unprotected");
}
#[test]
fn existing_temporary_hardlink_must_not_be_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(tmp.path().join("home"));
    paths.ensure().unwrap();
    let canary = tmp.path().join("synthetic-canary");
    std::fs::write(&canary, b"untouched").unwrap();
    let target = paths.home.join("synthetic.key");
    let pending = paths
        .home
        .join(format!(".synthetic.key.tmp{}", std::process::id()));
    std::fs::hard_link(&canary, &pending).unwrap();
    let _ = fsutil::write_private(&target, b"new-synthetic-value");
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"untouched",
        "private write followed preexisting alias"
    );
}

#[test]
fn junction_ancestor_is_rejected() {
    let t = tempfile::tempdir().unwrap();
    let target = t.path().join("real");
    fsutil::ensure_private_dir(&target).unwrap();
    fsutil::write_private(&target.join("state.json"), b"1").unwrap();
    let alias = t.path().join("alias");
    let status = std::process::Command::new("cmd.exe")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&alias)
        .arg(&target)
        .output()
        .unwrap();
    assert!(status.status.success(), "junction fixture failed");
    assert!(fsutil::read_private(&alias.join("state.json")).is_err());
    std::fs::remove_dir(alias).unwrap();
}
