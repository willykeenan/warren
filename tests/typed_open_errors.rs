//! Real relay controls for stable, data-free strict client error categories.
mod common;
use common::*;
use std::time::Duration;
use warren::mux::TapDir;
use warren::node::{daemon::OpenError, KnownPeers};
use warren::proto::{ErrorCode, Frame, FrameType};

fn assert_typed(error: OpenError, expected: &str) {
    assert!(
        matches!(
            (&error, expected),
            (OpenError::InvalidArgument, "invalid_argument")
                | (OpenError::PinRejected, "pin_rejected")
                | (OpenError::StorageUnavailable, "storage_unavailable")
        ),
        "wrong category: {error:?}"
    );
    assert_eq!(error.code(), expected);
    assert!(error.to_string().len() < 64);
}
fn opens(relay: &TestRelay) -> usize {
    relay
        .captures
        .lock()
        .unwrap()
        .iter()
        .filter(|(dir, bytes)| {
            matches!(dir, TapDir::In)
                && Frame::decode(bytes.clone().into()).unwrap().ty == FrameType::Open
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn strict_argument_pin_and_storage_categories_fail_before_open() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let key = b.identity().static_pub;
    for name in ["", "bad/name", "UPPER"] {
        assert_typed(
            a.d().inner.approve_peer_key(name, &key).await.unwrap_err(),
            "invalid_argument",
        );
        assert_typed(
            a.d().inner.forget_peer_key(name, &key).await.unwrap_err(),
            "invalid_argument",
        );
        assert_typed(
            a.d()
                .inner
                .open_private_pinned(name, 1234, &key)
                .await
                .err()
                .unwrap(),
            "invalid_argument",
        );
    }
    assert_typed(
        a.d()
            .inner
            .open_private_pinned("b", 0, &key)
            .await
            .err()
            .unwrap(),
        "invalid_argument",
    );
    assert_typed(
        a.d()
            .inner
            .open_gateway_pinned("b", "bad/share", &key)
            .await
            .err()
            .unwrap(),
        "invalid_argument",
    );
    for case in [
        "absent",
        "tofu",
        "wrong_key",
        "wrong_relay",
        "corrupt",
        "invalid_key",
    ] {
        let mut pins = KnownPeers {
            relay: a.ident().relay,
            ..KnownPeers::default()
        };
        match case {
            "absent" => {}
            "tofu" => pins.pin("b", &key, false),
            "wrong_key" => pins.pin("b", &warren::crypto::Identity::generate().static_pub, true),
            _ => pins.pin("b", &key, true),
        }
        if case == "wrong_relay" {
            pins.relay = "https://elsewhere.invalid".into();
        }
        if case == "invalid_key" {
            pins.peers.get_mut("b").unwrap().static_pub = "bad".into();
        }
        pins.save(&a.paths).unwrap();
        if case == "corrupt" {
            std::fs::write(a.paths.known_peers(), b"{").unwrap();
        }
        let before = std::fs::read(a.paths.known_peers()).unwrap();
        let category = if matches!(case, "corrupt" | "invalid_key") {
            "storage_unavailable"
        } else {
            "pin_rejected"
        };
        assert_typed(
            a.d()
                .inner
                .open_private_pinned("b", 1234, &key)
                .await
                .err()
                .unwrap(),
            category,
        );
        assert_typed(
            a.d()
                .inner
                .open_gateway_pinned("b", "camera", &key)
                .await
                .err()
                .unwrap(),
            category,
        );
        assert_eq!(std::fs::read(a.paths.known_peers()).unwrap(), before);
        if matches!(
            case,
            "corrupt" | "invalid_key" | "wrong_relay" | "wrong_key"
        ) {
            assert_typed(
                a.d().inner.approve_peer_key("b", &key).await.unwrap_err(),
                category,
            );
            assert_typed(
                a.d().inner.forget_peer_key("b", &key).await.unwrap_err(),
                category,
            );
            assert_eq!(std::fs::read(a.paths.known_peers()).unwrap(), before);
        }
        if case == "absent" {
            assert_typed(
                a.d().inner.forget_peer_key("b", &key).await.unwrap_err(),
                "pin_rejected",
            );
        }
    }
    assert_eq!(opens(&relay), 0);
    // A path that exists but cannot be read as a file is storage failure too.
    std::fs::remove_file(a.paths.known_peers()).unwrap();
    std::fs::create_dir(a.paths.known_peers()).unwrap();
    assert_typed(
        a.d().inner.approve_peer_key("b", &key).await.unwrap_err(),
        "storage_unavailable",
    );
    assert_typed(
        a.d().inner.forget_peer_key("b", &key).await.unwrap_err(),
        "storage_unavailable",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn successful_approval_and_actual_peer_forbidden_remain_distinct() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let key = b.identity().static_pub;
    a.d().inner.approve_peer_key("b", &key).await.unwrap();
    let approved = std::fs::read(a.paths.known_peers()).unwrap();
    a.d().inner.approve_peer_key("b", &key).await.unwrap();
    assert_eq!(std::fs::read(a.paths.known_peers()).unwrap(), approved);
    let (port, _) = echo_server().await;
    b.share(port, Some(vec!["someone-else".into()]));
    let error = a
        .d()
        .inner
        .open_private_pinned("b", port, &key)
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        OpenError::Refused {
            code: ErrorCode::Forbidden,
            ..
        }
    ));
    assert_eq!(error.code(), "forbidden");
    b.share(port, None);
    let mut channel = a
        .d()
        .inner
        .open_private_pinned("b", port, &key)
        .await
        .unwrap();
    channel.tx.send(b"typed error control").await.unwrap();
    assert_eq!(
        channel.rx.recv().await.unwrap().unwrap(),
        b"typed error control"
    );
    channel.tx.reset(ErrorCode::Aborted);
    a.d().inner.forget_peer_key("b", &key).await.unwrap();
    assert_typed(
        a.d()
            .inner
            .open_private_pinned("b", port, &key)
            .await
            .err()
            .unwrap(),
        "pin_rejected",
    );
}

// macOS immutable directory flag gives a real save failure after a successful
// read, independent of chmod repair in NodePaths::ensure. Restore it on unwind.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn failed_approval_and_forget_writes_are_storage_unavailable_and_atomic() {
    struct Frozen(std::path::PathBuf);
    impl Drop for Frozen {
        fn drop(&mut self) {
            assert!(std::process::Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status()
                .unwrap()
                .success());
        }
    }
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll(&relay, "b").await;
    let key = b.identity().static_pub;
    a.d().inner.approve_peer_key("b", &key).await.unwrap();
    let before = std::fs::read(a.paths.known_peers()).unwrap();
    let _frozen = Frozen(a.paths.home.clone());
    assert!(std::process::Command::new("/usr/bin/chflags")
        .arg("uchg")
        .arg(&_frozen.0)
        .status()
        .unwrap()
        .success());
    assert!(
        KnownPeers::load(&a.paths).is_ok(),
        "fixture must allow loading pins"
    );
    assert_typed(
        a.d()
            .inner
            .approve_peer_key("new-peer", &key)
            .await
            .unwrap_err(),
        "storage_unavailable",
    );
    assert_typed(
        a.d().inner.forget_peer_key("b", &key).await.unwrap_err(),
        "storage_unavailable",
    );
    assert_eq!(std::fs::read(a.paths.known_peers()).unwrap(), before);
    assert_eq!(opens(&relay), 0);
    drop(_frozen);
    // Removing the fault restores normal mutation through the exact same API.
    a.d().inner.forget_peer_key("b", &key).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn typed_pin_and_storage_failures_survive_final_noise_guard() {
    use std::sync::{Arc, Mutex};
    use warren::node::NodePaths;
    use warren::proto::OpenPayload;
    #[derive(Default)]
    struct Gate {
        paths: Option<NodePaths>,
        stream: Option<u32>,
        changed: bool,
        reset: bool,
    }
    for corrupt in [false, true] {
        let gate = Arc::new(Mutex::new(Gate::default()));
        let tap_gate = gate.clone();
        let relay = start_relay_with(move |cfg| {
            let previous = cfg.tap.clone().unwrap();
            cfg.tap = Some(Arc::new(move |dir, bytes| {
                previous(dir, bytes);
                let frame = Frame::decode(bytes.to_vec().into()).unwrap();
                let mut state = tap_gate.lock().unwrap();
                if state.paths.is_none() {
                    return;
                }
                if matches!(dir, TapDir::In)
                    && frame.ty == FrameType::Open
                    && OpenPayload::decode(&frame.payload).unwrap().dest == "b"
                {
                    state.stream = Some(frame.stream);
                }
                if Some(frame.stream) != state.stream {
                    return;
                }
                // Actual relay writer checkpoint, before delivering Noise 2.
                if matches!(dir, TapDir::Out) && frame.ty == FrameType::Data && !state.changed {
                    let paths = state.paths.as_ref().unwrap();
                    if corrupt {
                        std::fs::write(paths.known_peers(), b"{").unwrap();
                    } else {
                        let mut pins = KnownPeers::load(paths).unwrap();
                        pins.peers.remove("b");
                        pins.save(paths).unwrap();
                    }
                    state.changed = true;
                }
                if matches!(dir, TapDir::In)
                    && frame.ty == FrameType::Close
                    && frame.close_kind() == Some(ErrorCode::Forbidden)
                    && state.changed
                {
                    state.reset = true;
                }
            }));
        })
        .await;
        let a = enroll_started(&relay, "a").await;
        let b = enroll_started(&relay, "b").await;
        let (port, _) = echo_server().await;
        b.share(port, None);
        let key = b.identity().static_pub;
        a.d().inner.approve_peer_key("b", &key).await.unwrap();
        gate.lock().unwrap().paths = Some(a.paths.clone());
        let error = a
            .d()
            .inner
            .open_private_pinned("b", port, &key)
            .await
            .err()
            .unwrap();
        assert_typed(
            error,
            if corrupt {
                "storage_unavailable"
            } else {
                "pin_rejected"
            },
        );
        assert!(gate.lock().unwrap().changed);
        wait_for("typed final guard reset", Duration::from_secs(3), || {
            gate.lock().unwrap().reset
        })
        .await;
        assert_eq!(opens(&relay), 1);
    }
}
