//! Local-owner pin decisions never consult or trust a relay-provided key.
mod common;
use common::*;
use warren::mux::TapDir;
use warren::node::KnownPeers;
use warren::proto::{CtrlOp, CtrlRequest, ErrorCode, Frame, FrameType};

fn lookups_and_opens(relay: &TestRelay) -> usize {
    relay
        .captures
        .lock()
        .unwrap()
        .iter()
        .filter(|(dir, bytes)| {
            if !matches!(dir, TapDir::In) {
                return false;
            }
            let frame = Frame::decode(bytes.clone().into()).unwrap();
            frame.ty == FrameType::Open
                || (frame.ty == FrameType::Ctrl
                    && serde_json::from_slice::<CtrlRequest>(&frame.payload)
                        .is_ok_and(|r| matches!(r.op, CtrlOp::Lookup { .. })))
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn explicit_decisions_preserve_other_pins_and_require_exact_key_for_changes() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let key = b.identity().static_pub;
    let d = &a.d().inner;
    let mut pins = KnownPeers {
        relay: a.ident().relay,
        ..KnownPeers::default()
    };
    pins.pin("unrelated", &[9; 32], true);
    pins.pin("b", &key, false);
    pins.peers.get_mut("b").unwrap().first_seen = 123;
    pins.save(&a.paths).unwrap();
    let other = pins.peers["unrelated"].clone();
    relay.captures.lock().unwrap().clear();
    d.approve_peer_key("b", &key).await.unwrap();
    let approved = KnownPeers::load(&a.paths).unwrap();
    assert_eq!(approved.peers["b"].first_seen, 123);
    assert!(approved.peers["b"].trusted_at.is_some());
    assert_eq!(approved.peers["unrelated"], other);
    let unchanged = std::fs::read(a.paths.known_peers()).unwrap();
    d.approve_peer_key("b", &key).await.unwrap();
    assert!(d.approve_peer_key("b", &[7; 32]).await.is_err());
    assert!(d.forget_peer_key("b", &[7; 32]).await.is_err());
    assert!(d.approve_peer_key("../b", &key).await.is_err());
    assert_eq!(std::fs::read(a.paths.known_peers()).unwrap(), unchanged);
    assert_eq!(lookups_and_opens(&relay), 0);

    let (port, _) = echo_server().await;
    b.share(port, None);
    let mut channel = d.open_private_pinned("b", port, &key).await.unwrap();
    channel.tx.send(b"approved").await.unwrap();
    assert_eq!(channel.rx.recv().await.unwrap().unwrap(), b"approved");
    channel.tx.reset(ErrorCode::Aborted);
    d.forget_peer_key("b", &key).await.unwrap();
    relay.captures.lock().unwrap().clear();
    assert!(d.open_private_pinned("b", port, &key).await.is_err());
    assert_eq!(lookups_and_opens(&relay), 0);
    assert_eq!(
        KnownPeers::load(&a.paths).unwrap().peers["unrelated"],
        other
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn approval_fails_closed_on_storage_drift_and_serializes_competing_keys() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let d = &a.d().inner;
    let path = a.paths.known_peers();
    KnownPeers::default().save(&a.paths).unwrap();
    for bytes in [
        b"broken".to_vec(),
        br#"{"relay":"https://elsewhere.invalid","peers":{}}"#.to_vec(),
        br#"{"relay":"","peers":{"b":{"static_pub":"bad","first_seen":1,"trusted_at":1}}}"#
            .to_vec(),
    ] {
        std::fs::write(&path, &bytes).unwrap();
        assert!(d.approve_peer_key("b", &[1; 32]).await.is_err());
        assert!(d.forget_peer_key("b", &[1; 32]).await.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    KnownPeers::default().save(&a.paths).unwrap();
    relay.captures.lock().unwrap().clear();
    let (first, second) = tokio::join!(
        d.approve_peer_key("b", &[1; 32]),
        d.approve_peer_key("b", &[2; 32])
    );
    assert_ne!(first.is_ok(), second.is_ok());
    let pins = KnownPeers::load(&a.paths).unwrap();
    assert_eq!(pins.relay, a.ident().relay);
    assert_eq!(
        pins.pinned("b"),
        Some(if first.is_ok() { [1; 32] } else { [2; 32] })
    );
    assert_eq!(lookups_and_opens(&relay), 0);
}
