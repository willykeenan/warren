//! Real local-relay coverage for the explicit owner-approved client path.
mod common;

use common::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use warren::crypto;
use warren::mux::TapDir;
use warren::node::control::ControlRequest;
use warren::node::{KnownPeers, NodePaths};
use warren::proto::{CtrlOp, CtrlRequest, ErrorCode, Frame, FrameType, OpenPayload};

async fn trust(a: &TestNode, b: &TestNode) {
    a.ctl_ok(ControlRequest::Trust {
        name: b.name.clone(),
        expect: Some(crypto::fingerprint(&b.identity().static_pub)),
    })
    .await;
}

fn traffic(relay: &TestRelay) -> (usize, usize) {
    let mut opens = 0;
    let mut lookups = 0;
    for (dir, bytes) in relay.captures.lock().unwrap().iter() {
        if !matches!(dir, TapDir::In) {
            continue;
        }
        let f = Frame::decode(bytes.clone().into()).unwrap();
        opens += usize::from(f.ty == FrameType::Open);
        if f.ty == FrameType::Ctrl {
            if let Ok(req) = serde_json::from_slice::<CtrlRequest>(&f.payload) {
                lookups += usize::from(matches!(req.op, CtrlOp::Lookup { .. }));
            }
        }
    }
    (opens, lookups)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn explicitly_trusted_key_opens_and_ordinary_tofu_still_works() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (port, _) = echo_server().await;
    b.share(port, None);
    let key = b.identity().static_pub;

    // The legacy API still learns a TOFU pin; the new API must reject it.
    let ordinary = a.d().inner.open_private("b", port).await.unwrap();
    ordinary.tx.reset(ErrorCode::Aborted);
    assert!(KnownPeers::load(&a.paths).unwrap().peers["b"]
        .trusted_at
        .is_none());
    relay.captures.lock().unwrap().clear();
    assert!(a
        .d()
        .inner
        .open_private_pinned("b", port, &key)
        .await
        .is_err());
    assert_eq!(traffic(&relay), (0, 0));

    trust(&a, &b).await;
    relay.captures.lock().unwrap().clear();
    let mut channel = a
        .d()
        .inner
        .open_private_pinned("b", port, &key)
        .await
        .unwrap();
    channel.tx.send(b"explicit expected key").await.unwrap();
    assert_eq!(
        channel.rx.recv().await.unwrap().unwrap(),
        b"explicit expected key"
    );
    assert_eq!(traffic(&relay), (1, 0));
    channel.tx.reset(ErrorCode::Aborted);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn invalid_approval_and_selectors_fail_before_open_without_writing_pins() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (port, _) = echo_server().await;
    b.share(port, None);
    let key = b.identity().static_pub;
    let mut pins = KnownPeers {
        relay: a.ident().relay,
        ..KnownPeers::default()
    };
    for case in [
        "absent",
        "tofu",
        "changed",
        "other_relay",
        "corrupt",
        "malformed_key",
    ] {
        pins.peers.clear();
        pins.relay = a.ident().relay;
        match case {
            "absent" => {}
            "tofu" => pins.pin("b", &key, false),
            "changed" => pins.pin("b", &crypto::Identity::generate().static_pub, true),
            _ => pins.pin("b", &key, true),
        }
        if case == "other_relay" {
            pins.relay = "https://other.invalid".into();
        }
        pins.save(&a.paths).unwrap();
        if case == "corrupt" {
            std::fs::write(a.paths.known_peers(), b"{").unwrap();
        }
        if case == "malformed_key" {
            pins.peers.get_mut("b").unwrap().static_pub = "bad".into();
            pins.save(&a.paths).unwrap();
        }
        let before = std::fs::read(a.paths.known_peers()).unwrap();
        relay.captures.lock().unwrap().clear();
        assert!(
            a.d()
                .inner
                .open_private_pinned("b", port, &key)
                .await
                .is_err(),
            "{case}"
        );
        assert!(
            a.d()
                .inner
                .open_gateway_pinned("b", "camera", &key)
                .await
                .is_err(),
            "gateway {case}"
        );
        assert_eq!(traffic(&relay), (0, 0), "{case}");
        assert_eq!(
            std::fs::read(a.paths.known_peers()).unwrap(),
            before,
            "{case}"
        );
    }
    pins.peers.clear();
    pins.save(&a.paths).unwrap();
    trust(&a, &b).await;
    for (dest, selector) in [("b", 0), ("bad/name", port)] {
        relay.captures.lock().unwrap().clear();
        assert!(a
            .d()
            .inner
            .open_private_pinned(dest, selector, &key)
            .await
            .is_err());
        assert_eq!(traffic(&relay), (0, 0));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn handshake_failure_does_not_fall_back_to_relay_key() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (port, _) = echo_server().await;
    b.share(port, None);
    let wrong = crypto::Identity::generate().static_pub;
    let mut pins = KnownPeers {
        relay: a.ident().relay,
        ..KnownPeers::default()
    };
    pins.pin("b", &wrong, true);
    pins.save(&a.paths).unwrap();
    relay.captures.lock().unwrap().clear();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        a.d().inner.open_private_pinned("b", port, &wrong),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(traffic(&relay), (1, 0));
    assert_eq!(KnownPeers::load(&a.paths).unwrap().pinned("b"), Some(wrong));
}

#[derive(Default)]
struct Drift {
    paths: Option<NodePaths>,
    stream: Option<u32>,
    changed: bool,
    reset: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn approval_removed_during_handshake_resets_instead_of_returning_channel() {
    let drift = Arc::new(Mutex::new(Drift::default()));
    let d = drift.clone();
    let relay = start_relay_with(move |cfg| {
        let previous = cfg.tap.clone().unwrap();
        cfg.tap = Some(Arc::new(move |dir, bytes| {
            previous(dir, bytes);
            let frame = Frame::decode(bytes.to_vec().into()).unwrap();
            let mut state = d.lock().unwrap();
            if state.paths.is_none() {
                return;
            }
            if matches!(dir, TapDir::In) && frame.ty == FrameType::Open {
                let open = OpenPayload::decode(&frame.payload).unwrap();
                if open.dest == "b" {
                    state.stream = Some(frame.stream);
                }
            }
            if Some(frame.stream) != state.stream {
                return;
            }
            // Relay writer calls the tap before sending Noise message 2 to a.
            if matches!(dir, TapDir::Out) && frame.ty == FrameType::Data && !state.changed {
                let paths = state.paths.as_ref().unwrap();
                let mut pins = KnownPeers::load(paths).unwrap();
                pins.peers.remove("b");
                pins.save(paths).unwrap();
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
    trust(&a, &b).await;
    drift.lock().unwrap().paths = Some(a.paths.clone());
    relay.captures.lock().unwrap().clear();
    let result = a
        .d()
        .inner
        .open_private_pinned("b", port, &b.identity().static_pub)
        .await;
    assert!(result.is_err());
    assert!(
        drift.lock().unwrap().changed,
        "mutation must actually happen during the handshake"
    );
    wait_for(
        "client reset after approval drift",
        Duration::from_secs(3),
        || drift.lock().unwrap().reset,
    )
    .await;
    assert_eq!(traffic(&relay), (1, 0));
    assert!(KnownPeers::load(&a.paths).unwrap().pinned("b").is_none());
}

// A peer-owned Noise responder over the actual relay: no LAN target, policy
// bypass or production test switch is needed to test the named client selector.
async fn named_responder(
    mut raw: RawNode,
    identity: crypto::Identity,
    expected_share: &'static str,
) {
    let open = raw.next(Duration::from_secs(3)).await.unwrap();
    assert_eq!(open.ty, FrameType::Open);
    let selector = OpenPayload::decode(&open.payload).unwrap();
    assert_eq!(selector.flags, warren::proto::FLAG_GATEWAY);
    assert_eq!(selector.port, 0);
    assert_eq!(selector.dest, "b");
    raw.send(Frame::open_ok(open.stream)).await;
    let message = raw.next(Duration::from_secs(3)).await.unwrap();
    assert_eq!(message.ty, FrameType::Data);
    let mut noise = snow::Builder::new(crypto::NOISE_PARAMS.parse().unwrap())
        .local_private_key(&identity.static_secret)
        .unwrap()
        .prologue(crypto::NOISE_PROLOGUE)
        .unwrap()
        .build_responder()
        .unwrap();
    let mut plaintext = vec![0; warren::proto::MAX_PAYLOAD];
    let n = noise
        .read_message(&message.payload, &mut plaintext)
        .unwrap();
    let hello: warren::noise::Hello = serde_json::from_slice(&plaintext[..n]).unwrap();
    assert_eq!(hello.src, "a");
    assert_eq!(hello.dest, "b");
    assert_eq!(hello.port, 0);
    assert_eq!(
        noise.get_remote_static(),
        selector.src_static.as_ref().map(|k| k.as_slice())
    );
    let mut wire = vec![0; warren::proto::MAX_PAYLOAD];
    let n = noise.write_message(&[], &mut wire).unwrap();
    raw.send(Frame::new(FrameType::Data, open.stream, wire[..n].to_vec()))
        .await;
    let transport = noise.into_stateless_transport_mode().unwrap();
    let confirmation = raw.next(Duration::from_secs(3)).await.unwrap();
    let n = transport
        .read_message(0, &confirmation.payload, &mut plaintext)
        .unwrap();
    assert_eq!(&plaintext[..n], warren::noise::CONFIRM);
    let accepted = hello.share.as_deref() == Some(expected_share);
    let status = serde_json::to_vec(&warren::noise::Status {
        ok: accepted,
        code: if accepted {
            None
        } else {
            Some(ErrorCode::Forbidden)
        },
    })
    .unwrap();
    let n = transport.write_message(0, &status, &mut wire).unwrap();
    raw.send(Frame::new(FrameType::Data, open.stream, wire[..n].to_vec()))
        .await;
    if accepted {
        let message = raw.next(Duration::from_secs(3)).await.unwrap();
        let n = transport
            .read_message(1, &message.payload, &mut plaintext)
            .unwrap();
        assert_eq!(&plaintext[..n], b"named pinned bytes");
        let n = transport
            .write_message(1, &plaintext[..n], &mut wire)
            .unwrap();
        raw.send(Frame::new(FrameType::Data, open.stream, wire[..n].to_vec()))
            .await;
        // Keep the authenticated link alive until the client closes it.
        let _ = raw.next(Duration::from_secs(3)).await;
    } else {
        let _ = raw.next(Duration::from_secs(3)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn pinned_gateway_uses_encrypted_exact_selector_without_legacy_fallback() {
    for share in ["camera-secret", "unlisted"] {
        let relay = start_relay().await;
        let mut a = enroll_started(&relay, "a").await;
        let b = enroll(&relay, "b").await;
        let key = b.identity().static_pub;
        let raw = RawNode::connect(&relay, &b).await;
        trust(&a, &b).await;
        for invalid in ["", "bad/name"] {
            relay.captures.lock().unwrap().clear();
            assert!(a
                .d()
                .inner
                .open_gateway_pinned("b", invalid, &key)
                .await
                .is_err());
            assert_eq!(traffic(&relay), (0, 0));
        }
        relay.captures.lock().unwrap().clear();
        let responder = tokio::spawn(named_responder(raw, b.identity(), "camera-secret"));
        let result = a.d().inner.open_gateway_pinned("b", share, &key).await;
        if share == "camera-secret" {
            let mut channel = result.unwrap();
            channel.tx.send(b"named pinned bytes").await.unwrap();
            assert_eq!(
                channel.rx.recv().await.unwrap().unwrap(),
                b"named pinned bytes"
            );
            channel.tx.reset(ErrorCode::Aborted);
        } else {
            assert!(result.is_err());
        }
        responder.await.unwrap();
        assert_eq!(
            traffic(&relay),
            (1, 0),
            "named refusal never retries an ordinary port or looks up a key"
        );
        let wire = relay.captured_bytes().concat();
        for secret in ["camera-secret", "unlisted", "named pinned bytes"] {
            assert!(!wire.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
        a.stop().await;
    }
}
