mod common;
use common::*;
use std::time::Duration;
use warren::crypto;
use warren::mux::TapDir;
use warren::node::{
    embedded::{self, EmbeddedClient, PublicIdentity},
    IdentityFile,
};
use warren::proto::{ErrorCode, Frame, FrameType, OpenPayload};
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
async fn public_wrappers_require_approval_and_forget_blocks_future_encrypted_opens() {
    let relay = start_relay().await;
    let a = enroll(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let client = EmbeddedClient::start(&a.paths.home).await.unwrap();
    assert!(client.wait_connected(Duration::from_secs(5)).await);
    let info = client.public_identity();
    assert_eq!(info.name, "a");
    assert_eq!(info.relay_https, relay.url());
    assert_eq!(info.noise_static_public_key, a.identity().static_pub);
    assert_eq!(info.signing_public_key, a.identity().sign_pub());
    let (port, _) = echo_server().await;
    b.share(port, None);
    let key = b.identity().static_pub;
    relay.captures.lock().unwrap().clear();
    assert!(client.open_private_pinned("b", port, &key).await.is_err());
    assert!(client
        .open_gateway_pinned("b", "camera", &key)
        .await
        .is_err());
    assert_eq!(opens(&relay), 0);
    client.approve_verified_peer("b", &key).await.unwrap();
    let mut channel = client.open_private_pinned("b", port, &key).await.unwrap();
    channel.tx.send(b"embedded exact approval").await.unwrap();
    assert_eq!(
        channel.rx.recv().await.unwrap().unwrap(),
        b"embedded exact approval"
    );
    channel.tx.reset(ErrorCode::Aborted);
    client.forget_verified_peer("b", &key).await.unwrap();
    relay.captures.lock().unwrap().clear();
    assert!(client.open_private_pinned("b", port, &key).await.is_err());
    assert_eq!(opens(&relay), 0);
    client.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn gateway_wrapper_preserves_exact_encrypted_selector_and_refusal() {
    for share in ["camera-secret", "unlisted"] {
        let relay = start_relay().await;
        let a = enroll(&relay, "a").await;
        let b = enroll(&relay, "b").await;
        let client = EmbeddedClient::start(&a.paths.home).await.unwrap();
        assert!(client.wait_connected(Duration::from_secs(5)).await);
        let raw = RawNode::connect(&relay, &b).await;
        let key = b.identity().static_pub;
        client.approve_verified_peer("b", &key).await.unwrap();
        relay.captures.lock().unwrap().clear();
        let responder = tokio::spawn(named_responder(raw, b.identity(), "camera-secret"));
        let result = client.open_gateway_pinned("b", share, &key).await;
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
        assert_eq!(opens(&relay), 1);
        let wire = relay.captured_bytes().concat();
        for secret in ["camera-secret", "unlisted", "named pinned bytes"] {
            assert!(!wire.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
        client.shutdown().await;
    }
}

#[tokio::test]
async fn strict_public_metadata_and_persisted_rejection_precede_connection() {
    let relay = start_relay().await;
    let a = enroll(&relay, "a").await;
    let original = a.ident();
    assert!(PublicIdentity::from_identity(&original).is_ok());
    for relay in [
        "https://localhost",
        "https://[::1]:444",
        "https://127.0.0.1:444",
    ] {
        let mut ident = original.clone();
        ident.relay = relay.into();
        assert_eq!(
            PublicIdentity::from_identity(&ident).unwrap().relay_https,
            relay
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trap = format!("https://{}", listener.local_addr().unwrap());
    for bad in [
        "",
        "wss://example.com",
        "https://a/b",
        "https://u@a",
        "https://a?",
        "https://a#",
        "https://é.test",
        "https://a\n",
        "https://a\0",
        "https://[no]:443",
        "https://::1",
        "https://256.0.0.1",
        "https://-a.test",
        "https://a..b",
        "https://a:0",
        "https://a:65536",
        "https://a:",
        "https://a:abc",
        "https://a/%2f",
        "https://a\\b",
        "https://a/",
        "https://A",
        "https://a:443",
    ] {
        let mut ident = original.clone();
        ident.relay = bad.into();
        let error = PublicIdentity::from_identity(&ident)
            .unwrap_err()
            .to_string();
        assert_eq!(error, "invalid embedded identity metadata");
        warren::fsutil::write_json(&a.paths.identity(), &ident).unwrap();
        assert!(EmbeddedClient::start(&a.paths.home).await.is_err());
    }
    for field in [
        "name",
        "static",
        "sign",
        "mismatch_static",
        "mismatch_sign",
        "secret",
    ] {
        let mut ident = original.clone();
        ident.relay = trap.clone();
        match field {
            "name" => ident.name = "bad/name".into(),
            "static" => ident.static_pub = "00".into(),
            "sign" => ident.sign_pub = "zz".repeat(32),
            "mismatch_static" => ident.static_pub = "00".repeat(32),
            "mismatch_sign" => ident.sign_pub = "00".repeat(32),
            _ => {
                let mut value = serde_json::to_value(&ident).unwrap();
                value["static_secret"] = "bad".into();
                ident = serde_json::from_value(value).unwrap();
            }
        }
        assert!(PublicIdentity::from_identity(&ident).is_err());
        warren::fsutil::write_json(&a.paths.identity(), &ident).unwrap();
        assert!(EmbeddedClient::start(&a.paths.home).await.is_err());
    }
    for name in [
        "",
        "UPPER",
        "a b",
        "é",
        "bad\0",
        "abcdefghijklmnopqrstuvwxyz1234567",
    ] {
        let mut ident = original.clone();
        ident.name = name.into();
        assert!(PublicIdentity::from_identity(&ident).is_err());
    }
    let mut ident = original;
    ident.relay = format!("https://{}", "a".repeat(2049));
    assert!(PublicIdentity::from_identity(&ident).is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn join_rejects_bad_input_before_network_or_storage_and_normalizes_root_url() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("must-not-exist");
    for (relay, name) in [
        (format!("{url}/unsafe"), "valid"),
        (url, "bad/name"),
        ("https://secret@example.test".into(), "valid"),
    ] {
        let error = embedded::join(&home, "unused", &relay, Some(name), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error == "invalid embedded relay URL" || error == "invalid embedded node name");
        assert!(!home.exists());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err()
    );
    let relay = start_relay().await;
    let ident = embedded::join(
        &home,
        &relay.invite(Some("new")),
        &format!("{}/", relay.url()),
        Some("new"),
        Some(relay.pin),
    )
    .await
    .unwrap();
    assert_eq!(ident.relay, relay.url());
    assert!(PublicIdentity::from_identity(&ident).is_ok());
    assert!(IdentityFile::load(&warren::node::NodePaths::new(home)).is_ok());
}
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
