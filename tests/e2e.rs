//! End-to-end tests: a real relay (self-signed TLS on 127.0.0.1) and 2-3
//! nodes with their own temporary homes, driven in-process.
//!
//! Security requirements are referenced as SR1..SR9 (see docs/security.md).

mod common;

use common::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use warren::node::control::ControlRequest;
use warren::node::daemon::OpenError;
use warren::proto::*;

fn marker() -> Vec<u8> {
    b"WARREN-PLAINTEXT-MARKER-7f3a9c1e".to_vec()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_share_forward_and_nc() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);

    // forward: a:local -> b:echo
    let local = a.forward("b", echo).await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    assert_eq!(echo_roundtrip(local, &data).await, data);
    // Several concurrent connections over the same forward.
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        tasks.push(tokio::spawn(async move {
            let d = vec![i; 50_000];
            assert_eq!(echo_roundtrip(local, &d).await, d);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    // nc: the control socket becomes a pipe.
    let (mut r, mut w) = warren::node::control::open_with_framing(&a.paths, "b", echo, true)
        .await
        .unwrap()
        .unwrap();
    w.write_all(b"interactive").await.unwrap();
    w.flush().await.unwrap();
    let mut interactive = [0; 11];
    tokio::time::timeout(Duration::from_secs(10), r.read_exact(&mut interactive))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&interactive, b"interactive");
    // More than one frame, all byte values, before either side sends EOF.
    let binary: Vec<u8> = (0..131_329).map(|i| (i % 256) as u8).collect();
    let mut echoed = vec![0; binary.len()];
    let (sent, received) = tokio::join!(
        async {
            w.write_all(&binary).await?;
            w.flush().await
        },
        tokio::time::timeout(Duration::from_secs(10), r.read_exact(&mut echoed)),
    );
    sent.unwrap();
    received.unwrap().unwrap();
    assert_eq!(echoed, binary);
    w.write_all(b"hello over nc\n").await.unwrap();
    w.shutdown().await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"hello over nc\n");

    // status reflects the connection, forward and latency.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let st = a.ctl_ok(ControlRequest::Status).await;
    assert_eq!(st["connection"]["state"], "connected");
    assert!(st["connection"]["latency_ms"].as_f64().is_some(), "{st}");
    assert_eq!(st["forwards"][0]["node"], "b");
    assert_eq!(st["node"]["name"], "a");

    // devices lists both with fingerprints and online state.
    let dev = a.ctl_ok(ControlRequest::Devices).await;
    let list = dev.as_array().unwrap();
    assert_eq!(list.len(), 2);
    let bdev = list.iter().find(|d| d["name"] == "b").unwrap();
    assert_eq!(bdev["online"], true);
    assert_eq!(bdev["pin"], "pinned");
    assert_eq!(
        bdev["fingerprint"].as_str().unwrap(),
        b.ident().fingerprint()
    );
    let adev = list.iter().find(|d| d["name"] == "a").unwrap();
    assert_eq!(adev["pin"], "self");

    // Re-adding a forward on the same local port replaces it.
    a.ctl_ok(ControlRequest::ForwardAdd {
        local,
        node: "b".into(),
        port: echo,
    })
    .await;
    assert_eq!(echo_roundtrip(local, b"replaced").await, b"replaced");
    let st = a.ctl_ok(ControlRequest::Status).await;
    assert_eq!(st["forwards"].as_array().unwrap().len(), 1);

    // Removing the forward closes its listener.
    a.ctl_ok(ControlRequest::ForwardRemove { local }).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", local))
        .await
        .is_err());
}

/// SR1: the relay never sees plaintext of private streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_never_sees_private_plaintext() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    let local = a.forward("b", echo).await;

    let mut payload = Vec::new();
    for _ in 0..2000 {
        payload.extend_from_slice(&marker());
    }
    assert_eq!(echo_roundtrip(local, &payload).await, payload);
    // Also through nc, small messages.
    let (mut r, mut w) = warren::node::control::open(&a.paths, "b", echo)
        .await
        .unwrap()
        .unwrap();
    w.write_all(&marker()).await.unwrap();
    w.shutdown().await.unwrap();
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, marker());

    let caps = relay.captured_bytes();
    let data_frames = caps
        .iter()
        .filter(|m| m.first() == Some(&(FrameType::Data as u8)))
        .count();
    assert!(
        data_frames > 20,
        "capture saw only {data_frames} DATA frames"
    );
    let total: usize = caps.iter().map(|m| m.len()).sum();
    assert!(
        total > payload.len() * 2,
        "capture must include both directions"
    );
    let m = marker();
    for msg in &caps {
        assert!(!contains(msg, &m), "marker visible to the relay");
        assert!(
            !contains(msg, &m[..12]),
            "partial marker visible to the relay"
        );
    }
    let all: Vec<u8> = caps.concat();
    assert!(!contains(&all, &m[..12]));

    // Positive control: public (published) traffic is terminated at the relay,
    // so the same capture does see its plaintext.
    let web = http_backend().await;
    b.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "web".into(),
        replace: false,
        allow: vec![],
    })
    .await;
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (r, mut w) = tokio::io::split(tls);
    let mut body =
        b"POST /echo HTTP/1.1\r\nHost: web.warren.test\r\nContent-Length: 32\r\n\r\n".to_vec();
    body.extend_from_slice(&m);
    w.write_all(&body).await.unwrap();
    let mut rc = warren::http::BufConn::new(r, None);
    let (code, _, resp) = read_response(&mut rc).await;
    assert_eq!(code, 200);
    assert_eq!(resp, m);
    let all: Vec<u8> = relay.captured_bytes().concat();
    assert!(
        contains(&all, &m),
        "tap sees public plaintext (positive control)"
    );
}

/// SR2: unenrolled, forged, replayed, wrong-host and revoked credentials fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authentication_is_strict() {
    let relay = start_relay().await;
    let a = enroll(&relay, "a").await;
    let a_ident = a.ident();
    let a_id = a.identity();

    let refused = |v: &RelayVerdict, code: &str| match v {
        RelayVerdict::Error { code: c, .. } => assert_eq!(c, code, "{v:?}"),
        other => panic!("expected {code}, got {other:?}"),
    };

    // Unenrolled key.
    let stranger = warren::crypto::Identity::generate();
    let mut ws = raw_ws(&relay).await;
    let c = challenge(&mut ws).await;
    let v = send_hello(
        &mut ws,
        &auth_hello(&stranger, &stranger.node_id(), &c, "127.0.0.1"),
    )
    .await;
    refused(&v, "unknown_node");

    // Forged: a's node id, signed by another key (claimed or real sign_pub).
    let mut ws = raw_ws(&relay).await;
    let c = challenge(&mut ws).await;
    let v = send_hello(
        &mut ws,
        &auth_hello(&stranger, &a_ident.node_id, &c, "127.0.0.1"),
    )
    .await;
    refused(&v, "bad_signature");
    let mut ws = raw_ws(&relay).await;
    let c = challenge(&mut ws).await;
    let forged = NodeHello::Auth {
        version: PROTOCOL_VERSION,
        node_id: a_ident.node_id.clone(),
        sign_pub: hex::encode(a_id.sign_pub()),
        signature: hex::encode(stranger.sign_auth(&c, "127.0.0.1")),
    };
    refused(&send_hello(&mut ws, &forged).await, "bad_signature");

    // Signature bound to a different relay host.
    let mut ws = raw_ws(&relay).await;
    let c = challenge(&mut ws).await;
    let v = send_hello(
        &mut ws,
        &auth_hello(&a_id, &a_ident.node_id, &c, "evil.example"),
    )
    .await;
    refused(&v, "bad_signature");

    // Replay: a valid signature for one challenge fails on the next connection.
    let mut ws = raw_ws(&relay).await;
    let c1 = challenge(&mut ws).await;
    let good = auth_hello(&a_id, &a_ident.node_id, &c1, "127.0.0.1");
    assert!(matches!(
        send_hello(&mut ws, &good).await,
        RelayVerdict::Welcome { .. }
    ));
    drop(ws);
    let mut ws = raw_ws(&relay).await;
    let c2 = challenge(&mut ws).await;
    assert_ne!(c1, c2, "challenges must be fresh");
    refused(&send_hello(&mut ws, &good).await, "bad_signature");

    // The real daemon authenticates fine.
    let mut a = a;
    a.start_connected().await;

    // Revoked: kicked promptly and refused afterwards.
    let b = enroll_started(&relay, "b").await;
    assert!(relay.h().inner.db.revoke("b", warren::now_secs()).unwrap());
    wait_for("b to be disconnected", Duration::from_secs(5), || {
        !relay.online().contains(&"b".to_string())
    })
    .await;
    let mut ws = raw_ws(&relay).await;
    let c = challenge(&mut ws).await;
    let v = send_hello(
        &mut ws,
        &auth_hello(&b.identity(), &b.ident().node_id, &c, "127.0.0.1"),
    )
    .await;
    refused(&v, "revoked");
    // Other nodes can no longer reach it.
    let e = a.d().inner.open_private("b", 22).await.err().unwrap();
    assert!(matches!(e, OpenError::NoSuchNode(_)), "{e}");
    // b's daemon keeps failing to reconnect and says why.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let st = b.ctl_ok(ControlRequest::Status).await;
    assert_ne!(st["connection"]["state"], "connected");
    assert!(st["recent_errors"].to_string().contains("revoked"), "{st}");
}

/// SR3: codes are single use, expire, are rate-limited per IP and stored hashed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrollment_codes() {
    let relay = start_relay().await;
    let pin = Some(relay.pin);
    let url = relay.url();
    let home = |d: &tempfile::TempDir, n: &str| warren::node::NodePaths::new(d.path().join(n));
    let t = tempfile::tempdir().unwrap();

    // Single use.
    let code = relay.invite(None);
    warren::node::join(&home(&t, "x"), &code, &url, Some("x"), pin, false)
        .await
        .unwrap();
    let e = warren::node::join(&home(&t, "y"), &code, &url, Some("y"), pin, false)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("invalid_code"), "{e}");

    // Expired (created 11 minutes ago with the standard 10 minute lifetime).
    let old = relay
        .h()
        .inner
        .db
        .create_invite(None, warren::limits::INVITE_TTL, warren::now_secs() - 660)
        .unwrap();
    let e = warren::node::join(&home(&t, "z"), &old, &url, Some("z"), pin, false)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("invalid_code"), "{e}");

    // Invite-assigned names win.
    let named = relay.invite(Some("laptop"));
    let f = warren::node::join(&home(&t, "w"), &named, &url, Some("other"), pin, false)
        .await
        .unwrap();
    assert_eq!(f.name, "laptop");

    // Stored only as hashes: no code appears anywhere in the state directory.
    let mut raw = Vec::new();
    for e in std::fs::read_dir(relay.state_dir()).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            raw.extend(std::fs::read(p).unwrap());
        }
    }
    for c in [&code, &old, &named] {
        assert!(!contains(&raw, c.as_bytes()), "code stored in plaintext");
    }
    assert!(relay.h().inner.db.invite_hashes().unwrap().len() >= 3);

    // Rate limit: 5 failures per IP per 10 minutes, then even a valid code is refused.
    let relay2 = start_relay().await;
    let t2 = tempfile::tempdir().unwrap();
    for i in 0..5 {
        let e = warren::node::join(
            &home(&t2, &format!("n{i}")),
            "ABCDEFGHJK",
            &relay2.url(),
            Some("n"),
            Some(relay2.pin),
            false,
        )
        .await
        .unwrap_err();
        assert!(e.to_string().contains("invalid_code"), "{e}");
    }
    let valid = relay2.invite(None);
    let e = warren::node::join(
        &home(&t2, "ok"),
        &valid,
        &relay2.url(),
        Some("ok"),
        Some(relay2.pin),
        false,
    )
    .await
    .unwrap_err();
    assert!(e.to_string().contains("rate_limited"), "{e}");
    // The valid code was not consumed by the refused attempt.
    let db = &relay2.h().inner.db;
    assert!(matches!(
        db.join(&valid, Some("ok"), &[7; 32], &[8; 32], warren::now_secs())
            .unwrap(),
        warren::relay::db::JoinOutcome::Joined(_)
    ));
}

/// SR4: default deny at the destination (through the real relay).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_default_deny() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let c = enroll_started(&relay, "c").await;
    let (echo, accepts) = echo_server().await;

    // Nothing shared.
    let e = a.d().inner.open_private("b", echo).await.err().unwrap();
    assert!(
        matches!(
            e,
            OpenError::Refused {
                code: ErrorCode::NotShared,
                ..
            }
        ),
        "{e}"
    );
    // Shared with c only.
    b.share(echo, Some(vec!["c".into()]));
    let e = a.d().inner.open_private("b", echo).await.err().unwrap();
    assert!(
        matches!(
            e,
            OpenError::Refused {
                code: ErrorCode::Forbidden,
                ..
            }
        ),
        "{e}"
    );
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    let local = c.forward("b", echo).await;
    assert_eq!(echo_roundtrip(local, b"only c").await, b"only c");
    // Unsharing takes effect immediately.
    let mut s = warren::node::SharesFile::load(&b.paths).unwrap();
    s.remove(echo);
    s.save(&b.paths).unwrap();
    let e = c.d().inner.open_private("b", echo).await.err().unwrap();
    assert!(
        matches!(
            e,
            OpenError::Refused {
                code: ErrorCode::NotShared,
                ..
            }
        ),
        "{e}"
    );
    // Shared, but nothing listening: reported (end to end encrypted, after
    // the handshake) as such.
    let idle = free_port().await;
    b.share(idle, None);
    let e = a.d().inner.open_private("b", idle).await.err().unwrap();
    assert!(
        matches!(
            e,
            OpenError::Refused {
                code: ErrorCode::ConnectFailed,
                ..
            }
        ),
        "{e}"
    );
    assert!(e.to_string().contains("nothing is listening"), "{e}");
    // Unknown and offline destinations.
    let e = a.d().inner.open_private("nobody", 22).await.err().unwrap();
    assert!(matches!(e, OpenError::NoSuchNode(_)), "{e}");
    let mut c = c;
    c.stop().await;
    wait_for("c offline", Duration::from_secs(5), || {
        !relay.online().contains(&"c".into())
    })
    .await;
    let e = a.d().inner.open_private("c", 22).await.err().unwrap();
    assert!(
        matches!(
            e,
            OpenError::Refused {
                code: ErrorCode::NodeOffline,
                ..
            }
        ),
        "{e}"
    );
}

/// SR4 against a compromised relay: a fake relay that forwards whatever it
/// likes still cannot reach unshared ports or impersonate an allowed peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compromised_relay_cannot_bypass_destination_policy() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let relay = start_relay().await;
    let b = enroll(&relay, "b").await;
    let c = enroll(&relay, "c").await;
    let (echo, accepts) = echo_server().await;
    let (secret_port, secret_accepts) = echo_server().await;
    b.share(echo, Some(vec!["c".into()]));
    // b has pinned c's real key.
    {
        let mut k = warren::node::KnownPeers::load(&b.paths).unwrap();
        k.pin("c", &c.identity().static_pub, false);
        k.save(&b.paths).unwrap();
    }

    // The fake relay: same TLS stack, but it answers any auth and injects OPENs.
    let dir = tempfile::tempdir().unwrap();
    let (ck, pin) = warren::tls::persistent_self_signed(dir.path(), &["127.0.0.1".into()]).unwrap();
    let resolver = std::sync::Arc::new(warren::tls::CertResolver::new());
    resolver.set_default(ck);
    let acceptor = tokio_rustls::TlsAcceptor::from(warren::tls::server_config(resolver).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    repoint(&b, &format!("https://127.0.0.1:{}", addr.port()), &pin);
    let mut b = b;
    b.start_with(|c| c.ping_interval = Duration::from_secs(60))
        .await;

    let (tcp, _) = listener.accept().await.unwrap();
    let tls = acceptor.accept(tcp).await.unwrap();
    let mut conn = warren::http::BufConn::new(tls, None);
    let req = conn.read_request(32 * 1024).await.unwrap().unwrap();
    let key = req.header("sec-websocket-key").unwrap().to_vec();
    conn.inner
        .write_all(warren::ws::upgrade_response(&key).as_bytes())
        .await
        .unwrap();
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        conn.inner,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    let hello = RelayHello::Challenge {
        version: PROTOCOL_VERSION,
        challenge: hex::encode([1u8; 32]),
    };
    ws.send(Message::text(serde_json::to_string(&hello).unwrap()))
        .await
        .unwrap();
    let _auth = ws.next().await.unwrap().unwrap();
    let welcome = RelayVerdict::Welcome {
        node_id: b.ident().node_id,
        name: "b".into(),
        publish_domain: "x".into(),
        relay_version: "evil".into(),
    };
    ws.send(Message::text(serde_json::to_string(&welcome).unwrap()))
        .await
        .unwrap();
    assert!(b.d().wait_connected(Duration::from_secs(5)).await);

    async fn next_frame(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        >,
        stream: u32,
    ) -> Frame {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(20), ws.next())
                .await
                .expect("frame")
                .unwrap()
                .unwrap();
            if let Message::Binary(b) = m {
                let f = Frame::decode(b).unwrap();
                if f.stream == stream {
                    return f;
                }
            }
        }
    }
    let send_open = |stream: u32, port: u16, src: &str, key: [u8; 32]| {
        let p = OpenPayload {
            flags: 0,
            port,
            dest: "b".into(),
            src: src.into(),
            src_static: Some(key),
            client: String::new(),
        };
        Message::Binary(Frame::new(FrameType::Open, stream, p.encode()).encode())
    };

    // (a) An unshared port is refused before anything is connected.
    let attacker = warren::crypto::Identity::generate();
    ws.send(send_open(2, secret_port, "c", c.identity().static_pub))
        .await
        .unwrap();
    let f = next_frame(&mut ws, 2).await;
    assert_eq!(f.ty, FrameType::OpenErr);
    assert_eq!(f.open_error().0, ErrorCode::NotShared);

    // (b) Claiming to be an allowed peer with the right claimed key, but
    // without its private key: the Noise handshake exposes the impostor.
    ws.send(send_open(4, echo, "c", c.identity().static_pub))
        .await
        .unwrap();
    let f = next_frame(&mut ws, 4).await;
    assert_eq!(f.ty, FrameType::OpenOk);
    let mut hs = snow::Builder::new(warren::crypto::NOISE_PARAMS.parse().unwrap())
        .local_private_key(&attacker.static_secret)
        .unwrap()
        .remote_public_key(&b.identity().static_pub)
        .unwrap()
        .prologue(warren::crypto::NOISE_PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let hello = serde_json::to_vec(&warren::noise::Hello {
        v: 1,
        src: "c".into(),
        dest: "b".into(),
        port: echo,
    })
    .unwrap();
    let n = hs.write_message(&hello, &mut buf).unwrap();
    ws.send(Message::Binary(
        Frame::data(4, bytes::Bytes::copy_from_slice(&buf[..n])).encode(),
    ))
    .await
    .unwrap();
    let f = next_frame(&mut ws, 4).await;
    assert_eq!(f.ty, FrameType::Close, "{f:?}");
    assert_eq!(f.close_kind(), Some(ErrorCode::HandshakeFailed));

    // (c) Claiming an allowed name with a different key than b pinned.
    ws.send(send_open(6, echo, "c", attacker.static_pub))
        .await
        .unwrap();
    let f = next_frame(&mut ws, 6).await;
    assert_eq!(f.ty, FrameType::OpenErr);
    assert_eq!(f.open_error().0, ErrorCode::KeyChanged);

    // (d) A peer that is not on the share list.
    ws.send(send_open(8, echo, "mallory", attacker.static_pub))
        .await
        .unwrap();
    let f = next_frame(&mut ws, 8).await;
    assert_eq!(f.ty, FrameType::OpenErr);
    assert_eq!(f.open_error().0, ErrorCode::Forbidden);

    // No connection ever reached either local service.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(secret_accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    let st = b.ctl_ok(ControlRequest::Status).await;
    assert!(
        st["recent_errors"].to_string().contains("does not match"),
        "{st}"
    );
}

/// SR5: a changed key for a pinned peer is refused until `trust`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_change_requires_trust() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let mut b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    let local = a.forward("b", echo).await;
    assert_eq!(echo_roundtrip(local, b"first").await, b"first");
    let old_fp = b.ident().fingerprint();

    // b is re-enrolled under the same name with new keys.
    b.stop().await;
    assert!(relay.h().inner.db.revoke("b", warren::now_secs()).unwrap());
    let code = relay.invite(Some("b"));
    warren::node::join(&b.paths, &code, &relay.url(), None, Some(relay.pin), true)
        .await
        .unwrap();
    let new_fp = b.ident().fingerprint();
    assert_ne!(old_fp, new_fp);
    b.start_connected().await;

    let e = a.d().inner.open_private("b", echo).await.err().unwrap();
    match &e {
        OpenError::KeyChanged {
            name,
            pinned,
            current,
        } => {
            assert_eq!(name, "b");
            assert_eq!(pinned, &old_fp);
            assert_eq!(current, &new_fp);
        }
        other => panic!("expected KeyChanged, got {other}"),
    }
    assert!(e.to_string().contains("warren trust b --expect"), "{e}");
    // The forward refuses too (the connection is closed without data).
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", local))
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
    assert!(buf.is_empty());
    // devices shows the mismatch.
    let dev = a.ctl_ok(ControlRequest::Devices).await;
    let bdev = dev
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == "b")
        .unwrap()
        .clone();
    assert_eq!(bdev["pin"], "changed");

    // Replacing a pinned key needs the verified fingerprint.
    let r = a
        .ctl(ControlRequest::Trust {
            name: "b".into(),
            expect: None,
        })
        .await;
    assert_eq!(r.code.as_deref(), Some("fingerprint_required"), "{r:?}");
    assert!(
        r.error.as_deref().unwrap_or("").contains(&new_fp),
        "the refusal names the fingerprint to verify: {r:?}"
    );
    assert_eq!(bdev["trust"], format!("warren trust b --expect {new_fp}"));
    // trust with a wrong expected fingerprint is refused.
    let r = a
        .ctl(ControlRequest::Trust {
            name: "b".into(),
            expect: Some(old_fp.clone()),
        })
        .await;
    assert_eq!(r.code.as_deref(), Some("fingerprint_mismatch"));
    // trust shows both fingerprints and accepts the new key.
    let t = a
        .ctl_ok(ControlRequest::Trust {
            name: "b".into(),
            expect: Some(new_fp.clone()),
        })
        .await;
    assert_eq!(t["previous"], old_fp.as_str());
    assert_eq!(t["current"], new_fp.as_str());
    assert_eq!(t["changed"], true);
    assert_eq!(echo_roundtrip(local, b"after trust").await, b"after trust");
}

/// Relay backpressure: a destination that stops reading makes the relay stop
/// reading from the node feeding it, so its queue stays bounded and no link
/// carrying legal traffic is torn down; only a destination that makes no
/// progress at all for the stuck timeout is disconnected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_backpressure_bounds_queues_and_drops_only_stuck_links() {
    use futures_util::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_tungstenite::tungstenite::Message;
    use warren::limits::RELAY_LINK_DATA_BUDGET;

    let relay = start_relay_with(|c| c.link_stuck_timeout = Duration::from_secs(4)).await;
    let a = enroll(&relay, "a").await;
    let b = enroll(&relay, "b").await;
    let mut ra = RawNode::connect(&relay, &a).await;
    // b accepts one stream, grants a huge window, then stops reading.
    let mut wb = raw_ws(&relay).await;
    let c = challenge(&mut wb).await;
    let v = send_hello(
        &mut wb,
        &auth_hello(&b.identity(), &b.ident().node_id, &c, "127.0.0.1"),
    )
    .await;
    assert!(matches!(v, RelayVerdict::Welcome { .. }), "{v:?}");
    ra.send(open_frame(1, "b", 22)).await;
    let open = loop {
        let m = tokio::time::timeout(Duration::from_secs(5), wb.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Binary(m) = m {
            let f = Frame::decode(m).unwrap();
            if f.ty == FrameType::Open {
                break f;
            }
        }
    };
    let extra = 63 * 1024 * 1024;
    wb.send(Message::Binary(Frame::open_ok(open.stream).encode()))
        .await
        .unwrap();
    wb.send(Message::Binary(Frame::window(open.stream, extra).encode()))
        .await
        .unwrap();

    let a_closed = ra.closed.clone();
    let sent = std::sync::Arc::new(AtomicUsize::new(0));
    let s2 = sent.clone();
    let total = STREAM_WINDOW as usize + extra as usize;
    let sender = tokio::spawn(async move {
        loop {
            let f = ra.next(Duration::from_secs(5)).await.expect("OPEN_OK");
            if f.ty == FrameType::OpenOk {
                break;
            }
        }
        let chunk = bytes::Bytes::from(vec![7u8; MAX_PAYLOAD]);
        for _ in 0..total / MAX_PAYLOAD {
            ra.send(Frame::data(1, chunk.clone())).await;
            s2.fetch_add(MAX_PAYLOAD, Ordering::SeqCst);
        }
        ra
    });

    let b_link = || {
        relay
            .h()
            .inner
            .online
            .lock()
            .unwrap()
            .values()
            .find(|l| l.name == "b")
            .cloned()
    };
    wait_for("b's relay queue to fill", Duration::from_secs(15), || {
        b_link().is_some_and(|l| l.out.queued_data() + MAX_WS_MESSAGE > RELAY_LINK_DATA_BUDGET)
    })
    .await;
    // Paused, not dropped: the queue stays within its budget, the sender is
    // held back, and both links are still up.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let q = b_link().expect("b still connected").out.queued_data();
    assert!(q <= RELAY_LINK_DATA_BUDGET, "queue {q} exceeds the budget");
    assert!(
        sent.load(Ordering::SeqCst) < total,
        "the sender was never paused"
    );
    assert!(!a_closed.load(Ordering::SeqCst));
    assert!(relay.online().contains(&"a".to_string()));

    // No progress at all for the stuck timeout: b is disconnected, a is not.
    wait_for(
        "the stuck link to be dropped",
        Duration::from_secs(15),
        || !relay.online().contains(&"b".to_string()),
    )
    .await;
    let ra = tokio::time::timeout(Duration::from_secs(20), sender)
        .await
        .expect("the sender resumes once the stuck link is gone")
        .unwrap();
    assert!(!ra.is_closed(), "the source link was torn down");
    assert!(relay.online().contains(&"a".to_string()));
    drop(wb);
}

/// Publishing: HTTP keep-alive, chunked bodies, long-poll, WebSocket, and
/// SR7 (no X-Forwarded-* spoofing, no name hijacking).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_http_websocket_and_header_rewrite() {
    use futures_util::{SinkExt, StreamExt};
    let relay = start_relay().await;
    let b = enroll_started(&relay, "b").await;
    let c = enroll_started(&relay, "c").await;
    let web = http_backend().await;
    let r = b
        .ctl_ok(ControlRequest::Publish {
            port: web,
            name: "web".into(),
            replace: false,
            allow: vec![],
        })
        .await;
    assert_eq!(
        r["url"],
        format!("https://web.warren.test:{}/", relay.addr.port())
    );

    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    // 1: spoofed forwarding headers are replaced.
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\nX-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: http\r\nX-Real-IP: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\n\r\n").await.unwrap();
    let (code, _, body) = read_response(&mut rc).await;
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["xff"], serde_json::json!(["127.0.0.1"]));
    assert_eq!(v["proto"], serde_json::json!(["https"]));
    assert_eq!(v["host"], serde_json::json!(["web.warren.test"]));
    assert_eq!(v["forwarded"], serde_json::json!([]));
    assert_eq!(v["real_ip"], serde_json::json!([]));
    // 2: same connection (keep-alive), chunked request body, spoof attempt again.
    w.write_all(b"POST /echo HTTP/1.1\r\nHost: web.warren.test\r\nTransfer-Encoding: chunked\r\nx-forwarded-for: 1.2.3.4\r\n\r\n4\r\nwarr\r\n2\r\nen\r\n0\r\n\r\n").await.unwrap();
    let (code, _, body) = read_response(&mut rc).await;
    assert_eq!(code, 200);
    assert_eq!(body, b"warren");
    w.write_all(
        b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
    )
    .await
    .unwrap();
    let (_, _, body) = read_response(&mut rc).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["xff"], serde_json::json!(["127.0.0.1"]));
    // 3: chunked response.
    w.write_all(b"GET /chunked HTTP/1.1\r\nHost: web.warren.test\r\n\r\n")
        .await
        .unwrap();
    let (code, h, body) = read_response(&mut rc).await;
    assert_eq!(code, 200);
    assert_eq!(header(&h, "transfer-encoding"), Some("chunked"));
    assert_eq!(body, b"hello, world");
    // 4: long poll.
    let t0 = std::time::Instant::now();
    w.write_all(b"GET /slow HTTP/1.1\r\nHost: web.warren.test\r\n\r\n")
        .await
        .unwrap();
    let (_, _, body) = read_response(&mut rc).await;
    assert_eq!(body, b"late");
    assert!(t0.elapsed() >= Duration::from_millis(1400));
    // 5: a request smuggling attempt is refused and the connection closed.
    w.write_all(b"POST /echo HTTP/1.1\r\nHost: web.warren.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").await.unwrap();
    let (code, _, _) = read_response(&mut rc).await;
    assert_eq!(code, 400);
    // 6: a different Host on the same connection is refused (421) on a fresh connection.
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w2) = tokio::io::split(tls);
    let mut rc2 = warren::http::BufConn::new(rd, None);
    w2.write_all(b"GET /x HTTP/1.1\r\nHost: other.warren.test\r\n\r\n")
        .await
        .unwrap();
    let (code, _, _) = read_response(&mut rc2).await;
    assert_eq!(code, 421);

    // WebSocket upgrade through the relay.
    let tls = tls_connect(&relay, "web.warren.test").await;
    let url = format!("wss://web.warren.test:{}/ws", relay.addr.port());
    let (mut ws, resp) = tokio_tungstenite::client_async(url, tls).await.unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    for i in 0..5 {
        let msg = format!("ping {i}");
        ws.send(tokio_tungstenite::tungstenite::Message::text(msg.clone()))
            .await
            .unwrap();
        let back = ws.next().await.unwrap().unwrap();
        assert_eq!(back.into_text().unwrap().as_str(), msg);
    }
    let big = vec![42u8; 200_000];
    ws.send(tokio_tungstenite::tungstenite::Message::binary(big.clone()))
        .await
        .unwrap();
    let back = ws.next().await.unwrap().unwrap();
    assert_eq!(back.into_data().as_ref(), &big[..]);
    ws.close(None).await.unwrap();

    // SR7: another node cannot take the name, with or without --replace.
    for replace in [false, true] {
        let r = c
            .ctl(ControlRequest::Publish {
                port: web,
                name: "web".into(),
                replace,
                allow: vec![],
            })
            .await;
        assert_eq!(r.code.as_deref(), Some("name_taken"), "{r:?}");
    }
    // The owner needs --replace to change it.
    let r = b
        .ctl(ControlRequest::Publish {
            port: web,
            name: "web".into(),
            replace: false,
            allow: vec![],
        })
        .await;
    assert_eq!(r.code.as_deref(), Some("already_published"));
    // Allowlist: only 10.0.0.0/8 may connect, so 127.0.0.1 is refused.
    b.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "web".into(),
        replace: true,
        allow: vec!["10.0.0.0/8".into()],
    })
    .await;
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 403);
    b.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "web".into(),
        replace: true,
        allow: vec!["127.0.0.0/8".into()],
    })
    .await;

    // Unknown names and offline publishers.
    let tls = tls_connect(&relay, "nothing.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET / HTTP/1.1\r\nHost: nothing.warren.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 404);
    let mut b = b;
    b.stop().await;
    wait_for("b offline", Duration::from_secs(5), || {
        !relay.online().contains(&"b".into())
    })
    .await;
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 502);
    // Still not claimable by c while b is offline.
    let r = c
        .ctl(ControlRequest::Publish {
            port: web,
            name: "web".into(),
            replace: true,
            allow: vec![],
        })
        .await;
    assert_eq!(r.code.as_deref(), Some("name_taken"));
    // After b comes back, unpublish releases it.
    b.start_connected().await;
    b.ctl_ok(ControlRequest::Unpublish { name: "web".into() })
        .await;
    c.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "web".into(),
        replace: false,
        allow: vec![],
    })
    .await;
}

/// The node reconnects after the relay restarts; forwards and publishes resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_after_relay_restart() {
    let mut relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let b = enroll_started(&relay, "b").await;
    let (echo, _) = echo_server().await;
    b.share(echo, None);
    let local = a.forward("b", echo).await;
    assert_eq!(echo_roundtrip(local, b"before").await, b"before");
    let web = http_backend().await;
    b.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "site".into(),
        replace: false,
        allow: vec![],
    })
    .await;

    relay.restart().await;
    // Nodes notice and come back with jittered backoff.
    wait_for("both back online", Duration::from_secs(20), || {
        relay.online().len() == 2
    })
    .await;
    assert!(a.d().wait_connected(Duration::from_secs(5)).await);
    assert!(b.d().wait_connected(Duration::from_secs(5)).await);
    assert_eq!(echo_roundtrip(local, b"after").await, b"after");
    let tls = tls_connect(&relay, "site.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: site.warren.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 200);
    let st = a.ctl_ok(ControlRequest::Status).await;
    assert!(st["connection"]["connects"].as_u64().unwrap() >= 2);
}

/// SR6: stream count, open rate, frame size and window overrun limits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mux_limits_hold_under_abuse() {
    let relay = start_relay().await;
    let a = enroll(&relay, "a").await;
    let b = enroll(&relay, "b").await;
    let mut ra = RawNode::connect(&relay, &a).await;
    let mut rb = RawNode::connect(&relay, &b).await;

    // Open rate: a burst of 200 opens; beyond the 64-token bucket they are refused.
    for i in 0..200u32 {
        ra.send(open_frame(2 * i + 1, "b", 22)).await;
    }
    let mut limited = 0;
    let mut forwarded = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline && limited + forwarded < 200 {
        tokio::select! {
            f = ra.next(Duration::from_millis(200)) => {
                if let Some(f) = f {
                    if f.ty == FrameType::OpenErr && f.open_error().0 == ErrorCode::RateLimited {
                        limited += 1;
                    }
                }
            }
            f = rb.next(Duration::from_millis(200)) => {
                if let Some(f) = f {
                    if f.ty == FrameType::Open { forwarded += 1; }
                }
            }
        }
    }
    assert!(limited >= 120, "only {limited} opens rate-limited");
    assert!(
        (64..=80).contains(&forwarded),
        "{forwarded} opens forwarded"
    );

    // Stream count: keep opening (paced under the rate limit) until the
    // per-node cap of 1024 concurrent streams refuses more.
    let mut next = 1001u32;
    let mut open_now = forwarded;
    let mut too_many = false;
    while open_now < MAX_STREAMS_PER_NODE + 5 {
        for _ in 0..16 {
            ra.send(open_frame(next, "b", 22)).await;
            next += 2;
        }
        tokio::time::sleep(Duration::from_millis(260)).await;
        while let Ok(f) = ra.frames.try_recv() {
            if f.ty == FrameType::OpenErr {
                match f.open_error().0 {
                    ErrorCode::TooManyStreams => too_many = true,
                    ErrorCode::RateLimited => {}
                    other => panic!("unexpected {other}"),
                }
            }
        }
        while let Ok(f) = rb.frames.try_recv() {
            if f.ty == FrameType::Open {
                open_now += 1;
            }
        }
        if too_many {
            break;
        }
    }
    assert!(too_many, "stream cap never enforced ({open_now} open)");
    assert_eq!(
        open_now, MAX_STREAMS_PER_NODE,
        "exactly the cap is forwarded"
    );
    let a_link = relay
        .h()
        .inner
        .online
        .lock()
        .unwrap()
        .values()
        .find(|l| l.name == "a")
        .unwrap()
        .clone();
    assert_eq!(a_link.stream_count(), MAX_STREAMS_PER_NODE);
    drop(a_link);

    // Window overrun: a fresh pair of raw nodes, one accepted stream, then
    // more DATA than the 256 KiB window without waiting for credit.
    let c = enroll(&relay, "c").await;
    let d = enroll(&relay, "d").await;
    let mut rc = RawNode::connect(&relay, &c).await;
    let mut rd = RawNode::connect(&relay, &d).await;
    rc.send(open_frame(1, "d", 22)).await;
    let open = rd.next(Duration::from_secs(5)).await.unwrap();
    assert_eq!(open.ty, FrameType::Open);
    let p = OpenPayload::decode(&open.payload).unwrap();
    assert_eq!(p.src, "c", "relay stamps the authenticated source");
    assert_eq!(p.src_static, Some(c.identity().static_pub));
    rd.send(Frame::open_ok(open.stream)).await;
    assert_eq!(
        rc.next(Duration::from_secs(5)).await.unwrap().ty,
        FrameType::OpenOk
    );
    let chunk = bytes::Bytes::from(vec![0u8; MAX_PAYLOAD]);
    for _ in 0..5 {
        rc.send(Frame::data(1, chunk.clone())).await;
    }
    let mut reset_c = false;
    while let Some(f) = rc.next(Duration::from_secs(3)).await {
        if f.ty == FrameType::Close && f.close_kind() == Some(ErrorCode::WindowOverrun) {
            reset_c = true;
            break;
        }
    }
    assert!(reset_c, "sender was not reset on overrun");
    let mut delivered = 0usize;
    let mut reset_d = false;
    while let Some(f) = rd.next(Duration::from_secs(3)).await {
        match f.ty {
            FrameType::Data => delivered += f.payload.len(),
            FrameType::Close => {
                reset_d = f.close_kind() == Some(ErrorCode::WindowOverrun);
                break;
            }
            _ => {}
        }
    }
    assert!(reset_d);
    assert!(
        delivered <= STREAM_WINDOW as usize,
        "relay forwarded {delivered} bytes beyond the window"
    );

    // Frame size: a message larger than one maximal frame closes the link.
    rc.send_raw(vec![4u8; MAX_WS_MESSAGE + 1]).await;
    wait_for(
        "oversized frame to close the link",
        Duration::from_secs(5),
        || rc.is_closed(),
    )
    .await;
    wait_for("c offline", Duration::from_secs(5), || {
        !relay.online().contains(&"c".into())
    })
    .await;
    // A frame whose length field lies also closes the link.
    let mut bad = Frame::data(3, bytes::Bytes::from_static(b"abc"))
        .encode()
        .to_vec();
    bad[6] = 200;
    rd.send_raw(bad).await;
    wait_for(
        "malformed frame to close the link",
        Duration::from_secs(5),
        || rd.is_closed(),
    )
    .await;
    // A node may not use relay-side (even) stream ids.
    let mut ra2 = RawNode::connect(&relay, &c).await;
    ra2.send(open_frame(2, "d", 22)).await;
    wait_for("even id to close the link", Duration::from_secs(5), || {
        ra2.is_closed()
    })
    .await;
}

/// SR6 on the public side: header timeout, idle timeout, max header size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_side_slowloris_and_header_limits() {
    let relay = start_relay_with(|c| {
        c.header_timeout = Duration::from_millis(1500);
        c.idle_timeout = Duration::from_secs(2);
    })
    .await;
    let b = enroll_started(&relay, "b").await;
    let web = http_backend().await;
    b.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "web".into(),
        replace: false,
        allow: vec![],
    })
    .await;

    // Defaults: 10 s / 5 min / 32 KiB.
    let d = warren::relay::RelayConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        "r",
        "/tmp/unused".into(),
        warren::relay::TlsMode::SelfSigned,
    );
    assert_eq!(d.header_timeout, Duration::from_secs(10));
    assert_eq!(d.idle_timeout, Duration::from_secs(300));
    assert_eq!(warren::limits::MAX_REQUEST_HEAD, 32 * 1024);

    // Slowloris: dribbling a request head never completes it.
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (mut rd, mut w) = tokio::io::split(tls);
    let t0 = std::time::Instant::now();
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\n")
        .await
        .unwrap();
    let dribble = async {
        for i in 0..40 {
            if w.write_all(format!("X-{i}: y\r\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    };
    let mut buf = Vec::new();
    tokio::select! {
        _ = dribble => panic!("slow client was never cut off"),
        _ = rd.read_to_end(&mut buf) => {}
    }
    let took = t0.elapsed();
    assert!(took < Duration::from_secs(4), "cut off after {took:?}");
    assert!(!String::from_utf8_lossy(&buf).contains("200 OK"));

    // A TCP connection that never starts TLS is closed too.
    let mut raw = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let mut sink = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(4), raw.read_to_end(&mut sink)).await;
    assert!(r.is_ok(), "idle TCP connection not closed");

    // Oversized request head: 431.
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    let mut req = b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\nX-Big: ".to_vec();
    req.extend(std::iter::repeat_n(b'a', 33 * 1024));
    req.extend_from_slice(b"\r\n\r\n");
    let _ = w.write_all(&req).await;
    assert_eq!(read_response(&mut rc).await.0, 431);

    // The same on a keep-alive connection's second request.
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 200);
    let _ = w.write_all(&req).await;
    assert_eq!(read_response(&mut rc).await.0, 431);

    // Idle keep-alive connection is closed after the idle timeout.
    let tls = tls_connect(&relay, "web.warren.test").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: web.warren.test\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 200);
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(6), rc.fill()).await;
    assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "{r:?}");
    let idle = t0.elapsed();
    assert!(
        idle >= Duration::from_millis(1500) && idle < Duration::from_secs(5),
        "{idle:?}"
    );
}

/// SR8 (in-process part): status and device JSON never carry secrets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_outputs_have_no_secrets() {
    let relay = start_relay().await;
    let a = enroll_started(&relay, "a").await;
    let _b = enroll_started(&relay, "b").await;
    let raw_ident = std::fs::read_to_string(a.paths.identity()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw_ident).unwrap();
    let secrets = [
        v["sign_secret"].as_str().unwrap().to_string(),
        v["static_secret"].as_str().unwrap().to_string(),
    ];
    let st = a.ctl_ok(ControlRequest::Status).await.to_string();
    let dev = a.ctl_ok(ControlRequest::Devices).await.to_string();
    for s in &secrets {
        assert!(!st.contains(s.as_str()) && !dev.contains(s.as_str()));
        assert!(!st.contains(&s[..16]) && !dev.contains(&s[..16]));
    }
    assert!(warren::fsutil::is_private(&a.paths.home).unwrap());
    for f in ["identity.json", "known_peers.json"] {
        assert!(
            warren::fsutil::is_private(&a.paths.home.join(f)).unwrap(),
            "{f}"
        );
    }
    #[cfg(unix)]
    assert!(warren::fsutil::is_private(&a.paths.socket()).unwrap());
    assert!(warren::fsutil::is_private(&relay.state_dir()).unwrap());
    for e in std::fs::read_dir(relay.state_dir()).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            assert!(warren::fsutil::is_private(&p).unwrap(), "{}", p.display());
        }
    }
}

/// Custom domains configured by the relay operator route to a published name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custom_domain_routes_to_published_name() {
    let relay = start_relay().await;
    let b = enroll_started(&relay, "b").await;
    let web = http_backend().await;
    b.ctl_ok(ControlRequest::Publish {
        port: web,
        name: "web".into(),
        replace: false,
        allow: vec![],
    })
    .await;
    // What `warren relay domain add app.example.org web` does, against the
    // running relay's state file.
    let admin = warren::relay::db::Db::open(&relay.state_dir()).unwrap();
    admin.add_domain("App.Example.org", "web").unwrap();
    wait_for("domain reload", Duration::from_secs(5), || {
        relay.h().inner.route_public("app.example.org").as_deref() == Some("web")
    })
    .await;
    let tls = tls_connect(&relay, "app.example.org").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET /headers HTTP/1.1\r\nHost: app.example.org\r\n\r\n")
        .await
        .unwrap();
    let (code, _, body) = read_response(&mut rc).await;
    assert_eq!(code, 200);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["host"], serde_json::json!(["app.example.org"]));
    // Unknown hosts get nothing.
    let tls = tls_connect(&relay, "unknown.example.org").await;
    let (rd, mut w) = tokio::io::split(tls);
    let mut rc = warren::http::BufConn::new(rd, None);
    w.write_all(b"GET / HTTP/1.1\r\nHost: unknown.example.org\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(read_response(&mut rc).await.0, 404);
    assert!(admin.remove_domain("app.example.org").unwrap());
}

/// SR6: connection floods are bounded per client address, including
/// connections that never finish the TLS handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_address_connection_limit() {
    let relay = start_relay_with(|c| c.header_timeout = Duration::from_secs(5)).await;
    let mut held = Vec::new();
    for _ in 0..warren::limits::MAX_CONNECTIONS_PER_IP {
        held.push(tokio::net::TcpStream::connect(relay.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    // One more from the same address is dropped at once.
    let mut extra = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    let t0 = std::time::Instant::now();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), extra.read_to_end(&mut buf)).await;
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "excess connection was not dropped"
    );
    // The held ones are still open (their handshake deadline has not passed).
    let mut probe = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_millis(200), held[0].read(&mut probe)).await;
    assert!(r.is_err(), "held connection closed early");
    // Releasing them frees the slots again.
    drop(held);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let a = enroll(&relay, "a").await;
    let _raw = RawNode::connect(&relay, &a).await;
}
