mod common;
use common::*;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::TcpListener;
use warren::{
    node::{control::ControlRequest, KnownPeers},
    proto::*,
};

async fn cli(node: &TestNode, args: &[&str], input: &[u8]) -> std::process::Output {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_warren"))
        .env("WARREN_HOME", &node.paths.home)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn pin(owner: &TestNode, peer: &TestNode) {
    let mut pins = KnownPeers::load(&owner.paths).unwrap();
    pins.pin(&peer.name, &peer.identity().static_pub, true);
    pins.save(&owner.paths).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly supplied host private interface; binds only this host"]
async fn named_gateway_real_lan_roundtrip_revoke_and_policy() {
    let ip = std::env::var("WARREN_TEST_LAN_IP").expect(
        "set WARREN_TEST_LAN_IP to this host's private interface; no LAN discovery is performed",
    );
    let listener = TcpListener::bind(format!("{ip}:0")).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let a = accepts.clone();
    let live = active.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            a.fetch_add(1, Ordering::SeqCst);
            live.fetch_add(1, Ordering::SeqCst);
            let live = live.clone();
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    let relay = start_relay().await;
    let mut client = enroll_started(&relay, "client").await;
    let mut gateway = enroll_started(&relay, "gateway").await;
    pin(&gateway, &client);
    pin(&client, &gateway);
    let set = |to| ControlRequest::GatewaySet {
        name: "camera-secret".into(),
        target: address.to_string(),
        to,
    };
    gateway.ctl_ok(set(Some(vec!["client".into()]))).await;
    let status = gateway.ctl_ok(ControlRequest::Status).await.to_string();
    assert!(!status.contains(&address.to_string()));
    assert!(status.contains("camera-secret"));
    assert!(client
        .d()
        .inner
        .open_gateway("gateway", "unlisted")
        .await
        .is_err());
    assert!(client
        .d()
        .inner
        .open_private("gateway", address.port())
        .await
        .is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), 0);
    let mut channel = client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .unwrap();
    channel.tx.send(b"camera-bytes").await.unwrap();
    assert_eq!(channel.rx.recv().await.unwrap().unwrap(), b"camera-bytes");
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    gateway
        .ctl_ok(ControlRequest::GatewayRemove {
            name: "camera-secret".into(),
        })
        .await;
    let closed = tokio::time::timeout(Duration::from_secs(2), channel.rx.recv())
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap().is_none());
    wait_for("target TCP closed", Duration::from_secs(2), || {
        active.load(Ordering::SeqCst) == 0
    })
    .await;
    assert!(client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    gateway.ctl_ok(set(None)).await;
    let mut chan = client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .unwrap();
    // A replacement always starts a generation and closes the old stream.
    gateway.ctl_ok(set(None)).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), chan.rx.recv())
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap().is_none());
    wait_for(
        "replacement target TCP closed",
        Duration::from_secs(2),
        || active.load(Ordering::SeqCst) == 0,
    )
    .await;
    let mut stranger = enroll_started(&relay, "stranger").await;
    pin(&stranger, &gateway);
    assert!(stranger
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .is_err());
    let accepted = accepts.load(Ordering::SeqCst);
    // Even a separately pinned peer remains outside the prior grant snapshot.
    pin(&gateway, &stranger);
    assert!(stranger
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .is_err());
    assert_eq!(accepts.load(Ordering::SeqCst), accepted);
    stranger.stop().await;
    let mut chan = client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .unwrap();
    // Malformed external edits cancel active TCP and deny admission.
    let saved = std::fs::read(gateway.paths.shares()).unwrap();
    std::fs::write(gateway.paths.shares(), b"{malformed").unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), chan.rx.recv())
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap().is_none());
    wait_for(
        "malformed target TCP closed",
        Duration::from_secs(2),
        || active.load(Ordering::SeqCst) == 0,
    )
    .await;
    assert!(client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .is_err());
    std::fs::write(gateway.paths.shares(), saved).unwrap();
    // Actual CLI grant, nc half-close, persisted named forward, and revoke acknowledgements.
    let output = cli(
        &gateway,
        &[
            "--json",
            "share",
            "--target",
            &address.to_string(),
            "--name",
            "camera-secret",
            "--to",
            "client",
        ],
        b"",
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"name":"camera-secret","gateway":true})
    );
    let output = cli(
        &client,
        &["nc", "gateway", "--share", "camera-secret"],
        b"cli-gateway-half-close",
    )
    .await;
    assert_eq!(output.stdout, b"cli-gateway-half-close");
    let local = free_port().await;
    let output = cli(
        &client,
        &[
            "--json",
            "forward",
            &local.to_string(),
            "gateway",
            "--share",
            "camera-secret",
        ],
        b"",
    )
    .await;
    let forward: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(forward["share"], "camera-secret");
    assert_eq!(forward["active"], true);
    assert_eq!(
        echo_roundtrip(local, b"named-forward").await,
        b"named-forward"
    );
    let output = cli(
        &gateway,
        &["--json", "unshare", "--name", "camera-secret"],
        b"",
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"name":"camera-secret","removed":true})
    );
    assert!(client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .is_err());
    gateway.ctl_ok(set(Some(vec!["client".into()]))).await;
    // Changing the grant key to another valid key must deny the former peer.
    let mut file = warren::node::SharesFile::load(&gateway.paths).unwrap();
    file.gateways[0]
        .peers
        .insert("client".into(), hex::encode([9u8; 32]));
    file.save(&gateway.paths).unwrap();
    assert!(client
        .d()
        .inner
        .open_gateway("gateway", "camera-secret")
        .await
        .is_err());
    // Public/loopback/metadata targets are refused at mutation; no socket dial.
    for target in ["127.0.0.1:80", "8.8.8.8:80", "169.254.169.254:80"] {
        assert!(
            !gateway
                .ctl(ControlRequest::GatewaySet {
                    name: "bad".into(),
                    target: target.into(),
                    to: None
                })
                .await
                .ok
        );
    }
    let wire: Vec<u8> = relay
        .captures
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, b)| b.iter().copied())
        .collect();
    for private in ["camera-secret", &address.to_string(), "camera-bytes"] {
        assert!(!wire.windows(private.len()).any(|w| w == private.as_bytes()));
    }
    let audit = std::fs::read_to_string(gateway.paths.home.join("gateway-audit.json")).unwrap();
    assert!(audit.contains("connect"));
    assert!(audit.contains("refusal"));
    assert!(!audit.contains(&address.to_string()));
    client.stop().await;
    gateway.stop().await;
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_flags_and_pending_handshake_revoke() {
    let relay = start_relay().await;
    let client = enroll(&relay, "client").await;
    let mut gateway = enroll_started(&relay, "gateway").await;
    pin(&gateway, &client);
    gateway
        .ctl_ok(ControlRequest::GatewaySet {
            name: "camera".into(),
            target: "192.168.1.99:554".into(),
            to: Some(vec!["client".into()]),
        })
        .await;
    let mut raw = RawNode::connect(&relay, &client).await;
    for (i, (flags, port)) in [
        (3, 0),
        (4, 0),
        (FLAG_GATEWAY, 554),
        (0, 0),
        (FLAG_PUBLIC, 554),
    ]
    .into_iter()
    .enumerate()
    {
        let id = 2 * i as u32 + 1;
        raw.send(Frame::new(
            FrameType::Open,
            id,
            OpenPayload {
                flags,
                port,
                dest: "gateway".into(),
                ..Default::default()
            }
            .encode(),
        ))
        .await;
        let r = raw.next(Duration::from_secs(2)).await.unwrap();
        assert_eq!(r.ty, FrameType::OpenErr);
        assert_eq!(r.open_error().0, ErrorCode::BadRequest);
    }
    raw.send(Frame::new(
        FrameType::Open,
        21,
        OpenPayload {
            flags: FLAG_GATEWAY,
            port: 0,
            dest: "gateway".into(),
            ..Default::default()
        }
        .encode(),
    ))
    .await;
    assert_eq!(
        raw.next(Duration::from_secs(2)).await.unwrap().ty,
        FrameType::OpenOk
    );
    gateway
        .ctl_ok(ControlRequest::GatewayRemove {
            name: "camera".into(),
        })
        .await;
    assert_eq!(
        raw.next(Duration::from_secs(2)).await.unwrap().ty,
        FrameType::Close
    );
    gateway.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_failure_is_visible_and_denies_open_but_never_holds_revoke() {
    let relay = start_relay().await;
    let client = enroll(&relay, "client").await;
    let mut gateway = enroll_started(&relay, "gateway").await;
    pin(&gateway, &client);
    gateway
        .ctl_ok(ControlRequest::GatewaySet {
            name: "camera".into(),
            target: "192.168.1.99:554".into(),
            to: Some(vec!["client".into()]),
        })
        .await;
    let audit_path = gateway.paths.home.join("gateway-audit.json");
    std::fs::write(&audit_path, b"{preserve-damaged-evidence").unwrap();
    let rejected = gateway
        .ctl(ControlRequest::GatewaySet {
            name: "second".into(),
            target: "192.168.1.99:554".into(),
            to: None,
        })
        .await;
    assert!(!rejected.ok);
    let mut raw = RawNode::connect(&relay, &client).await;
    raw.send(Frame::new(
        FrameType::Open,
        1,
        OpenPayload {
            flags: FLAG_GATEWAY,
            port: 0,
            dest: "gateway".into(),
            ..Default::default()
        }
        .encode(),
    ))
    .await;
    let refused = raw.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!(refused.ty, FrameType::OpenErr);
    assert_eq!(refused.open_error().0, ErrorCode::Internal);
    let status = gateway.ctl_ok(ControlRequest::Status).await;
    assert_eq!(status["gateway_audit"]["degraded"], true);
    assert_eq!(status["gateway_count"], 1);
    let revoked = gateway
        .ctl(ControlRequest::GatewayRemove {
            name: "camera".into(),
        })
        .await;
    assert!(!revoked.ok);
    assert!(serde_json::to_string(&revoked)
        .unwrap()
        .contains("revoked and connections drained"));
    let status = gateway.ctl_ok(ControlRequest::Status).await;
    assert_eq!(status["gateway_count"], 0);
    assert_eq!(status["gateway_audit"]["degraded"], true);
    assert_eq!(
        std::fs::read(&audit_path).unwrap(),
        b"{preserve-damaged-evidence"
    );
    assert!(!status.to_string().contains("192.168.1.99"));
    gateway.stop().await;
}

#[test]
fn selector_is_old_relay_fail_closed_and_legacy_hello_stable() {
    let p = OpenPayload {
        flags: FLAG_GATEWAY,
        port: 0,
        dest: "gateway".into(),
        ..Default::default()
    };
    let round = OpenPayload::decode(&p.encode()).unwrap();
    assert_eq!(p, round);
    assert!(round.valid_private_selector());
    // This exact historical relay predicate rejects the new selector. No retry occurs.
    assert!(round.is_public() || round.port == 0);
    let old = r#"{"v":1,"src":"a","dest":"b","port":22}"#;
    let hello: warren::noise::Hello = serde_json::from_str(old).unwrap();
    assert!(hello.share.is_none());
    assert_eq!(serde_json::to_string(&hello).unwrap(), old);
}
