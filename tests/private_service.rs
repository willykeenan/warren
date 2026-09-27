mod common;
use common::*;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use warren::{
    node::{
        control::ControlRequest,
        private_service::{PrivateServiceHandler, ServiceContext},
        KnownPeers,
    },
    noise::SecureChannel,
    proto::*,
};

type ObservedPeer = (String, [u8; 32], [u8; 32]);

#[derive(Default)]
struct Handler {
    calls: AtomicUsize,
    active: Arc<AtomicUsize>,
    seen: Mutex<Vec<ObservedPeer>>,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl PrivateServiceHandler for Handler {
    fn handle<'a>(
        &'a self,
        context: &'a ServiceContext,
        stream: &'a mut SecureChannel,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            context
                .with_authorization(|| {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    self.active.fetch_add(1, Ordering::SeqCst);
                    self.seen.lock().unwrap().push((
                        context.peer_name().into(),
                        context.peer_static_key(),
                        context.registration().generation(),
                    ));
                })
                .unwrap();
            let _active = Active(self.active.clone());
            while let Ok(Some(bytes)) = stream.rx.recv().await {
                if context.with_authorization(|| ()).is_err()
                    || stream.tx.send(&bytes).await.is_err()
                {
                    break;
                }
            }
        })
    }
}
fn pin_peer(owner: &TestNode, peer: &TestNode, trusted: bool) {
    let mut pins = KnownPeers::load(&owner.paths).unwrap();
    pins.pin(&peer.name, &peer.identity().static_pub, trusted);
    pins.save(&owner.paths).unwrap();
}
async fn closed(channel: &mut SecureChannel) {
    let result = tokio::time::timeout(Duration::from_secs(2), channel.rx.recv())
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_pin_collisions_and_no_tofu() {
    let relay = start_relay().await;
    let mut owner = enroll_started(&relay, "owner").await;
    let mut peer = enroll_started(&relay, "peer").await;
    let handler = Arc::new(Handler::default());
    let key = peer.identity().static_pub;
    let register = || {
        owner
            .d()
            .inner
            .register_private_service(49100, "peer", key, handler.clone())
    };
    assert!(register().await.is_err());
    pin_peer(&owner, &peer, false);
    assert!(register().await.is_err(), "TOFU is insufficient");
    pin_peer(&owner, &peer, true);
    assert!(owner
        .d()
        .inner
        .register_private_service(49100, "peer", [9; 32], handler.clone())
        .await
        .is_err());
    owner
        .ctl_ok(ControlRequest::ShareSet {
            port: 49100,
            to: None,
        })
        .await;
    assert!(register().await.is_err());
    owner
        .ctl_ok(ControlRequest::ShareRemove { port: 49100 })
        .await;
    owner
        .ctl_ok(ControlRequest::Publish {
            port: 49100,
            name: "existing-service".into(),
            replace: false,
            allow: vec![],
        })
        .await;
    assert!(
        register().await.is_err(),
        "a previously published TCP port cannot become a service"
    );
    owner
        .ctl_ok(ControlRequest::Unpublish {
            name: "existing-service".into(),
        })
        .await;
    let reg = register().await.unwrap();
    assert!(register().await.is_err());
    assert!(
        !owner
            .ctl(ControlRequest::ShareSet {
                port: 49100,
                to: None
            })
            .await
            .ok
    );
    assert!(
        !owner
            .ctl(ControlRequest::Publish {
                port: 49100,
                name: "service".into(),
                replace: false,
                allow: vec![]
            })
            .await
            .ok
    );
    owner.d().inner.revoke_private_service(&reg).await.unwrap();
    assert!(
        !owner
            .ctl(ControlRequest::ShareSet {
                port: 49100,
                to: None
            })
            .await
            .ok,
        "revoked port stays reserved"
    );
    assert!(peer.d().inner.open_private("owner", 49100).await.is_err());
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    peer.stop().await;
    owner.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_identity_generation_revoke_and_changed_pin() {
    let relay = start_relay().await;
    let mut owner = enroll_started(&relay, "owner").await;
    let mut peer = enroll_started(&relay, "peer").await;
    let mut stranger = enroll_started(&relay, "stranger").await;
    pin_peer(&owner, &peer, true);
    pin_peer(&peer, &owner, true);
    pin_peer(&owner, &stranger, true);
    let handler = Arc::new(Handler::default());
    let reg = owner
        .d()
        .inner
        .register_private_service(49101, "peer", peer.identity().static_pub, handler.clone())
        .await
        .unwrap();
    assert!(stranger
        .d()
        .inner
        .open_private("owner", 49101)
        .await
        .is_err());
    let mut channel = peer.d().inner.open_private("owner", 49101).await.unwrap();
    channel.tx.send(b"service-private-body").await.unwrap();
    assert_eq!(
        channel.rx.recv().await.unwrap().unwrap(),
        b"service-private-body"
    );
    assert_eq!(
        handler.seen.lock().unwrap()[0],
        ("peer".into(), peer.identity().static_pub, reg.generation())
    );
    owner.d().inner.revoke_private_service(&reg).await.unwrap();
    assert_eq!(
        handler.active.load(Ordering::SeqCst),
        0,
        "revoke returns after handler drop"
    );
    closed(&mut channel).await;
    let replacement = owner
        .d()
        .inner
        .register_private_service(49101, "peer", peer.identity().static_pub, handler.clone())
        .await
        .unwrap();
    assert_ne!(reg.generation(), replacement.generation());
    assert!(
        owner.d().inner.revoke_private_service(&reg).await.is_err(),
        "stale revoke must not revoke replacement"
    );
    let mut channel = peer.d().inner.open_private("owner", 49101).await.unwrap();
    channel.tx.send(b"second").await.unwrap();
    assert_eq!(channel.rx.recv().await.unwrap().unwrap(), b"second");
    let mut pins = KnownPeers::load(&owner.paths).unwrap();
    pins.pin("peer", &[7; 32], true);
    pins.save(&owner.paths).unwrap();
    closed(&mut channel).await;
    assert_eq!(handler.active.load(Ordering::SeqCst), 0);
    pin_peer(&owner, &peer, true);
    assert!(
        peer.d().inner.open_private("owner", 49101).await.is_err(),
        "pin repair must not resurrect revoked generation"
    );
    let wire: Vec<u8> = relay
        .captures
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, b)| b.iter().copied())
        .collect();
    assert!(!wire
        .windows(b"service-private-body".len())
        .any(|w| w == b"service-private-body"));
    stranger.stop().await;
    peer.stop().await;
    owner.stop().await;
}

async fn raw_open(raw: &mut RawNode, id: u32, port: u16) {
    raw.send(Frame::new(
        FrameType::Open,
        id,
        OpenPayload {
            port,
            dest: "owner".into(),
            ..Default::default()
        }
        .encode(),
    ))
    .await;
    let reply = raw.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!(reply.ty, FrameType::OpenOk);
}
fn message1(
    peer: &TestNode,
    owner: &TestNode,
    src: &str,
    dest: &str,
    port: u16,
    share: Option<String>,
    key: Option<warren::crypto::Identity>,
) -> Vec<u8> {
    let identity = key.unwrap_or_else(|| peer.identity());
    let ownerkey = owner.identity().static_pub;
    let mut hs = snow::Builder::new(warren::crypto::NOISE_PARAMS.parse().unwrap())
        .local_private_key(&identity.static_secret)
        .unwrap()
        .remote_public_key(&ownerkey)
        .unwrap()
        .prologue(warren::crypto::NOISE_PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap();
    let hello = warren::noise::Hello {
        v: 1,
        src: src.into(),
        dest: dest.into(),
        port,
        share,
    };
    let mut out = vec![0; MAX_PAYLOAD];
    let n = hs
        .write_message(&serde_json::to_vec(&hello).unwrap(), &mut out)
        .unwrap();
    out.truncate(n);
    out
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_confirmation_replay_wrong_hello_key_and_pending_revoke() {
    let relay = start_relay().await;
    let peer = enroll(&relay, "peer").await;
    let mut owner = enroll_started(&relay, "owner").await;
    pin_peer(&owner, &peer, true);
    let handler = Arc::new(Handler::default());
    let reg = owner
        .d()
        .inner
        .register_private_service(49102, "peer", peer.identity().static_pub, handler.clone())
        .await
        .unwrap();
    let mut raw = RawNode::connect(&relay, &peer).await;
    for (i, (src, dest, port, share, key)) in [
        ("wrong", "owner", 49102, None, None),
        ("peer", "wrong", 49102, None, None),
        ("peer", "owner", 49103, None, None),
        ("peer", "owner", 49102, Some("gateway".into()), None),
        (
            "peer",
            "owner",
            49102,
            None,
            Some(warren::crypto::Identity::generate()),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let id = 2 * i as u32 + 1;
        raw_open(&mut raw, id, 49102).await;
        raw.send(Frame::new(
            FrameType::Data,
            id,
            message1(&peer, &owner, src, dest, port, share, key),
        ))
        .await;
        // A rejection can include a WINDOW credit before the final CLOSE.
        loop {
            let f = raw.next(Duration::from_secs(2)).await.unwrap();
            if f.ty == FrameType::Close {
                break;
            }
            assert_ne!(f.ty, FrameType::Data);
        }
    }
    let first = message1(&peer, &owner, "peer", "owner", 49102, None, None);
    for id in [21, 23] {
        raw_open(&mut raw, id, 49102).await;
        raw.send(Frame::new(FrameType::Data, id, first.clone()))
            .await;
        loop {
            let f = raw.next(Duration::from_secs(2)).await.unwrap();
            if f.ty == FrameType::Data {
                break;
            }
        }
    }
    assert_eq!(
        handler.calls.load(Ordering::SeqCst),
        0,
        "message1 or its replay must not dispatch"
    );
    owner.d().inner.revoke_private_service(&reg).await.unwrap();
    let mut closes = 0;
    while closes < 2 {
        if raw.next(Duration::from_secs(2)).await.unwrap().ty == FrameType::Close {
            closes += 1;
        }
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    owner.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoke_races_concurrent_admission_and_external_collision_fails_closed() {
    let relay = start_relay().await;
    let mut owner = enroll_started(&relay, "owner").await;
    let mut peer = enroll_started(&relay, "peer").await;
    pin_peer(&owner, &peer, true);
    pin_peer(&peer, &owner, true);
    let handler = Arc::new(Handler::default());
    let reg = owner
        .d()
        .inner
        .register_private_service(49104, "peer", peer.identity().static_pub, handler.clone())
        .await
        .unwrap();
    let mut established = peer.d().inner.open_private("owner", 49104).await.unwrap();
    established.tx.send(b"before-revoke").await.unwrap();
    assert_eq!(
        established.rx.recv().await.unwrap().unwrap(),
        b"before-revoke"
    );
    let mut opens = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let client = peer.d().inner.clone();
        opens.spawn(async move { client.open_private("owner", 49104).await });
    }
    owner.d().inner.revoke_private_service(&reg).await.unwrap();
    let calls_after_ack = handler.calls.load(Ordering::SeqCst);
    assert_eq!(handler.active.load(Ordering::SeqCst), 0);
    closed(&mut established).await;
    while let Some(result) = opens.join_next().await {
        if let Ok(mut stream) = result.unwrap() {
            closed(&mut stream).await;
        }
    }
    assert_eq!(handler.calls.load(Ordering::SeqCst), calls_after_ack);
    let reg = owner
        .d()
        .inner
        .register_private_service(49104, "peer", peer.identity().static_pub, handler.clone())
        .await
        .unwrap();
    let mut active = peer.d().inner.open_private("owner", 49104).await.unwrap();
    active.tx.send(b"before-collision").await.unwrap();
    assert_eq!(
        active.rx.recv().await.unwrap().unwrap(),
        b"before-collision"
    );
    let mut shares = warren::node::SharesFile::load(&owner.paths).unwrap();
    shares.set(49104, None);
    shares.save(&owner.paths).unwrap();
    closed(&mut active).await;
    assert!(peer.d().inner.open_private("owner", 49104).await.is_err());
    shares.remove(49104);
    shares.save(&owner.paths).unwrap();
    assert!(
        peer.d().inner.open_private("owner", 49104).await.is_err(),
        "external repair cannot resurrect grant"
    );
    owner.d().inner.revoke_private_service(&reg).await.unwrap();
    peer.stop().await;
    owner.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reserved_ports_and_pending_operations_are_bounded() {
    let relay = start_relay().await;
    let peer = enroll(&relay, "peer").await;
    let mut owner = enroll_started(&relay, "owner").await;
    pin_peer(&owner, &peer, true);
    let handler = Arc::new(Handler::default());
    let mut grants = Vec::new();
    for port in 50000..50064 {
        grants.push(
            owner
                .d()
                .inner
                .register_private_service(port, "peer", peer.identity().static_pub, handler.clone())
                .await
                .unwrap(),
        );
    }
    assert!(owner
        .d()
        .inner
        .register_private_service(50064, "peer", peer.identity().static_pub, handler.clone())
        .await
        .is_err());
    let mut raw = RawNode::connect(&relay, &peer).await;
    for i in 0..32 {
        raw_open(&mut raw, 2 * i + 1, 50000).await;
    }
    raw.send(Frame::new(
        FrameType::Open,
        65,
        OpenPayload {
            port: 50000,
            dest: "owner".into(),
            ..Default::default()
        }
        .encode(),
    ))
    .await;
    let refused = raw.next(Duration::from_secs(2)).await.unwrap();
    assert_eq!(refused.ty, FrameType::OpenErr);
    assert_eq!(refused.open_error().0, ErrorCode::TooManyStreams);
    owner
        .d()
        .inner
        .revoke_private_service(&grants[0])
        .await
        .unwrap();
    assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
    assert!(
        owner
            .d()
            .inner
            .register_private_service(50064, "peer", peer.identity().static_pub, handler.clone())
            .await
            .is_err(),
        "tombstones retain lifetime bound"
    );
    owner
        .d()
        .inner
        .register_private_service(50000, "peer", peer.identity().static_pub, handler)
        .await
        .unwrap();
    owner.stop().await;
}

struct PanickingHandler;
impl PrivateServiceHandler for PanickingHandler {
    fn handle<'a>(
        &'a self,
        context: &'a ServiceContext,
        _: &'a mut SecureChannel,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let _ = context.with_authorization(|| panic!("synthetic handler failure"));
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_commit_panic_fails_closed_without_breaking_revoke() {
    let relay = start_relay().await;
    let mut owner = enroll_started(&relay, "owner").await;
    let mut peer = enroll_started(&relay, "peer").await;
    pin_peer(&owner, &peer, true);
    pin_peer(&peer, &owner, true);
    let reg = owner
        .d()
        .inner
        .register_private_service(
            49105,
            "peer",
            peer.identity().static_pub,
            Arc::new(PanickingHandler),
        )
        .await
        .unwrap();
    if let Ok(mut channel) = peer.d().inner.open_private("owner", 49105).await {
        closed(&mut channel).await;
    }
    owner.d().inner.revoke_private_service(&reg).await.unwrap();
    assert!(owner
        .d()
        .inner
        .register_private_service(
            49105,
            "peer",
            peer.identity().static_pub,
            Arc::new(Handler::default())
        )
        .await
        .is_err());
    peer.stop().await;
    owner.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_shutdown_drains_service_and_rejects_registration() {
    let relay = start_relay().await;
    let mut owner = enroll_started(&relay, "owner").await;
    let mut peer = enroll_started(&relay, "peer").await;
    pin_peer(&owner, &peer, true);
    pin_peer(&peer, &owner, true);
    let handler = Arc::new(Handler::default());
    let daemon = owner.d().inner.clone();
    daemon
        .register_private_service(49106, "peer", peer.identity().static_pub, handler.clone())
        .await
        .unwrap();
    let mut stream = peer.d().inner.open_private("owner", 49106).await.unwrap();
    stream.tx.send(b"active-before-stop").await.unwrap();
    assert_eq!(
        stream.rx.recv().await.unwrap().unwrap(),
        b"active-before-stop"
    );
    owner.stop().await;
    assert_eq!(handler.active.load(Ordering::SeqCst), 0);
    closed(&mut stream).await;
    assert!(daemon
        .register_private_service(49106, "peer", peer.identity().static_pub, handler)
        .await
        .is_err());
    peer.stop().await;
}
