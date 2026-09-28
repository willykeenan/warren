#![cfg(any(target_os = "macos", target_os = "linux"))]
mod common;
use common::*;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, Mutex};
use warren::{
    device_enrollment::{Approval, Clock, Credential, EnrollmentBroker, EnrollmentError, Time},
    node::{
        private_service::{PrivateServiceHandler, ServiceContext, ServiceRegistration},
        KnownPeers,
    },
    noise::SecureChannel,
};

type Result<T> = std::result::Result<T, EnrollmentError>;
#[derive(Default)]
struct FakeClock {
    wall: AtomicI64,
    mono: AtomicU64,
}
impl FakeClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wall: AtomicI64::new(2_000_000_000),
            mono: AtomicU64::new(0),
        })
    }
    fn advance(&self, n: u64) {
        self.wall.fetch_add(n as i64, Ordering::SeqCst);
        self.mono.fetch_add(n, Ordering::SeqCst);
    }
}
impl Clock for FakeClock {
    fn now(&self) -> Result<Time> {
        Ok(Time {
            wall_seconds: self.wall.load(Ordering::SeqCst),
            monotonic: Duration::from_secs(self.mono.load(Ordering::SeqCst)),
        })
    }
}
enum Command {
    ConcurrentRedeem(
        [u8; 16],
        [u8; 32],
        Arc<tokio::sync::Barrier>,
        oneshot::Sender<Result<Credential>>,
    ),
    Approve(ServiceRegistration, u64, oneshot::Sender<Result<Approval>>),
    Redeem([u8; 16], [u8; 32], oneshot::Sender<Result<Credential>>),
    Manage([u8; 16], [u8; 32], oneshot::Sender<Result<u64>>),
}
struct Handler {
    broker: Arc<EnrollmentBroker>,
    commands: Mutex<mpsc::Receiver<Command>>,
    changes: AtomicU64,
}
impl PrivateServiceHandler for Handler {
    fn handle<'a>(
        &'a self,
        context: &'a ServiceContext,
        _stream: &'a mut SecureChannel,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            loop {
                let command = self.commands.lock().await.recv().await;
                match command {
                    Some(Command::ConcurrentRedeem(id, secret, barrier, reply)) => {
                        barrier.wait().await;
                        let _ = reply.send(self.broker.redeem(context, &id, &secret));
                    }
                    Some(Command::Approve(reg, ttl, reply)) => {
                        let _ = reply.send(self.broker.approve(
                            context,
                            &reg,
                            Duration::from_secs(ttl),
                        ));
                    }
                    Some(Command::Redeem(id, secret, reply)) => {
                        let _ = reply.send(self.broker.redeem(context, &id, &secret));
                    }
                    Some(Command::Manage(id, token, reply)) => {
                        let _ =
                            reply.send(self.broker.with_management(context, &id, &token, || {
                                self.changes.fetch_add(1, Ordering::SeqCst) + 1
                            }));
                    }
                    None => break,
                }
            }
        })
    }
}
struct Fixture {
    relay: TestRelay,
    owner: TestNode,
    peer: TestNode,
    directory: tempfile::TempDir,
    clock: Arc<FakeClock>,
    broker: Arc<EnrollmentBroker>,
    bootstrap: ServiceRegistration,
    management: ServiceRegistration,
    boot: mpsc::Sender<Command>,
    manage: mpsc::Sender<Command>,
    _boot_stream: SecureChannel,
    _manage_stream: SecureChannel,
}
fn pin_peer(owner: &TestNode, peer: &TestNode) {
    let mut pins = KnownPeers::load(&owner.paths).unwrap();
    pins.pin(&peer.name, &peer.identity().static_pub, true);
    pins.save(&owner.paths).unwrap();
}
fn state_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
impl Fixture {
    async fn new() -> Self {
        let relay = start_relay().await;
        let owner = enroll_started(&relay, "owner").await;
        let peer = enroll_started(&relay, "peer").await;
        pin_peer(&owner, &peer);
        pin_peer(&peer, &owner);
        let directory = state_dir();
        let clock = FakeClock::new();
        let broker =
            Arc::new(EnrollmentBroker::open_with_clock(directory.path(), clock.clone()).unwrap());
        let (boot, brx) = mpsc::channel(16);
        let (manage, mrx) = mpsc::channel(16);
        let handler = |commands| {
            Arc::new(Handler {
                broker: broker.clone(),
                commands: Mutex::new(commands),
                changes: AtomicU64::new(0),
            })
        };
        let bootstrap = owner
            .d()
            .inner
            .register_private_service(49100, "peer", peer.identity().static_pub, handler(brx))
            .await
            .unwrap();
        let management = owner
            .d()
            .inner
            .register_private_service(49101, "peer", peer.identity().static_pub, handler(mrx))
            .await
            .unwrap();
        let boot_stream = peer.d().inner.open_private("owner", 49100).await.unwrap();
        let manage_stream = peer.d().inner.open_private("owner", 49101).await.unwrap();
        Self {
            relay,
            owner,
            peer,
            directory,
            clock,
            broker,
            bootstrap,
            management,
            boot,
            manage,
            _boot_stream: boot_stream,
            _manage_stream: manage_stream,
        }
    }
    async fn approve(&self, ttl: u64) -> Result<Approval> {
        let (tx, rx) = oneshot::channel();
        assert!(self
            .boot
            .send(Command::Approve(self.management.clone(), ttl, tx))
            .await
            .is_ok());
        rx.await.unwrap()
    }
    async fn redeem(&self, approval: &Approval) -> Result<Credential> {
        let (tx, rx) = oneshot::channel();
        assert!(self
            .boot
            .send(Command::Redeem(approval.id(), *approval.secret(), tx))
            .await
            .is_ok());
        rx.await.unwrap()
    }
    async fn access(&self, credential: &Credential) -> Result<u64> {
        let (tx, rx) = oneshot::channel();
        assert!(self
            .manage
            .send(Command::Manage(credential.id(), *credential.token(), tx))
            .await
            .is_ok());
        rx.await.unwrap()
    }
    async fn stop(mut self) {
        self.peer.stop().await;
        self.owner.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confirmed_context_single_consume_management_and_revoke() {
    let f = Fixture::new().await;
    let approval = f.approve(120).await.unwrap();
    assert!(matches!(
        f.approve(120).await,
        Err(EnrollmentError::Changed)
    ));
    // Owner-only test control carries QR material locally, never on the wire.
    let mut extra_streams = Vec::new();
    for _ in 0..7 {
        extra_streams.push(f.peer.d().inner.open_private("owner", 49100).await.unwrap());
    }
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut receivers = Vec::new();
    for _ in 0..8 {
        let (tx, rx) = oneshot::channel();
        assert!(f
            .boot
            .send(Command::ConcurrentRedeem(
                approval.id(),
                *approval.secret(),
                barrier.clone(),
                tx
            ))
            .await
            .is_ok());
        receivers.push(rx);
    }
    let mut issued = Vec::new();
    for rx in receivers {
        match rx.await.unwrap() {
            Ok(c) => issued.push(c),
            Err(e) => assert_eq!(e, EnrollmentError::Consumed),
        }
    }
    assert_eq!(issued.len(), 1);
    let credential = issued.pop().unwrap();
    assert_eq!(f.access(&credential).await.unwrap(), 1);
    let persisted = std::fs::read(f.directory.path().join("enrollment.sqlite3")).unwrap();
    for secret in [approval.secret(), credential.token()] {
        assert!(!persisted.windows(32).any(|w| w == secret));
        assert!(!String::from_utf8_lossy(&persisted).contains(&hex::encode(secret)));
        for wire in f.relay.captured_bytes() {
            assert!(!wire.windows(32).any(|w| w == secret));
        }
    }
    f.broker
        .revoke_management(&f.owner.d().inner)
        .await
        .unwrap();
    assert!(f
        .peer
        .d()
        .inner
        .open_private("owner", f.bootstrap.port())
        .await
        .is_err());
    assert!(f
        .peer
        .d()
        .inner
        .open_private("owner", f.management.port())
        .await
        .is_err());
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_context_secret_expiry_and_rollback_deny() {
    let f = Fixture::new().await;
    assert!(matches!(
        f.approve(121).await,
        Err(EnrollmentError::Invalid)
    ));
    let approval = f.approve(120).await.unwrap();
    let (tx, rx) = oneshot::channel();
    assert!(f
        .manage
        .send(Command::Redeem(approval.id(), *approval.secret(), tx))
        .await
        .is_ok());
    assert!(matches!(
        rx.await.unwrap(),
        Err(EnrollmentError::PeerNotApproved)
    ));
    let (tx, rx) = oneshot::channel();
    assert!(f
        .boot
        .send(Command::Redeem(approval.id(), [9; 32], tx))
        .await
        .is_ok());
    assert!(matches!(rx.await.unwrap(), Err(EnrollmentError::Invalid)));
    f.clock.advance(120);
    assert!(matches!(
        f.redeem(&approval).await,
        Err(EnrollmentError::Expired)
    ));
    let second = f.approve(120).await.unwrap();
    let credential = f.redeem(&second).await.unwrap();
    assert_eq!(f.access(&credential).await.unwrap(), 1);
    f.clock.wall.fetch_sub(1, Ordering::SeqCst);
    assert!(matches!(
        f.access(&credential).await,
        Err(EnrollmentError::Unavailable)
    ));
    f.clock.advance(2);
    assert!(
        matches!(
            f.access(&credential).await,
            Err(EnrollmentError::Unavailable)
        ),
        "rollback poisons despite clock repair"
    );
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_monotonic_expiry_and_wrong_peer_deny() {
    let f = Fixture::new().await;
    let approval = f.approve(120).await.unwrap();
    let credential = f.redeem(&approval).await.unwrap();
    let mut stranger = enroll_started(&f.relay, "stranger").await;
    pin_peer(&f.owner, &stranger);
    pin_peer(&stranger, &f.owner);
    let (tx, rx) = mpsc::channel(2);
    let h = Arc::new(Handler {
        broker: f.broker.clone(),
        commands: Mutex::new(rx),
        changes: AtomicU64::new(0),
    });
    f.owner
        .d()
        .inner
        .register_private_service(49102, "stranger", stranger.identity().static_pub, h)
        .await
        .unwrap();
    let _stream = stranger
        .d()
        .inner
        .open_private("owner", 49102)
        .await
        .unwrap();
    let (reply, result) = oneshot::channel();
    assert!(tx
        .send(Command::Manage(credential.id(), *credential.token(), reply))
        .await
        .is_ok());
    assert!(matches!(
        result.await.unwrap(),
        Err(EnrollmentError::PeerNotApproved)
    ));
    f.clock.mono.fetch_add(86400, Ordering::SeqCst);
    assert!(
        matches!(f.access(&credential).await, Err(EnrollmentError::Expired)),
        "monotonic expiry holds while wall stands still"
    );
    stranger.stop().await;
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_invalidates_pending_and_credentials_and_second_owner_denied() {
    let mut f = Fixture::new().await;
    let approval = f.approve(120).await.unwrap();
    assert!(EnrollmentBroker::open_with_clock(f.directory.path(), f.clock.clone()).is_err());
    f.peer.stop().await;
    f.owner.stop().await;
    let path = f.directory.path().to_owned();
    let clock = f.clock.clone();
    drop(f.broker);
    let broker = EnrollmentBroker::open_with_clock(&path, clock).unwrap();
    drop(broker);
    let raw = rusqlite::Connection::open(path.join("enrollment.sqlite3"))
        .unwrap()
        .query_row("SELECT payload FROM enrollment_state", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap();
    let state: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(state["pending"].is_null());
    assert!(state["active"].is_null());
    assert_eq!(
        state["consumed"][0],
        serde_json::to_value(approval.id()).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permission_failure_poison_prevents_consumption_and_repair_reuse() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new().await;
    let approval = f.approve(120).await.unwrap();
    let path = f.directory.path().join("enrollment.sqlite3");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        f.redeem(&approval).await,
        Err(EnrollmentError::Unavailable)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        f.redeem(&approval).await,
        Err(EnrollmentError::Unavailable)
    ));
    f.stop().await;
}

#[test]
fn private_state_symlink_hardlink_torn_state_and_clock_rollback_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let d = state_dir();
    let clock = FakeClock::new();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(EnrollmentBroker::open_with_clock(d.path(), clock.clone()).is_err());
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let broker = EnrollmentBroker::open_with_clock(d.path(), clock.clone()).unwrap();
    drop(broker);
    clock.wall.fetch_sub(1, Ordering::SeqCst);
    assert!(EnrollmentBroker::open_with_clock(d.path(), clock.clone()).is_err());
    clock.wall.fetch_add(1, Ordering::SeqCst);
    let path = d.path().join("enrollment.sqlite3");
    let second = d.path().join("alias");
    std::fs::hard_link(&path, &second).unwrap();
    assert!(EnrollmentBroker::open_with_clock(d.path(), clock.clone()).is_err());
    std::fs::remove_file(second).unwrap();
    let original = d.path().join("original");
    std::fs::rename(&path, &original).unwrap();
    symlink(&original, &path).unwrap();
    assert!(EnrollmentBroker::open_with_clock(d.path(), clock.clone()).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(original, &path).unwrap();
    std::fs::write(path, b"torn sqlite state").unwrap();
    assert!(EnrollmentBroker::open_with_clock(d.path(), clock).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_rotation_rejects_old_credential_on_replacement_stream() {
    let mut f = Fixture::new().await;
    let first = f.approve(120).await.unwrap();
    let old = f.redeem(&first).await.unwrap();
    assert_eq!(f.access(&old).await.unwrap(), 1);
    f.broker
        .revoke_management(&f.owner.d().inner)
        .await
        .unwrap();
    // Both existing streams must be closed when the owner receives success.
    for stream in [&mut f._boot_stream, &mut f._manage_stream] {
        let result = tokio::time::timeout(Duration::from_secs(1), stream.rx.recv())
            .await
            .unwrap();
        assert!(matches!(result, Ok(None) | Err(_)));
    }
    let (boot, brx) = mpsc::channel(4);
    let (manage, mrx) = mpsc::channel(4);
    let handler = |commands| {
        Arc::new(Handler {
            broker: f.broker.clone(),
            commands: Mutex::new(commands),
            changes: AtomicU64::new(0),
        })
    };
    let bootstrap = f
        .owner
        .d()
        .inner
        .register_private_service(49100, "peer", f.peer.identity().static_pub, handler(brx))
        .await
        .unwrap();
    let management = f
        .owner
        .d()
        .inner
        .register_private_service(49101, "peer", f.peer.identity().static_pub, handler(mrx))
        .await
        .unwrap();
    assert_ne!(bootstrap.generation(), f.bootstrap.generation());
    assert_ne!(management.generation(), f.management.generation());
    let _bootstrap_stream = f.peer.d().inner.open_private("owner", 49100).await.unwrap();
    let _management_stream = f.peer.d().inner.open_private("owner", 49101).await.unwrap();
    let (reply, response) = oneshot::channel();
    assert!(boot
        .send(Command::Approve(management, 120, reply))
        .await
        .is_ok());
    let next = response.await.unwrap().unwrap();
    let (reply, response) = oneshot::channel();
    assert!(boot
        .send(Command::Redeem(next.id(), *next.secret(), reply))
        .await
        .is_ok());
    let new = response.await.unwrap().unwrap();
    let (reply, response) = oneshot::channel();
    assert!(manage
        .send(Command::Manage(old.id(), *old.token(), reply))
        .await
        .is_ok());
    assert!(matches!(
        response.await.unwrap(),
        Err(EnrollmentError::Invalid)
    ));
    let (reply, response) = oneshot::channel();
    assert!(manage
        .send(Command::Manage(new.id(), *new.token(), reply))
        .await
        .is_ok());
    assert_eq!(response.await.unwrap().unwrap(), 1);
    let (reply, response) = oneshot::channel();
    assert!(boot
        .send(Command::Redeem(first.id(), *first.secret(), reply))
        .await
        .is_ok());
    assert!(matches!(
        response.await.unwrap(),
        Err(EnrollmentError::Consumed)
    ));
    f.stop().await;
}
