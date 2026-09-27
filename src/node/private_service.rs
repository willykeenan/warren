//! In-process services authorized by an explicit, immutable peer grant.
use super::{KnownPeers, NodePaths, PublishesFile, SharesFile};
use crate::{
    crypto,
    mux::{MuxReceiver, MuxSender},
    noise::{self, SecureChannel},
    proto::{ErrorCode, OpenPayload},
};
use anyhow::{bail, Result};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

const MAX_PORTS: usize = 64;
const MAX_OPERATIONS: usize = 32;
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// A trusted local handler. Its future must yield; it must not detach stream work.
/// The runtime retains ownership of the stream and drops it before revoke returns.
pub trait PrivateServiceHandler: Send + Sync {
    fn handle<'a>(
        &'a self,
        context: &'a ServiceContext,
        stream: &'a mut SecureChannel,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Opaque registration identity. A stale handle cannot revoke a replacement grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRegistration {
    port: u16,
    generation: [u8; 32],
}
impl ServiceRegistration {
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn generation(&self) -> [u8; 32] {
        self.generation
    }
}

/// Constructed only after the existing Noise fresh-confirmation check succeeds.
pub struct ServiceContext {
    runtime: Arc<PrivateServices>,
    registration: ServiceRegistration,
    peer: String,
    key: [u8; 32],
}
impl ServiceContext {
    pub fn peer_name(&self) -> &str {
        &self.peer
    }
    pub fn peer_static_key(&self) -> [u8; 32] {
        self.key
    }
    pub fn registration(&self) -> &ServiceRegistration {
        &self.registration
    }
    /// Linearize a short synchronous local commit against explicit revocation.
    /// Never block or call this runtime recursively inside `commit`.
    /// Async backends must provide their own generation-aware transaction boundary.
    pub fn with_authorization<T>(&self, commit: impl FnOnce() -> T) -> Result<T> {
        let state = self.runtime.lock();
        if !self.runtime.current(&state, &self.registration) {
            bail!("private service authorization is no longer current");
        }
        Ok(commit())
    }
}

#[derive(Clone)]
struct Grant {
    registration: ServiceRegistration,
    peer: String,
    key: [u8; 32],
    handler: Arc<dyn PrivateServiceHandler>,
}
struct Operation {
    registration: ServiceRegistration,
    cancel: CancellationToken,
    done: watch::Receiver<bool>,
}
#[derive(Default)]
struct State {
    // Tombstones prevent revoked service ports falling back to ordinary TCP shares.
    ports: BTreeMap<u16, Option<Grant>>,
    operations: BTreeMap<u64, Operation>,
    next: u64,
    stopped: bool,
}
pub(crate) struct PrivateServices {
    paths: NodePaths,
    identity: crypto::Identity,
    name: String,
    state: Mutex<State>,
    pub(crate) mutation: tokio::sync::Mutex<()>,
}
struct Finished {
    runtime: Arc<PrivateServices>,
    id: u64,
    done: watch::Sender<bool>,
}
impl Drop for Finished {
    fn drop(&mut self) {
        self.runtime.lock().operations.remove(&self.id);
        self.done.send_replace(true);
    }
}
impl PrivateServices {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                // A handler panic during its synchronous commit must fail closed,
                // including when Finished runs while that panic is unwinding.
                let mut state = poisoned.into_inner();
                state.stopped = true;
                for slot in state.ports.values_mut() {
                    *slot = None;
                }
                for operation in state.operations.values() {
                    operation.cancel.cancel();
                }
                state
            }
        }
    }
    pub(crate) fn new(paths: NodePaths, identity: crypto::Identity, name: String) -> Arc<Self> {
        Arc::new(Self {
            paths,
            identity,
            name,
            state: Mutex::new(State::default()),
            mutation: tokio::sync::Mutex::new(()),
        })
    }
    fn policy_allows(&self, grant: &Grant) -> bool {
        let Ok(pins) = KnownPeers::load(&self.paths) else {
            return false;
        };
        pins.peers
            .get(&grant.peer)
            .is_some_and(|p| p.trusted_at.is_some())
            && pins.pinned(&grant.peer) == Some(grant.key)
            && self.port_available(grant.registration.port).is_ok()
    }
    fn port_available(&self, port: u16) -> Result<()> {
        if SharesFile::load(&self.paths)?
            .shares
            .iter()
            .any(|s| s.port == port)
            || PublishesFile::load(&self.paths)?
                .publishes
                .iter()
                .any(|p| p.port == port)
        {
            bail!("private service port conflicts with a TCP share or public publish");
        }
        Ok(())
    }
    fn current(&self, state: &State, registration: &ServiceRegistration) -> bool {
        !state.stopped
            && state
                .ports
                .get(&registration.port)
                .and_then(Option::as_ref)
                .is_some_and(|g| g.registration == *registration && self.policy_allows(g))
    }
    pub(crate) fn reserved(&self, port: u16) -> bool {
        self.lock().ports.contains_key(&port)
    }
    /// Register only an explicitly trusted, previously pinned exact key.
    /// There is no TOFU, persistent grant, public listener, or implicit replacement.
    pub(crate) fn register(
        &self,
        port: u16,
        peer: &str,
        key: [u8; 32],
        handler: Arc<dyn PrivateServiceHandler>,
    ) -> Result<ServiceRegistration> {
        if port == 0 || !crate::valid_name(peer) {
            bail!("invalid private service selector");
        }
        let registration = ServiceRegistration {
            port,
            generation: crypto::random32(),
        };
        let grant = Grant {
            registration: registration.clone(),
            peer: peer.into(),
            key,
            handler,
        };
        if !self.policy_allows(&grant) {
            bail!(
                "service requires a nonconflicting port and an explicitly trusted exact peer key"
            );
        }
        let mut state = self.lock();
        if state.stopped
            || state.ports.get(&port).is_some_and(Option::is_some)
            || (!state.ports.contains_key(&port) && state.ports.len() >= MAX_PORTS)
            || state
                .operations
                .values()
                .any(|op| op.registration.port == port)
        {
            bail!("private service unavailable, already registered, or still draining");
        }
        state.ports.insert(port, Some(grant));
        Ok(registration)
    }
    /// Cancel pending handshakes and active handlers, then wait for stream drop.
    pub(crate) async fn revoke(&self, registration: &ServiceRegistration) -> Result<()> {
        // Do not wait behind an unrelated public publish's relay response.
        // State admission is atomic; register refuses a port while old operations drain.
        let waits = {
            let mut state = self.lock();
            let Some(slot) = state.ports.get_mut(&registration.port) else {
                bail!("unknown service registration");
            };
            if slot
                .as_ref()
                .is_some_and(|g| g.registration != *registration)
            {
                bail!("stale service registration");
            }
            *slot = None;
            Self::cancel(&state, Some(registration))
        };
        Self::drain(waits).await;
        Ok(())
    }
    fn cancel(
        state: &State,
        registration: Option<&ServiceRegistration>,
    ) -> Vec<watch::Receiver<bool>> {
        state
            .operations
            .values()
            .filter(|op| registration.is_none_or(|r| op.registration == *r))
            .map(|op| {
                op.cancel.cancel();
                op.done.clone()
            })
            .collect()
    }
    async fn drain(waits: Vec<watch::Receiver<bool>>) {
        for mut done in waits {
            while !*done.borrow_and_update() {
                if done.changed().await.is_err() {
                    break;
                }
            }
        }
    }
    pub(crate) async fn watch(self: Arc<Self>, stop: CancellationToken) {
        loop {
            tokio::select! { biased;
                _ = stop.cancelled() => {
                    let waits = { let mut s = self.lock(); s.stopped = true; for g in s.ports.values_mut() { *g = None; } Self::cancel(&s, None) };
                    Self::drain(waits).await; return;
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            let waits = {
                let mut s = self.lock();
                let invalid: Vec<_> = s
                    .ports
                    .values()
                    .flatten()
                    .filter(|g| !self.policy_allows(g))
                    .map(|g| g.registration.clone())
                    .collect();
                let mut waits = Vec::new();
                for r in invalid {
                    s.ports.insert(r.port, None);
                    waits.extend(Self::cancel(&s, Some(&r)));
                }
                waits
            };
            Self::drain(waits).await;
        }
    }
    pub(crate) fn spawn(self: &Arc<Self>, p: OpenPayload, tx: MuxSender, rx: MuxReceiver) {
        let (done, recv) = watch::channel(false);
        let cancel = CancellationToken::new();
        let (id, grant) = {
            let mut state = self.lock();
            let Some(grant) = state.ports.get(&p.port).and_then(Option::as_ref).cloned() else {
                tx.reject(ErrorCode::Forbidden, "private service unavailable");
                return;
            };
            if p.flags != 0
                || p.dest != self.name
                || p.src != grant.peer
                || p.src_static != Some(grant.key)
                || !self.current(&state, &grant.registration)
            {
                tx.reject(ErrorCode::Forbidden, "private service not authorized");
                return;
            }
            if state.operations.len() >= MAX_OPERATIONS {
                tx.reject(ErrorCode::TooManyStreams, "private service busy");
                return;
            }
            state.next += 1;
            let id = state.next;
            state.operations.insert(
                id,
                Operation {
                    registration: grant.registration.clone(),
                    cancel: cancel.clone(),
                    done: recv,
                },
            );
            (id, grant)
        };
        let runtime = self.clone();
        tokio::spawn(async move {
            let _finished = Finished {
                runtime: runtime.clone(),
                id,
                done,
            };
            tokio::select! { biased;
                _ = cancel.cancelled() => {},
                _ = tokio::time::timeout(OPERATION_TIMEOUT, runtime.incoming(p, tx, rx, grant)) => {}
            }
        });
    }
    async fn incoming(
        self: &Arc<Self>,
        p: OpenPayload,
        tx: MuxSender,
        rx: MuxReceiver,
        grant: Grant,
    ) {
        if !tx.accept() {
            return;
        }
        let Ok(responder) = noise::respond(tx, rx, &self.identity).await else {
            return;
        };
        let hello = &responder.hello;
        if responder.remote_static != grant.key
            || hello.v != 1
            || hello.src != grant.peer
            || hello.dest != self.name
            || hello.port != p.port
            || hello.share.is_some()
        {
            responder.refuse(ErrorCode::Forbidden);
            return;
        }
        let Ok(confirmed) = responder.complete().await else {
            return;
        };
        if !self.current(&self.lock(), &grant.registration) {
            confirmed.refuse(ErrorCode::Forbidden).await;
            return;
        }
        let Ok(mut stream) = confirmed.accept().await else {
            return;
        };
        let context = ServiceContext {
            runtime: self.clone(),
            registration: grant.registration,
            peer: grant.peer,
            key: grant.key,
        };
        if context.with_authorization(|| ()).is_err() {
            return;
        }
        grant.handler.handle(&context, &mut stream).await;
    }
}
