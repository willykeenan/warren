//! The node daemon (`warren up`): one persistent WebSocket to the relay with
//! jittered reconnect, destination-side share enforcement, Noise-encrypted
//! private streams, forwards, publishes and the local control socket.

use super::control::{self, ControlRequest, ControlResponse};
use super::{
    Forward, ForwardsFile, IdentityFile, KnownPeers, NodePaths, PinCheck, Publish, PublishesFile,
    ShareDecision, SharesFile,
};
use crate::crypto::{self, Identity};
use crate::limits::{TokenBucket, NODE_OPENS_PER_SEC, NODE_OPEN_BURST};
use crate::mux::{self, LinkOut, MuxReceiver, MuxSender, Slot, StreamHost};
use crate::net::{self, RelayUrl};
use crate::noise::{self, Hello, SecureChannel};
use crate::proto::*;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::{oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

/// How long local connections wait for the relay connection to come back.
const SESSION_WAIT: Duration = Duration::from_secs(10);
/// Number of recent errors kept for `warren status`.
const MAX_ERRORS: usize = 20;

/// Daemon settings.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub paths: NodePaths,
    pub ping_interval: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl DaemonConfig {
    pub fn new(paths: NodePaths) -> DaemonConfig {
        DaemonConfig {
            paths,
            ping_interval: Duration::from_secs(15),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
        }
    }
}

/// Jittered exponential backoff: attempt 0 waits 0.5–1 x `min`, doubling up to `max`.
pub fn backoff_delay(attempt: u32, min: Duration, max: Duration) -> Duration {
    let base = min
        .saturating_mul(1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX))
        .min(max);
    let ms = base.as_millis() as u64;
    let jittered = rand::thread_rng().gen_range(ms / 2..=ms.max(1));
    Duration::from_millis(jittered)
}

/// Why opening a private stream failed.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("not connected to the relay")]
    NotConnected,
    #[error("{node}: {message} ({code})")]
    Refused {
        code: ErrorCode,
        node: String,
        message: String,
    },
    #[error("the key of {name} changed (pinned {pinned}, relay now reports {current}); if this is expected, check the fingerprint on {name} itself (`warren status` there) and run `warren trust {name} --expect {current}`")]
    KeyChanged {
        name: String,
        pinned: String,
        current: String,
    },
    #[error("no node named {0:?} on this relay")]
    NoSuchNode(String),
    #[error("secure handshake with {0} failed: {1}")]
    Handshake(String, String),
    #[error("{0}")]
    Other(String),
}

impl OpenError {
    pub fn code(&self) -> String {
        match self {
            OpenError::NotConnected => "not_connected".into(),
            OpenError::Refused { code, .. } => code.name().into(),
            OpenError::KeyChanged { .. } => "key_changed".into(),
            OpenError::NoSuchNode(_) => "no_such_node".into(),
            OpenError::Handshake(..) => "handshake_failed".into(),
            OpenError::Other(_) => "error".into(),
        }
    }
}

/// A control request to the relay failed.
#[derive(Debug, Clone)]
pub struct CtrlFailure {
    pub code: String,
    pub message: String,
}

impl CtrlFailure {
    fn new(code: &str, message: &str) -> CtrlFailure {
        CtrlFailure {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// A short random delay before retrying a rate-limited request.
fn retry_jitter(min_ms: u64, max_ms: u64) -> Duration {
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

/// One live relay connection.
pub struct Session {
    out: LinkOut,
    table: Mutex<HashMap<u32, Slot>>,
    next_odd: AtomicU32,
    ctrl_id: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<CtrlResponse>>>,
    pings: Mutex<HashMap<u64, Instant>>,
    last_pong: Mutex<Instant>,
    /// Paces our own stream opens under the relay's per-node limit.
    opens: Mutex<TokenBucket>,
    pub publish_domain: String,
    pub connected_at: i64,
}

impl StreamHost for Session {
    fn out(&self) -> &LinkOut {
        &self.out
    }
    fn remove_stream(&self, id: u32) {
        self.table.lock().unwrap().remove(&id);
    }
}

impl Session {
    pub fn stream_count(&self) -> usize {
        self.table.lock().unwrap().len()
    }

    /// Send a control request to the relay and wait for its answer. A
    /// request the relay refused as rate limited was not carried out, so it
    /// is retried for up to 10 s (`SESSION_WAIT`).
    pub async fn ctrl(&self, op: CtrlOp) -> Result<Value, CtrlFailure> {
        let deadline = Instant::now() + SESSION_WAIT;
        loop {
            match self.ctrl_once(op.clone()).await {
                Err(f) if f.code == "rate_limited" && Instant::now() < deadline => {
                    tokio::time::sleep(retry_jitter(50, 150)).await;
                }
                r => return r,
            }
        }
    }

    async fn ctrl_once(&self, op: CtrlOp) -> Result<Value, CtrlFailure> {
        let id = self.ctrl_id.fetch_add(1, Ordering::Relaxed);
        let Ok(frame) = Frame::ctrl(&CtrlRequest { id, op }) else {
            return Err(CtrlFailure::new("too_large", "control request too large"));
        };
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        if !self.out.send(frame) {
            self.pending.lock().unwrap().remove(&id);
            return Err(CtrlFailure::new("not_connected", "relay connection closed"));
        }
        match tokio::time::timeout(Duration::from_secs(15), rx).await {
            Ok(Ok(r)) if r.ok => Ok(r.result),
            // The relay's words are shown to the user: make them safe.
            Ok(Ok(r)) => Err(CtrlFailure {
                code: crate::sanitize_remote_code(r.code.as_deref().unwrap_or("error")),
                message: crate::sanitize_remote_text(r.error.as_deref().unwrap_or_default()),
            }),
            Ok(Err(_)) => Err(CtrlFailure::new("not_connected", "relay connection closed")),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(CtrlFailure::new("timeout", "relay did not answer"))
            }
        }
    }

    pub async fn lookup(&self, name: &str) -> Result<DeviceInfo, CtrlFailure> {
        let v = self
            .ctrl(CtrlOp::Lookup {
                name: name.to_string(),
            })
            .await?;
        serde_json::from_value(v).map_err(|_| CtrlFailure {
            code: "protocol".into(),
            message: "malformed lookup reply".into(),
        })
    }

    /// Wait for a token of our own open-rate bucket.
    async fn pace_open(&self) {
        loop {
            let wait = match self.opens.lock().unwrap().take_or_wait() {
                Ok(()) => return,
                Err(w) => w,
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// Open a stream to `dest:port` through the relay. Opens are paced under
    /// the relay's per-node rate, and an open the relay still refused as rate
    /// limited is retried for up to 10 s (`SESSION_WAIT`), so a burst of local
    /// connections is delayed rather than dropped.
    pub async fn open(
        self: &Arc<Self>,
        dest: &str,
        port: u16,
    ) -> Result<(MuxSender, MuxReceiver), (ErrorCode, String)> {
        let deadline = Instant::now() + SESSION_WAIT;
        loop {
            self.pace_open().await;
            match self.open_once(dest, port).await {
                Err((ErrorCode::RateLimited, _)) if Instant::now() < deadline => {
                    tokio::time::sleep(retry_jitter(20, 80)).await;
                }
                r => return r,
            }
        }
    }

    async fn open_once(
        self: &Arc<Self>,
        dest: &str,
        port: u16,
    ) -> Result<(MuxSender, MuxReceiver), (ErrorCode, String)> {
        let (tx, rx, reply, id) = {
            let mut t = self.table.lock().unwrap();
            if t.len() >= MAX_STREAMS_PER_NODE {
                return Err((
                    ErrorCode::TooManyStreams,
                    "too many streams on this node".into(),
                ));
            }
            let id = loop {
                let id = self.next_odd.fetch_add(2, Ordering::Relaxed);
                if !t.contains_key(&id) {
                    break id;
                }
            };
            let host: Arc<dyn StreamHost> = self.clone();
            let (slot, tx, rx, reply) = mux::new_stream(id, host, true);
            t.insert(id, slot);
            (tx, rx, reply.expect("outgoing"), id)
        };
        let p = OpenPayload {
            port,
            dest: dest.to_string(),
            ..Default::default()
        };
        if !self.out.send(Frame::new(FrameType::Open, id, p.encode())) {
            return Err((ErrorCode::LinkClosed, "relay connection closed".into()));
        }
        mux::wait_open(reply, Duration::from_secs(15)).await?;
        Ok((tx, rx))
    }

    fn teardown(&self) {
        let slots: Vec<Slot> = self.table.lock().unwrap().drain().map(|(_, s)| s).collect();
        for mut s in slots {
            s.kill(ErrorCode::LinkClosed);
        }
        self.pending.lock().unwrap().clear();
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ErrorEntry {
    at: i64,
    message: String,
}

#[derive(Debug, Clone)]
struct ConnStatus {
    state: &'static str,
    since: i64,
    latency: Option<Duration>,
    connects: u64,
}

struct ForwardState {
    fwd: Forward,
    task: Option<tokio::task::JoinHandle<()>>,
    error: Option<String>,
}

/// Shared daemon state.
pub struct DaemonInner {
    pub cfg: DaemonConfig,
    pub ident: IdentityFile,
    id: Identity,
    relay: RelayUrl,
    pin: Option<[u8; 32]>,
    session: watch::Sender<Option<Arc<Session>>>,
    status: Mutex<ConnStatus>,
    errors: Mutex<VecDeque<ErrorEntry>>,
    forwards: Mutex<BTreeMap<u16, ForwardState>>,
    publishes: Mutex<Vec<Publish>>,
    /// Serializes changes to `known_peers.json`.
    peers_lock: tokio::sync::Mutex<()>,
    /// Serializes first-contact key lookups, so a burst of connections to a
    /// new peer asks the relay once.
    lookup_lock: tokio::sync::Mutex<()>,
    pub shutdown: CancellationToken,
}

/// A running daemon.
pub struct DaemonHandle {
    pub inner: Arc<DaemonInner>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl DaemonHandle {
    pub async fn shutdown(self) {
        self.inner.shutdown.cancel();
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
        let _ = std::fs::remove_file(self.inner.cfg.paths.socket());
    }

    /// Wait until connected to the relay.
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        self.inner.wait_session(timeout).await.is_some()
    }

    pub fn is_connected(&self) -> bool {
        self.inner.current().is_some()
    }

    /// Wait for the daemon to stop (after `shutdown` via control socket or signal).
    pub async fn wait(self) {
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Start the daemon: control socket, forwards and the relay connection loop.
pub async fn start(cfg: DaemonConfig) -> Result<DaemonHandle> {
    let open_files = crate::limits::raise_open_files_limit(crate::limits::WANTED_OPEN_FILES);
    let paths = cfg.paths.clone();
    paths.ensure()?;
    let ident = IdentityFile::load(&paths)?;
    let id = ident.identity()?;
    let relay = ident.relay_url()?;
    let pin = ident.pin()?;
    let publishes = PublishesFile::load(&paths)?.publishes;
    let (session_tx, _) = watch::channel(None);
    let inner = Arc::new(DaemonInner {
        cfg,
        ident,
        id,
        relay,
        pin,
        session: session_tx,
        status: Mutex::new(ConnStatus {
            state: "connecting",
            since: crate::now_secs(),
            latency: None,
            connects: 0,
        }),
        errors: Mutex::new(VecDeque::new()),
        forwards: Mutex::new(BTreeMap::new()),
        publishes: Mutex::new(publishes),
        peers_lock: tokio::sync::Mutex::new(()),
        lookup_lock: tokio::sync::Mutex::new(()),
        shutdown: CancellationToken::new(),
    });

    let listener = bind_control(&paths).await?;
    let mut tasks = Vec::new();
    {
        let d = inner.clone();
        tasks.push(tokio::spawn(async move { d.serve_control(listener).await }));
    }
    for f in ForwardsFile::load(&paths)?.forwards {
        if let Err(e) = inner.start_forward(f.clone()) {
            inner.record_error(format!(
                "forward {} -> {}:{}: {e:#}",
                f.local, f.node, f.port
            ));
            inner.forwards.lock().unwrap().insert(
                f.local,
                ForwardState {
                    fwd: f,
                    task: None,
                    error: Some(format!("{e:#}")),
                },
            );
        }
    }
    {
        let d = inner.clone();
        tasks.push(tokio::spawn(async move { d.connect_loop().await }));
    }
    tracing::info!(node = %inner.ident.name, relay = %inner.relay.https(), open_files, "warren node started");
    Ok(DaemonHandle { inner, tasks })
}

async fn bind_control(paths: &NodePaths) -> Result<UnixListener> {
    let sock = paths.socket();
    if sock.exists() {
        if UnixStream::connect(&sock).await.is_ok() {
            anyhow::bail!("warren is already running for {}", paths.home.display());
        }
        let _ = std::fs::remove_file(&sock);
    }
    let l = UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

impl DaemonInner {
    pub fn current(&self) -> Option<Arc<Session>> {
        self.session.borrow().clone()
    }

    pub async fn wait_session(&self, timeout: Duration) -> Option<Arc<Session>> {
        if let Some(s) = self.current() {
            return Some(s);
        }
        let mut rx = self.session.subscribe();
        let r = tokio::time::timeout(timeout, async {
            loop {
                if let Some(s) = rx.borrow_and_update().clone() {
                    return Some(s);
                }
                if rx.changed().await.is_err() {
                    return None;
                }
            }
        })
        .await;
        r.ok().flatten()
    }

    fn record_error(&self, message: String) {
        tracing::warn!("{message}");
        let mut e = self.errors.lock().unwrap();
        e.push_back(ErrorEntry {
            at: crate::now_secs(),
            message,
        });
        while e.len() > MAX_ERRORS {
            e.pop_front();
        }
    }

    fn set_state(&self, state: &'static str) {
        let mut s = self.status.lock().unwrap();
        if s.state != state {
            s.state = state;
            s.since = crate::now_secs();
        }
        if state != "connected" {
            s.latency = None;
        }
    }

    async fn connect_loop(self: Arc<Self>) {
        let mut attempt: u32 = 0;
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            self.set_state("connecting");
            let started = Instant::now();
            match self.connect_once().await {
                Ok(reason) => {
                    tracing::info!("relay connection ended: {reason}");
                    if started.elapsed() > Duration::from_secs(30) {
                        attempt = 0;
                    }
                }
                Err(e) => self.record_error(format!("relay connection failed: {e:#}")),
            }
            self.session.send_replace(None);
            if self.shutdown.is_cancelled() {
                break;
            }
            self.set_state("disconnected");
            let delay = backoff_delay(attempt, self.cfg.backoff_min, self.cfg.backoff_max);
            attempt = attempt.saturating_add(1);
            tokio::select! {
                _ = self.shutdown.cancelled() => break,
                _ = tokio::time::sleep(delay) => {}
            }
        }
        self.set_state("stopped");
    }

    /// One relay session, from connect to disconnect.
    async fn connect_once(self: &Arc<Self>) -> Result<&'static str> {
        let mut ws = tokio::select! {
            _ = self.shutdown.cancelled() => return Ok("shutting down"),
            r = crate::ws::connect_relay(&self.relay, self.pin) => r?,
        };
        let challenge = super::read_challenge(&mut ws).await?;
        let hello = NodeHello::Auth {
            version: PROTOCOL_VERSION,
            node_id: self.ident.node_id.clone(),
            sign_pub: hex::encode(self.id.sign_pub()),
            signature: hex::encode(self.id.sign_auth(&challenge, self.relay.auth_host())),
        };
        ws.send(Message::text(serde_json::to_string(&hello)?))
            .await?;
        let publish_domain = match super::read_verdict(&mut ws).await? {
            RelayVerdict::Welcome { publish_domain, .. } => publish_domain,
            RelayVerdict::Error { code, message } => {
                anyhow::bail!(
                    "relay refused authentication ({}): {}",
                    crate::sanitize_remote_code(&code),
                    crate::sanitize_remote_text(&message)
                )
            }
            RelayVerdict::Joined { .. } => anyhow::bail!("unexpected relay reply"),
        };
        let (out, rx) = LinkOut::new(CancellationToken::new());
        let session = Arc::new(Session {
            out: out.clone(),
            table: Mutex::new(HashMap::new()),
            next_odd: AtomicU32::new(1),
            ctrl_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
            pings: Mutex::new(HashMap::new()),
            last_pong: Mutex::new(Instant::now()),
            opens: Mutex::new(TokenBucket::new(NODE_OPENS_PER_SEC, NODE_OPEN_BURST)),
            publish_domain,
            connected_at: crate::now_secs(),
        });
        let (sink, mut stream) = ws.split();
        let writer = tokio::spawn(mux::run_writer(sink, rx, out.clone(), None));
        {
            let mut s = self.status.lock().unwrap();
            s.connects += 1;
        }
        self.set_state("connected");
        self.session.send_replace(Some(session.clone()));
        tracing::info!(relay = %self.relay.https(), "connected to relay");
        {
            let d = self.clone();
            let s = session.clone();
            tokio::spawn(async move { d.reclaim_publishes(&s).await });
        }

        let mut ping = tokio::time::interval(self.cfg.ping_interval);
        let mut nonce: u64 = 0;
        let reason = loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => break "shutting down",
                _ = out.token().cancelled() => break "link closed",
                _ = ping.tick() => {
                    if session.last_pong.lock().unwrap().elapsed() > self.cfg.ping_interval * 3 + Duration::from_secs(1) {
                        break "keepalive timeout";
                    }
                    nonce += 1;
                    session.pings.lock().unwrap().insert(nonce, Instant::now());
                    out.send(Frame::new(FrameType::Ping, CONTROL_STREAM, bytes::Bytes::copy_from_slice(&nonce.to_be_bytes())));
                }
                m = stream.next() => match m {
                    Some(Ok(Message::Binary(b))) => match Frame::decode(b) {
                        Ok(f) => {
                            if let Err(e) = self.on_frame(&session, f) {
                                break e;
                            }
                        }
                        Err(_) => break "malformed frame from relay",
                    },
                    Some(Ok(Message::Close(_))) | None => break "closed by relay",
                    Some(Err(_)) => break "connection error",
                    Some(Ok(_)) => {}
                }
            }
        };
        out.close();
        self.session.send_replace(None);
        session.teardown();
        let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
        Ok(reason)
    }

    fn on_frame(self: &Arc<Self>, session: &Arc<Session>, f: Frame) -> Result<(), &'static str> {
        match f.ty {
            FrameType::Ping => {
                session
                    .out
                    .send(Frame::new(FrameType::Pong, CONTROL_STREAM, f.payload));
            }
            FrameType::Pong => {
                *session.last_pong.lock().unwrap() = Instant::now();
                if f.payload.len() == 8 {
                    let n = u64::from_be_bytes(f.payload[..8].try_into().unwrap_or([0; 8]));
                    if let Some(t) = session.pings.lock().unwrap().remove(&n) {
                        self.status.lock().unwrap().latency = Some(t.elapsed());
                    }
                }
            }
            FrameType::Ctrl => {
                if let Ok(r) = serde_json::from_slice::<CtrlResponse>(&f.payload) {
                    if let Some(tx) = session.pending.lock().unwrap().remove(&r.id) {
                        let _ = tx.send(r);
                    }
                } else if let Ok(ev) = serde_json::from_slice::<CtrlEvent>(&f.payload) {
                    if ev.event == "revoked" {
                        self.record_error("this node was revoked by the relay operator".into());
                    }
                }
            }
            FrameType::Open => {
                if f.stream == CONTROL_STREAM || f.stream % 2 == 1 {
                    return Err("relay used an odd stream id");
                }
                self.incoming(session, f);
            }
            _ => {
                let mut t = session.table.lock().unwrap();
                if let Some(slot) = t.get_mut(&f.stream) {
                    let id = f.stream;
                    if slot.deliver(f, &session.out) {
                        t.remove(&id);
                    }
                }
            }
        }
        Ok(())
    }

    fn incoming(self: &Arc<Self>, session: &Arc<Session>, f: Frame) {
        let id = f.stream;
        let Ok(p) = OpenPayload::decode(&f.payload) else {
            session
                .out
                .send(Frame::open_err(id, ErrorCode::BadRequest, "malformed OPEN"));
            return;
        };
        let (tx, rx) = {
            let mut t = session.table.lock().unwrap();
            if t.contains_key(&id) {
                return;
            }
            if t.len() >= MAX_STREAMS_PER_NODE {
                drop(t);
                session.out.send(Frame::open_err(
                    id,
                    ErrorCode::TooManyStreams,
                    "too many streams",
                ));
                return;
            }
            let host: Arc<dyn StreamHost> = session.clone();
            let (slot, tx, rx, _) = mux::new_stream(id, host, false);
            t.insert(id, slot);
            (tx, rx)
        };
        let d = self.clone();
        tokio::spawn(async move {
            if p.is_public() {
                d.public_incoming(p, tx, rx).await;
            } else {
                d.private_incoming(p, tx, rx).await;
            }
        });
    }

    /// Destination side of a private stream: policy, pinning, Noise, proxy.
    async fn private_incoming(self: Arc<Self>, p: OpenPayload, tx: MuxSender, rx: MuxReceiver) {
        let paths = &self.cfg.paths;
        // The source name is the relay's claim; it must at least be a name.
        if !crate::valid_name(&p.src) {
            tx.reject(ErrorCode::BadRequest, "invalid source name");
            return;
        }
        // 1. Default deny, enforced here regardless of what the relay allowed.
        let shares = match SharesFile::load(paths) {
            Ok(s) => s,
            Err(e) => {
                self.record_error(format!("reading shares: {e:#}"));
                tx.reject(ErrorCode::Internal, "share policy unreadable");
                return;
            }
        };
        match shares.decide(p.port, &p.src) {
            ShareDecision::Allowed => {}
            ShareDecision::NotShared => {
                tracing::info!(src = %p.src, port = p.port, "refused: port not shared");
                tx.reject(
                    ErrorCode::NotShared,
                    &format!("port {} is not shared", p.port),
                );
                return;
            }
            ShareDecision::Forbidden => {
                tracing::info!(src = %p.src, port = p.port, "refused: not in share list");
                tx.reject(
                    ErrorCode::Forbidden,
                    &format!("port {} is not shared with {}", p.port, p.src),
                );
                return;
            }
        }
        // 2. The relay's claim about the source key must match our pin.
        let Some(claimed) = p.src_static else {
            tx.reject(ErrorCode::BadRequest, "missing source key");
            return;
        };
        let pin_state = match KnownPeers::load(paths) {
            Ok(k) => k.check(&p.src, &claimed),
            Err(e) => {
                // Fail closed: an unreadable pin store pins nothing new.
                self.record_error(format!("reading pinned keys: {e:#}"));
                tx.reject(ErrorCode::Internal, "pinned keys unreadable");
                return;
            }
        };
        if let PinCheck::Changed { pinned } = pin_state {
            self.record_error(format!(
                "refused connection from {}: its key changed (pinned {}, now {}); if expected, check the fingerprint on {} and run `warren trust {} --expect {}`",
                p.src,
                crypto::fingerprint(&pinned),
                crypto::fingerprint(&claimed),
                p.src,
                p.src,
                crypto::fingerprint(&claimed),
            ));
            tx.reject(
                ErrorCode::KeyChanged,
                "destination has a different key pinned for you",
            );
            return;
        }
        if !tx.accept() {
            return;
        }
        // 3. Noise message 1: proves the initiator holds the claimed static key.
        let responder = match noise::respond(tx, rx, &self.id).await {
            Ok(r) => r,
            Err(e) => {
                self.record_error(format!("handshake from {} failed: {e}", p.src));
                return;
            }
        };
        if !crypto::ct_eq(&responder.remote_static, &claimed) {
            self.record_error(format!(
                "refused connection claiming to be {}: presented key {} does not match",
                p.src,
                crypto::fingerprint(&responder.remote_static)
            ));
            responder.refuse(ErrorCode::HandshakeFailed);
            return;
        }
        let h = &responder.hello;
        if h.dest != self.ident.name || h.port != p.port || h.src != p.src {
            self.record_error(format!(
                "refused connection from {}: request does not match the relay's OPEN",
                p.src
            ));
            responder.refuse(ErrorCode::Forbidden);
            return;
        }
        // 4. Message 2 and the initiator's confirmation. Message 1 alone could
        // be a recording replayed by the relay; nothing below happens until
        // the initiator proves it is taking part in this handshake.
        let confirmed = match responder.complete().await {
            Ok(c) => c,
            Err(e) => {
                self.record_error(format!("handshake from {} was not completed: {e}", p.src));
                return;
            }
        };
        if pin_state == PinCheck::New {
            if let Err(e) = self.pin_peer(&p.src, &claimed).await {
                self.record_error(format!("{e}"));
                confirmed.refuse(ErrorCode::KeyChanged).await;
                return;
            }
        }
        // 5. Connect to the local service and pipe.
        let tcp = match net::dial_local(p.port).await {
            Ok(t) => t,
            Err(e) => {
                tracing::info!(port = p.port, "local connect failed: {e}");
                confirmed.refuse(ErrorCode::ConnectFailed).await;
                return;
            }
        };
        let chan = match confirmed.accept().await {
            Ok(c) => c,
            Err(e) => {
                self.record_error(format!("handshake with {} failed: {e}", p.src));
                return;
            }
        };
        let (r, w) = tcp.into_split();
        if let Err(e) = chan.pipe(r, w).await {
            tracing::debug!(src = %p.src, port = p.port, "stream ended: {e}");
        }
    }

    /// Public stream from the relay: proxy bytes to the published local port.
    async fn public_incoming(self: Arc<Self>, p: OpenPayload, tx: MuxSender, mut rx: MuxReceiver) {
        let port = self
            .publishes
            .lock()
            .unwrap()
            .iter()
            .find(|x| x.name == p.dest)
            .map(|x| x.port);
        let Some(port) = port else {
            tx.reject(ErrorCode::NoSuchPublish, "not published here");
            return;
        };
        let tcp = match net::dial_local(port).await {
            Ok(t) => t,
            Err(e) => {
                self.record_error(format!(
                    "publish {}: nothing reachable on 127.0.0.1:{port}: {e}",
                    p.dest
                ));
                tx.reject(ErrorCode::ConnectFailed, "published service unreachable");
                return;
            }
        };
        if !tx.accept() {
            return;
        }
        let (r, w) = tcp.into_split();
        let up = mux::copy_to_stream(r, &tx);
        let down = mux::copy_from_stream(&mut rx, w);
        tokio::pin!(up);
        tokio::pin!(down);
        let (mut up_done, mut down_done) = (false, false);
        // Either direction failing (e.g. the relay reset the stream because
        // the public client left) ends both, so an idle backend connection
        // is not held open.
        while !(up_done && down_done) {
            tokio::select! {
                r = &mut up, if !up_done => {
                    up_done = true;
                    if r.is_err() { break; }
                }
                r = &mut down, if !down_done => {
                    down_done = true;
                    if r.is_err() { break; }
                }
            }
        }
        if !(up_done && down_done) {
            tx.reset(ErrorCode::Aborted);
        }
    }

    /// Pin a peer key seen for the first time (serialized with `trust`).
    async fn pin_peer(&self, name: &str, key: &[u8; 32]) -> Result<(), OpenError> {
        let _g = self.peers_lock.lock().await;
        let paths = &self.cfg.paths;
        let mut k = KnownPeers::load(paths).map_err(|e| OpenError::Other(format!("{e:#}")))?;
        match k.check(name, key) {
            PinCheck::Match => Ok(()),
            PinCheck::Changed { pinned } => Err(OpenError::KeyChanged {
                name: name.to_string(),
                pinned: crypto::fingerprint(&pinned),
                current: crypto::fingerprint(key),
            }),
            PinCheck::New => {
                if k.relay.is_empty() {
                    k.relay = self.ident.relay.clone();
                }
                k.pin(name, key, false);
                k.save(paths)
                    .map_err(|e| OpenError::Other(format!("{e:#}")))?;
                tracing::info!(peer = %name, fingerprint = %crypto::fingerprint(key), "pinned new peer key");
                Ok(())
            }
        }
    }

    /// The key pinned for `name`, if any (an unreadable store is an error).
    fn pinned_key(&self, name: &str) -> Result<Option<[u8; 32]>, OpenError> {
        KnownPeers::load(&self.cfg.paths)
            .map(|k| k.pinned(name))
            .map_err(|e| OpenError::Other(format!("{e:#}")))
    }

    /// The key to use for `dest`: the pinned one, or on first contact the
    /// relay's (then pinned). Concurrent first contacts share one lookup.
    async fn peer_key(&self, session: &Arc<Session>, dest: &str) -> Result<[u8; 32], OpenError> {
        if let Some(k) = self.pinned_key(dest)? {
            return Ok(k);
        }
        let _g = self.lookup_lock.lock().await;
        if let Some(k) = self.pinned_key(dest)? {
            return Ok(k);
        }
        let info = session
            .lookup(dest)
            .await
            .map_err(|f| match f.code.as_str() {
                "no_such_node" => OpenError::NoSuchNode(dest.to_string()),
                "not_connected" => OpenError::NotConnected,
                _ => OpenError::Other(f.message),
            })?;
        let k = info
            .static_key()
            .ok_or_else(|| OpenError::Other("relay returned a malformed key".into()))?;
        self.pin_peer(dest, &k).await?;
        Ok(k)
    }

    /// Open an end-to-end encrypted stream to `dest:port`.
    pub async fn open_private(
        self: &Arc<Self>,
        dest: &str,
        port: u16,
    ) -> Result<SecureChannel, OpenError> {
        let session = self
            .wait_session(SESSION_WAIT)
            .await
            .ok_or(OpenError::NotConnected)?;
        let key = self.peer_key(&session, dest).await?;
        let (tx, rx) = session
            .open(dest, port)
            .await
            .map_err(|(code, message)| match code {
                ErrorCode::NoSuchNode => OpenError::NoSuchNode(dest.to_string()),
                _ => OpenError::Refused {
                    code,
                    node: dest.to_string(),
                    message,
                },
            })?;
        let hello = Hello {
            v: 1,
            src: self.ident.name.clone(),
            dest: dest.to_string(),
            port,
        };
        let refused = |code: ErrorCode| {
            let message = match code {
                ErrorCode::KeyChanged => "the destination has a different key pinned for this node (it may need `warren trust`)".to_string(),
                ErrorCode::ConnectFailed => format!("nothing is listening on port {port} there"),
                _ => "the destination refused the stream".to_string(),
            };
            OpenError::Refused {
                code,
                node: dest.to_string(),
                message,
            }
        };
        match noise::initiate(tx, rx, &self.id, &key, &hello).await {
            Ok(c) => Ok(c),
            // Refused after a completed handshake: the reason is authentic.
            Err(noise::NoiseError::Refused(code)) => Err(refused(code)),
            Err(e) => {
                // Distinguish a changed key from other failures.
                if let Ok(info) = session.lookup(dest).await {
                    if let Some(current) = info.static_key() {
                        if !crypto::ct_eq(&current, &key) {
                            return Err(OpenError::KeyChanged {
                                name: dest.to_string(),
                                pinned: crypto::fingerprint(&key),
                                current: crypto::fingerprint(&current),
                            });
                        }
                    }
                }
                if let noise::NoiseError::Io(io) = &e {
                    if io.kind() == std::io::ErrorKind::ConnectionReset {
                        let msg = io.to_string();
                        let code = [
                            ErrorCode::KeyChanged,
                            ErrorCode::ConnectFailed,
                            ErrorCode::Forbidden,
                            ErrorCode::HandshakeFailed,
                        ]
                        .into_iter()
                        .find(|c| msg.contains(c.name()))
                        .unwrap_or(ErrorCode::Aborted);
                        return Err(refused(code));
                    }
                }
                Err(OpenError::Handshake(dest.to_string(), e.to_string()))
            }
        }
    }

    async fn reclaim_publishes(self: &Arc<Self>, session: &Arc<Session>) {
        let list = self.publishes.lock().unwrap().clone();
        for p in list {
            let r = session
                .ctrl(CtrlOp::Publish {
                    name: p.name.clone(),
                    replace: false,
                    reclaim: true,
                    allow: p.allow.clone(),
                })
                .await;
            if let Err(f) = r {
                self.record_error(format!(
                    "re-publishing {}: {} ({})",
                    p.name, f.message, f.code
                ));
            }
        }
    }

    fn start_forward(self: &Arc<Self>, f: Forward) -> Result<()> {
        let std_l = std::net::TcpListener::bind(("127.0.0.1", f.local))
            .with_context(|| format!("cannot listen on 127.0.0.1:{}", f.local))?;
        std_l.set_nonblocking(true)?;
        let l = TcpListener::from_std(std_l)?;
        let d = self.clone();
        let fwd = f.clone();
        let task = tokio::spawn(async move { d.run_forward(fwd, l).await });
        let old = self.forwards.lock().unwrap().insert(
            f.local,
            ForwardState {
                fwd: f,
                task: Some(task),
                error: None,
            },
        );
        if let Some(ForwardState { task: Some(t), .. }) = old {
            t.abort();
        }
        Ok(())
    }

    async fn run_forward(self: Arc<Self>, f: Forward, l: TcpListener) {
        loop {
            let (tcp, _) = tokio::select! {
                _ = self.shutdown.cancelled() => return,
                r = l.accept() => match crate::net::accepted(r, "forward").await {
                    Some(x) => x,
                    None => continue,
                },
            };
            let _ = tcp.set_nodelay(true);
            let d = self.clone();
            let f = f.clone();
            tokio::spawn(async move {
                match d.open_private(&f.node, f.port).await {
                    Ok(chan) => {
                        let (r, w) = tcp.into_split();
                        let _ = chan.pipe(r, w).await;
                    }
                    Err(e) => {
                        d.record_error(format!("forward {} -> {}:{}: {e}", f.local, f.node, f.port))
                    }
                }
            });
        }
    }

    fn status_json(&self) -> Value {
        let st = self.status.lock().unwrap().clone();
        let shares = SharesFile::load(&self.cfg.paths).unwrap_or_default();
        let forwards: Vec<Value> = self
            .forwards
            .lock()
            .unwrap()
            .values()
            .map(|f| {
                json!({
                    "local": f.fwd.local,
                    "node": f.fwd.node,
                    "port": f.fwd.port,
                    "listening": f.task.is_some(),
                    "error": f.error,
                })
            })
            .collect();
        let publishes: Vec<Value> = self
            .publishes
            .lock()
            .unwrap()
            .iter()
            .map(|p| json!({"name": p.name, "port": p.port, "url": p.url, "allow": p.allow}))
            .collect();
        let errors: Vec<ErrorEntry> = self.errors.lock().unwrap().iter().cloned().collect();
        let session = self.current();
        json!({
            "node": {
                "name": self.ident.name,
                "node_id": self.ident.node_id,
                "fingerprint": self.ident.fingerprint(),
            },
            "relay": self.relay.https(),
            "connection": {
                "state": st.state,
                "since": st.since,
                "latency_ms": st.latency.map(|d| (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0),
                "connects": st.connects,
                "streams": session.as_ref().map(|s| s.stream_count()).unwrap_or(0),
            },
            "daemon": { "running": true, "pid": std::process::id() },
            "shares": shares.shares,
            "forwards": forwards,
            "publishes": publishes,
            "recent_errors": errors,
        })
    }

    async fn handle_request(self: &Arc<Self>, req: ControlRequest) -> ControlResponse {
        match req {
            ControlRequest::Status => ControlResponse::ok(self.status_json()),
            ControlRequest::Shutdown => {
                self.shutdown.cancel();
                ControlResponse::ok(json!({"stopping": true}))
            }
            ControlRequest::ForwardAdd { local, node, port } => {
                if !crate::valid_name(&node) || port == 0 || local == 0 {
                    return ControlResponse::err("bad_request", "invalid forward");
                }
                let f = Forward { local, node, port };
                // Replacing a forward on the same port: stop the old listener first.
                let old = self.forwards.lock().unwrap().remove(&local);
                if let Some(ForwardState { task: Some(t), .. }) = old {
                    t.abort();
                    let _ = t.await;
                }
                if let Err(e) = self.start_forward(f.clone()) {
                    return ControlResponse::err("bind_failed", format!("{e:#}"));
                }
                let mut file = ForwardsFile::load(&self.cfg.paths).unwrap_or_default();
                file.forwards.retain(|x| x.local != local);
                file.forwards.push(f.clone());
                file.forwards.sort_by_key(|x| x.local);
                if let Err(e) = file.save(&self.cfg.paths) {
                    return ControlResponse::err("io", format!("{e:#}"));
                }
                ControlResponse::ok(serde_json::to_value(f).unwrap_or_default())
            }
            ControlRequest::ForwardRemove { local } => {
                let removed = self.forwards.lock().unwrap().remove(&local);
                if let Some(ForwardState { task: Some(t), .. }) = &removed {
                    t.abort();
                }
                let mut file = ForwardsFile::load(&self.cfg.paths).unwrap_or_default();
                let n = file.forwards.len();
                file.forwards.retain(|x| x.local != local);
                let changed = n != file.forwards.len();
                if changed {
                    let _ = file.save(&self.cfg.paths);
                }
                if removed.is_none() && !changed {
                    return ControlResponse::err(
                        "not_found",
                        format!("no forward on port {local}"),
                    );
                }
                ControlResponse::ok(json!({"local": local}))
            }
            ControlRequest::Publish {
                port,
                name,
                replace,
                allow,
            } => {
                let Some(session) = self.wait_session(SESSION_WAIT).await else {
                    return ControlResponse::err("not_connected", "not connected to the relay");
                };
                if !replace {
                    if let Some(existing) = self
                        .publishes
                        .lock()
                        .unwrap()
                        .iter()
                        .find(|p| p.name == name)
                    {
                        return ControlResponse::err(
                            "already_published",
                            format!(
                                "{name:?} is already published from port {}; use --replace",
                                existing.port
                            ),
                        );
                    }
                }
                match session
                    .ctrl(CtrlOp::Publish {
                        name: name.clone(),
                        replace,
                        reclaim: false,
                        allow: allow.clone(),
                    })
                    .await
                {
                    Ok(v) => {
                        let url = v["url"].as_str().unwrap_or_default().to_string();
                        let allow: Vec<String> =
                            serde_json::from_value(v["allow"].clone()).unwrap_or(allow);
                        let entry = Publish {
                            name: name.clone(),
                            port,
                            allow,
                            url: url.clone(),
                        };
                        {
                            let mut p = self.publishes.lock().unwrap();
                            p.retain(|x| x.name != name);
                            p.push(entry.clone());
                            p.sort_by(|a, b| a.name.cmp(&b.name));
                            let _ = (PublishesFile {
                                publishes: p.clone(),
                            })
                            .save(&self.cfg.paths);
                        }
                        ControlResponse::ok(serde_json::to_value(entry).unwrap_or_default())
                    }
                    Err(f) => ControlResponse::err(&f.code, f.message),
                }
            }
            ControlRequest::Unpublish { name } => {
                let local = {
                    let mut p = self.publishes.lock().unwrap();
                    let n = p.len();
                    p.retain(|x| x.name != name);
                    let _ = (PublishesFile {
                        publishes: p.clone(),
                    })
                    .save(&self.cfg.paths);
                    n != p.len()
                };
                let remote = match self.wait_session(SESSION_WAIT).await {
                    Some(s) => s.ctrl(CtrlOp::Unpublish { name: name.clone() }).await,
                    None => Err(CtrlFailure {
                        code: "not_connected".into(),
                        message: "not connected to the relay".into(),
                    }),
                };
                match remote {
                    Ok(_) => ControlResponse::ok(json!({"name": name})),
                    Err(f) if local && f.code == "not_found" => {
                        ControlResponse::ok(json!({"name": name}))
                    }
                    Err(f) => ControlResponse::err(&f.code, f.message),
                }
            }
            ControlRequest::Devices => {
                let Some(session) = self.wait_session(SESSION_WAIT).await else {
                    return ControlResponse::err("not_connected", "not connected to the relay");
                };
                let list = match fetch_devices(&session).await {
                    Ok(l) => l,
                    Err(f) => return ControlResponse::err(&f.code, f.message),
                };
                let known = KnownPeers::load(&self.cfg.paths);
                if let Err(e) = &known {
                    self.record_error(format!("reading pinned keys: {e:#}"));
                }
                let out: Vec<Value> = list
                    .iter()
                    .map(|d| {
                        let key = d.static_key().unwrap_or([0; 32]);
                        let fingerprint = crypto::fingerprint(&key);
                        let me = d.name == self.ident.name;
                        let pin = if me {
                            "self"
                        } else {
                            match &known {
                                Err(_) => "unreadable",
                                Ok(k) => match k.check(&d.name, &key) {
                                    PinCheck::Match => "pinned",
                                    PinCheck::New => "new",
                                    PinCheck::Changed { .. } => "changed",
                                },
                            }
                        };
                        // Names come from the relay: make them safe to print.
                        let name = crate::sanitize_remote_text(&d.name);
                        let mut v = json!({
                            "name": name,
                            "node_id": crate::sanitize_remote_text(&d.node_id),
                            "fingerprint": fingerprint,
                            "online": d.online,
                            "last_seen": d.last_seen,
                            "pin": pin,
                        });
                        if pin == "changed" && crate::valid_name(&d.name) {
                            v["trust"] =
                                json!(format!("warren trust {} --expect {fingerprint}", d.name));
                        }
                        v
                    })
                    .collect();
                ControlResponse::ok(Value::Array(out))
            }
            ControlRequest::Trust { name, expect } => {
                if !crate::valid_name(&name) {
                    return ControlResponse::err("bad_request", format!("invalid name {name:?}"));
                }
                let Some(session) = self.wait_session(SESSION_WAIT).await else {
                    return ControlResponse::err("not_connected", "not connected to the relay");
                };
                let info = match session.lookup(&name).await {
                    Ok(i) => i,
                    Err(f) => return ControlResponse::err(&f.code, f.message),
                };
                let Some(key) = info.static_key() else {
                    return ControlResponse::err("protocol", "malformed key from relay");
                };
                let current = crypto::fingerprint(&key);
                let _g = self.peers_lock.lock().await;
                // Never rewrite a store that cannot be read: that would drop
                // every other pin and silently return those peers to
                // trust-on-first-use.
                let mut k = match KnownPeers::load(&self.cfg.paths) {
                    Ok(k) => k,
                    Err(e) => {
                        return ControlResponse::err(
                            "pin_store_unreadable",
                            format!(
                                "{e:#}; nothing was changed. Repair {} (or move it away, which forgets every pinned key) and try again",
                                self.cfg.paths.known_peers().display()
                            ),
                        )
                    }
                };
                let previous = k.pinned(&name);
                let previous_fp = previous.map(|p| crypto::fingerprint(&p));
                match &expect {
                    Some(e) => {
                        let norm = |s: &str| s.to_ascii_lowercase().replace([':', ' ', '-'], "");
                        if norm(e) != norm(&current) {
                            return ControlResponse::err(
                                "fingerprint_mismatch",
                                format!("{name} currently has fingerprint {current}, not {e}"),
                            );
                        }
                    }
                    // Replacing a pinned key needs the fingerprint the user
                    // verified; otherwise the relay could hand over a
                    // different key between showing one and this lookup.
                    None => {
                        if let Some(prev) = previous {
                            if !crypto::ct_eq(&prev, &key) {
                                return ControlResponse::err(
                                    "fingerprint_required",
                                    format!(
                                        "the key of {name} changed: pinned {}, the relay now reports {current}. Check the fingerprint on {name} itself (`warren status` there), then run `warren trust {name} --expect {current}`",
                                        previous_fp.as_deref().unwrap_or_default()
                                    ),
                                );
                            }
                        }
                    }
                }
                if k.relay.is_empty() {
                    k.relay = self.ident.relay.clone();
                }
                k.pin(&name, &key, true);
                if let Err(e) = k.save(&self.cfg.paths) {
                    return ControlResponse::err("io", format!("{e:#}"));
                }
                ControlResponse::ok(json!({
                    "name": name,
                    "previous": previous_fp,
                    "current": current,
                    "changed": previous_fp.as_deref() != Some(current.as_str()),
                }))
            }
            ControlRequest::Open { .. } => ControlResponse::err("bad_request", "unexpected open"),
        }
    }

    async fn serve_control(self: Arc<Self>, l: UnixListener) {
        loop {
            let (s, _) = tokio::select! {
                _ = self.shutdown.cancelled() => break,
                r = l.accept() => match crate::net::accepted(r, "control socket").await {
                    Some(x) => x,
                    None => continue,
                },
            };
            let d = self.clone();
            tokio::spawn(async move { d.control_conn(s).await });
        }
        let _ = std::fs::remove_file(self.cfg.paths.socket());
    }

    async fn control_conn(self: Arc<Self>, s: UnixStream) {
        let (r, mut w) = s.into_split();
        let mut r = tokio::io::BufReader::new(r);
        let line =
            match tokio::time::timeout(Duration::from_secs(10), control::read_line(&mut r)).await {
                Ok(Ok(Some(l))) => l,
                _ => return,
            };
        let req: ControlRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                let _ = write_resp(
                    &mut w,
                    &ControlResponse::err("bad_request", "malformed request"),
                )
                .await;
                return;
            }
        };
        if let ControlRequest::Open { node, port } = req {
            match self.open_private(&node, port).await {
                Ok(chan) => {
                    if write_resp(
                        &mut w,
                        &ControlResponse::ok(json!({"node": node, "port": port})),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    let _ = chan.pipe(r, w).await;
                }
                Err(e) => {
                    let _ =
                        write_resp(&mut w, &ControlResponse::err(&e.code(), e.to_string())).await;
                }
            }
            return;
        }
        let resp = self.handle_request(req).await;
        let _ = write_resp(&mut w, &resp).await;
    }
}

/// Every registered node, fetched page by page.
async fn fetch_devices(session: &Session) -> Result<Vec<DeviceInfo>, CtrlFailure> {
    let mut list: Vec<DeviceInfo> = Vec::new();
    let mut offset = 0;
    loop {
        let v = session
            .ctrl(CtrlOp::Devices {
                offset,
                limit: None,
            })
            .await?;
        let page: DevicesPage = serde_json::from_value(v)
            .map_err(|_| CtrlFailure::new("protocol", "malformed devices reply"))?;
        list.extend(page.devices);
        match page.next {
            None => return Ok(list),
            // A relay must make progress and stay within reason.
            Some(n) if n > offset && list.len() < 1_000_000 => offset = n,
            Some(_) => {
                return Err(CtrlFailure::new(
                    "protocol",
                    "inconsistent devices paging from the relay",
                ))
            }
        }
    }
}

async fn write_resp<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    r: &ControlResponse,
) -> std::io::Result<()> {
    let mut v = serde_json::to_vec(r).unwrap_or_default();
    v.push(b'\n');
    w.write_all(&v).await?;
    w.flush().await
}

/// Run the daemon in the foreground until SIGINT/SIGTERM or `shutdown`.
pub async fn run(cfg: DaemonConfig) -> Result<()> {
    let h = start(cfg).await?;
    let token = h.inner.shutdown.clone();
    tokio::spawn(async move {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
            _ = token.cancelled() => {}
        }
        token.cancel();
    });
    let paths = h.inner.cfg.paths.clone();
    h.inner.shutdown.cancelled().await;
    h.wait().await;
    let _ = std::fs::remove_file(paths.socket());
    tracing::info!("warren node stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_bounds() {
        let min = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        for _ in 0..50 {
            let d0 = backoff_delay(0, min, max);
            assert!(d0 >= Duration::from_millis(500) && d0 <= Duration::from_secs(1));
            let d3 = backoff_delay(3, min, max);
            assert!(d3 >= Duration::from_secs(4) && d3 <= Duration::from_secs(8));
            let d20 = backoff_delay(20, min, max);
            assert!(d20 >= Duration::from_secs(30) && d20 <= Duration::from_secs(60));
            let big = backoff_delay(u32::MAX, min, max);
            assert!(big <= max);
        }
    }
}
