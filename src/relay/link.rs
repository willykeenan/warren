//! One authenticated node connection on the relay: authentication and
//! enrollment, frame dispatch, forwarding of private streams (ciphertext only),
//! control requests and the relay's own endpoint streams for public traffic.

use super::db::{ClaimOutcome, JoinOutcome};
use super::RelayInner;
use crate::crypto;
use crate::limits::{TokenBucket, NODE_AUTH_TIMEOUT};
use crate::mux::{self, LinkOut, MuxReceiver, MuxSender, Slot, StreamHost, TapDir};
use crate::proto::*;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;

type ServerTls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// Largest total credit the relay lets one direction of a forwarded stream hold.
const MAX_FORWARD_CREDIT: i64 = 64 * 1024 * 1024;

/// One side of a forwarded stream.
struct Side {
    link: Weak<NodeLink>,
    out: LinkOut,
    id: u32,
}

/// A private stream bridged between two node links. The relay only moves
/// DATA payloads (Noise ciphertext) and accounts credit to detect overruns.
struct Pair {
    /// The node that sent OPEN (odd stream id on its link).
    init: Side,
    /// The destination node (even stream id on its link).
    targ: Side,
    credit_init: AtomicI64,
    credit_targ: AtomicI64,
    fin_init: AtomicBool,
    fin_targ: AtomicBool,
}

impl Pair {
    fn remove_both(self: &Arc<Self>) {
        for side in [&self.init, &self.targ] {
            if let Some(l) = side.link.upgrade() {
                let mut t = l.table.lock().unwrap();
                if matches!(t.get(&side.id), Some(Entry::Fwd(p)) if Arc::ptr_eq(p, self)) {
                    t.remove(&side.id);
                }
            }
        }
    }

    fn reset_both(self: &Arc<Self>, code: ErrorCode) {
        self.init.out.send(Frame::reset(self.init.id, code));
        self.targ.out.send(Frame::reset(self.targ.id, code));
        self.remove_both();
    }
}

enum Entry {
    Fwd(Arc<Pair>),
    Local(Slot),
}

/// An authenticated node connection.
pub struct NodeLink {
    pub conn_id: u64,
    pub node_id: String,
    pub name: String,
    pub static_pub: [u8; 32],
    pub out: LinkOut,
    pub peer: SocketAddr,
    table: Mutex<HashMap<u32, Entry>>,
    opens: Mutex<TokenBucket>,
    pings: Mutex<TokenBucket>,
    ctrls: Mutex<TokenBucket>,
    next_even: AtomicU32,
    last_pong: Mutex<Instant>,
}

impl StreamHost for NodeLink {
    fn out(&self) -> &LinkOut {
        &self.out
    }

    fn remove_stream(&self, id: u32) {
        let mut t = self.table.lock().unwrap();
        if matches!(t.get(&id), Some(Entry::Local(_))) {
            t.remove(&id);
        }
    }
}

impl NodeLink {
    /// Number of streams currently open on this link.
    pub fn stream_count(&self) -> usize {
        self.table.lock().unwrap().len()
    }

    fn next_free_even(&self, t: &HashMap<u32, Entry>) -> u32 {
        loop {
            let id = self.next_even.fetch_add(2, Ordering::Relaxed);
            if id == 0 {
                continue;
            }
            if !t.contains_key(&id) {
                return id;
            }
        }
    }

    pub fn send_event(&self, event: &str, detail: serde_json::Value) {
        self.out.send(Frame::ctrl(&CtrlEvent {
            event: event.to_string(),
            detail,
        }));
    }

    /// Open a relay-terminated public stream to this node.
    pub async fn open_public(
        self: &Arc<Self>,
        name: &str,
        client: SocketAddr,
    ) -> Result<(MuxSender, MuxReceiver), (ErrorCode, String)> {
        let (tx, rx, reply, id) = {
            let mut t = self.table.lock().unwrap();
            if t.len() >= MAX_STREAMS_PER_NODE {
                return Err((
                    ErrorCode::TooManyStreams,
                    "node has too many streams".into(),
                ));
            }
            let id = self.next_free_even(&t);
            let host: Arc<dyn StreamHost> = self.clone();
            let (slot, tx, rx, reply) = mux::new_stream(id, host, true);
            t.insert(id, Entry::Local(slot));
            (tx, rx, reply.expect("outgoing"), id)
        };
        let p = OpenPayload {
            flags: FLAG_PUBLIC,
            port: 0,
            dest: name.to_string(),
            client: client.to_string(),
            ..Default::default()
        };
        if !self.out.send(Frame::new(FrameType::Open, id, p.encode())) {
            return Err((ErrorCode::LinkClosed, "node link closed".into()));
        }
        mux::wait_open(reply, Duration::from_secs(15)).await?;
        Ok((tx, rx))
    }

    fn teardown(&self) {
        let entries: Vec<(u32, Entry)> = self.table.lock().unwrap().drain().collect();
        for (id, e) in entries {
            match e {
                Entry::Local(mut slot) => slot.kill(ErrorCode::LinkClosed),
                Entry::Fwd(pair) => {
                    let other = if id % 2 == 1 { &pair.targ } else { &pair.init };
                    other
                        .out
                        .send(Frame::reset(other.id, ErrorCode::LinkClosed));
                    pair.remove_both();
                }
            }
        }
    }

    /// Handle one frame. `Err` closes the link.
    fn on_frame(self: &Arc<Self>, inner: &Arc<RelayInner>, f: Frame) -> Result<(), &'static str> {
        match f.ty {
            FrameType::Ping => {
                if f.stream != CONTROL_STREAM || f.payload.len() > 64 {
                    return Err("bad PING");
                }
                if self.pings.lock().unwrap().try_take() {
                    self.out
                        .send(Frame::new(FrameType::Pong, CONTROL_STREAM, f.payload));
                }
                Ok(())
            }
            FrameType::Pong => {
                *self.last_pong.lock().unwrap() = Instant::now();
                Ok(())
            }
            FrameType::Ctrl => {
                if f.stream != CONTROL_STREAM {
                    return Err("CTRL on a data stream");
                }
                self.handle_ctrl(inner, &f.payload);
                Ok(())
            }
            FrameType::Open => self.handle_open(inner, f),
            _ => {
                if f.stream == CONTROL_STREAM {
                    return Err("stream frame on the control stream");
                }
                self.route(f);
                Ok(())
            }
        }
    }

    fn handle_open(
        self: &Arc<Self>,
        inner: &Arc<RelayInner>,
        f: Frame,
    ) -> Result<(), &'static str> {
        let s = f.stream;
        if s % 2 == 0 {
            return Err("node used an even stream id");
        }
        if self.table.lock().unwrap().contains_key(&s) {
            return Err("duplicate stream id");
        }
        let refuse = |code: ErrorCode, msg: &str| {
            self.out.send(Frame::open_err(s, code, msg));
            Ok(())
        };
        let Ok(p) = OpenPayload::decode(&f.payload) else {
            return refuse(ErrorCode::BadRequest, "malformed OPEN");
        };
        if !self.opens.lock().unwrap().try_take() {
            return refuse(ErrorCode::RateLimited, "too many stream opens per second");
        }
        if p.is_public() || p.port == 0 {
            return refuse(ErrorCode::BadRequest, "invalid OPEN");
        }
        if self.stream_count() >= MAX_STREAMS_PER_NODE {
            return refuse(ErrorCode::TooManyStreams, "too many streams on this node");
        }
        let dest = {
            let reg = inner.registry.read().unwrap();
            reg.by_name
                .get(&p.dest)
                .and_then(|id| reg.nodes.get(id))
                .cloned()
        };
        let Some(dest) = dest else {
            return refuse(
                ErrorCode::NoSuchNode,
                &format!("no node named {:?}", p.dest),
            );
        };
        let Some(dlink) = inner.link_for(&dest.node_id) else {
            return refuse(ErrorCode::NodeOffline, &format!("{} is offline", p.dest));
        };
        let (t, pair) = {
            let mut dt = dlink.table.lock().unwrap();
            if dt.len() >= MAX_STREAMS_PER_NODE {
                drop(dt);
                return refuse(
                    ErrorCode::TooManyStreams,
                    "destination has too many streams",
                );
            }
            let t = dlink.next_free_even(&dt);
            let pair = Arc::new(Pair {
                init: Side {
                    link: Arc::downgrade(self),
                    out: self.out.clone(),
                    id: s,
                },
                targ: Side {
                    link: Arc::downgrade(&dlink),
                    out: dlink.out.clone(),
                    id: t,
                },
                credit_init: AtomicI64::new(STREAM_WINDOW as i64),
                credit_targ: AtomicI64::new(STREAM_WINDOW as i64),
                fin_init: AtomicBool::new(false),
                fin_targ: AtomicBool::new(false),
            });
            dt.insert(t, Entry::Fwd(pair.clone()));
            (t, pair)
        };
        self.table.lock().unwrap().insert(s, Entry::Fwd(pair));
        let fwd = OpenPayload {
            flags: 0,
            port: p.port,
            dest: p.dest,
            src: self.name.clone(),
            src_static: Some(self.static_pub),
            client: String::new(),
        };
        dlink.out.send(Frame::new(FrameType::Open, t, fwd.encode()));
        Ok(())
    }

    fn route(self: &Arc<Self>, f: Frame) {
        let id = f.stream;
        let pair = {
            let mut t = self.table.lock().unwrap();
            match t.get_mut(&id) {
                None => return,
                Some(Entry::Local(slot)) => {
                    if slot.deliver(f, &self.out) {
                        t.remove(&id);
                    }
                    return;
                }
                Some(Entry::Fwd(p)) => p.clone(),
            }
        };
        let from_init = id % 2 == 1;
        let other = if from_init { &pair.targ } else { &pair.init };
        match f.ty {
            FrameType::Data => {
                let credit = if from_init {
                    &pair.credit_init
                } else {
                    &pair.credit_targ
                };
                let n = f.payload.len() as i64;
                if credit.fetch_sub(n, Ordering::AcqRel) - n < 0 {
                    tracing::debug!(node = %self.name, stream = id, "window overrun");
                    pair.reset_both(ErrorCode::WindowOverrun);
                    return;
                }
                other.out.send(Frame::data(other.id, f.payload));
            }
            FrameType::Window => {
                let Ok(n) = f.window_credit() else {
                    pair.reset_both(ErrorCode::Protocol);
                    return;
                };
                // A WINDOW from one side grants credit to the other side's sending direction.
                let credit = if from_init {
                    &pair.credit_targ
                } else {
                    &pair.credit_init
                };
                if credit.fetch_add(n as i64, Ordering::AcqRel) + n as i64 > MAX_FORWARD_CREDIT {
                    pair.reset_both(ErrorCode::Protocol);
                    return;
                }
                other.out.send(Frame::window(other.id, n));
            }
            FrameType::Close => match f.close_kind() {
                None => {
                    let (mine, theirs) = if from_init {
                        (&pair.fin_init, &pair.fin_targ)
                    } else {
                        (&pair.fin_targ, &pair.fin_init)
                    };
                    mine.store(true, Ordering::SeqCst);
                    other.out.send(Frame::fin(other.id));
                    if theirs.load(Ordering::SeqCst) {
                        pair.remove_both();
                    }
                }
                Some(code) => {
                    other.out.send(Frame::reset(other.id, code));
                    pair.remove_both();
                }
            },
            FrameType::OpenOk if !from_init => {
                other.out.send(Frame::open_ok(other.id));
            }
            FrameType::OpenErr if !from_init => {
                let (code, msg) = f.open_error();
                other.out.send(Frame::open_err(other.id, code, &msg));
                pair.remove_both();
            }
            _ => {}
        }
    }

    fn handle_ctrl(self: &Arc<Self>, inner: &Arc<RelayInner>, payload: &[u8]) {
        let req: CtrlRequest = match serde_json::from_slice(payload) {
            Ok(r) => r,
            Err(_) => {
                self.reply(0, Err(("bad_request", "malformed control request".into())));
                return;
            }
        };
        if !self.ctrls.lock().unwrap().try_take() {
            self.reply(
                req.id,
                Err(("rate_limited", "too many control requests".into())),
            );
            return;
        }
        let r = self.ctrl_op(inner, req.op);
        self.reply(req.id, r);
    }

    fn reply(&self, id: u64, r: Result<serde_json::Value, (&'static str, String)>) {
        let resp = match r {
            Ok(v) => CtrlResponse {
                id,
                ok: true,
                error: None,
                code: None,
                result: v,
            },
            Err((code, msg)) => CtrlResponse {
                id,
                ok: false,
                error: Some(msg),
                code: Some(code.to_string()),
                result: serde_json::Value::Null,
            },
        };
        self.out.send(Frame::ctrl(&resp));
    }

    fn ctrl_op(
        self: &Arc<Self>,
        inner: &Arc<RelayInner>,
        op: CtrlOp,
    ) -> Result<serde_json::Value, (&'static str, String)> {
        let internal = |e: anyhow::Error| ("internal", format!("{e:#}"));
        match op {
            CtrlOp::Devices => Ok(serde_json::to_value(devices(inner)).unwrap_or_default()),
            CtrlOp::Lookup { name } => devices(inner)
                .into_iter()
                .find(|d| d.name == name)
                .map(|d| serde_json::to_value(d).unwrap_or_default())
                .ok_or(("no_such_node", format!("no node named {name:?}"))),
            CtrlOp::Publish {
                name,
                replace,
                reclaim,
                allow,
            } => {
                if !crate::valid_publish_name(&name) {
                    return Err((
                        "bad_name",
                        format!("invalid name {name:?}: use [a-z0-9-]{{1,32}}, not starting or ending with '-'"),
                    ));
                }
                let allow = normalize_cidrs(&allow).map_err(|e| ("bad_cidr", e))?;
                let outcome = inner
                    .db
                    .claim_publish(
                        &name,
                        &self.node_id,
                        &allow,
                        replace || reclaim,
                        crate::now_secs(),
                    )
                    .map_err(internal)?;
                match outcome {
                    ClaimOutcome::TakenByOther => Err((
                        "name_taken",
                        format!("{name:?} is published by another node"),
                    )),
                    ClaimOutcome::AlreadyYours => Err((
                        "already_published",
                        format!("this node already publishes {name:?}; use --replace to change it"),
                    )),
                    ClaimOutcome::Claimed | ClaimOutcome::Updated => {
                        inner.reload().map_err(internal)?;
                        tracing::info!(node = %self.name, %name, "name published");
                        Ok(serde_json::json!({
                            "name": name,
                            "url": public_url(inner, &name),
                            "allow": allow,
                        }))
                    }
                }
            }
            CtrlOp::Unpublish { name } => {
                if inner.db.unpublish(&name, &self.node_id).map_err(internal)? {
                    inner.reload().map_err(internal)?;
                    tracing::info!(node = %self.name, %name, "name unpublished");
                    Ok(serde_json::json!({ "name": name }))
                } else {
                    Err(("not_found", format!("this node does not publish {name:?}")))
                }
            }
            CtrlOp::Publishes => {
                let reg = inner.registry.read().unwrap();
                let mine: Vec<_> = reg
                    .publishes
                    .values()
                    .filter(|p| p.node_id == self.node_id)
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name,
                            "url": public_url(inner, &p.name),
                            "allow": p.allow,
                        })
                    })
                    .collect();
                Ok(serde_json::Value::Array(mine))
            }
        }
    }
}

/// Public URL of a published name.
pub fn public_url(inner: &RelayInner, name: &str) -> String {
    let port = inner.cfg.listen.port();
    if port == 443 || port == 0 {
        format!("https://{name}.{}/", inner.cfg.publish_domain)
    } else {
        format!("https://{name}.{}:{port}/", inner.cfg.publish_domain)
    }
}

fn devices(inner: &RelayInner) -> Vec<DeviceInfo> {
    let online: std::collections::HashSet<String> =
        inner.online.lock().unwrap().keys().cloned().collect();
    let reg = inner.registry.read().unwrap();
    let mut v: Vec<DeviceInfo> = reg
        .nodes
        .values()
        .map(|n| DeviceInfo {
            node_id: n.node_id.clone(),
            name: n.name.clone(),
            static_pub: hex::encode(n.static_pub),
            sign_pub: hex::encode(n.sign_pub),
            online: online.contains(&n.node_id),
            last_seen: n.last_seen,
            created_at: n.created_at,
        })
        .collect();
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// Validate and normalize an allowlist of CIDRs or bare addresses.
pub fn normalize_cidrs(v: &[String]) -> Result<Vec<String>, String> {
    if v.len() > 64 {
        return Err("at most 64 allowlist entries".into());
    }
    v.iter()
        .map(|s| {
            let s = s.trim();
            if let Ok(n) = s.parse::<ipnet::IpNet>() {
                Ok(n.trunc().to_string())
            } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                Ok(ipnet::IpNet::from(ip).to_string())
            } else {
                Err(format!("invalid CIDR {s:?}"))
            }
        })
        .collect()
}

async fn send_verdict(ws: &mut WebSocketStream<ServerTls>, v: &RelayVerdict) {
    if let Ok(s) = serde_json::to_string(v) {
        let _ = ws.send(Message::text(s)).await;
    }
}

fn verdict_error(code: &str, message: &str) -> RelayVerdict {
    RelayVerdict::Error {
        code: code.into(),
        message: message.into(),
    }
}

/// Serve an upgraded `/v1/node` WebSocket.
pub async fn serve_node(
    inner: Arc<RelayInner>,
    mut ws: WebSocketStream<ServerTls>,
    peer: SocketAddr,
) {
    let challenge = crypto::random32();
    let hello = RelayHello::Challenge {
        version: PROTOCOL_VERSION,
        challenge: hex::encode(challenge),
    };
    if ws
        .send(Message::text(
            serde_json::to_string(&hello).unwrap_or_default(),
        ))
        .await
        .is_err()
    {
        return;
    }
    let msg = match tokio::time::timeout(NODE_AUTH_TIMEOUT, ws.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t,
        _ => return,
    };
    let Ok(answer) = serde_json::from_str::<NodeHello>(msg.as_str()) else {
        send_verdict(&mut ws, &verdict_error("bad_request", "malformed hello")).await;
        return;
    };
    let record = match answer {
        NodeHello::Join {
            version,
            code,
            name,
            sign_pub,
            static_pub,
            signature,
        } => {
            let v = handle_join(
                &inner,
                peer,
                &challenge,
                version,
                &code,
                name.as_deref(),
                &sign_pub,
                &static_pub,
                &signature,
            );
            send_verdict(&mut ws, &v).await;
            let _ = ws.close(None).await;
            return;
        }
        NodeHello::Auth {
            version,
            node_id,
            sign_pub,
            signature,
        } => {
            if version != PROTOCOL_VERSION {
                send_verdict(
                    &mut ws,
                    &verdict_error("version", "unsupported protocol version"),
                )
                .await;
                return;
            }
            let rec = {
                let reg = inner.registry.read().unwrap();
                reg.nodes.get(&node_id).cloned()
            };
            let Some(rec) = rec else {
                let revoked = inner
                    .db
                    .nodes()
                    .map(|v| {
                        v.iter()
                            .any(|n| n.node_id == node_id && n.revoked_at.is_some())
                    })
                    .unwrap_or(false);
                let (code, msg) = if revoked {
                    ("revoked", "this node has been revoked")
                } else {
                    ("unknown_node", "this node is not enrolled on this relay")
                };
                tracing::info!(%peer, code, "node authentication refused");
                send_verdict(&mut ws, &verdict_error(code, msg)).await;
                return;
            };
            let sig = hex::decode(signature.trim()).unwrap_or_default();
            let claimed = crypto::parse_key32(&sign_pub);
            let ok = claimed.is_some_and(|k| crypto::ct_eq(&k, &rec.sign_pub))
                && crypto::verify(
                    &rec.sign_pub,
                    &crypto::auth_message(&challenge, &inner.cfg.domain),
                    &sig,
                );
            if !ok {
                tracing::info!(%peer, node = %rec.name, "node authentication failed: bad signature");
                send_verdict(
                    &mut ws,
                    &verdict_error("bad_signature", "authentication failed"),
                )
                .await;
                return;
            }
            rec
        }
    };

    let welcome = RelayVerdict::Welcome {
        node_id: record.node_id.clone(),
        name: record.name.clone(),
        publish_domain: inner.cfg.publish_domain.clone(),
        relay_version: crate::VERSION.to_string(),
    };
    send_verdict(&mut ws, &welcome).await;

    let (out, rx) = LinkOut::new(CancellationToken::new());
    let link = Arc::new(NodeLink {
        conn_id: inner.conn_id(),
        node_id: record.node_id.clone(),
        name: record.name.clone(),
        static_pub: record.static_pub,
        out: out.clone(),
        peer,
        table: Mutex::new(HashMap::new()),
        opens: Mutex::new(TokenBucket::new(MAX_OPENS_PER_SEC, MAX_OPENS_PER_SEC)),
        pings: Mutex::new(TokenBucket::new(10, 20)),
        ctrls: Mutex::new(TokenBucket::new(20, 40)),
        next_even: AtomicU32::new(2),
        last_pong: Mutex::new(Instant::now()),
    });
    if let Some(old) = inner
        .online
        .lock()
        .unwrap()
        .insert(record.node_id.clone(), link.clone())
    {
        old.out.close();
    }
    let _ = inner.db.touch_last_seen(&record.node_id, crate::now_secs());
    tracing::info!(node = %record.name, %peer, "node connected");

    let (sink, mut stream) = ws.split();
    let writer = tokio::spawn(mux::run_writer(
        sink,
        rx,
        out.clone(),
        inner.cfg.tap.clone(),
    ));
    let mut ping = tokio::time::interval(inner.cfg.ping_interval);
    ping.tick().await;
    let tap = inner.cfg.tap.clone();
    let reason = loop {
        tokio::select! {
            _ = out.token().cancelled() => break "link closed",
            _ = inner.shutdown.cancelled() => break "relay shutting down",
            _ = ping.tick() => {
                if link.last_pong.lock().unwrap().elapsed() > inner.cfg.ping_interval * 3 {
                    break "keepalive timeout";
                }
                let now = crate::now_secs().to_be_bytes();
                out.send(Frame::new(FrameType::Ping, CONTROL_STREAM, bytes::Bytes::copy_from_slice(&now)));
            }
            m = stream.next() => match m {
                Some(Ok(Message::Binary(b))) => {
                    if let Some(t) = &tap {
                        t(TapDir::In, &b);
                    }
                    match Frame::decode(b) {
                        Ok(f) => {
                            if let Err(e) = link.on_frame(&inner, f) {
                                break e;
                            }
                        }
                        Err(_) => break "malformed frame",
                    }
                }
                Some(Ok(Message::Text(_))) => break "unexpected text message",
                Some(Ok(Message::Close(_))) | None => break "closed by node",
                Some(Err(_)) => break "websocket error",
                Some(Ok(_)) => {}
            }
        }
    };
    tracing::info!(node = %link.name, reason, "node disconnected");
    out.close();
    {
        let mut online = inner.online.lock().unwrap();
        if online
            .get(&link.node_id)
            .is_some_and(|l| l.conn_id == link.conn_id)
        {
            online.remove(&link.node_id);
        }
    }
    link.teardown();
    let _ = inner.db.touch_last_seen(&link.node_id, crate::now_secs());
    let _ = tokio::time::timeout(Duration::from_secs(3), writer).await;
}

#[allow(clippy::too_many_arguments)]
fn handle_join(
    inner: &Arc<RelayInner>,
    peer: SocketAddr,
    challenge: &[u8; 32],
    version: u32,
    code: &str,
    name: Option<&str>,
    sign_pub: &str,
    static_pub: &str,
    signature: &str,
) -> RelayVerdict {
    let ip = peer.ip();
    if inner.join_limiter.lock().unwrap().blocked(ip) {
        tracing::warn!(%ip, "enrollment refused: too many failed attempts");
        return verdict_error(
            "rate_limited",
            "too many failed enrollment attempts from this address; try again later",
        );
    }
    let fail = |code: &str, msg: &str| {
        inner.join_limiter.lock().unwrap().record(ip);
        tracing::info!(%ip, reason = code, "enrollment failed");
        verdict_error(code, msg)
    };
    if version != PROTOCOL_VERSION {
        return verdict_error("version", "unsupported protocol version");
    }
    let Some(code) = crypto::normalize_code(code) else {
        return fail(
            "invalid_code",
            "invalid, expired or already used enrollment code",
        );
    };
    let (Some(sp), Some(xp)) = (
        crypto::parse_key32(sign_pub),
        crypto::parse_key32(static_pub),
    ) else {
        return fail("bad_request", "malformed keys");
    };
    let sig = hex::decode(signature.trim()).unwrap_or_default();
    if !crypto::verify(
        &sp,
        &crypto::join_message(challenge, &inner.cfg.domain, &xp),
        &sig,
    ) {
        return fail("bad_signature", "enrollment signature invalid");
    }
    if let Some(n) = name {
        if !crate::valid_name(n) {
            return verdict_error("bad_name", "names must match [a-z0-9-]{1,32}");
        }
    }
    match inner.db.join(&code, name, &sp, &xp, crate::now_secs()) {
        Ok(JoinOutcome::Joined(rec)) => {
            let _ = inner.reload();
            tracing::info!(node = %rec.name, %ip, "node enrolled");
            RelayVerdict::Joined {
                node_id: rec.node_id,
                name: rec.name,
                publish_domain: inner.cfg.publish_domain.clone(),
            }
        }
        Ok(JoinOutcome::InvalidCode) => fail(
            "invalid_code",
            "invalid, expired or already used enrollment code",
        ),
        Ok(JoinOutcome::NameTaken(n)) => verdict_error(
            "name_taken",
            &format!("the name {n:?} is already in use on this relay"),
        ),
        Ok(JoinOutcome::BadName(n)) if n.is_empty() => {
            verdict_error("bad_name", "a name is required (use --name)")
        }
        Ok(JoinOutcome::BadName(n)) => verdict_error("bad_name", &format!("invalid name {n:?}")),
        Ok(JoinOutcome::KeyInUse) => verdict_error("key_in_use", "this key is already registered"),
        Err(e) => {
            tracing::warn!("enrollment database error: {e:#}");
            verdict_error("internal", "internal error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidrs() {
        assert_eq!(
            normalize_cidrs(&["10.1.2.3/8".into(), "192.0.2.7".into(), "::1".into()]).unwrap(),
            vec!["10.0.0.0/8", "192.0.2.7/32", "::1/128"]
        );
        assert!(normalize_cidrs(&["nope".into()]).is_err());
        assert!(normalize_cidrs(&vec!["10.0.0.0/8".to_string(); 65]).is_err());
    }
}
