//! Stream multiplexing over one WebSocket: outbound queues, per-stream flow
//! control and the endpoint-side stream handles used by nodes and by the relay
//! for public traffic.

use crate::limits::{MAX_LINK_QUEUE, NODE_LINK_DATA_BUDGET};
use crate::proto::{ErrorCode, Frame, FrameType, MAX_PAYLOAD, MAX_WS_MESSAGE, STREAM_WINDOW};
use bytes::Bytes;
use futures_util::{task::AtomicWaker, Sink, SinkExt};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_util::sync::CancellationToken;

/// Upper bound on send credit a peer may grant for one stream. Prevents a
/// hostile peer from overflowing the credit counter.
const MAX_CREDIT: usize = 64 * 1024 * 1024;
/// Send WINDOW updates once this many bytes have been consumed.
const WINDOW_UPDATE_THRESHOLD: u32 = STREAM_WINDOW / 4;

/// Direction of a tapped message, from the point of view of the tapping side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapDir {
    In,
    Out,
}

/// Observer of raw binary WebSocket messages (used by tests to capture exactly
/// what the relay sees).
pub type Tap = Arc<dyn Fn(TapDir, &[u8]) + Send + Sync>;

/// One queued, encoded frame.
struct Queued {
    bytes: Bytes,
    /// Counted against the DATA budget (else against the control cap).
    data: bool,
}

/// Byte accounting shared by a link's queue and its writer.
struct Accounting {
    /// Bytes of frames that are not flow-controlled, capped at [`MAX_LINK_QUEUE`].
    ctrl: AtomicUsize,
    /// Bytes of DATA frames queued.
    data: AtomicUsize,
    /// Room for DATA bytes; senders wait for permits.
    budget: Semaphore,
    /// When the writer last moved a frame toward the socket (ms since `base`).
    progress_ms: AtomicU64,
    base: Instant,
}

impl Accounting {
    fn note_progress(&self) {
        let ms = self.base.elapsed().as_millis() as u64;
        self.progress_ms.fetch_max(ms, Ordering::AcqRel);
    }
}

/// Outbound frame queue of one link.
///
/// Two lanes feed the writer: connection-level frames that may overtake data
/// (PING, PONG, WINDOW, CTRL) and everything else in order (OPEN, OPEN_OK,
/// OPEN_ERR, DATA, CLOSE), so keepalives and credit updates are not stuck
/// behind a long data queue while a stream's DATA never overtakes its OPEN or
/// is overtaken by its FIN.
///
/// DATA is flow-controlled per stream and additionally bounded per link by a
/// byte budget: [`LinkOut::send_data`] waits for room instead of failing, so
/// legal traffic never tears the link down. Everything else goes through the
/// non-blocking [`LinkOut::send`], capped at [`MAX_LINK_QUEUE`] bytes: a peer
/// that stops reading while provoking replies is disconnected.
#[derive(Clone)]
pub struct LinkOut {
    prio: mpsc::UnboundedSender<Queued>,
    ordered: mpsc::UnboundedSender<Queued>,
    acct: Arc<Accounting>,
    closed: CancellationToken,
}

/// Receiving end of a [`LinkOut`], drained by [`run_writer`].
pub struct LinkRx {
    prio: mpsc::UnboundedReceiver<Queued>,
    ordered: mpsc::UnboundedReceiver<Queued>,
    acct: Arc<Accounting>,
}

impl LinkRx {
    fn release(&self, q: Queued) -> Bytes {
        let n = q.bytes.len();
        if q.data {
            self.acct.data.fetch_sub(n, Ordering::AcqRel);
            self.acct.budget.add_permits(n);
        } else {
            self.acct.ctrl.fetch_sub(n, Ordering::AcqRel);
        }
        q.bytes
    }

    /// Next encoded frame to write (connection-level frames first); `None`
    /// once every [`LinkOut`] clone is gone.
    pub async fn recv(&mut self) -> Option<Bytes> {
        let q = tokio::select! {
            biased;
            Some(q) = self.prio.recv() => q,
            Some(q) = self.ordered.recv() => q,
            else => return None,
        };
        Some(self.release(q))
    }

    /// Next encoded frame if one is queued.
    pub fn try_recv(&mut self) -> Option<Bytes> {
        let q = match self.prio.try_recv() {
            Ok(q) => q,
            Err(_) => self.ordered.try_recv().ok()?,
        };
        Some(self.release(q))
    }
}

fn is_priority(ty: FrameType) -> bool {
    matches!(
        ty,
        FrameType::Ping | FrameType::Pong | FrameType::Window | FrameType::Ctrl
    )
}

impl LinkOut {
    /// A queue with the node-side DATA budget ([`NODE_LINK_DATA_BUDGET`]).
    pub fn new(closed: CancellationToken) -> (LinkOut, LinkRx) {
        LinkOut::with_data_budget(closed, NODE_LINK_DATA_BUDGET)
    }

    /// A queue whose DATA senders wait once `budget` bytes are queued.
    pub fn with_data_budget(closed: CancellationToken, budget: usize) -> (LinkOut, LinkRx) {
        let (ptx, prx) = mpsc::unbounded_channel();
        let (otx, orx) = mpsc::unbounded_channel();
        let acct = Arc::new(Accounting {
            ctrl: AtomicUsize::new(0),
            data: AtomicUsize::new(0),
            // At least one maximal frame must always fit.
            budget: Semaphore::new(budget.max(MAX_WS_MESSAGE)),
            progress_ms: AtomicU64::new(0),
            base: Instant::now(),
        });
        (
            LinkOut {
                prio: ptx,
                ordered: otx,
                acct: acct.clone(),
                closed,
            },
            LinkRx {
                prio: prx,
                ordered: orx,
                acct,
            },
        )
    }

    /// Queue a frame without waiting. Returns false if the link is closed (or
    /// was just closed because the peer stopped reading: more than
    /// [`MAX_LINK_QUEUE`] bytes of such frames are queued).
    pub fn send(&self, f: Frame) -> bool {
        if self.closed.is_cancelled() {
            return false;
        }
        let prio = is_priority(f.ty);
        let b = f.encode();
        let n = b.len();
        let q = self.acct.ctrl.fetch_add(n, Ordering::AcqRel) + n;
        if q > MAX_LINK_QUEUE {
            tracing::warn!("link outbound queue exceeded {MAX_LINK_QUEUE} bytes; closing link");
            self.acct.ctrl.fetch_sub(n, Ordering::AcqRel);
            self.closed.cancel();
            return false;
        }
        let lane = if prio { &self.prio } else { &self.ordered };
        if lane
            .send(Queued {
                bytes: b,
                data: false,
            })
            .is_err()
        {
            self.acct.ctrl.fetch_sub(n, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Queue a DATA frame, waiting while the link's DATA budget is used up.
    /// Returns false if the link is (or gets) closed.
    pub async fn send_data(&self, f: Frame) -> bool {
        self.send_data_on(f, None).await
    }

    async fn send_data_on(&self, f: Frame, stream: Option<&StreamShared>) -> bool {
        if self.closed.is_cancelled() {
            return false;
        }
        let b = f.encode();
        let n = b.len();
        let permit = tokio::select! {
            p = self.acct.budget.acquire_many(n as u32) => match p {
                Ok(p) => p,
                Err(_) => return false,
            },
            _ = self.closed.cancelled() => return false,
        };
        // The final enqueue and terminal reset use the same short gate.
        // A retired allocation cannot enqueue into a reused numeric route.
        let retired = stream.map(|s| s.retired.lock().unwrap());
        if retired.as_ref().is_some_and(|r| **r) {
            return false;
        }
        permit.forget();
        self.acct.data.fetch_add(n, Ordering::AcqRel);
        if self.closed.is_cancelled()
            || self
                .ordered
                .send(Queued {
                    bytes: b,
                    data: true,
                })
                .is_err()
        {
            self.acct.data.fetch_sub(n, Ordering::AcqRel);
            self.acct.budget.add_permits(n);
            return false;
        }
        true
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub fn close(&self) {
        self.closed.cancel();
    }

    pub fn token(&self) -> &CancellationToken {
        &self.closed
    }

    /// Bytes currently queued (DATA and everything else).
    pub fn queued_bytes(&self) -> usize {
        self.acct.ctrl.load(Ordering::Acquire) + self.acct.data.load(Ordering::Acquire)
    }

    /// DATA bytes currently queued.
    pub fn queued_data(&self) -> usize {
        self.acct.data.load(Ordering::Acquire)
    }

    /// How long this link's writer has made no progress, counting from
    /// `since` at the earliest (the moment a sender started waiting).
    pub fn stalled_for(&self, since: Instant) -> std::time::Duration {
        let last = self.acct.base
            + std::time::Duration::from_millis(self.acct.progress_ms.load(Ordering::Acquire));
        Instant::now().saturating_duration_since(last.max(since))
    }
}

/// Drain a link's outbound queue into the WebSocket sink, batching writes.
pub async fn run_writer<S>(mut sink: S, mut rx: LinkRx, out: LinkOut, tap: Option<Tap>)
where
    S: Sink<Message, Error = WsError> + Unpin,
{
    loop {
        let first = tokio::select! {
            _ = out.closed.cancelled() => break,
            m = rx.recv() => m,
        };
        let Some(first) = first else { break };
        let mut batch = vec![first];
        while batch.len() < 64 {
            match rx.try_recv() {
                Some(b) => batch.push(b),
                None => break,
            }
        }
        let mut failed = false;
        for b in batch {
            if let Some(t) = &tap {
                t(TapDir::Out, &b);
            }
            if sink.feed(Message::Binary(b)).await.is_err() {
                failed = true;
                break;
            }
            out.acct.note_progress();
        }
        if failed || sink.flush().await.is_err() {
            out.close();
            break;
        }
        out.acct.note_progress();
    }
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sink.close()).await;
}

/// Events delivered to an endpoint stream.
#[derive(Debug)]
pub enum StreamEvent {
    Data(Bytes),
    Fin,
    Reset(ErrorCode),
}

/// Result of an OPEN: `Err((code, message))` when refused.
pub type OpenResult = Result<(), (ErrorCode, String)>;

/// State shared between a stream's table slot and its handles.
pub struct StreamShared {
    pub id: u32,
    credit: Semaphore,
    recv_outstanding: AtomicU32,
    fin_sent: AtomicBool,
    fin_recv: AtomicBool,
    reset: AtomicBool,
    // Serializes terminal ownership and synchronous wire enqueue, never awaits
    // or host table removal. Exactly one terminal path owns numeric cleanup.
    retired: Mutex<bool>,
    local_abort: CancellationToken,
    read_waker: AtomicWaker,
}

impl StreamShared {
    fn new(id: u32) -> StreamShared {
        StreamShared {
            id,
            credit: Semaphore::new(STREAM_WINDOW as usize),
            recv_outstanding: AtomicU32::new(0),
            fin_sent: AtomicBool::new(false),
            fin_recv: AtomicBool::new(false),
            reset: AtomicBool::new(false),
            retired: Mutex::new(false),
            local_abort: CancellationToken::new(),
            read_waker: AtomicWaker::new(),
        }
    }

    fn fully_closed(&self) -> bool {
        self.reset.load(Ordering::SeqCst)
            || (self.fin_sent.load(Ordering::SeqCst) && self.fin_recv.load(Ordering::SeqCst))
    }
}

/// Something that owns a table of streams on one link.
pub trait StreamHost: Send + Sync + 'static {
    fn out(&self) -> &LinkOut;
    fn remove_stream(&self, id: u32);
}

/// Table entry for an endpoint stream; the link reader delivers frames to it.
pub struct Slot {
    tx: mpsc::UnboundedSender<StreamEvent>,
    shared: Arc<StreamShared>,
    open_reply: Option<oneshot::Sender<OpenResult>>,
}

impl Slot {
    /// Deliver a frame. Returns true if the slot must be removed from the table.
    pub fn deliver(&mut self, f: Frame, out: &LinkOut) -> bool {
        let shared = self.shared.clone();
        let mut retired = shared.retired.lock().unwrap();
        if *retired {
            // Another path owns removal; do not free the ID ahead of it.
            return false;
        }
        let id = self.shared.id;
        match f.ty {
            FrameType::Data => {
                let n = f.payload.len() as u32;
                let prev = self.shared.recv_outstanding.fetch_add(n, Ordering::AcqRel);
                if prev.saturating_add(n) > STREAM_WINDOW {
                    tracing::debug!(stream = id, "window overrun; resetting stream");
                    out.send(Frame::reset(id, ErrorCode::WindowOverrun));
                    self.kill_inner(ErrorCode::WindowOverrun);
                    *retired = true;
                    return true;
                }
                let _ = self.tx.send(StreamEvent::Data(f.payload));
                false
            }
            FrameType::Window => {
                let Ok(n) = f.window_credit() else {
                    out.send(Frame::reset(id, ErrorCode::Protocol));
                    self.kill_inner(ErrorCode::Protocol);
                    *retired = true;
                    return true;
                };
                if self.shared.credit.available_permits() + n as usize > MAX_CREDIT {
                    out.send(Frame::reset(id, ErrorCode::Protocol));
                    self.kill_inner(ErrorCode::Protocol);
                    *retired = true;
                    return true;
                }
                self.shared.credit.add_permits(n as usize);
                false
            }
            FrameType::Close => match f.close_kind() {
                None => {
                    self.shared.fin_recv.store(true, Ordering::SeqCst);
                    let _ = self.tx.send(StreamEvent::Fin);
                    let closed = self.shared.fully_closed();
                    *retired = closed;
                    closed
                }
                Some(code) => {
                    self.kill_inner(code);
                    *retired = true;
                    true
                }
            },
            FrameType::OpenOk => {
                if let Some(r) = self.open_reply.take() {
                    let _ = r.send(Ok(()));
                }
                false
            }
            FrameType::OpenErr => {
                let (code, msg) = f.open_error();
                if let Some(r) = self.open_reply.take() {
                    let _ = r.send(Err((code, msg)));
                }
                self.kill_inner(code);
                *retired = true;
                true
            }
            _ => false,
        }
    }

    /// Abort the stream locally (link died or protocol error).
    pub fn kill(&mut self, code: ErrorCode) {
        *self.shared.retired.lock().unwrap() = true;
        self.kill_inner(code);
    }

    fn kill_inner(&mut self, code: ErrorCode) {
        self.shared.reset.store(true, Ordering::SeqCst);
        self.shared.credit.close();
        if let Some(r) = self.open_reply.take() {
            let _ = r.send(Err((code, "stream aborted".into())));
        }
        let _ = self.tx.send(StreamEvent::Reset(code));
    }

    pub fn id(&self) -> u32 {
        self.shared.id
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        // Detached slots can never grant an old handle numeric-route custody.
        *self.shared.retired.lock().unwrap() = true;
    }
}

struct Guard {
    host: Arc<dyn StreamHost>,
    shared: Arc<StreamShared>,
}

impl Guard {
    fn reset(&self, code: ErrorCode) {
        let owns_cleanup = {
            let mut retired = self.shared.retired.lock().unwrap();
            let owns_cleanup = !*retired;
            *retired = true;
            self.shared.reset.store(true, Ordering::SeqCst);
            self.shared.local_abort.cancel();
            self.shared.read_waker.wake();
            self.shared.credit.close();
            if owns_cleanup {
                self.host.out().send(Frame::reset(self.shared.id, code));
            }
            owns_cleanup
        };
        // Never acquire the host table while holding the retirement gate:
        // frame delivery owns the table before acquiring that gate.
        if owns_cleanup {
            self.host.remove_stream(self.shared.id);
        }
    }
}

/// Weak reset-only capability: no stream, link or encryption ownership.
#[derive(Clone)]
pub(crate) struct MuxAbort(Weak<Guard>);

impl MuxAbort {
    pub(crate) fn abort(&self) {
        if let Some(guard) = self.0.upgrade() {
            guard.reset(ErrorCode::Aborted);
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.reset(ErrorCode::Aborted);
    }
}

/// Create an endpoint stream. The caller inserts the returned [`Slot`] into its
/// table *before* sending OPEN (outgoing) or before processing further frames
/// (incoming).
pub fn new_stream(
    id: u32,
    host: Arc<dyn StreamHost>,
    outgoing: bool,
) -> (
    Slot,
    MuxSender,
    MuxReceiver,
    Option<oneshot::Receiver<OpenResult>>,
) {
    let shared = Arc::new(StreamShared::new(id));
    let (tx, rx) = mpsc::unbounded_channel();
    let (otx, orx) = if outgoing {
        let (a, b) = oneshot::channel();
        (Some(a), Some(b))
    } else {
        (None, None)
    };
    let guard = Arc::new(Guard {
        host: host.clone(),
        shared: shared.clone(),
    });
    let slot = Slot {
        tx,
        shared: shared.clone(),
        open_reply: otx,
    };
    let sender = MuxSender {
        host: host.clone(),
        shared: shared.clone(),
        _guard: guard.clone(),
    };
    let receiver = MuxReceiver {
        host,
        shared,
        rx,
        unacked: 0,
        leftover: Bytes::new(),
        eof: false,
        _guard: guard,
    };
    (slot, sender, receiver, orx)
}

/// Sending half of an endpoint stream.
pub struct MuxSender {
    host: Arc<dyn StreamHost>,
    shared: Arc<StreamShared>,
    _guard: Arc<Guard>,
}

fn broken(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, msg.to_string())
}

impl MuxSender {
    pub(crate) fn abort_handle(&self) -> MuxAbort {
        MuxAbort(Arc::downgrade(&self._guard))
    }

    pub fn id(&self) -> u32 {
        self.shared.id
    }

    /// Send one DATA frame (at most [`MAX_PAYLOAD`] bytes), waiting for credit.
    pub async fn send(&self, data: Bytes) -> io::Result<()> {
        if self.shared.local_abort.is_cancelled() {
            return Err(broken("stream reset"));
        }
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame too large",
            ));
        }
        if self.shared.fin_sent.load(Ordering::SeqCst) {
            return Err(broken("stream already finished"));
        }
        let permit = self
            .shared
            .credit
            .acquire_many(data.len() as u32)
            .await
            .map_err(|_| broken("stream closed"))?;
        permit.forget();
        if self.shared.reset.load(Ordering::SeqCst) {
            return Err(broken("stream reset"));
        }
        let sent = tokio::select! {
            biased;
            _ = self.shared.local_abort.cancelled() => return Err(broken("stream reset")),
            sent = self.host.out().send_data_on(Frame::data(self.shared.id, data), Some(&self.shared)) => sent,
        };
        if !sent {
            return Err(broken("link closed"));
        }
        Ok(())
    }

    /// Send arbitrary bytes, split into frames.
    pub async fn send_all(&self, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(MAX_PAYLOAD) {
            self.send(Bytes::copy_from_slice(chunk)).await?;
        }
        Ok(())
    }

    /// Graceful half-close (FIN).
    pub fn finish(&self) {
        let owns_cleanup = {
            let mut retired = self.shared.retired.lock().unwrap();
            if *retired || self.shared.fin_sent.swap(true, Ordering::SeqCst) {
                return;
            }
            self.host.out().send(Frame::fin(self.shared.id));
            let closed = self.shared.fully_closed();
            *retired = closed;
            closed
        };
        if owns_cleanup {
            self.host.remove_stream(self.shared.id);
        }
    }

    /// Abort the stream in both directions.
    pub fn reset(&self, code: ErrorCode) {
        self._guard.reset(code);
    }

    /// Refuse an incoming OPEN.
    pub fn reject(&self, code: ErrorCode, msg: &str) {
        {
            let mut retired = self.shared.retired.lock().unwrap();
            if *retired {
                return;
            }
            *retired = true;
            self.shared.reset.store(true, Ordering::SeqCst);
            self.host
                .out()
                .send(Frame::open_err(self.shared.id, code, msg));
            self.shared.credit.close();
        }
        self.host.remove_stream(self.shared.id);
    }

    /// Accept an incoming OPEN.
    pub fn accept(&self) -> bool {
        let retired = self.shared.retired.lock().unwrap();
        !*retired && self.host.out().send(Frame::open_ok(self.shared.id))
    }

    pub fn is_reset(&self) -> bool {
        self.shared.reset.load(Ordering::SeqCst)
    }
}

/// Receiving half of an endpoint stream. Also usable as an [`AsyncRead`].
pub struct MuxReceiver {
    host: Arc<dyn StreamHost>,
    shared: Arc<StreamShared>,
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    unacked: u32,
    leftover: Bytes,
    eof: bool,
    _guard: Arc<Guard>,
}

impl MuxReceiver {
    pub fn id(&self) -> u32 {
        self.shared.id
    }

    fn credit(&mut self, n: usize) {
        let retired = self.shared.retired.lock().unwrap();
        if *retired {
            return;
        }
        self.unacked += n as u32;
        if self.unacked >= WINDOW_UPDATE_THRESHOLD {
            let n = self.unacked;
            self.unacked = 0;
            // Decrease the outstanding count *before* granting, so the reader
            // never sees a legitimate sender as overrunning.
            self.shared.recv_outstanding.fetch_sub(n, Ordering::AcqRel);
            self.host.out().send(Frame::window(self.shared.id, n));
        }
    }

    /// Next DATA payload; `Ok(None)` on FIN.
    pub async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        if self.shared.local_abort.is_cancelled() {
            return Err(reset_error(ErrorCode::Aborted));
        }
        if self.eof {
            return Ok(None);
        }
        let event = tokio::select! {
            biased;
            _ = self.shared.local_abort.cancelled() => return Err(reset_error(ErrorCode::Aborted)),
            event = self.rx.recv() => event,
        };
        match event {
            Some(StreamEvent::Data(b)) => {
                self.credit(b.len());
                Ok(Some(b))
            }
            Some(StreamEvent::Fin) => {
                self.eof = true;
                Ok(None)
            }
            Some(StreamEvent::Reset(code)) => Err(reset_error(code)),
            None => Err(reset_error(ErrorCode::LinkClosed)),
        }
    }
}

/// io::Error for a reset stream, carrying the code in its message.
pub fn reset_error(code: ErrorCode) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        format!("stream reset: {code}"),
    )
}

impl AsyncRead for MuxReceiver {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.shared.read_waker.register(cx.waker());
        if this.shared.local_abort.is_cancelled() {
            return Poll::Ready(Err(reset_error(ErrorCode::Aborted)));
        }
        if this.leftover.is_empty() {
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(StreamEvent::Data(b))) => {
                    this.credit(b.len());
                    this.leftover = b;
                }
                Poll::Ready(Some(StreamEvent::Fin)) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(StreamEvent::Reset(code))) => {
                    return Poll::Ready(Err(reset_error(code)))
                }
                Poll::Ready(None) => return Poll::Ready(Err(reset_error(ErrorCode::LinkClosed))),
            }
        }
        let n = this.leftover.len().min(buf.remaining());
        buf.put_slice(&this.leftover.split_to(n));
        Poll::Ready(Ok(()))
    }
}

/// Wait for OPEN_OK / OPEN_ERR with a timeout.
pub async fn wait_open(
    reply: oneshot::Receiver<OpenResult>,
    timeout: std::time::Duration,
) -> OpenResult {
    match tokio::time::timeout(timeout, reply).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => Err((ErrorCode::LinkClosed, "link closed".into())),
        Err(_) => Err((ErrorCode::Internal, "timed out waiting for the peer".into())),
    }
}

/// Copy an [`AsyncRead`] into a stream until EOF, then FIN.
pub async fn copy_to_stream<R>(mut r: R, tx: &MuxSender) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut total = 0u64;
    let mut buf = vec![0u8; MAX_PAYLOAD];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            tx.finish();
            return Ok(total);
        }
        total += n as u64;
        tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
    }
}

/// Copy a stream into an [`tokio::io::AsyncWrite`] until FIN, then shut down the writer.
pub async fn copy_from_stream<W>(rx: &mut MuxReceiver, mut w: W) -> io::Result<u64>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut total = 0u64;
    while let Some(b) = rx.recv().await? {
        total += b.len() as u64;
        w.write_all(&b).await?;
        w.flush().await?;
    }
    let _ = w.shutdown().await;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A loopback host: frames sent by one side are delivered to the other.
    struct TestHost {
        out: LinkOut,
        table: Mutex<HashMap<u32, Slot>>,
    }

    impl StreamHost for TestHost {
        fn out(&self) -> &LinkOut {
            &self.out
        }
        fn remove_stream(&self, id: u32) {
            self.table.lock().unwrap().remove(&id);
        }
    }

    fn host() -> (Arc<TestHost>, LinkRx) {
        let (out, rx) = LinkOut::new(CancellationToken::new());
        (
            Arc::new(TestHost {
                out,
                table: Mutex::new(HashMap::new()),
            }),
            rx,
        )
    }

    fn deliver(h: &TestHost, raw: Bytes) {
        let f = Frame::decode(raw).unwrap();
        let mut t = h.table.lock().unwrap();
        if let Some(s) = t.get_mut(&f.stream) {
            let out = h.out.clone();
            if s.deliver(f.clone(), &out) {
                t.remove(&f.stream);
            }
        }
    }

    #[tokio::test]
    async fn retired_abort_and_last_drop_preserve_reused_id() {
        let (h, mut wire) = host();
        let (slot, tx, mut rx, _) = new_stream(11, h.clone(), false);
        h.table.lock().unwrap().insert(11, slot);
        let abort = tx.abort_handle();
        tx.finish();
        deliver(&h, Frame::fin(11).encode());
        assert!(rx.recv().await.unwrap().is_none());
        assert!(h.table.lock().unwrap().is_empty());
        while wire.try_recv().is_some() {}
        let (new_slot, new_tx, _new_rx, _) = new_stream(11, h.clone(), false);
        h.table.lock().unwrap().insert(11, new_slot);
        abort.abort();
        drop(tx);
        drop(rx); // The last old Guard must not remove the replacement.
        assert!(h.table.lock().unwrap().contains_key(&11));
        assert!(wire.try_recv().is_none());
        new_tx
            .send(Bytes::from_static(b"replacement survives"))
            .await
            .unwrap();
        assert_eq!(
            Frame::decode(wire.try_recv().unwrap()).unwrap().ty,
            FrameType::Data
        );
    }

    #[tokio::test]
    async fn retired_receive_and_accept_cannot_emit_on_reused_id() {
        let (h, mut wire) = host();
        let (slot, tx, mut rx, _) = new_stream(15, h.clone(), false);
        h.table.lock().unwrap().insert(15, slot);
        deliver(
            &h,
            Frame::data(15, Bytes::from(vec![0; MAX_PAYLOAD])).encode(),
        );
        tx.finish();
        deliver(&h, Frame::fin(15).encode());
        while wire.try_recv().is_some() {}
        let (slot, _new_tx, _new_rx, _) = new_stream(15, h.clone(), false);
        h.table.lock().unwrap().insert(15, slot);
        assert!(rx.recv().await.unwrap().is_some()); // drain old buffered bytes
        assert!(!tx.accept());
        assert!(
            wire.try_recv().is_none(),
            "old WINDOW/OPEN_OK must not reach a reused route"
        );
    }

    #[tokio::test]
    async fn retirement_claim_cannot_release_id_before_claimant_cleanup() {
        struct PausedHost {
            out: LinkOut,
            table: Mutex<HashMap<u32, Slot>>,
            paused: AtomicBool,
            entered: std::sync::mpsc::Sender<()>,
            resume: Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl StreamHost for PausedHost {
            fn out(&self) -> &LinkOut {
                &self.out
            }
            fn remove_stream(&self, id: u32) {
                if !self.paused.swap(true, Ordering::SeqCst) {
                    self.entered.send(()).unwrap();
                    self.resume
                        .lock()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                }
                self.table.lock().unwrap().remove(&id);
            }
        }
        let (out, _wire) = LinkOut::new(CancellationToken::new());
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let h = Arc::new(PausedHost {
            out,
            table: Mutex::new(HashMap::new()),
            paused: AtomicBool::new(false),
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
        });
        let (slot, tx, rx, _) = new_stream(13, h.clone(), false);
        h.table.lock().unwrap().insert(13, slot);
        tx.finish(); // Incoming FIN would normally release this slot.
        let abort = tx.abort_handle();
        let worker = std::thread::spawn(move || abort.abort());
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        {
            let mut table = h.table.lock().unwrap();
            // Force delivery while the reset claimant is paused immediately
            // before numeric removal. It must not release the route early.
            assert!(!table.get_mut(&13).unwrap().deliver(Frame::fin(13), &h.out));
            assert!(!table
                .get_mut(&13)
                .unwrap()
                .deliver(Frame::reset(13, ErrorCode::Aborted), &h.out));
            assert!(table.contains_key(&13));
        }
        resume_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(h.table.lock().unwrap().is_empty());
        let (slot, new_tx, _new_rx, _) = new_stream(13, h.clone(), false);
        h.table.lock().unwrap().insert(13, slot);
        drop(tx);
        drop(rx);
        assert!(h.table.lock().unwrap().contains_key(&13));
        new_tx
            .send(Bytes::from_static(b"new allocation"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn abort_wakes_link_budget_and_async_read_without_direction_access() {
        let (out, mut wire) = LinkOut::with_data_budget(CancellationToken::new(), MAX_WS_MESSAGE);
        let h = Arc::new(TestHost {
            out,
            table: Mutex::new(HashMap::new()),
        });
        let (slot, tx, mut rx, _) = new_stream(7, h.clone(), false);
        h.table.lock().unwrap().insert(7, slot);
        let abort = tx.abort_handle();
        tx.send(Bytes::from(vec![0; MAX_PAYLOAD])).await.unwrap();
        {
            let send = tx.send(Bytes::from_static(b"blocked on link budget"));
            let mut byte = [0];
            let read = tokio::io::AsyncReadExt::read(&mut rx, &mut byte);
            tokio::pin!(send, read);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                    send.as_mut(),
                    cx
                )))
                .await
                .is_pending()
            );
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                    read.as_mut(),
                    cx
                )))
                .await
                .is_pending()
            );
            abort.abort();
            abort.clone().abort();
            let (s, r) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                tokio::join!(&mut send, &mut read)
            })
            .await
            .unwrap();
            assert!(s.is_err());
            assert!(r.is_err());
        }
        assert!(tx.send(Bytes::new()).await.is_err());
        assert!(rx.recv().await.is_err());
        let frames: Vec<_> = std::iter::from_fn(|| wire.try_recv())
            .map(|f| Frame::decode(f).unwrap())
            .collect();
        assert_eq!(
            frames
                .iter()
                .filter(|f| f.close_kind() == Some(ErrorCode::Aborted) && f.ty == FrameType::Close)
                .count(),
            1
        );
        assert_eq!(frames.iter().filter(|f| f.ty == FrameType::Data).count(), 1);
    }

    #[tokio::test]
    async fn weak_abort_handle_does_not_retain_stream_or_host() {
        let (h, mut wire) = host();
        let weak_host = Arc::downgrade(&h);
        let (slot, tx, rx, _) = new_stream(9, h.clone(), false);
        h.table.lock().unwrap().insert(9, slot);
        let abort = tx.abort_handle();
        let weak_guard = abort.0.clone();
        drop(tx);
        assert!(weak_guard.upgrade().is_some());
        drop(rx);
        assert!(weak_guard.upgrade().is_none());
        assert!(h.table.lock().unwrap().is_empty());
        drop(h);
        assert!(weak_host.upgrade().is_none());
        abort.abort();
        assert!(wire.try_recv().is_some()); // ordinary last-half drop reset
        assert!(wire.try_recv().is_none()); // dead weak handle sent nothing
    }

    #[tokio::test]
    async fn data_flow_and_credit() {
        let (a, mut a_wire) = host();
        let (b, mut b_wire) = host();
        let (sa, txa, mut rxa, _) = new_stream(1, a.clone(), true);
        let (sb, txb, mut rxb, _) = new_stream(1, b.clone(), false);
        a.table.lock().unwrap().insert(1, sa);
        b.table.lock().unwrap().insert(1, sb);

        // Pump frames between the two hosts.
        let (a2, b2) = (a.clone(), b.clone());
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(m) = a_wire.recv() => deliver(&b2, m),
                    Some(m) = b_wire.recv() => deliver(&a2, m),
                    else => break,
                }
            }
        });

        // 1 MiB exceeds the window several times over: credit must flow back.
        let payload: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
        let p2 = payload.clone();
        let send = tokio::spawn(async move {
            txa.send_all(&p2).await.unwrap();
            txa.finish();
            txa
        });
        let mut got = Vec::new();
        while let Some(b) = rxb.recv().await.unwrap() {
            got.extend_from_slice(&b);
        }
        assert_eq!(got, payload);
        let _txa = send.await.unwrap();
        txb.finish();
        assert!(rxa.recv().await.unwrap().is_none());
        pump.abort();
    }

    #[tokio::test]
    async fn overrun_resets_stream() {
        let (b, mut b_wire) = host();
        let (sb, _txb, mut rxb, _) = new_stream(3, b.clone(), false);
        b.table.lock().unwrap().insert(3, sb);
        // Deliver more than the window without any credit being granted.
        let chunk = Bytes::from(vec![0u8; MAX_PAYLOAD]);
        for _ in 0..5 {
            deliver(&b, Frame::data(3, chunk.clone()).encode());
        }
        assert!(b.table.lock().unwrap().is_empty());
        // Reset frame was sent back.
        let mut saw_reset = false;
        while let Some(m) = b_wire.try_recv() {
            let f = Frame::decode(m).unwrap();
            if f.ty == FrameType::Close && f.close_kind() == Some(ErrorCode::WindowOverrun) {
                saw_reset = true;
            }
        }
        assert!(saw_reset);
        // Receiver sees the data that fit, then the reset.
        let mut n = 0;
        let err = loop {
            match rxb.recv().await {
                Ok(Some(b)) => n += b.len(),
                Ok(None) => panic!("unexpected fin"),
                Err(e) => break e,
            }
        };
        assert!(n <= STREAM_WINDOW as usize);
        assert!(err.to_string().contains("window_overrun"));
    }

    #[tokio::test]
    async fn drop_sends_reset_and_frees_slot() {
        let (a, mut wire) = host();
        let (sa, txa, rxa, _) = new_stream(5, a.clone(), true);
        a.table.lock().unwrap().insert(5, sa);
        drop(txa);
        drop(rxa);
        assert!(a.table.lock().unwrap().is_empty());
        let f = Frame::decode(wire.recv().await.unwrap()).unwrap();
        assert_eq!(f.ty, FrameType::Close);
        assert_eq!(f.close_kind(), Some(ErrorCode::Aborted));
    }

    #[tokio::test]
    async fn queue_cap_closes_link() {
        let (out, _rx) = LinkOut::new(CancellationToken::new());
        let big = Bytes::from(vec![0u8; MAX_PAYLOAD]);
        let mut sent = 0usize;
        while out.send(Frame::data(1, big.clone())) {
            sent += 1;
            assert!(sent < 10_000);
        }
        assert!(out.is_closed());
        assert!(sent * MAX_PAYLOAD <= MAX_LINK_QUEUE);
    }

    #[tokio::test]
    async fn data_budget_waits_instead_of_closing() {
        let (out, mut rx) = LinkOut::with_data_budget(CancellationToken::new(), 3 * MAX_WS_MESSAGE);
        let big = Bytes::from(vec![0u8; MAX_PAYLOAD]);
        for _ in 0..3 {
            assert!(out.send_data(Frame::data(1, big.clone())).await);
        }
        // The budget is used up: the next DATA waits, and the link stays open.
        let o2 = out.clone();
        let b2 = big.clone();
        let waiting = tokio::spawn(async move { o2.send_data(Frame::data(1, b2)).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        assert!(!out.is_closed());
        // Control frames still get through (and are not stuck behind DATA).
        assert!(out.send(Frame::new(FrameType::Ping, 0, Bytes::from_static(b"p"))));
        let first = Frame::decode(rx.recv().await.unwrap()).unwrap();
        assert_eq!(first.ty, FrameType::Ping);
        // Draining makes room for the waiting sender.
        rx.recv().await.unwrap();
        assert!(waiting.await.unwrap());
        assert_eq!(out.queued_data(), 3 * MAX_WS_MESSAGE);
        // Closing wakes waiters with a failure.
        let o3 = out.clone();
        let blocked = tokio::spawn(async move { o3.send_data(Frame::data(1, big)).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        out.close();
        assert!(!blocked.await.unwrap());
    }

    #[tokio::test]
    async fn stall_is_measured_from_the_last_progress() {
        let (out, rx) = LinkOut::new(CancellationToken::new());
        let t0 = Instant::now();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        // A sender that just started waiting is not stalled, however long the
        // link was idle before.
        assert!(out.stalled_for(Instant::now()) < std::time::Duration::from_millis(5));
        assert!(out.stalled_for(t0) >= std::time::Duration::from_millis(30));
        drop(rx);
    }

    #[tokio::test]
    async fn fin_never_overtakes_data() {
        let (out, mut rx) = LinkOut::new(CancellationToken::new());
        assert!(out.send(Frame::new(FrameType::Open, 1, Bytes::new())));
        assert!(
            out.send_data(Frame::data(1, Bytes::from_static(b"x")))
                .await
        );
        assert!(out.send(Frame::fin(1)));
        assert!(out.send(Frame::window(3, 10)));
        let order: Vec<FrameType> = std::iter::from_fn(|| rx.try_recv())
            .map(|b| Frame::decode(b).unwrap().ty)
            .collect();
        assert_eq!(
            order,
            vec![
                FrameType::Window,
                FrameType::Open,
                FrameType::Data,
                FrameType::Close
            ]
        );
        assert_eq!(out.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn excessive_credit_is_protocol_error() {
        let (b, _wire) = host();
        let (sb, _tx, _rx, _) = new_stream(7, b.clone(), false);
        b.table.lock().unwrap().insert(7, sb);
        deliver(&b, Frame::window(7, u32::MAX).encode());
        assert!(b.table.lock().unwrap().is_empty());
    }
}
