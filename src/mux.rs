//! Stream multiplexing over one WebSocket: outbound queues, per-stream flow
//! control and the endpoint-side stream handles used by nodes and by the relay
//! for public traffic.

use crate::limits::MAX_LINK_QUEUE;
use crate::proto::{ErrorCode, Frame, FrameType, MAX_PAYLOAD, STREAM_WINDOW};
use bytes::Bytes;
use futures_util::{Sink, SinkExt};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
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

/// Outbound frame queue of one link. Unbounded in slots but capped in bytes:
/// a link that stops reading is closed instead of consuming unbounded memory.
#[derive(Clone)]
pub struct LinkOut {
    tx: mpsc::UnboundedSender<Bytes>,
    queued: Arc<AtomicUsize>,
    closed: CancellationToken,
}

impl LinkOut {
    pub fn new(closed: CancellationToken) -> (LinkOut, mpsc::UnboundedReceiver<Bytes>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            LinkOut {
                tx,
                queued: Arc::new(AtomicUsize::new(0)),
                closed,
            },
            rx,
        )
    }

    /// Queue a frame. Returns false if the link is closed (or was just closed
    /// for exceeding its queue cap).
    pub fn send(&self, f: Frame) -> bool {
        if self.closed.is_cancelled() {
            return false;
        }
        let b = f.encode();
        let n = b.len();
        let q = self.queued.fetch_add(n, Ordering::AcqRel) + n;
        if q > MAX_LINK_QUEUE {
            tracing::warn!("link outbound queue exceeded {MAX_LINK_QUEUE} bytes; closing link");
            self.closed.cancel();
            return false;
        }
        self.tx.send(b).is_ok()
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

    pub fn queued_bytes(&self) -> usize {
        self.queued.load(Ordering::Acquire)
    }

    fn written(&self, n: usize) {
        self.queued.fetch_sub(n, Ordering::AcqRel);
    }
}

/// Drain a link's outbound queue into the WebSocket sink, batching writes.
pub async fn run_writer<S>(
    mut sink: S,
    mut rx: mpsc::UnboundedReceiver<Bytes>,
    out: LinkOut,
    tap: Option<Tap>,
) where
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
                Ok(b) => batch.push(b),
                Err(_) => break,
            }
        }
        let mut failed = false;
        for b in batch {
            let n = b.len();
            if let Some(t) = &tap {
                t(TapDir::Out, &b);
            }
            let r = sink.feed(Message::Binary(b)).await;
            out.written(n);
            if r.is_err() {
                failed = true;
                break;
            }
        }
        if failed || sink.flush().await.is_err() {
            out.close();
            break;
        }
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
        let id = self.shared.id;
        match f.ty {
            FrameType::Data => {
                let n = f.payload.len() as u32;
                let prev = self.shared.recv_outstanding.fetch_add(n, Ordering::AcqRel);
                if prev.saturating_add(n) > STREAM_WINDOW {
                    tracing::debug!(stream = id, "window overrun; resetting stream");
                    out.send(Frame::reset(id, ErrorCode::WindowOverrun));
                    self.kill(ErrorCode::WindowOverrun);
                    return true;
                }
                let _ = self.tx.send(StreamEvent::Data(f.payload));
                false
            }
            FrameType::Window => {
                let Ok(n) = f.window_credit() else {
                    out.send(Frame::reset(id, ErrorCode::Protocol));
                    self.kill(ErrorCode::Protocol);
                    return true;
                };
                if self.shared.credit.available_permits() + n as usize > MAX_CREDIT {
                    out.send(Frame::reset(id, ErrorCode::Protocol));
                    self.kill(ErrorCode::Protocol);
                    return true;
                }
                self.shared.credit.add_permits(n as usize);
                false
            }
            FrameType::Close => match f.close_kind() {
                None => {
                    self.shared.fin_recv.store(true, Ordering::SeqCst);
                    let _ = self.tx.send(StreamEvent::Fin);
                    self.shared.fully_closed()
                }
                Some(code) => {
                    self.kill(code);
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
                self.kill(code);
                true
            }
            _ => false,
        }
    }

    /// Abort the stream locally (link died or protocol error).
    pub fn kill(&mut self, code: ErrorCode) {
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

struct Guard {
    host: Arc<dyn StreamHost>,
    shared: Arc<StreamShared>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.shared.fully_closed() {
            self.shared.reset.store(true, Ordering::SeqCst);
            self.host
                .out()
                .send(Frame::reset(self.shared.id, ErrorCode::Aborted));
        }
        self.shared.credit.close();
        self.host.remove_stream(self.shared.id);
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
    pub fn id(&self) -> u32 {
        self.shared.id
    }

    /// Send one DATA frame (at most [`MAX_PAYLOAD`] bytes), waiting for credit.
    pub async fn send(&self, data: Bytes) -> io::Result<()> {
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
        if !self.host.out().send(Frame::data(self.shared.id, data)) {
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
        if !self.shared.fin_sent.swap(true, Ordering::SeqCst) {
            self.host.out().send(Frame::fin(self.shared.id));
            if self.shared.fully_closed() {
                self.host.remove_stream(self.shared.id);
            }
        }
    }

    /// Abort the stream in both directions.
    pub fn reset(&self, code: ErrorCode) {
        if !self.shared.reset.swap(true, Ordering::SeqCst) {
            self.host.out().send(Frame::reset(self.shared.id, code));
            self.shared.credit.close();
            self.host.remove_stream(self.shared.id);
        }
    }

    /// Refuse an incoming OPEN.
    pub fn reject(&self, code: ErrorCode, msg: &str) {
        if !self.shared.reset.swap(true, Ordering::SeqCst) {
            self.host
                .out()
                .send(Frame::open_err(self.shared.id, code, msg));
            self.shared.credit.close();
            self.host.remove_stream(self.shared.id);
        }
    }

    /// Accept an incoming OPEN.
    pub fn accept(&self) -> bool {
        self.host.out().send(Frame::open_ok(self.shared.id))
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
        if self.eof {
            return Ok(None);
        }
        match self.rx.recv().await {
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

    fn host() -> (Arc<TestHost>, mpsc::UnboundedReceiver<Bytes>) {
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
        while let Ok(m) = b_wire.try_recv() {
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
    async fn excessive_credit_is_protocol_error() {
        let (b, _wire) = host();
        let (sb, _tx, _rx, _) = new_stream(7, b.clone(), false);
        b.table.lock().unwrap().insert(7, sb);
        deliver(&b, Frame::window(7, u32::MAX).encode());
        assert!(b.table.lock().unwrap().is_empty());
    }
}
