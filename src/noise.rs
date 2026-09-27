//! End-to-end encryption for private streams:
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` between the two nodes, run inside a
//! multiplexed stream so the relay only ever forwards ciphertext.
//!
//! * Message 1 (initiator to responder) carries a JSON [`Hello`] naming the
//!   source, destination and port, so the destination can check the request
//!   against what the relay claimed.
//! * Message 2 (responder to initiator) completes the handshake.
//! * The initiator's first transport message is a fixed confirmation. Message
//!   1 contains nothing from the responder, so a relay could replay a recorded
//!   one; only a live initiator can encrypt to the responder's fresh
//!   ephemeral key, so the responder does nothing (in particular, does not
//!   connect to the local service) before the confirmation arrives.
//! * The responder's first transport message is a status: whether the local
//!   service could be reached. The relay cannot tell success from failure.
//! * Every later DATA frame is exactly one Noise transport message. An empty
//!   plaintext message is the authenticated end-of-stream marker; a FIN that
//!   arrives without it is treated as truncation.

use crate::crypto::{Identity, NOISE_PARAMS, NOISE_PROLOGUE};
use crate::mux::{MuxReceiver, MuxSender};
use crate::proto::{ErrorCode, MAX_PAYLOAD};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest plaintext carried by one transport message.
pub const MAX_PLAINTEXT: usize = MAX_PAYLOAD - 16;
/// Time allowed for each handshake message.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// Plaintext of the initiator's first transport message.
pub const CONFIRM: &[u8] = b"warren-v1-confirm";

/// Plaintext (JSON) of the responder's first transport message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
}

/// Handshake payload of message 1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hello {
    pub v: u32,
    pub src: String,
    pub dest: String,
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("stream: {0}")]
    Io(#[from] io::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("peer closed the stream during the handshake")]
    Closed,
    #[error("malformed handshake payload")]
    BadPayload,
    #[error("the destination refused the stream ({0})")]
    Refused(ErrorCode),
}

fn builder() -> snow::Builder<'static> {
    snow::Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
}

async fn recv_msg(rx: &mut MuxReceiver) -> Result<Bytes, NoiseError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, rx.recv()).await {
        Err(_) => Err(NoiseError::Timeout),
        Ok(Err(e)) => Err(NoiseError::Io(e)),
        Ok(Ok(None)) => Err(NoiseError::Closed),
        Ok(Ok(Some(b))) => Ok(b),
    }
}

async fn recv_transport(rx: &mut SecureReceiver) -> Result<Vec<u8>, NoiseError> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, rx.recv()).await {
        Err(_) => Err(NoiseError::Timeout),
        Ok(Err(e)) => Err(NoiseError::Io(e)),
        Ok(Ok(None)) => Err(NoiseError::Closed),
        Ok(Ok(Some(b))) => Ok(b),
    }
}

/// Run the initiator side. `peer_static` is the destination's pinned key.
/// Returns once the destination has reported that its local service is
/// connected; a refusal after the handshake is [`NoiseError::Refused`].
pub async fn initiate(
    tx: MuxSender,
    mut rx: MuxReceiver,
    me: &Identity,
    peer_static: &[u8; 32],
    hello: &Hello,
) -> Result<SecureChannel, NoiseError> {
    let mut hs = builder()
        .local_private_key(&me.static_secret)?
        .remote_public_key(peer_static)?
        .prologue(NOISE_PROLOGUE)?
        .build_initiator()?;
    let payload = serde_json::to_vec(hello).map_err(|_| NoiseError::BadPayload)?;
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let n = hs.write_message(&payload, &mut buf)?;
    tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
    let msg2 = recv_msg(&mut rx).await?;
    let mut out = vec![0u8; MAX_PAYLOAD];
    hs.read_message(&msg2, &mut out)?;
    let transport = hs.into_stateless_transport_mode()?;
    let mut chan = SecureChannel::new(tx, rx, transport);
    chan.tx.send(CONFIRM).await?;
    let status = recv_transport(&mut chan.rx).await?;
    let status: Status = serde_json::from_slice(&status).map_err(|_| NoiseError::BadPayload)?;
    if status.ok {
        Ok(chan)
    } else {
        Err(NoiseError::Refused(
            status.code.unwrap_or(ErrorCode::Internal),
        ))
    }
}

/// A responder that has read and authenticated message 1 but not yet answered.
pub struct Responder {
    hs: snow::HandshakeState,
    tx: MuxSender,
    rx: MuxReceiver,
    /// The initiator's static key, proven by the handshake.
    pub remote_static: [u8; 32],
    pub hello: Hello,
}

/// Read message 1 as the responder.
pub async fn respond(
    tx: MuxSender,
    mut rx: MuxReceiver,
    me: &Identity,
) -> Result<Responder, NoiseError> {
    let mut hs = builder()
        .local_private_key(&me.static_secret)?
        .prologue(NOISE_PROLOGUE)?
        .build_responder()?;
    let msg1 = recv_msg(&mut rx).await?;
    let mut payload = vec![0u8; MAX_PAYLOAD];
    let n = hs.read_message(&msg1, &mut payload)?;
    let hello: Hello = serde_json::from_slice(&payload[..n]).map_err(|_| NoiseError::BadPayload)?;
    let rs = hs.get_remote_static().ok_or(NoiseError::BadPayload)?;
    let remote_static = <[u8; 32]>::try_from(rs).map_err(|_| NoiseError::BadPayload)?;
    Ok(Responder {
        hs,
        tx,
        rx,
        remote_static,
        hello,
    })
}

impl Responder {
    /// Send message 2 and wait for the initiator's confirmation, which a
    /// replayed message 1 cannot produce.
    pub async fn complete(mut self) -> Result<Confirmed, NoiseError> {
        let mut buf = vec![0u8; MAX_PAYLOAD];
        let n = self.hs.write_message(b"{\"v\":1}", &mut buf)?;
        self.tx.send(Bytes::copy_from_slice(&buf[..n])).await?;
        let transport = self.hs.into_stateless_transport_mode()?;
        let mut chan = SecureChannel::new(self.tx, self.rx, transport);
        let confirm = recv_transport(&mut chan.rx).await?;
        if confirm != CONFIRM {
            chan.tx.reset(ErrorCode::HandshakeFailed);
            return Err(NoiseError::BadPayload);
        }
        Ok(Confirmed { chan })
    }

    /// Refuse after message 1: reset the stream without completing the handshake.
    pub fn refuse(self, code: ErrorCode) {
        self.tx.reset(code);
    }
}

/// A completed handshake with a proven-live initiator, before the
/// responder's status.
pub struct Confirmed {
    chan: SecureChannel,
}

impl Confirmed {
    /// Report success; the channel is ready for data.
    pub async fn accept(mut self) -> Result<SecureChannel, NoiseError> {
        let st = serde_json::to_vec(&Status {
            ok: true,
            code: None,
        })
        .map_err(|_| NoiseError::BadPayload)?;
        self.chan.tx.send(&st).await?;
        Ok(self.chan)
    }

    /// Report a refusal (encrypted, so only the initiator learns why), then
    /// abort the stream.
    pub async fn refuse(mut self, code: ErrorCode) {
        if let Ok(st) = serde_json::to_vec(&Status {
            ok: false,
            code: Some(code),
        }) {
            let _ = self.chan.tx.send(&st).await;
        }
        self.chan.tx.reset(ErrorCode::Aborted);
    }
}

/// An established encrypted stream.
pub struct SecureChannel {
    pub tx: SecureSender,
    pub rx: SecureReceiver,
}

impl SecureChannel {
    fn new(tx: MuxSender, rx: MuxReceiver, t: snow::StatelessTransportState) -> SecureChannel {
        let t = Arc::new(t);
        SecureChannel {
            tx: SecureSender {
                tx,
                t: t.clone(),
                nonce: 0,
                buf: vec![0u8; MAX_PAYLOAD],
            },
            rx: SecureReceiver {
                rx,
                t,
                nonce: 0,
                buf: vec![0u8; MAX_PAYLOAD],
                eof: false,
            },
        }
    }

    /// Relay bytes between this channel and a local reader/writer until both
    /// directions finish. Returns (bytes sent, bytes received).
    pub async fn pipe<R, W>(self, r: R, w: W) -> io::Result<(u64, u64)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let SecureChannel { mut tx, mut rx } = self;
        let up = async {
            let r = tx.copy_from(r).await;
            (r, tx)
        };
        let down = rx.copy_to(w);
        tokio::pin!(up);
        tokio::pin!(down);
        let mut up_res: Option<io::Result<u64>> = None;
        let mut down_res: Option<io::Result<u64>> = None;
        let mut sender: Option<SecureSender> = None;
        while up_res.is_none() || down_res.is_none() {
            tokio::select! {
                (r, t) = &mut up, if up_res.is_none() => {
                    if let Err(e) = &r {
                        t.reset(ErrorCode::Aborted);
                        return Err(io::Error::new(e.kind(), e.to_string()));
                    }
                    up_res = Some(r);
                    sender = Some(t);
                }
                r = &mut down, if down_res.is_none() => {
                    if let Err(e) = r {
                        if let Some(t) = &sender { t.reset(ErrorCode::Aborted); }
                        return Err(e);
                    }
                    down_res = Some(r);
                }
            }
        }
        drop(sender);
        Ok((
            up_res.and_then(|r| r.ok()).unwrap_or(0),
            down_res.and_then(|r| r.ok()).unwrap_or(0),
        ))
    }
}

/// Encrypting half.
pub struct SecureSender {
    tx: MuxSender,
    t: Arc<snow::StatelessTransportState>,
    nonce: u64,
    buf: Vec<u8>,
}

impl SecureSender {
    /// Encrypt and send up to [`MAX_PLAINTEXT`] bytes.
    pub async fn send(&mut self, plain: &[u8]) -> io::Result<()> {
        debug_assert!(plain.len() <= MAX_PLAINTEXT);
        let n = self
            .t
            .write_message(self.nonce, plain, &mut self.buf)
            .map_err(|e| io::Error::other(format!("encrypt: {e}")))?;
        self.nonce += 1;
        self.tx.send(Bytes::copy_from_slice(&self.buf[..n])).await
    }

    /// Send the authenticated end-of-stream marker and FIN.
    pub async fn finish(&mut self) -> io::Result<()> {
        self.send(&[]).await?;
        self.tx.finish();
        Ok(())
    }

    pub fn reset(&self, code: ErrorCode) {
        self.tx.reset(code);
    }

    /// Copy a reader into the channel until EOF, then finish.
    pub async fn copy_from<R: AsyncRead + Unpin>(&mut self, mut r: R) -> io::Result<u64> {
        let mut plain = vec![0u8; MAX_PLAINTEXT];
        let mut total = 0;
        loop {
            let n = r.read(&mut plain).await?;
            if n == 0 {
                self.finish().await?;
                return Ok(total);
            }
            total += n as u64;
            self.send(&plain[..n]).await?;
        }
    }
}

/// Decrypting half.
pub struct SecureReceiver {
    rx: MuxReceiver,
    t: Arc<snow::StatelessTransportState>,
    nonce: u64,
    buf: Vec<u8>,
    eof: bool,
}

impl SecureReceiver {
    /// Next plaintext chunk; `Ok(None)` at authenticated end of stream.
    pub async fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.eof {
            // Drain until the FIN so the stream closes cleanly.
            return match self.rx.recv().await? {
                None => Ok(None),
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data after end of stream",
                )),
            };
        }
        let Some(msg) = self.rx.recv().await? else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream truncated (FIN without authenticated end marker)",
            ));
        };
        let n = self
            .t
            .read_message(self.nonce, &msg, &mut self.buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
        self.nonce += 1;
        if n == 0 {
            self.eof = true;
            return Ok(None);
        }
        Ok(Some(self.buf[..n].to_vec()))
    }

    /// Copy decrypted data into a writer until end of stream, then shut it down.
    pub async fn copy_to<W: AsyncWrite + Unpin>(&mut self, mut w: W) -> io::Result<u64> {
        let mut total = 0;
        while let Some(p) = self.recv().await? {
            total += p.len() as u64;
            w.write_all(&p).await?;
            // Framed control output buffers a payload until flushed. Deliver it
            // before awaiting the peer again (SSH banners must not need EOF).
            w.flush().await?;
        }
        w.shutdown().await?;
        // Wait for the peer's FIN (bounded) so the stream is fully closed.
        let _ = tokio::time::timeout(Duration::from_secs(5), self.rx.recv()).await;
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::{new_stream, LinkOut, LinkRx, Slot, StreamHost};
    use crate::proto::Frame;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio_util::sync::CancellationToken;

    struct H {
        out: LinkOut,
        table: Mutex<HashMap<u32, Slot>>,
    }
    impl StreamHost for H {
        fn out(&self) -> &LinkOut {
            &self.out
        }
        fn remove_stream(&self, id: u32) {
            self.table.lock().unwrap().remove(&id);
        }
    }

    type Ends = (MuxSender, MuxReceiver);

    fn pair() -> (Ends, Ends, Arc<Mutex<Vec<Bytes>>>) {
        let mk = || {
            let (out, rx) = LinkOut::new(CancellationToken::new());
            (
                Arc::new(H {
                    out,
                    table: Mutex::new(HashMap::new()),
                }),
                rx,
            )
        };
        let (a, mut aw): (Arc<H>, LinkRx) = mk();
        let (b, mut bw) = mk();
        let (sa, ta, ra, _) = new_stream(1, a.clone(), true);
        let (sb, tb, rb, _) = new_stream(1, b.clone(), false);
        a.table.lock().unwrap().insert(1, sa);
        b.table.lock().unwrap().insert(1, sb);
        let wire = Arc::new(Mutex::new(Vec::new()));
        let w2 = wire.clone();
        tokio::spawn(async move {
            let dl = |h: &H, m: Bytes| {
                let f = Frame::decode(m).unwrap();
                let mut t = h.table.lock().unwrap();
                if let Some(s) = t.get_mut(&f.stream) {
                    if s.deliver(f.clone(), &h.out) {
                        t.remove(&f.stream);
                    }
                }
            };
            loop {
                tokio::select! {
                    Some(m) = aw.recv() => { w2.lock().unwrap().push(m.clone()); dl(&b, m) },
                    Some(m) = bw.recv() => { w2.lock().unwrap().push(m.clone()); dl(&a, m) },
                    else => break,
                }
            }
        });
        ((ta, ra), (tb, rb), wire)
    }

    #[tokio::test]
    async fn handshake_and_transport() {
        let ((ta, ra), (tb, rb), wire) = pair();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let hello = Hello {
            v: 1,
            src: "a".into(),
            dest: "b".into(),
            port: 22,
        };
        let ib2 = ib.clone();
        let resp = tokio::spawn(async move {
            let r = respond(tb, rb, &ib2).await.unwrap();
            let rs = r.remote_static;
            let h = r.hello.clone();
            (r.complete().await.unwrap().accept().await.unwrap(), rs, h)
        });
        let mut ca = initiate(ta, ra, &ia, &ib.static_pub, &hello).await.unwrap();
        let (mut cb, rs, h) = resp.await.unwrap();
        assert_eq!(rs, ia.static_pub);
        assert_eq!(h, hello);
        let marker = b"SECRET-MARKER-0123456789".repeat(100);
        ca.tx.send(&marker).await.unwrap();
        assert_eq!(cb.rx.recv().await.unwrap().unwrap(), marker);
        cb.tx.send(b"pong").await.unwrap();
        assert_eq!(ca.rx.recv().await.unwrap().unwrap(), b"pong");
        ca.tx.finish().await.unwrap();
        assert!(cb.rx.recv().await.unwrap().is_none());
        // Nothing on the wire contains the marker.
        let all: Vec<u8> = wire
            .lock()
            .unwrap()
            .iter()
            .flat_map(|b| b.to_vec())
            .collect();
        assert!(!all.windows(24).any(|w| w == &marker[..24]));
    }

    #[tokio::test]
    async fn wrong_responder_key_fails() {
        let ((ta, ra), (tb, rb), _wire) = pair();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let impostor = Identity::generate();
        let hello = Hello {
            v: 1,
            src: "a".into(),
            dest: "b".into(),
            port: 22,
        };
        // Responder holds a different key than the one the initiator pinned.
        let resp = tokio::spawn(async move { respond(tb, rb, &impostor).await.map(|_| ()) });
        let r = tokio::time::timeout(
            Duration::from_secs(20),
            initiate(ta, ra, &ia, &ib.static_pub, &hello),
        )
        .await
        .unwrap();
        assert!(r.is_err());
        assert!(resp.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn refusal_after_confirmation_is_reported() {
        let ((ta, ra), (tb, rb), _wire) = pair();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let hello = Hello {
            v: 1,
            src: "a".into(),
            dest: "b".into(),
            port: 9,
        };
        let ib2 = ib.clone();
        tokio::spawn(async move {
            let c = respond(tb, rb, &ib2)
                .await
                .unwrap()
                .complete()
                .await
                .unwrap();
            c.refuse(ErrorCode::ConnectFailed).await;
        });
        let e = initiate(ta, ra, &ia, &ib.static_pub, &hello)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(e, NoiseError::Refused(ErrorCode::ConnectFailed)),
            "{e}"
        );
    }

    /// Replaying a recorded message 1 gets a message 2, but never the
    /// confirmation the responder waits for before doing anything.
    #[tokio::test]
    async fn replayed_message_one_is_never_confirmed() {
        let ia = Identity::generate();
        let ib = Identity::generate();
        let hello = Hello {
            v: 1,
            src: "a".into(),
            dest: "b".into(),
            port: 22,
        };
        // Record a message 1.
        let mut hs = builder()
            .local_private_key(&ia.static_secret)
            .unwrap()
            .remote_public_key(&ib.static_pub)
            .unwrap()
            .prologue(NOISE_PROLOGUE)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; MAX_PAYLOAD];
        let n = hs
            .write_message(&serde_json::to_vec(&hello).unwrap(), &mut buf)
            .unwrap();
        let msg1 = Bytes::copy_from_slice(&buf[..n]);
        // Replay it to a responder, with a guessed "confirmation".
        let ((ta, _ra), (tb, rb), _wire) = pair();
        let ib2 = ib.clone();
        let resp = tokio::spawn(async move {
            let r = respond(tb, rb, &ib2).await.unwrap();
            assert_eq!(r.remote_static, ia.static_pub);
            r.complete().await.map(|_| ())
        });
        ta.send(msg1).await.unwrap();
        ta.send(Bytes::from_static(CONFIRM)).await.unwrap();
        let r = resp.await.unwrap();
        assert!(r.is_err(), "a replayed handshake was confirmed");
    }

    #[tokio::test]
    async fn truncation_detected() {
        let ((ta, ra), (tb, rb), _wire) = pair();
        let ia = Identity::generate();
        let ib = Identity::generate();
        let hello = Hello {
            v: 1,
            src: "a".into(),
            dest: "b".into(),
            port: 1,
        };
        let ib2 = ib.clone();
        let resp = tokio::spawn(async move {
            respond(tb, rb, &ib2)
                .await
                .unwrap()
                .complete()
                .await
                .unwrap()
                .accept()
                .await
                .unwrap()
        });
        let ca = initiate(ta, ra, &ia, &ib.static_pub, &hello).await.unwrap();
        let mut cb = resp.await.unwrap();
        // Plain FIN without the encrypted end marker, as a malicious relay could inject.
        ca.tx.tx.finish();
        let e = cb.rx.recv().await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }
}
