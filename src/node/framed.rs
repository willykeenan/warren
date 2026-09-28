//! Local IPC framing: an explicit zero-length chunk closes one direction.
//! The writer buffers at most one chunk; callers flush interactive writes.
//! Named pipes have no socket half-close. Truncation is an error, never EOF.
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const MAX: usize = 65536;
pub struct FramedRead<R> {
    inner: R,
    header: [u8; 4],
    used: usize,
    remaining: usize,
    ended: bool,
}
impl<R> FramedRead<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            header: [0; 4],
            used: 0,
            remaining: 0,
            ended: false,
        }
    }
}
impl<R: AsyncRead + Unpin> AsyncRead for FramedRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        if s.ended || out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while s.remaining == 0 {
            let mut b = ReadBuf::new(&mut s.header[s.used..]);
            ready!(Pin::new(&mut s.inner).poll_read(cx, &mut b))?;
            let n = b.filled().len();
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "control frame missing EOF",
                )));
            }
            s.used += n;
            if s.used < 4 {
                continue;
            }
            s.remaining = u32::from_be_bytes(s.header) as usize;
            s.used = 0;
            if s.remaining == 0 {
                s.ended = true;
                return Poll::Ready(Ok(()));
            }
            if s.remaining > MAX {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized control frame",
                )));
            }
        }
        let limit = out.remaining().min(s.remaining);
        let mut b = ReadBuf::new(&mut out.initialize_unfilled()[..limit]);
        ready!(Pin::new(&mut s.inner).poll_read(cx, &mut b))?;
        let n = b.filled().len();
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated control frame",
            )));
        }
        s.remaining -= n;
        out.advance(n);
        Poll::Ready(Ok(()))
    }
}
pub struct FramedWrite<W> {
    inner: W,
    pending: Vec<u8>,
    sent: usize,
    closing: bool,
}
impl<W> FramedWrite<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            sent: 0,
            closing: false,
        }
    }
}
impl<W: AsyncWrite + Unpin> FramedWrite<W> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.sent < self.pending.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.sent..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.sent += n;
        }
        self.pending.clear();
        self.sent = 0;
        Poll::Ready(Ok(()))
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for FramedWrite<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let s = self.get_mut();
        if s.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(s.drain(cx))?;
        let n = bytes.len().min(MAX);
        if n != 0 {
            s.pending.extend_from_slice(&(n as u32).to_be_bytes());
            s.pending.extend_from_slice(&bytes[..n]);
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        ready!(s.drain(cx))?;
        Pin::new(&mut s.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let s = self.get_mut();
        ready!(s.drain(cx))?;
        if !s.closing {
            s.pending.extend_from_slice(&[0; 4]);
            s.closing = true;
        }
        ready!(s.drain(cx))?;
        Pin::new(&mut s.inner).poll_flush(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn flush_delivers_without_closing() {
        let (a, b) = tokio::io::duplex(64);
        let mut w = FramedWrite::new(a);
        let mut r = FramedRead::new(b);
        w.write_all(b"hello").await.unwrap();
        w.flush().await.unwrap();
        let mut b = [0; 5];
        r.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");
    }
    #[tokio::test]
    async fn chunks_half_close_and_backpressure() {
        let (a, b) = tokio::io::duplex(7);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let mut r = FramedRead::new(ar);
        let mut w = FramedWrite::new(aw);
        let task = tokio::spawn(async move {
            let mut r = FramedRead::new(br);
            let mut data = Vec::new();
            r.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, vec![42; MAX * 2 + 9]);
            let mut w = FramedWrite::new(bw);
            w.write_all(b"after EOF").await.unwrap();
            w.shutdown().await.unwrap();
        });
        w.write_all(&vec![42; MAX * 2 + 9]).await.unwrap();
        w.shutdown().await.unwrap();
        w.shutdown().await.unwrap();
        assert!(w.write_all(b"late").await.is_err());
        let mut reply = Vec::new();
        r.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"after EOF");
        task.await.unwrap();
    }
    #[tokio::test]
    async fn rejects_truncation_and_oversize() {
        for bytes in [&[][..], &[0, 0], &[0, 0, 0, 2, 1], &[0, 1, 0, 1]] {
            let mut r = FramedRead::new(bytes);
            assert!(r.read_to_end(&mut Vec::new()).await.is_err());
        }
        let mut r = FramedRead::new(&[0, 0, 0, 0][..]);
        assert_eq!(r.read_to_end(&mut Vec::new()).await.unwrap(), 0);
    }
}
