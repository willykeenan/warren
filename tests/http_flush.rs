use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use warren::http::{ByteSink, WriteSink};

struct GatedIo {
    io: tokio::io::DuplexStream,
    blocked: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
    wake: Arc<futures_util::task::AtomicWaker>,
}
impl AsyncRead for GatedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, b)
    }
}
impl AsyncWrite for GatedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.blocked.load(Ordering::SeqCst) {
            self.wake.register(cx.waker());
            self.hits.fetch_add(1, Ordering::SeqCst);
            return Poll::Pending;
        }
        Pin::new(&mut self.io).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn public_tls_write_sink_flushes_final_tail_and_preserves_half_close() {
    let (cert, key) = warren::tls::generate_self_signed(&["relay.test".into()]).unwrap();
    let ck = warren::tls::certified_key_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let pin = warren::tls::cert_sha256(ck.cert[0].as_ref());
    let resolver = warren::tls::CertResolver::new();
    resolver.set_default(ck);
    let acceptor =
        tokio_rustls::TlsAcceptor::from(warren::tls::server_config(Arc::new(resolver)).unwrap());
    let connector =
        tokio_rustls::TlsConnector::from(warren::tls::client_config(Some(pin)).unwrap());
    let (a, b) = tokio::io::duplex(1024 * 1024);
    let blocked = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let wake = Arc::new(futures_util::task::AtomicWaker::new());
    let gio = GatedIo {
        io: a,
        blocked: blocked.clone(),
        hits: hits.clone(),
        wake: wake.clone(),
    };
    let (server, client) = tokio::join!(
        acceptor.accept(gio),
        connector.connect(warren::tls::server_name("relay.test").unwrap(), b)
    );
    let (mut server_r, server_w) = tokio::io::split(server.unwrap());
    let mut client = client.unwrap();
    let mut sink = WriteSink(server_w);
    // Keep the public request half polled, just as serve() does after upgrade.
    let reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        server_r.read_to_end(&mut buf).await.unwrap();
        buf
    });
    let prefix = bytes::Bytes::from(vec![42; 196_608]);
    sink.put(prefix.clone()).await.unwrap();
    sink.0.flush().await.unwrap();
    let mut got = vec![0; prefix.len()];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.as_slice(), prefix.as_ref());
    blocked.store(true, Ordering::SeqCst);
    let tail = bytes::Bytes::from(vec![42; 3_392]);

    {
        let put = sink.put(tail.clone());
        tokio::pin!(put);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut put)
                .await
                .is_err(),
            "put must wait for buffered TLS ciphertext, not only plaintext acceptance"
        );
        assert!(
            hits.load(Ordering::SeqCst) > 0,
            "lower transport was actually backpressured"
        );
        blocked.store(false, Ordering::SeqCst);
        wake.wake();
        tokio::time::timeout(Duration::from_secs(1), &mut put)
            .await
            .unwrap()
            .unwrap();
    }
    let mut tail_got = vec![0; tail.len()];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut tail_got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tail_got.as_slice(), tail.as_ref());
    println!("put_waited_for_tls_flush_and_exact_200000_bytes_delivered=true");
    // Flushing does not close the writer or end the opposite direction.
    client.write_all(b"reverse request").await.unwrap();
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), reader)
            .await
            .unwrap()
            .unwrap(),
        b"reverse request"
    );
    sink.put(bytes::Bytes::from_static(b"response after request EOF"))
        .await
        .unwrap();
    let mut last = vec![0; b"response after request EOF".len()];
    tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut last))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(last, b"response after request EOF");
    println!("request_half_close_preserves_response_direction=true");
}

struct FailingWriter {
    write_fails: bool,
    flush_fails: bool,
    writes: Arc<AtomicUsize>,
    flushes: Arc<AtomicUsize>,
}
impl AsyncWrite for FailingWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.write_fails {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write fixture",
            )))
        } else {
            Poll::Ready(Ok(b.len()))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        if self.flush_fails {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "flush fixture",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        panic!("put must not shut down the writer")
    }
}
#[tokio::test]
async fn public_write_sink_propagates_write_and_flush_errors() {
    for (write_fails, flush_fails, expected, expected_flushes) in [
        (true, false, io::ErrorKind::BrokenPipe, 0),
        (false, true, io::ErrorKind::ConnectionReset, 1),
    ] {
        let writes = Arc::new(AtomicUsize::new(0));
        let flushes = Arc::new(AtomicUsize::new(0));
        let mut sink = WriteSink(FailingWriter {
            write_fails,
            flush_fails,
            writes: writes.clone(),
            flushes: flushes.clone(),
        });
        assert_eq!(
            sink.put(bytes::Bytes::from_static(b"body"))
                .await
                .unwrap_err()
                .kind(),
            expected
        );
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(flushes.load(Ordering::SeqCst), expected_flushes);
    }
}
