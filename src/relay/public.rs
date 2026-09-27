//! Public HTTPS for published names. TLS terminates here (necessarily: this
//! is the public side); each client connection becomes one stream to the
//! owning node. Every request head is parsed so `X-Forwarded-*` can be
//! replaced, and bodies are framed so the next request on a keep-alive
//! connection is found reliably. After a successful `Upgrade` the connection
//! becomes an opaque byte pipe.

use super::RelayInner;
use crate::http::{
    simple_response, Activity, BodyKind, BufConn, ByteSink, HttpError, MuxSink, Request, WriteSink,
};
use crate::limits::{MAX_REQUEST_HEAD, MAX_RESPONSE_HEAD};
use crate::mux::{MuxReceiver, MuxSender};
use crate::proto::ErrorCode;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};

type ServerTls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// Client-supplied headers that are always removed; the relay sets its own.
pub const STRIPPED_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
];

/// What the request side tells the response side about each request.
enum ReqInfo {
    Forwarded {
        method: String,
        upgrade: Option<oneshot::Sender<bool>>,
    },
    /// Send these bytes (a relay-generated error) and close.
    Reject(Vec<u8>),
}

async fn reply_close<W: AsyncWrite + Unpin>(w: &mut W, code: u16, reason: &str, body: &str) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = w
            .write_all(&simple_response(code, reason, body, true))
            .await;
        let _ = w.shutdown().await;
    })
    .await;
}

/// Serve one public client connection whose first request is `first`.
pub async fn serve(
    inner: Arc<RelayInner>,
    mut conn: BufConn<ServerTls>,
    first: Request,
    name: String,
    host: String,
    peer: SocketAddr,
    activity: Arc<Activity>,
) {
    let publish = inner.registry.read().unwrap().publishes.get(&name).cloned();
    let Some(publish) = publish else {
        reply_close(
            &mut conn.inner,
            404,
            "Not Found",
            "nothing is published under this name\n",
        )
        .await;
        return;
    };
    if !publish.allow.is_empty() {
        let allowed = publish.allow.iter().any(|c| {
            c.parse::<ipnet::IpNet>()
                .map(|n| n.contains(&peer.ip()))
                .unwrap_or(false)
        });
        if !allowed {
            reply_close(&mut conn.inner, 403, "Forbidden", "forbidden\n").await;
            return;
        }
    }
    let Some(link) = inner.link_for(&publish.node_id) else {
        reply_close(
            &mut conn.inner,
            502,
            "Bad Gateway",
            "the publishing machine is offline\n",
        )
        .await;
        return;
    };
    let (tx, rx) = match link.open_public(&name, peer).await {
        Ok(s) => s,
        Err((code, msg)) => {
            tracing::debug!(%name, %code, %msg, "public open refused");
            let (status, reason) = match code {
                ErrorCode::TooManyStreams | ErrorCode::RateLimited => (503, "Service Unavailable"),
                _ => (502, "Bad Gateway"),
            };
            reply_close(
                &mut conn.inner,
                status,
                reason,
                "the published service is unavailable\n",
            )
            .await;
            return;
        }
    };

    let BufConn {
        inner: tls, buf, ..
    } = conn;
    let (r, w) = tokio::io::split(tls);
    let mut client = BufConn::new(r, Some(activity.clone()));
    client.buf = buf;
    let upstream = BufConn::new(rx, Some(activity.clone()));

    let (info_tx, info_rx) = mpsc::unbounded_channel();
    let header_timeout = inner.cfg.header_timeout;
    let idle = inner.cfg.idle_timeout;
    let ip = peer.ip().to_string();

    let requests = request_side(&mut client, first, &tx, info_tx, &host, &ip, header_timeout);
    let responses = response_side(upstream, w, info_rx);
    let watchdog = async {
        loop {
            let left = idle.saturating_sub(activity.idle_for());
            if left.is_zero() {
                break;
            }
            tokio::time::sleep(left.max(Duration::from_millis(50))).await;
        }
    };
    tokio::pin!(requests);
    tokio::pin!(responses);
    tokio::pin!(watchdog);
    let mut req_done = false;
    loop {
        tokio::select! {
            _ = &mut watchdog => {
                tracing::debug!(%name, "public connection idle timeout");
                tx.reset(ErrorCode::Aborted);
                break;
            }
            r = &mut requests, if !req_done => {
                req_done = true;
                if r.is_err() {
                    tx.reset(ErrorCode::Aborted);
                    // Give the response side a moment to flush a rejection.
                    let _ = tokio::time::timeout(Duration::from_secs(2), &mut responses).await;
                    break;
                }
            }
            rejected = &mut responses => {
                if rejected && !req_done {
                    // Let the request side drain what the client is still
                    // sending so closing does not reset the connection
                    // before the client has read the rejection.
                    let _ = tokio::time::timeout(Duration::from_millis(1500), &mut requests).await;
                }
                break;
            }
        }
    }
}

/// Queue a relay-generated rejection, stop the upstream side and drain the
/// client briefly (bounded) so the rejection is not lost to a reset.
async fn reject(
    info: &mpsc::UnboundedSender<ReqInfo>,
    response: Vec<u8>,
    client: &mut BufConn<ReadHalf<ServerTls>>,
    tx: &MuxSender,
) -> Result<(), HttpError> {
    let _ = info.send(ReqInfo::Reject(response));
    tx.finish();
    client.buf.clear();
    super::drain(&mut client.inner).await;
    Ok(())
}

/// Parse requests from the client, rewrite their heads and stream them upstream.
async fn request_side(
    client: &mut BufConn<ReadHalf<ServerTls>>,
    first: Request,
    tx: &MuxSender,
    info: mpsc::UnboundedSender<ReqInfo>,
    host: &str,
    ip: &str,
    header_timeout: Duration,
) -> Result<(), HttpError> {
    let mut sink = MuxSink(tx);
    let mut req = first;
    loop {
        if req.host().as_deref().is_some_and(|h| h != host) {
            return reject(
                &info,
                simple_response(
                    421,
                    "Misdirected Request",
                    "Host changed on this connection\n",
                    true,
                ),
                client,
                tx,
            )
            .await;
        }
        let kind = match req.body_kind() {
            Ok(k) => k,
            Err(_) => {
                return reject(
                    &info,
                    simple_response(400, "Bad Request", "bad request\n", true),
                    client,
                    tx,
                )
                .await;
            }
        };
        let upgrade = req.is_upgrade();
        let head = req.encode(
            STRIPPED_HEADERS,
            &[
                ("X-Forwarded-For", ip.to_string()),
                ("X-Forwarded-Proto", "https".to_string()),
                ("X-Forwarded-Host", host.to_string()),
            ],
        );
        let (ack_tx, ack_rx) = if upgrade {
            let (a, b) = oneshot::channel();
            (Some(a), Some(b))
        } else {
            (None, None)
        };
        if info
            .send(ReqInfo::Forwarded {
                method: req.method.clone(),
                upgrade: ack_tx,
            })
            .is_err()
        {
            return Ok(());
        }
        sink.put(head.into()).await?;
        client.copy_body(kind, &mut sink).await?;
        if let Some(ack) = ack_rx {
            if ack.await == Ok(true) {
                client.copy_to_eof(&mut sink).await?;
                tx.finish();
                return Ok(());
            }
        }
        if req.wants_close() || kind == BodyKind::UntilClose {
            tx.finish();
            return Ok(());
        }
        // Next request on the keep-alive connection. Waiting for its first
        // byte is bounded by the idle watchdog; the rest of the head by the
        // header timeout.
        if !client.wait_readable().await? {
            tx.finish();
            return Ok(());
        }
        req = match tokio::time::timeout(header_timeout, client.read_request(MAX_REQUEST_HEAD))
            .await
        {
            Err(_) => return Err(HttpError::Truncated),
            Ok(Ok(Some(r))) => r,
            Ok(Ok(None)) => {
                tx.finish();
                return Ok(());
            }
            Ok(Err(HttpError::TooLarge)) => {
                return reject(
                    &info,
                    simple_response(
                        431,
                        "Request Header Fields Too Large",
                        "request header too large\n",
                        true,
                    ),
                    client,
                    tx,
                )
                .await;
            }
            Ok(Err(_)) => {
                return reject(
                    &info,
                    simple_response(400, "Bad Request", "bad request\n", true),
                    client,
                    tx,
                )
                .await;
            }
        };
    }
}

/// Parse responses coming back from the node and stream them to the client.
async fn response_side(
    mut upstream: BufConn<MuxReceiver>,
    w: WriteHalf<ServerTls>,
    mut info: mpsc::UnboundedReceiver<ReqInfo>,
) -> bool {
    let mut sink = WriteSink(w);
    let mut rejected = false;
    let _ = async {
        while let Some(i) = info.recv().await {
            match i {
                ReqInfo::Reject(bytes) => {
                    rejected = true;
                    sink.put(bytes.into()).await?;
                    return Ok::<(), HttpError>(());
                }
                ReqInfo::Forwarded {
                    method,
                    mut upgrade,
                } => loop {
                    let resp = match upstream.read_response(MAX_RESPONSE_HEAD).await {
                        Ok(r) => r,
                        Err(e) => {
                            let _ = sink
                                .put(
                                    simple_response(
                                        502,
                                        "Bad Gateway",
                                        "bad response from the published service\n",
                                        true,
                                    )
                                    .into(),
                                )
                                .await;
                            return Err(e);
                        }
                    };
                    if resp.code == 101 {
                        let Some(ack) = upgrade.take() else {
                            return Err(HttpError::Malformed("unexpected 101"));
                        };
                        sink.put(resp.raw.clone()).await?;
                        let _ = ack.send(true);
                        upstream.copy_to_eof(&mut sink).await?;
                        return Ok(());
                    }
                    sink.put(resp.raw.clone()).await?;
                    if (100..200).contains(&resp.code) {
                        continue;
                    }
                    let kind = resp.body_kind(&method)?;
                    upstream.copy_body(kind, &mut sink).await?;
                    if let Some(ack) = upgrade.take() {
                        let _ = ack.send(false);
                    }
                    if resp.closes() || kind == BodyKind::UntilClose {
                        return Ok(());
                    }
                    break;
                },
            }
        }
        Ok(())
    }
    .await;
    let _ = tokio::time::timeout(Duration::from_secs(5), sink.0.shutdown()).await;
    rejected
}
