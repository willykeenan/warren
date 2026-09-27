//! Shared harness for end-to-end tests: a real relay with a self-signed
//! certificate on 127.0.0.1 and nodes with their own temporary homes.

#![allow(dead_code)]

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use warren::crypto::Identity;
use warren::mux::TapDir;
use warren::net::RelayUrl;
use warren::node::control::{self, ControlRequest, ControlResponse};
use warren::node::daemon::{self, DaemonConfig, DaemonHandle};
use warren::node::{IdentityFile, NodePaths};
use warren::proto::*;
use warren::relay::{self, RelayConfig, RelayHandle, TlsMode};

pub const PUBLISH_DOMAIN: &str = "warren.test";

pub type Captures = Arc<Mutex<Vec<(TapDir, Vec<u8>)>>>;

pub struct TestRelay {
    pub handle: Option<RelayHandle>,
    pub dir: tempfile::TempDir,
    pub addr: SocketAddr,
    pub pin: [u8; 32],
    pub captures: Captures,
}

impl TestRelay {
    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub fn h(&self) -> &RelayHandle {
        self.handle.as_ref().expect("relay running")
    }

    pub fn state_dir(&self) -> PathBuf {
        self.dir.path().join("relay")
    }

    pub fn invite(&self, name: Option<&str>) -> String {
        self.h()
            .inner
            .db
            .create_invite(name, Duration::from_secs(600), warren::now_secs())
            .unwrap()
    }

    pub fn captured_bytes(&self) -> Vec<Vec<u8>> {
        self.captures
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b)| b.clone())
            .collect()
    }

    /// Stop the relay (all connections drop).
    pub async fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
    }

    /// Start again on the same address with the same state.
    pub async fn restart(&mut self) {
        self.stop().await;
        let cfg = relay_config(self.addr, &self.state_dir(), self.captures.clone());
        let mut last = None;
        for _ in 0..50 {
            match relay::start(cfg.clone()).await {
                Ok(h) => {
                    assert_eq!(h.cert_sha256, Some(self.pin), "pin must survive restarts");
                    self.handle = Some(h);
                    return;
                }
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        panic!("relay restart failed: {last:?}");
    }

    pub fn online(&self) -> Vec<String> {
        self.h().online_names()
    }
}

pub fn relay_config(addr: SocketAddr, state: &Path, captures: Captures) -> RelayConfig {
    let mut cfg = RelayConfig::new(addr, "127.0.0.1", state.to_path_buf(), TlsMode::SelfSigned);
    cfg.publish_domain = PUBLISH_DOMAIN.into();
    cfg.revision_poll = Duration::from_millis(200);
    let c = captures.clone();
    cfg.tap = Some(Arc::new(move |d, b: &[u8]| {
        c.lock().unwrap().push((d, b.to_vec()));
    }));
    cfg
}

pub async fn start_relay() -> TestRelay {
    start_relay_with(|_| {}).await
}

/// The relay raises the soft open-file limit as far as the hard limit allows;
/// say so once if that is still too low for these tests.
fn check_open_files() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let n = warren::limits::raise_open_files_limit(warren::limits::WANTED_OPEN_FILES);
        if n < 2048 {
            eprintln!(
                "warning: the open file limit is {n} and cannot be raised; some tests need \
                 about 1000 open files (raise the hard limit, e.g. `ulimit -n 4096`)"
            );
        }
    });
}

pub async fn start_relay_with(f: impl FnOnce(&mut RelayConfig)) -> TestRelay {
    check_open_files();
    let dir = tempfile::tempdir().unwrap();
    let captures: Captures = Arc::new(Mutex::new(Vec::new()));
    let mut cfg = relay_config(
        "127.0.0.1:0".parse().unwrap(),
        &dir.path().join("relay"),
        captures.clone(),
    );
    f(&mut cfg);
    let h = relay::start(cfg).await.unwrap();
    TestRelay {
        addr: h.addr,
        pin: h.cert_sha256.unwrap(),
        handle: Some(h),
        dir,
        captures,
    }
}

pub struct TestNode {
    pub name: String,
    pub paths: NodePaths,
    pub dir: tempfile::TempDir,
    pub daemon: Option<DaemonHandle>,
}

impl TestNode {
    pub fn d(&self) -> &DaemonHandle {
        self.daemon.as_ref().expect("daemon running")
    }

    pub fn ident(&self) -> IdentityFile {
        IdentityFile::load(&self.paths).unwrap()
    }

    pub fn identity(&self) -> Identity {
        self.ident().identity().unwrap()
    }

    pub async fn ctl(&self, req: ControlRequest) -> ControlResponse {
        control::request(&self.paths, &req).await.unwrap()
    }

    pub async fn ctl_ok(&self, req: ControlRequest) -> serde_json::Value {
        let r = self.ctl(req.clone()).await;
        assert!(r.ok, "{req:?} failed: {r:?}");
        r.result
    }

    pub async fn start(&mut self) {
        self.start_with(|_| {}).await;
    }

    pub async fn start_with(&mut self, f: impl FnOnce(&mut DaemonConfig)) {
        let mut cfg = DaemonConfig::new(self.paths.clone());
        cfg.ping_interval = Duration::from_secs(1);
        cfg.backoff_min = Duration::from_millis(200);
        cfg.backoff_max = Duration::from_secs(2);
        f(&mut cfg);
        let h = daemon::start(cfg).await.unwrap();
        self.daemon = Some(h);
    }

    pub async fn start_connected(&mut self) {
        self.start().await;
        assert!(
            self.d().wait_connected(Duration::from_secs(10)).await,
            "{} did not connect",
            self.name
        );
    }

    pub async fn stop(&mut self) {
        if let Some(d) = self.daemon.take() {
            d.shutdown().await;
        }
    }

    pub fn share(&self, port: u16, to: Option<Vec<String>>) {
        let mut s = warren::node::SharesFile::load(&self.paths).unwrap();
        s.set(port, to);
        s.save(&self.paths).unwrap();
    }

    /// Forward a fresh local port to `node:port`; returns the local port.
    pub async fn forward(&self, node: &str, port: u16) -> u16 {
        for _ in 0..20 {
            let local = free_port().await;
            let r = self
                .ctl(ControlRequest::ForwardAdd {
                    local,
                    node: node.into(),
                    port,
                })
                .await;
            if r.ok {
                return local;
            }
        }
        panic!("could not add a forward");
    }
}

pub async fn enroll(relay: &TestRelay, name: &str) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let paths = NodePaths::new(dir.path().join("home"));
    let code = relay.invite(None);
    warren::node::join(
        &paths,
        &code,
        &relay.url(),
        Some(name),
        Some(relay.pin),
        false,
    )
    .await
    .unwrap();
    TestNode {
        name: name.into(),
        paths,
        dir,
        daemon: None,
    }
}

pub async fn enroll_started(relay: &TestRelay, name: &str) -> TestNode {
    let mut n = enroll(relay, name).await;
    n.start_connected().await;
    n
}

pub async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// TCP echo server; returns its port and a counter of accepted connections.
pub async fn echo_server() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    (port, count)
}

/// Send `data` through `port` (half-closing afterwards) and read everything back.
pub async fn echo_roundtrip(port: u16, data: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut r, mut w) = s.split();
    let write = async {
        w.write_all(data).await.unwrap();
        w.shutdown().await.unwrap();
    };
    let mut got = Vec::new();
    let read = r.read_to_end(&mut got);
    let (_, rr) =
        tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(write, read) })
            .await
            .expect("echo roundtrip timed out");
    rr.unwrap();
    got
}

pub async fn wait_for(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !f() {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// Raw protocol client: authenticates like a node, then speaks frames directly.

pub type ClientWs = warren::ws::ClientWs;

pub async fn raw_ws(relay: &TestRelay) -> ClientWs {
    let url = RelayUrl::parse(&relay.url()).unwrap();
    warren::ws::connect_relay(&url, Some(relay.pin))
        .await
        .unwrap()
}

pub async fn next_text(ws: &mut ClientWs) -> String {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => return t.as_str().to_string(),
            Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => continue,
            other => panic!("expected text, got {other:?}"),
        }
    }
}

pub async fn challenge(ws: &mut ClientWs) -> [u8; 32] {
    let t = next_text(ws).await;
    let RelayHello::Challenge { challenge, .. } = serde_json::from_str(&t).unwrap();
    warren::crypto::parse_key32(&challenge).unwrap()
}

pub async fn send_hello(ws: &mut ClientWs, h: &NodeHello) -> RelayVerdict {
    ws.send(Message::text(serde_json::to_string(h).unwrap()))
        .await
        .unwrap();
    serde_json::from_str(&next_text(ws).await).unwrap()
}

pub fn auth_hello(id: &Identity, node_id: &str, challenge: &[u8; 32], host: &str) -> NodeHello {
    NodeHello::Auth {
        version: PROTOCOL_VERSION,
        node_id: node_id.into(),
        sign_pub: hex::encode(id.sign_pub()),
        signature: hex::encode(id.sign_auth(challenge, host)),
    }
}

/// An authenticated raw connection.
pub struct RawNode {
    pub sink: futures_util::stream::SplitSink<ClientWs, Message>,
    pub frames: mpsc::UnboundedReceiver<Frame>,
    pub closed: Arc<std::sync::atomic::AtomicBool>,
}

impl RawNode {
    pub async fn connect(relay: &TestRelay, node: &TestNode) -> RawNode {
        let mut ws = raw_ws(relay).await;
        let c = challenge(&mut ws).await;
        let ident = node.ident();
        let v = send_hello(
            &mut ws,
            &auth_hello(&node.identity(), &ident.node_id, &c, "127.0.0.1"),
        )
        .await;
        assert!(matches!(v, RelayVerdict::Welcome { .. }), "{v:?}");
        RawNode::from_ws(ws)
    }

    pub fn from_ws(ws: ClientWs) -> RawNode {
        let (sink, mut stream) = ws.split();
        let (tx, frames) = mpsc::unbounded_channel();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c = closed.clone();
        tokio::spawn(async move {
            while let Some(m) = stream.next().await {
                match m {
                    Ok(Message::Binary(b)) => {
                        if let Ok(f) = Frame::decode(b) {
                            let _ = tx.send(f);
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        RawNode {
            sink,
            frames,
            closed,
        }
    }

    pub async fn send(&mut self, f: Frame) {
        let _ = self.sink.send(Message::Binary(f.encode())).await;
    }

    pub async fn send_raw(&mut self, b: Vec<u8>) {
        let _ = self.sink.send(Message::Binary(b.into())).await;
    }

    /// Next frame that is not a PING (PINGs are answered).
    pub async fn next(&mut self, timeout: Duration) -> Option<Frame> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let f = tokio::time::timeout_at(deadline, self.frames.recv())
                .await
                .ok()??;
            if f.ty == FrameType::Ping {
                self.send(Frame::new(FrameType::Pong, 0, f.payload)).await;
                continue;
            }
            return Some(f);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

pub fn open_frame(stream: u32, dest: &str, port: u16) -> Frame {
    let p = OpenPayload {
        port,
        dest: dest.into(),
        ..Default::default()
    };
    Frame::new(FrameType::Open, stream, p.encode())
}

// ---------------------------------------------------------------------------
// Public HTTPS client helpers.

pub type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;

pub async fn tls_connect(relay: &TestRelay, sni: &str) -> ClientTls {
    let tcp = TcpStream::connect(relay.addr).await.unwrap();
    let cfg = warren::tls::client_config(Some(relay.pin)).unwrap();
    tokio_rustls::TlsConnector::from(cfg)
        .connect(warren::tls::server_name(sni).unwrap(), tcp)
        .await
        .unwrap()
}

/// Read one HTTP/1.1 response (status, headers lower-cased, decoded body).
pub async fn read_response<R: tokio::io::AsyncRead + Unpin>(
    r: &mut warren::http::BufConn<R>,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let resp = r.read_response(64 * 1024).await.unwrap();
    let headers: Vec<(String, String)> = resp
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.to_ascii_lowercase(),
                String::from_utf8_lossy(v).to_string(),
            )
        })
        .collect();
    let kind = resp.body_kind("GET").unwrap();
    let mut body = Vec::new();
    match kind {
        warren::http::BodyKind::None => {}
        warren::http::BodyKind::Length(n) => {
            struct V<'a>(&'a mut Vec<u8>);
            impl warren::http::ByteSink for V<'_> {
                async fn put(&mut self, d: bytes::Bytes) -> std::io::Result<()> {
                    self.0.extend_from_slice(&d);
                    Ok(())
                }
            }
            r.copy_exact(n, &mut V(&mut body)).await.unwrap();
        }
        warren::http::BodyKind::Chunked => loop {
            let line = r.read_line(4096).await.unwrap();
            let size = usize::from_str_radix(
                std::str::from_utf8(&line[..line.len() - 2])
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .trim(),
                16,
            )
            .unwrap();
            if size == 0 {
                // trailers
                loop {
                    let t = r.read_line(4096).await.unwrap();
                    if t.as_ref() == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            while r.buf.len() < size + 2 {
                assert!(r.fill().await.unwrap() > 0, "eof in chunk");
            }
            let chunk = r.buf.split_to(size + 2);
            body.extend_from_slice(&chunk[..size]);
        },
        warren::http::BodyKind::UntilClose => loop {
            if !r.buf.is_empty() {
                body.extend_from_slice(&r.buf.split());
            }
            if r.fill().await.unwrap() == 0 {
                break;
            }
        },
    }
    (resp.code, headers, body)
}

pub fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
}

/// A small HTTP/1.1 backend used behind publishes:
/// * `GET /headers` returns the forwarding headers it saw;
/// * `POST /echo` echoes the (Content-Length or chunked) body;
/// * `GET /chunked` answers with a chunked body;
/// * `GET /slow` answers after 1.5 s (long poll);
/// * `GET /ws` upgrades to a WebSocket echo.
pub async fn http_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(serve_backend(s));
        }
    });
    port
}

async fn serve_backend(s: TcpStream) {
    use warren::http::{BodyKind, BufConn};
    let (r, mut w) = s.into_split();
    let mut c = BufConn::new(r, None);
    loop {
        let req = match c.read_request(64 * 1024).await {
            Ok(Some(r)) => r,
            _ => return,
        };
        struct V<'a>(&'a mut Vec<u8>);
        impl warren::http::ByteSink for V<'_> {
            async fn put(&mut self, d: bytes::Bytes) -> std::io::Result<()> {
                self.0.extend_from_slice(&d);
                Ok(())
            }
        }
        let mut raw_body = Vec::new();
        let kind = req.body_kind().unwrap();
        c.copy_body(kind, &mut V(&mut raw_body)).await.unwrap();
        let body = if kind == BodyKind::Chunked {
            decode_chunked(&raw_body)
        } else {
            raw_body
        };
        let path = req.path.clone();
        if path == "/ws" && req.is_websocket_upgrade() {
            let key = req.header("sec-websocket-key").unwrap().to_vec();
            w.write_all(warren::ws::upgrade_response(&key).as_bytes())
                .await
                .unwrap();
            let stream = c.inner.reunite(w).unwrap();
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                stream,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            while let Some(Ok(m)) = ws.next().await {
                if m.is_text() || m.is_binary() {
                    let _ = ws.send(m).await;
                } else if m.is_close() {
                    break;
                }
            }
            return;
        }
        let resp = match path.as_str() {
            "/headers" => {
                let get = |n: &str| {
                    req.headers
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case(n))
                        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
                        .collect::<Vec<_>>()
                };
                let b = serde_json::json!({
                    "xff": get("x-forwarded-for"),
                    "proto": get("x-forwarded-proto"),
                    "host": get("x-forwarded-host"),
                    "forwarded": get("forwarded"),
                    "real_ip": get("x-real-ip"),
                })
                .to_string();
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{b}", b.len()).into_bytes()
            }
            "/echo" => {
                let mut v = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                v.extend_from_slice(&body);
                v
            }
            "/chunked" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n".to_vec(),
            "/slow" => {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nlate".to_vec()
            }
            _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        };
        if w.write_all(&resp).await.is_err() {
            return;
        }
    }
}

pub fn decode_chunked(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let end = i + raw[i..].windows(2).position(|w| w == b"\r\n").unwrap();
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[i..end])
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .trim(),
            16,
        )
        .unwrap();
        i = end + 2;
        if size == 0 {
            return out;
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size + 2;
    }
}

/// Write the identity file's relay/pin fields (to point a node at another relay).
pub fn repoint(node: &TestNode, relay_url: &str, pin: &[u8; 32]) {
    let p = node.paths.identity();
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
    v["relay"] = relay_url.into();
    v["relay_cert_sha256"] = hex::encode(pin).into();
    warren::fsutil::write_json(&p, &v).unwrap();
}
