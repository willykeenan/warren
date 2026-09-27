//! The relay: authenticates nodes, forwards private streams between them
//! without being able to read them, and terminates TLS for published names.

pub mod acme;
pub mod db;
pub mod link;
pub mod public;

use crate::http::{simple_response, Activity, BufConn, HttpError};
use crate::limits::{self, FailureLimiter};
use crate::mux::Tap;
use crate::tls::CertResolver;
use anyhow::{Context, Result};
use db::{Db, NodeRecord, PublishRecord};
use link::NodeLink;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

/// How the relay obtains certificates.
#[derive(Debug, Clone)]
pub enum TlsMode {
    /// PEM files (chain and key) used for every name.
    Files { cert: PathBuf, key: PathBuf },
    /// A persistent self-signed certificate (tests and local development).
    SelfSigned,
    /// Automatic certificates via ACME HTTP-01.
    Acme { email: String, directory: String },
}

/// Relay configuration.
#[derive(Clone)]
pub struct RelayConfig {
    pub listen: SocketAddr,
    /// The relay's own host name; nodes sign it into every authentication.
    pub domain: String,
    /// Published names live at `NAME.<publish_domain>`.
    pub publish_domain: String,
    pub state_dir: PathBuf,
    pub tls: TlsMode,
    /// Plain-HTTP listener for ACME HTTP-01 challenges and redirects.
    pub http_listen: Option<SocketAddr>,
    pub header_timeout: Duration,
    pub idle_timeout: Duration,
    pub ping_interval: Duration,
    pub revision_poll: Duration,
    /// Observer of every binary message the relay receives or sends on node links.
    pub tap: Option<Tap>,
}

impl RelayConfig {
    pub fn new(listen: SocketAddr, domain: &str, state_dir: PathBuf, tls: TlsMode) -> RelayConfig {
        RelayConfig {
            listen,
            domain: domain.to_ascii_lowercase(),
            publish_domain: domain.to_ascii_lowercase(),
            state_dir,
            tls,
            http_listen: None,
            header_timeout: limits::PUBLIC_HEADER_TIMEOUT,
            idle_timeout: limits::PUBLIC_IDLE_TIMEOUT,
            ping_interval: Duration::from_secs(20),
            revision_poll: Duration::from_secs(1),
            tap: None,
        }
    }
}

/// In-memory view of the database.
#[derive(Debug, Default)]
pub struct Registry {
    /// Active (non-revoked) nodes by id.
    pub nodes: HashMap<String, NodeRecord>,
    pub by_name: HashMap<String, String>,
    pub publishes: HashMap<String, PublishRecord>,
    /// Custom host name to publish name.
    pub domains: HashMap<String, String>,
    pub rev: i64,
}

/// Shared relay state.
pub struct RelayInner {
    pub cfg: RelayConfig,
    pub db: Db,
    pub resolver: Arc<CertResolver>,
    acceptor: TlsAcceptor,
    pub registry: RwLock<Registry>,
    pub online: Mutex<HashMap<String, Arc<NodeLink>>>,
    pub join_limiter: Mutex<FailureLimiter>,
    pub shutdown: CancellationToken,
    next_conn: std::sync::atomic::AtomicU64,
    pub public_slots: Arc<Semaphore>,
    pub public_per_ip: Mutex<HashMap<IpAddr, usize>>,
    pub acme: Option<Arc<acme::AcmeManager>>,
    pub cert_sha256: Option<[u8; 32]>,
}

/// A running relay.
pub struct RelayHandle {
    pub addr: SocketAddr,
    pub http_addr: Option<SocketAddr>,
    /// SHA-256 of the self-signed certificate nodes should pin (self-signed mode).
    pub cert_sha256: Option<[u8; 32]>,
    pub inner: Arc<RelayInner>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RelayHandle {
    /// Stop accepting, close every connection and wait for the tasks.
    pub async fn shutdown(self) {
        self.inner.shutdown.cancel();
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
        }
        let links: Vec<_> = self.inner.online.lock().unwrap().drain().collect();
        for (_, l) in links {
            l.out.close();
        }
    }

    /// Names of currently connected nodes.
    pub fn online_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .inner
            .online
            .lock()
            .unwrap()
            .values()
            .map(|l| l.name.clone())
            .collect();
        v.sort();
        v
    }
}

impl RelayInner {
    fn conn_id(&self) -> u64 {
        self.next_conn
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Reload the registry from the database; kick links of revoked nodes.
    pub fn reload(&self) -> Result<()> {
        let rev = self.db.revision()?;
        let nodes = self.db.nodes()?;
        let pubs = self.db.publishes()?;
        let domains = self.db.domains()?;
        let mut reg = Registry {
            rev,
            ..Default::default()
        };
        for n in nodes.into_iter().filter(|n| n.revoked_at.is_none()) {
            reg.by_name.insert(n.name.clone(), n.node_id.clone());
            reg.nodes.insert(n.node_id.clone(), n);
        }
        for p in pubs {
            reg.publishes.insert(p.name.clone(), p);
        }
        for (h, n) in domains {
            reg.domains.insert(h, n);
        }
        let hosts: Vec<String> = reg.domains.keys().cloned().collect();
        let pub_names: Vec<String> = reg.publishes.keys().cloned().collect();
        let active: std::collections::HashSet<String> = reg.nodes.keys().cloned().collect();
        *self.registry.write().unwrap() = reg;
        // Disconnect nodes that are no longer active (revoked).
        let kicked: Vec<Arc<NodeLink>> = {
            let mut online = self.online.lock().unwrap();
            let gone: Vec<String> = online
                .keys()
                .filter(|id| !active.contains(*id))
                .cloned()
                .collect();
            gone.iter().filter_map(|id| online.remove(id)).collect()
        };
        for l in kicked {
            tracing::info!(node = %l.name, "node revoked; disconnecting");
            l.send_event("revoked", serde_json::Value::Null);
            l.out.close();
        }
        // Certificates for custom domains and published names.
        match (&self.cfg.tls, &self.acme) {
            (TlsMode::SelfSigned, _) => {
                for h in hosts {
                    if !self.resolver.has_host(&h) {
                        if let Ok((c, k)) =
                            crate::tls::generate_self_signed(std::slice::from_ref(&h))
                        {
                            if let Ok(ck) =
                                crate::tls::certified_key_from_pem(c.as_bytes(), k.as_bytes())
                            {
                                self.resolver.set_host(&h, ck);
                            }
                        }
                    }
                }
            }
            (TlsMode::Acme { .. }, Some(acme)) => {
                for h in hosts {
                    acme.ensure(h);
                }
                for n in pub_names {
                    acme.ensure(format!("{n}.{}", self.cfg.publish_domain));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Public name for a Host value, if any.
    pub fn route_public(&self, host: &str) -> Option<String> {
        let reg = self.registry.read().unwrap();
        if let Some(n) = reg.domains.get(host) {
            return Some(n.clone());
        }
        let suffix = format!(".{}", self.cfg.publish_domain);
        let label = host.strip_suffix(&suffix)?;
        if crate::valid_publish_name(label) {
            Some(label.to_string())
        } else {
            None
        }
    }

    pub fn link_for(&self, node_id: &str) -> Option<Arc<NodeLink>> {
        self.online.lock().unwrap().get(node_id).cloned()
    }
}

/// Start a relay.
pub async fn start(cfg: RelayConfig) -> Result<RelayHandle> {
    crate::fsutil::ensure_private_dir(&cfg.state_dir)?;
    let db = Db::open(&cfg.state_dir)?;
    let resolver = Arc::new(CertResolver::new());
    let mut cert_sha256 = None;
    let mut acme_mgr = None;
    match &cfg.tls {
        TlsMode::Files { cert, key } => {
            resolver.set_default(crate::tls::load_cert_files(cert, key)?);
        }
        TlsMode::SelfSigned => {
            let mut sans = vec![cfg.domain.clone()];
            sans.push(format!("*.{}", cfg.publish_domain));
            if cfg.publish_domain != cfg.domain {
                sans.push(cfg.publish_domain.clone());
            }
            let (ck, fp) = crate::tls::persistent_self_signed(&cfg.state_dir, &sans)?;
            resolver.set_default(ck.clone());
            resolver.set_wildcard(&cfg.publish_domain, ck);
            cert_sha256 = Some(fp);
        }
        TlsMode::Acme { email, directory } => {
            let m = Arc::new(acme::AcmeManager::new(
                email.clone(),
                directory.clone(),
                cfg.state_dir.join("certs"),
                resolver.clone(),
            )?);
            m.load_existing()?;
            acme_mgr = Some(m);
        }
    }
    let acceptor = TlsAcceptor::from(crate::tls::server_config(resolver.clone())?);
    let listener = TcpListener::bind(cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    let addr = listener.local_addr()?;
    let http_listener = match cfg.http_listen {
        Some(a) => Some(
            TcpListener::bind(a)
                .await
                .with_context(|| format!("binding {a}"))?,
        ),
        None => None,
    };
    let http_addr = http_listener.as_ref().and_then(|l| l.local_addr().ok());
    let inner = Arc::new(RelayInner {
        cfg: cfg.clone(),
        db,
        resolver,
        acceptor,
        registry: RwLock::new(Registry::default()),
        online: Mutex::new(HashMap::new()),
        join_limiter: Mutex::new(FailureLimiter::new(
            limits::JOIN_FAILURES_PER_WINDOW,
            limits::JOIN_FAILURE_WINDOW,
        )),
        shutdown: CancellationToken::new(),
        next_conn: std::sync::atomic::AtomicU64::new(1),
        public_slots: Arc::new(Semaphore::new(limits::MAX_PUBLIC_CONNECTIONS)),
        public_per_ip: Mutex::new(HashMap::new()),
        acme: acme_mgr.clone(),
        cert_sha256,
    });
    inner.reload()?;
    if let Some(m) = &acme_mgr {
        m.ensure(cfg.domain.clone());
    }

    let mut tasks = Vec::new();
    // Accept loop.
    {
        let inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = inner.shutdown.cancelled() => break,
                    r = listener.accept() => match r {
                        Ok((tcp, peer)) => {
                            let inner = inner.clone();
                            tokio::spawn(async move { handle_conn(inner, tcp, peer).await });
                        }
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }));
    }
    // Revision poll: picks up admin changes (invites, revocations, domains).
    {
        let inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            let mut last = inner.registry.read().unwrap().rev;
            loop {
                tokio::select! {
                    _ = inner.shutdown.cancelled() => break,
                    _ = tokio::time::sleep(inner.cfg.revision_poll) => {}
                }
                match inner.db.revision() {
                    Ok(r) if r != last => {
                        last = r;
                        if let Err(e) = inner.reload() {
                            tracing::warn!("reloading state failed: {e:#}");
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!("reading state revision failed: {e:#}"),
                }
            }
        }));
    }
    if let Some(l) = http_listener {
        let inner = inner.clone();
        tasks.push(tokio::spawn(async move {
            acme::serve_http(l, inner.acme.clone(), inner.shutdown.clone()).await;
        }));
    }
    if let Some(m) = acme_mgr {
        let token = inner.shutdown.clone();
        tasks.push(tokio::spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = m.renew_loop() => {}
            }
        }));
    }
    tracing::info!(%addr, domain = %cfg.domain, "relay listening");
    Ok(RelayHandle {
        addr,
        http_addr,
        cert_sha256,
        inner,
        tasks,
    })
}

async fn write_and_close<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = w.write_all(bytes).await;
        let _ = w.shutdown().await;
    })
    .await;
}

async fn handle_conn(inner: Arc<RelayInner>, tcp: TcpStream, peer: SocketAddr) {
    let _ = tcp.set_nodelay(true);
    let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
    let deadline = tokio::time::Instant::now() + inner.cfg.header_timeout;
    let shutdown = inner.shutdown.clone();
    let work = async {
        let tls = match tokio::time::timeout_at(deadline, inner.acceptor.accept(tcp)).await {
            Ok(Ok(s)) => s,
            _ => return,
        };
        let sni = tls
            .get_ref()
            .1
            .server_name()
            .map(|s| s.to_ascii_lowercase());
        let activity = Activity::new();
        let mut conn = BufConn::new(tls, Some(activity.clone()));
        let req =
            match tokio::time::timeout_at(deadline, conn.read_request(limits::MAX_REQUEST_HEAD))
                .await
            {
                Err(_) => {
                    tracing::debug!(%peer, "request head timeout");
                    return;
                }
                Ok(Ok(Some(r))) => r,
                Ok(Ok(None)) => return,
                Ok(Err(HttpError::TooLarge)) => {
                    write_and_close(
                        &mut conn.inner,
                        &simple_response(
                            431,
                            "Request Header Fields Too Large",
                            "request header too large\n",
                            true,
                        ),
                    )
                    .await;
                    return;
                }
                Ok(Err(_)) => {
                    write_and_close(
                        &mut conn.inner,
                        &simple_response(400, "Bad Request", "bad request\n", true),
                    )
                    .await;
                    return;
                }
            };
        let host = match req.host().or_else(|| sni.clone()) {
            Some(h) => h,
            None => {
                write_and_close(
                    &mut conn.inner,
                    &simple_response(400, "Bad Request", "missing Host\n", true),
                )
                .await;
                return;
            }
        };
        if let Some(s) = &sni {
            if *s != host {
                write_and_close(
                    &mut conn.inner,
                    &simple_response(
                        421,
                        "Misdirected Request",
                        "Host does not match TLS server name\n",
                        true,
                    ),
                )
                .await;
                return;
            }
        }
        if host == inner.cfg.domain {
            api(inner.clone(), conn, req, peer).await;
        } else if let Some(name) = inner.route_public(&host) {
            public::serve(inner.clone(), conn, req, name, host, peer, activity).await;
        } else {
            write_and_close(
                &mut conn.inner,
                &simple_response(404, "Not Found", "unknown host\n", true),
            )
            .await;
        }
    };
    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = work => {}
    }
}

type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;

async fn api(
    inner: Arc<RelayInner>,
    mut conn: BufConn<ServerTls>,
    req: crate::http::Request,
    peer: SocketAddr,
) {
    let path = req.path.split('?').next().unwrap_or("").to_string();
    match (req.method.as_str(), path.as_str()) {
        ("GET", "/v1/node") if req.is_websocket_upgrade() => {
            let key = match req.header("sec-websocket-key") {
                Some(k) if req.header_str("sec-websocket-version").as_deref() == Some("13") => {
                    k.to_vec()
                }
                _ => {
                    write_and_close(
                        &mut conn.inner,
                        &simple_response(400, "Bad Request", "bad WebSocket request\n", true),
                    )
                    .await;
                    return;
                }
            };
            let resp = crate::ws::upgrade_response(&key);
            if conn.inner.write_all(resp.as_bytes()).await.is_err() {
                return;
            }
            let leftover = conn.buf.split().to_vec();
            let ws = tokio_tungstenite::WebSocketStream::from_partially_read(
                conn.inner,
                leftover,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                Some(crate::ws::config()),
            )
            .await;
            link::serve_node(inner, ws, peer).await;
        }
        ("GET", "/healthz") => {
            write_and_close(&mut conn.inner, &simple_response(200, "OK", "ok\n", true)).await;
        }
        ("GET", "/") => {
            write_and_close(
                &mut conn.inner,
                &simple_response(200, "OK", "warren relay\n", true),
            )
            .await;
        }
        _ => {
            write_and_close(
                &mut conn.inner,
                &simple_response(404, "Not Found", "not found\n", true),
            )
            .await;
        }
    }
}
