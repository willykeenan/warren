//! Private named gateway policy and cancellation. Targets never leave this node.
use super::{KnownPeers, NodePaths, SharesFile};
use crate::{
    crypto,
    gateway_policy::GatewayTarget,
    mux::{MuxReceiver, MuxSender},
    net, noise,
    proto::{ErrorCode, OpenPayload},
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayShare {
    pub name: String,
    pub target: String,
    pub generation: String,
    #[serde(deserialize_with = "unique_peers")]
    pub peers: BTreeMap<String, String>,
}

fn unique_peers<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Peers;
    impl<'de> serde::de::Visitor<'de> for Peers {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("unique gateway peer keys")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut peers = BTreeMap::new();
            while let Some((name, key)) = map.next_entry::<String, String>()? {
                if peers.insert(name, key).is_some() {
                    return Err(serde::de::Error::custom("duplicate gateway peer"));
                }
            }
            Ok(peers)
        }
    }
    deserializer.deserialize_map(Peers)
}

pub fn validate(shares: &[GatewayShare]) -> Result<()> {
    let mut names = HashSet::new();
    for s in shares {
        if !crate::valid_name(&s.name)
            || !names.insert(&s.name)
            || crypto::parse_key32(&s.generation).is_none()
            || s.peers.is_empty()
        {
            bail!("invalid or duplicate gateway share");
        }
        GatewayTarget::parse(&s.target).map_err(|_| anyhow::anyhow!("invalid gateway target"))?;
        for (name, key) in &s.peers {
            if !crate::valid_name(name) || crypto::parse_key32(key).is_none() {
                bail!("invalid gateway peer grant");
            }
        }
    }
    Ok(())
}

pub fn grant(
    paths: &NodePaths,
    name: String,
    target: String,
    to: Option<Vec<String>>,
) -> Result<GatewayShare> {
    if !crate::valid_name(&name) {
        bail!("share name must match [a-z0-9-] and be 1-32 characters");
    }
    GatewayTarget::parse(&target).map_err(|_| anyhow::anyhow!("target must be an exact permitted LAN host:port; public, loopback and relay overrides are unavailable"))?;
    let pins = KnownPeers::load(paths)?;
    let names = to.unwrap_or_else(|| pins.peers.keys().cloned().collect());
    let mut peers = BTreeMap::new();
    for peer in names {
        if !crate::valid_name(&peer) || peers.contains_key(&peer) {
            bail!("invalid or duplicate granted peer");
        }
        let key = pins.pinned(&peer).ok_or_else(|| anyhow::anyhow!("peer {peer} has no pinned key; verify its fingerprint and run warren trust before granting"))?;
        peers.insert(peer, hex::encode(key));
    }
    if peers.is_empty() {
        bail!("no pinned peers to grant; verify a peer fingerprint and run warren trust first");
    }
    Ok(GatewayShare {
        name,
        target,
        peers,
        generation: hex::encode(crypto::random32()),
    })
}

/// Offline caller must first establish the daemon is not running.
pub fn offline_mutate(paths: &NodePaths, new: Option<GatewayShare>, name: &str) -> Result<()> {
    if !crate::valid_name(name) {
        bail!("invalid share name");
    }
    if let Some(ref share) = new {
        validate(std::slice::from_ref(share))?;
        if share.name != name {
            bail!("gateway share name mismatch");
        }
    }
    let adding = new.is_some();
    let mut file = SharesFile::load(paths)?;
    // An intent is recorded before persistence; it never asserts activation.
    if adding {
        audit(paths, name, "", "policy", "grant_intent")?;
    }
    file.gateways.retain(|s| s.name != name);
    if let Some(s) = new {
        file.gateways.push(s);
    }
    file.save(paths)?;
    if !adding && audit(paths, name, "", "policy", "revoked_offline").is_err() {
        bail!("gateway removed from saved policy, but audit is unavailable; preserve and repair gateway-audit.json before granting again");
    }
    Ok(())
}

const MAX_AUDIT_RECORDS: usize = 512;
const MAX_AUDIT_BYTES: u64 = 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    at: i64,
    share: String,
    peer: String,
    event: String,
    reason: String,
}

fn read_audit(paths: &NodePaths) -> Result<Vec<AuditRecord>> {
    let path = paths.home.join("gateway-audit.json");
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if !meta.file_type().is_file() || meta.len() > MAX_AUDIT_BYTES => {
            bail!("invalid audit file")
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    let records: Vec<AuditRecord> = crate::fsutil::read_json(&path)?.unwrap_or_default();
    if records.len() > MAX_AUDIT_RECORDS
        || records.iter().any(|r| {
            (!r.share.is_empty() && !crate::valid_name(&r.share))
                || (!r.peer.is_empty() && !crate::valid_name(&r.peer))
                || r.event.len() > 32
                || r.reason.len() > 64
                || !r
                    .event
                    .bytes()
                    .chain(r.reason.bytes())
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
        })
    {
        bail!("invalid audit records");
    }
    Ok(records)
}

// Never reset malformed evidence. All externally surfaced failures are fixed text.
fn audit(paths: &NodePaths, share: &str, peer: &str, event: &str, reason: &str) -> Result<()> {
    let result = (|| {
        let mut records = read_audit(paths)?;
        records.push(AuditRecord {
            at: crate::now_secs(),
            share: share.into(),
            peer: peer.into(),
            event: event.into(),
            reason: reason.into(),
        });
        if records.len() > MAX_AUDIT_RECORDS {
            records.drain(..records.len() - MAX_AUDIT_RECORDS);
        }
        crate::fsutil::write_json(&paths.home.join("gateway-audit.json"), &records)
    })();
    result.map_err(|_:anyhow::Error| anyhow::anyhow!("gateway audit unavailable; preserve and repair gateway-audit.json before granting or connecting"))
}

#[derive(Serialize)]
struct AuditHealth {
    last_write: &'static str,
    degraded: bool,
    failures: u64,
    last_failure_at: Option<i64>,
}
impl Default for AuditHealth {
    fn default() -> Self {
        Self {
            last_write: "unattempted",
            degraded: false,
            failures: 0,
            last_failure_at: None,
        }
    }
}
impl AuditHealth {
    fn failed(&mut self) {
        self.degraded = true;
        self.failures = self.failures.saturating_add(1);
        self.last_failure_at = Some(crate::now_secs());
    }
}

struct Operation {
    share: Option<String>,
    generation: Option<String>,
    cancel: CancellationToken,
    done: watch::Receiver<bool>,
}
struct State {
    shares: Vec<GatewayShare>,
    operations: HashMap<u64, Operation>,
    next: u64,
}
pub struct GatewayRuntime {
    paths: NodePaths,
    identity: crypto::Identity,
    name: String,
    relay: net::RelayUrl,
    relay_peers: Mutex<HashSet<std::net::IpAddr>>,
    poisoned: std::sync::atomic::AtomicBool,
    state: Mutex<State>,
    policy_io: Mutex<()>,
    mutation: tokio::sync::Mutex<()>,
    audit_lock: Mutex<AuditHealth>,
}
struct Finished {
    runtime: Arc<GatewayRuntime>,
    id: u64,
    done: watch::Sender<bool>,
}
impl Drop for Finished {
    fn drop(&mut self) {
        self.runtime
            .state
            .lock()
            .unwrap()
            .operations
            .remove(&self.id);
        self.done.send_replace(true);
    }
}

impl GatewayRuntime {
    pub fn new(
        paths: NodePaths,
        identity: crypto::Identity,
        name: String,
        relay: net::RelayUrl,
    ) -> Result<Arc<Self>> {
        let shares = SharesFile::load(&paths)?.gateways;
        Ok(Arc::new(Self {
            paths,
            identity,
            name,
            relay,
            relay_peers: Mutex::new(HashSet::new()),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            state: Mutex::new(State {
                shares,
                operations: HashMap::new(),
                next: 0,
            }),
            policy_io: Mutex::new(()),
            mutation: tokio::sync::Mutex::new(()),
            audit_lock: Mutex::new(AuditHealth::default()),
        }))
    }
    pub fn status(&self) -> Vec<serde_json::Value> {
        self.refresh();
        self.state
            .lock()
            .unwrap()
            .shares
            .iter()
            .map(|s| serde_json::json!({"name":s.name}))
            .collect()
    }
    pub fn relay_connected(&self, address: std::net::IpAddr) {
        self.relay_peers.lock().unwrap().insert(address);
    }
    pub fn audit_health(&self) -> serde_json::Value {
        let mut health = self.audit_lock.lock().unwrap();
        if read_audit(&self.paths).is_err() {
            health.failed();
        }
        serde_json::json!({"last_write":health.last_write,"degraded":health.degraded,"failures":health.failures,"last_failure_at":health.last_failure_at,"admission":"audit_write_required"})
    }
    fn required_log(&self, share: &str, peer: &str, event: &str, reason: &str) -> Result<()> {
        let mut health = self.audit_lock.lock().unwrap();
        match audit(&self.paths, share, peer, event, reason) {
            Ok(()) => {
                health.last_write = "ok";
                health.degraded = false;
                Ok(())
            }
            Err(e) => {
                health.last_write = "failed";
                health.failed();
                Err(e)
            }
        }
    }
    fn log(&self, share: &str, peer: &str, event: &str, reason: &str) {
        if self.required_log(share, peer, event, reason).is_err() {
            tracing::warn!("gateway audit unavailable; new grants and connections require a successful audit write");
        }
    }
    /// Synchronous policy replacement and cancellation share the admission lock.
    fn replace(&self, shares: Vec<GatewayShare>) -> Vec<watch::Receiver<bool>> {
        let mut state = self.state.lock().unwrap();
        if state.shares == shares {
            return Vec::new();
        }
        let waits = state
            .operations
            .values()
            .filter(|op| match (&op.share, &op.generation) {
                (Some(name), Some(generation)) => !shares.iter().any(|s| {
                    &s.name == name
                        && &s.generation == generation
                        && state.shares.iter().any(|old| old == s)
                }),
                _ => true,
            })
            .map(|op| {
                op.cancel.cancel();
                op.done.clone()
            })
            .collect();
        state.shares = shares;
        waits
    }
    fn refresh(&self) -> Vec<watch::Receiver<bool>> {
        // Malformed/unreadable/removal denies all gateway access and cancels old handlers.
        let _io = self.policy_io.lock().unwrap();
        let shares = if self.poisoned.load(std::sync::atomic::Ordering::SeqCst) {
            Vec::new()
        } else {
            SharesFile::load(&self.paths)
                .map(|f| f.gateways)
                .unwrap_or_default()
        };
        self.replace(shares)
    }
    async fn drain(waits: Vec<watch::Receiver<bool>>) {
        for mut done in waits {
            while !*done.borrow_and_update() {
                if done.changed().await.is_err() {
                    break;
                }
            }
        }
    }
    pub async fn watch(self: Arc<Self>, stop: CancellationToken) {
        loop {
            tokio::select! { biased; _ = stop.cancelled() => { let waits = self.replace(Vec::new()); Self::drain(waits).await; return; }, _ = tokio::time::sleep(Duration::from_millis(100)) => {} }
            let _guard = self.mutation.lock().await;
            Self::drain(self.refresh()).await;
        }
    }
    pub async fn mutate_local(
        &self,
        port: u16,
        to: Option<Vec<String>>,
        remove: bool,
    ) -> Result<bool> {
        let _guard = self.mutation.lock().await;
        let _io = self.policy_io.lock().unwrap();
        if port == 0
            || to
                .as_ref()
                .is_some_and(|names| names.iter().any(|n| !crate::valid_name(n)))
        {
            bail!("invalid local share");
        }
        let mut file = SharesFile::load(&self.paths)?;
        let removed = if remove {
            file.remove(port)
        } else {
            file.set(port, to);
            false
        };
        file.save(&self.paths)?;
        Ok(removed)
    }
    pub async fn mutate(
        &self,
        new: Option<(String, String, Option<Vec<String>>)>,
        name: &str,
    ) -> Result<()> {
        let _guard = self.mutation.lock().await;
        if !crate::valid_name(name) {
            bail!("invalid share name");
        }
        let new = new
            .map(|(n, t, to)| grant(&self.paths, n, t, to))
            .transpose()?;
        if new.as_ref().is_some_and(|s| s.name != name) {
            bail!("gateway share name mismatch");
        }
        let adding = new.is_some();
        let (waits, saved) = {
            let _io = self.policy_io.lock().unwrap();
            let mut file = SharesFile::load(&self.paths)?;
            if adding {
                self.required_log(name, "", "policy", "grant_intent")?;
            }
            file.gateways.retain(|s| s.name != name);
            if let Some(s) = new {
                file.gateways.push(s);
            }
            let saved = file.save(&self.paths).is_ok();
            self.poisoned
                .store(!saved, std::sync::atomic::Ordering::SeqCst);
            let waits = self.replace(if saved { file.gateways } else { Vec::new() });
            (waits, saved)
        };
        Self::drain(waits).await;
        if !saved {
            bail!("policy persistence failed; access canceled; repair file before restart");
        }
        if !adding && self.required_log(name, "", "policy", "revoked").is_err() {
            bail!("gateway revoked and connections drained, but audit is unavailable; preserve and repair gateway-audit.json before granting or connecting");
        }
        Ok(())
    }
    pub fn spawn(self: &Arc<Self>, p: OpenPayload, tx: MuxSender, rx: MuxReceiver) {
        self.refresh();
        let cancel = CancellationToken::new();
        let (done, recv) = watch::channel(false);
        let id = {
            let mut state = self.state.lock().unwrap();
            state.next += 1;
            let id = state.next;
            state.operations.insert(
                id,
                Operation {
                    share: None,
                    generation: None,
                    cancel: cancel.clone(),
                    done: recv,
                },
            );
            id
        };
        let runtime = self.clone();
        tokio::spawn(async move {
            let _finished = Finished {
                runtime: runtime.clone(),
                id,
                done,
            };
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = runtime.incoming(id, p, tx, rx) => {} }
        });
    }
    async fn incoming(&self, id: u64, p: OpenPayload, tx: MuxSender, rx: MuxReceiver) {
        if !p.is_gateway() || !crate::valid_name(&p.src) || p.dest != self.name {
            tx.reject(ErrorCode::BadRequest, "invalid gateway selector");
            return;
        }
        let Some(claimed) = p.src_static else {
            tx.reject(ErrorCode::BadRequest, "missing peer key");
            return;
        };
        let known = KnownPeers::load(&self.paths)
            .ok()
            .and_then(|k| k.pinned(&p.src));
        if known != Some(claimed) {
            self.log("", &p.src, "refusal", "unknown_or_changed_key");
            tx.reject(
                ErrorCode::KeyChanged,
                "gateway requires a pinned, explicitly granted key",
            );
            return;
        }
        if self
            .required_log("", &p.src, "open", "handshake_intent")
            .is_err()
        {
            tx.reject(ErrorCode::Internal, "gateway audit unavailable");
            return;
        }
        if !tx.accept() {
            return;
        }
        let Ok(responder) = noise::respond(tx, rx, &self.identity).await else {
            self.log("", &p.src, "refusal", "handshake");
            return;
        };
        let h = &responder.hello;
        if h.v != 1
            || h.src != p.src
            || h.dest != self.name
            || h.port != 0
            || !crypto::ct_eq(&responder.remote_static, &claimed)
            || !h.share.as_ref().is_some_and(|s| crate::valid_name(s))
        {
            responder.refuse(ErrorCode::Forbidden);
            return;
        }
        let name = h.share.clone().unwrap();
        let share = {
            self.refresh();
            let mut state = self.state.lock().unwrap();
            let share = state
                .shares
                .iter()
                .find(|s| {
                    s.name == name
                        && s.peers.get(&p.src).and_then(|k| crypto::parse_key32(k)) == Some(claimed)
                })
                .cloned();
            if let (Some(s), Some(op)) = (&share, state.operations.get_mut(&id)) {
                op.share = Some(name.clone());
                op.generation = Some(s.generation.clone());
                if op.cancel.is_cancelled() {
                    return;
                }
            }
            share
        };
        let Some(share) = share else {
            self.log(&name, &p.src, "refusal", "not_granted");
            responder.refuse(ErrorCode::Forbidden);
            return;
        };
        let Ok(confirmed) = responder.complete().await else {
            self.log(&name, &p.src, "refusal", "confirmation");
            return;
        };
        self.refresh();
        if !self.current(id, &share) {
            confirmed.refuse(ErrorCode::Forbidden).await;
            return;
        }
        if self
            .required_log(&name, &p.src, "connect", "connect_intent")
            .is_err()
        {
            confirmed.refuse(ErrorCode::Internal).await;
            return;
        }
        let target = GatewayTarget::parse(&share.target).expect("validated policy");
        let relay_peers: Vec<_> = self.relay_peers.lock().unwrap().iter().copied().collect();
        let tcp = match net::dial_gateway(&target, &self.relay, &relay_peers).await {
            Ok(t) => t,
            Err(_) => {
                self.log(&name, &p.src, "refusal", "address_or_connect");
                confirmed.refuse(ErrorCode::ConnectFailed).await;
                return;
            }
        };
        self.refresh();
        if !self.current(id, &share) {
            drop(tcp);
            confirmed.refuse(ErrorCode::Forbidden).await;
            return;
        }
        if self
            .required_log(&name, &p.src, "connect", "connect_ready")
            .is_err()
        {
            drop(tcp);
            confirmed.refuse(ErrorCode::Internal).await;
            return;
        }
        let Ok(chan) = confirmed.accept().await else {
            return;
        };
        let (r, w) = tcp.into_split();
        let _ = chan.pipe(r, w).await;
        self.log(&name, &p.src, "close", "stream_ended");
    }
    fn current(&self, id: u64, share: &GatewayShare) -> bool {
        let state = self.state.lock().unwrap();
        state.shares.contains(share)
            && state
                .operations
                .get(&id)
                .is_some_and(|op| !op.cancel.is_cancelled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, NodePaths, Arc<GatewayRuntime>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(dir.path());
        paths.ensure().unwrap();
        let identity = crypto::Identity::generate();
        let mut pins = KnownPeers::default();
        pins.pin("peer", &identity.static_pub, true);
        pins.save(&paths).unwrap();
        let runtime = GatewayRuntime::new(
            paths.clone(),
            identity,
            "gateway".into(),
            net::RelayUrl::parse("https://127.0.0.1").unwrap(),
        )
        .unwrap();
        (dir, paths, runtime)
    }
    fn request() -> Option<(String, String, Option<Vec<String>>)> {
        Some(("camera".into(), "192.168.1.2:554".into(), None))
    }

    #[tokio::test]
    async fn damaged_audit_blocks_online_and_offline_grants_and_connect_admission() {
        for directory in [false, true] {
            let (_dir, paths, runtime) = fixture();
            let audit_path = paths.home.join("gateway-audit.json");
            if directory {
                std::fs::create_dir(&audit_path).unwrap();
            } else {
                std::fs::write(&audit_path, b"{damaged").unwrap();
            }
            assert!(runtime
                .mutate(request(), "camera")
                .await
                .unwrap_err()
                .to_string()
                .contains("audit unavailable"));
            assert!(SharesFile::load(&paths).unwrap().gateways.is_empty());
            assert!(runtime.status().is_empty());
            let share = grant(&paths, "camera".into(), "192.168.1.2:554".into(), None).unwrap();
            assert!(offline_mutate(&paths, Some(share), "camera")
                .unwrap_err()
                .to_string()
                .contains("audit unavailable"));
            assert!(SharesFile::load(&paths).unwrap().gateways.is_empty());
            assert!(runtime
                .required_log("camera", "peer", "connect", "connect_intent")
                .is_err());
            let health = runtime.audit_health();
            assert_eq!(health["degraded"], true);
            assert_eq!(health["last_write"], "failed");
            let serialized = health.to_string();
            assert!(!serialized.contains("192.168"));
            assert!(!serialized.contains("damaged"));
            if directory {
                assert!(audit_path.is_dir());
            } else {
                assert_eq!(std::fs::read(audit_path).unwrap(), b"{damaged");
            }
        }
    }

    #[tokio::test]
    async fn offline_revoke_survives_bad_audit_and_repair_allows_new_grants() {
        let (_dir, paths, runtime) = fixture();
        let share = grant(&paths, "camera".into(), "192.168.1.2:554".into(), None).unwrap();
        offline_mutate(&paths, Some(share), "camera").unwrap();
        let records = read_audit(&paths).unwrap();
        assert_eq!(records[0].reason, "grant_intent");
        let audit_path = paths.home.join("gateway-audit.json");
        std::fs::write(&audit_path, b"{damaged").unwrap();
        assert!(offline_mutate(&paths, None, "camera")
            .unwrap_err()
            .to_string()
            .contains("removed from saved policy"));
        assert!(SharesFile::load(&paths).unwrap().gateways.is_empty());
        // Explicit repair preserves the old bytes; the running path never resets them.
        let preserved = paths.home.join("gateway-audit.preserved.json");
        std::fs::rename(&audit_path, &preserved).unwrap();
        runtime.mutate(request(), "camera").await.unwrap();
        assert_eq!(runtime.status().len(), 1);
        assert_eq!(runtime.audit_health()["degraded"], false);
        assert_eq!(std::fs::read(preserved).unwrap(), b"{damaged");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unwritable_audit_directory_denies_grants_without_activation() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, paths, runtime) = fixture();
        crate::fsutil::write_json(
            &paths.home.join("gateway-audit.json"),
            &Vec::<AuditRecord>::new(),
        )
        .unwrap();
        std::fs::set_permissions(&paths.home, std::fs::Permissions::from_mode(0o500)).unwrap();
        let online = runtime.mutate(request(), "camera").await;
        let offline = offline_mutate(
            &paths,
            Some(grant(&paths, "camera".into(), "192.168.1.2:554".into(), None).unwrap()),
            "camera",
        );
        std::fs::set_permissions(&paths.home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(online
            .unwrap_err()
            .to_string()
            .contains("audit unavailable"));
        assert!(offline
            .unwrap_err()
            .to_string()
            .contains("audit unavailable"));
        assert!(SharesFile::load(&paths).unwrap().gateways.is_empty());
        assert!(read_audit(&paths).unwrap().is_empty());
    }

    #[test]
    fn malformed_grants_and_duplicate_peers_fail_closed() {
        let key = hex::encode([7u8; 32]);
        let raw = format!(
            r#"{{"name":"camera","target":"192.168.1.7:554","generation":"{key}","peers":{{"a":"{key}","a":"{key}"}}}}"#
        );
        assert!(serde_json::from_str::<GatewayShare>(&raw).is_err());
        let share = GatewayShare {
            name: "camera".into(),
            target: "192.168.1.7:554".into(),
            generation: key.clone(),
            peers: BTreeMap::from([("a".into(), key)]),
        };
        assert!(validate(std::slice::from_ref(&share)).is_ok());
        assert!(validate(&[share.clone(), share.clone()]).is_err());
        let mut invalid = share;
        invalid.peers.insert("a".into(), "badkey".into());
        assert!(validate(&[invalid]).is_err());
    }
    #[tokio::test]
    async fn revoke_waits_for_pending_operation_drop() {
        let dir = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(dir.path());
        paths.ensure().unwrap();
        let identity = crypto::Identity::generate();
        let mut pins = KnownPeers::default();
        pins.pin("peer", &identity.static_pub, true);
        pins.save(&paths).unwrap();
        let share = grant(&paths, "camera".into(), "192.168.1.2:554".into(), None).unwrap();
        let mut file = SharesFile::default();
        file.gateways.push(share.clone());
        file.save(&paths).unwrap();
        let runtime = GatewayRuntime::new(
            paths,
            identity,
            "gateway".into(),
            net::RelayUrl::parse("https://127.0.0.1").unwrap(),
        )
        .unwrap();
        let token = CancellationToken::new();
        let (done, recv) = watch::channel(false);
        runtime.state.lock().unwrap().operations.insert(
            1,
            Operation {
                share: Some(share.name),
                generation: Some(share.generation),
                cancel: token.clone(),
                done: recv,
            },
        );
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        struct DropProbe(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let state = runtime.clone();
        let probe = dropped.clone();
        let task = tokio::spawn(async move {
            let _finished = Finished {
                runtime: state,
                id: 1,
                done,
            };
            let pending_resolution = async {
                let _drop = DropProbe(probe);
                std::future::pending::<()>().await;
            };
            tokio::select! {biased; _=token.cancelled()=>{}, _=pending_resolution=>{}}
        });
        tokio::task::yield_now().await;
        std::fs::write(runtime.paths.home.join("gateway-audit.json"), b"{damaged").unwrap();
        let error = runtime.mutate(None, "camera").await.unwrap_err();
        assert!(error
            .to_string()
            .contains("revoked and connections drained"));
        assert!(SharesFile::load(&runtime.paths)
            .unwrap()
            .gateways
            .is_empty());
        assert_eq!(runtime.audit_health()["degraded"], true);
        assert_eq!(
            std::fs::read(runtime.paths.home.join("gateway-audit.json")).unwrap(),
            b"{damaged"
        );
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(task.is_finished());
        assert!(runtime.state.lock().unwrap().operations.is_empty());
    }
}
