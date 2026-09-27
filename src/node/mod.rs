//! The node: identity and policy files under `~/.warren` (or `WARREN_HOME`),
//! enrollment, and the daemon that keeps the relay connection.

pub mod control;
pub mod daemon;

use crate::crypto::{self, Identity};
use crate::fsutil;
use crate::net::RelayUrl;
use crate::proto::{NodeHello, RelayHello, RelayVerdict, PROTOCOL_VERSION};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use tokio_tungstenite::tungstenite::Message;

/// Locations of a node's files.
#[derive(Debug, Clone)]
pub struct NodePaths {
    pub home: PathBuf,
}

impl NodePaths {
    pub fn new(home: impl Into<PathBuf>) -> NodePaths {
        NodePaths { home: home.into() }
    }

    /// `$WARREN_HOME`, else `~/.warren`.
    pub fn from_env() -> Result<NodePaths> {
        if let Some(h) = std::env::var_os("WARREN_HOME").filter(|v| !v.is_empty()) {
            return Ok(NodePaths::new(PathBuf::from(h)));
        }
        let home = std::env::var_os("HOME").context("HOME is not set; set WARREN_HOME")?;
        Ok(NodePaths::new(PathBuf::from(home).join(".warren")))
    }

    pub fn identity(&self) -> PathBuf {
        self.home.join("identity.json")
    }
    pub fn shares(&self) -> PathBuf {
        self.home.join("shares.json")
    }
    pub fn known_peers(&self) -> PathBuf {
        self.home.join("known_peers.json")
    }
    pub fn forwards(&self) -> PathBuf {
        self.home.join("forwards.json")
    }
    pub fn publishes(&self) -> PathBuf {
        self.home.join("publishes.json")
    }
    pub fn socket(&self) -> PathBuf {
        self.home.join("warren.sock")
    }
    pub fn logs(&self) -> PathBuf {
        self.home.join("logs")
    }

    pub fn ensure(&self) -> Result<()> {
        fsutil::ensure_private_dir(&self.home)
    }
}

/// The node's enrollment record, including its private keys (file mode 0600).
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityFile {
    pub version: u32,
    pub node_id: String,
    pub name: String,
    pub relay: String,
    #[serde(default)]
    pub relay_cert_sha256: Option<String>,
    pub publish_domain: String,
    pub sign_pub: String,
    pub static_pub: String,
    sign_secret: String,
    static_secret: String,
    pub enrolled_at: i64,
}

impl fmt::Debug for IdentityFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityFile")
            .field("node_id", &self.node_id)
            .field("name", &self.name)
            .field("relay", &self.relay)
            .field("secrets", &"[redacted]")
            .finish()
    }
}

impl IdentityFile {
    pub fn load(paths: &NodePaths) -> Result<IdentityFile> {
        fsutil::read_json(&paths.identity())?.ok_or_else(|| {
            anyhow!(
                "this machine is not enrolled (no {}); run `warren join CODE --relay URL`",
                paths.identity().display()
            )
        })
    }

    pub fn identity(&self) -> Result<Identity> {
        let s = crypto::parse_key32(&self.sign_secret).context("corrupt identity file")?;
        let x = crypto::parse_key32(&self.static_secret).context("corrupt identity file")?;
        Ok(Identity::from_parts(s, x))
    }

    pub fn relay_url(&self) -> Result<RelayUrl> {
        RelayUrl::parse(&self.relay)
    }

    pub fn pin(&self) -> Result<Option<[u8; 32]>> {
        match &self.relay_cert_sha256 {
            None => Ok(None),
            Some(h) => Ok(Some(
                crypto::parse_key32(h).context("invalid relay certificate pin")?,
            )),
        }
    }

    pub fn fingerprint(&self) -> String {
        crypto::parse_key32(&self.static_pub)
            .map(|k| crypto::fingerprint(&k))
            .unwrap_or_default()
    }
}

/// One shared port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    pub port: u16,
    /// Node names allowed to connect; `None` means every enrolled node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
}

/// `shares.json`: the destination-side policy. Default deny.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharesFile {
    #[serde(default)]
    pub shares: Vec<Share>,
}

/// Result of a policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareDecision {
    Allowed,
    NotShared,
    Forbidden,
}

impl SharesFile {
    pub fn load(paths: &NodePaths) -> Result<SharesFile> {
        Ok(fsutil::read_json(&paths.shares())?.unwrap_or_default())
    }

    pub fn save(&self, paths: &NodePaths) -> Result<()> {
        paths.ensure()?;
        fsutil::write_json(&paths.shares(), self)
    }

    pub fn decide(&self, port: u16, src: &str) -> ShareDecision {
        match self.shares.iter().find(|s| s.port == port) {
            None => ShareDecision::NotShared,
            Some(Share { to: None, .. }) => ShareDecision::Allowed,
            Some(Share { to: Some(list), .. }) if list.iter().any(|n| n == src) => {
                ShareDecision::Allowed
            }
            Some(_) => ShareDecision::Forbidden,
        }
    }

    pub fn set(&mut self, port: u16, to: Option<Vec<String>>) {
        self.shares.retain(|s| s.port != port);
        self.shares.push(Share { port, to });
        self.shares.sort_by_key(|s| s.port);
    }

    pub fn remove(&mut self, port: u16) -> bool {
        let n = self.shares.len();
        self.shares.retain(|s| s.port != port);
        n != self.shares.len()
    }
}

/// A pinned peer key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownPeer {
    pub static_pub: String,
    pub first_seen: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_at: Option<i64>,
}

/// `known_peers.json`: keys pinned on first sight.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KnownPeers {
    #[serde(default)]
    pub relay: String,
    #[serde(default)]
    pub peers: BTreeMap<String, KnownPeer>,
}

/// Result of comparing a key with the pin for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    Match,
    New,
    Changed { pinned: [u8; 32] },
}

impl KnownPeers {
    pub fn load(paths: &NodePaths) -> Result<KnownPeers> {
        Ok(fsutil::read_json(&paths.known_peers())?.unwrap_or_default())
    }

    pub fn save(&self, paths: &NodePaths) -> Result<()> {
        paths.ensure()?;
        fsutil::write_json(&paths.known_peers(), self)
    }

    pub fn check(&self, name: &str, key: &[u8; 32]) -> PinCheck {
        match self
            .peers
            .get(name)
            .and_then(|p| crypto::parse_key32(&p.static_pub))
        {
            None => PinCheck::New,
            Some(k) if crypto::ct_eq(&k, key) => PinCheck::Match,
            Some(k) => PinCheck::Changed { pinned: k },
        }
    }

    pub fn pinned(&self, name: &str) -> Option<[u8; 32]> {
        self.peers
            .get(name)
            .and_then(|p| crypto::parse_key32(&p.static_pub))
    }

    pub fn pin(&mut self, name: &str, key: &[u8; 32], trusted: bool) {
        let now = crate::now_secs();
        self.peers.insert(
            name.to_string(),
            KnownPeer {
                static_pub: hex::encode(key),
                first_seen: now,
                trusted_at: trusted.then_some(now),
            },
        );
    }
}

/// A local port forwarded to a peer's shared port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Forward {
    pub local: u16,
    pub node: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForwardsFile {
    #[serde(default)]
    pub forwards: Vec<Forward>,
}

impl ForwardsFile {
    pub fn load(paths: &NodePaths) -> Result<ForwardsFile> {
        Ok(fsutil::read_json(&paths.forwards())?.unwrap_or_default())
    }
    pub fn save(&self, paths: &NodePaths) -> Result<()> {
        paths.ensure()?;
        fsutil::write_json(&paths.forwards(), self)
    }
}

/// A local port published under a public name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Publish {
    pub name: String,
    pub port: u16,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublishesFile {
    #[serde(default)]
    pub publishes: Vec<Publish>,
}

impl PublishesFile {
    pub fn load(paths: &NodePaths) -> Result<PublishesFile> {
        Ok(fsutil::read_json(&paths.publishes())?.unwrap_or_default())
    }
    pub fn save(&self, paths: &NodePaths) -> Result<()> {
        paths.ensure()?;
        fsutil::write_json(&paths.publishes(), self)
    }
}

/// Errors from enrollment, with the relay's machine-readable code.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("already enrolled as {0:?}; use --force to enroll again with new keys")]
    AlreadyEnrolled(String),
    #[error("relay refused enrollment ({code}): {message}")]
    Refused { code: String, message: String },
    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

/// Enroll this machine with a one-time code.
pub async fn join(
    paths: &NodePaths,
    code: &str,
    relay: &str,
    name: Option<&str>,
    pin: Option<[u8; 32]>,
    force: bool,
) -> Result<IdentityFile, JoinError> {
    if let Ok(existing) = IdentityFile::load(paths) {
        if !force {
            return Err(JoinError::AlreadyEnrolled(existing.name));
        }
    }
    let url = RelayUrl::parse(relay)?;
    if let Some(n) = name {
        if !crate::valid_name(n) {
            return Err(anyhow!("invalid name {n:?}: use [a-z0-9-]{{1,32}}").into());
        }
    }
    let code = crypto::normalize_code(code).ok_or_else(|| JoinError::Refused {
        code: "invalid_code".into(),
        message: "that is not a well-formed enrollment code".into(),
    })?;
    let id = Identity::generate();
    let mut ws = crate::ws::connect_relay(&url, pin).await?;
    let challenge = read_challenge(&mut ws).await?;
    let hello = NodeHello::Join {
        version: PROTOCOL_VERSION,
        code,
        name: name.map(str::to_string),
        sign_pub: hex::encode(id.sign_pub()),
        static_pub: hex::encode(id.static_pub),
        signature: hex::encode(id.sign_join(&challenge, url.auth_host())),
    };
    ws.send(Message::text(
        serde_json::to_string(&hello).map_err(anyhow::Error::from)?,
    ))
    .await
    .map_err(anyhow::Error::from)?;
    let verdict = read_verdict(&mut ws).await?;
    let _ = ws.close(None).await;
    let (node_id, name, publish_domain) = match verdict {
        RelayVerdict::Joined {
            node_id,
            name,
            publish_domain,
        } => (node_id, name, publish_domain),
        RelayVerdict::Error { code, message } => return Err(JoinError::Refused { code, message }),
        RelayVerdict::Welcome { .. } => return Err(anyhow!("unexpected relay reply").into()),
    };
    let file = IdentityFile {
        version: 1,
        node_id,
        name,
        relay: url.https(),
        relay_cert_sha256: pin.map(hex::encode),
        publish_domain,
        sign_pub: hex::encode(id.sign_pub()),
        static_pub: hex::encode(id.static_pub),
        sign_secret: hex::encode(id.sign_secret()),
        static_secret: hex::encode(id.static_secret),
        enrolled_at: crate::now_secs(),
    };
    paths.ensure()?;
    fsutil::write_json(&paths.identity(), &file)?;
    // Pins made against another relay's registry do not carry over.
    let mut peers = KnownPeers::load(paths)?;
    if peers.relay != file.relay {
        peers = KnownPeers {
            relay: file.relay.clone(),
            peers: BTreeMap::new(),
        };
        peers.save(paths)?;
    }
    Ok(file)
}

pub(crate) async fn read_challenge<S>(ws: &mut S) -> Result<[u8; 32]>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let m = tokio::time::timeout(std::time::Duration::from_secs(15), ws.next())
        .await
        .context("timed out waiting for the relay")?
        .context("relay closed the connection")??;
    let Message::Text(t) = m else {
        bail!("unexpected message from relay");
    };
    let RelayHello::Challenge { version, challenge } =
        serde_json::from_str(t.as_str()).context("malformed relay hello")?;
    if version != PROTOCOL_VERSION {
        bail!("relay speaks protocol version {version}, this build speaks {PROTOCOL_VERSION}");
    }
    crypto::parse_key32(&challenge).context("malformed challenge")
}

pub(crate) async fn read_verdict<S>(ws: &mut S) -> Result<RelayVerdict>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let m = tokio::time::timeout(std::time::Duration::from_secs(15), ws.next())
        .await
        .context("timed out waiting for the relay")?
        .context("relay closed the connection")??;
    let Message::Text(t) = m else {
        bail!("unexpected message from relay");
    };
    serde_json::from_str(t.as_str()).context("malformed relay reply")
}

/// Default node name: the host name, sanitized to `[a-z0-9-]{1,32}`.
pub fn default_name() -> String {
    let raw = std::process::Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    sanitize_name(&raw)
}

pub fn sanitize_name(raw: &str) -> String {
    let first = raw.trim().split('.').next().unwrap_or("");
    let mut s: String = first
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    s.truncate(32);
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "node".into()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_policy_default_deny() {
        let mut s = SharesFile::default();
        assert_eq!(s.decide(22, "a"), ShareDecision::NotShared);
        s.set(22, None);
        assert_eq!(s.decide(22, "a"), ShareDecision::Allowed);
        assert_eq!(s.decide(23, "a"), ShareDecision::NotShared);
        s.set(8080, Some(vec!["c".into()]));
        assert_eq!(s.decide(8080, "a"), ShareDecision::Forbidden);
        assert_eq!(s.decide(8080, "c"), ShareDecision::Allowed);
        assert!(s.remove(22));
        assert!(!s.remove(22));
        assert_eq!(s.decide(22, "a"), ShareDecision::NotShared);
    }

    #[test]
    fn pins() {
        let mut k = KnownPeers::default();
        assert_eq!(k.check("b", &[1; 32]), PinCheck::New);
        k.pin("b", &[1; 32], false);
        assert_eq!(k.check("b", &[1; 32]), PinCheck::Match);
        assert_eq!(
            k.check("b", &[2; 32]),
            PinCheck::Changed { pinned: [1; 32] }
        );
        k.pin("b", &[2; 32], true);
        assert_eq!(k.check("b", &[2; 32]), PinCheck::Match);
        assert!(k.peers["b"].trusted_at.is_some());
    }

    #[test]
    fn identity_file_hides_secrets() {
        let t = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(t.path().join("w"));
        let id = Identity::generate();
        let f = IdentityFile {
            version: 1,
            node_id: id.node_id(),
            name: "a".into(),
            relay: "https://r".into(),
            relay_cert_sha256: None,
            publish_domain: "r".into(),
            sign_pub: hex::encode(id.sign_pub()),
            static_pub: hex::encode(id.static_pub),
            sign_secret: hex::encode(id.sign_secret()),
            static_secret: hex::encode(id.static_secret),
            enrolled_at: 0,
        };
        paths.ensure().unwrap();
        fsutil::write_json(&paths.identity(), &f).unwrap();
        assert_eq!(fsutil::mode_of(&paths.home).unwrap(), 0o700);
        assert_eq!(fsutil::mode_of(&paths.identity()).unwrap(), 0o600);
        let back = IdentityFile::load(&paths).unwrap();
        assert_eq!(back.identity().unwrap().static_pub, id.static_pub);
        let dbg = format!("{back:?}");
        assert!(!dbg.contains(&hex::encode(id.static_secret)));
        assert!(!dbg.contains(&hex::encode(id.sign_secret())));
    }

    #[test]
    fn names() {
        assert_eq!(sanitize_name("My-MacBook.local\n"), "my-macbook");
        assert_eq!(sanitize_name("___"), "node");
        assert_eq!(sanitize_name(&"x".repeat(50)).len(), 32);
        assert!(crate::valid_name(&default_name()));
    }
}
