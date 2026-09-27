//! The node: identity and policy files under `~/.warren` (on Windows
//! `%LOCALAPPDATA%\warren`; or `WARREN_HOME`, or `--home`), enrollment, and
//! the daemon that keeps the relay connection.

pub mod control;
pub mod daemon;
pub mod framed;
pub mod ipc;

use crate::crypto::{self, Identity};
use crate::fsutil;
use crate::net::RelayUrl;
use crate::proto::{NodeHello, RelayHello, RelayVerdict, PROTOCOL_VERSION};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use tokio_tungstenite::tungstenite::Message;

/// Longest Unix socket path this platform accepts (`sun_path` less its
/// terminating NUL). Windows uses a named pipe whose name does not depend on
/// the length of the home.
pub const MAX_SOCKET_PATH: usize = if cfg!(any(target_os = "linux", target_os = "android")) {
    107
} else {
    103
};

/// The node home is too deep for its control socket (Unix only).
#[derive(Debug, Clone, thiserror::Error)]
#[error(
    "WARREN_HOME is too long for the control socket ({path} is {len} bytes; the limit is \
     {MAX_SOCKET_PATH}): use a shorter WARREN_HOME"
)]
pub struct SocketPathTooLong {
    pub path: String,
    pub len: usize,
}

/// Locations of a node's files.
#[derive(Debug, Clone)]
pub struct NodePaths {
    pub home: PathBuf,
}

impl NodePaths {
    pub fn new(home: impl Into<PathBuf>) -> NodePaths {
        NodePaths { home: home.into() }
    }

    /// The node home: `cli_home` (`--home`) if given, else `$WARREN_HOME`,
    /// else the default: `~/.warren` on Unix, `%LOCALAPPDATA%\warren` on
    /// Windows (local, not roaming, so keys never follow a roaming profile to
    /// another machine; `HOME` is ignored there, so Git Bash, PowerShell and
    /// cmd agree).
    pub fn resolve(cli_home: Option<&Path>) -> Result<NodePaths> {
        if let Some(h) = cli_home.filter(|h| !h.as_os_str().is_empty()) {
            return Ok(NodePaths::new(h));
        }
        if let Some(h) = std::env::var_os("WARREN_HOME").filter(|v| !v.is_empty()) {
            return Ok(NodePaths::new(PathBuf::from(h)));
        }
        Ok(NodePaths::new(default_home()?))
    }

    /// [`NodePaths::resolve`] without `--home`.
    pub fn from_env() -> Result<NodePaths> {
        NodePaths::resolve(None)
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
    /// The control socket.
    #[cfg(unix)]
    pub fn socket(&self) -> PathBuf {
        self.home.join("warren.sock")
    }
    /// [`NodePaths::socket`], or an error saying the home is too long for a
    /// Unix socket path.
    #[cfg(unix)]
    pub fn checked_socket(&self) -> Result<PathBuf, SocketPathTooLong> {
        let p = self.socket();
        let len = p.as_os_str().len();
        if len > MAX_SOCKET_PATH {
            return Err(SocketPathTooLong {
                path: p.display().to_string(),
                len,
            });
        }
        Ok(p)
    }
    /// Check that the daemon of this home can have a control channel: on
    /// Unix the socket path must fit `sun_path`; Windows has no limit.
    pub fn check_control(&self) -> Result<(), SocketPathTooLong> {
        #[cfg(unix)]
        self.checked_socket()?;
        Ok(())
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
        fsutil::ensure_private_file(&paths.identity())?;
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
    /// Load the pin store. A file that cannot be parsed, or that holds an
    /// entry whose key is not a valid key, is an error: callers must fail
    /// closed rather than treat pinned peers as new.
    pub fn load(paths: &NodePaths) -> Result<KnownPeers> {
        let path = paths.known_peers();
        let k: KnownPeers = fsutil::read_json(&path)?.unwrap_or_default();
        for (name, p) in &k.peers {
            if crypto::parse_key32(&p.static_pub).is_none() {
                bail!(
                    "{}: the pinned key for {name:?} is not a valid key",
                    path.display()
                );
            }
        }
        Ok(k)
    }

    pub fn save(&self, paths: &NodePaths) -> Result<()> {
        paths.ensure()?;
        fsutil::write_json(&paths.known_peers(), self)
    }

    pub fn check(&self, name: &str, key: &[u8; 32]) -> PinCheck {
        let Some(p) = self.peers.get(name) else {
            return PinCheck::New;
        };
        match crypto::parse_key32(&p.static_pub) {
            Some(k) if crypto::ct_eq(&k, key) => PinCheck::Match,
            Some(k) => PinCheck::Changed { pinned: k },
            // An entry that exists but cannot be read never counts as "new".
            None => PinCheck::Changed { pinned: [0; 32] },
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
    /// The daemon is running with the current identity and would keep using it.
    #[error("warren is running for {0}; stop it first with `warren down`, run `warren join` again, then start it with `warren up` (or `warren install`)")]
    DaemonRunning(String),
    /// Invalid arguments, found before contacting the relay.
    #[error("{0}")]
    Usage(String),
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
    let url = RelayUrl::parse(relay).map_err(|e| JoinError::Usage(format!("{e:#}")))?;
    if let Some(n) = name {
        if !crate::valid_name(n) {
            return Err(JoinError::Usage(format!(
                "invalid name {n:?}: use [a-z0-9-]{{1,32}}"
            )));
        }
    }
    // A home too long for the control socket could never run `warren up`.
    paths
        .check_control()
        .map_err(|e| JoinError::Usage(e.to_string()))?;
    // A running daemon loaded the current identity at start and would keep
    // authenticating with it (revoked, after a re-enrollment) forever.
    if control::daemon_running(paths).await {
        return Err(JoinError::DaemonRunning(paths.home.display().to_string()));
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
        RelayVerdict::Error { code, message } => {
            return Err(JoinError::Refused {
                code: crate::sanitize_remote_code(&code),
                message: crate::sanitize_remote_text(&message),
            })
        }
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

/// The default node home (see [`NodePaths::resolve`]).
#[cfg(unix)]
pub fn default_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; set WARREN_HOME")?;
    Ok(PathBuf::from(home).join(".warren"))
}

/// The default node home (see [`NodePaths::resolve`]).
#[cfg(windows)]
pub fn default_home() -> Result<PathBuf> {
    let var = |n: &str| {
        std::env::var_os(n)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    var("LOCALAPPDATA")
        .or_else(|| var("USERPROFILE").map(|p| p.join("AppData").join("Local")))
        .map(|p| p.join("warren"))
        .context("neither LOCALAPPDATA nor USERPROFILE is set; set WARREN_HOME")
}

/// Default node name: the host name, sanitized to `[a-z0-9-]{1,32}`.
#[cfg(unix)]
pub fn default_name() -> String {
    let raw = std::process::Command::new("uname")
        .arg("-n")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    sanitize_name(&raw)
}

/// Default node name: the computer name, sanitized to `[a-z0-9-]{1,32}`.
#[cfg(windows)]
pub fn default_name() -> String {
    sanitize_name(&std::env::var("COMPUTERNAME").unwrap_or_default())
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

    #[cfg(unix)]
    #[test]
    fn control_socket_path_length() {
        let ok = NodePaths::new("/tmp/w");
        assert_eq!(ok.checked_socket().unwrap(), ok.socket());
        let longest = NodePaths::new(
            "/".to_string() + &"h".repeat(MAX_SOCKET_PATH - "/warren.sock".len() - 1),
        );
        assert!(longest.checked_socket().is_ok());
        let deep = NodePaths::new(longest.home.join("x"));
        let e = deep.checked_socket().unwrap_err();
        assert_eq!(e.len, MAX_SOCKET_PATH + 2);
        assert!(e.to_string().contains("use a shorter WARREN_HOME"), "{e}");
        // The platform takes the longest path and refuses anything longer
        // (the directories do not exist, so a usable path fails with NotFound).
        let err = |p: &NodePaths| {
            std::os::unix::net::UnixListener::bind(p.socket())
                .unwrap_err()
                .kind()
        };
        assert_eq!(err(&longest), std::io::ErrorKind::NotFound);
        let one_more = NodePaths::new(format!("{}h", longest.home.display()));
        assert_eq!(err(&one_more), std::io::ErrorKind::InvalidInput);
    }

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
    fn pin_store_fails_closed() {
        let t = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(t.path().join("w"));
        let mut k = KnownPeers::default();
        k.pin("b", &[1; 32], false);
        k.save(&paths).unwrap();
        assert!(KnownPeers::load(&paths).unwrap().pinned("b").is_some());
        // Truncated file.
        std::fs::write(paths.known_peers(), b"{\"relay\": \"https://x").unwrap();
        assert!(KnownPeers::load(&paths).is_err());
        // Parsable file with a broken key.
        std::fs::write(
            paths.known_peers(),
            br#"{"relay":"https://x","peers":{"b":{"static_pub":"zz","first_seen":1}}}"#,
        )
        .unwrap();
        assert!(KnownPeers::load(&paths).is_err());
        // In memory, a broken entry is never "new".
        let mut k = KnownPeers::default();
        k.peers.insert(
            "b".into(),
            KnownPeer {
                static_pub: "zz".into(),
                first_seen: 1,
                trusted_at: None,
            },
        );
        assert!(matches!(k.check("b", &[1; 32]), PinCheck::Changed { .. }));
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
        #[cfg(unix)]
        {
            assert_eq!(fsutil::mode_of(&paths.home).unwrap(), 0o700);
            assert_eq!(fsutil::mode_of(&paths.identity()).unwrap(), 0o600);
        }
        assert!(fsutil::is_private(&paths.home).unwrap());
        assert!(fsutil::is_private(&paths.identity()).unwrap());
        let back = IdentityFile::load(&paths).unwrap();
        assert_eq!(back.identity().unwrap().static_pub, id.static_pub);
        let dbg = format!("{back:?}");
        assert!(!dbg.contains(&hex::encode(id.static_secret)));
        assert!(!dbg.contains(&hex::encode(id.sign_secret())));
    }

    #[test]
    fn home_resolution() {
        let t = tempfile::tempdir().unwrap();
        let explicit = t.path().join("explicit");
        assert_eq!(NodePaths::resolve(Some(&explicit)).unwrap().home, explicit);
        // An empty --home is ignored like an empty WARREN_HOME.
        let empty = PathBuf::new();
        let fallback = NodePaths::resolve(Some(&empty)).unwrap();
        assert_eq!(fallback.home, NodePaths::from_env().unwrap().home);
    }

    #[test]
    fn names() {
        assert_eq!(sanitize_name("My-MacBook.local\n"), "my-macbook");
        assert_eq!(sanitize_name("DESKTOP-4F2K9QL"), "desktop-4f2k9ql");
        assert_eq!(sanitize_name("___"), "node");
        assert_eq!(sanitize_name(&"x".repeat(50)).len(), 32);
        assert!(crate::valid_name(&default_name()));
    }
}
