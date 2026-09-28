//! Client-only lifecycle with caller-owned private application storage.
use super::{daemon, IdentityFile, JoinError, NodePaths};
use anyhow::{bail, Context, Result};
use std::{path::Path, sync::Mutex, time::Duration};

// Serialize the create-new/SQLite-open window within this process. In particular,
// the initializing descriptor must close before another local SQLite owner can
// acquire POSIX locks on the newly created inode.
static HOME_LEASE_INIT: Mutex<()> = Mutex::new(());

#[cfg(unix)]
fn prepare_home_lock(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            drop(file);
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    // Never open/close an existing inode outside SQLite: closing any descriptor
    // for that inode releases this process's POSIX fcntl locks, including locks
    // held by a different, live SQLite connection. SQLite manages its own closes.
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("ownership lock must be a private, owner-controlled regular file");
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_home_lock(path: &Path) -> Result<()> {
    crate::fsutil::touch_private(path)
}

/// Process-safe ownership using SQLite's OS-backed exclusive lock. Closing the
/// connection (including process death) releases it; the file is never deleted.
pub(super) struct HomeLease {
    _connection: Mutex<rusqlite::Connection>,
}
impl HomeLease {
    pub(super) fn acquire(paths: &NodePaths) -> Result<Self> {
        let _initialization = HOME_LEASE_INIT
            .lock()
            .map_err(|_| anyhow::anyhow!("ownership lock initialization failed"))?;
        paths.ensure()?;
        // Resolve ordinary app-directory aliases only after ensuring the private
        // root exists. Keep the final filename unresolved so metadata checks and
        // SQLite NOFOLLOW still reject a symlink at the ownership file itself.
        // Canonicalizing a directory opens/closes no descriptor for the lock inode.
        let path = paths
            .home
            .canonicalize()
            .context("resolve private storage root for ownership lock")?
            .join(".warren-owner.sqlite3");
        prepare_home_lock(&path)?;
        let connection = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(Duration::ZERO)?;
        connection
            .execute_batch("BEGIN EXCLUSIVE")
            .context("storage is already owned or its ownership lock is unavailable")?;
        Ok(Self {
            _connection: Mutex::new(connection),
        })
    }
}

fn paths(storage_root: &Path) -> Result<NodePaths> {
    if !storage_root.is_absolute() {
        bail!("embedded storage root must be an explicit absolute path");
    }
    Ok(NodePaths::new(storage_root))
}

/// Validated public metadata. This type contains no identity secrets and has no
/// serialization implementation; callers choose their own public representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub name: String,
    pub noise_static_public_key: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub relay_https: String,
}

fn invalid_metadata() -> anyhow::Error {
    anyhow::anyhow!("invalid embedded identity metadata")
}

// Admit the full input before using the deliberately permissive core parser.
fn canonical_relay(value: &str) -> Result<String> {
    if value.len() > 2048
        || !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        || value.contains(['@', '?', '#', '\\'])
    {
        return Err(invalid_metadata());
    }
    let authority = value
        .strip_prefix("https://")
        .ok_or_else(invalid_metadata)?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty() || authority.contains('/') {
        return Err(invalid_metadata());
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(invalid_metadata)?;
        let host = host
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid_metadata())?;
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':').ok_or_else(invalid_metadata)?)
        };
        (host.to_string(), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(invalid_metadata());
        }
        if host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && host.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Err(invalid_metadata());
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
            value.parse::<u16>().map_err(|_| invalid_metadata())?
        }
        Some(_) => return Err(invalid_metadata()),
        None => 443,
    };
    if port == 0 {
        return Err(invalid_metadata());
    }
    let parsed = crate::net::RelayUrl { host, port };
    let canonical = parsed.https();
    if crate::net::RelayUrl::parse(&canonical).map_err(|_| invalid_metadata())? != parsed {
        return Err(invalid_metadata());
    }
    Ok(canonical)
}

impl PublicIdentity {
    pub fn from_identity(identity: &IdentityFile) -> Result<Self> {
        if !crate::valid_name(&identity.name) {
            return Err(invalid_metadata());
        }
        let relay_https = canonical_relay(&identity.relay)?;
        if relay_https != identity.relay {
            return Err(invalid_metadata());
        }
        let noise_static_public_key =
            crate::crypto::parse_key32(&identity.static_pub).ok_or_else(invalid_metadata)?;
        let signing_public_key =
            crate::crypto::parse_key32(&identity.sign_pub).ok_or_else(invalid_metadata)?;
        let derived = identity.identity().map_err(|_| invalid_metadata())?;
        if noise_static_public_key != derived.static_pub || signing_public_key != derived.sign_pub()
        {
            return Err(invalid_metadata());
        }
        Ok(Self {
            name: identity.name.clone(),
            noise_static_public_key,
            signing_public_key,
            relay_https,
        })
    }
}

/// Enroll once, without desktop control IPC or replacement of any existing
/// identity. Cancellation or an uncertain network reply must not be retried
/// automatically; the application owns explicit recovery.
pub async fn join(
    storage_root: &Path,
    code: &str,
    relay: &str,
    name: Option<&str>,
    relay_certificate_pin: Option<[u8; 32]>,
) -> Result<IdentityFile, JoinError> {
    let relay = canonical_relay(relay)
        .map_err(|_| JoinError::Usage("invalid embedded relay URL".into()))?;
    if name.is_some_and(|name| !crate::valid_name(name)) {
        return Err(JoinError::Usage("invalid embedded node name".into()));
    }
    let paths = paths(storage_root)?;
    let identity = tokio::time::timeout(
        Duration::from_secs(45),
        super::join_mode(
            &paths,
            code,
            &relay,
            name,
            relay_certificate_pin,
            false,
            true,
        ),
    )
    .await
    .map_err(|_| {
        JoinError::Usage("embedded enrollment timed out; outcome may be uncertain".into())
    })?
    .map_err(|error| match error {
        JoinError::Usage(_) => JoinError::Usage("embedded enrollment rejected".into()),
        JoinError::AlreadyEnrolled(_) => JoinError::AlreadyEnrolled("existing identity".into()),
        JoinError::DaemonRunning(_) => JoinError::DaemonRunning("embedded storage".into()),
        JoinError::Refused { .. } => JoinError::Refused {
            code: "refused".into(),
            message: "embedded enrollment refused".into(),
        },
        JoinError::Other(_) => JoinError::Other(anyhow::anyhow!(
            "embedded enrollment failed; outcome may be uncertain"
        )),
    })?;
    PublicIdentity::from_identity(&identity).map_err(|_| {
        JoinError::Other(anyhow::anyhow!(
            "embedded enrollment metadata invalid; outcome may be uncertain"
        ))
    })?;
    Ok(identity)
}

/// Narrow outbound lifecycle handle. No daemon/control/forward/service mutation
/// API is public here. All public opens require an explicitly approved key.
pub struct EmbeddedClient {
    pub(crate) handle: Option<daemon::DaemonHandle>,
    public_identity: PublicIdentity,
}
impl EmbeddedClient {
    pub async fn start(storage_root: &Path) -> Result<Self> {
        let cfg = daemon::DaemonConfig::new(paths(storage_root)?);
        let handle = daemon::start_mode(cfg, true)
            .await
            .map_err(|_| anyhow::anyhow!("embedded client could not start"))?;
        // start_mode validated this same immutable identity before spawning tasks.
        let public_identity = PublicIdentity::from_identity(&handle.inner.ident)?;
        Ok(Self {
            handle: Some(handle),
            public_identity,
        })
    }
    pub fn public_identity(&self) -> &PublicIdentity {
        &self.public_identity
    }
    pub async fn open_private_pinned(
        &self,
        dest: &str,
        port: u16,
        expected_key: &[u8; 32],
    ) -> Result<crate::noise::SecureChannel, daemon::OpenError> {
        self.handle
            .as_ref()
            .ok_or(daemon::OpenError::NotConnected)?
            .inner
            .open_private_pinned(dest, port, expected_key)
            .await
    }
    pub async fn open_gateway_pinned(
        &self,
        dest: &str,
        share: &str,
        expected_key: &[u8; 32],
    ) -> Result<crate::noise::SecureChannel, daemon::OpenError> {
        self.handle
            .as_ref()
            .ok_or(daemon::OpenError::NotConnected)?
            .inner
            .open_gateway_pinned(dest, share, expected_key)
            .await
    }
    /// Record an externally verified exact peer key; this performs no key lookup.
    pub async fn approve_verified_peer(
        &self,
        name: &str,
        key: &[u8; 32],
    ) -> Result<(), daemon::OpenError> {
        self.handle
            .as_ref()
            .ok_or(daemon::OpenError::NotConnected)?
            .inner
            .approve_peer_key(name, key)
            .await
    }
    /// Remove the exact approval. Existing channels require caller-owned draining.
    pub async fn forget_verified_peer(
        &self,
        name: &str,
        key: &[u8; 32],
    ) -> Result<(), daemon::OpenError> {
        self.handle
            .as_ref()
            .ok_or(daemon::OpenError::NotConnected)?
            .inner
            .forget_peer_key(name, key)
            .await
    }
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        match &self.handle {
            Some(h) => h.wait_connected(timeout).await,
            None => false,
        }
    }
    pub fn is_connected(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| h.is_connected())
    }
    /// Cancel the connection and await bounded transport task termination.
    pub async fn shutdown(mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await;
        }
    }
}
impl Drop for EmbeddedClient {
    fn drop(&mut self) {
        if let Some(h) = &self.handle {
            h.cancel_client();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{KnownPeers, SharesFile};

    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn outbound_transport_and_shutdown_drain_without_public_unpinned_api() {
        let root = tempfile::tempdir().unwrap();
        let relay = crate::relay::start(crate::relay::RelayConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1",
            root.path().join("relay"),
            crate::relay::TlsMode::SelfSigned,
        ))
        .await
        .unwrap();
        let url = format!("https://{}", relay.addr);
        let client_paths = NodePaths::new(root.path().join("phone"));
        let server_paths = NodePaths::new(root.path().join("server"));
        for (paths, name) in [(&client_paths, "phone"), (&server_paths, "server")] {
            let invite = relay
                .inner
                .db
                .create_invite(None, Duration::from_secs(60), crate::now_secs())
                .unwrap();
            join(&paths.home, &invite, &url, Some(name), relay.cert_sha256)
                .await
                .unwrap();
        }
        let key = IdentityFile::load(&server_paths)
            .unwrap()
            .identity()
            .unwrap()
            .static_pub;
        let mut pins = KnownPeers {
            relay: url,
            ..KnownPeers::default()
        };
        pins.pin("server", &key, true);
        pins.save(&client_paths).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut shares = SharesFile::default();
        shares.set(port, None);
        shares.save(&server_paths).unwrap();
        let server = daemon::start(daemon::DaemonConfig::new(server_paths))
            .await
            .unwrap();
        let client = EmbeddedClient::start(&client_paths.home).await.unwrap();
        assert!(server.wait_connected(Duration::from_secs(5)).await);
        assert!(client.wait_connected(Duration::from_secs(5)).await);
        // Internal transport-only probe. No ordinary-open method is exposed by
        // EmbeddedClient; public wrappers have separate strict approval coverage.
        let mut channel = client
            .handle
            .as_ref()
            .unwrap()
            .inner
            .open_private("server", port)
            .await
            .unwrap();
        let (mut tcp, _) = listener.accept().await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        channel.tx.send(b"abc").await.unwrap();
        let mut bytes = [0; 3];
        tcp.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abc");
        tcp.write_all(b"xyz").await.unwrap();
        assert_eq!(channel.rx.recv().await.unwrap().unwrap(), b"xyz");
        client.shutdown().await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), channel.rx.recv())
                .await
                .unwrap()
                .is_err()
        );
        assert!(channel.tx.send(b"after shutdown").await.is_err());
        server.shutdown().await;
        relay.shutdown().await;
    }
}
