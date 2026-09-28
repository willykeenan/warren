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
    let paths = paths(storage_root)?;
    tokio::time::timeout(
        Duration::from_secs(45),
        super::join_mode(
            &paths,
            code,
            relay,
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
}

/// Narrow outbound lifecycle handle. No daemon/control/forward/service mutation
/// API is public here. Strict pinned opening is a separate composition step.
pub struct EmbeddedClient {
    pub(crate) handle: Option<daemon::DaemonHandle>,
}
impl EmbeddedClient {
    pub async fn start(storage_root: &Path) -> Result<Self> {
        let cfg = daemon::DaemonConfig::new(paths(storage_root)?);
        Ok(Self {
            handle: Some(daemon::start_mode(cfg, true).await?),
        })
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
        // EmbeddedClient; the separately reviewed pinned API is composed later.
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
