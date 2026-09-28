//! Local-only enrollment state. There is no network/CLI redemption endpoint here.
use crate::{
    crypto,
    node::{
        daemon::DaemonInner,
        private_service::{ServiceContext, ServiceRegistration},
    },
};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::fs;

const APPROVAL_TTL: u64 = 120;
const CREDENTIAL_TTL: u64 = 86400;
const MAX_TOMBSTONES: usize = 128;
const MAX_STATE: usize = 128 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentError {
    #[error("enrollment_state_unavailable")]
    Unavailable,
    #[error("platform_not_qualified")]
    Unsupported,
    #[error("peer_not_approved")]
    PeerNotApproved,
    #[error("enrollment_invalid")]
    Invalid,
    #[error("enrollment_consumed")]
    Consumed,
    #[error("approval_changed")]
    Changed,
    #[error("enrollment_expired")]
    Expired,
}
type Result<T> = std::result::Result<T, EnrollmentError>;
fn unavailable<T>(_: T) -> EnrollmentError {
    EnrollmentError::Unavailable
}
fn hash(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}
fn id() -> [u8; 16] {
    rand::random()
}

/// Deliberately has no Debug/Display/Serialize/Clone. Expose only to local owner UI.
pub struct Approval {
    id: [u8; 16],
    secret: [u8; 32],
}
impl Approval {
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }
}
/// Deliberately has no Debug/Display/Serialize/Clone. Deliver only over the secure stream.
pub struct Credential {
    id: [u8; 16],
    token: [u8; 32],
    expires_at: i64,
}
impl Credential {
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    pub fn token(&self) -> &[u8; 32] {
        &self.token
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Trusted clock dependency; never accept this from a remote request.
#[derive(Clone, Copy)]
pub struct Time {
    pub wall_seconds: i64,
    pub monotonic: Duration,
}
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<Time>;
}
struct SystemClock(Instant);
impl Clock for SystemClock {
    fn now(&self) -> Result<Time> {
        Ok(Time {
            wall_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(unavailable)?
                .as_secs()
                .try_into()
                .map_err(unavailable)?,
            monotonic: self.0.elapsed(),
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    peer: String,
    key: [u8; 32],
    bootstrap: [u8; 32],
    management: [u8; 32],
    bootstrap_port: u16,
    management_port: u16,
}
impl Binding {
    fn matches(&self, c: &ServiceContext, management: bool) -> bool {
        c.peer_name() == self.peer
            && crypto::ct_eq(&c.peer_static_key(), &self.key)
            && c.registration().generation()
                == if management {
                    self.management
                } else {
                    self.bootstrap
                }
            && c.registration().port()
                == if management {
                    self.management_port
                } else {
                    self.bootstrap_port
                }
    }
    fn valid(&self) -> bool {
        crate::valid_name(&self.peer)
            && self.bootstrap_port != 0
            && self.management_port != 0
            && self.bootstrap_port != self.management_port
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    id: [u8; 16],
    hash: [u8; 32],
    binding: Binding,
    expires: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    id: [u8; 16],
    hash: [u8; 32],
    binding: Binding,
    expires: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    last_wall: i64,
    pending: Option<Pending>,
    active: Option<Active>,
    consumed: Vec<[u8; 16]>,
}
impl Record {
    fn validate(&self) -> bool {
        self.version == 1
            && self.last_wall > 0
            && self.consumed.len() <= MAX_TOMBSTONES
            && self
                .pending
                .as_ref()
                .is_none_or(|p| p.binding.valid() && p.expires > 0)
            && self
                .active
                .as_ref()
                .is_none_or(|p| p.binding.valid() && p.expires > 0)
            && !(self.pending.is_some() && self.active.is_some())
    }
    fn tombstone(&mut self, id: [u8; 16]) {
        if self.consumed.len() == MAX_TOMBSTONES {
            self.consumed.remove(0);
        }
        self.consumed.push(id);
    }
}
struct Inner {
    connection: Connection,
    record: Record,
    last_mono: Duration,
    pending_deadline: Option<Duration>,
    active_deadline: Option<Duration>,
    bindings: Option<(ServiceRegistration, ServiceRegistration)>,
    poisoned: bool,
    revoking: bool,
}
pub struct EnrollmentBroker {
    directory: PathBuf,
    directory_handle: File,
    database_handle: File,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
    revoke_lock: tokio::sync::Mutex<()>,
}
impl EnrollmentBroker {
    /// Directory must already be privately owned, mode 0700. No permission repair.
    pub fn open(directory: &Path) -> Result<Self> {
        Self::open_with_clock(directory, Arc::new(SystemClock(Instant::now())))
    }
    /// Testing/embedding clock is trusted local infrastructure, never request input.
    pub fn open_with_clock(directory: &Path, clock: Arc<dyn Clock>) -> Result<Self> {
        let (directory_handle, database_handle) = storage::open(directory)?;
        let path = directory.join("enrollment.sqlite3");
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(unavailable)?;
        connection
            .busy_timeout(Duration::ZERO)
            .map_err(unavailable)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA fullfsync=ON; PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;").map_err(unavailable)?;
        let check: String = connection
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(unavailable)?;
        if check != "ok" {
            return Err(EnrollmentError::Unavailable);
        }
        connection.execute_batch("CREATE TABLE IF NOT EXISTS enrollment_state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);").map_err(unavailable)?;
        let now = clock.now()?;
        if now.wall_seconds <= 0 {
            return Err(EnrollmentError::Unavailable);
        }
        let old =
            connection.query_row("SELECT payload FROM enrollment_state WHERE id=1", [], |r| {
                r.get::<_, String>(0)
            });
        let mut record = match old {
            Ok(raw) if raw.len() <= MAX_STATE => {
                serde_json::from_str::<Record>(&raw).map_err(unavailable)?
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Record {
                version: 1,
                last_wall: now.wall_seconds,
                pending: None,
                active: None,
                consumed: Vec::new(),
            },
            _ => return Err(EnrollmentError::Unavailable),
        };
        if !record.validate() || now.wall_seconds < record.last_wall {
            return Err(EnrollmentError::Unavailable);
        }
        // Restart invalidates both pending approvals and credentials. No recovery replay.
        if let Some(pending) = record.pending.take() {
            record.tombstone(pending.id);
        }
        record.active = None;
        record.last_wall = now.wall_seconds;
        let broker = Self {
            directory: directory.into(),
            directory_handle,
            database_handle,
            clock,
            revoke_lock: tokio::sync::Mutex::new(()),
            inner: Mutex::new(Inner {
                connection,
                record,
                last_mono: now.monotonic,
                pending_deadline: None,
                active_deadline: None,
                bindings: None,
                poisoned: false,
                revoking: false,
            }),
        };
        {
            let mut inner = broker.lock()?;
            broker.persist(&mut inner)?;
        }
        Ok(broker)
    }
    fn lock(&self) -> Result<MutexGuard<'_, Inner>> {
        self.inner.lock().map_err(unavailable)
    }
    fn check_files(&self) -> Result<()> {
        storage::verify(
            &self.directory,
            &self.directory_handle,
            &self.database_handle,
        )
    }
    fn tick(&self, inner: &mut Inner) -> Result<Time> {
        if inner.poisoned || inner.revoking {
            return Err(EnrollmentError::Unavailable);
        }
        let result = (|| {
            self.check_files()?;
            let now = self.clock.now()?;
            if now.wall_seconds < inner.record.last_wall || now.monotonic < inner.last_mono {
                return Err(EnrollmentError::Unavailable);
            }
            inner.record.last_wall = now.wall_seconds;
            inner.last_mono = now.monotonic;
            Ok(now)
        })();
        if result.is_err() {
            inner.poisoned = true;
        }
        result
    }
    fn persist(&self, inner: &mut Inner) -> Result<()> {
        let result = (|| {
            self.check_files()?;
            let raw = serde_json::to_string(&inner.record).map_err(unavailable)?;
            if raw.len() > MAX_STATE || !inner.record.validate() {
                return Err(EnrollmentError::Unavailable);
            }
            let tx = inner.connection.transaction().map_err(unavailable)?;
            tx.execute("INSERT INTO enrollment_state(id,payload) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![raw]).map_err(unavailable)?;
            tx.commit().map_err(unavailable)?;
            self.directory_handle.sync_all().map_err(unavailable)?;
            self.check_files()
        })();
        if result.is_err() {
            inner.poisoned = true;
        }
        result
    }
    /// Trusted local owner action. Never invoke automatically on incoming traffic.
    /// Approval secrets return only to that owner, not to the preliminary stream.
    pub fn approve(
        &self,
        bootstrap: &ServiceContext,
        management: &ServiceRegistration,
        ttl: Duration,
    ) -> Result<Approval> {
        bootstrap
            .with_authorization(|| {
                let mut inner = self.lock()?;
                let now = self.tick(&mut inner)?;
                if ttl.is_zero()
                    || ttl > Duration::from_secs(APPROVAL_TTL)
                    || ttl.subsec_nanos() != 0
                {
                    return Err(EnrollmentError::Invalid);
                }
                if inner.record.pending.is_some() || inner.record.active.is_some() {
                    return Err(EnrollmentError::Changed);
                }
                let binding = Binding {
                    peer: bootstrap.peer_name().into(),
                    key: bootstrap.peer_static_key(),
                    bootstrap: bootstrap.registration().generation(),
                    management: management.generation(),
                    bootstrap_port: bootstrap.registration().port(),
                    management_port: management.port(),
                };
                if !binding.valid() {
                    return Err(EnrollmentError::Invalid);
                }
                let approval = Approval {
                    id: id(),
                    secret: crypto::random32(),
                };
                inner.record.pending = Some(Pending {
                    id: approval.id,
                    hash: hash(&approval.secret),
                    binding,
                    expires: now
                        .wall_seconds
                        .checked_add(ttl.as_secs() as i64)
                        .ok_or(EnrollmentError::Unavailable)?,
                });
                inner.pending_deadline = now.monotonic.checked_add(ttl);
                if inner.pending_deadline.is_none() {
                    inner.poisoned = true;
                    return Err(EnrollmentError::Unavailable);
                }
                inner.bindings = Some((bootstrap.registration().clone(), management.clone()));
                self.persist(&mut inner)?;
                Ok(approval)
            })
            .map_err(|_| EnrollmentError::PeerNotApproved)?
    }
    /// Only a confirmed bootstrap context can consume the one-time approval.
    pub fn redeem(
        &self,
        context: &ServiceContext,
        enrollment_id: &[u8; 16],
        secret: &[u8; 32],
    ) -> Result<Credential> {
        context
            .with_authorization(|| {
                let mut inner = self.lock()?;
                let now = self.tick(&mut inner)?;
                if inner.record.consumed.contains(enrollment_id) {
                    self.persist(&mut inner)?;
                    return Err(EnrollmentError::Consumed);
                }
                let pending = inner
                    .record
                    .pending
                    .as_ref()
                    .ok_or(EnrollmentError::Invalid)?;
                if !pending.binding.matches(context, false) {
                    return Err(EnrollmentError::PeerNotApproved);
                }
                if pending.id != *enrollment_id || !crypto::ct_eq(&pending.hash, &hash(secret)) {
                    return Err(EnrollmentError::Invalid);
                }
                if now.wall_seconds >= pending.expires
                    || inner
                        .pending_deadline
                        .is_none_or(|deadline| now.monotonic >= deadline)
                {
                    let old = inner.record.pending.take().unwrap();
                    inner.record.tombstone(old.id);
                    self.persist(&mut inner)?;
                    return Err(EnrollmentError::Expired);
                }
                let credential = Credential {
                    id: id(),
                    token: crypto::random32(),
                    expires_at: now
                        .wall_seconds
                        .checked_add(CREDENTIAL_TTL as i64)
                        .ok_or(EnrollmentError::Unavailable)?,
                };
                let pending = inner.record.pending.take().unwrap();
                inner.record.tombstone(pending.id);
                inner.record.active = Some(Active {
                    id: credential.id,
                    hash: hash(&credential.token),
                    binding: pending.binding,
                    expires: credential.expires_at,
                });
                inner.pending_deadline = None;
                inner.active_deadline = now
                    .monotonic
                    .checked_add(Duration::from_secs(CREDENTIAL_TTL));
                if inner.active_deadline.is_none() {
                    inner.poisoned = true;
                    return Err(EnrollmentError::Unavailable);
                }
                // Consumption and token hash are in one durable transaction BEFORE bytes escape.
                self.persist(&mut inner)?;
                Ok(credential)
            })
            .map_err(|_| EnrollmentError::PeerNotApproved)?
    }
    /// Short synchronous protected mutation only. No check-then-await boundary.
    pub fn with_management<T>(
        &self,
        context: &ServiceContext,
        credential_id: &[u8; 16],
        token: &[u8; 32],
        commit: impl FnOnce() -> T,
    ) -> Result<T> {
        context
            .with_authorization(|| {
                let mut inner = self.lock()?;
                let now = self.tick(&mut inner)?;
                let active = inner
                    .record
                    .active
                    .as_ref()
                    .ok_or(EnrollmentError::Invalid)?;
                if !active.binding.matches(context, true) {
                    return Err(EnrollmentError::PeerNotApproved);
                }
                if active.id != *credential_id || !crypto::ct_eq(&active.hash, &hash(token)) {
                    return Err(EnrollmentError::Invalid);
                }
                if now.wall_seconds >= active.expires
                    || inner
                        .active_deadline
                        .is_none_or(|deadline| now.monotonic >= deadline)
                {
                    inner.record.active = None;
                    self.persist(&mut inner)?;
                    return Err(EnrollmentError::Expired);
                }
                self.persist(&mut inner)?;
                Ok(commit())
            })
            .map_err(|_| EnrollmentError::PeerNotApproved)?
    }
    /// Local owner revoke: deny broker access first, then drain both service grants.
    /// Does not revoke any named LAN-device share. Never await from either handler.
    pub async fn revoke_management(&self, daemon: &DaemonInner) -> Result<()> {
        let _revoke = self.revoke_lock.lock().await;
        let (bindings, saved) = {
            let mut inner = self.lock()?;
            inner.revoking = true;
            if let Some(pending) = inner.record.pending.take() {
                inner.record.tombstone(pending.id);
            }
            inner.record.active = None;
            inner.active_deadline = None;
            inner.pending_deadline = None;
            let bindings = inner.bindings.clone();
            let saved = self.persist(&mut inner);
            (bindings, saved)
        };
        let mut drained = true;
        if let Some((bootstrap, management)) = bindings {
            drained &= daemon.revoke_private_service(&bootstrap).await.is_ok();
            drained &= daemon.revoke_private_service(&management).await.is_ok();
        }
        let mut inner = self.lock()?;
        inner.revoking = !drained;
        if drained {
            inner.bindings = None;
        }
        if saved.is_err() || !drained {
            inner.poisoned = true;
            return Err(EnrollmentError::Unavailable);
        }
        Ok(())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod storage {
    use super::*;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    fn owned(path: &Path, directory: bool) -> Result<fs::Metadata> {
        let m = fs::symlink_metadata(path).map_err(unavailable)?;
        // macOS ACL grants can override mode bits. Reject all extended ACLs;
        // this read-only system tool is fixed, never shell-interpolated.
        #[cfg(target_os = "macos")]
        {
            let output = std::process::Command::new("/bin/ls")
                .args(["-lde", "--"])
                .arg(path)
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .map_err(unavailable)?;
            let line = std::str::from_utf8(&output.stdout).map_err(unavailable)?;
            let mode = line
                .split_whitespace()
                .next()
                .ok_or(EnrollmentError::Unavailable)?;
            if !output.status.success()
                || output.stdout.len() > 16384
                || mode.contains('+')
                || line.lines().skip(1).any(|line| !line.trim().is_empty())
            {
                return Err(EnrollmentError::Unavailable);
            }
        }

        if m.uid() != rustix::process::geteuid().as_raw()
            || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || if directory {
                !m.is_dir()
            } else {
                !m.is_file() || m.nlink() != 1
            }
        {
            return Err(EnrollmentError::Unavailable);
        }
        Ok(m)
    }
    fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    pub(super) fn open(dir: &Path) -> Result<(File, File)> {
        owned(dir, true)?;
        let dh = File::open(dir).map_err(unavailable)?;
        let path = dir.join("enrollment.sqlite3");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                owned(&path, false)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(unavailable)?
                    .sync_all()
                    .map_err(unavailable)?;
                dh.sync_all().map_err(unavailable)?;
            }
            Err(_) => return Err(EnrollmentError::Unavailable),
        }
        let db = File::open(&path).map_err(unavailable)?;
        verify(dir, &dh, &db)?;
        Ok((dh, db))
    }
    pub(super) fn verify(dir: &Path, dh: &File, db: &File) -> Result<()> {
        let directory = owned(dir, true)?;
        let database = owned(&dir.join("enrollment.sqlite3"), false)?;
        if !same(&directory, &dh.metadata().map_err(unavailable)?)
            || !same(&database, &db.metadata().map_err(unavailable)?)
            || database.len() > 1024 * 1024
        {
            return Err(EnrollmentError::Unavailable);
        }
        for entry in fs::read_dir(dir).map_err(unavailable)? {
            let entry = entry.map_err(unavailable)?;
            match entry.file_name().to_str() {
                Some("enrollment.sqlite3") => {}
                Some("enrollment.sqlite3-journal") => {
                    owned(&entry.path(), false)?;
                }
                _ => return Err(EnrollmentError::Unavailable),
            }
        }
        Ok(())
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod storage {
    use super::*;
    pub(super) fn open(_: &Path) -> Result<(File, File)> {
        Err(EnrollmentError::Unsupported)
    }
    pub(super) fn verify(_: &Path, _: &File, _: &File) -> Result<()> {
        Err(EnrollmentError::Unsupported)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn directory() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn pending() -> Pending {
        Pending {
            id: [1; 16],
            hash: hash(&[2; 32]),
            binding: Binding {
                peer: "fixture".into(),
                key: [3; 32],
                bootstrap: [4; 32],
                management: [5; 32],
                bootstrap_port: 49100,
                management_port: 49101,
            },
            expires: crate::now_secs() + 120,
        }
    }
    #[test]
    fn sqlite_write_failure_poisons_and_restart_burns_pending() {
        let d = directory();
        let broker = EnrollmentBroker::open(d.path()).unwrap();
        {
            let mut inner = broker.lock().unwrap();
            inner.record.pending = Some(pending());
            broker.persist(&mut inner).unwrap();
            inner
                .connection
                .pragma_update(None, "query_only", true)
                .unwrap();
            inner.record.pending = None;
            inner.record.tombstone([1; 16]);
            assert!(broker.persist(&mut inner).is_err());
            assert!(inner.poisoned);
            let raw: String = inner
                .connection
                .query_row("SELECT payload FROM enrollment_state", [], |r| r.get(0))
                .unwrap();
            assert!(
                serde_json::from_str::<Record>(&raw)
                    .unwrap()
                    .pending
                    .is_some(),
                "failed transaction does not pretend consumption succeeded"
            );
        }
        drop(broker);
        let broker = EnrollmentBroker::open(d.path()).unwrap();
        let inner = broker.lock().unwrap();
        assert!(inner.record.pending.is_none());
        assert!(inner.record.active.is_none());
        assert!(inner.record.consumed.contains(&[1; 16]));
    }
    #[test]
    fn subprocess_store_worker() {
        let Some(path) = std::env::var_os("WARREN_ENROLLMENT_WORKER_DIR") else {
            return;
        };
        if std::env::var_os("WARREN_ENROLLMENT_EXPECT_LOCKED").is_some() {
            assert!(EnrollmentBroker::open(Path::new(&path)).is_err());
            return;
        }
        let broker = EnrollmentBroker::open(Path::new(&path)).unwrap();
        {
            let mut inner = broker.lock().unwrap();
            let p = pending();
            inner.record.active = Some(Active {
                id: [6; 16],
                hash: hash(&[7; 32]),
                binding: p.binding,
                expires: crate::now_secs() + 86400,
            });
            inner.record.tombstone(p.id);
            broker.persist(&mut inner).unwrap();
        }
        std::process::exit(0); // Deliberately skip Rust destructors after committed consumption.
    }
    #[test]
    fn process_owner_lock_and_abrupt_exit_keep_consumption_durable() {
        let d = directory();
        let broker = EnrollmentBroker::open(d.path()).unwrap();
        let invoke = |locked: bool| {
            let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
            cmd.args([
                "--exact",
                "device_enrollment::tests::subprocess_store_worker",
            ])
            .env("WARREN_ENROLLMENT_WORKER_DIR", d.path());
            if locked {
                cmd.env("WARREN_ENROLLMENT_EXPECT_LOCKED", "1");
            }
            cmd.output().unwrap()
        };
        assert!(invoke(true).status.success());
        drop(broker);
        assert!(invoke(false).status.success());
        let broker = EnrollmentBroker::open(d.path()).unwrap();
        let inner = broker.lock().unwrap();
        assert!(inner.record.consumed.contains(&[1; 16]));
        assert!(
            inner.record.active.is_none(),
            "restart revokes credential even after ambiguous delivery"
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_is_rejected_without_repair() {
        let d = directory();
        let broker = EnrollmentBroker::open(d.path()).unwrap();
        drop(broker);
        let file = d.path().join("enrollment.sqlite3");
        assert!(std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&file)
            .status()
            .unwrap()
            .success());
        assert!(EnrollmentBroker::open(d.path()).is_err());
        let output = std::process::Command::new("/bin/ls")
            .arg("-le")
            .arg(file)
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("everyone allow read"),
            "unknown permissions must not be repaired"
        );
    }
}
