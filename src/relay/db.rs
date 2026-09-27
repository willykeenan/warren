//! Relay state: one SQLite file under `--state DIR` (0600 in a 0700 directory).
//!
//! The running relay and the admin commands (`warren relay invite`, `revoke`,
//! `domain`) share this file. Every administrative change bumps a revision
//! counter that the running relay polls to reload its in-memory registry.

use crate::crypto;
use crate::fsutil;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// File name of the relay database inside the state directory.
pub const DB_FILE: &str = "relay.sqlite3";

/// A registered node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub node_id: String,
    pub name: String,
    pub sign_pub: [u8; 32],
    pub static_pub: [u8; 32],
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// A published name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRecord {
    pub name: String,
    pub node_id: String,
    pub allow: Vec<String>,
    pub created_at: i64,
}

/// Outcome of an enrollment attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    Joined(NodeRecord),
    /// Unknown, expired or already used code.
    InvalidCode,
    NameTaken(String),
    BadName(String),
    KeyInUse,
}

/// Outcome of a publish claim.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed,
    Updated,
    AlreadyYours,
    TakenByOther,
    /// The claiming node is revoked (or unknown): it may not hold names.
    NotActive,
}

pub struct Db {
    conn: Mutex<Connection>,
    path: PathBuf,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
INSERT OR IGNORE INTO meta (k, v) VALUES ('rev', '1');
INSERT OR IGNORE INTO meta (k, v) VALUES ('schema', '1');
CREATE TABLE IF NOT EXISTS nodes (
    node_id    TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    sign_pub   BLOB NOT NULL UNIQUE,
    static_pub BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER,
    revoked_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_active_name ON nodes(name) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS invites (
    code_hash  BLOB PRIMARY KEY,
    name       TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE TABLE IF NOT EXISTS publishes (
    name       TEXT PRIMARY KEY,
    node_id    TEXT NOT NULL,
    allow      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS domains (
    host TEXT PRIMARY KEY,
    name TEXT NOT NULL
);
"#;

fn key32(v: Vec<u8>) -> [u8; 32] {
    let mut k = [0u8; 32];
    if v.len() == 32 {
        k.copy_from_slice(&v);
    }
    k
}

impl Db {
    /// Open (creating if needed) the database in `state_dir`.
    pub fn open(state_dir: &Path) -> Result<Db> {
        fsutil::ensure_private_dir(state_dir)?;
        let path = state_dir.join(DB_FILE);
        fsutil::touch_private(&path)?;
        let conn =
            Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db {
            conn: Mutex::new(conn),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn with<T>(&self, f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>) -> Result<T> {
        let mut c = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        Ok(f(&mut c)?)
    }

    /// Current revision counter.
    pub fn revision(&self) -> Result<i64> {
        self.with(|c| {
            let v: String = c.query_row("SELECT v FROM meta WHERE k = 'rev'", [], |r| r.get(0))?;
            Ok(v.parse().unwrap_or(0))
        })
    }

    fn bump(tx: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
        tx.execute(
            "UPDATE meta SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT) WHERE k = 'rev'",
            [],
        )?;
        Ok(())
    }

    pub fn get_meta(&self, k: &str) -> Result<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
                .optional()
        })
    }

    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![k, v],
            )?;
            Ok(())
        })
    }

    /// Create a one-time code. Only its hash is stored.
    pub fn create_invite(&self, name: Option<&str>, ttl: Duration, now: i64) -> Result<String> {
        if let Some(n) = name {
            anyhow::ensure!(
                crate::valid_name(n),
                "invalid name {n:?}: use [a-z0-9-]{{1,32}}"
            );
        }
        let code = crypto::generate_code();
        let hash = crypto::hash_code(&code);
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Opportunistically drop long-dead invites.
            tx.execute("DELETE FROM invites WHERE expires_at < ?1", [now - 86_400])?;
            tx.execute(
                "INSERT INTO invites (code_hash, name, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![hash.to_vec(), name, now, now + ttl.as_secs() as i64],
            )?;
            tx.commit()
        })?;
        Ok(code)
    }

    /// Redeem a code and register the node in one transaction. The code is
    /// consumed only if registration succeeds.
    pub fn join(
        &self,
        code: &str,
        requested_name: Option<&str>,
        sign_pub: &[u8; 32],
        static_pub: &[u8; 32],
        now: i64,
    ) -> Result<JoinOutcome> {
        let hash = crypto::hash_code(code);
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<(Option<String>, i64, Option<i64>)> = tx
                .query_row(
                    "SELECT name, expires_at, used_at FROM invites WHERE code_hash = ?1",
                    [hash.to_vec()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((invite_name, expires_at, used_at)) = row else {
                return Ok(JoinOutcome::InvalidCode);
            };
            if used_at.is_some() || now >= expires_at {
                return Ok(JoinOutcome::InvalidCode);
            }
            let name = match (invite_name, requested_name) {
                (Some(n), _) => n,
                (None, Some(n)) => n.to_string(),
                (None, None) => return Ok(JoinOutcome::BadName(String::new())),
            };
            if !crate::valid_name(&name) {
                return Ok(JoinOutcome::BadName(name));
            }
            let taken: bool = tx
                .query_row(
                    "SELECT 1 FROM nodes WHERE name = ?1 AND revoked_at IS NULL",
                    [&name],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if taken {
                return Ok(JoinOutcome::NameTaken(name));
            }
            let key_used: bool = tx
                .query_row(
                    "SELECT 1 FROM nodes WHERE sign_pub = ?1",
                    [sign_pub.to_vec()],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if key_used {
                return Ok(JoinOutcome::KeyInUse);
            }
            let node_id = crypto::node_id_for(sign_pub);
            tx.execute(
                "INSERT INTO nodes (node_id, name, sign_pub, static_pub, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![node_id, name, sign_pub.to_vec(), static_pub.to_vec(), now],
            )?;
            tx.execute(
                "UPDATE invites SET used_at = ?1 WHERE code_hash = ?2",
                params![now, hash.to_vec()],
            )?;
            Db::bump(&tx)?;
            tx.commit()?;
            Ok(JoinOutcome::Joined(NodeRecord {
                node_id,
                name,
                sign_pub: *sign_pub,
                static_pub: *static_pub,
                created_at: now,
                last_seen: None,
                revoked_at: None,
            }))
        })
    }

    /// All nodes, including revoked ones.
    pub fn nodes(&self) -> Result<Vec<NodeRecord>> {
        self.with(|c| {
            let mut st = c.prepare(
                "SELECT node_id, name, sign_pub, static_pub, created_at, last_seen, revoked_at FROM nodes ORDER BY name",
            )?;
            let rows = st.query_map([], |r| {
                Ok(NodeRecord {
                    node_id: r.get(0)?,
                    name: r.get(1)?,
                    sign_pub: key32(r.get(2)?),
                    static_pub: key32(r.get(3)?),
                    created_at: r.get(4)?,
                    last_seen: r.get(5)?,
                    revoked_at: r.get(6)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Revoke the active node called `name`; also releases its published names.
    pub fn revoke(&self, name: &str, now: i64) -> Result<bool> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let id: Option<String> = tx
                .query_row(
                    "SELECT node_id FROM nodes WHERE name = ?1 AND revoked_at IS NULL",
                    [name],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(id) = id else { return Ok(false) };
            tx.execute(
                "UPDATE nodes SET revoked_at = ?1 WHERE node_id = ?2",
                params![now, id],
            )?;
            tx.execute("DELETE FROM publishes WHERE node_id = ?1", [&id])?;
            Db::bump(&tx)?;
            tx.commit()?;
            Ok(true)
        })
    }

    pub fn touch_last_seen(&self, node_id: &str, now: i64) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE nodes SET last_seen = ?1 WHERE node_id = ?2",
                params![now, node_id],
            )?;
            Ok(())
        })
    }

    pub fn publishes(&self) -> Result<Vec<PublishRecord>> {
        self.with(|c| {
            let mut st =
                c.prepare("SELECT name, node_id, allow, created_at FROM publishes ORDER BY name")?;
            let rows = st.query_map([], |r| {
                let allow: String = r.get(2)?;
                Ok(PublishRecord {
                    name: r.get(0)?,
                    node_id: r.get(1)?,
                    allow: allow
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                    created_at: r.get(3)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Claim `name` for `node_id`. Another node's name is never taken over.
    pub fn claim_publish(
        &self,
        name: &str,
        node_id: &str,
        allow: &[String],
        replace: bool,
        now: i64,
    ) -> Result<ClaimOutcome> {
        let allow = allow.join(",");
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Checked in the same transaction as the insert: `revoke` deletes
            // a node's publishes in its own transaction, so a revoked node can
            // never end up owning a name nothing would release.
            let active: Option<Option<i64>> = tx
                .query_row(
                    "SELECT revoked_at FROM nodes WHERE node_id = ?1",
                    [node_id],
                    |r| r.get(0),
                )
                .optional()?;
            if !matches!(active, Some(None)) {
                return Ok(ClaimOutcome::NotActive);
            }
            let owner: Option<String> = tx
                .query_row("SELECT node_id FROM publishes WHERE name = ?1", [name], |r| {
                    r.get(0)
                })
                .optional()?;
            let outcome = match owner {
                Some(o) if o != node_id => return Ok(ClaimOutcome::TakenByOther),
                Some(_) if !replace => return Ok(ClaimOutcome::AlreadyYours),
                Some(_) => {
                    tx.execute(
                        "UPDATE publishes SET allow = ?1 WHERE name = ?2",
                        params![allow, name],
                    )?;
                    ClaimOutcome::Updated
                }
                None => {
                    tx.execute(
                        "INSERT INTO publishes (name, node_id, allow, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![name, node_id, allow, now],
                    )?;
                    ClaimOutcome::Claimed
                }
            };
            Db::bump(&tx)?;
            tx.commit()?;
            Ok(outcome)
        })
    }

    /// Release `name` if `node_id` owns it.
    pub fn unpublish(&self, name: &str, node_id: &str) -> Result<bool> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let n = tx.execute(
                "DELETE FROM publishes WHERE name = ?1 AND node_id = ?2",
                params![name, node_id],
            )?;
            if n > 0 {
                Db::bump(&tx)?;
            }
            tx.commit()?;
            Ok(n > 0)
        })
    }

    pub fn add_domain(&self, host: &str, name: &str) -> Result<()> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO domains (host, name) VALUES (?1, ?2) ON CONFLICT(host) DO UPDATE SET name = excluded.name",
                params![host.to_ascii_lowercase(), name],
            )?;
            Db::bump(&tx)?;
            tx.commit()
        })
    }

    pub fn remove_domain(&self, host: &str) -> Result<bool> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let n = tx.execute(
                "DELETE FROM domains WHERE host = ?1",
                [host.to_ascii_lowercase()],
            )?;
            Db::bump(&tx)?;
            tx.commit()?;
            Ok(n > 0)
        })
    }

    pub fn domains(&self) -> Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT host, name FROM domains ORDER BY host")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    /// Number of invites stored (for tests and `relay info`).
    pub fn invite_hashes(&self) -> Result<Vec<Vec<u8>>> {
        self.with(|c| {
            let mut st = c.prepare("SELECT code_hash FROM invites")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> ([u8; 32], [u8; 32]) {
        ([n; 32], [n.wrapping_add(100); 32])
    }

    #[test]
    fn invites_are_single_use_expire_and_hashed() {
        let t = tempfile::tempdir().unwrap();
        let db = Db::open(t.path()).unwrap();
        assert!(fsutil::is_private(t.path()).unwrap());
        assert!(fsutil::is_private(db.path()).unwrap());
        let now = 1_000_000;
        let code = db
            .create_invite(None, Duration::from_secs(600), now)
            .unwrap();
        let (s1, x1) = keys(1);
        // Expired
        assert_eq!(
            db.join(&code, Some("a"), &s1, &x1, now + 600).unwrap(),
            JoinOutcome::InvalidCode
        );
        // Valid once
        match db.join(&code, Some("a"), &s1, &x1, now + 10).unwrap() {
            JoinOutcome::Joined(r) => assert_eq!(r.name, "a"),
            other => panic!("{other:?}"),
        }
        let (s2, x2) = keys(2);
        assert_eq!(
            db.join(&code, Some("b"), &s2, &x2, now + 11).unwrap(),
            JoinOutcome::InvalidCode
        );
        // Unknown code
        assert_eq!(
            db.join("ABCDEFGHJK", Some("b"), &s2, &x2, now).unwrap(),
            JoinOutcome::InvalidCode
        );
        // Stored only as hash: the plaintext code is nowhere in the file.
        drop(db);
        let mut raw = Vec::new();
        for e in std::fs::read_dir(t.path()).unwrap() {
            raw.extend(std::fs::read(e.unwrap().path()).unwrap());
        }
        assert!(!raw.windows(code.len()).any(|w| w == code.as_bytes()));
    }

    #[test]
    fn names_and_keys() {
        let t = tempfile::tempdir().unwrap();
        let db = Db::open(t.path()).unwrap();
        let now = 5;
        let c1 = db
            .create_invite(Some("laptop"), Duration::from_secs(600), now)
            .unwrap();
        let (s1, x1) = keys(1);
        // Invite name wins over the requested one.
        match db.join(&c1, Some("other"), &s1, &x1, now).unwrap() {
            JoinOutcome::Joined(r) => assert_eq!(r.name, "laptop"),
            o => panic!("{o:?}"),
        }
        let c2 = db
            .create_invite(None, Duration::from_secs(600), now)
            .unwrap();
        let (s2, x2) = keys(2);
        assert_eq!(
            db.join(&c2, Some("laptop"), &s2, &x2, now).unwrap(),
            JoinOutcome::NameTaken("laptop".into())
        );
        // Name conflict does not burn the code.
        assert_eq!(
            db.join(&c2, Some("Bad Name"), &s2, &x2, now).unwrap(),
            JoinOutcome::BadName("Bad Name".into())
        );
        assert_eq!(
            db.join(&c2, Some("desk"), &s1, &x2, now).unwrap(),
            JoinOutcome::KeyInUse
        );
        assert!(matches!(
            db.join(&c2, Some("desk"), &s2, &x2, now).unwrap(),
            JoinOutcome::Joined(_)
        ));
        let rev = db.revision().unwrap();
        assert!(db.revoke("laptop", now).unwrap());
        assert!(!db.revoke("laptop", now).unwrap());
        assert!(db.revision().unwrap() > rev);
        // After revocation the name can be enrolled again with new keys.
        let c3 = db
            .create_invite(Some("laptop"), Duration::from_secs(600), now)
            .unwrap();
        let (s3, x3) = keys(3);
        assert!(matches!(
            db.join(&c3, None, &s3, &x3, now).unwrap(),
            JoinOutcome::Joined(_)
        ));
        let nodes = db.nodes().unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes.iter().filter(|n| n.revoked_at.is_some()).count(), 1);
        assert!(db
            .create_invite(Some("NO"), Duration::from_secs(1), now)
            .is_err());
    }

    /// Enroll a node and return its id.
    fn enroll(db: &Db, name: &str, n: u8) -> String {
        let code = db.create_invite(None, Duration::from_secs(600), 1).unwrap();
        let (sp, xp) = keys(n);
        match db.join(&code, Some(name), &sp, &xp, 1).unwrap() {
            JoinOutcome::Joined(r) => r.node_id,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn publish_ownership() {
        let t = tempfile::tempdir().unwrap();
        let db = Db::open(t.path()).unwrap();
        let n1 = enroll(&db, "one", 1);
        let n2 = enroll(&db, "two", 2);
        let (n1, n2) = (n1.as_str(), n2.as_str());
        assert_eq!(
            db.claim_publish("web", n1, &[], false, 1).unwrap(),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            db.claim_publish("web", n1, &[], false, 1).unwrap(),
            ClaimOutcome::AlreadyYours
        );
        assert_eq!(
            db.claim_publish("web", n1, &["10.0.0.0/8".into()], true, 1)
                .unwrap(),
            ClaimOutcome::Updated
        );
        assert_eq!(
            db.claim_publish("web", n2, &[], true, 1).unwrap(),
            ClaimOutcome::TakenByOther
        );
        assert_eq!(
            db.claim_publish("web", n2, &[], false, 1).unwrap(),
            ClaimOutcome::TakenByOther
        );
        assert!(!db.unpublish("web", n2).unwrap());
        let p = db.publishes().unwrap();
        assert_eq!(p[0].allow, vec!["10.0.0.0/8".to_string()]);
        assert!(db.unpublish("web", n1).unwrap());
        assert_eq!(
            db.claim_publish("web", n2, &[], false, 1).unwrap(),
            ClaimOutcome::Claimed
        );
        // A revoked node cannot claim names (revoke released its names).
        assert!(db.revoke("two", 2).unwrap());
        assert!(db.publishes().unwrap().is_empty());
        assert_eq!(
            db.claim_publish("web", n2, &[], true, 1).unwrap(),
            ClaimOutcome::NotActive
        );
        assert_eq!(
            db.claim_publish("web", "nunknown", &[], false, 1).unwrap(),
            ClaimOutcome::NotActive
        );
        assert!(db.publishes().unwrap().is_empty());
        db.add_domain("App.Example.org", "web").unwrap();
        assert_eq!(
            db.domains().unwrap(),
            vec![("app.example.org".into(), "web".into())]
        );
        assert!(db.remove_domain("app.example.org").unwrap());
        db.set_meta("acme", "x").unwrap();
        assert_eq!(db.get_meta("acme").unwrap().as_deref(), Some("x"));
    }

    #[test]
    fn two_handles_share_state() {
        let t = tempfile::tempdir().unwrap();
        let a = Db::open(t.path()).unwrap();
        let b = Db::open(t.path()).unwrap();
        let r0 = a.revision().unwrap();
        b.add_domain("x.example", "web").unwrap();
        assert!(a.revision().unwrap() > r0);
        assert_eq!(a.domains().unwrap().len(), 1);
    }
}
