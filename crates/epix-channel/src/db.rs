//! The private channel index: a file-backed SQLite database that lives OUTSIDE
//! every xite directory (in `<data_root>/private/channels.db`), so it is never
//! served to peers and survives xite-db rebuilds. It holds the decrypted result
//! of trial-decrypting the anonymous envelope pool — threads, messages (with an
//! FTS5 full-text index), the per-conversation ratchet sessions, and the durable
//! set of expected detection tags that make inbound matching O(1).
//!
//! Nothing here is ever published. The plaintext bodies and the ratchet blobs
//! are the sensitive at-rest data; Phase 1 stores them in a 0600 file (the same
//! posture as `private/users.json`, which already holds the master seed in the
//! clear). The schema carries `enc` discriminators so a later phase can seal
//! bodies + ratchets with XChaCha20-Poly1305 under a seed-derived key.

use epix_core::{Error, Result};
use epix_db::Database;
use epix_envelope::{
    EnvelopeStore, InboundCommit, NewSession, OutboundCommit, OutboundMessage, OutboundRecovery,
    OutboundSession, PendingOutbound, RlnReservation, SessionMatch,
};
use rusqlite::OptionalExtension;
use serde_json::Value;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS identity (
    identity_id   INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    xid           TEXT NOT NULL,
    auth_address  TEXT NOT NULL,
    derive_index  INTEGER NOT NULL,
    bundle_json   TEXT,
    scan_cursor   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(auth_address, derive_index));

CREATE TABLE IF NOT EXISTS session (
    session_id    INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    identity_id   INTEGER NOT NULL REFERENCES identity(identity_id),
    conv_id       TEXT NOT NULL,
    peer_xid      TEXT,
    -- The peer DEVICE's identity key (leg key). One human `peer_xid` may have
    -- several devices, each a distinct pairwise ratchet, so the leg is keyed by
    -- the device key, NOT the human name. NOT NULL (a device always has an ik;
    -- '' only for legacy pre-v3 rows) so the UNIQUE below actually fires — SQLite
    -- treats NULLs as distinct, which previously let NULL-peer sessions duplicate.
    peer_ik       TEXT NOT NULL DEFAULT '',
    -- Linked-identity address that published peer_ik. Retained even if the
    -- bundle file is later removed, so device revocation remains enforceable.
    peer_auth     TEXT,
    role          TEXT NOT NULL,
    ratchet       BLOB NOT NULL,
    enc           INTEGER NOT NULL DEFAULT 0,
    established_ms INTEGER NOT NULL,
    -- One pairwise session PER peer DEVICE in a (possibly group) conversation.
    UNIQUE(identity_id, conv_id, peer_ik));

CREATE TABLE IF NOT EXISTS expected_tag (
    tag           BLOB PRIMARY KEY NOT NULL,
    session_id    INTEGER NOT NULL REFERENCES session(session_id) ON DELETE CASCADE,
    n             INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS expected_tag_session ON expected_tag(session_id);

CREATE TABLE IF NOT EXISTS thread (
    thread_id     INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    identity_id   INTEGER NOT NULL REFERENCES identity(identity_id),
    conv_id       TEXT NOT NULL,
    peer_xid      TEXT,
    members       TEXT,          -- JSON array of all participants (reply-all)
    subject       TEXT,
    snippet       TEXT,
    last_ms       INTEGER NOT NULL DEFAULT 0,
    msg_count     INTEGER NOT NULL DEFAULT 0,
    unread        INTEGER NOT NULL DEFAULT 0,
    starred       INTEGER NOT NULL DEFAULT 0,
    archived      INTEGER NOT NULL DEFAULT 0,
    enc           INTEGER NOT NULL DEFAULT 0,
    UNIQUE(identity_id, conv_id));
CREATE INDEX IF NOT EXISTS thread_identity_last ON thread(identity_id, last_ms);

CREATE TABLE IF NOT EXISTS msg (
    msg_id        INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    identity_id   INTEGER NOT NULL REFERENCES identity(identity_id),
    thread_id     INTEGER NOT NULL REFERENCES thread(thread_id),
    conv_id       TEXT NOT NULL,
    dir           TEXT NOT NULL,            -- 'in' | 'out'
    sender_xid    TEXT,
    subject       TEXT,
    body          TEXT,
    enc           INTEGER NOT NULL DEFAULT 0,
    sent_ms       INTEGER NOT NULL DEFAULT 0,
    received_ms   INTEGER NOT NULL DEFAULT 0,
    epoch         INTEGER NOT NULL DEFAULT 0,
    read          INTEGER NOT NULL DEFAULT 0,
    sign_h        BLOB,                    -- 16B blake3 prefix of the pool sig (null for own sent)
    -- Idempotency is PER IDENTITY: one count-hiding record legitimately carries a
    -- slot for several recipients, so a node hosting more than one channel identity
    -- can index the SAME record once per addressed identity (not once per record).
    UNIQUE(sign_h, identity_id));
CREATE INDEX IF NOT EXISTS msg_conv ON msg(identity_id, conv_id, sent_ms);

CREATE VIRTUAL TABLE IF NOT EXISTS msg_fts USING fts5(
    subject, body, content='msg', content_rowid='msg_id');

CREATE TRIGGER IF NOT EXISTS msg_ai AFTER INSERT ON msg BEGIN
    INSERT INTO msg_fts(rowid, subject, body) VALUES (new.msg_id, new.subject, new.body);
END;
CREATE TRIGGER IF NOT EXISTS msg_ad AFTER DELETE ON msg BEGIN
    INSERT INTO msg_fts(msg_fts, rowid, subject, body) VALUES('delete', old.msg_id, old.subject, old.body);
END;
CREATE TRIGGER IF NOT EXISTS msg_au AFTER UPDATE ON msg BEGIN
    INSERT INTO msg_fts(msg_fts, rowid, subject, body) VALUES('delete', old.msg_id, old.subject, old.body);
    INSERT INTO msg_fts(rowid, subject, body) VALUES (new.msg_id, new.subject, new.body);
END;

-- Per-identity so a deferred/undelivered slot for one identity is re-checked
-- independently of another identity's delivered slot in the same record.
CREATE TABLE IF NOT EXISTS processed (
    sign_h        BLOB NOT NULL,
    identity_id   INTEGER NOT NULL,
    PRIMARY KEY(sign_h, identity_id));

-- Exact signed records awaiting successful pool append. Session advances and
-- the corresponding row are inserted in one transaction, so a crash can only
-- leave an appendable record, never a stranded ratchet advance.
CREATE TABLE IF NOT EXISTS outbound (
    outbox_id     INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    record_json  TEXT NOT NULL,
    shard_path   TEXT NOT NULL,
    created_ms   INTEGER NOT NULL,
    next_attempt_ms INTEGER NOT NULL,
    -- Throwaway pool-record author key, private and deleted on ack. It permits
    -- re-PoW/re-sign without touching the already-advanced pairwise ratchet.
    author_key    TEXT,
    key_enc       INTEGER NOT NULL DEFAULT 0,
    rln_first_unit INTEGER,
    rln_weight    INTEGER,
    rln_root      BLOB,
    last_error    TEXT);
CREATE INDEX IF NOT EXISTS outbound_due ON outbound(next_attempt_ms, outbox_id);

-- Ordering is scoped to the ratchet legs touched by a row. A multi-recipient
-- record owns several keys, and every chunk of one conversation also owns its
-- conversation key. Independent conversations may therefore make progress
-- while an unrelated row is backed off, without allowing same-leg overtaking.
CREATE TABLE IF NOT EXISTS outbound_dependency (
    outbox_id     INTEGER NOT NULL REFERENCES outbound(outbox_id) ON DELETE CASCADE,
    dep_key       TEXT NOT NULL,
    PRIMARY KEY(outbox_id, dep_key));
CREATE INDEX IF NOT EXISTS outbound_dependency_key
    ON outbound_dependency(dep_key, outbox_id);

-- Route changes are two-phase. The current representation is first written to
-- its new shard, then every prior durable shard copy is stripped by logical id.
-- Keeping all old paths makes repeated descriptor changes crash-recoverable.
CREATE TABLE IF NOT EXISTS outbound_route_cleanup (
    outbox_id     INTEGER NOT NULL REFERENCES outbound(outbox_id) ON DELETE CASCADE,
    shard_path    TEXT NOT NULL,
    PRIMARY KEY(outbox_id, shard_path));

-- Finalized device/session revocations are monotonic locally. A later resolver
-- outage must never reopen the exact auth/IK tuple already observed as revoked.
CREATE TABLE IF NOT EXISTS revoked_device (
    xid           TEXT NOT NULL,
    auth_address  TEXT NOT NULL DEFAULT '',
    peer_ik       TEXT NOT NULL DEFAULT '',
    observed_ms   INTEGER NOT NULL,
    PRIMARY KEY(xid, auth_address, peer_ik));

CREATE TABLE IF NOT EXISTS shard_cursor (
    shard_path    TEXT PRIMARY KEY NOT NULL,
    records       INTEGER NOT NULL DEFAULT 0,
    sealed        INTEGER NOT NULL DEFAULT 0,
    updated_ms    INTEGER NOT NULL DEFAULT 0);
";

/// A stored identity row.
#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub identity_id: i64,
    pub xid: String,
    pub auth_address: String,
    pub derive_index: i64,
    pub bundle_json: Option<String>,
    pub scan_cursor: i64,
}

/// Current peer-device metadata retained by an established session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPeer {
    pub xid: String,
    pub peer_ik: String,
    pub peer_auth: Option<String>,
}

/// A durable, device-scoped finalized revocation observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedDevice {
    pub xid: String,
    pub auth_address: String,
    pub peer_ik: String,
}

/// The private channel index.
#[derive(Clone)]
pub struct ChannelDb {
    db: Database,
    /// When set, message content and ratchet blobs are sealed at rest under this
    /// key (see [`crate::enc`]); `None` = plaintext at rest.
    enc_key: Option<[u8; 32]>,
}

fn db_err(e: rusqlite::Error) -> Error {
    Error::Db(e.to_string())
}

fn canonical_xid(xid: &str) -> String {
    let xid = xid.trim().trim_end_matches('.');
    if xid.ends_with(".epix") {
        xid.to_string()
    } else {
        format!("{xid}.epix")
    }
}

fn decode_rln_reservation(
    first_unit: Option<i64>,
    weight: Option<i64>,
    root: Option<Vec<u8>>,
) -> Result<Option<RlnReservation>> {
    let (Some(first_unit), Some(weight)) = (first_unit, weight) else {
        if first_unit.is_some() || weight.is_some() || root.is_some() {
            return Err(Error::Db("outbox has an incomplete RLN reservation".into()));
        }
        return Ok(None);
    };
    let first_unit = u32::try_from(first_unit)
        .map_err(|_| Error::Db("outbox RLN first unit is out of range".into()))?;
    let weight =
        u32::try_from(weight).map_err(|_| Error::Db("outbox RLN weight is out of range".into()))?;
    let root = root
        .map(|bytes| {
            bytes
                .try_into()
                .map_err(|_| Error::Db("outbox RLN root is not 32 bytes".into()))
        })
        .transpose()?;
    Ok(Some(RlnReservation {
        first_unit,
        weight,
        root,
    }))
}

fn outbound_dependency_keys(commit: &OutboundCommit) -> Result<std::collections::BTreeSet<String>> {
    let mut keys = std::collections::BTreeSet::new();
    let mut scopes = std::collections::BTreeSet::new();
    if let Some(sent) = &commit.sent {
        scopes.insert((sent.identity_id, sent.conv_id.clone()));
    }
    for session in &commit.sessions {
        scopes.insert((session.identity_id, session.conv_id.clone()));
        keys.insert(serde_json::to_string(&(
            "leg",
            session.identity_id,
            &session.conv_id,
            &session.peer_ik,
        ))?);
    }
    if scopes.len() > 1 {
        return Err(Error::Db(
            "one outbound record spans more than one local conversation".into(),
        ));
    }
    if let Some((identity_id, conv_id)) = scopes.into_iter().next() {
        keys.insert(serde_json::to_string(&(
            "conversation",
            identity_id,
            conv_id,
        ))?);
    }
    Ok(keys)
}

fn prepare_channel_db_path(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(Error::Io)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn harden_channel_db_files(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let file = std::path::PathBuf::from(name);
        if file.exists() {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
                .map_err(Error::Io)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_channel_db_files(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn device_revoked_conn(
    conn: &rusqlite::Connection,
    xid: &str,
    auth_address: Option<&str>,
    peer_ik: &str,
) -> Result<bool> {
    let xid = canonical_xid(xid);
    let auth = auth_address.unwrap_or("");
    let found = conn
        .query_row(
            "SELECT 1 FROM revoked_device
             WHERE xid=?1 AND (
                (auth_address != '' AND auth_address=?2) OR
                (peer_ik != '' AND peer_ik=?3)
             ) LIMIT 1",
            rusqlite::params![xid, auth, peer_ik],
            |_| Ok(()),
        )
        .optional()
        .map_err(db_err)?;
    Ok(found.is_some())
}

fn reject_revoked_peer(
    conn: &rusqlite::Connection,
    xid: Option<&str>,
    auth_address: Option<&str>,
    peer_ik: &str,
) -> Result<()> {
    let Some(xid) = xid else { return Ok(()) };
    if device_revoked_conn(conn, &canonical_xid(xid), auth_address, peer_ik)? {
        return Err(Error::Db(format!("channel peer {xid} is revoked")));
    }
    Ok(())
}

fn local_identity_revoked(conn: &rusqlite::Connection, identity_id: i64) -> Result<bool> {
    let row = conn
        .query_row(
            "SELECT xid, auth_address FROM identity WHERE identity_id=?1",
            [identity_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(db_err)?;
    let Some((xid, auth)) = row else {
        return Err(Error::Db(format!(
            "channel identity {identity_id} disappeared"
        )));
    };
    device_revoked_conn(conn, &xid, Some(&auth), "")
}

fn reject_revoked_local_identity(conn: &rusqlite::Connection, identity_id: i64) -> Result<()> {
    if local_identity_revoked(conn, identity_id)? {
        return Err(Error::Db(format!(
            "local channel identity {identity_id} is revoked"
        )));
    }
    Ok(())
}

impl ChannelDb {
    /// Open (creating if needed) the file-backed index, plaintext at rest.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        prepare_channel_db_path(path)?;
        let db = Database::open(path)?;
        harden_channel_db_files(path)?;
        let opened = Self::open_inner(db, None)?;
        harden_channel_db_files(path)?;
        Ok(opened)
    }

    /// Open the file-backed index with at-rest encryption under `key`.
    pub fn open_encrypted(path: impl AsRef<std::path::Path>, key: [u8; 32]) -> Result<Self> {
        let path = path.as_ref();
        prepare_channel_db_path(path)?;
        let db = Database::open(path)?;
        harden_channel_db_files(path)?;
        let opened = Self::open_inner(db, Some(key))?;
        harden_channel_db_files(path)?;
        Ok(opened)
    }

    /// An in-memory index (tests, and nodes with no data dir).
    pub fn memory() -> Result<Self> {
        Self::open_inner(Database::open_in_memory()?, None)
    }

    /// An in-memory index with at-rest encryption (tests).
    pub fn memory_encrypted(key: [u8; 32]) -> Result<Self> {
        Self::open_inner(Database::open_in_memory()?, Some(key))
    }

    /// Bump on any change that a pre-existing db must be MIGRATED for (not just a
    /// new `CREATE TABLE IF NOT EXISTS`). v2 = per-identity idempotency on `msg`
    /// (drop the record-wide `sign_h UNIQUE`) + `processed`. v3 = per-DEVICE
    /// sessions (`session.peer_ik` leg key; UNIQUE moved off the human `peer_xid`).
    /// v4 = retain the peer device's linked-identity address for revocation.
    const SCHEMA_VERSION: i64 = 6;

    fn open_inner(db: Database, enc_key: Option<[u8; 32]>) -> Result<Self> {
        let me = Self { db, enc_key };
        let prior = me.user_version()?;
        me.db.execute_batch(SCHEMA)?; // creates anything missing (fresh db → done)
        if prior < 2 {
            me.migrate_to_v2()?; // rebuild the two tables whose constraints changed
        }
        if prior < 3 {
            me.migrate_to_v3()?; // rebuild session for the per-device leg key
        }
        if prior < 4 {
            me.migrate_to_v4()?; // add the peer device's linked-identity address
        }
        if prior < 5 {
            me.migrate_to_v5()?; // durable record recovery material and status
        }
        if prior < 6 {
            me.migrate_to_v6()?; // per-leg ordering and recoverable route cleanup
        }
        // Each migration advances user_version in the same transaction as its
        // schema mutation. This final assignment is only a no-op for current
        // databases and a guard for future fresh-schema changes.
        me.set_user_version(Self::SCHEMA_VERSION)?;
        me.ensure_encryption_compatible()?;
        Ok(me)
    }

    fn ensure_encryption_compatible(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        if self.enc_key.is_none() {
            return Self::reject_encrypted_rows_without_key(&conn);
        }

        self.authenticate_encrypted_rows(&conn)?;
        self.encrypt_plaintext_rows(&mut conn)
    }

    fn reject_encrypted_rows_without_key(conn: &rusqlite::Connection) -> Result<()> {
        let has_encrypted: i64 = conn
            .query_row(
                "SELECT EXISTS(
                SELECT 1 FROM msg WHERE enc=1
                UNION ALL
                SELECT 1 FROM session WHERE enc=1
                UNION ALL
                SELECT 1 FROM thread WHERE enc=1
                UNION ALL
                SELECT 1 FROM outbound WHERE key_enc=1
             )",
                [],
                |row| row.get(0),
            )
            .map_err(db_err)?;
        if has_encrypted != 0 {
            return Err(Error::Db(
                "channels.db contains encrypted rows; enable channel_encrypt_at_rest to open it"
                    .into(),
            ));
        }
        Ok(())
    }

    fn authenticate_encrypted_rows(&self, conn: &rusqlite::Connection) -> Result<()> {
        // Authenticate every encrypted field before touching plaintext rows.
        // Sampling one row would let a later corrupt or differently-keyed row
        // survive startup and fail only after the index was already in use.
        {
            let mut stmt = conn
                .prepare("SELECT ratchet FROM session WHERE enc=1")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(db_err)?;
            for row in rows {
                self.dec_blob(&row.map_err(db_err)?, 1)?;
            }
        }
        for (table, fields) in [
            ("msg", ["subject", "body"]),
            ("thread", ["subject", "snippet"]),
        ] {
            let sql = format!(
                "SELECT {}, {} FROM {table} WHERE enc=1",
                fields[0], fields[1]
            );
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                    ))
                })
                .map_err(db_err)?;
            for row in rows {
                let (left, right) = row.map_err(db_err)?;
                if let Some(value) = left {
                    self.dec_text(&value, 1)?;
                }
                if let Some(value) = right {
                    self.dec_text(&value, 1)?;
                }
            }
        }
        {
            let mut stmt = conn
                .prepare("SELECT author_key FROM outbound WHERE key_enc=1")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(db_err)?;
            for row in rows {
                self.dec_text(&row.map_err(db_err)?, 1)?;
            }
        }
        Ok(())
    }

    fn encrypt_plaintext_rows(&self, conn: &mut rusqlite::Connection) -> Result<()> {
        // Enabling encryption on an existing plaintext index is an all-or-none
        // migration. No successful open may leave sensitive enc=0 rows behind.
        let tx = conn.transaction().map_err(db_err)?;
        let sessions: Vec<(i64, Vec<u8>)> = {
            let mut stmt = tx
                .prepare("SELECT session_id, ratchet FROM session WHERE enc=0")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(db_err)?;
            rows.map(|row| row.map_err(db_err)).collect::<Result<_>>()?
        };
        for (session_id, ratchet) in sessions {
            let (stored, enc) = self.enc_blob(&ratchet);
            tx.execute(
                "UPDATE session SET ratchet=?1, enc=?2 WHERE session_id=?3",
                rusqlite::params![stored, enc, session_id],
            )
            .map_err(db_err)?;
        }
        let messages: Vec<(i64, Option<String>, Option<String>)> = {
            let mut stmt = tx
                .prepare("SELECT msg_id, subject, body FROM msg WHERE enc=0")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .map_err(db_err)?;
            rows.map(|row| row.map_err(db_err)).collect::<Result<_>>()?
        };
        for (msg_id, subject, body) in messages {
            let subject = subject.map(|value| self.enc_text(&value).0);
            let body = body.map(|value| self.enc_text(&value).0);
            tx.execute(
                "UPDATE msg SET subject=?1, body=?2, enc=1 WHERE msg_id=?3",
                rusqlite::params![subject, body, msg_id],
            )
            .map_err(db_err)?;
        }
        let threads: Vec<(i64, Option<String>, Option<String>)> = {
            let mut stmt = tx
                .prepare("SELECT thread_id, subject, snippet FROM thread WHERE enc=0")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .map_err(db_err)?;
            rows.map(|row| row.map_err(db_err)).collect::<Result<_>>()?
        };
        for (thread_id, subject, snippet) in threads {
            let subject = subject.map(|value| self.enc_text(&value).0);
            let snippet = snippet.map(|value| self.enc_text(&value).0);
            tx.execute(
                "UPDATE thread SET subject=?1, snippet=?2, enc=1 WHERE thread_id=?3",
                rusqlite::params![subject, snippet, thread_id],
            )
            .map_err(db_err)?;
        }
        let outbox_keys: Vec<(i64, String)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT outbox_id, author_key FROM outbound
                     WHERE key_enc=0 AND COALESCE(author_key, '') != ''",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(db_err)?;
            rows.map(|row| row.map_err(db_err)).collect::<Result<_>>()?
        };
        for (outbox_id, author_key) in outbox_keys {
            let (stored, enc) = self.enc_text(&author_key);
            tx.execute(
                "UPDATE outbound SET author_key=?1, key_enc=?2 WHERE outbox_id=?3",
                rusqlite::params![stored, enc, outbox_id],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    fn user_version(&self) -> Result<i64> {
        let conn = self.db.conn()?;
        conn.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(db_err)
    }

    fn set_user_version(&self, v: i64) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute_batch(&format!("PRAGMA user_version = {v}")).map_err(db_err)
    }

    /// Migrate a pre-v2 db in place, PRESERVING all messages and ratchet sessions.
    /// Only `msg` (its record-wide `sign_h UNIQUE` had to become
    /// `UNIQUE(sign_h, identity_id)`, which SQLite can only change by rebuilding the
    /// table) and `processed` (record-wide → per-identity; its old rows carry no
    /// identity so they are dropped — harmless, a re-processed record is idempotent
    /// via the msg uniqueness) are rebuilt. Runs once (guarded by user_version);
    /// on a fresh db the tables are already new-shaped so the copy is a no-op.
    fn migrate_to_v2(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute_batch(
            "\
            DROP TRIGGER IF EXISTS msg_ai;
            DROP TRIGGER IF EXISTS msg_ad;
            DROP TRIGGER IF EXISTS msg_au;
            ALTER TABLE msg RENAME TO msg_old_v1;
            CREATE TABLE msg (
                msg_id        INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                identity_id   INTEGER NOT NULL REFERENCES identity(identity_id),
                thread_id     INTEGER NOT NULL REFERENCES thread(thread_id),
                conv_id       TEXT NOT NULL,
                dir           TEXT NOT NULL,
                sender_xid    TEXT,
                subject       TEXT,
                body          TEXT,
                enc           INTEGER NOT NULL DEFAULT 0,
                sent_ms       INTEGER NOT NULL DEFAULT 0,
                received_ms   INTEGER NOT NULL DEFAULT 0,
                epoch         INTEGER NOT NULL DEFAULT 0,
                read          INTEGER NOT NULL DEFAULT 0,
                sign_h        BLOB,
                UNIQUE(sign_h, identity_id));
            INSERT INTO msg
                (msg_id, identity_id, thread_id, conv_id, dir, sender_xid, subject, body, enc,
                 sent_ms, received_ms, epoch, read, sign_h)
                SELECT msg_id, identity_id, thread_id, conv_id, dir, sender_xid, subject, body, enc,
                 sent_ms, received_ms, epoch, read, sign_h FROM msg_old_v1;
            DROP TABLE msg_old_v1;
            CREATE INDEX IF NOT EXISTS msg_conv ON msg(identity_id, conv_id, sent_ms);
            DROP TABLE IF EXISTS msg_fts;
            CREATE VIRTUAL TABLE msg_fts USING fts5(subject, body, content='msg', content_rowid='msg_id');
            INSERT INTO msg_fts(msg_fts) VALUES('rebuild');
            CREATE TRIGGER msg_ai AFTER INSERT ON msg BEGIN
                INSERT INTO msg_fts(rowid, subject, body) VALUES (new.msg_id, new.subject, new.body);
            END;
            CREATE TRIGGER msg_ad AFTER DELETE ON msg BEGIN
                INSERT INTO msg_fts(msg_fts, rowid, subject, body) VALUES('delete', old.msg_id, old.subject, old.body);
            END;
            CREATE TRIGGER msg_au AFTER UPDATE ON msg BEGIN
                INSERT INTO msg_fts(msg_fts, rowid, subject, body) VALUES('delete', old.msg_id, old.subject, old.body);
                INSERT INTO msg_fts(rowid, subject, body) VALUES (new.msg_id, new.subject, new.body);
            END;
            DROP TABLE IF EXISTS processed;
            CREATE TABLE processed (
                sign_h        BLOB NOT NULL,
                identity_id   INTEGER NOT NULL,
                PRIMARY KEY(sign_h, identity_id));
            PRAGMA user_version = 2;
            ",
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    /// Migrate a v2 db to v3: give `session` a `peer_ik` leg column and move its
    /// UNIQUE off the human `peer_xid` onto `(identity_id, conv_id, peer_ik)`, so a
    /// peer's multiple devices get distinct pairwise ratchets instead of colliding.
    ///
    /// Legacy v2 sessions are DROPPED rather than migrated: their leg was keyed by
    /// the human name, but every live path now keys by the device identity key
    /// (`hex(ik)`), and no legacy row carries that key. Migrating them with a
    /// name-derived `peer_ik` would leave every pre-v3 session unreachable by
    /// `session_id_for_leg` — a continued conversation would fork a new session on
    /// the next reply, orphan the old row, and fire a spurious first-contact event.
    /// A clean drop makes conversations re-establish via a single X3DH handshake.
    /// (channels.db is new in this release cycle, so this only touches dev data.)
    fn migrate_to_v3(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        // Both toggles must be set OUTSIDE a transaction. `foreign_keys=OFF` lets us
        // drop the `session` table that `expected_tag` references; `legacy_alter_table
        // =ON` stops SQLite's "smart rename" from rewriting `expected_tag`'s FK to
        // the temp name. Recipe: create the new table under a temp name, DROP the
        // old, RENAME the new into place, then clear `expected_tag` (its rows point
        // at the now-gone legacy sessions).
        conn.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")
            .map_err(db_err)?;
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute_batch(
            "\
            CREATE TABLE session_v3 (
                session_id    INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                identity_id   INTEGER NOT NULL REFERENCES identity(identity_id),
                conv_id       TEXT NOT NULL,
                peer_xid      TEXT,
                peer_ik       TEXT NOT NULL DEFAULT '',
                role          TEXT NOT NULL,
                ratchet       BLOB NOT NULL,
                enc           INTEGER NOT NULL DEFAULT 0,
                established_ms INTEGER NOT NULL,
                UNIQUE(identity_id, conv_id, peer_ik));
            DROP TABLE session;
            ALTER TABLE session_v3 RENAME TO session;
            DELETE FROM expected_tag;
            PRAGMA user_version = 3;
            ",
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        conn.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;")
            .map_err(db_err)?;
        Ok(())
    }

    fn migrate_to_v4(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        let has_peer_auth = {
            let mut stmt = conn.prepare("PRAGMA table_info(session)").map_err(db_err)?;
            let columns = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(db_err)?;
            let mut found = false;
            for column in columns {
                if column.map_err(db_err)? == "peer_auth" {
                    found = true;
                }
            }
            found
        };
        let tx = conn.transaction().map_err(db_err)?;
        if !has_peer_auth {
            tx.execute_batch("ALTER TABLE session ADD COLUMN peer_auth TEXT")
                .map_err(db_err)?;
        }
        tx.execute_batch("PRAGMA user_version = 4")
            .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    fn migrate_to_v5(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        let columns = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(outbound)")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(db_err)?;
            rows.map(|row| row.map_err(db_err))
                .collect::<Result<std::collections::HashSet<_>>>()?
        };
        let tx = conn.transaction().map_err(db_err)?;
        for (name, sql) in [
            (
                "author_key",
                "ALTER TABLE outbound ADD COLUMN author_key TEXT",
            ),
            (
                "key_enc",
                "ALTER TABLE outbound ADD COLUMN key_enc INTEGER NOT NULL DEFAULT 0",
            ),
            (
                "rln_first_unit",
                "ALTER TABLE outbound ADD COLUMN rln_first_unit INTEGER",
            ),
            (
                "rln_weight",
                "ALTER TABLE outbound ADD COLUMN rln_weight INTEGER",
            ),
            ("rln_root", "ALTER TABLE outbound ADD COLUMN rln_root BLOB"),
            (
                "last_error",
                "ALTER TABLE outbound ADD COLUMN last_error TEXT",
            ),
        ] {
            if !columns.contains(name) {
                tx.execute_batch(sql).map_err(db_err)?;
            }
        }
        tx.execute_batch("PRAGMA user_version = 5")
            .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    fn migrate_to_v6(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbound_dependency (
                outbox_id INTEGER NOT NULL REFERENCES outbound(outbox_id) ON DELETE CASCADE,
                dep_key TEXT NOT NULL,
                PRIMARY KEY(outbox_id, dep_key));
             CREATE INDEX IF NOT EXISTS outbound_dependency_key
                ON outbound_dependency(dep_key, outbox_id);
             CREATE TABLE IF NOT EXISTS outbound_route_cleanup (
                outbox_id INTEGER NOT NULL REFERENCES outbound(outbox_id) ON DELETE CASCADE,
                shard_path TEXT NOT NULL,
                PRIMARY KEY(outbox_id, shard_path));
             INSERT OR IGNORE INTO outbound_dependency(outbox_id, dep_key)
                SELECT outbox_id, 'legacy-global' FROM outbound;
             PRAGMA user_version = 6;",
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Whether content is sealed at rest (drives the search fallback).
    pub fn is_encrypted(&self) -> bool {
        self.enc_key.is_some()
    }

    // --- at-rest sealing helpers ------------------------------------------
    // `enc_*` turn plaintext into what is stored (+ the row's `enc` flag);
    // `dec_*` reverse it based on that flag, so a db can hold a mix during an
    // enable/disable transition.

    /// Plaintext text → (stored text, enc flag). Stored form is base64 of the
    /// sealed bytes when encryption is on, so it still fits a TEXT column.
    fn enc_text(&self, s: &str) -> (String, i64) {
        use base64::Engine as _;
        match &self.enc_key {
            Some(k) => {
                let b = base64::engine::general_purpose::STANDARD.encode(crate::enc::seal(k, s.as_bytes()));
                (b, 1)
            }
            None => (s.to_string(), 0),
        }
    }

    /// Stored text + enc flag → plaintext. Authentication failures are surfaced;
    /// callers must never render ciphertext as an empty message or ratchet.
    fn dec_text(&self, stored: &str, enc: i64) -> Result<String> {
        use base64::Engine as _;
        if enc == 0 {
            return Ok(stored.to_string());
        }
        let k = self.enc_key.as_ref().ok_or_else(|| {
            Error::Db("encrypted channel text cannot be opened without its key".into())
        })?;
        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(stored)
            .map_err(|_| Error::Db("encrypted channel text is not valid base64".into()))
            .and_then(|b| {
                crate::enc::open(k, &b)
                    .ok_or_else(|| Error::Db("encrypted channel text failed authentication".into()))
            })?;
        String::from_utf8(plaintext)
            .map_err(|_| Error::Db("decrypted channel text is not UTF-8".into()))
    }

    /// Plaintext blob → (stored blob, enc flag). Used for the ratchet session state.
    fn enc_blob(&self, b: &[u8]) -> (Vec<u8>, i64) {
        match &self.enc_key {
            Some(k) => (crate::enc::seal(k, b), 1),
            None => (b.to_vec(), 0),
        }
    }

    /// Stored blob + enc flag → plaintext blob.
    fn dec_blob(&self, b: &[u8], enc: i64) -> Result<Vec<u8>> {
        if enc == 0 {
            return Ok(b.to_vec());
        }
        let k = self.enc_key.as_ref().ok_or_else(|| {
            Error::Db("encrypted channel ratchet cannot be opened without its key".into())
        })?;
        crate::enc::open(k, b)
            .ok_or_else(|| Error::Db("encrypted channel ratchet failed authentication".into()))
    }

    /// Seal a message's `(subject, body)` for storage → `(subject_stored,
    /// body_stored, snippet_stored, enc)`. The snippet is a preview of the
    /// PLAINTEXT body, sealed too so the thread list leaks nothing at rest.
    fn seal_content(&self, subject: &str, body: &str) -> (String, String, String, i64) {
        let snippet: String = body.chars().take(140).collect();
        let (subject_stored, enc) = self.enc_text(subject);
        let (body_stored, _) = self.enc_text(body);
        let (snippet_stored, _) = self.enc_text(&snippet);
        (subject_stored, body_stored, snippet_stored, enc)
    }

    /// Decrypt the named text `fields` in each result row per its `enc` marker,
    /// then drop the marker from the output. A no-op on plaintext rows.
    fn decrypt_rows(&self, mut rows: Vec<Value>, fields: &[&str]) -> Result<Vec<Value>> {
        for row in rows.iter_mut() {
            let enc = row.get("enc").and_then(|v| v.as_i64()).unwrap_or(0);
            if enc != 0 {
                for f in fields {
                    if let Some(s) = row.get(*f).and_then(|v| v.as_str()) {
                        let dec = self.dec_text(s, enc)?;
                        row[*f] = Value::from(dec);
                    }
                }
            }
            if let Some(obj) = row.as_object_mut() {
                obj.remove("enc");
            }
        }
        Ok(rows)
    }

    /// The underlying pool (read queries go straight through it).
    pub fn database(&self) -> &Database {
        &self.db
    }

    // --- identities -------------------------------------------------------

    /// Insert or fetch an identity by `(auth_address, derive_index)`.
    pub fn upsert_identity(
        &self,
        xid: &str,
        auth_address: &str,
        derive_index: i64,
        bundle_json: Option<&str>,
    ) -> Result<i64> {
        self.db.execute(
            "INSERT INTO identity (xid, auth_address, derive_index, bundle_json)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(auth_address, derive_index)
             DO UPDATE SET xid=excluded.xid, bundle_json=excluded.bundle_json",
            &[
                Value::from(xid),
                Value::from(auth_address),
                Value::from(derive_index),
                bundle_json.map(Value::from).unwrap_or(Value::Null),
            ],
        )?;
        let rows = self.db.query(
            "SELECT identity_id FROM identity WHERE auth_address=? AND derive_index=?",
            &[Value::from(auth_address), Value::from(derive_index)],
        )?;
        rows.first()
            .and_then(|r| r.get("identity_id").and_then(|v| v.as_i64()))
            .ok_or_else(|| Error::Db("identity upsert did not return id".into()))
    }

    /// All identities (the indexer trial-matches every inbound record against
    /// each of these).
    pub fn identities(&self) -> Result<Vec<IdentityRow>> {
        let rows = self.db.query(
            "SELECT identity_id, xid, auth_address, derive_index, bundle_json, scan_cursor
             FROM identity ORDER BY identity_id DESC",
            &[],
        )?;
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some(IdentityRow {
                    identity_id: r.get("identity_id")?.as_i64()?,
                    xid: r.get("xid")?.as_str()?.to_string(),
                    auth_address: r.get("auth_address")?.as_str()?.to_string(),
                    derive_index: r.get("derive_index")?.as_i64()?,
                    bundle_json: r.get("bundle_json").and_then(|v| v.as_str()).map(String::from),
                    scan_cursor: r.get("scan_cursor").and_then(|v| v.as_i64()).unwrap_or(0),
                })
            })
            .collect())
    }

    /// Distinct established peers, including devices whose published bundle
    /// file has since disappeared. Revocation refresh uses this union with the
    /// current bundle directory so deletion cannot erase the revocation link.
    pub fn session_peers(&self) -> Result<Vec<SessionPeer>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT peer_xid, peer_ik, peer_auth
                 FROM session WHERE peer_xid IS NOT NULL AND peer_xid != ''",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SessionPeer {
                    xid: row.get(0)?,
                    peer_ik: row.get(1)?,
                    peer_auth: row.get(2)?,
                })
            })
            .map_err(db_err)?;
        rows.map(|row| row.map_err(db_err)).collect()
    }

    /// Persist a finalized device revocation. Either linked auth address or
    /// identity key is sufficient to match the same device later.
    pub fn remember_revoked_device(
        &self,
        xid: &str,
        auth_address: Option<&str>,
        peer_ik: &str,
        observed_ms: i64,
    ) -> Result<()> {
        self.remember_revoked_devices(
            &[RevokedDevice {
                xid: xid.to_string(),
                auth_address: auth_address.unwrap_or("").to_string(),
                peer_ik: peer_ik.to_string(),
            }],
            observed_ms,
        )
    }

    /// Persist one finalized status snapshot atomically. A partial tombstone
    /// set must never become visible if any row in the snapshot fails.
    pub fn remember_revoked_devices(
        &self,
        devices: &[RevokedDevice],
        observed_ms: i64,
    ) -> Result<()> {
        if devices.is_empty() {
            return Ok(());
        }
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        for device in devices {
            tx.execute(
                "INSERT OR IGNORE INTO revoked_device
                    (xid, auth_address, peer_ik, observed_ms) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    canonical_xid(&device.xid),
                    device.auth_address,
                    device.peer_ik,
                    observed_ms,
                ],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Bind upgraded v3 sessions to authenticated v3 bundles before a bundle
    /// disappears. Only NULL/empty legacy values are filled and conflicting
    /// authenticated claims for one `(xid, ik)` are rejected.
    pub fn backfill_session_peer_auth(&self, bindings: &[(String, String, String)]) -> Result<()> {
        let mut by_leg = std::collections::HashMap::new();
        for (xid, peer_ik, auth) in bindings {
            let key = (canonical_xid(xid), peer_ik.clone());
            if by_leg
                .insert(key.clone(), auth.clone())
                .is_some_and(|old| old != *auth)
            {
                return Err(Error::Db(format!(
                    "conflicting authenticated bundle owners for {}/{}",
                    key.0, key.1
                )));
            }
        }
        if by_leg.is_empty() {
            return Ok(());
        }
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let sessions: Vec<(i64, String, String)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT session_id, peer_xid, peer_ik FROM session
                     WHERE peer_xid IS NOT NULL AND COALESCE(peer_auth, '')=''",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .map_err(db_err)?;
            rows.map(|row| row.map_err(db_err)).collect::<Result<_>>()?
        };
        for (session_id, xid, peer_ik) in sessions {
            if let Some(auth) = by_leg.get(&(canonical_xid(&xid), peer_ik)) {
                tx.execute(
                    "UPDATE session SET peer_auth=?1
                     WHERE session_id=?2 AND COALESCE(peer_auth, '')=''",
                    rusqlite::params![auth, session_id],
                )
                .map_err(db_err)?;
            }
        }
        tx.commit().map_err(db_err)
    }

    pub fn is_device_revoked(
        &self,
        xid: &str,
        auth_address: Option<&str>,
        peer_ik: &str,
    ) -> Result<bool> {
        let conn = self.db.conn()?;
        device_revoked_conn(&conn, xid, auth_address, peer_ik)
    }

    pub fn revoked_devices(&self) -> Result<Vec<RevokedDevice>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare("SELECT xid, auth_address, peer_ik FROM revoked_device")
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(RevokedDevice {
                    xid: row.get(0)?,
                    auth_address: row.get(1)?,
                    peer_ik: row.get(2)?,
                })
            })
            .map_err(db_err)?;
        rows.map(|row| row.map_err(db_err)).collect()
    }

    // --- processed set ----------------------------------------------------

    /// Whether a pool signature (16-byte prefix) has already been indexed. BLOB
    /// columns must be bound with typed rusqlite params (the generic `Value`
    /// path would encode the bytes as a JSON array, never matching the BLOB).
    pub fn is_processed(&self, sign_h: &[u8], identity_id: i64) -> Result<bool> {
        let conn = self.db.conn()?;
        let found = conn
            .query_row(
                "SELECT 1 FROM processed WHERE sign_h=?1 AND identity_id=?2",
                rusqlite::params![sign_h, identity_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(db_err)?;
        Ok(found.is_some())
    }

    /// Mark a pool signature processed FOR ONE IDENTITY (a record carries slots for
    /// several recipients, so "processed" is per addressed identity — another
    /// identity's undelivered slot in the same record is re-checked independently).
    pub fn mark_processed(&self, sign_h: &[u8], identity_id: i64) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO processed (sign_h, identity_id) VALUES (?1, ?2)",
            rusqlite::params![sign_h, identity_id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    // --- tag matching -----------------------------------------------------

    /// Find the session an inbound `tag` is expected by (Tier-1 O(1) lookup).
    pub fn session_for_tag(&self, tag: &[u8]) -> Result<Option<SessionMatch>> {
        let conn = self.db.conn()?;
        let row = conn
            .query_row(
                "SELECT s.session_id, s.identity_id, s.conv_id, s.peer_xid, s.peer_ik,
                        s.peer_auth, s.ratchet, e.n, s.enc
                 FROM expected_tag e JOIN session s ON s.session_id = e.session_id
                 WHERE e.tag = ?1",
                rusqlite::params![tag],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, i64>(7)?,
                        r.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(db_err)?;
        row.map(
            |(session_id, identity_id, conv_id, peer_xid, peer_ik, peer_auth, ratchet, n, enc)| {
                Ok(SessionMatch {
            session_id,
            identity_id,
            conv_id,
            peer_xid,
                    peer_ik,
                    peer_auth,
                    ratchet: self.dec_blob(&ratchet, enc)?,
            n: n as u32,
                })
            },
        )
        .transpose()
    }

    /// The ratchet blob for a session (decrypted if sealed at rest).
    pub fn session_ratchet(&self, session_id: i64) -> Result<Vec<u8>> {
        let conn = self.db.conn()?;
        let (blob, enc) = conn
            .query_row(
                "SELECT ratchet, enc FROM session WHERE session_id=?",
                [session_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(db_err)?;
        self.dec_blob(&blob, enc)
    }

    // --- session creation (for the send/first-contact paths) --------------

    /// Create a session and register its initial expected receive tags in one
    /// transaction. Returns the new `session_id`.
    pub fn create_session(&self, session: NewSession<'_>) -> Result<i64> {
        let NewSession {
            identity_id,
            conv_id,
            peer_xid,
            peer_ik,
            peer_auth,
            role,
            ratchet,
            established_ms,
            recv_tags,
        } = session;
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let (ratchet_stored, enc) = self.enc_blob(ratchet);
        tx.execute(
            "INSERT INTO session
                (identity_id, conv_id, peer_xid, peer_ik, peer_auth, role, ratchet, enc, established_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(identity_id, conv_id, peer_ik)
               DO UPDATE SET ratchet=excluded.ratchet, enc=excluded.enc,
                 peer_xid=excluded.peer_xid,
                 peer_auth=COALESCE(excluded.peer_auth, session.peer_auth)",
            rusqlite::params![
                identity_id,
                conv_id,
                peer_xid,
                peer_ik,
                peer_auth,
                role,
                ratchet_stored,
                enc,
                established_ms,
            ],
        )
        .map_err(db_err)?;
        let session_id: i64 = tx
            .query_row(
                "SELECT session_id FROM session WHERE identity_id=? AND conv_id=? AND peer_ik=?",
                rusqlite::params![identity_id, conv_id, peer_ik],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        for (n, tag) in recv_tags {
            tx.execute(
                "INSERT OR IGNORE INTO expected_tag (tag, session_id, n) VALUES (?1, ?2, ?3)",
                rusqlite::params![tag, session_id, *n as i64],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        Ok(session_id)
    }

    /// Persist an advanced ratchet for an existing session (own send path).
    pub fn update_session_ratchet(&self, session_id: i64, ratchet: &[u8]) -> Result<()> {
        let conn = self.db.conn()?;
        let (ratchet_stored, enc) = self.enc_blob(ratchet);
        conn.execute(
            "UPDATE session SET ratchet=?1, enc=?2 WHERE session_id=?3",
            rusqlite::params![ratchet_stored, enc, session_id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Atomically advance all sessions used by one sealed record, insert the
    /// optional own-message copy, and retain that exact record in the outbox.
    /// The transport acknowledges the row only after a successful pool append.
    pub fn commit_outbound(&self, commit: &OutboundCommit) -> Result<(i64, i64)> {
        Self::validate_outbound_batch(std::slice::from_ref(commit))?;
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let result = self.commit_outbound_tx(&tx, commit)?;
        tx.commit().map_err(db_err)?;
        Ok(result)
    }

    /// Atomically stage every chunk of one logical message. No earlier chunk is
    /// visible if a later chunk fails validation, proof generation, or storage.
    pub fn commit_outbound_batch(&self, commits: &[OutboundCommit]) -> Result<Vec<(i64, i64)>> {
        if commits.is_empty() {
            return Ok(Vec::new());
        }
        Self::validate_outbound_batch(commits)?;
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let mut results = Vec::with_capacity(commits.len());
        for commit in commits {
            results.push(self.commit_outbound_tx(&tx, commit)?);
        }
        tx.commit().map_err(db_err)?;
        Ok(results)
    }

    fn validate_outbound_batch(commits: &[OutboundCommit]) -> Result<()> {
        let mut session_ids = std::collections::HashSet::new();
        let mut legs = std::collections::HashSet::new();
        let mut sent_rows = 0usize;
        for commit in commits {
            sent_rows += usize::from(commit.sent.is_some());
            for session in &commit.sessions {
                Self::validate_outbound_session(session, &mut session_ids, &mut legs)?;
            }
        }
        if sent_rows > 1 {
            return Err(Error::Db(
                "outbound batch contains more than one logical sent message".into(),
            ));
        }
        Ok(())
    }

    fn validate_outbound_session(
        session: &OutboundSession,
        session_ids: &mut std::collections::HashSet<i64>,
        legs: &mut std::collections::HashSet<(i64, String, String)>,
    ) -> Result<()> {
        if let Some(session_id) = session.session_id {
            if !session_ids.insert(session_id) {
                return Err(Error::Db(format!(
                    "outbound batch advances session {session_id} more than once"
                )));
            }
            if session.ratchet_before.is_none() {
                return Err(Error::Db(format!(
                    "outbound session {session_id} is missing its compare-and-swap state"
                )));
            }
        } else if session.ratchet_before.is_some() {
            return Err(Error::Db(
                "new outbound session unexpectedly has prior ratchet state".into(),
            ));
        }

        let leg = (
            session.identity_id,
            session.conv_id.clone(),
            session.peer_ik.clone(),
        );
        if !legs.insert(leg) {
            return Err(Error::Db(format!(
                "outbound batch advances leg {}/{}/{} more than once",
                session.identity_id, session.conv_id, session.peer_ik
            )));
        }
        Ok(())
    }

    fn commit_outbound_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        commit: &OutboundCommit,
    ) -> Result<(i64, i64)> {
        let record_json = serde_json::to_string(&commit.record)?;

        if let Some(sent) = &commit.sent {
            reject_revoked_local_identity(tx, sent.identity_id)?;
        } else if let Some(session) = commit.sessions.first() {
            // Tail chunks do not repeat the own-message copy, but they still use
            // the same local identity and must pass the commit-time tombstone.
            reject_revoked_local_identity(tx, session.identity_id)?;
        }

        for session in &commit.sessions {
            self.commit_outbound_session_tx(tx, session)?;
        }

        let msg_id = self.insert_outbound_message_tx(tx, commit.sent.as_ref())?;
        let (author_key, key_enc) = self.enc_text(&commit.recovery.author_private_key);
        let (rln_first_unit, rln_weight, rln_root) = commit
            .recovery
            .rln
            .as_ref()
            .map(|reservation| {
                (
                    Some(reservation.first_unit as i64),
                    Some(reservation.weight as i64),
                    reservation.root.map(|root| root.to_vec()),
                )
            })
            .unwrap_or((None, None, None));
        tx.execute(
            "INSERT INTO outbound
                (record_json, shard_path, created_ms, next_attempt_ms,
                 author_key, key_enc, rln_first_unit, rln_weight, rln_root, last_error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            rusqlite::params![
                record_json,
                commit.shard_path,
                commit.created_ms,
                commit.next_attempt_ms,
                author_key,
                key_enc,
                rln_first_unit,
                rln_weight,
                rln_root,
            ],
        )
        .map_err(db_err)?;
        let outbox_id = tx.last_insert_rowid();
        for dependency in outbound_dependency_keys(commit)? {
            tx.execute(
                "INSERT INTO outbound_dependency(outbox_id, dep_key) VALUES (?1, ?2)",
                rusqlite::params![outbox_id, dependency],
            )
            .map_err(db_err)?;
        }
        Ok((outbox_id, msg_id))
    }

    fn commit_outbound_session_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        session: &OutboundSession,
    ) -> Result<()> {
        reject_revoked_peer(
            tx,
            session.peer_xid.as_deref(),
            session.peer_auth.as_deref(),
            &session.peer_ik,
        )?;
        let (ratchet_stored, enc) = self.enc_blob(&session.ratchet_after);
        let Some(session_id) = session.session_id else {
            return Self::insert_outbound_session_tx(tx, session, ratchet_stored, enc);
        };

        let current = tx
            .query_row(
                "SELECT identity_id, conv_id, peer_ik, ratchet, enc
                 FROM session WHERE session_id=?1",
                [session_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(db_err)?
            .ok_or_else(|| {
                Error::Db(format!(
                    "outbound session {session_id} disappeared before commit"
                ))
            })?;
        if current.0 != session.identity_id
            || current.1 != session.conv_id
            || current.2 != session.peer_ik
        {
            return Err(Error::Db(format!(
                "outbound session {session_id} does not match its staged leg"
            )));
        }
        let before = session.ratchet_before.as_deref().ok_or_else(|| {
            Error::Db(format!(
                "outbound session {session_id} is missing its compare-and-swap state"
            ))
        })?;
        if self.dec_blob(&current.3, current.4)? != before {
            return Err(Error::Db(format!(
                "outbound session {session_id} advanced after it was sealed"
            )));
        }
        let changed = tx
            .execute(
                "UPDATE session SET ratchet=?1, enc=?2,
                    peer_auth=COALESCE(?3, peer_auth)
                 WHERE session_id=?4",
                rusqlite::params![ratchet_stored, enc, session.peer_auth, session_id],
            )
            .map_err(db_err)?;
        if changed != 1 {
            return Err(Error::Db(format!(
                "outbound session {session_id} disappeared before commit"
            )));
        }
        Ok(())
    }

    fn insert_outbound_session_tx(
        tx: &rusqlite::Transaction<'_>,
        session: &OutboundSession,
        ratchet_stored: Vec<u8>,
        enc: i64,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO session
                (identity_id, conv_id, peer_xid, peer_ik, peer_auth, role,
                 ratchet, enc, established_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                session.identity_id,
                session.conv_id,
                session.peer_xid,
                session.peer_ik,
                session.peer_auth,
                session.role,
                ratchet_stored,
                enc,
                session.established_ms,
            ],
        )
        .map_err(db_err)?;
        let session_id = tx.last_insert_rowid();
        for (n, tag) in &session.recv_tags {
            tx.execute(
                "INSERT OR IGNORE INTO expected_tag (tag, session_id, n) VALUES (?1, ?2, ?3)",
                rusqlite::params![tag, session_id, *n as i64],
            )
            .map_err(db_err)?;
        }
        Ok(())
    }

    fn insert_outbound_message_tx(
        &self,
        tx: &rusqlite::Transaction<'_>,
        sent: Option<&OutboundMessage>,
    ) -> Result<i64> {
        let Some(sent) = sent else {
            return Ok(0);
        };
        let members_json = if sent.members.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&sent.members)?)
        };
        let (subject_stored, body_stored, snippet_stored, enc) =
            self.seal_content(&sent.subject, &sent.body);
        let thread_id = upsert_thread_tx(
            tx,
            sent.identity_id,
            &sent.conv_id,
            sent.peer_xid.as_deref(),
            members_json.as_deref(),
            &subject_stored,
            &snippet_stored,
            enc,
            sent.sent_ms,
            0,
            1,
        )?;
        tx.execute(
            "INSERT INTO msg
                (identity_id, thread_id, conv_id, dir, sender_xid, subject, body, enc,
                 sent_ms, received_ms, epoch, read, sign_h)
             VALUES (?1, ?2, ?3, 'out', ?4, ?5, ?6, ?7, ?8, ?8, 0, 1, NULL)",
            rusqlite::params![
                sent.identity_id,
                thread_id,
                sent.conv_id,
                sent.sender_xid,
                subject_stored,
                body_stored,
                enc,
                sent.sent_ms,
            ],
        )
        .map_err(db_err)?;
        Ok(tx.last_insert_rowid())
    }

    fn query_pending_outbound<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<Vec<PendingOutbound>> {
        let conn = self.db.conn()?;
        let mut stmt = conn.prepare(sql).map_err(db_err)?;
        let rows = stmt
            .query_map(params, |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (
                outbox_id,
                record_json,
                shard_path,
                created_ms,
                next_attempt_ms,
                author_key,
                key_enc,
                rln_first_unit,
                rln_weight,
                rln_root,
                last_error,
            ) = row.map_err(db_err)?;
            out.push(PendingOutbound {
                outbox_id,
                record: serde_json::from_str(&record_json)?,
                shard_path,
                created_ms,
                next_attempt_ms,
                recovery: OutboundRecovery {
                    author_private_key: self.dec_text(&author_key, key_enc)?,
                    rln: decode_rln_reservation(rln_first_unit, rln_weight, rln_root)?,
                },
                last_error,
            });
        }
        Ok(out)
    }

    /// Oldest durable outbound records, in append order.
    pub fn pending_outbound(&self, limit: usize) -> Result<Vec<PendingOutbound>> {
        self.query_pending_outbound(
            "SELECT outbox_id, record_json, shard_path, created_ms, next_attempt_ms,
                    COALESCE(author_key, ''), key_enc, rln_first_unit, rln_weight,
                    rln_root, last_error
             FROM outbound ORDER BY outbox_id ASC LIMIT ?1",
            [limit as i64],
        )
    }

    /// Due rows whose ratchet dependencies have no older pending owner. A
    /// migrated legacy row remains a finite global barrier, but a backed-off
    /// normal row blocks only its own conversation/device legs.
    pub fn due_outbound_prefix(&self, now_ms: i64, limit: usize) -> Result<Vec<PendingOutbound>> {
        self.query_pending_outbound(
            "SELECT o.outbox_id, o.record_json, o.shard_path, o.created_ms,
                    o.next_attempt_ms, COALESCE(o.author_key, ''), o.key_enc,
                    o.rln_first_unit, o.rln_weight, o.rln_root, o.last_error
             FROM outbound o
             WHERE o.next_attempt_ms <= ?1
               AND NOT EXISTS (
                   SELECT 1 FROM outbound_dependency legacy
                   WHERE legacy.dep_key='legacy-global'
                     AND legacy.outbox_id < o.outbox_id)
               AND NOT EXISTS (
                   SELECT 1
                   FROM outbound_dependency mine
                   JOIN outbound_dependency older
                     ON older.dep_key=mine.dep_key
                    AND older.outbox_id < mine.outbox_id
                   WHERE mine.outbox_id=o.outbox_id)
             ORDER BY o.next_attempt_ms ASC, o.outbox_id ASC LIMIT ?2",
            rusqlite::params![now_ms, limit as i64],
        )
    }

    /// Every dependency-ready due row up through `outbox_id`.
    pub fn pending_outbound_through(&self, outbox_id: i64) -> Result<Vec<PendingOutbound>> {
        self.query_pending_outbound(
            "SELECT o.outbox_id, o.record_json, o.shard_path, o.created_ms,
                    o.next_attempt_ms, COALESCE(o.author_key, ''), o.key_enc,
                    o.rln_first_unit, o.rln_weight, o.rln_root, o.last_error
             FROM outbound o
             WHERE o.outbox_id <= ?1
               AND o.next_attempt_ms <= ?2
               AND NOT EXISTS (
                   SELECT 1 FROM outbound_dependency legacy
                   WHERE legacy.dep_key='legacy-global'
                     AND legacy.outbox_id < o.outbox_id)
               AND NOT EXISTS (
                   SELECT 1
                   FROM outbound_dependency mine
                   JOIN outbound_dependency older
                     ON older.dep_key=mine.dep_key
                    AND older.outbox_id < mine.outbox_id
                   WHERE mine.outbox_id=o.outbox_id)
             ORDER BY o.outbox_id ASC",
            rusqlite::params![outbox_id, epix_core::time::now_ms()],
        )
    }

    pub fn outbound_pending(&self, outbox_id: i64) -> Result<bool> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM outbound WHERE outbox_id=?1)",
            [outbox_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists != 0)
        .map_err(db_err)
    }

    /// Back off a failed append without losing the exact signed record.
    pub fn reschedule_outbound(&self, outbox_id: i64, next_attempt_ms: i64) -> Result<()> {
        self.reschedule_outbound_error(outbox_id, next_attempt_ms, None)
    }

    pub fn reschedule_outbound_error(
        &self,
        outbox_id: i64,
        next_attempt_ms: i64,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "UPDATE outbound SET next_attempt_ms=?1, last_error=?2 WHERE outbox_id=?3",
            rusqlite::params![next_attempt_ms, error, outbox_id],
        )
        .map_err(db_err)?;
        Ok(())
    }

    /// Replace only the public representation of a queued logical ciphertext.
    /// Session state, sent-message copy, recovery key, and RLN reservation stay
    /// untouched.
    pub fn replace_outbound_record(
        &self,
        outbox_id: i64,
        record: &Value,
        shard_path: &str,
        recovery: &OutboundRecovery,
    ) -> Result<()> {
        let mut conn = self.db.conn()?;
        let record_json = serde_json::to_string(record)?;
        let (author_key, key_enc) = self.enc_text(&recovery.author_private_key);
        let (rln_first_unit, rln_weight, rln_root) = recovery
            .rln
            .as_ref()
            .map(|reservation| {
                (
                    Some(reservation.first_unit as i64),
                    Some(reservation.weight as i64),
                    reservation.root.map(|root| root.to_vec()),
                )
            })
            .unwrap_or((None, None, None));
        let tx = conn.transaction().map_err(db_err)?;
        let old_path = tx
            .query_row(
                "SELECT shard_path FROM outbound WHERE outbox_id=?1",
                [outbox_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(db_err)?
            .ok_or_else(|| Error::Db(format!("outbox row {outbox_id} disappeared")))?;
        if old_path != shard_path {
            tx.execute(
                "INSERT OR IGNORE INTO outbound_route_cleanup(outbox_id, shard_path)
                 VALUES (?1, ?2)",
                rusqlite::params![outbox_id, old_path],
            )
            .map_err(db_err)?;
            // A repeated route change may return to a path that was previously
            // queued for cleanup. It is current again and must not be removed.
            tx.execute(
                "DELETE FROM outbound_route_cleanup
                 WHERE outbox_id=?1 AND shard_path=?2",
                rusqlite::params![outbox_id, shard_path],
            )
            .map_err(db_err)?;
        }
        let changed = tx
            .execute(
                "UPDATE outbound SET record_json=?1, shard_path=?2,
                    author_key=?3, key_enc=?4, rln_first_unit=?5,
                    rln_weight=?6, rln_root=?7, last_error=NULL
                 WHERE outbox_id=?8",
                rusqlite::params![
                    record_json,
                    shard_path,
                    author_key,
                    key_enc,
                    rln_first_unit,
                    rln_weight,
                    rln_root,
                    outbox_id,
                ],
            )
            .map_err(db_err)?;
        if changed != 1 {
            return Err(Error::Db(format!("outbox row {outbox_id} disappeared")));
        }
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    pub fn outbound_route_cleanup(&self, outbox_id: i64) -> Result<Vec<String>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT shard_path FROM outbound_route_cleanup
                 WHERE outbox_id=?1 ORDER BY shard_path",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([outbox_id], |row| row.get::<_, String>(0))
            .map_err(db_err)?;
        rows.map(|row| row.map_err(db_err)).collect()
    }

    pub fn outbox_status(&self) -> Result<(i64, Option<String>)> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT COUNT(*),
                    (SELECT last_error FROM outbound ORDER BY outbox_id LIMIT 1)
             FROM outbound",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db_err)
    }

    /// Persist a route-only descriptor migration for an exact signed record.
    /// The compare on the old path prevents a stale retry from overwriting a
    /// newer migration decision.
    pub fn reroute_outbound(&self, outbox_id: i64, old_path: &str, new_path: &str) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute(
            "INSERT OR IGNORE INTO outbound_route_cleanup(outbox_id, shard_path)
             SELECT outbox_id, shard_path FROM outbound
             WHERE outbox_id=?1 AND shard_path=?2",
            rusqlite::params![outbox_id, old_path],
        )
        .map_err(db_err)?;
        tx.execute(
            "DELETE FROM outbound_route_cleanup
             WHERE outbox_id=?1 AND shard_path=?2",
            rusqlite::params![outbox_id, new_path],
        )
        .map_err(db_err)?;
        let changed = tx
            .execute(
                "UPDATE outbound SET shard_path=?1
                 WHERE outbox_id=?2 AND shard_path=?3",
                rusqlite::params![new_path, outbox_id, old_path],
            )
            .map_err(db_err)?;
        if changed != 1 {
            return Err(Error::Db(format!(
                "outbox row {outbox_id} changed while rerouting"
            )));
        }
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    /// Remove one outbox row after its exact record was durably merged into the
    /// local pool shard. Repeating the acknowledgement is harmless.
    pub fn ack_outbound(&self, outbox_id: i64) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute("DELETE FROM outbound WHERE outbox_id=?1", [outbox_id])
            .map_err(db_err)?;
        Ok(())
    }

    /// Look up an existing session id for one leg `(identity, conv, peer_ik)`.
    pub fn session_id_for_leg(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_ik: &str,
    ) -> Result<Option<i64>> {
        let conn = self.db.conn()?;
        conn.query_row(
                "SELECT session_id FROM session WHERE identity_id=? AND conv_id=? AND peer_ik=?",
                rusqlite::params![identity_id, conv_id, peer_ik],
                |row| row.get::<_, i64>(0),
            )
        .optional()
        .map_err(db_err)
    }

    // --- inbound commit (the atomic index write) --------------------------

    /// Commit a decrypted inbound message together with its session/tag updates
    /// in ONE transaction: upsert the thread (+unread), insert the message
    /// (+FTS via triggers), advance the ratchet, consume the matched tag,
    /// register the next lookahead tags, and record the signature as processed.
    /// Returns the new `msg_id`, or `None` if the signature was already indexed
    /// (idempotent replay).
    pub fn commit_inbound(&self, c: &InboundCommit) -> Result<Option<i64>> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;

        // Idempotency is PER IDENTITY: the same record delivered to a DIFFERENT
        // local identity's slot is a distinct inbox row, not a duplicate.
        let already_processed = tx
            .query_row(
                "SELECT 1 FROM processed WHERE sign_h=? AND identity_id=?",
                rusqlite::params![c.sign_h, c.identity_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(db_err)?
            .is_some();
        if already_processed {
            tx.commit().map_err(db_err)?;
            return Ok(None);
        }

        if local_identity_revoked(&tx, c.identity_id)? {
            // A revoked local slot is a permanent discard, not a retriable DB
            // failure. Record it atomically for this identity only, without
            // advancing the session ratchet, so another active local slot in the
            // same count-hiding record can still index.
            tx.execute(
                "INSERT OR IGNORE INTO processed (sign_h, identity_id) VALUES (?1, ?2)",
                rusqlite::params![c.sign_h, c.identity_id],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            return Ok(None);
        }
        let session_id = if let Some(session_id) = c.session_id {
            let peer = tx
                .query_row(
                    "SELECT peer_xid, peer_auth, peer_ik FROM session WHERE session_id=?1",
                    [session_id],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(db_err)?
                .ok_or_else(|| Error::Db(format!("inbound session {session_id} disappeared")))?;
            reject_revoked_peer(&tx, peer.0.as_deref(), peer.1.as_deref(), &peer.2)?;
            session_id
        } else {
            let session = c.new_session.as_ref().ok_or_else(|| {
                Error::Db("first-contact inbound commit is missing its staged session".into())
            })?;
            if session.identity_id != c.identity_id || session.conv_id != c.conv_id {
                return Err(Error::Db(
                    "first-contact session does not match its inbound message".into(),
                ));
            }
            reject_revoked_peer(
                &tx,
                session.peer_xid.as_deref(),
                session.peer_auth.as_deref(),
                &session.peer_ik,
            )?;

            // A concurrent opener for the same leg wins. This later opener is a
            // replay/race, not a second message or a forked ratchet.
            if tx
                .query_row(
                    "SELECT session_id FROM session
                     WHERE identity_id=?1 AND conv_id=?2 AND peer_ik=?3",
                    rusqlite::params![session.identity_id, session.conv_id, session.peer_ik],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(db_err)?
                .is_some()
            {
                tx.execute(
                    "INSERT OR IGNORE INTO processed (sign_h, identity_id) VALUES (?1, ?2)",
                    rusqlite::params![c.sign_h, c.identity_id],
                )
                .map_err(db_err)?;
                tx.commit().map_err(db_err)?;
                return Ok(None);
            }

            let (ratchet_stored, enc) = self.enc_blob(&session.ratchet_after);
            tx.execute(
                "INSERT INTO session
                    (identity_id, conv_id, peer_xid, peer_ik, peer_auth, role,
                     ratchet, enc, established_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    session.identity_id,
                    session.conv_id,
                    session.peer_xid,
                    session.peer_ik,
                    session.peer_auth,
                    session.role,
                    ratchet_stored,
                    enc,
                    session.established_ms,
                ],
            )
            .map_err(db_err)?;
            let session_id = tx.last_insert_rowid();
            for (n, tag) in &session.recv_tags {
                tx.execute(
                    "INSERT OR IGNORE INTO expected_tag (tag, session_id, n) VALUES (?1, ?2, ?3)",
                    rusqlite::params![tag, session_id, *n as i64],
                )
                .map_err(db_err)?;
            }
            session_id
        };

        let members_json = if c.members.is_empty() {
            None
        } else {
            serde_json::to_string(&c.members).ok()
        };
        let (subject_stored, body_stored, snippet_stored, enc) =
            self.seal_content(&c.subject, &c.body);
        let thread_id = upsert_thread_tx(
            &tx,
            c.identity_id,
            &c.conv_id,
            c.peer_xid.as_deref(),
            members_json.as_deref(),
            &subject_stored,
            &snippet_stored,
            enc,
            c.sent_ms,
            /*incr_unread=*/ 1,
            /*incr_count=*/ 1,
        )?;

        let msg_id: i64 = {
            tx.execute(
                "INSERT INTO msg
                    (identity_id, thread_id, conv_id, dir, sender_xid, subject, body, enc,
                     sent_ms, received_ms, epoch, read, sign_h)
                 VALUES (?1, ?2, ?3, 'in', ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11)",
                rusqlite::params![
                    c.identity_id,
                    thread_id,
                    c.conv_id,
                    c.sender_xid,
                    subject_stored,
                    body_stored,
                    enc,
                    c.sent_ms,
                    c.received_ms,
                    c.epoch,
                    c.sign_h,
                ],
            )
            .map_err(db_err)?;
            tx.last_insert_rowid()
        };

        let (ratchet_stored, renc) = self.enc_blob(&c.ratchet_after);
        tx.execute(
            "UPDATE session SET ratchet=?1, enc=?2, peer_xid=COALESCE(peer_xid, ?3) WHERE session_id=?4",
            rusqlite::params![ratchet_stored, renc, c.peer_xid, session_id],
        )
        .map_err(db_err)?;

        tx.execute(
            "DELETE FROM expected_tag WHERE tag=?1",
            rusqlite::params![c.consumed_tag],
        )
        .map_err(db_err)?;
        for (n, tag) in &c.new_tags {
            tx.execute(
                "INSERT OR IGNORE INTO expected_tag (tag, session_id, n) VALUES (?1, ?2, ?3)",
                rusqlite::params![tag, session_id, *n as i64],
            )
            .map_err(db_err)?;
        }

        tx.execute(
            "INSERT OR IGNORE INTO processed (sign_h, identity_id) VALUES (?1, ?2)",
            rusqlite::params![c.sign_h, c.identity_id],
        )
        .map_err(db_err)?;

        tx.commit().map_err(db_err)?;
        Ok(Some(msg_id))
    }

    /// Insert an OWN sent message (no pool signature; written directly, never
    /// posted encrypted-to-self) and bump its thread.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_sent(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_xid: Option<&str>,
        members: &[String],
        sender_xid: &str,
        subject: &str,
        body: &str,
        sent_ms: i64,
    ) -> Result<i64> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let members_json =
            if members.is_empty() { None } else { serde_json::to_string(members).ok() };
        let (subject_stored, body_stored, snippet_stored, enc) = self.seal_content(subject, body);
        let thread_id = upsert_thread_tx(
            &tx, identity_id, conv_id, peer_xid, members_json.as_deref(), &subject_stored,
            &snippet_stored, enc, sent_ms, /*unread=*/ 0, /*count=*/ 1,
        )?;
        tx.execute(
            "INSERT INTO msg
                (identity_id, thread_id, conv_id, dir, sender_xid, subject, body, enc,
                 sent_ms, received_ms, epoch, read, sign_h)
             VALUES (?1, ?2, ?3, 'out', ?4, ?5, ?6, ?7, ?8, ?8, 0, 1, NULL)",
            rusqlite::params![
                identity_id, thread_id, conv_id, sender_xid, subject_stored, body_stored, enc, sent_ms
            ],
        )
        .map_err(db_err)?;
        let msg_id = tx.last_insert_rowid();
        tx.commit().map_err(db_err)?;
        Ok(msg_id)
    }

    /// Insert one already-decrypted LEGACY message into the private index,
    /// idempotently. `dedup_h` is a stable 16-byte key for the source message
    /// (so re-running the one-shot migration imports nothing twice); it is
    /// stored in the `sign_h` column, which is `UNIQUE`. Historical messages are
    /// imported as already-read (no unread bump). Returns `true` if a new row
    /// landed, `false` if it was already present.
    #[allow(clippy::too_many_arguments)]
    pub fn import_legacy(
        &self,
        identity_id: i64,
        conv_id: &str,
        sender_xid: &str,
        is_out: bool,
        members: &[String],
        subject: &str,
        body: &str,
        sent_ms: i64,
        dedup_h: &[u8],
    ) -> Result<bool> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        // Idempotency is PER IDENTITY (matching `UNIQUE(sign_h, identity_id)` and
        // `commit_inbound`): the same source message legitimately imports once per
        // local identity, so scoping the dedup to this identity avoids silently
        // dropping a second identity's own copy.
        let dup: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM msg WHERE sign_h=?1 AND identity_id=?2",
                rusqlite::params![dedup_h, identity_id],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        if dup > 0 {
            return Ok(false);
        }
        let members_json =
            if members.is_empty() { None } else { serde_json::to_string(members).ok() };
        // On a received message the peer is the sender; on a sent one there is
        // no single peer (the thread's members carry the audience).
        let peer_xid = if is_out { None } else { Some(sender_xid) };
        let (subject_stored, body_stored, snippet_stored, enc) = self.seal_content(subject, body);
        let thread_id = upsert_thread_tx(
            &tx, identity_id, conv_id, peer_xid, members_json.as_deref(), &subject_stored,
            &snippet_stored, enc, sent_ms, /*unread=*/ 0, /*count=*/ 1,
        )?;
        let dir = if is_out { "out" } else { "in" };
        tx.execute(
            "INSERT INTO msg
                (identity_id, thread_id, conv_id, dir, sender_xid, subject, body, enc,
                 sent_ms, received_ms, epoch, read, sign_h)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, 0, 1, ?10)",
            rusqlite::params![
                identity_id, thread_id, conv_id, dir, sender_xid, subject_stored, body_stored, enc,
                sent_ms, dedup_h
            ],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(true)
    }

    // --- reads ------------------------------------------------------------

    /// Threads for an identity/folder, newest first.
    pub fn threads(
        &self,
        identity_id: i64,
        folder: &str,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<Value>> {
        let filter = match folder {
            "archived" => "archived=1",
            "starred" => "starred=1 AND archived=0",
            _ => "archived=0",
        };
        let sql = format!(
            "SELECT thread_id, conv_id, peer_xid, members, subject, snippet, last_ms, msg_count,
                    unread, starred, archived, enc
             FROM thread WHERE identity_id=? AND {filter}
             ORDER BY last_ms DESC LIMIT ? OFFSET ?"
        );
        let rows = self.db.query(
            &sql,
            &[
                Value::from(identity_id),
                Value::from(limit),
                Value::from(offset),
            ],
        )?;
        self.decrypt_rows(rows, &["subject", "snippet"])
    }

    /// Messages of a conversation, oldest first.
    pub fn messages(&self, identity_id: i64, conv_id: &str) -> Result<Vec<Value>> {
        let rows = self.db.query(
            "SELECT msg_id, dir, sender_xid, subject, body, sent_ms, received_ms, read, enc
             FROM msg WHERE identity_id=? AND conv_id=? ORDER BY sent_ms ASC, msg_id ASC",
            &[Value::from(identity_id), Value::from(conv_id)],
        )?;
        self.decrypt_rows(rows, &["subject", "body"])
    }

    /// Full-text search over subjects+bodies for an identity, newest first. When
    /// at-rest encryption is on, FTS indexes ciphertext (useless), so search
    /// falls back to a decrypt-then-scan over the identity's messages.
    pub fn search(&self, identity_id: i64, query: &str, limit: i64) -> Result<Vec<Value>> {
        if self.is_encrypted() {
            return self.search_scan(identity_id, query, limit);
        }
        self.db.query(
            "SELECT m.msg_id, m.conv_id, m.dir, m.sender_xid, m.subject, m.sent_ms,
                    snippet(msg_fts, 1, '[', ']', '…', 12) AS snippet
             FROM msg_fts f JOIN msg m ON m.msg_id = f.rowid
             WHERE f.msg_fts MATCH ? AND m.identity_id = ?
             ORDER BY m.sent_ms DESC LIMIT ?",
            &[Value::from(query), Value::from(identity_id), Value::from(limit)],
        )
    }

    /// Decrypt-then-scan search used when content is sealed at rest. Linear in
    /// the identity's message count; a substring (case-insensitive) match, which
    /// is what the site's own client-side search does anyway.
    fn search_scan(&self, identity_id: i64, query: &str, limit: i64) -> Result<Vec<Value>> {
        let rows = self.db.query(
            "SELECT msg_id, conv_id, dir, sender_xid, subject, body, sent_ms, enc
             FROM msg WHERE identity_id=? ORDER BY sent_ms DESC",
            &[Value::from(identity_id)],
        )?;
        let q = query.to_lowercase();
        let mut out = Vec::new();
        for row in rows {
            let enc = row.get("enc").and_then(|v| v.as_i64()).unwrap_or(0);
            let subject = self.dec_text(
                row.get("subject").and_then(|v| v.as_str()).unwrap_or(""),
                enc,
            )?;
            let body =
                self.dec_text(row.get("body").and_then(|v| v.as_str()).unwrap_or(""), enc)?;
            if subject.to_lowercase().contains(&q) || body.to_lowercase().contains(&q) {
                let snippet: String = body.chars().take(80).collect();
                out.push(serde_json::json!({
                    "msg_id": row.get("msg_id").cloned().unwrap_or(Value::Null),
                    "conv_id": row.get("conv_id").cloned().unwrap_or(Value::Null),
                    "dir": row.get("dir").cloned().unwrap_or(Value::Null),
                    "sender_xid": row.get("sender_xid").cloned().unwrap_or(Value::Null),
                    "subject": subject,
                    "sent_ms": row.get("sent_ms").cloned().unwrap_or(Value::Null),
                    "snippet": snippet,
                }));
                if out.len() >= limit as usize {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Mark a conversation read/unread (per-device state).
    pub fn mark_read(&self, identity_id: i64, conv_id: &str, read: bool) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let read_i = if read { 1 } else { 0 };
        tx.execute(
            "UPDATE msg SET read=?1 WHERE identity_id=?2 AND conv_id=?3",
            rusqlite::params![read_i, identity_id, conv_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "UPDATE thread SET unread=?1 WHERE identity_id=?2 AND conv_id=?3",
            rusqlite::params![if read { 0 } else { 1 }, identity_id, conv_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// Set per-device conversation flags (star / archive). A `None` field is
    /// left unchanged. Local index only — the sealed pool records are immutable
    /// and never touched, so this state is per-device by design.
    pub fn set_conv_state(
        &self,
        identity_id: i64,
        conv_id: &str,
        starred: Option<bool>,
        archived: Option<bool>,
    ) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        if let Some(v) = starred {
            tx.execute(
                "UPDATE thread SET starred=?1 WHERE identity_id=?2 AND conv_id=?3",
                rusqlite::params![v as i64, identity_id, conv_id],
            )
            .map_err(db_err)?;
        }
        if let Some(v) = archived {
            tx.execute(
                "UPDATE thread SET archived=?1 WHERE identity_id=?2 AND conv_id=?3",
                rusqlite::params![v as i64, identity_id, conv_id],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)
    }

    /// Total unread conversations for an identity (drives the badge).
    pub fn unread_count(&self, identity_id: i64) -> Result<i64> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT COUNT(*) FROM thread WHERE identity_id=? AND unread>0 AND archived=0",
            [identity_id],
            |r| r.get::<_, i64>(0),
        )
        .map_err(db_err)
    }

    /// Delete a conversation from the LOCAL index only (the sealed pool records
    /// are immutable and untouched).
    pub fn delete_conversation(&self, identity_id: i64, conv_id: &str) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        tx.execute(
            "DELETE FROM msg WHERE identity_id=?1 AND conv_id=?2",
            rusqlite::params![identity_id, conv_id],
        )
        .map_err(db_err)?;
        tx.execute(
            "DELETE FROM thread WHERE identity_id=?1 AND conv_id=?2",
            rusqlite::params![identity_id, conv_id],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        Ok(())
    }
}

/// Upsert a thread inside a transaction and return its id. `incr_unread` /
/// `incr_count` are added to the running totals; `subject_stored`/`snippet_stored`
/// (already sealed if at-rest encryption is on, with `enc` the flag) are set when
/// the thread is new or this message is newer than the stored `last_ms`.
#[allow(clippy::too_many_arguments)]
fn upsert_thread_tx(
    tx: &rusqlite::Transaction,
    identity_id: i64,
    conv_id: &str,
    peer_xid: Option<&str>,
    members: Option<&str>,
    subject_stored: &str,
    snippet_stored: &str,
    enc: i64,
    sent_ms: i64,
    incr_unread: i64,
    incr_count: i64,
) -> Result<i64> {
    tx.execute(
        "INSERT INTO thread
            (identity_id, conv_id, peer_xid, members, subject, snippet, enc, last_ms, msg_count, unread)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(identity_id, conv_id) DO UPDATE SET
            peer_xid = COALESCE(thread.peer_xid, excluded.peer_xid),
            members  = COALESCE(excluded.members, thread.members),
            subject  = CASE WHEN excluded.last_ms >= thread.last_ms THEN excluded.subject ELSE thread.subject END,
            snippet  = CASE WHEN excluded.last_ms >= thread.last_ms THEN excluded.snippet ELSE thread.snippet END,
            enc      = CASE WHEN excluded.last_ms >= thread.last_ms THEN excluded.enc ELSE thread.enc END,
            last_ms  = MAX(thread.last_ms, excluded.last_ms),
            msg_count = thread.msg_count + ?9,
            unread   = thread.unread + ?10",
        rusqlite::params![
            identity_id,
            conv_id,
            peer_xid,
            members,
            subject_stored,
            snippet_stored,
            enc,
            sent_ms,
            incr_count,
            incr_unread,
        ],
    )
    .map_err(db_err)?;
    let id: i64 = tx
        .query_row(
            "SELECT thread_id FROM thread WHERE identity_id=? AND conv_id=?",
            rusqlite::params![identity_id, conv_id],
            |r| r.get(0),
        )
        .map_err(db_err)?;
    Ok(id)
}

/// `ChannelDb` is one implementation of the generic [`EnvelopeStore`] — it lets the
/// app-agnostic `epix-envelope` indexer write decrypted messages into this schema.
/// The methods forward to the inherent ones above; the app-specific reads
/// (threads/messages/search/…) are NOT part of the trait and stay inherent.
impl EnvelopeStore for ChannelDb {
    fn is_processed(&self, sign_h: &[u8], identity_id: i64) -> Result<bool> {
        ChannelDb::is_processed(self, sign_h, identity_id)
    }
    fn mark_processed(&self, sign_h: &[u8], identity_id: i64) -> Result<()> {
        ChannelDb::mark_processed(self, sign_h, identity_id)
    }
    fn session_for_tag(&self, tag: &[u8]) -> Result<Option<SessionMatch>> {
        ChannelDb::session_for_tag(self, tag)
    }
    fn session_ratchet(&self, session_id: i64) -> Result<Vec<u8>> {
        ChannelDb::session_ratchet(self, session_id)
    }
    fn session_id_for_leg(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_ik: &str,
    ) -> Result<Option<i64>> {
        ChannelDb::session_id_for_leg(self, identity_id, conv_id, peer_ik)
    }
    fn create_session(&self, session: NewSession<'_>) -> Result<i64> {
        ChannelDb::create_session(self, session)
    }
    fn update_session_ratchet(&self, session_id: i64, ratchet: &[u8]) -> Result<()> {
        ChannelDb::update_session_ratchet(self, session_id, ratchet)
    }
    fn commit_outbound(&self, commit: &OutboundCommit) -> Result<(i64, i64)> {
        ChannelDb::commit_outbound(self, commit)
    }
    fn commit_outbound_batch(&self, commits: &[OutboundCommit]) -> Result<Vec<(i64, i64)>> {
        ChannelDb::commit_outbound_batch(self, commits)
    }
    fn commit_inbound(&self, c: &InboundCommit) -> Result<Option<i64>> {
        ChannelDb::commit_inbound(self, c)
    }
    fn insert_sent(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_xid: Option<&str>,
        members: &[String],
        sender_xid: &str,
        subject: &str,
        body: &str,
        sent_ms: i64,
    ) -> Result<i64> {
        ChannelDb::insert_sent(
            self, identity_id, conv_id, peer_xid, members, sender_xid, subject, body, sent_ms,
        )
    }
    fn unread_count(&self, identity_id: i64) -> Result<i64> {
        ChannelDb::unread_count(self, identity_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> ChannelDb {
        ChannelDb::memory().unwrap()
    }

    fn recovery() -> OutboundRecovery {
        OutboundRecovery {
            author_private_key: epix_crypt::new_seed(),
            rln: None,
        }
    }

    #[test]
    fn identity_upsert_is_idempotent() {
        let d = db();
        let a = d.upsert_identity("mud.epix", "epix1mud", 0, Some("{\"ik\":\"x\"}")).unwrap();
        let b = d.upsert_identity("mud.epix", "epix1mud", 0, Some("{\"ik\":\"y\"}")).unwrap();
        assert_eq!(a, b, "same (auth,index) -> same identity row");
        assert_eq!(d.identities().unwrap().len(), 1);
        // different derive_index -> new identity
        let c = d.upsert_identity("mud.epix", "epix1mud", 1, None).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn processed_set_roundtrips() {
        let d = db();
        let h = vec![1u8; 16];
        // Per-identity: processed for id 1 does NOT imply processed for id 2.
        assert!(!d.is_processed(&h, 1).unwrap());
        d.mark_processed(&h, 1).unwrap();
        assert!(d.is_processed(&h, 1).unwrap());
        assert!(!d.is_processed(&h, 2).unwrap(), "processed is keyed per identity");
        d.mark_processed(&h, 1).unwrap(); // idempotent
    }

    #[test]
    fn inbound_commit_is_atomic_and_idempotent() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        let sid = d
            .create_session(NewSession {
                identity_id: idn,
                conv_id: "cafe00",
                peer_xid: Some("dice.epix"),
                peer_ik: "ik-dice",
                peer_auth: None,
                role: "resp",
                ratchet: b"ratchet-v0",
                established_ms: 1000,
                recv_tags: &[],
            })
            .unwrap();

        let c = InboundCommit {
            identity_id: idn,
            session_id: Some(sid),
            new_session: None,
            conv_id: "cafe00".into(),
            peer_xid: Some("dice.epix".into()),
            sender_xid: Some("dice.epix".into()),
            members: vec![],
            subject: "hello".into(),
            body: "secret body ZXQ1".into(),
            sent_ms: 2000,
            received_ms: 2100,
            epoch: 20678,
            sign_h: vec![9u8; 16],
            ratchet_after: b"ratchet-v1".to_vec(),
            consumed_tag: vec![],
            new_tags: vec![(1, vec![7u8; 32])],
        };
        let m1 = d.commit_inbound(&c).unwrap();
        assert!(m1.is_some());
        // replay is a no-op (same sign_h)
        let m2 = d.commit_inbound(&c).unwrap();
        assert!(m2.is_none());

        // thread shows one unread, ratchet advanced, tag registered.
        let threads = d.threads(idn, "all", 0, 10).unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0]["unread"].as_i64(), Some(1));
        assert_eq!(threads[0]["msg_count"].as_i64(), Some(1));
        assert_eq!(d.session_ratchet(sid).unwrap(), b"ratchet-v1");
        let sm = d.session_for_tag(&vec![7u8; 32]).unwrap().unwrap();
        assert_eq!(sm.session_id, sid);
        assert_eq!(sm.n, 1);
        assert_eq!(d.unread_count(idn).unwrap(), 1);
    }

    #[test]
    fn fts_search_finds_body_terms() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        d.insert_sent(idn, "c1", Some("dice.epix"), &[], "mud.epix", "Dinner", "pizza at eight", 5000)
            .unwrap();
        d.insert_sent(idn, "c2", Some("dice.epix"), &[], "mud.epix", "Work", "ship the release", 6000)
            .unwrap();
        let hits = d.search(idn, "pizza", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["conv_id"].as_str(), Some("c1"));
        let hits2 = d.search(idn, "release", 10).unwrap();
        assert_eq!(hits2.len(), 1);
        assert_eq!(hits2[0]["conv_id"].as_str(), Some("c2"));
    }

    #[test]
    fn mark_read_clears_unread_and_delete_removes_thread() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        let sid = d
            .create_session(NewSession {
                identity_id: idn,
                conv_id: "cx",
                peer_xid: Some("p.epix"),
                peer_ik: "ik-p",
                peer_auth: None,
                role: "resp",
                ratchet: b"r",
                established_ms: 1,
                recv_tags: &[],
            })
            .unwrap();
        d.commit_inbound(&InboundCommit {
            identity_id: idn,
            session_id: Some(sid),
            new_session: None,
            conv_id: "cx".into(),
            peer_xid: Some("p.epix".into()),
            sender_xid: Some("p.epix".into()),
            members: vec![],
            subject: "s".into(),
            body: "b".into(),
            sent_ms: 10,
            received_ms: 11,
            epoch: 1,
            sign_h: vec![3u8; 16],
            ratchet_after: b"r2".to_vec(),
            consumed_tag: vec![],
            new_tags: vec![],
        })
        .unwrap();
        assert_eq!(d.unread_count(idn).unwrap(), 1);
        d.mark_read(idn, "cx", true).unwrap();
        assert_eq!(d.unread_count(idn).unwrap(), 0);
        d.delete_conversation(idn, "cx").unwrap();
        assert!(d.threads(idn, "all", 0, 10).unwrap().is_empty());
        assert!(d.messages(idn, "cx").unwrap().is_empty());
    }

    #[test]
    fn read_and_conversation_flag_updates_roll_back_as_units() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        d.insert_sent(idn, "tx", None, &[], "mud.epix", "s", "b", 1)
            .unwrap();
        d.database()
            .execute_batch(
                "UPDATE msg SET read=0 WHERE conv_id='tx';
                 UPDATE thread SET unread=1 WHERE conv_id='tx';
                 CREATE TRIGGER fail_thread_read BEFORE UPDATE OF unread ON thread
                 BEGIN SELECT RAISE(FAIL, 'injected thread failure'); END;",
            )
            .unwrap();
        assert!(d.mark_read(idn, "tx", true).is_err());
        {
            let conn = d.database().conn().unwrap();
            let read: i64 = conn
                .query_row("SELECT read FROM msg WHERE conv_id='tx'", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(read, 0, "the earlier message update rolled back");
        }
        d.database()
            .execute_batch(
                "DROP TRIGGER fail_thread_read;
                 CREATE TRIGGER fail_archive BEFORE UPDATE OF archived ON thread
                 WHEN new.archived=1
                 BEGIN SELECT RAISE(FAIL, 'injected archive failure'); END;",
            )
            .unwrap();
        assert!(d.set_conv_state(idn, "tx", Some(true), Some(true)).is_err());
        let conn = d.database().conn().unwrap();
        let (starred, archived): (i64, i64) = conn
            .query_row(
                "SELECT starred, archived FROM thread WHERE conv_id='tx'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((starred, archived), (0, 0));
    }

    #[test]
    fn set_conv_state_persists_star_and_archive_into_folders() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        let sid = d
            .create_session(NewSession {
                identity_id: idn,
                conv_id: "cs",
                peer_xid: Some("p.epix"),
                peer_ik: "ik-p",
                peer_auth: None,
                role: "resp",
                ratchet: b"r",
                established_ms: 1,
                recv_tags: &[],
            })
            .unwrap();
        d.commit_inbound(&InboundCommit {
            identity_id: idn,
            session_id: Some(sid),
            new_session: None,
            conv_id: "cs".into(),
            peer_xid: Some("p.epix".into()),
            sender_xid: Some("p.epix".into()),
            members: vec![],
            subject: "s".into(),
            body: "b".into(),
            sent_ms: 10,
            received_ms: 11,
            epoch: 1,
            sign_h: vec![7u8; 16],
            ratchet_after: b"r2".to_vec(),
            consumed_tag: vec![],
            new_tags: vec![],
        })
        .unwrap();
        // Starts in the default (non-archived) folder, not starred/archived.
        assert_eq!(d.threads(idn, "all", 0, 10).unwrap().len(), 1);
        assert!(d.threads(idn, "starred", 0, 10).unwrap().is_empty());

        // Star it: shows in the starred folder, still in "all".
        d.set_conv_state(idn, "cs", Some(true), None).unwrap();
        assert_eq!(d.threads(idn, "starred", 0, 10).unwrap().len(), 1);
        assert_eq!(d.threads(idn, "all", 0, 10).unwrap().len(), 1);

        // Archive it: leaves "all", enters "archived", drops out of "starred"
        // (starred filter excludes archived).
        d.set_conv_state(idn, "cs", None, Some(true)).unwrap();
        assert!(d.threads(idn, "all", 0, 10).unwrap().is_empty());
        assert_eq!(d.threads(idn, "archived", 0, 10).unwrap().len(), 1);
        assert!(d.threads(idn, "starred", 0, 10).unwrap().is_empty());

        // A None field must not clobber the other flag: unarchive, star stays.
        d.set_conv_state(idn, "cs", None, Some(false)).unwrap();
        assert_eq!(d.threads(idn, "all", 0, 10).unwrap().len(), 1);
        assert_eq!(d.threads(idn, "starred", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn at_rest_encryption_seals_content_but_reads_and_search_still_work() {
        let d = ChannelDb::memory_encrypted([3u8; 32]).unwrap();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        d.insert_sent(idn, "cx", Some("p.epix"), &[], "mud.epix", "Secret Subj", "TOP SECRET ZQ9", 100)
            .unwrap();

        // Reads decrypt transparently.
        let msgs = d.messages(idn, "cx").unwrap();
        assert_eq!(msgs[0]["body"].as_str(), Some("TOP SECRET ZQ9"));
        assert_eq!(msgs[0]["subject"].as_str(), Some("Secret Subj"));
        let threads = d.threads(idn, "all", 0, 10).unwrap();
        assert_eq!(threads[0]["subject"].as_str(), Some("Secret Subj"));
        assert!(threads[0]["snippet"].as_str().unwrap().contains("TOP SECRET"));
        // Search works via decrypt-then-scan.
        assert_eq!(d.search(idn, "secret", 10).unwrap().len(), 1);
        assert_eq!(d.search(idn, "nomatch", 10).unwrap().len(), 0);

        // The RAW columns hold ciphertext, never the plaintext, and enc=1.
        let conn = d.database().conn().unwrap();
        let raw_body: String =
            conn.query_row("SELECT body FROM msg WHERE identity_id=?", [idn], |r| r.get(0)).unwrap();
        assert_ne!(raw_body, "TOP SECRET ZQ9");
        assert!(!raw_body.contains("SECRET"));
        let raw_snip: String =
            conn.query_row("SELECT snippet FROM thread WHERE identity_id=?", [idn], |r| r.get(0)).unwrap();
        assert!(!raw_snip.contains("SECRET"), "thread preview is sealed too");
        let enc: i64 =
            conn.query_row("SELECT enc FROM msg WHERE identity_id=?", [idn], |r| r.get(0)).unwrap();
        assert_eq!(enc, 1);
    }

    #[test]
    fn at_rest_encryption_seals_the_ratchet_blob() {
        let d = ChannelDb::memory_encrypted([4u8; 32]).unwrap();
        let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let sid = d
            .create_session(NewSession {
                identity_id: idn,
                conv_id: "cv",
                peer_xid: Some("b.epix"),
                peer_ik: "ik-b",
                peer_auth: None,
                role: "init",
                ratchet: b"RATCHET-STATE-XYZ",
                established_ms: 1,
                recv_tags: &[],
            })
            .unwrap();
        assert_eq!(d.session_ratchet(sid).unwrap(), b"RATCHET-STATE-XYZ");

        // The raw ratchet column is sealed. Scoped so the single in-memory
        // connection is released before the next db method (pool size 1).
        {
            let conn = d.database().conn().unwrap();
            let raw: Vec<u8> = conn
                .query_row("SELECT ratchet FROM session WHERE session_id=?", [sid], |r| r.get(0))
                .unwrap();
            assert_ne!(raw.as_slice(), b"RATCHET-STATE-XYZ".as_slice());
            assert!(!raw.windows(7).any(|w| w == b"RATCHET"));
        }

        // An advance re-seals and still decrypts, and session_for_tag decrypts too.
        d.update_session_ratchet(sid, b"RATCHET-STATE-2").unwrap();
        assert_eq!(d.session_ratchet(sid).unwrap(), b"RATCHET-STATE-2");
        d.create_session(NewSession {
            identity_id: idn,
            conv_id: "cv",
            peer_xid: Some("b.epix"),
            peer_ik: "ik-b",
            peer_auth: None,
            role: "init",
            ratchet: b"RS3",
            established_ms: 1,
            recv_tags: &[(0, vec![7u8; 32])],
        })
        .unwrap();
        let sm = d.session_for_tag(&[7u8; 32]).unwrap().unwrap();
        assert_eq!(sm.ratchet, b"RS3");
    }

    #[test]
    fn encrypted_database_refuses_reopen_without_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        {
            let d = ChannelDb::open_encrypted(&path, [5u8; 32]).unwrap();
            let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
            d.insert_sent(
                idn,
                "cv",
                Some("b.epix"),
                &[],
                "a.epix",
                "encrypted",
                "must not look empty",
                1,
            )
            .unwrap();
            d.create_session(NewSession {
                identity_id: idn,
                conv_id: "cv",
                peer_xid: Some("b.epix"),
                peer_ik: "ik-b",
                peer_auth: Some("epix1b"),
                role: "init",
                ratchet: b"encrypted-ratchet",
                established_ms: 1,
                recv_tags: &[],
            })
            .unwrap();
        }

        let err = ChannelDb::open(&path)
            .err()
            .expect("disabled encryption must fail closed");
        assert!(
            err.to_string().contains("channel_encrypt_at_rest"),
            "the startup error explains how to recover: {err}"
        );
        assert!(
            ChannelDb::open_encrypted(&path, [5u8; 32]).is_ok(),
            "the original encryption setting still opens the database"
        );
        assert!(
            ChannelDb::open_encrypted(&path, [6u8; 32]).is_err(),
            "a wrong configured key fails during startup, not on the first read"
        );

        // A thread can outlive all messages and sessions. Its encrypted subject
        // and snippet alone must still prevent a keyless or wrong-key reopen.
        let thread_only = dir.path().join("nested/private/thread-only.db");
        {
            let d = ChannelDb::open_encrypted(&thread_only, [7u8; 32]).unwrap();
            let idn = d.upsert_identity("c.epix", "epix1c", 0, None).unwrap();
            d.insert_sent(idn, "thread", None, &[], "c.epix", "sealed", "preview", 1)
                .unwrap();
            let conn = d.database().conn().unwrap();
            conn.execute("DELETE FROM msg", []).unwrap();
            conn.execute("DELETE FROM session", []).unwrap();
        }
        assert!(ChannelDb::open(&thread_only).is_err());
        assert!(ChannelDb::open_encrypted(&thread_only, [8u8; 32]).is_err());
        assert!(ChannelDb::open_encrypted(&thread_only, [7u8; 32]).is_ok());
    }

    #[test]
    fn enabling_encryption_migrates_every_plaintext_sensitive_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/channels.db");
        let idn;
        let sid;
        let recovery_key = "outbox-recovery-secret".to_string();
        {
            let d = ChannelDb::open(&path).unwrap();
            idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
            d.insert_sent(
                idn,
                "cv",
                Some("b.epix"),
                &[],
                "a.epix",
                "plaintext-subject",
                "plaintext-body",
                1,
            )
            .unwrap();
            sid = d
                .create_session(NewSession {
                    identity_id: idn,
                    conv_id: "cv",
                    peer_xid: Some("b.epix"),
                    peer_ik: "ik-b",
                    peer_auth: Some("epix1b"),
                    role: "init",
                    ratchet: b"plaintext-ratchet",
                    established_ms: 1,
                    recv_tags: &[],
                })
                .unwrap();
            d.commit_outbound(&OutboundCommit {
                sessions: Vec::new(),
                record: serde_json::json!({"v": 1}),
                shard_path: "pool/1/0.json".into(),
                created_ms: 1,
                next_attempt_ms: 1,
                recovery: OutboundRecovery {
                    author_private_key: recovery_key.clone(),
                    rln: Some(RlnReservation {
                        first_unit: 3,
                        weight: 2,
                        root: Some([9u8; 32]),
                    }),
                },
                sent: None,
            })
            .unwrap();
        }

        let d = ChannelDb::open_encrypted(&path, [19u8; 32]).unwrap();
        assert_eq!(d.session_ratchet(sid).unwrap(), b"plaintext-ratchet");
        assert_eq!(d.messages(idn, "cv").unwrap()[0]["body"], "plaintext-body");
        let pending = d.pending_outbound(1).unwrap().remove(0);
        assert_eq!(pending.recovery.author_private_key, recovery_key);
        assert_eq!(pending.recovery.rln.unwrap().root, Some([9u8; 32]));
        let conn = d.database().conn().unwrap();
        let (msg_subject, msg_body, msg_enc): (String, String, i64) = conn
            .query_row("SELECT subject, body, enc FROM msg LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        let (thread_subject, thread_snippet, thread_enc): (String, String, i64) = conn
            .query_row(
                "SELECT subject, snippet, enc FROM thread LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let (ratchet, session_enc): (Vec<u8>, i64) = conn
            .query_row("SELECT ratchet, enc FROM session LIMIT 1", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!((msg_enc, thread_enc, session_enc), (1, 1, 1));
        for stored in [msg_subject, msg_body, thread_subject, thread_snippet] {
            assert!(!stored.contains("plaintext"));
        }
        assert!(!ratchet.windows(9).any(|window| window == b"plaintext"));
        let (author_key, key_enc): (String, i64) = conn
            .query_row(
                "SELECT author_key, key_enc FROM outbound LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(key_enc, 1);
        assert!(!author_key.contains("outbox-recovery-secret"));
    }

    #[test]
    fn encrypted_open_validates_later_rows_not_only_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        {
            let d = ChannelDb::open_encrypted(&path, [20u8; 32]).unwrap();
            let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
            for (conv, ik) in [("one", "ik-one"), ("two", "ik-two")] {
                d.create_session(NewSession {
                    identity_id: idn,
                    conv_id: conv,
                    peer_xid: Some("b.epix"),
                    peer_ik: ik,
                    peer_auth: Some("epix1b"),
                    role: "init",
                    ratchet: conv.as_bytes(),
                    established_ms: 1,
                    recv_tags: &[],
                })
                .unwrap();
            }
            let conn = d.database().conn().unwrap();
            conn.execute(
                "UPDATE session SET ratchet=?1, enc=1 WHERE conv_id='two'",
                rusqlite::params![vec![7u8; 48]],
            )
            .unwrap();
        }
        assert!(
            ChannelDb::open_encrypted(&path, [20u8; 32]).is_err(),
            "a corrupt later encrypted row must fail startup"
        );
    }

    #[test]
    fn v4_migration_is_idempotent_after_column_was_already_added() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        {
            let d = ChannelDb::open(&path).unwrap();
            d.database()
                .execute_batch("PRAGMA user_version = 3")
                .unwrap();
        }
        let d = ChannelDb::open(&path).unwrap();
        assert_eq!(d.user_version().unwrap(), 6);
    }

    #[cfg(unix)]
    #[test]
    fn file_database_uses_private_unix_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("profile/private");
        let path = private.join("channels.db");
        let d = ChannelDb::open(&path).unwrap();
        let _conn = d.database().conn().unwrap();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for suffix in ["-wal", "-shm"] {
            let sidecar = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            if sidecar.exists() {
                assert_eq!(
                    std::fs::metadata(sidecar).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn clean_nested_open_and_revocation_tombstones_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh/profile/private/channels.db");
        {
            let d = ChannelDb::open(&path).expect("open creates missing private directories");
            d.remember_revoked_device("peer.epix", Some("epix1old"), "old-ik", 11)
                .unwrap();
        }
        let d = ChannelDb::open(&path).unwrap();
        assert!(d
            .is_device_revoked("peer.epix", Some("epix1old"), "new-ik")
            .unwrap());
        assert!(d
            .is_device_revoked("peer.epix", Some("epix1new"), "old-ik")
            .unwrap());
        assert!(
            !d.is_device_revoked("peer.epix", Some("epix1sibling"), "sibling-ik")
                .unwrap(),
            "a sibling or newly linked device remains usable"
        );
    }

    #[test]
    fn finalized_revocation_snapshot_is_persisted_atomically() {
        let d = db();
        d.database()
            .execute_batch(
                "CREATE TRIGGER fail_second_revocation BEFORE INSERT ON revoked_device
                 WHEN new.peer_ik='second'
                 BEGIN SELECT RAISE(FAIL, 'injected tombstone failure'); END;",
            )
            .unwrap();
        let snapshot = vec![
            RevokedDevice {
                xid: "peer.epix".into(),
                auth_address: "epix1one".into(),
                peer_ik: "first".into(),
            },
            RevokedDevice {
                xid: "peer.epix".into(),
                auth_address: "epix1two".into(),
                peer_ik: "second".into(),
            },
        ];
        assert!(d.remember_revoked_devices(&snapshot, 1).is_err());
        assert!(
            d.revoked_devices().unwrap().is_empty(),
            "an insertion failure rolls back the entire finalized snapshot"
        );
    }

    #[test]
    fn first_contact_session_message_and_processed_marker_roll_back_together() {
        let d = db();
        let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        d.database()
            .execute_batch(
                "CREATE TRIGGER fail_first_contact BEFORE INSERT ON msg
                 BEGIN SELECT RAISE(FAIL, 'injected message failure'); END;",
            )
            .unwrap();
        let sign_h = vec![42u8; 16];
        let commit = InboundCommit {
            identity_id: idn,
            session_id: None,
            new_session: Some(epix_envelope::OutboundSession {
                session_id: None,
                identity_id: idn,
                conv_id: "new-conv".into(),
                peer_xid: Some("b.epix".into()),
                peer_ik: "b-ik".into(),
                peer_auth: Some("epix1b".into()),
                role: "resp".into(),
                ratchet_before: None,
                ratchet_after: b"after".to_vec(),
                established_ms: 1,
                recv_tags: vec![(0, vec![1u8; 32])],
            }),
            conv_id: "new-conv".into(),
            peer_xid: Some("b.epix".into()),
            sender_xid: Some("b.epix".into()),
            members: Vec::new(),
            subject: "subject".into(),
            body: "body".into(),
            sent_ms: 1,
            received_ms: 2,
            epoch: 0,
            sign_h: sign_h.clone(),
            ratchet_after: b"after".to_vec(),
            consumed_tag: Vec::new(),
            new_tags: Vec::new(),
        };
        assert!(d.commit_inbound(&commit).is_err());
        assert!(d
            .session_id_for_leg(idn, "new-conv", "b-ik")
            .unwrap()
            .is_none());
        assert!(!d.is_processed(&sign_h, idn).unwrap());
        assert!(d.threads(idn, "all", 0, 10).unwrap().is_empty());
    }

    #[test]
    fn commit_seams_recheck_durable_revocations() {
        let d = db();
        let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let sid = d
            .create_session(NewSession {
                identity_id: idn,
                conv_id: "cv",
                peer_xid: Some("b"),
                peer_ik: "b-ik",
                peer_auth: Some("epix1b"),
                role: "init",
                ratchet: b"before",
                established_ms: 1,
                recv_tags: &[(0, vec![9u8; 32])],
            })
            .unwrap();
        d.remember_revoked_device("b.epix", Some("epix1b"), "b-ik", 2)
            .unwrap();
        let inbound = InboundCommit {
            identity_id: idn,
            session_id: Some(sid),
            new_session: None,
            conv_id: "cv".into(),
            peer_xid: Some("b.epix".into()),
            sender_xid: Some("b.epix".into()),
            members: Vec::new(),
            subject: "blocked".into(),
            body: "blocked".into(),
            sent_ms: 3,
            received_ms: 3,
            epoch: 0,
            sign_h: vec![3u8; 16],
            ratchet_after: b"after".to_vec(),
            consumed_tag: vec![9u8; 32],
            new_tags: Vec::new(),
        };
        assert!(d.commit_inbound(&inbound).is_err());
        assert_eq!(d.session_ratchet(sid).unwrap(), b"before");

        d.remember_revoked_device("a.epix", Some("epix1a"), "", 4)
            .unwrap();
        let outbound = OutboundCommit {
            sessions: vec![epix_envelope::OutboundSession {
                session_id: Some(sid),
                identity_id: idn,
                conv_id: "cv".into(),
                peer_xid: Some("b.epix".into()),
                peer_ik: "b-ik".into(),
                peer_auth: Some("epix1b".into()),
                role: "init".into(),
                ratchet_before: Some(b"before".to_vec()),
                ratchet_after: b"out".to_vec(),
                established_ms: 1,
                recv_tags: Vec::new(),
            }],
            record: serde_json::json!({"sign":"blocked"}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 4,
            next_attempt_ms: 4,
            recovery: recovery(),
            sent: None,
        };
        assert!(d.commit_outbound(&outbound).is_err());
        assert!(d.pending_outbound(10).unwrap().is_empty());
    }

    #[test]
    fn revoked_local_slot_is_discarded_without_blocking_active_slot() {
        let d = db();
        let revoked = d
            .upsert_identity("mine.epix", "epix1revoked", 0, None)
            .unwrap();
        let active = d
            .upsert_identity("mine.epix", "epix1active", 1, None)
            .unwrap();
        let make_commit = |identity_id: i64, suffix: &str| InboundCommit {
            identity_id,
            session_id: None,
            new_session: Some(epix_envelope::OutboundSession {
                session_id: None,
                identity_id,
                conv_id: format!("conv-{suffix}"),
                peer_xid: Some("peer.epix".into()),
                peer_ik: format!("peer-ik-{suffix}"),
                peer_auth: Some("epix1peer".into()),
                role: "resp".into(),
                ratchet_before: None,
                ratchet_after: b"after".to_vec(),
                established_ms: 1,
                recv_tags: Vec::new(),
            }),
            conv_id: format!("conv-{suffix}"),
            peer_xid: Some("peer.epix".into()),
            sender_xid: Some("peer.epix".into()),
            members: Vec::new(),
            subject: "subject".into(),
            body: "body".into(),
            sent_ms: 1,
            received_ms: 2,
            epoch: 0,
            sign_h: vec![77u8; 16],
            ratchet_after: b"after".to_vec(),
            consumed_tag: Vec::new(),
            new_tags: Vec::new(),
        };
        d.remember_revoked_device("mine.epix", Some("epix1revoked"), "", 3)
            .unwrap();

        assert!(d
            .commit_inbound(&make_commit(revoked, "revoked"))
            .unwrap()
            .is_none());
        assert!(d.is_processed(&[77u8; 16], revoked).unwrap());
        assert!(d.threads(revoked, "all", 0, 10).unwrap().is_empty());

        assert!(d
            .commit_inbound(&make_commit(active, "active"))
            .unwrap()
            .is_some());
        assert!(d.is_processed(&[77u8; 16], active).unwrap());
        assert_eq!(d.threads(active, "all", 0, 10).unwrap().len(), 1);
    }

    #[test]
    fn outbound_commit_rolls_back_session_and_record_on_mid_tx_failure() {
        let d = db();
        let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let session = |ratchet: &[u8]| epix_envelope::OutboundSession {
            session_id: None,
            identity_id: idn,
            conv_id: "same-conv".into(),
            peer_xid: Some("b.epix".into()),
            peer_ik: "same-device-key".into(),
            peer_auth: Some("epix1b".into()),
            role: "init".into(),
            ratchet_before: None,
            ratchet_after: ratchet.to_vec(),
            established_ms: 10,
            recv_tags: Vec::new(),
        };
        let commit = OutboundCommit {
            // The second insert violates the per-leg UNIQUE constraint after
            // the first one has executed. This injects a mid-transaction error.
            sessions: vec![session(b"state-1"), session(b"state-2")],
            record: serde_json::json!({"sign": "exact-record"}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 10,
            next_attempt_ms: 20,
            recovery: recovery(),
            sent: None,
        };
        assert!(d.commit_outbound(&commit).is_err());
        assert!(
            d.session_id_for_leg(idn, "same-conv", "same-device-key")
                .unwrap()
                .is_none(),
            "the first session insert rolled back"
        );
        assert!(
            d.pending_outbound(10).unwrap().is_empty(),
            "no orphan outbox row"
        );
    }

    #[test]
    fn later_chunk_failure_rolls_back_the_entire_logical_send() {
        let d = db();
        let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let chunk = |peer_ik: &str, own: bool| OutboundCommit {
            sessions: vec![epix_envelope::OutboundSession {
                session_id: None,
                identity_id: idn,
                conv_id: "group".into(),
                peer_xid: Some("b.epix".into()),
                peer_ik: peer_ik.into(),
                peer_auth: Some("epix1b".into()),
                role: "init".into(),
                ratchet_before: None,
                ratchet_after: b"after".to_vec(),
                established_ms: 1,
                recv_tags: Vec::new(),
            }],
            record: serde_json::json!({"sign": peer_ik}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 1,
            next_attempt_ms: 1,
            recovery: recovery(),
            sent: own.then(|| epix_envelope::OutboundMessage {
                identity_id: idn,
                conv_id: "group".into(),
                peer_xid: None,
                members: vec!["a.epix".into(), "b.epix".into()],
                sender_xid: "a.epix".into(),
                subject: "subject".into(),
                body: "body".into(),
                sent_ms: 1,
            }),
        };
        assert!(d
            .commit_outbound_batch(&[chunk("same-device", true), chunk("same-device", false)])
            .is_err());
        assert!(d
            .session_id_for_leg(idn, "group", "same-device")
            .unwrap()
            .is_none());
        assert!(d.pending_outbound(10).unwrap().is_empty());
        assert!(d.messages(idn, "group").unwrap().is_empty());
    }

    #[test]
    fn outbound_batch_rejects_duplicate_existing_leg_and_stale_ratchet() {
        let d = db();
        let idn = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let sid = d
            .create_session(NewSession {
                identity_id: idn,
                conv_id: "cv",
                peer_xid: Some("b.epix"),
                peer_ik: "ik-b",
                peer_auth: Some("epix1b"),
                role: "init",
                ratchet: b"before",
                established_ms: 1,
                recv_tags: &[],
            })
            .unwrap();
        let commit = |suffix: &str, before: &[u8]| OutboundCommit {
            sessions: vec![epix_envelope::OutboundSession {
                session_id: Some(sid),
                identity_id: idn,
                conv_id: "cv".into(),
                peer_xid: Some("b.epix".into()),
                peer_ik: "ik-b".into(),
                peer_auth: Some("epix1b".into()),
                role: "init".into(),
                ratchet_before: Some(before.to_vec()),
                ratchet_after: format!("after-{suffix}").into_bytes(),
                established_ms: 1,
                recv_tags: Vec::new(),
            }],
            record: serde_json::json!({"sign": suffix}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 1,
            next_attempt_ms: 1,
            recovery: recovery(),
            sent: None,
        };
        assert!(d
            .commit_outbound_batch(&[commit("one", b"before"), commit("two", b"before")])
            .is_err());
        assert_eq!(d.session_ratchet(sid).unwrap(), b"before");
        assert!(d.pending_outbound(10).unwrap().is_empty());

        assert!(d.commit_outbound(&commit("stale", b"wrong-state")).is_err());
        assert_eq!(d.session_ratchet(sid).unwrap(), b"before");
        assert!(d.pending_outbound(10).unwrap().is_empty());
    }

    #[test]
    fn outbox_readiness_blocks_same_conversation_but_not_an_unrelated_one() {
        let d = db();
        let identity_id = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let commit = |conv: &str, sign: &str, next_attempt_ms| OutboundCommit {
            sessions: Vec::new(),
            record: serde_json::json!({"sign": sign}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 1,
            next_attempt_ms,
            recovery: recovery(),
            sent: Some(epix_envelope::OutboundMessage {
                identity_id,
                conv_id: conv.into(),
                peer_xid: None,
                members: Vec::new(),
                sender_xid: "a.epix".into(),
                subject: sign.into(),
                body: sign.into(),
                sent_ms: 1,
            }),
        };
        let (first, _) = d.commit_outbound(&commit("conv-a", "first", 200)).unwrap();
        let (same_conv, _) = d.commit_outbound(&commit("conv-a", "second", 100)).unwrap();
        let (other_conv, _) = d.commit_outbound(&commit("conv-b", "third", 100)).unwrap();
        let due = d.due_outbound_prefix(150, 10).unwrap();
        assert_eq!(
            due.iter().map(|row| row.outbox_id).collect::<Vec<_>>(),
            vec![other_conv],
            "a backed-off conversation does not block an unrelated one"
        );

        d.reschedule_outbound(first, 50).unwrap();
        let due = d.due_outbound_prefix(150, 10).unwrap();
        assert_eq!(
            due.iter().map(|row| row.outbox_id).collect::<Vec<_>>(),
            vec![first, other_conv],
            "the second same-conversation row waits until the first is acknowledged"
        );
        d.ack_outbound(first).unwrap();
        assert_eq!(
            d.due_outbound_prefix(150, 10).unwrap()[0].outbox_id,
            same_conv
        );
    }

    #[test]
    fn due_outbox_limit_prioritizes_the_oldest_deadline() {
        let d = db();
        let identity_id = d.upsert_identity("a.epix", "epix1a", 0, None).unwrap();
        let commit = |conv: String, next_attempt_ms| OutboundCommit {
            sessions: Vec::new(),
            record: serde_json::json!({"sign": conv}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 1,
            next_attempt_ms,
            recovery: recovery(),
            sent: Some(epix_envelope::OutboundMessage {
                identity_id,
                conv_id: conv.clone(),
                peer_xid: None,
                members: Vec::new(),
                sender_xid: "a.epix".into(),
                subject: conv.clone(),
                body: conv,
                sent_ms: 1,
            }),
        };

        let mut older = Vec::new();
        for index in 0..128 {
            let (outbox_id, _) = d
                .commit_outbound(&commit(format!("older-{index}"), 100))
                .unwrap();
            older.push(outbox_id);
        }
        let (newer, _) = d.commit_outbound(&commit("newer".into(), 1)).unwrap();

        let due = d.due_outbound_prefix(100, 128).unwrap();
        assert_eq!(due.len(), 128);
        assert_eq!(due[0].outbox_id, newer);
        assert!(due.iter().any(|row| row.outbox_id == newer));
        assert!(!due.iter().any(|row| row.outbox_id == older[127]));
    }

    #[test]
    fn v5_pending_row_is_a_finite_universal_migration_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        {
            let raw = epix_db::Database::open(&path).unwrap();
            raw.execute_batch(SCHEMA).unwrap();
            raw.execute_batch(
                "INSERT INTO outbound
                    (record_json, shard_path, created_ms, next_attempt_ms,
                     author_key, key_enc)
                 VALUES ('{\"sign\":\"legacy\"}', 'pool/w0/00.json', 1, 200, '', 0);
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }
        let d = ChannelDb::open(&path).unwrap();
        let legacy = d.pending_outbound(1).unwrap()[0].outbox_id;
        let (newer, _) = d
            .commit_outbound(&OutboundCommit {
                sessions: Vec::new(),
                record: serde_json::json!({"sign": "new"}),
                shard_path: "pool/w0/00.json".into(),
                created_ms: 2,
                next_attempt_ms: 100,
                recovery: recovery(),
                sent: None,
            })
            .unwrap();
        assert!(d.due_outbound_prefix(150, 10).unwrap().is_empty());
        d.reschedule_outbound(legacy, 50).unwrap();
        assert_eq!(d.due_outbound_prefix(150, 10).unwrap()[0].outbox_id, legacy);
        d.ack_outbound(legacy).unwrap();
        assert_eq!(d.due_outbound_prefix(150, 10).unwrap()[0].outbox_id, newer);
    }

    #[test]
    fn route_cleanup_paths_survive_repeated_migration_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        let d = ChannelDb::open(&path).unwrap();
        let recovery = recovery();
        let (outbox_id, _) = d
            .commit_outbound(&OutboundCommit {
                sessions: Vec::new(),
                record: serde_json::json!({"sign": "one"}),
                shard_path: "pool-a/w0/00.json".into(),
                created_ms: 1,
                next_attempt_ms: 1,
                recovery: recovery.clone(),
                sent: None,
            })
            .unwrap();
        d.replace_outbound_record(
            outbox_id,
            &serde_json::json!({"sign": "two"}),
            "pool-b/w0/00.json",
            &recovery,
        )
        .unwrap();
        d.replace_outbound_record(
            outbox_id,
            &serde_json::json!({"sign": "three"}),
            "pool-c/w0/00.json",
            &recovery,
        )
        .unwrap();
        drop(d);

        let reopened = ChannelDb::open(&path).unwrap();
        assert_eq!(
            reopened.outbound_route_cleanup(outbox_id).unwrap(),
            vec!["pool-a/w0/00.json", "pool-b/w0/00.json"]
        );
        reopened.ack_outbound(outbox_id).unwrap();
        assert!(reopened
            .outbound_route_cleanup(outbox_id)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn migrates_v1_db_preserving_data_and_gaining_per_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        // Seed a v1-shaped db: record-wide `msg.sign_h UNIQUE` + `processed(sign_h PK)`,
        // one indexed message, user_version 0.
        {
            let raw = epix_db::Database::open(&path).unwrap();
            raw.execute_batch(
                "CREATE TABLE identity (identity_id INTEGER PRIMARY KEY AUTOINCREMENT, xid TEXT,
                     auth_address TEXT, derive_index INTEGER, bundle_json TEXT, scan_cursor INTEGER DEFAULT 0);
                 CREATE TABLE thread (thread_id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id INTEGER,
                     conv_id TEXT, peer_xid TEXT, members TEXT, subject TEXT, snippet TEXT,
                     last_ms INTEGER DEFAULT 0, msg_count INTEGER DEFAULT 0, unread INTEGER DEFAULT 0,
                     starred INTEGER DEFAULT 0, archived INTEGER DEFAULT 0, enc INTEGER DEFAULT 0);
                 CREATE TABLE msg (msg_id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id INTEGER,
                     thread_id INTEGER, conv_id TEXT, dir TEXT, sender_xid TEXT, subject TEXT, body TEXT,
                     enc INTEGER DEFAULT 0, sent_ms INTEGER DEFAULT 0, received_ms INTEGER DEFAULT 0,
                     epoch INTEGER DEFAULT 0, read INTEGER DEFAULT 0, sign_h BLOB UNIQUE);
                 CREATE TABLE processed (sign_h BLOB PRIMARY KEY NOT NULL);
                 INSERT INTO identity (identity_id, xid, auth_address, derive_index) VALUES (1,'mud.epix','epix1mud',0);
                 INSERT INTO identity (identity_id, xid, auth_address, derive_index) VALUES (2,'work.epix','epix1work',0);
                 INSERT INTO thread (thread_id, identity_id, conv_id) VALUES (1,1,'abcd');
                 INSERT INTO msg (identity_id, thread_id, conv_id, dir, subject, body, sign_h)
                     VALUES (1,1,'abcd','in','Hi','v1 body keep', X'0102');
                 INSERT INTO processed (sign_h) VALUES (X'0102');
                 PRAGMA user_version = 0;",
            )
            .unwrap();
        }

        // Opening via ChannelDb runs the v1→v2→v3 migrations.
        let d = ChannelDb::open(&path).unwrap();
        assert_eq!(d.user_version().unwrap(), 6, "migrated to latest schema");

        // The v1 message survived the msg-table rebuild, FTS included.
        let msgs = d.messages(1, "abcd").unwrap();
        assert_eq!(msgs.len(), 1, "v1 message preserved through migration");
        assert_eq!(msgs[0]["body"].as_str(), Some("v1 body keep"));
        assert_eq!(d.search(1, "keep", 10).unwrap().len(), 1, "FTS rebuilt for the migrated row");

        // Per-identity now: the SAME sign_h under a DIFFERENT identity is allowed
        // (was impossible under v1's record-wide UNIQUE), while a same-identity
        // duplicate is still rejected.
        let conn = d.db.conn().unwrap();
        conn.execute(
            "INSERT INTO msg (identity_id, thread_id, conv_id, dir, sign_h) VALUES (2, 1, 'abcd', 'in', X'0102')",
            [],
        )
        .expect("same sign_h under a different identity is allowed after v2");
        assert!(
            conn.execute(
                "INSERT INTO msg (identity_id, thread_id, conv_id, dir, sign_h) VALUES (1, 1, 'abcd', 'in', X'0102')",
                [],
            )
            .is_err(),
            "a same-(sign_h, identity) duplicate is still rejected"
        );
    }
}
