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
use epix_envelope::{EnvelopeStore, InboundCommit, SessionMatch};
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
    role          TEXT NOT NULL,
    ratchet       BLOB NOT NULL,
    enc           INTEGER NOT NULL DEFAULT 0,
    established_ms INTEGER NOT NULL,
    -- One pairwise session PER peer in a (possibly group) conversation.
    UNIQUE(identity_id, conv_id, peer_xid));

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
    sign_h        BLOB UNIQUE);            -- 16B blake3 prefix of the pool sig (null for own sent)
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

CREATE TABLE IF NOT EXISTS processed (sign_h BLOB PRIMARY KEY NOT NULL);

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

impl ChannelDb {
    /// Open (creating if needed) the file-backed index, plaintext at rest.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::open_inner(Database::open(path)?, None)
    }

    /// Open the file-backed index with at-rest encryption under `key`.
    pub fn open_encrypted(path: impl AsRef<std::path::Path>, key: [u8; 32]) -> Result<Self> {
        Self::open_inner(Database::open(path)?, Some(key))
    }

    /// An in-memory index (tests, and nodes with no data dir).
    pub fn memory() -> Result<Self> {
        Self::open_inner(Database::open_in_memory()?, None)
    }

    /// An in-memory index with at-rest encryption (tests).
    pub fn memory_encrypted(key: [u8; 32]) -> Result<Self> {
        Self::open_inner(Database::open_in_memory()?, Some(key))
    }

    fn open_inner(db: Database, enc_key: Option<[u8; 32]>) -> Result<Self> {
        let me = Self { db, enc_key };
        me.db.execute_batch(SCHEMA)?;
        Ok(me)
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

    /// Stored text + enc flag → plaintext (best-effort; a decrypt failure yields "").
    fn dec_text(&self, stored: &str, enc: i64) -> String {
        use base64::Engine as _;
        if enc == 0 {
            return stored.to_string();
        }
        let Some(k) = &self.enc_key else { return String::new() };
        base64::engine::general_purpose::STANDARD
            .decode(stored)
            .ok()
            .and_then(|b| crate::enc::open(k, &b))
            .and_then(|p| String::from_utf8(p).ok())
            .unwrap_or_default()
    }

    /// Plaintext blob → (stored blob, enc flag). Used for the ratchet session state.
    fn enc_blob(&self, b: &[u8]) -> (Vec<u8>, i64) {
        match &self.enc_key {
            Some(k) => (crate::enc::seal(k, b), 1),
            None => (b.to_vec(), 0),
        }
    }

    /// Stored blob + enc flag → plaintext blob.
    fn dec_blob(&self, b: &[u8], enc: i64) -> Vec<u8> {
        if enc == 0 {
            return b.to_vec();
        }
        match &self.enc_key {
            Some(k) => crate::enc::open(k, b).unwrap_or_default(),
            None => b.to_vec(),
        }
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
    fn decrypt_rows(&self, mut rows: Vec<Value>, fields: &[&str]) -> Vec<Value> {
        for row in rows.iter_mut() {
            let enc = row.get("enc").and_then(|v| v.as_i64()).unwrap_or(0);
            if enc != 0 {
                for f in fields {
                    if let Some(s) = row.get(*f).and_then(|v| v.as_str()) {
                        let dec = self.dec_text(s, enc);
                        row[*f] = Value::from(dec);
                    }
                }
            }
            if let Some(obj) = row.as_object_mut() {
                obj.remove("enc");
            }
        }
        rows
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
             FROM identity ORDER BY identity_id",
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

    // --- processed set ----------------------------------------------------

    /// Whether a pool signature (16-byte prefix) has already been indexed. BLOB
    /// columns must be bound with typed rusqlite params (the generic `Value`
    /// path would encode the bytes as a JSON array, never matching the BLOB).
    pub fn is_processed(&self, sign_h: &[u8]) -> Result<bool> {
        let conn = self.db.conn()?;
        let found = conn
            .query_row(
                "SELECT 1 FROM processed WHERE sign_h=?1",
                rusqlite::params![sign_h],
                |_| Ok(()),
            )
            .optional()
            .map_err(db_err)?;
        Ok(found.is_some())
    }

    /// Mark a pool signature processed (for records that matched no identity, so
    /// a plain rescan skips them; a new session triggers an explicit re-scan).
    pub fn mark_processed(&self, sign_h: &[u8]) -> Result<()> {
        let conn = self.db.conn()?;
        conn.execute(
            "INSERT OR IGNORE INTO processed (sign_h) VALUES (?1)",
            rusqlite::params![sign_h],
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
                "SELECT s.session_id, s.identity_id, s.conv_id, s.peer_xid, s.ratchet, e.n, s.enc
                 FROM expected_tag e JOIN session s ON s.session_id = e.session_id
                 WHERE e.tag = ?1",
                rusqlite::params![tag],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(db_err)?;
        Ok(row.map(|(session_id, identity_id, conv_id, peer_xid, ratchet, n, enc)| SessionMatch {
            session_id,
            identity_id,
            conv_id,
            peer_xid,
            ratchet: self.dec_blob(&ratchet, enc),
            n: n as u32,
        }))
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
        Ok(self.dec_blob(&blob, enc))
    }

    // --- session creation (for the send/first-contact paths) --------------

    /// Create a session and register its initial expected receive tags in one
    /// transaction. Returns the new `session_id`.
    pub fn create_session(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_xid: Option<&str>,
        role: &str,
        ratchet: &[u8],
        established_ms: i64,
        recv_tags: &[(u32, Vec<u8>)],
    ) -> Result<i64> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let (ratchet_stored, enc) = self.enc_blob(ratchet);
        tx.execute(
            "INSERT INTO session (identity_id, conv_id, peer_xid, role, ratchet, enc, established_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(identity_id, conv_id, peer_xid)
               DO UPDATE SET ratchet=excluded.ratchet, enc=excluded.enc",
            rusqlite::params![identity_id, conv_id, peer_xid, role, ratchet_stored, enc, established_ms],
        )
        .map_err(db_err)?;
        let session_id: i64 = tx
            .query_row(
                "SELECT session_id FROM session WHERE identity_id=? AND conv_id=? AND peer_xid IS ?",
                rusqlite::params![identity_id, conv_id, peer_xid],
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

    /// Look up an existing session id for one leg `(identity, conv, peer)`.
    pub fn session_id_for_leg(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_xid: &str,
    ) -> Result<Option<i64>> {
        let conn = self.db.conn()?;
        let r = conn
            .query_row(
                "SELECT session_id FROM session WHERE identity_id=? AND conv_id=? AND peer_xid=?",
                rusqlite::params![identity_id, conv_id, peer_xid],
                |row| row.get::<_, i64>(0),
            )
            .ok();
        Ok(r)
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

        // Idempotency: a duplicate signature is a no-op.
        if tx
            .query_row(
                "SELECT 1 FROM msg WHERE sign_h=?",
                rusqlite::params![c.sign_h],
                |_| Ok(()),
            )
            .is_ok()
        {
            tx.commit().map_err(db_err)?;
            return Ok(None);
        }

        let members_json =
            if c.members.is_empty() { None } else { serde_json::to_string(&c.members).ok() };
        let (subject_stored, body_stored, snippet_stored, enc) = self.seal_content(&c.subject, &c.body);
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
            rusqlite::params![ratchet_stored, renc, c.peer_xid, c.session_id],
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
                rusqlite::params![tag, c.session_id, *n as i64],
            )
            .map_err(db_err)?;
        }

        tx.execute(
            "INSERT OR IGNORE INTO processed (sign_h) VALUES (?1)",
            rusqlite::params![c.sign_h],
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
        let dup: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM msg WHERE sign_h=?1",
                rusqlite::params![dedup_h],
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
        let rows =
            self.db.query(&sql, &[Value::from(identity_id), Value::from(limit), Value::from(offset)])?;
        Ok(self.decrypt_rows(rows, &["subject", "snippet"]))
    }

    /// Messages of a conversation, oldest first.
    pub fn messages(&self, identity_id: i64, conv_id: &str) -> Result<Vec<Value>> {
        let rows = self.db.query(
            "SELECT msg_id, dir, sender_xid, subject, body, sent_ms, received_ms, read, enc
             FROM msg WHERE identity_id=? AND conv_id=? ORDER BY sent_ms ASC, msg_id ASC",
            &[Value::from(identity_id), Value::from(conv_id)],
        )?;
        Ok(self.decrypt_rows(rows, &["subject", "body"]))
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
            let subject = self.dec_text(row.get("subject").and_then(|v| v.as_str()).unwrap_or(""), enc);
            let body = self.dec_text(row.get("body").and_then(|v| v.as_str()).unwrap_or(""), enc);
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
        let conn = self.db.conn()?;
        let read_i = if read { 1 } else { 0 };
        conn.execute(
            "UPDATE msg SET read=?1 WHERE identity_id=?2 AND conv_id=?3",
            rusqlite::params![read_i, identity_id, conv_id],
        )
        .map_err(db_err)?;
        conn.execute(
            "UPDATE thread SET unread=?1 WHERE identity_id=?2 AND conv_id=?3",
            rusqlite::params![if read { 0 } else { 1 }, identity_id, conv_id],
        )
        .map_err(db_err)?;
        Ok(())
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
        let conn = self.db.conn()?;
        if let Some(v) = starred {
            conn.execute(
                "UPDATE thread SET starred=?1 WHERE identity_id=?2 AND conv_id=?3",
                rusqlite::params![v as i64, identity_id, conv_id],
            )
            .map_err(db_err)?;
        }
        if let Some(v) = archived {
            conn.execute(
                "UPDATE thread SET archived=?1 WHERE identity_id=?2 AND conv_id=?3",
                rusqlite::params![v as i64, identity_id, conv_id],
            )
            .map_err(db_err)?;
        }
        Ok(())
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
    fn is_processed(&self, sign_h: &[u8]) -> Result<bool> {
        ChannelDb::is_processed(self, sign_h)
    }
    fn mark_processed(&self, sign_h: &[u8]) -> Result<()> {
        ChannelDb::mark_processed(self, sign_h)
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
        peer_xid: &str,
    ) -> Result<Option<i64>> {
        ChannelDb::session_id_for_leg(self, identity_id, conv_id, peer_xid)
    }
    fn create_session(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_xid: Option<&str>,
        role: &str,
        ratchet: &[u8],
        established_ms: i64,
        recv_tags: &[(u32, Vec<u8>)],
    ) -> Result<i64> {
        ChannelDb::create_session(
            self, identity_id, conv_id, peer_xid, role, ratchet, established_ms, recv_tags,
        )
    }
    fn update_session_ratchet(&self, session_id: i64, ratchet: &[u8]) -> Result<()> {
        ChannelDb::update_session_ratchet(self, session_id, ratchet)
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
        assert!(!d.is_processed(&h).unwrap());
        d.mark_processed(&h).unwrap();
        assert!(d.is_processed(&h).unwrap());
        d.mark_processed(&h).unwrap(); // idempotent
    }

    #[test]
    fn inbound_commit_is_atomic_and_idempotent() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        let sid = d
            .create_session(idn, "cafe00", Some("dice.epix"), "resp", b"ratchet-v0", 1000, &[])
            .unwrap();

        let c = InboundCommit {
            identity_id: idn,
            session_id: sid,
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
        let sid = d.create_session(idn, "cx", Some("p.epix"), "resp", b"r", 1, &[]).unwrap();
        d.commit_inbound(&InboundCommit {
            identity_id: idn,
            session_id: sid,
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
    fn set_conv_state_persists_star_and_archive_into_folders() {
        let d = db();
        let idn = d.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
        let sid = d.create_session(idn, "cs", Some("p.epix"), "resp", b"r", 1, &[]).unwrap();
        d.commit_inbound(&InboundCommit {
            identity_id: idn,
            session_id: sid,
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
        let sid = d.create_session(idn, "cv", Some("b.epix"), "init", b"RATCHET-STATE-XYZ", 1, &[]).unwrap();
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
        d.create_session(idn, "cv", Some("b.epix"), "init", b"RS3", 1, &[(0, vec![7u8; 32])]).unwrap();
        let sm = d.session_for_tag(&[7u8; 32]).unwrap().unwrap();
        assert_eq!(sm.ratchet, b"RS3");
    }
}
