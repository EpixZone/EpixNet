//! Source-side progress for copying locally authored mail to verified sibling devices.
//! A pool record's signature changes when a copy is sealed again. The private
//! source ID survives retries, including a crash between staging and checkpointing.
use super::{db_err, device_revoked_conn, ChannelDb};
use epix_core::{Error, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

/// One original sent item, in local insertion order. The author and conversation
/// are taken from the private index, never from a remote request.
pub struct SentHistoryRow {
    pub msg_id: i64,
    pub conv_id: String,
    pub sender_xid: String,
    pub members: Vec<String>,
    pub subject: String,
    pub body: String,
    pub sent_ms: i64,
    pub source_id: String,
}

const MAX_PAGE: usize = 16;

// Keep the cheap scheduling probe and the plaintext export on exactly the same scope.
const PENDING: &str = "
    FROM msg m JOIN thread t ON t.thread_id=m.thread_id
    WHERE m.identity_id=?1 AND m.sender_xid=?2 AND m.dir='out' AND m.sign_h IS NULL
      AND t.app='mail' AND m.msg_id>?3
      AND NOT EXISTS (SELECT 1 FROM mail_sync_staged WHERE peer_ik=?4 AND msg_id=m.msg_id)";

fn history_cursor(
    conn: &Connection,
    identity_id: i64,
    peer_ik: &str,
) -> Result<Option<(String, i64)>> {
    let scope = conn
        .query_row(
            "SELECT i.xid, i.auth_address, COALESCE(c.through_msg_id,0)
         FROM identity i LEFT JOIN mail_sync_cursor c
           ON c.identity_id=i.identity_id AND c.xid=i.xid AND c.peer_ik=?2
         WHERE i.identity_id=?1 AND i.enabled=1",
            params![identity_id, peer_ik],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(db_err)?;
    let Some((xid, auth, cursor)) = scope else {
        return Ok(None);
    };
    if device_revoked_conn(conn, &xid, Some(&auth), peer_ik)? {
        return Ok(None);
    }
    Ok(Some((xid, cursor)))
}

fn pending_after(conn: &Connection, id: i64, xid: &str, after: i64, peer: &str) -> Result<bool> {
    conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 {PENDING})"),
        params![id, xid, after, peer],
        |row| row.get(0),
    )
    .map_err(db_err)
}

fn page_start(conn: &Connection, id: i64, xid: &str, cursor: i64, peer: &str) -> Result<i64> {
    let failed: Option<i64> = conn.query_row(
        "SELECT after_msg_id FROM mail_sync_retry_position WHERE identity_id=? AND xid=? AND peer_ik=?",
        params![id,xid,peer], |r| r.get(0)
    ).optional().map_err(db_err)?;
    if let Some(after) = failed.filter(|&n| n > cursor) {
        if pending_after(conn, id, xid, after, peer)? {
            return Ok(after);
        }
    }
    Ok(cursor)
}

pub(super) fn record_live_sibling_slots(
    tx: &Transaction<'_>,
    commits: &[epix_envelope::OutboundCommit],
    results: &[(i64, i64)],
) -> Result<()> {
    let own = results.iter().find(|(_, id)| *id != 0);
    for session in commits
        .iter()
        .flat_map(|c| &c.sessions)
        .filter(|s| s.sent_copy)
    {
        // A disable, rebind or revocation may have landed while the worker
        // sealed the page. Recheck in the actual outbox transaction.
        let (source, _) =
            history_cursor(tx, session.identity_id, &session.peer_ik)?.ok_or_else(|| {
                Error::Db("sent copy source or destination is no longer active".into())
            })?;
        if session.peer_xid.as_deref() != Some(&source) {
            return Err(Error::Db(
                "sent copy device belongs to a different identity".into(),
            ));
        }
        if let Some((_, msg_id)) = own {
            record_delivery(tx, session.identity_id, &session.peer_ik, *msg_id)?;
        }
    }
    Ok(())
}

impl ChannelDb {
    pub(super) fn migrate_sent_history(&self) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        if !Self::table_columns(&tx, "msg")?.contains("source_id") {
            tx.execute_batch("ALTER TABLE msg ADD COLUMN source_id TEXT")
                .map_err(db_err)?;
        }
        tx.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS sent_source_id ON msg(identity_id, source_id)
                 WHERE dir='out' AND source_id IS NOT NULL;
             CREATE INDEX IF NOT EXISTS original_mail_cursor ON msg(identity_id, sender_xid, msg_id)
                 WHERE dir='out' AND sign_h IS NULL;
             CREATE TABLE IF NOT EXISTS mail_sync_cursor (
                 identity_id INTEGER NOT NULL REFERENCES identity(identity_id) ON DELETE CASCADE,
                 xid TEXT NOT NULL, peer_ik TEXT NOT NULL, through_msg_id INTEGER NOT NULL,
                 PRIMARY KEY(identity_id, xid, peer_ik));
             CREATE TABLE IF NOT EXISTS mail_sync_staged (
                 msg_id INTEGER NOT NULL REFERENCES msg(msg_id) ON DELETE CASCADE,
                 peer_ik TEXT NOT NULL, PRIMARY KEY(peer_ik, msg_id));
             PRAGMA user_version = 8;",
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)
    }

    /// A background sweep can skip chain resolution when every eligible row
    /// already reached the durable outbox for this device.
    pub fn has_pending_sent_history(&self, identity_id: i64, peer_ik: &str) -> Result<bool> {
        let conn = self.db.conn()?;
        let Some((xid, cursor)) = history_cursor(&conn, identity_id, peer_ik)? else {
            return Ok(false);
        };
        pending_after(&conn, identity_id, &xid, cursor, peer_ik)
    }

    /// Read a bounded page for one sibling. The caller resolves and authenticates
    /// both live devices before sending. Only rows authored here have a NULL
    /// sign_h. Received, imported, other-identity and non-mail rows never leave.
    pub fn next_sent_history(
        &self,
        identity_id: i64,
        peer_ik: &str,
        limit: usize,
    ) -> Result<Vec<SentHistoryRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        let Some((xid, cursor)) = history_cursor(&tx, identity_id, peer_ik)? else {
            return Ok(Vec::new());
        };
        let after = page_start(&tx, identity_id, &xid, cursor, peer_ik)?;
        let mut stmt = tx.prepare(&format!(
            "SELECT m.msg_id, m.conv_id, t.members, t.peer_xid, m.subject, m.body, m.sent_ms, m.enc, m.source_id
             {PENDING} ORDER BY m.msg_id LIMIT ?5",
        )).map_err(db_err)?;
        let mut rows = stmt
            .query(params![
                identity_id,
                xid,
                after,
                peer_ik,
                limit.min(MAX_PAGE) as i64
            ])
            .map_err(db_err)?;
        let mut page = Vec::new();
        while let Some(row) = rows.next().map_err(db_err)? {
            let msg_id = row.get(0).map_err(db_err)?;
            let member_json: Option<String> = row.get(2).map_err(db_err)?;
            let members = match member_json {
                Some(json) => serde_json::from_str(&json)?,
                None => {
                    let peer: Option<String> = row.get(3).map_err(db_err)?;
                    std::iter::once(xid.clone())
                        .chain(peer.filter(|p| p != &xid))
                        .collect()
                }
            };
            let enc = row.get(7).map_err(db_err)?;
            let stored_id: Option<String> = row.get(8).map_err(db_err)?;

            page.push(SentHistoryRow {
                msg_id,
                conv_id: row.get(1).map_err(db_err)?,
                sender_xid: xid.clone(),
                members,
                subject: self.dec_text(&row.get::<_, String>(4).map_err(db_err)?, enc)?,
                body: self.dec_text(&row.get::<_, String>(5).map_err(db_err)?, enc)?,
                sent_ms: row.get(6).map_err(db_err)?,
                source_id: stored_id.unwrap_or_default(),
            });
        }
        drop(rows);
        drop(stmt);
        for row in &mut page {
            if row.source_id.is_empty() {
                row.source_id = assign_source_id(&tx, row.msg_id)?;
            }
        }
        tx.commit().map_err(db_err)?;
        Ok(page)
    }

    /// A failed attempt yields to later originals on the next sweep. Keep the
    /// delivery cursor untouched so this row is retried after wrapping around.
    pub fn defer_sent_history(
        &self,
        identity_id: i64,
        xid: &str,
        peer_ik: &str,
        msg_id: i64,
    ) -> Result<()> {
        self.db.conn()?.execute(
            "INSERT INTO mail_sync_retry_position(identity_id,xid,peer_ik,after_msg_id)
             SELECT identity_id,xid,?3,?4 FROM identity WHERE identity_id=?1 AND xid=?2 AND enabled=1
             ON CONFLICT(identity_id,xid,peer_ik) DO UPDATE SET after_msg_id=excluded.after_msg_id",
             params![identity_id,xid,peer_ik,msg_id],
        ).map_err(db_err)?;
        Ok(())
    }

    /// Call only after the durable outbox accepted this item for this device.
    pub fn mark_sent_history_staged(
        &self,
        identity_id: i64,
        peer_ik: &str,
        msg_id: i64,
    ) -> Result<()> {
        let mut conn = self.db.conn()?;
        let tx = conn.transaction().map_err(db_err)?;
        record_delivery(&tx, identity_id, peer_ik, msg_id)?;
        tx.commit().map_err(db_err)
    }
}

fn record_delivery(
    tx: &Transaction<'_>,
    identity_id: i64,
    peer_ik: &str,
    msg_id: i64,
) -> Result<()> {
    let Some((xid, cursor)) = history_cursor(tx, identity_id, peer_ik)? else {
        return Ok(());
    };
    if msg_id <= cursor {
        return Ok(());
    }
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO mail_sync_staged(msg_id,peer_ik)
         SELECT m.msg_id,?1 FROM msg m JOIN thread t ON t.thread_id=m.thread_id
         WHERE m.identity_id=?2 AND m.msg_id=?3 AND m.sender_xid=?4
            AND m.dir='out' AND m.sign_h IS NULL AND t.app='mail'",
            params![peer_ik, identity_id, msg_id, xid],
        )
        .map_err(db_err)?;
    if inserted == 0 {
        return Ok(());
    }
    // Live fanout can land ahead of old missing rows. Compact only the known
    // prefix, leaving sparse receipts after the first gap for the next sweep.
    let first_pending: Option<i64> = tx
        .query_row(
            &format!("SELECT m.msg_id {PENDING} ORDER BY m.msg_id LIMIT 1"),
            params![identity_id, xid, cursor, peer_ik],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_err)?;
    let through = match first_pending {
        Some(first) => first - 1,
        None => tx.query_row(
            "SELECT MAX(msg_id) FROM msg WHERE identity_id=?1 AND sender_xid=?2 AND dir='out' AND sign_h IS NULL",
            params![identity_id,xid], |r| r.get(0),
        ).map_err(db_err)?,
    };
    if through > cursor {
        tx.execute(
            "INSERT INTO mail_sync_cursor VALUES(?1,?2,?3,?4)
             ON CONFLICT(identity_id,xid,peer_ik) DO UPDATE SET through_msg_id=excluded.through_msg_id",
            params![identity_id,xid,peer_ik,through],
        ).map_err(db_err)?;
        tx.execute(
            "DELETE FROM mail_sync_staged WHERE peer_ik=?1 AND msg_id IN
                (SELECT msg_id FROM msg WHERE identity_id=?2 AND sender_xid=?3
                   AND dir='out' AND sign_h IS NULL AND msg_id>?4 AND msg_id<=?5)",
            params![peer_ik, identity_id, xid, cursor, through],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

fn assign_source_id(tx: &Transaction<'_>, msg_id: i64) -> Result<String> {
    // Older messages have no logical ID. Allocate once before returning their
    // plaintext, so every sibling and every restart uses the same identifier.
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| Error::Db(e.to_string()))?;
    let id = hex::encode(bytes);
    tx.execute(
        "UPDATE msg SET source_id=? WHERE msg_id=?",
        params![id, msg_id],
    )
    .map_err(db_err)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "alice.epix";
    const PEER: &str = "bob.epix";

    fn add_original(db: &ChannelDb, id: i64, body: &str) -> i64 {
        db.insert_sent(
            id,
            "07070707070707070707070707070707",
            Some(PEER),
            &[ME.to_string(), PEER.to_string()],
            ME,
            "Wallet Testing",
            body,
            1780000002345,
        )
        .unwrap()
    }

    #[test]
    fn v7_index_gains_source_ids_without_rewriting_or_merging_existing_messages() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        {
            let old = epix_db::Database::open(&path).unwrap();
            old.execute_batch(super::super::SCHEMA).unwrap();
            old.execute_batch("PRAGMA user_version=7;
                INSERT INTO identity(identity_id,xid,auth_address,derive_index) VALUES(1,'alice.epix','laptop',0);
                INSERT INTO thread(thread_id,identity_id,conv_id,peer_xid) VALUES(1,1,'legacy-thread','bob.epix');
                INSERT INTO msg(identity_id,thread_id,conv_id,dir,sender_xid,subject,body,sent_ms,read)
                  VALUES(1,1,'legacy-thread','out','alice.epix','Old','Old sent row',123,1);").unwrap();
        }
        let migrated = ChannelDb::open(&path).unwrap();
        let page = migrated.next_sent_history(1, "phone", 2).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].members, [ME, PEER]);
        assert_eq!(page[0].body, "Old sent row");
        assert_eq!(page[0].sent_ms, 123);
        assert_eq!(migrated.messages(1, "legacy-thread").unwrap().len(), 1);
    }

    #[test]
    fn live_slot_in_a_later_transport_chunk_stages_its_receipt_atomically() {
        use epix_envelope::{OutboundCommit, OutboundMessage, OutboundRecovery, OutboundSession};
        let db = ChannelDb::memory().unwrap();
        let id = db.upsert_identity(ME, "laptop", 0, None).unwrap();
        let earlier = add_original(&db, id, "older");
        let make_chunk = |peer: &str, sent_copy: bool| OutboundCommit {
            sessions: vec![OutboundSession {
                sent_copy,
                identity_id: id,
                session_id: None,
                conv_id: if sent_copy {
                    format!("{}conversation", epix_envelope::store::SENT_COPY_OUT)
                } else {
                    "conversation".into()
                },
                peer_xid: Some(if sent_copy { ME } else { PEER }.into()),
                peer_ik: peer.into(),
                peer_auth: None,
                role: "init".into(),
                ratchet_before: None,
                ratchet_after: vec![1],
                established_ms: 123,
                recv_tags: vec![],
            }],
            record: serde_json::json!({"sign":peer}),
            shard_path: "pool/w0/00.json".into(),
            created_ms: 123,
            next_attempt_ms: 123,
            recovery: OutboundRecovery {
                author_private_key: "test".into(),
                rln: None,
            },
            sent: None,
        };
        let mut chunks = [make_chunk("bob-phone", false), make_chunk("phone", true)];
        chunks[0].sent = Some(OutboundMessage {
            identity_id: id,
            conv_id: "conversation".into(),
            peer_xid: Some(PEER.into()),
            members: vec![ME.into(), PEER.into()],
            sender_xid: ME.into(),
            subject: "now".into(),
            body: "newer".into(),
            sent_ms: 123,
            app: "mail".into(),
            source_id: Some("a".repeat(64)),
        });
        db.db
            .execute_batch(
                "CREATE TRIGGER fail_receipt BEFORE INSERT ON mail_sync_staged
                             BEGIN SELECT RAISE(ABORT,'test failure'); END",
            )
            .unwrap();
        assert!(db.commit_outbound_batch(&chunks).is_err());
        assert!(db.pending_outbound(10).unwrap().is_empty());
        assert!(db.messages(id, "conversation").unwrap().is_empty());
        db.db.execute_batch("DROP TRIGGER fail_receipt").unwrap();
        db.commit_outbound_batch(&chunks).unwrap();
        let page = db.next_sent_history(id, "phone", 5).unwrap();
        assert_eq!(page.iter().map(|r| r.msg_id).collect::<Vec<_>>(), [earlier]);
        assert_eq!(
            db.next_sent_history(id, "fresh-tablet", 5).unwrap().len(),
            2
        );
        db.mark_sent_history_staged(id, "phone", earlier).unwrap();
        assert!(!db.has_pending_sent_history(id, "phone").unwrap());
    }

    #[test]
    fn previously_sent_messages_resume_in_order_without_replaying_live_copies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        let key = [9u8; 32];
        let db = ChannelDb::open_encrypted(&path, key).unwrap();
        let id = db.upsert_identity(ME, "laptop", 0, None).unwrap();
        let first = add_original(&db, id, "first reply");
        let second = add_original(&db, id, "first reply");
        let live = add_original(&db, id, "live reply");
        // The newest record already included the phone. It cannot advance
        // the checkpoint past the two older replies.
        db.mark_sent_history_staged(id, "phone", live).unwrap();
        let rows = db.next_sent_history(id, "phone", 1).unwrap();
        let row = &rows[0];
        assert_eq!(row.msg_id, first);
        assert_eq!(row.body, "first reply");
        assert_eq!(row.subject, "Wallet Testing");
        assert_eq!(row.sender_xid, ME);
        assert_eq!(row.sent_ms, 1780000002345);
        assert_eq!(row.members, [ME, PEER]);
        assert_eq!(hex::decode(&row.source_id).unwrap().len(), 32);
        let first_source = row.source_id.clone();
        // Persisted ciphertext remains intact when assigning a legacy source ID.
        let stored: String = db
            .db
            .conn()
            .unwrap()
            .query_row("SELECT body FROM msg WHERE msg_id=?", [first], |r| r.get(0))
            .unwrap();
        assert_ne!(stored, row.body);
        drop(db);
        let db = ChannelDb::open_encrypted(&path, key).unwrap();
        // Crash after staging but before acknowledging: the source ID is stable.
        let retry = db.next_sent_history(id, "phone", 16).unwrap();
        assert_eq!(retry.len(), 2);
        assert_eq!(retry[0].source_id, first_source);
        assert_ne!(
            retry[1].source_id, first_source,
            "identical content can be sent twice"
        );
        db.mark_sent_history_staged(id, "phone", first).unwrap();
        db.mark_sent_history_staged(id, "phone", first).unwrap();
        assert_eq!(
            db.next_sent_history(id, "phone", 1).unwrap()[0].msg_id,
            second
        );
        db.mark_sent_history_staged(id, "phone", second).unwrap();
        assert!(!db.has_pending_sent_history(id, "phone").unwrap());
        assert!(db.next_sent_history(id, "phone", 16).unwrap().is_empty());
        assert_eq!(
            db.db
                .conn()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM mail_sync_staged", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(db.next_sent_history(id, "tablet", 16).unwrap().len(), 3);
        assert_eq!(
            db.next_sent_history(id, "tablet", 1).unwrap()[0].source_id,
            first_source
        );
    }

    #[test]
    fn failed_rows_yield_to_later_mail_and_retry_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("channels.db");
        let db = ChannelDb::open(&path).unwrap();
        let id = db.upsert_identity(ME, "laptop", 0, None).unwrap();
        let first = add_original(&db, id, "large reply");
        let second = add_original(&db, id, "second large reply");
        let third = add_original(&db, id, "short reply");
        db.defer_sent_history(id, ME, "phone", first).unwrap();
        drop(db);
        let db = ChannelDb::open(&path).unwrap();
        assert_eq!(
            db.next_sent_history(id, "phone", 1).unwrap()[0].msg_id,
            second
        );
        db.defer_sent_history(id, ME, "phone", second).unwrap();
        assert_eq!(
            db.next_sent_history(id, "phone", 1).unwrap()[0].msg_id,
            third
        );
        db.mark_sent_history_staged(id, "phone", third).unwrap();
        let pending = db.next_sent_history(id, "phone", 4).unwrap();
        assert_eq!(
            pending.iter().map(|r| r.msg_id).collect::<Vec<_>>(),
            [first, second]
        );
        for row in pending {
            db.mark_sent_history_staged(id, "phone", row.msg_id)
                .unwrap();
        }
        assert!(!db.has_pending_sent_history(id, "phone").unwrap());
        assert_eq!(db.next_sent_history(id, "tablet", 5).unwrap().len(), 3);
    }

    #[test]
    fn only_current_locally_authored_mail_is_eligible_and_revocations_stop_exports() {
        let db = ChannelDb::memory().unwrap();
        let id = db.upsert_identity(ME, "laptop", 0, None).unwrap();
        let other = db.upsert_identity("other.epix", "other", 0, None).unwrap();
        add_original(&db, other, "other account");
        // Both imported sent copies and genuine inbound messages have a source
        // signature. Neither can propagate by way of a trusted sibling.
        for (owner, outbound, hash) in [(ME, true, 1), (PEER, false, 2)] {
            db.import_legacy(
                id,
                "incoming",
                owner,
                outbound,
                &[ME.into(), PEER.into()],
                "subject",
                "private",
                4,
                &[hash; 16],
            )
            .unwrap();
        }
        let original = add_original(&db, id, "own reply");
        let scoped = db
            .insert_sent(
                id,
                "scoped",
                Some(PEER),
                &[ME.into(), PEER.into()],
                ME,
                "scope",
                "other app",
                9,
            )
            .unwrap();
        db.db
            .conn()
            .unwrap()
            .execute("UPDATE thread SET app='chat' WHERE conv_id='scoped'", [])
            .unwrap();
        db.mark_sent_history_staged(id, "phone", scoped).unwrap();
        let eligible = db.next_sent_history(id, "phone", 16).unwrap();
        assert_eq!(
            eligible.iter().map(|r| r.msg_id).collect::<Vec<_>>(),
            [original]
        );
        db.set_identity_enabled(id, false).unwrap();
        assert!(!db.has_pending_sent_history(id, "phone").unwrap());
        db.set_identity_enabled(id, true).unwrap();
        db.upsert_identity("changed.epix", "laptop", 0, None)
            .unwrap();
        assert!(db.next_sent_history(id, "phone", 16).unwrap().is_empty());
        db.upsert_identity(ME, "laptop", 0, None).unwrap();
        db.remember_revoked_device(ME, Some("linked-phone"), "phone", 7)
            .unwrap();
        assert!(!db.has_pending_sent_history(id, "phone").unwrap());
        assert!(db.has_pending_sent_history(id, "tablet").unwrap());
        db.remember_revoked_device(ME, Some("laptop"), "laptop-key", 8)
            .unwrap();
        assert!(db.next_sent_history(id, "tablet", 16).unwrap().is_empty());
    }

    #[test]
    fn bounded_pages_and_history_state_are_scoped_to_the_identity_lifetime() {
        let db = ChannelDb::memory().unwrap();
        let id = db.upsert_identity(ME, "laptop", 0, None).unwrap();
        for _ in 0..(MAX_PAGE + 3) {
            add_original(&db, id, "item");
        }
        assert!(db.next_sent_history(id, "phone", 0).unwrap().is_empty());
        let first = db.next_sent_history(id, "phone", usize::MAX).unwrap();
        assert_eq!(first.len(), MAX_PAGE);
        for row in first {
            db.mark_sent_history_staged(id, "phone", row.msg_id)
                .unwrap();
        }
        let remaining = db.next_sent_history(id, "phone", usize::MAX).unwrap();
        assert_eq!(remaining.len(), 3);
        db.mark_sent_history_staged(id, "phone", remaining[2].msg_id)
            .unwrap();
        db.delete_identity(id).unwrap();
        let conn = db.db.conn().unwrap();
        for table in ["mail_sync_cursor", "mail_sync_staged"] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}
