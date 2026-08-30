//! One-shot import of pre-cutover ("legacy") Epix Mail into the private channel
//! index.
//!
//! The old model stored each conversation as an `epix-orset-1` CRDT in a user's
//! `data/users/<xid>/messages.json`. Every post carries a plaintext-keyed
//! ciphertext dict `ct: { "<recipient_xid>": "<base64 ECIES>" , ... }` (the very
//! metadata leak the new design removes), where each value is
//! `ECIES(JSON.stringify({subject, body}))` sealed to that recipient's mail
//! public key. The sender's own copy is included in `ct` too.
//!
//! Importing is therefore: for every post across every user's `messages.json`,
//! find the ciphertext addressed to me, decrypt it with my mail private key,
//! and insert the `{subject, body}` into the private index under the post's
//! `conv_id`/`ts`, deriving direction from whether I authored it. This reads the
//! legacy data and writes only the private index — it deletes nothing, and it is
//! idempotent (safe to re-run), so it is decoupled from the destructive shared-
//! site cleanup of the hard cutover.

use epix_core::Result;
use serde_json::Value;

use crate::db::ChannelDb;

/// Outcome counters for a migration run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LegacyImport {
    /// New messages written to the private index.
    pub imported: i64,
    /// Messages that decrypted to me but were already imported (idempotent).
    pub skipped: i64,
    /// Posts examined in total (across all files).
    pub scanned: i64,
}

/// Strip a trailing `.epix` and lowercase, so `Mud.epix` and `mud` compare equal.
fn norm(xid: &str) -> String {
    xid.trim().trim_end_matches(".epix").trim_end_matches(".EPIX").to_ascii_lowercase()
}

/// Try to ECIES-decrypt `b64` with my mail `privkey`; returns the UTF-8
/// plaintext on success. Only the ciphertext actually sealed to my key verifies
/// (the AEAD MAC fails otherwise), so this doubles as "is this copy mine?".
fn try_open(b64: &str, privkey: &str) -> Option<String> {
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let pt = epix_crypt::ecies::ecies_decrypt(&blob, privkey).ok()?;
    String::from_utf8(pt).ok()
}

/// A stable 16-byte identifier for a legacy message, used as the private index's
/// dedup key (`sign_h`). Bound to the importing identity so two identities on
/// one node never collide on the same source message.
fn dedup_h(identity_id: i64, conv_id: &str, from_xid: &str, ts: i64) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(b"epix/channel/legacy-import/v1");
    h.update(&identity_id.to_le_bytes());
    h.update(conv_id.as_bytes());
    h.update(&[0]);
    h.update(norm(from_xid).as_bytes());
    h.update(&[0]);
    h.update(&ts.to_le_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize().as_bytes()[..16]);
    out
}

/// Import one already-parsed `messages.json` post into `db`, if it is addressed
/// to me. Returns `Some(true)` on a new import, `Some(false)` on an idempotent
/// skip, and `None` if the post is not for me / malformed (not counted as
/// scanned-with-a-copy). Errors from the DB are surfaced.
fn import_post(
    db: &ChannelDb,
    identity_id: i64,
    my_xid: &str,
    privkey: &str,
    post: &Value,
) -> Result<Option<bool>> {
    // Tombstoned edits carry no ciphertext of interest.
    if post.get("deleted").and_then(|v| v.as_bool()) == Some(true) {
        return Ok(None);
    }
    let Some(conv_id) = post.get("conv_id").and_then(|v| v.as_str()) else { return Ok(None) };
    let from_xid = post.get("from_xid").and_then(|v| v.as_str()).unwrap_or("");
    // The message timestamp; fall back to date_added/clock if `ts` is absent.
    let ts = post
        .get("ts")
        .and_then(|v| v.as_i64())
        .or_else(|| post.get("date_added").and_then(|v| v.as_i64()))
        .or_else(|| post.get("clock").and_then(|v| v.as_i64()))
        .unwrap_or(0);
    let Some(ct) = post.get("ct").and_then(|v| v.as_object()) else { return Ok(None) };

    // Prefer the entry keyed by my xid (fast path); otherwise try every entry,
    // since only the one sealed to my key decrypts — this is robust to the
    // identity being named by address vs xid-name.
    let mut plaintext = None;
    if let Some(v) = ct
        .iter()
        .find(|(k, _)| norm(k) == norm(my_xid))
        .and_then(|(_, v)| v.as_str())
    {
        plaintext = try_open(v, privkey);
    }
    if plaintext.is_none() {
        for v in ct.values() {
            if let Some(b64) = v.as_str() {
                if let Some(pt) = try_open(b64, privkey) {
                    plaintext = Some(pt);
                    break;
                }
            }
        }
    }
    let Some(pt) = plaintext else { return Ok(None) };

    // The legacy plaintext is `{subject, body}`.
    let parsed: Value = serde_json::from_str(&pt).unwrap_or(Value::Null);
    let subject = parsed.get("subject").and_then(|v| v.as_str()).unwrap_or("");
    let body = parsed.get("body").and_then(|v| v.as_str()).unwrap_or(&pt);

    let is_out = norm(from_xid) == norm(my_xid);
    let members: Vec<String> = post
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let h = dedup_h(identity_id, conv_id, from_xid, ts);
    let newly =
        db.import_legacy(identity_id, conv_id, from_xid, is_out, &members, subject, body, ts, &h)?;
    Ok(Some(newly))
}

/// Import every message addressed to me from a batch of legacy `messages.json`
/// containers (each a parsed `{ "record_format": "epix-orset-1", "post": [...] }`).
/// Idempotent. CPU-bound (one ECIES open per candidate ciphertext) — callers
/// should run this off the async runtime.
pub fn import_legacy_containers(
    db: &ChannelDb,
    identity_id: i64,
    my_xid: &str,
    privkey: &str,
    containers: &[Value],
) -> LegacyImport {
    let mut out = LegacyImport::default();
    for container in containers {
        let Some(posts) = container.get("post").and_then(|v| v.as_array()) else { continue };
        for post in posts {
            out.scanned += 1;
            match import_post(db, identity_id, my_xid, privkey, post) {
                Ok(Some(true)) => out.imported += 1,
                Ok(Some(false)) => out.skipped += 1,
                Ok(None) => {}
                // A single bad record must not abort the whole migration.
                Err(_) => {}
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    // A deterministic mail keypair for the recipient "me".
    const MY_PRIV: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

    fn seal_for(privkey: &str, subject: &str, body: &str) -> String {
        let pubkey = epix_crypt::private_to_compressed_pubkey(privkey).unwrap();
        let msg = serde_json::to_string(&json!({ "subject": subject, "body": body })).unwrap();
        let (blob, _k) = epix_crypt::ecies::ecies_encrypt(msg.as_bytes(), &pubkey).unwrap();
        base64::engine::general_purpose::STANDARD.encode(blob)
    }

    fn container(posts: Vec<Value>) -> Value {
        json!({ "record_format": "epix-orset-1", "post": posts })
    }

    #[test]
    fn imports_only_messages_addressed_to_me_and_is_idempotent() {
        let db = ChannelDb::memory().unwrap();
        let id = db.upsert_identity("me.epix", "epix1me", 0, None).unwrap();

        // A received message (peer authored, sealed a copy to me + to themselves).
        let recv = json!({
            "conv_id": "c1", "seq": 1, "ts": 1000, "from_xid": "peer.epix",
            "members": ["me.epix", "peer.epix"],
            "ct": {
                "me.epix": seal_for(MY_PRIV, "Hi", "hello from peer"),
                // A copy for someone else that I must NOT be able to open.
                "peer.epix": seal_for(
                    "22c8a4485fa256587c3809b5079c8864d7339e9fb061a08c8834bd1c7e5f0f18",
                    "Hi", "not mine"),
            },
        });
        // A sent message (I authored it; my own copy is in ct).
        let sent = json!({
            "conv_id": "c1", "seq": 2, "ts": 2000, "from_xid": "me.epix",
            "ct": { "me.epix": seal_for(MY_PRIV, "Hi", "my reply") },
        });
        // A message in a conversation I'm not part of (no copy for me).
        let foreign = json!({
            "conv_id": "c9", "seq": 1, "ts": 3000, "from_xid": "a.epix",
            "ct": { "b.epix": seal_for(
                "3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011",
                "X", "for b only") },
        });

        let batch = vec![container(vec![recv, foreign]), container(vec![sent])];
        let r = import_legacy_containers(&db, id, "me.epix", MY_PRIV, &batch);
        assert_eq!(r.scanned, 3, "all three posts examined");
        assert_eq!(r.imported, 2, "only the two addressed to me imported");
        assert_eq!(r.skipped, 0);

        // Direction was derived correctly, and bodies decrypted.
        let msgs = db.messages(id, "c1").unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["dir"].as_str(), Some("in"));
        assert_eq!(msgs[0]["body"].as_str(), Some("hello from peer"));
        assert_eq!(msgs[1]["dir"].as_str(), Some("out"));
        assert_eq!(msgs[1]["body"].as_str(), Some("my reply"));
        assert!(db.messages(id, "c9").unwrap().is_empty(), "foreign conv not imported");

        // FTS index was populated from imported plaintext.
        assert_eq!(db.search(id, "peer", 10).unwrap().len(), 1);

        // Re-running imports nothing new (idempotent).
        let r2 = import_legacy_containers(&db, id, "me.epix", MY_PRIV, &batch);
        assert_eq!(r2.imported, 0, "second run imports nothing");
        assert_eq!(r2.skipped, 2, "both of my messages recognized as already present");
        assert_eq!(db.messages(id, "c1").unwrap().len(), 2, "no duplicate rows");
    }
}
