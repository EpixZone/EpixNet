//! Signed post-record primitives for the OR-Set merge-file class (Option A,
//! `docs/signed-crdt-posts-plan.md`).
//!
//! A record is a JSON object. Its signed payload is the record with ONLY its
//! `sign` field removed (a record has no `signs` map, unlike content.json),
//! canonicalized with the same [`dumps_sorted`](crate::canonical::dumps_sorted)
//! that content.json uses. The signature is `epix-crypt`'s recoverable ECDSA,
//! so verification RECOVERS the signer and compares it to the record's
//! immutable `author` (author-continuity). This is the per-record integrity
//! check that replaces the whole-file sha512 for a merge file.
//!
//! Signing happens on the node (`recordSign` WS command) with the user's
//! cert-aware auth key, so canonicalization only ever runs in Rust - there is
//! no JS/Rust byte-parity surface for signing.

use crate::canonical::dumps_sorted;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Max future skew allowed for a record `clock` (milliseconds). A record whose
/// `clock` is beyond `now_ms + this` is rejected so a device cannot pin
/// `clock = i64::MAX` and permanently block future edits/tombstones of a
/// `post_id`. The record clock is the MILLISECOND domain - do not compare it
/// against the seconds-domain content.json `modified` guard.
pub const CLOCK_SKEW_BOUND_MS: i64 = 5 * 60 * 1000;

/// Why a record failed verification. Every variant means "drop this record";
/// none is ever a panic (a malformed signature recovers to `Err`, not a crash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The record is not a JSON object.
    NotObject,
    /// A required immutable/identity field is missing.
    MissingField(&'static str),
    /// `deleted: true` but `body` is non-empty (content smuggled in a delete).
    TombstoneHasBody,
    /// `clock` is negative.
    NegativeClock,
    /// `clock` is further than [`CLOCK_SKEW_BOUND_MS`] into the future.
    ClockTooFarFuture,
    /// `author` is not an authorized signer of the governing content.json.
    UnauthorizedAuthor,
    /// The signature does not recover to `author` (forged, tampered, or garbage).
    BadSignature,
}

/// The canonical signed payload of a record: the object with ONLY `sign`
/// removed, dumped like content.json. Callers that sign and callers that verify
/// MUST both route through this one function - any byte drift silently drops
/// records.
pub fn record_signed_data(record: &Value) -> String {
    let mut r = record.clone();
    if let Value::Object(map) = &mut r {
        map.remove("sign");
    }
    dumps_sorted(&r)
}

/// Derive the immutable CRDT key from a record's immutable origin fields:
/// `truncate53(sha256("<author>:<nonce>:<date_added>"))`. The top 53 bits keep
/// the id exact in a JS `Number` and INTEGER-affine for the `post` table. Two
/// distinct posts share an id only on a ~2^26/author birthday collision, which
/// the client removes entirely by re-rolling the nonce at mint time against its
/// local set. Migrated legacy posts KEEP their old integer id and are not
/// re-derived, so this is enforced only at creation, never re-checked in
/// [`verify_record`] (the signature already binds `post_id` to the record).
pub fn derive_post_id(author: &str, nonce: &str, date_added: i64) -> i64 {
    let input = format!("{author}:{nonce}:{date_added}");
    truncate53(&input)
}

/// Derive a STABLE CRDT key from a natural per-author key string, e.g. a wiki
/// slug or a vote target uri: `truncate53(sha256("<author>|<key>"))`. Two writes
/// with the same `(author, key)` land on the same id, so editing a wiki page or
/// re-voting supersedes the prior record instead of creating a new item. This
/// is how non-post apps map their natural key onto the post_id-keyed OR-Set.
pub fn derive_post_id_keyed(author: &str, key: &str) -> i64 {
    truncate53(&format!("{author}|{key}"))
}

/// Top 53 bits of `sha256(input)` as a non-negative i64 - exact in a JS Number
/// and INTEGER-affine for the post table.
fn truncate53(input: &str) -> i64 {
    let digest = Sha256::digest(input.as_bytes());
    let top8: [u8; 8] = digest[..8].try_into().expect("sha256 is 32 bytes");
    (u64::from_be_bytes(top8) >> 11) as i64
}

/// Verify a single inbound record. `valid_signers` is the resolved authorized
/// signer set of the governing content.json (see `verify::valid_signers`).
/// Returns `Ok(())` iff the record is well-formed, its `clock` is in bounds,
/// its `author` is authorized, and its signature recovers to that `author`.
pub fn verify_record(
    record: &Value,
    valid_signers: &[String],
    now_ms: i64,
) -> Result<(), RecordError> {
    let obj = record.as_object().ok_or(RecordError::NotObject)?;

    let author = obj
        .get("author")
        .and_then(|v| v.as_str())
        .ok_or(RecordError::MissingField("author"))?;
    let sign =
        obj.get("sign").and_then(|v| v.as_str()).ok_or(RecordError::MissingField("sign"))?;
    let clock =
        obj.get("clock").and_then(|v| v.as_i64()).ok_or(RecordError::MissingField("clock"))?;
    // Identity fields must be present (they are part of the signed payload).
    // The id provenance is either a random `nonce` (unique items) or a natural
    // `key` (stable per-(author,key) items like a wiki slug or a vote target).
    obj.get("post_id")
        .and_then(|v| v.as_i64())
        .ok_or(RecordError::MissingField("post_id"))?;
    let has_nonce = obj.get("nonce").and_then(|v| v.as_str()).is_some();
    let has_key = obj.get("key").and_then(|v| v.as_str()).is_some();
    if !has_nonce && !has_key {
        return Err(RecordError::MissingField("nonce-or-key"));
    }
    obj.get("date_added")
        .and_then(|v| v.as_i64())
        .ok_or(RecordError::MissingField("date_added"))?;

    // A tombstone must carry no body - a delete cannot smuggle content.
    if obj.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false) {
        let body = obj.get("body").and_then(|v| v.as_str()).unwrap_or("");
        if !body.is_empty() {
            return Err(RecordError::TombstoneHasBody);
        }
    }

    // Bounded clock (anti-freeze).
    if clock < 0 {
        return Err(RecordError::NegativeClock);
    }
    if clock > now_ms + CLOCK_SKEW_BOUND_MS {
        return Err(RecordError::ClockTooFarFuture);
    }

    // The claimed `author` (for a moderation tombstone, the ORIGINAL author
    // whose item is being deleted) must be an authorized signer of this dir.
    if !valid_signers.iter().any(|s| s == author) {
        return Err(RecordError::UnauthorizedAuthor);
    }

    let payload = record_signed_data(record);
    // A cross-author MODERATION tombstone (`deleted: true, moderated: true`)
    // may be signed by ANY authorized signer of the directory (a moderator or
    // the author), not just the author - so a moderator can hide another
    // user's item. It can only DELETE (tombstone), never edit content. Every
    // other record obeys author-continuity: the signature MUST recover to the
    // record's own `author`, so no one can supersede another author's item.
    let moderated = obj.get("moderated").and_then(|v| v.as_bool()).unwrap_or(false);
    let deleted = obj.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false);
    let ok = if moderated && deleted {
        valid_signers.iter().any(|s| {
            epix_crypt::verify(&payload, s, sign) || epix_crypt::verify_keccak(&payload, s, sign)
        })
    } else {
        // Author-continuity: the signature must recover to `author` under the
        // double-sha256 OR keccak scheme (recovery always yields SOME address
        // for a well-formed sig, so compare to `author` under both digests; a
        // garbage sig fails both, yielding BadSignature - never a panic).
        epix_crypt::verify(&payload, author, sign)
            || epix_crypt::verify_keccak(&payload, author, sign)
    };
    if ok {
        Ok(())
    } else {
        Err(RecordError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PRIV: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

    fn author_addr() -> String {
        epix_crypt::privatekey_to_address(PRIV).unwrap()
    }

    /// Build a live record for `author`, sign it (dbl scheme) with `priv_hex`,
    /// and embed the signature. `clock` defaults sane.
    fn signed_record(author: &str, priv_hex: &str, clock: i64) -> Value {
        let nonce = "9f3a1c77e0b4426d0000000000000000";
        let date_added = 1737331200_i64;
        let post_id = derive_post_id(author, nonce, date_added);
        let mut rec = json!({
            "post_id": post_id,
            "nonce": nonce,
            "author": author,
            "clock": clock,
            "supersedes": 0,
            "deleted": false,
            "body": "hello world",
            "date_added": date_added,
        });
        let sig = epix_crypt::sign(&record_signed_data(&rec), priv_hex).unwrap();
        rec["sign"] = json!(sig);
        rec
    }

    #[test]
    fn record_signed_data_strips_only_sign() {
        // `sign` is removed; a stray `signs` (records never have one) is NOT
        // treated specially - it would stay in the payload if present.
        let rec = json!({ "b": 1, "a": 2, "sign": "xxx" });
        assert_eq!(record_signed_data(&rec), r#"{"a": 2, "b": 1}"#);
        let rec2 = json!({ "sign": "x", "signs": {"k": "v"}, "a": 1 });
        assert_eq!(record_signed_data(&rec2), r#"{"a": 1, "signs": {"k": "v"}}"#);
    }

    #[test]
    fn derive_post_id_is_deterministic_and_in_range() {
        let a = derive_post_id("epix1abc", "nonce123", 1737331200);
        let b = derive_post_id("epix1abc", "nonce123", 1737331200);
        assert_eq!(a, b, "same inputs -> same id");
        assert!(a >= 0 && a < (1_i64 << 53), "id fits in 53 bits: {a}");
        // Different nonce -> different id.
        assert_ne!(a, derive_post_id("epix1abc", "nonce124", 1737331200));
        // Different author -> different id.
        assert_ne!(a, derive_post_id("epix1abd", "nonce123", 1737331200));
    }

    #[test]
    fn verify_accepts_a_valid_record() {
        let author = author_addr();
        let rec = signed_record(&author, PRIV, 1737331500123);
        assert_eq!(verify_record(&rec, &[author], 1737331500123), Ok(()));
    }

    #[test]
    fn verify_accepts_a_keccak_signed_record() {
        let author = author_addr();
        let nonce = "abcd";
        let date_added = 1737331200_i64;
        let mut rec = json!({
            "post_id": derive_post_id(&author, nonce, date_added),
            "nonce": nonce, "author": author, "clock": 100_i64, "supersedes": 0,
            "deleted": false, "body": "k", "date_added": date_added,
        });
        rec["sign"] = json!(epix_crypt::sign_keccak(&record_signed_data(&rec), PRIV).unwrap());
        assert_eq!(verify_record(&rec, &[author], 1_000_000), Ok(()));
    }

    #[test]
    fn verify_rejects_wrong_signing_key() {
        // author claims one address but the record is signed by a different key.
        let other = "22b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let author = author_addr(); // authorized signer
        let mut rec = signed_record(&author, other, 100); // signed by the wrong key
        // still declares the authorized author, but the sig recovers elsewhere.
        rec["author"] = json!(author);
        assert_eq!(verify_record(&rec, &[author], 1_000_000), Err(RecordError::BadSignature));
    }

    #[test]
    fn verify_rejects_author_not_in_valid_signers() {
        let author = author_addr();
        let rec = signed_record(&author, PRIV, 100);
        // The directory only authorizes someone else.
        let others = vec!["epix1someoneelse".to_string()];
        assert_eq!(verify_record(&rec, &others, 1_000_000), Err(RecordError::UnauthorizedAuthor));
    }

    #[test]
    fn verify_rejects_a_tampered_field() {
        let author = author_addr();
        let mut rec = signed_record(&author, PRIV, 100);
        rec["body"] = json!("tampered after signing");
        assert_eq!(verify_record(&rec, &[author], 1_000_000), Err(RecordError::BadSignature));
    }

    #[test]
    fn verify_rejects_a_flipped_deleted_flag() {
        let author = author_addr();
        let mut rec = signed_record(&author, PRIV, 100);
        // Flip deleted true but keep the (now non-empty) body -> payload changes
        // AND the tombstone-body rule; both would reject. Empty the body so we
        // isolate the signature check.
        rec["deleted"] = json!(true);
        rec["body"] = json!("");
        assert_eq!(verify_record(&rec, &[author], 1_000_000), Err(RecordError::BadSignature));
    }

    #[test]
    fn verify_rejects_garbage_signature_without_panicking() {
        let author = author_addr();
        let mut rec = signed_record(&author, PRIV, 100);
        rec["sign"] = json!("!!!not base64!!!");
        assert_eq!(verify_record(&rec, &[author.clone()], 1_000_000), Err(RecordError::BadSignature));
        rec["sign"] = json!("YWJj"); // valid base64, wrong length
        assert_eq!(verify_record(&rec, &[author], 1_000_000), Err(RecordError::BadSignature));
    }

    #[test]
    fn verify_rejects_a_far_future_clock() {
        let author = author_addr();
        let rec = signed_record(&author, PRIV, 10_000_000);
        // now is well before the clock, beyond the skew bound.
        let now = 10_000_000 - CLOCK_SKEW_BOUND_MS - 1;
        assert_eq!(verify_record(&rec, &[author.clone()], now), Err(RecordError::ClockTooFarFuture));
        // exactly at the bound is allowed.
        assert_eq!(verify_record(&rec, &[author], 10_000_000 - CLOCK_SKEW_BOUND_MS), Ok(()));
    }

    #[test]
    fn verify_rejects_a_tombstone_with_a_body() {
        let author = author_addr();
        let nonce = "ff";
        let date_added = 1737331200_i64;
        let mut rec = json!({
            "post_id": derive_post_id(&author, nonce, date_added),
            "nonce": nonce, "author": author, "clock": 100_i64, "supersedes": 0,
            "deleted": true, "body": "should be empty", "date_added": date_added,
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), PRIV).unwrap());
        // Signature is valid, but a tombstone may not carry a body.
        assert_eq!(verify_record(&rec, &[author], 1_000_000), Err(RecordError::TombstoneHasBody));
    }

    #[test]
    fn moderation_tombstone_by_a_moderator_is_accepted() {
        // A moderator (a different key, but an authorized signer of the dir)
        // may tombstone the author's item when moderated:true + deleted:true.
        let author = author_addr();
        let mod_pk = "22b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let moderator = epix_crypt::privatekey_to_address(mod_pk).unwrap();
        let mut rec = json!({
            "post_id": 123_i64, "nonce": "n", "author": author, "clock": 9_i64,
            "supersedes": 1, "deleted": true, "moderated": true, "body": "",
            "date_added": 1737331200_i64,
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), mod_pk).unwrap());
        let signers = vec![author.clone(), moderator];
        assert_eq!(verify_record(&rec, &signers, 1_000_000), Ok(()));

        // A stranger (not an authorized signer) cannot forge a moderation tombstone.
        let stranger = "33b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let mut forged = json!({
            "post_id": 123_i64, "nonce": "n", "author": author, "clock": 9_i64,
            "supersedes": 1, "deleted": true, "moderated": true, "body": "",
            "date_added": 1737331200_i64,
        });
        forged["sign"] = json!(epix_crypt::sign(&record_signed_data(&forged), stranger).unwrap());
        assert_eq!(verify_record(&forged, &signers, 1_000_000), Err(RecordError::BadSignature));

        // moderated flag WITHOUT delete gets no relaxation - a moderator can't
        // edit another author's content, only tombstone it.
        let mut edit = json!({
            "post_id": 123_i64, "nonce": "n", "author": author, "clock": 9_i64,
            "supersedes": 1, "deleted": false, "moderated": true, "body": "rewritten",
            "date_added": 1737331200_i64,
        });
        edit["sign"] = json!(epix_crypt::sign(&record_signed_data(&edit), mod_pk).unwrap());
        assert_eq!(verify_record(&edit, &signers, 1_000_000), Err(RecordError::BadSignature));
    }

    #[test]
    fn verify_rejects_missing_fields() {
        let author = author_addr();
        let mut rec = signed_record(&author, PRIV, 100);
        rec.as_object_mut().unwrap().remove("author");
        assert_eq!(verify_record(&rec, &[author.clone()], 1_000_000), Err(RecordError::MissingField("author")));
        // Removing the nonce with no `key` present fails (need one id source).
        let mut rec2 = signed_record(&author, PRIV, 100);
        rec2.as_object_mut().unwrap().remove("nonce");
        assert_eq!(verify_record(&rec2, &[author], 1_000_000), Err(RecordError::MissingField("nonce-or-key")));
    }
}
