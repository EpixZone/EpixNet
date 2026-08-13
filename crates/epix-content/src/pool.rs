//! The anonymous sealed-envelope pool merge-file class `epix-pool-1`.
//!
//! Where [`crate::merge`]'s `epix-orset-1` is an *attributed* CRDT (every record
//! is signed by an authorized directory signer and carries `post_id`/`author`),
//! the pool is a **flat, anonymous, grow-only set of sealed envelopes**. Each
//! record is posted under a FRESH throwaway keypair (never the user's identity),
//! is size-padded, is timestamped only to the day, and carries no sender,
//! recipient, conversation id or sequence. Authorization is not an ACL check but
//! a **proof-of-work** over the record, so anyone may post but spam costs real
//! CPU. This is the substrate for metadata-private Epix Mail (see
//! `docs/channels.md`): the network cannot tell who sent an envelope, to
//! whom, or what it says — only the intended recipient's node, trial-decrypting
//! every envelope locally, can open the ones addressed to it.
//!
//! A container is `{ "record_format": "epix-pool-1", "env": [ <record>, … ] }`.
//! [`merge_pool`] unions the verified records of two containers (dedup by
//! signature) and, like the OR-Set, NEVER removes a version for being absent on
//! one side — a blank/partial container merges to a no-op. Pool records are
//! IMMUTABLE: there are no edits, tombstones, `post_id` grouping or supersede
//! logic (deletion is a purely local index action; the sealed record is never
//! recalled). The only removal is deterministic overflow eviction (§`merge_pool`).
//!
//! ## Record fields (exhaustive — unknown keys are rejected)
//!
//! | field    | type            | meaning |
//! |----------|-----------------|---------|
//! | `v`      | int (== 1)      | record version |
//! | `epoch`  | int             | days since the Unix epoch (day-granular time) |
//! | `tag`    | b64, 32 bytes   | detection tag (opaque to the network) |
//! | `ct`     | b64, bucket len | padded sealed ciphertext (a `pad_buckets` size) |
//! | `pow`    | int (u64 nonce) | proof-of-work nonce |
//! | `author` | epix1 address   | FRESH per-record ephemeral signer |
//! | `sign`   | b64             | recoverable ECDSA by `author` over the record |
//!
//! The signed payload is the record with ONLY `sign` removed, canonicalized by
//! the same [`record_signed_data`](crate::record::record_signed_data) used by
//! `epix-orset-1` — so `pow` is INSIDE the signed payload (solve-then-sign), and
//! one canonicalization pass serves both the PoW check and the signature check.

use crate::record::record_signed_data;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The container `record_format` marker for the pool class.
pub const POOL_RECORD_FORMAT: &str = "epix-pool-1";

/// The records array key inside a pool container (`"env"` for *envelopes*, kept
/// distinct from `epix-orset-1`'s `"post"` so the two classes never collide).
pub const POOL_RECORDS_KEY: &str = "env";

/// The exact, exhaustive field set of a pool record. Any other key is a covert
/// channel and rejected by [`verify_pool_record`].
const ALLOWED_FIELDS: &[&str] = &["v", "epoch", "tag", "ct", "pow", "author", "sign"];

/// The only record version this build accepts.
const POOL_RECORD_V: i64 = 1;

/// Milliseconds per day — the epoch quantum.
const MS_PER_DAY: i64 = 86_400_000;

/// Days per shard week.
const DAYS_PER_WEEK: i64 = 7;

/// Why a pool record failed admission. Every variant means "drop this record".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// The record is not a JSON object.
    NotObject,
    /// A key outside [`ALLOWED_FIELDS`] is present (no covert channel allowed).
    UnknownField(String),
    /// A required field is missing.
    MissingField(&'static str),
    /// `v` is not [`POOL_RECORD_V`].
    BadVersion,
    /// `tag` is not valid base64 of exactly 32 bytes.
    BadTag,
    /// `ct` is not valid base64, or its length is not one of `pad_buckets`.
    BadCiphertextSize,
    /// The canonical record exceeds `max_record_bytes`.
    RecordTooLarge,
    /// `epoch` does not fall in this shard's week.
    WrongShard,
    /// `epoch` is before the pool's `since_week`, or negative.
    EpochBeforeStart,
    /// `epoch` is further than one day into the future (replay / clock abuse).
    EpochInFuture,
    /// `sha256d(payload)` does not clear `pow_bits` leading zero bits.
    InsufficientPow,
    /// The signature does not recover to `author`.
    BadSignature,
}

/// The owner-signed pool descriptor from a xite's root content.json:
/// `"pool": { "<name>": { "dir", "class", "since_week", "fanout", "pow_bits",
/// "pad_buckets", "max_record_bytes", "max_shard_bytes" } }`. Parsed once and
/// carried on `AppState`; it governs every shard under `dir/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolRule {
    /// Directory the shards live under, relative to the xite root (e.g. `pool`).
    pub dir: String,
    /// The record class marker (`epix-pool-1`).
    pub class: String,
    /// The first week (see [`week_of`]) shards exist for; earlier epochs rejected.
    pub since_week: i64,
    /// Number of shards a week is split into by `tag[0] % fanout` (1..=256).
    pub fanout: u16,
    /// Required leading-zero bits of `sha256d(payload)` (anti-spam difficulty).
    pub pow_bits: u32,
    /// The exact permitted decoded `ct` lengths (padding buckets), sorted.
    pub pad_buckets: Vec<usize>,
    /// Max canonical bytes of a single record.
    pub max_record_bytes: usize,
    /// Soft cap on a shard file; overflow triggers deterministic eviction.
    pub max_shard_bytes: usize,
    /// Backfill traversal order. `true` (the default, descriptor
    /// `"sync_order": "newest_first"`) walks weeks newest→oldest so recent mail
    /// is delivered before older history is filled in; `false`
    /// (`"oldest_first"`) walks in chronological order. Live/current-week mail is
    /// never subject to this — it arrives via push and the current-week sweep.
    pub newest_first: bool,
}

impl PoolRule {
    /// Parse one entry of the `pool` descriptor. Returns `None` if `value` is
    /// not an object or is missing a required field / has an out-of-range one,
    /// so a malformed descriptor simply yields no pool (fail-closed).
    pub fn parse(value: &Value) -> Option<PoolRule> {
        let obj = value.as_object()?;
        let dir = obj.get("dir")?.as_str()?.trim_matches('/').to_string();
        if dir.is_empty() {
            return None;
        }
        let class = obj.get("class")?.as_str()?.to_string();
        if class != POOL_RECORD_FORMAT {
            return None;
        }
        let since_week = obj.get("since_week")?.as_i64()?;
        let fanout = obj.get("fanout")?.as_u64()?;
        if !(1..=256).contains(&fanout) {
            return None;
        }
        let pow_bits = obj.get("pow_bits")?.as_u64()?;
        if pow_bits > 240 {
            return None;
        }
        let mut pad_buckets: Vec<usize> = obj
            .get("pad_buckets")?
            .as_array()?
            .iter()
            .filter_map(|b| b.as_u64().map(|n| n as usize))
            .collect();
        pad_buckets.sort_unstable();
        pad_buckets.dedup();
        if pad_buckets.is_empty() {
            return None;
        }
        let max_record_bytes = obj.get("max_record_bytes")?.as_u64()? as usize;
        let max_shard_bytes = obj.get("max_shard_bytes")?.as_u64()? as usize;
        if max_record_bytes == 0 || max_shard_bytes == 0 {
            return None;
        }
        // Default to newest-first backfill; only an explicit "oldest_first" flips
        // it. An unknown value falls back to the default rather than failing.
        let newest_first =
            obj.get("sync_order").and_then(|v| v.as_str()) != Some("oldest_first");
        Some(PoolRule {
            dir,
            class,
            since_week,
            fanout: fanout as u16,
            pow_bits: pow_bits as u32,
            pad_buckets,
            max_record_bytes,
            max_shard_bytes,
            newest_first,
        })
    }
}

/// Parse the owner-signed `pool` descriptor of a (root) content.json into the
/// pool rules it declares. Malformed entries are skipped (fail-closed). The
/// descriptor shape is `"pool": { "<name>": { <PoolRule fields> }, … }`.
pub fn pool_rules_of(content: &Value) -> Vec<PoolRule> {
    content
        .get("pool")
        .and_then(|v| v.as_object())
        .map(|m| m.values().filter_map(PoolRule::parse).collect())
        .unwrap_or_default()
}

/// Whether `inner_path` falls under any declared pool directory. Used by both
/// content verification (no hashed/optional/merge file may live under a pool
/// dir) and the file-serving gate (pool shards are served, other paths are not).
pub fn is_under_pool_dir(rules: &[PoolRule], inner_path: &str) -> bool {
    rules.iter().any(|r| inner_path == r.dir || inner_path.starts_with(&format!("{}/", r.dir)))
}

// ---------------------------------------------------------------------------
// Epoch / shard math
// ---------------------------------------------------------------------------

/// The current epoch (days since the Unix epoch) for a wall-clock `now_ms`.
pub fn epoch_now(now_ms: i64) -> i64 {
    now_ms.div_euclid(MS_PER_DAY)
}

/// The shard week an `epoch` (day) belongs to.
pub fn week_of(epoch: i64) -> i64 {
    epoch.div_euclid(DAYS_PER_WEEK)
}

/// The shard sub-index for a 32-byte `tag` under `fanout`.
pub fn shard_sub(tag: &[u8], fanout: u16) -> u16 {
    let first = tag.first().copied().unwrap_or(0);
    (first as u16) % fanout.max(1)
}

/// The inner path of the shard a `(epoch, tag)` maps to: `<dir>/w<week>/<xx>.json`
/// with `xx` a two-hex-digit sub-index. Fully determined by the signed rule, so
/// a syncing node can enumerate every shard path and never reveals which one it
/// actually cares about.
pub fn shard_path(rule: &PoolRule, epoch: i64, tag: &[u8]) -> String {
    let week = week_of(epoch);
    let sub = shard_sub(tag, rule.fanout);
    format!("{}/w{}/{:02x}.json", rule.dir, week, sub)
}

/// Every shard path from `since_week` through `up_to_week` inclusive. The sync
/// sweep and backfill walk this list; because it is exhaustive, fetching any
/// shard signals nothing about the node's interests.
pub fn all_shard_paths(rule: &PoolRule, up_to_week: i64) -> Vec<String> {
    let mut paths = Vec::new();
    if up_to_week < rule.since_week {
        return paths;
    }
    for week in rule.since_week..=up_to_week {
        for sub in 0..rule.fanout {
            paths.push(format!("{}/w{}/{:02x}.json", rule.dir, week, sub));
        }
    }
    paths
}

/// Shard paths in the order the backfill sweep should fetch them, honoring the
/// rule's `newest_first` flag: newest week first (default) so recent mail is
/// delivered before older history, or chronological if the descriptor set
/// `"sync_order": "oldest_first"`. Within a week the `fanout` shards are listed
/// in sub-index order (the sweep fetches them in parallel regardless).
pub fn sync_shard_paths(rule: &PoolRule, up_to_week: i64) -> Vec<String> {
    if up_to_week < rule.since_week {
        return Vec::new();
    }
    let weeks: Vec<i64> = if rule.newest_first {
        (rule.since_week..=up_to_week).rev().collect()
    } else {
        (rule.since_week..=up_to_week).collect()
    };
    let mut paths = Vec::with_capacity(weeks.len() * rule.fanout as usize);
    for week in weeks {
        for sub in 0..rule.fanout {
            paths.push(format!("{}/w{}/{:02x}.json", rule.dir, week, sub));
        }
    }
    paths
}

/// Parse `<dir>/w<week>/<sub>.json` back to `(week, sub)`, validating it belongs
/// to `rule`. Used by the serve/write path to confirm an inner_path is a shard.
pub fn parse_shard_path(rule: &PoolRule, inner_path: &str) -> Option<(i64, u16)> {
    let rest = inner_path.strip_prefix(&format!("{}/w", rule.dir))?;
    let (week_str, file) = rest.split_once('/')?;
    let week: i64 = week_str.parse().ok()?;
    if week < rule.since_week {
        return None;
    }
    let sub_str = file.strip_suffix(".json")?;
    let sub = u16::from_str_radix(sub_str, 16).ok()?;
    if sub >= rule.fanout {
        return None;
    }
    Some((week, sub))
}

// ---------------------------------------------------------------------------
// Container helpers
// ---------------------------------------------------------------------------

/// The records array of a pool container (empty if absent/malformed).
pub fn pool_records_of(container: &Value) -> Vec<Value> {
    container
        .get(POOL_RECORDS_KEY)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Wrap records into a canonical pool container.
pub fn make_pool_container(records: Vec<Value>) -> Value {
    json!({ "record_format": POOL_RECORD_FORMAT, POOL_RECORDS_KEY: records })
}

fn sign_of(r: &Value) -> &str {
    r.get("sign").and_then(|v| v.as_str()).unwrap_or("")
}
fn epoch_of(r: &Value) -> i64 {
    r.get("epoch").and_then(|v| v.as_i64()).unwrap_or(0)
}
fn tag_str_of(r: &Value) -> &str {
    r.get("tag").and_then(|v| v.as_str()).unwrap_or("")
}

/// Deterministic on-disk order: `(epoch, tag, sign)`. Ordering by tag (not
/// arrival) means a node syncing a sealed week later learns nothing about the
/// order envelopes were actually sent in.
fn sort_records(records: &mut [Value]) {
    records.sort_by(|a, b| {
        epoch_of(a)
            .cmp(&epoch_of(b))
            .then_with(|| tag_str_of(a).cmp(tag_str_of(b)))
            .then_with(|| sign_of(a).cmp(sign_of(b)))
    });
}

// ---------------------------------------------------------------------------
// Proof of work
// ---------------------------------------------------------------------------

/// `sha256(sha256(data))`.
fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data.as_ref());
    let second = Sha256::digest(first.as_slice());
    second.into()
}

/// Leading zero bits of a byte string (big-endian).
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in bytes {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Whether a canonical `payload` clears `pow_bits` leading zero bits of its
/// double-SHA256. This is the anti-spam admission gate that replaces the OR-Set's
/// authorized-signer ACL — anyone may author a record, but only after burning
/// the required work.
pub fn meets_pow(payload: &str, pow_bits: u32) -> bool {
    leading_zero_bits(&sha256d(payload.as_bytes())) >= pow_bits
}

/// Solve the proof of work for a record in place: try `pow` nonces until
/// `sha256d(record_signed_data(record))` clears `pow_bits`, set `record["pow"]`
/// to the winning nonce, and return it. The caller signs AFTER this (the
/// signature is excluded from the payload, so solving is stable). Reference
/// implementation; a hot-path solver may splice the nonce over a cached
/// canonical prefix instead of re-serializing each attempt.
pub fn solve_pow(record: &mut Value, pow_bits: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        record["pow"] = json!(nonce);
        if meets_pow(&record_signed_data(record), pow_bits) {
            return nonce;
        }
        nonce += 1;
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a single inbound pool record for the shard at `shard_week`.
///
/// Admission rules (all must hold):
/// 1. object; exactly [`ALLOWED_FIELDS`] present (no unknown keys);
/// 2. `v == 1`;
/// 3. `tag` decodes to 32 bytes;
/// 4. `ct` decodes to a length in `rule.pad_buckets`;
/// 5. canonical record ≤ `rule.max_record_bytes`;
/// 6. `week_of(epoch) == shard_week`, `week_of(epoch) >= since_week`, and
///    `epoch <= epoch_now(now_ms) + 1` (binds record→shard, kills cross-shard
///    and cross-epoch replay);
/// 7. `sha256d(payload)` clears `rule.pow_bits`;
/// 8. `sign` recovers to `author`.
pub fn verify_pool_record(
    record: &Value,
    rule: &PoolRule,
    shard_week: i64,
    now_ms: i64,
) -> Result<(), PoolError> {
    let obj = record.as_object().ok_or(PoolError::NotObject)?;

    // 1. exact field set — reject any covert extra key.
    for key in obj.keys() {
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(PoolError::UnknownField(key.clone()));
        }
    }

    // 2. version
    let v = obj.get("v").and_then(|x| x.as_i64()).ok_or(PoolError::MissingField("v"))?;
    if v != POOL_RECORD_V {
        return Err(PoolError::BadVersion);
    }

    let epoch =
        obj.get("epoch").and_then(|x| x.as_i64()).ok_or(PoolError::MissingField("epoch"))?;
    let tag_b64 =
        obj.get("tag").and_then(|x| x.as_str()).ok_or(PoolError::MissingField("tag"))?;
    let ct_b64 = obj.get("ct").and_then(|x| x.as_str()).ok_or(PoolError::MissingField("ct"))?;
    obj.get("pow").and_then(|x| x.as_u64()).ok_or(PoolError::MissingField("pow"))?;
    let author =
        obj.get("author").and_then(|x| x.as_str()).ok_or(PoolError::MissingField("author"))?;
    let sign =
        obj.get("sign").and_then(|x| x.as_str()).ok_or(PoolError::MissingField("sign"))?;

    // 3. tag = 32 bytes
    let tag = base64::engine::general_purpose::STANDARD
        .decode(tag_b64)
        .map_err(|_| PoolError::BadTag)?;
    if tag.len() != 32 {
        return Err(PoolError::BadTag);
    }

    // 4. ciphertext length ∈ buckets
    let ct = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .map_err(|_| PoolError::BadCiphertextSize)?;
    if !rule.pad_buckets.contains(&ct.len()) {
        return Err(PoolError::BadCiphertextSize);
    }

    // 5. record size cap (canonical payload + the sign field's bytes are what
    //    lands on disk; bound the whole record to keep shards predictable).
    let payload = record_signed_data(record);
    if payload.len() > rule.max_record_bytes {
        return Err(PoolError::RecordTooLarge);
    }

    // 6. epoch/shard binding
    let week = week_of(epoch);
    if epoch < 0 || week < rule.since_week {
        return Err(PoolError::EpochBeforeStart);
    }
    if week != shard_week {
        return Err(PoolError::WrongShard);
    }
    if epoch > epoch_now(now_ms) + 1 {
        return Err(PoolError::EpochInFuture);
    }

    // 7. proof of work
    if !meets_pow(&payload, rule.pow_bits) {
        return Err(PoolError::InsufficientPow);
    }

    // 8. self-signature (recovers to `author` under dbl or keccak scheme; a
    //    garbage signature fails both, never panics).
    if epix_crypt::verify(&payload, author, sign)
        || epix_crypt::verify_keccak(&payload, author, sign)
    {
        Ok(())
    } else {
        Err(PoolError::BadSignature)
    }
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

/// The serialized byte length of a set of records as a canonical pool container
/// (the measure the shard cap is enforced against).
fn container_len(records: &[Value]) -> usize {
    crate::canonical::dumps_sorted(&make_pool_container(records.to_vec())).len()
}

/// Merge two pool containers into the union of their VERIFIED records for
/// `shard_week`, deduped by signature. Grow-only, commutative and idempotent:
/// a version absent on one side is never dropped for that reason. Every record
/// (local and inbound) is re-verified, so a poisoned on-disk shard cannot smuggle
/// a forged/under-powered record through a merge.
///
/// Returns `(merged_container, delta)` where `delta` is the records now present
/// that were NOT in `local` — exactly what the indexer must trial-decrypt and
/// what a live push must re-flood, so neither ever rescans a whole shard.
///
/// **Overflow eviction:** if the union exceeds `rule.max_shard_bytes`, records
/// are kept in ascending `sha256d(payload)` order (most proof-of-work first) and
/// the tail is dropped until the shard fits. This is deterministic on the union,
/// so every honest node converges on the same survivors, and it makes flooding a
/// shard cost genuine work rather than displacing others cheaply. Eviction is an
/// emergency valve only; the operational lever is raising `fanout`/`pow_bits`.
pub fn merge_pool(
    local: &Value,
    inbound: &Value,
    rule: &PoolRule,
    shard_week: i64,
    now_ms: i64,
) -> (Value, Vec<Value>) {
    use std::collections::BTreeMap;

    let local_signs: std::collections::BTreeSet<String> =
        pool_records_of(local).iter().map(|r| sign_of(r).to_string()).collect();

    let mut by_sign: BTreeMap<String, Value> = BTreeMap::new();
    for r in pool_records_of(local).into_iter().chain(pool_records_of(inbound)) {
        if verify_pool_record(&r, rule, shard_week, now_ms).is_err() {
            continue;
        }
        let sig = sign_of(&r).to_string();
        if sig.is_empty() {
            continue;
        }
        by_sign.entry(sig).or_insert(r);
    }

    let mut records: Vec<Value> = by_sign.into_values().collect();

    // Deterministic overflow eviction (rare): keep the highest-work records.
    if container_len(&records) > rule.max_shard_bytes {
        records.sort_by(|a, b| {
            let ha = sha256d(record_signed_data(a).as_bytes());
            let hb = sha256d(record_signed_data(b).as_bytes());
            ha.cmp(&hb).then_with(|| sign_of(a).cmp(sign_of(b)))
        });
        while records.len() > 1 && container_len(&records) > rule.max_shard_bytes {
            records.pop();
        }
    }

    sort_records(&mut records);

    let delta: Vec<Value> =
        records.iter().filter(|r| !local_signs.contains(sign_of(r))).cloned().collect();

    (make_pool_container(records), delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> PoolRule {
        PoolRule {
            dir: "pool".into(),
            class: POOL_RECORD_FORMAT.into(),
            since_week: 0,
            fanout: 16,
            pow_bits: 8, // cheap for tests
            pad_buckets: vec![64, 128, 256],
            max_record_bytes: 4096,
            max_shard_bytes: 1_000_000,
            newest_first: true,
        }
    }

    // A random 32-byte tag, base64. Generated at runtime (CodeQL flags literal
    // crypto values even in tests). `seed` varies the value per call.
    fn tag_b64(seed: u8) -> String {
        let mut t = [0u8; 32];
        // fill deterministically from the seed so shard routing is predictable
        for (i, b) in t.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        base64::engine::general_purpose::STANDARD.encode(t)
    }

    fn ct_b64(len: usize, fill: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode(vec![fill; len])
    }

    /// Build a fully valid pool record for `epoch` with a fresh ephemeral author:
    /// solve PoW, then sign. `tag_seed`/`ct_fill` vary the content.
    fn valid_record(epoch: i64, tag_seed: u8, ct_len: usize, ct_fill: u8) -> Value {
        let pk = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&pk).unwrap();
        let mut rec = json!({
            "v": 1,
            "epoch": epoch,
            "tag": tag_b64(tag_seed),
            "ct": ct_b64(ct_len, ct_fill),
            "pow": 0,
            "author": author,
        });
        solve_pow(&mut rec, 8);
        let sig = epix_crypt::sign(&record_signed_data(&rec), &pk).unwrap();
        rec["sign"] = json!(sig);
        rec
    }

    // now_ms for an epoch's own day (so `epoch <= today+1` holds).
    fn now_for(epoch: i64) -> i64 {
        epoch * MS_PER_DAY + 1
    }

    #[test]
    fn epoch_and_week_math() {
        assert_eq!(epoch_now(0), 0);
        assert_eq!(epoch_now(MS_PER_DAY - 1), 0);
        assert_eq!(epoch_now(MS_PER_DAY), 1);
        assert_eq!(week_of(0), 0);
        assert_eq!(week_of(6), 0);
        assert_eq!(week_of(7), 1);
        assert_eq!(week_of(13), 1);
    }

    #[test]
    fn shard_path_roundtrips() {
        let r = rule();
        let tag = base64::engine::general_purpose::STANDARD.decode(tag_b64(3)).unwrap();
        let epoch = 100;
        let p = shard_path(&r, epoch, &tag);
        let (week, sub) = parse_shard_path(&r, &p).expect("parses back");
        assert_eq!(week, week_of(epoch));
        assert_eq!(sub, shard_sub(&tag, r.fanout));
        assert!(p.starts_with("pool/w"));
    }

    #[test]
    fn all_shard_paths_are_exhaustive() {
        let r = rule();
        let paths = all_shard_paths(&r, 1); // weeks 0 and 1
        assert_eq!(paths.len(), 2 * r.fanout as usize);
        assert!(paths.contains(&"pool/w0/00.json".to_string()));
        assert!(paths.contains(&"pool/w1/0f.json".to_string()));
        assert!(all_shard_paths(&r, -1).is_empty());
    }

    #[test]
    fn parse_rejects_bad_descriptor() {
        assert!(PoolRule::parse(&json!({"dir": "pool"})).is_none()); // missing fields
        assert!(PoolRule::parse(&json!({
            "dir": "pool", "class": "epix-orset-1", "since_week": 0, "fanout": 16,
            "pow_bits": 8, "pad_buckets": [64], "max_record_bytes": 100, "max_shard_bytes": 100
        }))
        .is_none()); // wrong class
        assert!(PoolRule::parse(&json!({
            "dir": "pool", "class": POOL_RECORD_FORMAT, "since_week": 0, "fanout": 0,
            "pow_bits": 8, "pad_buckets": [64], "max_record_bytes": 100, "max_shard_bytes": 100
        }))
        .is_none()); // fanout out of range
        let ok = PoolRule::parse(&json!({
            "dir": "pool/", "class": POOL_RECORD_FORMAT, "since_week": 5, "fanout": 16,
            "pow_bits": 22, "pad_buckets": [256, 64, 64, 128], "max_record_bytes": 45000,
            "max_shard_bytes": 6000000
        }))
        .expect("valid descriptor parses");
        assert_eq!(ok.dir, "pool");
        assert_eq!(ok.pad_buckets, vec![64, 128, 256]); // sorted + deduped
        assert!(ok.newest_first, "defaults to newest-first backfill");

        // Explicit oldest_first flips the flag.
        let oldest = PoolRule::parse(&json!({
            "dir": "pool", "class": POOL_RECORD_FORMAT, "since_week": 0, "fanout": 4,
            "pow_bits": 8, "pad_buckets": [64], "max_record_bytes": 100,
            "max_shard_bytes": 100, "sync_order": "oldest_first"
        }))
        .unwrap();
        assert!(!oldest.newest_first);
    }

    #[test]
    fn pool_rules_and_dir_membership() {
        let content = json!({
            "pool": {
                "mail": {
                    "dir": "pool", "class": POOL_RECORD_FORMAT, "since_week": 0, "fanout": 16,
                    "pow_bits": 8, "pad_buckets": [64], "max_record_bytes": 100,
                    "max_shard_bytes": 100
                }
            }
        });
        let rules = pool_rules_of(&content);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].dir, "pool");
        assert!(is_under_pool_dir(&rules, "pool"));
        assert!(is_under_pool_dir(&rules, "pool/w3/0a.json"));
        assert!(!is_under_pool_dir(&rules, "poolside/x.json"));
        assert!(!is_under_pool_dir(&rules, "data/users/mud.epix/data.json"));
        assert!(pool_rules_of(&json!({})).is_empty());
    }

    #[test]
    fn sync_order_controls_backfill_direction() {
        let mut r = rule();
        r.fanout = 1; // one shard per week, so week order is obvious
        // weeks 0..=2, newest-first default
        let newest = sync_shard_paths(&r, 2);
        assert_eq!(newest, vec!["pool/w2/00.json", "pool/w1/00.json", "pool/w0/00.json"]);
        r.newest_first = false;
        let oldest = sync_shard_paths(&r, 2);
        assert_eq!(oldest, vec!["pool/w0/00.json", "pool/w1/00.json", "pool/w2/00.json"]);
    }

    #[test]
    fn verify_accepts_a_valid_record() {
        let r = rule();
        let epoch = 100;
        let rec = valid_record(epoch, 1, 128, 7);
        assert_eq!(verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)), Ok(()));
    }

    #[test]
    fn verify_rejects_unknown_field() {
        let r = rule();
        let epoch = 100;
        let mut rec = valid_record(epoch, 1, 128, 7);
        rec["leak"] = json!("who=mud.epix"); // a covert channel
        assert!(matches!(
            verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::UnknownField(_))
        ));
    }

    #[test]
    fn verify_rejects_bad_tag_length() {
        let r = rule();
        let epoch = 100;
        let mut rec = valid_record(epoch, 1, 128, 7);
        rec["tag"] = json!(base64::engine::general_purpose::STANDARD.encode([0u8; 16]));
        // signature/pow now stale too, but the tag check fires first.
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::BadTag)
        );
    }

    #[test]
    fn verify_rejects_non_bucket_ciphertext() {
        let r = rule();
        let epoch = 100;
        let pk = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&pk).unwrap();
        let mut rec = json!({
            "v": 1, "epoch": epoch, "tag": tag_b64(2),
            "ct": ct_b64(100, 3), // 100 ∉ {64,128,256}
            "pow": 0, "author": author,
        });
        solve_pow(&mut rec, 8);
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), &pk).unwrap());
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::BadCiphertextSize)
        );
    }

    #[test]
    fn verify_rejects_wrong_shard_week() {
        let r = rule();
        let epoch = 100; // week 14
        let rec = valid_record(epoch, 1, 128, 7);
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch) + 1, now_for(epoch)),
            Err(PoolError::WrongShard)
        );
    }

    #[test]
    fn verify_rejects_future_epoch() {
        let r = rule();
        let epoch = 100;
        let rec = valid_record(epoch, 1, 128, 7);
        // "now" is two days before the record's epoch => beyond today+1.
        let now = (epoch - 2) * MS_PER_DAY + 1;
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch), now),
            Err(PoolError::EpochInFuture)
        );
    }

    #[test]
    fn verify_rejects_epoch_before_since_week() {
        let mut r = rule();
        r.since_week = 20; // shards start at week 20
        let epoch = 100; // week 14 < 20
        let rec = valid_record(epoch, 1, 128, 7);
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::EpochBeforeStart)
        );
    }

    #[test]
    fn verify_rejects_insufficient_pow() {
        let mut r = rule();
        r.pow_bits = 24; // record was solved for only 8 bits
        let epoch = 100;
        let rec = valid_record(epoch, 1, 128, 7);
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::InsufficientPow)
        );
    }

    #[test]
    fn verify_rejects_tampered_ciphertext() {
        let r = rule();
        let epoch = 100;
        let mut rec = valid_record(epoch, 1, 128, 7);
        // Flip the ciphertext after signing: payload changes -> sig no longer
        // recovers to author (and PoW is stale, but the size/shape still pass to
        // reach the signature check).
        rec["ct"] = json!(ct_b64(128, 9));
        let res = verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch));
        assert!(matches!(res, Err(PoolError::InsufficientPow) | Err(PoolError::BadSignature)));
    }

    #[test]
    fn verify_rejects_forged_signature() {
        let r = rule();
        let epoch = 100;
        let mut rec = valid_record(epoch, 1, 128, 7);
        rec["sign"] = json!("!!!not-base64!!!");
        assert_eq!(
            verify_pool_record(&rec, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::BadSignature)
        );
    }

    #[test]
    fn merge_is_commutative_idempotent_and_returns_delta() {
        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let a = valid_record(epoch, 1, 128, 1);
        let b = valid_record(epoch, 2, 128, 2);

        let local = make_pool_container(vec![a.clone()]);
        let inbound = make_pool_container(vec![b.clone()]);

        let (ab, delta_ab) = merge_pool(&local, &inbound, &r, week, now);
        let (ba, _) = merge_pool(&inbound, &local, &r, week, now);
        assert_eq!(ab, ba, "commutative");
        // delta is exactly what's new to `local` (record b).
        assert_eq!(delta_ab.len(), 1);
        assert_eq!(sign_of(&delta_ab[0]), sign_of(&b));

        // idempotent: merging the same inbound again yields no new delta.
        let (ab2, delta2) = merge_pool(&ab, &inbound, &r, week, now);
        assert_eq!(ab2, ab, "idempotent");
        assert!(delta2.is_empty(), "no new records the second time");
    }

    #[test]
    fn absence_is_not_deletion() {
        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let keep = valid_record(epoch, 1, 128, 1);
        let local = make_pool_container(vec![keep.clone()]);
        let blank = make_pool_container(vec![]);
        let (merged, delta) = merge_pool(&local, &blank, &r, week, now);
        assert_eq!(pool_records_of(&merged).len(), 1, "blank inbound removes nothing");
        assert!(delta.is_empty());
    }

    #[test]
    fn merge_drops_forged_and_underpowered_records() {
        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let good = valid_record(epoch, 1, 128, 1);

        // An under-powered record (solved for 0 bits only; likely < 8 leading
        // zero bits) that also carries a valid self-signature.
        let pk = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&pk).unwrap();
        let mut weak = json!({
            "v": 1, "epoch": epoch, "tag": tag_b64(9), "ct": ct_b64(128, 5),
            "pow": 0, "author": author,
        });
        // do NOT solve pow; sign as-is
        weak["sign"] = json!(epix_crypt::sign(&record_signed_data(&weak), &pk).unwrap());
        // Only count this test meaningful if the weak record indeed fails pow.
        let weak_fails = !meets_pow(&record_signed_data(&weak), r.pow_bits);

        let (merged, _) = merge_pool(
            &make_pool_container(vec![good.clone()]),
            &make_pool_container(vec![weak]),
            &r,
            week,
            now,
        );
        let expected = if weak_fails { 1 } else { 2 };
        assert_eq!(pool_records_of(&merged).len(), expected);
        assert!(pool_records_of(&merged).iter().any(|x| sign_of(x) == sign_of(&good)));
    }

    #[test]
    fn overflow_eviction_is_deterministic_and_convergent() {
        let mut r = rule();
        r.max_shard_bytes = 900; // tiny: forces eviction with a few records
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let recs: Vec<Value> = (0..6).map(|i| valid_record(epoch, i as u8 + 1, 64, i as u8)).collect();

        // Merge in two different orders; survivors must match byte-for-byte.
        let mut c1 = make_pool_container(vec![]);
        for rec in &recs {
            let (m, _) = merge_pool(&c1, &make_pool_container(vec![rec.clone()]), &r, week, now);
            c1 = m;
        }
        let mut c2 = make_pool_container(vec![]);
        for rec in recs.iter().rev() {
            let (m, _) = merge_pool(&c2, &make_pool_container(vec![rec.clone()]), &r, week, now);
            c2 = m;
        }
        assert_eq!(c1, c2, "eviction converges regardless of arrival order");
        assert!(container_len(&pool_records_of(&c1)) <= r.max_shard_bytes);
        assert!(!pool_records_of(&c1).is_empty(), "keeps at least the highest-work record");
    }

    #[test]
    fn records_sorted_by_epoch_then_tag_not_arrival() {
        let r = rule();
        let now = now_for(102);
        // three records across two epochs, inserted out of order
        let e1 = valid_record(100, 5, 64, 1);
        let e2 = valid_record(100, 1, 64, 2);
        let e3 = valid_record(101, 3, 64, 3);
        let (merged, _) = {
            let mut c = make_pool_container(vec![]);
            for rec in [e3.clone(), e1.clone(), e2.clone()] {
                let (m, _) = merge_pool(&c, &make_pool_container(vec![rec]), &r, week_of(100), now);
                c = m;
            }
            (c, ())
        };
        let out = pool_records_of(&merged);
        // epoch ascending; within epoch 100, tag ascending (seed 1 < seed 5).
        let epochs: Vec<i64> = out.iter().map(epoch_of).collect();
        let mut sorted = epochs.clone();
        sorted.sort();
        assert_eq!(epochs, sorted, "on-disk order is by epoch, not arrival");
    }
}
