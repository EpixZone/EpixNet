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
//! signed payload) and, like the OR-Set, NEVER removes a version for being absent on
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
use std::collections::{BTreeMap, BTreeSet};

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

/// Upper bound on the decoded `rln` proof blob. An RLN Groth16 proof plus its
/// public values serializes to a few hundred bytes; this is generous headroom.
const MAX_RLN_PROOF_BYTES: usize = 1024;

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
    /// The pool requires an RLN proof (`rln_required`) but the record has none.
    MissingRlnProof,
    /// The `rln` field is not valid base64, is empty, or exceeds the size cap.
    /// Only its shape is checked here; the zk proof is verified at the node's
    /// ingest seam, where the membership root and the RLN verifier are available.
    BadRlnProof,
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
    /// Whether records must carry a valid RLN proof (the `rln` field) to be
    /// admitted (anonymous rate limiting). [`verify_pool_record`] checks the
    /// field's presence and shape; the zk proof itself is verified by the node
    /// against the membership root (see the `epix-rln` crate). Absent or
    /// `false` means PoW-only admission.
    pub rln_required: bool,
    /// Weeks of pool history to keep before old shards are pruned from disk. `0`
    /// (the default, or an absent `retention_weeks`) keeps everything forever.
    /// Owner-set per xite via content.json, so each xite picks the policy that
    /// fits its function (ephemeral chat, longer-lived mail, archival forum).
    pub retention_weeks: i64,
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
        let declared_max_shard_bytes = obj.get("max_shard_bytes")?.as_u64()? as usize;
        if max_record_bytes == 0 || declared_max_shard_bytes == 0 {
            return None;
        }
        // A shard bigger than the signed-object serve cap can never be fetched or
        // union-swept (`get_signed` refuses it), so the pool would silently stop
        // propagating. Clamp eviction to keep every shard servable, whatever the
        // owner declared. Mirrors `epix_edx::fetch::MAX_SIGNED_BYTES` (8 MiB).
        const MAX_SERVE_BYTES: usize = 8 << 20;
        let max_shard_bytes = declared_max_shard_bytes.min(MAX_SERVE_BYTES);
        if max_shard_bytes < crate::canonical::dumps_sorted(&make_pool_container(Vec::new())).len()
        {
            return None;
        }
        // Default to newest-first backfill; only an explicit "oldest_first" flips
        // it. An unknown value falls back to the default rather than failing.
        let newest_first =
            obj.get("sync_order").and_then(|v| v.as_str()) != Some("oldest_first");
        // RLN admission is opt-in per pool; absent/false means PoW-only.
        let rln_required = obj.get("rln_required").and_then(|v| v.as_bool()).unwrap_or(false);
        // Retention is opt-in per pool; absent/<=0 means keep forever.
        let retention_weeks =
            obj.get("retention_weeks").and_then(|v| v.as_i64()).filter(|&n| n > 0).unwrap_or(0);
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
            rln_required,
            retention_weeks,
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

/// The oldest week to KEEP under `rule`'s retention, given the current week, or
/// `None` for indefinite retention (`retention_weeks <= 0`). Shards for weeks
/// strictly older than the returned value are expired and may be pruned.
pub fn retention_keep_from(rule: &PoolRule, cur_week: i64) -> Option<i64> {
    if rule.retention_weeks <= 0 {
        None
    } else {
        Some(cur_week - rule.retention_weeks + 1)
    }
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
    // Require the CANONICAL spelling `shard_path` emits — reject leading zeros, a
    // '+' sign, whitespace, or uppercase hex. Otherwise unboundedly many distinct
    // strings map to one logical shard, which defeats per-shard serialization (two
    // spellings take different locks) and lets a peer allocate unbounded per-path
    // state.
    if week_str != week.to_string() || sub_str != format!("{sub:02x}") {
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
    let first = Sha256::digest(data);
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

/// Immutable logical identity of one sealed pool message. Transport
/// representations may change `pow`, `rln`, and `sign` while recovering a
/// durable outbox row, but the ciphertext, routing tag, epoch, and anonymous
/// author stay fixed. Deduping on this tuple prevents a re-proof/re-PoW from
/// delivering the same logical message twice.
pub fn logical_record_data(record: &Value) -> String {
    crate::canonical::dumps_sorted(&json!({
        "v": record.get("v").cloned().unwrap_or(Value::Null),
        "epoch": record.get("epoch").cloned().unwrap_or(Value::Null),
        "tag": record.get("tag").cloned().unwrap_or(Value::Null),
        "ct": record.get("ct").cloned().unwrap_or(Value::Null),
        "author": record.get("author").cloned().unwrap_or(Value::Null),
    }))
}

pub fn record_work_bits(record: &Value) -> u32 {
    leading_zero_bits(&sha256d(record_signed_data(record).as_bytes()))
}

pub fn rln_reservation_id(epoch: i64, ct: &[u8]) -> [u8; 32] {
    let mut material = b"epix-rln-outbox-reservation-v1\0".to_vec();
    material.extend_from_slice(&epoch.to_be_bytes());
    material.extend_from_slice(ct);
    Sha256::digest(material).into()
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
///
/// Step 1: exactly [`ALLOWED_FIELDS`] present. The optional `rln` proof field
/// is permitted only where the pool rule requires RLN admission.
fn check_field_set(
    obj: &serde_json::Map<String, Value>,
    rule: &PoolRule,
) -> Result<(), PoolError> {
    for key in obj.keys() {
        if ALLOWED_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if key == "rln" && rule.rln_required {
            continue;
        }
        return Err(PoolError::UnknownField(key.clone()));
    }
    Ok(())
}

/// Step 4b: a well-formed, size-bounded RLN proof blob, only where the pool
/// requires one (a no-op otherwise).
fn check_rln_proof(
    obj: &serde_json::Map<String, Value>,
    rule: &PoolRule,
) -> Result<(), PoolError> {
    if !rule.rln_required {
        return Ok(());
    }
    let rln_b64 = obj.get("rln").and_then(|x| x.as_str()).ok_or(PoolError::MissingRlnProof)?;
    let rln = base64::engine::general_purpose::STANDARD
        .decode(rln_b64)
        .map_err(|_| PoolError::BadRlnProof)?;
    if rln.is_empty() || rln.len() > MAX_RLN_PROOF_BYTES {
        return Err(PoolError::BadRlnProof);
    }
    Ok(())
}

/// Step 6: epoch↔shard binding plus the cross-epoch replay guard.
fn check_epoch_shard(
    epoch: i64,
    rule: &PoolRule,
    shard_week: i64,
    now_ms: i64,
) -> Result<(), PoolError> {
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
    Ok(())
}

pub fn verify_pool_record(
    record: &Value,
    rule: &PoolRule,
    shard_week: i64,
    now_ms: i64,
) -> Result<(), PoolError> {
    let obj = record.as_object().ok_or(PoolError::NotObject)?;

    // 1. exact field set — reject any covert extra key.
    check_field_set(obj, rule)?;

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

    // 4b. RLN proof shape (only where the pool requires it). The zk proof binds
    //     to `ct` + `epoch` and is verified by the node against the membership
    //     root; here we only ensure a well-formed, size-bounded blob is present.
    //     The `rln` field is part of `record_signed_data`, so PoW and the
    //     record signature cover it like every other field.
    check_rln_proof(obj, rule)?;

    // 5. record size cap (canonical payload + the sign field's bytes are what
    //    lands on disk; bound the whole record to keep shards predictable).
    let payload = record_signed_data(record);
    if payload.len() > rule.max_record_bytes {
        return Err(PoolError::RecordTooLarge);
    }

    // 6. epoch/shard binding
    check_epoch_shard(epoch, rule, shard_week, now_ms)?;

    // 7. proof of work
    if !meets_pow(&payload, rule.pow_bits) {
        return Err(PoolError::InsufficientPow);
    }

    // 8. self-signature (recovers to `author` under dbl or keccak scheme; a
    //    garbage signature fails both, never panics).
    if !epix_crypt::is_canonical_recoverable_signature(sign) {
        return Err(PoolError::BadSignature);
    }
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
/// `shard_week`, deduped by canonical signed payload. Grow-only, commutative and idempotent:
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
    shard_sub: u16,
    now_ms: i64,
) -> (Value, Vec<Value>) {
    let local_ids = verified_local_ids(local, rule, shard_week, shard_sub, now_ms);

    // Bind the record to this shard's SUB-index too. `verify_pool_record`
    // binds only the week; without this an attacker could copy valid records
    // from OTHER subs (no fresh PoW needed) into one shard, inflate it past
    // `max_shard_bytes`, and force eviction of the genuine records addressed
    // to that sub. A record only ever belongs in `shard_sub(tag, fanout)`.
    let mut records = collect_merge_records(local, inbound, rule, shard_week, shard_sub, now_ms);

    // Deterministic overflow eviction (rare): keep the highest-work records.
    evict_overflow(&mut records, rule.max_shard_bytes);

    sort_records(&mut records);

    let delta: Vec<Value> = records
        .iter()
        .filter(|record| !local_ids.contains(&pool_payload_id(record)))
        .cloned()
        .collect();

    (make_pool_container(records), delta)
}

fn pool_payload_id(record: &Value) -> [u8; 32] {
    sha256d(logical_record_data(record).as_bytes())
}

fn record_routes_to_sub(record: &Value, rule: &PoolRule, shard_sub: u16) -> bool {
    record
        .get("tag")
        .and_then(|tag| tag.as_str())
        .and_then(|tag| base64::engine::general_purpose::STANDARD.decode(tag).ok())
        .map(|tag| crate::pool::shard_sub(&tag, rule.fanout) == shard_sub)
        .unwrap_or(false)
}

fn verified_local_ids(
    local: &Value,
    rule: &PoolRule,
    shard_week: i64,
    shard_sub: u16,
    now_ms: i64,
) -> BTreeSet<[u8; 32]> {
    pool_records_of(local)
        .into_iter()
        .filter(|record| {
            record_routes_to_sub(record, rule, shard_sub)
                && verify_pool_record(record, rule, shard_week, now_ms).is_ok()
        })
        .map(|record| pool_payload_id(&record))
        .collect()
}

fn is_merge_candidate(
    record: &Value,
    rule: &PoolRule,
    shard_week: i64,
    shard_sub: u16,
    now_ms: i64,
) -> bool {
    verify_pool_record(record, rule, shard_week, now_ms).is_ok()
        && record_routes_to_sub(record, rule, shard_sub)
        && !sign_of(record).is_empty()
}

fn collect_merge_records(
    local: &Value,
    inbound: &Value,
    rule: &PoolRule,
    shard_week: i64,
    shard_sub: u16,
    now_ms: i64,
) -> Vec<Value> {
    let mut by_payload: BTreeMap<[u8; 32], Value> = BTreeMap::new();
    let records = pool_records_of(local)
        .into_iter()
        .chain(pool_records_of(inbound))
        .filter(|record| is_merge_candidate(record, rule, shard_week, shard_sub, now_ms));
    for record in records {
        // A Bitcoin compact recovery header has an optional +4 compressed-key
        // flag. Both encodings recover the same author and cover the same
        // payload. Keying by raw signature would let an observer toggle that
        // unauthenticated flag and occupy a second shard entry. Keep one record
        // per signed payload and choose the lexicographically smaller signature
        // so partitions converge regardless of which encoding arrived first.
        let id = pool_payload_id(&record);
        match by_payload.entry(id) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(record);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let candidate_work = sha256d(record_signed_data(&record).as_bytes());
                let retained_work = sha256d(record_signed_data(slot.get()).as_bytes());
                if candidate_work < retained_work
                    || (candidate_work == retained_work && sign_of(&record) < sign_of(slot.get()))
                {
                    slot.insert(record);
                }
            }
        }
    }
    by_payload.into_values().collect()
}

fn evict_overflow(records: &mut Vec<Value>, max_shard_bytes: usize) {
    if container_len(records) <= max_shard_bytes {
        return;
    }
    records.sort_by(|a, b| {
        let ha = sha256d(record_signed_data(a).as_bytes());
        let hb = sha256d(record_signed_data(b).as_bytes());
        ha.cmp(&hb).then_with(|| sign_of(a).cmp(sign_of(b)))
    });
    // A singleton is not exempt from the byte cap. Retaining an oversized
    // final record would let append report success while GetSigned refuses
    // the shard, which is especially dangerous for a durable outbox.
    while !records.is_empty() && container_len(records) > max_shard_bytes {
        records.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn high_s_recovery_variant(signature: &str) -> String {
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .unwrap();
        let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let low_s = raw[33..65].to_vec();
        let mut high_s = [0u8; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let value = order[index] as i16 - low_s[index] as i16 - borrow;
            if value < 0 {
                high_s[index] = (value + 256) as u8;
                borrow = 1;
            } else {
                high_s[index] = value as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0);
        raw[33..65].copy_from_slice(&high_s);
        raw[0] = 27 + ((raw[0] - 27) ^ 1);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

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
            rln_required: false,
            retention_weeks: 0,
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

    // A 32-byte tag whose FIRST byte fixes the shard sub-index, the rest varied by
    // `variant` so several records can share one sub yet stay distinct.
    fn tag_b64_at(sub: u8, variant: u8) -> String {
        let mut t = [0u8; 32];
        t[0] = sub;
        for (i, b) in t.iter_mut().enumerate().skip(1) {
            *b = variant.wrapping_add(i as u8);
        }
        base64::engine::general_purpose::STANDARD.encode(t)
    }

    /// A valid record routed to shard sub `sub` (via its tag's first byte),
    /// distinct per `variant`. Mirrors [`valid_record`] but pins the sub so a set
    /// of records can legitimately share one shard.
    fn valid_record_at(epoch: i64, sub: u8, variant: u8, ct_len: usize, ct_fill: u8) -> Value {
        let pk = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&pk).unwrap();
        let mut rec = json!({
            "v": 1,
            "epoch": epoch,
            "tag": tag_b64_at(sub, variant),
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

    // --- RLN admission (structural) ---

    fn rln_rule() -> PoolRule {
        let mut r = rule();
        r.rln_required = true;
        r
    }

    /// A valid record that also carries an `rln` proof blob. The rln field is
    /// present BEFORE PoW/sign, so both cover it (as they will on the wire).
    fn valid_record_with_rln(epoch: i64, rln_bytes: &[u8]) -> Value {
        let pk = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&pk).unwrap();
        let mut rec = json!({
            "v": 1,
            "epoch": epoch,
            "tag": tag_b64(1),
            "ct": ct_b64(64, 7),
            "pow": 0,
            "author": author,
            "rln": base64::engine::general_purpose::STANDARD.encode(rln_bytes),
        });
        solve_pow(&mut rec, 8);
        let sig = epix_crypt::sign(&record_signed_data(&rec), &pk).unwrap();
        rec["sign"] = json!(sig);
        rec
    }

    #[test]
    fn rln_required_accepts_wellformed_proof() {
        let epoch = 100;
        let rec = valid_record_with_rln(epoch, &[1u8; 300]);
        assert_eq!(verify_pool_record(&rec, &rln_rule(), week_of(epoch), now_for(epoch)), Ok(()));
    }

    #[test]
    fn rln_required_rejects_missing_proof() {
        let epoch = 100;
        let rec = valid_record(epoch, 1, 64, 7); // no rln field
        assert_eq!(
            verify_pool_record(&rec, &rln_rule(), week_of(epoch), now_for(epoch)),
            Err(PoolError::MissingRlnProof)
        );
    }

    #[test]
    fn rln_field_rejected_when_pool_does_not_require_it() {
        let epoch = 100;
        // The rln field present under a PoW-only rule is a covert channel.
        let rec = valid_record_with_rln(epoch, &[1u8; 200]);
        assert_eq!(
            verify_pool_record(&rec, &rule(), week_of(epoch), now_for(epoch)),
            Err(PoolError::UnknownField("rln".into()))
        );
    }

    #[test]
    fn rln_required_rejects_oversized_proof() {
        let epoch = 100;
        let rec = valid_record_with_rln(epoch, &[1u8; MAX_RLN_PROOF_BYTES + 1]);
        assert_eq!(
            verify_pool_record(&rec, &rln_rule(), week_of(epoch), now_for(epoch)),
            Err(PoolError::BadRlnProof)
        );
    }

    #[test]
    fn rln_required_rejects_non_base64_proof() {
        let epoch = 100;
        let mut rec = valid_record(epoch, 1, 64, 7);
        rec["rln"] = json!("!!! not base64 !!!");
        assert_eq!(
            verify_pool_record(&rec, &rln_rule(), week_of(epoch), now_for(epoch)),
            Err(PoolError::BadRlnProof)
        );
    }

    #[test]
    fn retention_parsed_and_keep_from_computed() {
        let mut v = json!({
            "dir": "pool", "class": POOL_RECORD_FORMAT, "since_week": 0, "fanout": 16,
            "pow_bits": 8, "pad_buckets": [64], "max_record_bytes": 4096,
            "max_shard_bytes": 1000, "retention_weeks": 4
        });
        let r = PoolRule::parse(&v).unwrap();
        assert_eq!(r.retention_weeks, 4);
        // With current week 100 and a 4-week window, weeks < 97 are expired.
        assert_eq!(retention_keep_from(&r, 100), Some(97));

        // Absent / non-positive => indefinite (keep everything).
        v.as_object_mut().unwrap().remove("retention_weeks");
        let r0 = PoolRule::parse(&v).unwrap();
        assert_eq!(r0.retention_weeks, 0);
        assert_eq!(retention_keep_from(&r0, 100), None);
    }

    #[test]
    fn rln_required_parsed_from_descriptor() {
        let mut v = json!({
            "dir": "pool", "class": POOL_RECORD_FORMAT, "since_week": 0, "fanout": 16,
            "pow_bits": 8, "pad_buckets": [64], "max_record_bytes": 4096,
            "max_shard_bytes": 1000, "rln_required": true
        });
        assert!(PoolRule::parse(&v).unwrap().rln_required);
        // absent => false (PoW-only)
        v.as_object_mut().unwrap().remove("rln_required");
        assert!(!PoolRule::parse(&v).unwrap().rln_required);
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
        assert!(PoolRule::parse(&json!({
            "dir": "pool", "class": POOL_RECORD_FORMAT, "since_week": 0, "fanout": 1,
            "pow_bits": 0, "pad_buckets": [64], "max_record_bytes": 100,
            "max_shard_bytes": 1
        }))
        .is_none()); // even an empty canonical shard could never be served
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
    fn verify_rejects_a_valid_high_s_signature_variant() {
        let r = rule();
        let epoch = 100;
        let mut record = valid_record(epoch, 1, 128, 7);
        let alternate = high_s_recovery_variant(record["sign"].as_str().unwrap());
        assert!(epix_crypt::verify(
            &record_signed_data(&record),
            record["author"].as_str().unwrap(),
            &alternate,
        ));
        record["sign"] = json!(alternate);
        assert_eq!(
            verify_pool_record(&record, &r, week_of(epoch), now_for(epoch)),
            Err(PoolError::BadSignature)
        );
    }

    #[test]
    fn merge_is_commutative_idempotent_and_returns_delta() {
        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let sub = 3u16;
        let a = valid_record_at(epoch, sub as u8, 1, 128, 1);
        let b = valid_record_at(epoch, sub as u8, 2, 128, 2);

        let local = make_pool_container(vec![a.clone()]);
        let inbound = make_pool_container(vec![b.clone()]);

        let (ab, delta_ab) = merge_pool(&local, &inbound, &r, week, sub, now);
        let (ba, _) = merge_pool(&inbound, &local, &r, week, sub, now);
        assert_eq!(ab, ba, "commutative");
        // delta is exactly what's new to `local` (record b).
        assert_eq!(delta_ab.len(), 1);
        assert_eq!(sign_of(&delta_ab[0]), sign_of(&b));

        // idempotent: merging the same inbound again yields no new delta.
        let (ab2, delta2) = merge_pool(&ab, &inbound, &r, week, sub, now);
        assert_eq!(ab2, ab, "idempotent");
        assert!(delta2.is_empty(), "no new records the second time");
    }

    #[test]
    fn merge_dedups_compact_signature_header_variants() {
        use base64::Engine as _;

        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let sub = 3u16;
        let record = valid_record_at(epoch, sub as u8, 9, 128, 4);
        let mut alternate = record.clone();
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(sign_of(&record))
            .unwrap();
        assert!((27..=30).contains(&raw[0]));
        raw[0] += 4; // same recovery id, optional compressed-key flag
        alternate["sign"] = json!(base64::engine::general_purpose::STANDARD.encode(raw));

        assert_eq!(verify_pool_record(&record, &r, week, now), Ok(()));
        assert_eq!(
            verify_pool_record(&alternate, &r, week, now),
            Err(PoolError::BadSignature),
            "the optional recovery-header encoding is noncanonical for pool records"
        );
        assert_ne!(sign_of(&record), sign_of(&alternate));

        let left = make_pool_container(vec![record]);
        let right = make_pool_container(vec![alternate]);
        let (lr, delta_lr) = merge_pool(&left, &right, &r, week, sub, now);
        let (rl, delta_rl) = merge_pool(&right, &left, &r, week, sub, now);
        assert_eq!(lr, rl, "both partitions choose the same canonical variant");
        assert_eq!(
            pool_records_of(&lr).len(),
            1,
            "one payload occupies one slot"
        );
        assert!(
            delta_lr.is_empty(),
            "alternate signature is not a new payload"
        );
        assert_eq!(
            delta_rl.len(),
            1,
            "a canonical inbound record repairs a persisted noncanonical variant"
        );

        // Mirror the persistence seam, which writes only when delta is nonempty.
        // A partition that had stored the formerly-accepted +4 variant therefore
        // does replace it when it receives the canonical form.
        let mut persisted = right;
        if !delta_rl.is_empty() {
            persisted = rl;
        }
        assert_eq!(
            persisted, lr,
            "write-on-delta storage converges to canonical bytes"
        );
    }

    #[test]
    fn absence_is_not_deletion() {
        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let keep = valid_record_at(epoch, 3, 1, 128, 1);
        let local = make_pool_container(vec![keep.clone()]);
        let blank = make_pool_container(vec![]);
        let (merged, delta) = merge_pool(&local, &blank, &r, week, 3, now);
        assert_eq!(pool_records_of(&merged).len(), 1, "blank inbound removes nothing");
        assert!(delta.is_empty());
    }

    #[test]
    fn merge_drops_forged_and_underpowered_records() {
        let r = rule();
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        let good = valid_record_at(epoch, 3, 1, 128, 1);

        // An under-powered record (solved for 0 bits only; likely < 8 leading
        // zero bits) that also carries a valid self-signature. Same sub as `good`
        // so this test isolates the PoW check, not the sub-index binding.
        let pk = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&pk).unwrap();
        let mut weak = json!({
            "v": 1, "epoch": epoch, "tag": tag_b64_at(3, 9), "ct": ct_b64(128, 5),
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
            3,
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
        let recs: Vec<Value> =
            (0..6).map(|i| valid_record_at(epoch, 3, i as u8 + 1, 64, i as u8)).collect();

        // Merge in two different orders; survivors must match byte-for-byte.
        let mut c1 = make_pool_container(vec![]);
        for rec in &recs {
            let (m, _) = merge_pool(&c1, &make_pool_container(vec![rec.clone()]), &r, week, 3, now);
            c1 = m;
        }
        let mut c2 = make_pool_container(vec![]);
        for rec in recs.iter().rev() {
            let (m, _) = merge_pool(&c2, &make_pool_container(vec![rec.clone()]), &r, week, 3, now);
            c2 = m;
        }
        assert_eq!(c1, c2, "eviction converges regardless of arrival order");
        assert!(container_len(&pool_records_of(&c1)) <= r.max_shard_bytes);
        assert!(!pool_records_of(&c1).is_empty(), "keeps at least the highest-work record");
    }

    #[test]
    fn oversized_singleton_is_rejected_by_capacity() {
        let mut r = rule();
        let epoch = 100;
        let record = valid_record_at(epoch, 3, 1, 128, 1);
        r.max_shard_bytes = container_len(&[record.clone()]).saturating_sub(1);

        let (merged, delta) = merge_pool(
            &make_pool_container(Vec::new()),
            &make_pool_container(vec![record]),
            &r,
            week_of(epoch),
            3,
            now_for(epoch),
        );

        assert!(pool_records_of(&merged).is_empty());
        assert!(delta.is_empty());
        assert!(container_len(&pool_records_of(&merged)) <= r.max_shard_bytes);
    }

    #[test]
    fn records_sorted_by_epoch_then_tag_not_arrival() {
        let r = rule();
        let now = now_for(102);
        // three records across two epochs (same week, same sub), inserted out of order
        let e1 = valid_record_at(100, 3, 5, 64, 1);
        let e2 = valid_record_at(100, 3, 1, 64, 2);
        let e3 = valid_record_at(101, 3, 3, 64, 3);
        let (merged, _) = {
            let mut c = make_pool_container(vec![]);
            for rec in [e3.clone(), e1.clone(), e2.clone()] {
                let (m, _) = merge_pool(&c, &make_pool_container(vec![rec]), &r, week_of(100), 3, now);
                c = m;
            }
            (c, ())
        };
        let out = pool_records_of(&merged);
        // epoch ascending; within epoch 100, tag ascending (variant 1 < variant 5).
        let epochs: Vec<i64> = out.iter().map(epoch_of).collect();
        let mut sorted = epochs.clone();
        sorted.sort();
        assert_eq!(epochs, sorted, "on-disk order is by epoch, not arrival");
    }

    #[test]
    fn merge_drops_records_for_the_wrong_sub() {
        let r = rule(); // fanout 16
        let epoch = 100;
        let week = week_of(epoch);
        let now = now_for(epoch);
        // A perfectly valid record whose tag routes to sub 5.
        let rec = valid_record_at(epoch, 5, 1, 64, 1);
        let tag = base64::engine::general_purpose::STANDARD
            .decode(rec["tag"].as_str().unwrap())
            .unwrap();
        assert_eq!(shard_sub(&tag, r.fanout), 5);

        // Merged into sub 5 it is admitted...
        let (into5, _) =
            merge_pool(&make_pool_container(vec![]), &make_pool_container(vec![rec.clone()]), &r, week, 5, now);
        assert_eq!(pool_records_of(&into5).len(), 1, "record for sub 5 lands in sub 5");

        // ...but merged into a DIFFERENT sub it is rejected — no cross-sub piling,
        // even though the record is otherwise valid (real PoW + signature).
        let (into6, delta6) =
            merge_pool(&make_pool_container(vec![]), &make_pool_container(vec![rec]), &r, week, 6, now);
        assert!(pool_records_of(&into6).is_empty(), "record for sub 5 must not land in sub 6");
        assert!(delta6.is_empty());
    }
}
