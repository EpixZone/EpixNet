//! The generic **anonymous envelope pool** primitive.
//!
//! A pool is a set of per-week, per-fanout merge-file shards
//! (`<dir>/w<week>/<xx>.json`) of the `epix-pool-1` class (see
//! [`epix_content::pool`]) declared on a xite's root content.json. Records are
//! anonymous, size-padded, PoW-gated sealed blobs — the network cannot tell who
//! wrote one, to whom, or what it says. This module is the NODE-side lifecycle
//! for such a pool: append (local write), inbound merge (peer push / sweep),
//! anti-entropy sweep, historical backfill, and the serve/write gate.
//!
//! It is deliberately **content-agnostic**: it knows nothing about mail. Every
//! newly-landed record is broadcast on the pool-delta bus
//! ([`AppState::subscribe_pool_deltas`]); consumers — the mail indexer today,
//! any other xite's handler tomorrow — subscribe and filter by address. Adding a
//! new pool-backed feature needs no change here.

use crate::state::AppState;
use epix_content::pool::{self, PoolRule};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

/// A batch of newly-landed pool records for one xite, broadcast to consumers.
#[derive(Clone)]
pub struct PoolDelta {
    pub address: String,
    pub records: Arc<Vec<Value>>,
}

/// Serializes descriptor reads that must remain valid through a durable pool
/// or outbox commit against descriptor and RLN-gate refresh.
pub struct PoolRuleTransaction {
    state: Arc<AppState>,
    address: String,
    permit: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl PoolRuleTransaction {
    /// Rebuild and publish this address's descriptor cache and admission gate
    /// while this transaction still excludes every pool reader and writer.
    pub async fn refresh_rules(&self) {
        self.state.refresh_pool_rules_locked(&self.address).await;
    }
}

impl Drop for PoolRuleTransaction {
    fn drop(&mut self) {
        self.permit.take();
        self.state
            .release_pool_shard_lock(&self.address, POOL_RULE_TRANSITION_LOCK);
    }
}

/// Node-installed hook that verifies a pool record's RLN proof — the zero-
/// knowledge part that [`epix_content::pool::verify_pool_record`] deliberately
/// does NOT do (so `epix-content` stays free of the proving stack).
///
/// Implemented by a heavier crate that depends on `epix-rln` (which holds the
/// membership tree, the verifier, and the nullifier log), and installed on
/// [`AppState`] via [`AppState::set_pool_admission`]. It is consulted only for
/// records of a pool whose rule sets `rln_required`; if no admission hook is
/// installed for such a pool, records are dropped (fail closed).
pub type PoolRecordId = [u8; 32];

/// The RLN-relevant fields of one structurally verified pool record. `id` is
/// SHA-256 of its immutable logical envelope tuple. It stays stable across
/// re-signing, re-PoW, and current-root RLN reproof.
#[derive(Clone)]
pub struct PoolAdmissionRecord {
    pub id: PoolRecordId,
    pub rln_proof: Vec<u8>,
    pub ct: Vec<u8>,
    pub epoch: i64,
}

/// One admission decision. `evict` contains records that were accepted earlier
/// but lost deterministic RLN reconciliation and must be removed from disk.
#[derive(Default)]
pub struct PoolAdmissionDecision {
    /// Persist this record as the deterministic survivor.
    pub admit: bool,
    /// Emit this record to application consumers. Replacements of an already
    /// spent allowance unit persist for convergence but are never delivered.
    pub deliver: bool,
    pub evict: Vec<PoolRecordId>,
    /// Hex identity commitments revealed by double-signalling proofs.
    pub offenders: Vec<String>,
    /// A fail-closed admission error, such as durable poison persistence
    /// failure. The caller must not commit any associated shard mutation.
    pub error: Option<String>,
}

/// Result of rebuilding an address's gate from its latest descriptor and the
/// retained local shard records.
#[derive(Default)]
pub struct PoolAdmissionRefresh {
    pub evict: Vec<PoolRecordId>,
    /// Hex identity commitments revealed while warming retained records.
    pub offenders: Vec<String>,
    pub loaded_members: Option<usize>,
    pub error: Option<String>,
    /// Per-address transaction permit. The caller holds it through persistent
    /// evictions so no admission can race the disk snapshot and gate swap.
    pub permit: Option<tokio::sync::OwnedMutexGuard<()>>,
}

/// Decisions for one structurally verified batch plus the transaction permit
/// that must remain held until its shard writes and cross-shard evictions are
/// durable.
#[derive(Default)]
pub struct PoolAdmissionBatch {
    pub decisions: Vec<PoolAdmissionDecision>,
    pub permit: Option<tokio::sync::OwnedMutexGuard<()>>,
}

pub trait PoolAdmission: Send + Sync {
    /// Rebuild one address's gate and warm its nullifier state from records that
    /// already passed structural verification and are retained on disk.
    fn refresh_address(
        &self,
        address: &str,
        content: Option<&Value>,
        retained: &mut dyn FnMut() -> Result<Vec<PoolAdmissionRecord>, String>,
    ) -> PoolAdmissionRefresh;

    /// Decide a deterministic batch under the same per-address transaction
    /// permit the caller holds through persistent writes and evictions.
    fn admit_records(&self, address: &str, records: &[PoolAdmissionRecord]) -> PoolAdmissionBatch;

    /// Select records that may be returned by a disk rescan. This verifies RLN
    /// proofs against the loaded gate without mutating nullifier state and
    /// excludes records that touch durable double-signal poison.
    fn allow_rescan_records(&self, address: &str, records: &[PoolAdmissionRecord]) -> Vec<bool>;
}

/// Peers to fetch from in an anti-entropy sweep.
const POOL_SWEEP_PEERS: usize = 16;

/// Quiet-shard backoff: first miss waits this long, doubling per consecutive
/// quiet pass up to [`POOL_SWEEP_QUIET_CAP_MS`]. Small enough that a shard that
/// starts receiving is back in the hot set within a couple of minutes.
const POOL_SWEEP_QUIET_BASE_MS: i64 = 60_000;
/// Ceiling for the quiet backoff: even a shard that has never held anything is
/// re-checked at least this often.
const POOL_SWEEP_QUIET_CAP_MS: i64 = 30 * 60_000;

/// One sweep pass over pool shard paths, shared by the periodic sweep and the
/// historical backfill. The whole path list goes out in ONE dial session, so a
/// pass costs one dial per peer rather than one per (peer, path); the session
/// itself reports every dial outcome to the peer reputation registry, so dead
/// candidates still sink into backoff without this type accounting for them.
struct SweepPass {
    candidates: Vec<epix_core::PeerAddr>,
    /// Paths some peer actually served (whether or not they held anything new).
    served: usize,
    /// Paths whose served copy contributed records we did not already have.
    merged: usize,
    /// Paths requested this pass.
    paths: usize,
}

impl SweepPass {
    fn new(candidates: Vec<epix_core::PeerAddr>) -> Self {
        Self { candidates, served: 0, merged: 0, paths: 0 }
    }

    /// Fetch EVERY due path in ONE dial session and merge what comes back.
    ///
    /// The session dials the candidates once and pulls the whole path list
    /// across the live links in parallel ([`AppState::edx_fetch_signed_many`]),
    /// so a pass costs one dial per peer instead of one per (peer, path). The
    /// per-path loop it replaces asked every reachable peer for every path
    /// whenever a shard was empty everywhere - the normal case - which on a
    /// Tor node measured ~350 round trips and 5-7 MINUTES per pass, running
    /// back to back forever and starving page traffic of circuits.
    ///
    /// One copy per path rather than a [`POOL_SWEEP_UNION`]-wide union: the
    /// session spreads its requests over whichever links answer, passes repeat,
    /// and records also arrive by push, so convergence is unaffected while the
    /// cost drops by more than an order of magnitude.
    /// `cool_quiet` records the quiet-backoff for paths that yielded nothing.
    /// Only the PERIODIC sweep does that: a historical backfill legitimately
    /// finds most of its (old, already-synced) paths empty, and letting it
    /// write backoff cooled every current-week shard at startup - which is
    /// exactly the hot set the periodic sweep exists to watch.
    async fn sweep_paths(
        &mut self,
        state: &Arc<AppState>,
        address: &str,
        paths: Vec<String>,
        cool_quiet: bool,
    ) {
        if paths.is_empty() || self.candidates.is_empty() {
            return;
        }
        self.paths += paths.len();
        let served = state
            .edx_fetch_signed_many(address, paths.clone(), self.candidates.clone(), None)
            .await
            .unwrap_or_default();
        for path in &paths {
            let merged = match served.get(path) {
                Some(bytes) => {
                    self.served += 1;
                    state
                        .apply_inbound_pool_update(address, path, bytes)
                        .await
                        .unwrap_or(false)
                }
                None => false,
            };
            if merged {
                self.merged += 1;
            }
            if cool_quiet || merged {
                state.note_pool_sweep_result(address, path, merged);
            }
        }
    }
}
/// Peers to flood a freshly appended record to.
const POOL_PUSH_LIMIT: usize = 8;
/// Peers to re-flood an inbound-merged record to (smaller, anti-storm).
const POOL_REFLOOD_LIMIT: usize = 3;
const POOL_RULE_TRANSITION_LOCK: &str = "\0pool-rule-transition";
/// Match the admission layer's live nullifier window. Records older than this
/// cannot collide with current traffic because the epoch is an external input.
pub const RLN_ACTIVE_EPOCHS: i64 = 8;

/// Oldest epoch in the exact active RLN window, including the current epoch.
pub fn rln_oldest_active_epoch(current_epoch: i64) -> i64 {
    current_epoch
        .saturating_sub(RLN_ACTIVE_EPOCHS.saturating_sub(1))
        .max(0)
}

fn retention_keep_from_for_rule(rule: &PoolRule, current_epoch: i64) -> Option<i64> {
    let current_week = pool::week_of(current_epoch);
    let configured = pool::retention_keep_from(rule, current_week)?;
    if rule.rln_required {
        Some(configured.min(pool::week_of(rln_oldest_active_epoch(current_epoch))))
    } else {
        Some(configured)
    }
}

#[derive(Default)]
struct FilteredRlnAdmission {
    container: Value,
    evicted: Vec<PoolRecordId>,
    suppress_delivery: Vec<PoolRecordId>,
    offenders: Vec<String>,
    errors: Vec<String>,
    permit: Option<tokio::sync::OwnedMutexGuard<()>>,
}

type PoolAdmissionCandidate = (PoolRecordId, Value, PoolAdmissionRecord);

fn pool_admission_candidate(
    record: Value,
    rule: &PoolRule,
    week: i64,
    now: i64,
    oldest_epoch: i64,
) -> Option<PoolAdmissionCandidate> {
    pool::verify_pool_record(&record, rule, week, now).ok()?;
    let admission = admission_record(&record)?;
    (admission.epoch >= oldest_epoch).then_some((admission.id, record, admission))
}

fn pool_admission_candidates(
    records: Vec<Value>,
    rule: &PoolRule,
    week: i64,
    now: i64,
    oldest_epoch: i64,
) -> Vec<PoolAdmissionCandidate> {
    let mut candidates = Vec::new();
    for record in records {
        if let Some(candidate) = pool_admission_candidate(record, rule, week, now, oldest_epoch) {
            candidates.push(candidate);
        }
    }
    candidates.sort_by_key(|(id, _, _)| *id);
    candidates
}

fn apply_pool_admission_decision(
    candidate: (PoolRecordId, Value),
    decision: PoolAdmissionDecision,
    kept: &mut Vec<(PoolRecordId, Value)>,
    evicted: &mut BTreeSet<PoolRecordId>,
    suppress_delivery: &mut BTreeSet<PoolRecordId>,
    offenders: &mut BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let (id, record) = candidate;
    evicted.extend(decision.evict);
    offenders.extend(decision.offenders);
    if let Some(error) = decision.error {
        errors.push(error);
    }
    if !decision.admit {
        return;
    }
    if !decision.deliver {
        suppress_delivery.insert(id);
    }
    kept.push((id, record));
}

fn apply_pool_admission_batch(
    admission: Arc<dyn PoolAdmission>,
    address: String,
    candidates: Vec<PoolAdmissionCandidate>,
) -> FilteredRlnAdmission {
    let admission_records: Vec<PoolAdmissionRecord> = candidates
        .iter()
        .map(|(_, _, record)| record.clone())
        .collect();
    let mut batch = admission.admit_records(&address, &admission_records);
    let mut kept = Vec::new();
    let mut evicted = BTreeSet::new();
    let mut suppress_delivery = BTreeSet::new();
    let mut offenders = BTreeSet::new();
    let mut errors = Vec::new();
    for ((id, record, _), decision) in
        candidates.into_iter().zip(batch.decisions.drain(..))
    {
        apply_pool_admission_decision(
            (id, record),
            decision,
            &mut kept,
            &mut evicted,
            &mut suppress_delivery,
            &mut offenders,
            &mut errors,
        );
    }
    kept.retain(|(id, _)| !evicted.contains(id));
    suppress_delivery.retain(|id| !evicted.contains(id));
    FilteredRlnAdmission {
        container: pool::make_pool_container(
            kept.into_iter().map(|(_, record)| record).collect(),
        ),
        evicted: evicted.into_iter().collect(),
        suppress_delivery: suppress_delivery.into_iter().collect(),
        offenders: offenders.into_iter().collect(),
        errors,
        permit: batch.permit.take(),
    }
}

enum PoolWriteOutcome {
    Committed {
        delta: Vec<Value>,
        /// Whether every record offered by the peer is represented by the
        /// durable merged shard. This is separate from `delta`: an exact
        /// duplicate is accepted even though it produces no delivery delta.
        accepted: bool,
        snapshot: Vec<u8>,
    },
    CapacityRejected,
}

struct OutboundPoolRoute {
    tag: Vec<u8>,
    epoch: i64,
    shard: String,
    record_id: Option<PoolRecordId>,
}

struct InboundPoolMerge<'a> {
    inner_path: &'a str,
    rule: &'a PoolRule,
    week: i64,
    sub: u16,
    incoming: &'a Value,
    evicted: &'a [PoolRecordId],
    offer_well_formed: bool,
    offered_ids: &'a BTreeSet<PoolRecordId>,
}

fn outbound_pool_route(
    rule: &PoolRule,
    record: &Value,
    expected_shard: Option<&str>,
) -> Result<OutboundPoolRoute, String> {
    let tag = record
        .get("tag")
        .and_then(Value::as_str)
        .and_then(b64_decode)
        .ok_or("pool record missing tag")?;
    let epoch = record
        .get("epoch")
        .and_then(Value::as_i64)
        .ok_or("pool record missing epoch")?;
    let shard = pool::shard_path(rule, epoch, &tag);
    if expected_shard.is_some_and(|expected| expected != shard) {
        return Err(format!(
            "staged pool route changed: expected {}, current rule routes to {shard}",
            expected_shard.unwrap_or_default()
        ));
    }
    Ok(OutboundPoolRoute {
        tag,
        epoch,
        shard,
        record_id: pool_record_id(record),
    })
}

fn pool_record_ids(container: &Value) -> BTreeSet<PoolRecordId> {
    pool::pool_records_of(container)
        .iter()
        .filter_map(pool_record_id)
        .collect()
}

fn remove_evicted_pool_records(
    existing: Value,
    evicted: &[PoolRecordId],
) -> (Value, bool) {
    let evicted: BTreeSet<PoolRecordId> = evicted.iter().copied().collect();
    let before = pool::pool_records_of(&existing);
    let filtered: Vec<Value> = before
        .iter()
        .filter(|record| {
            admission_record(record).is_none_or(|record| !evicted.contains(&record.id))
        })
        .cloned()
        .collect();
    let removed = filtered.len() != before.len();
    if removed {
        (pool::make_pool_container(filtered), true)
    } else {
        (existing, false)
    }
}

fn merge_outbound_pool_shard(
    storage: &epix_xite::XiteStorage,
    rule: &PoolRule,
    route: &OutboundPoolRoute,
    incoming: &Value,
    evicted: &[PoolRecordId],
) -> Result<PoolWriteOutcome, String> {
    let existing = read_pool_container(storage, &route.shard)?;
    let already_present = route.record_id.is_some_and(|id| {
        pool::pool_records_of(&existing)
            .iter()
            .any(|record| pool_record_id(record) == Some(id))
    });
    if rule.rln_required
        && pool::pool_records_of(incoming).is_empty()
        && evicted.is_empty()
        && !already_present
    {
        return Err("local RLN record was rejected by admission".into());
    }
    let (existing, _) = remove_evicted_pool_records(existing, evicted);
    let (merged, delta) = pool::merge_pool(
        &existing,
        incoming,
        rule,
        pool::week_of(route.epoch),
        pool::shard_sub(&route.tag, rule.fanout),
        now_ms(),
    );
    if !pool_record_ids(incoming).is_subset(&pool_record_ids(&merged)) {
        return Ok(PoolWriteOutcome::CapacityRejected);
    }
    let snapshot = serde_json::to_vec(&merged).map_err(|error| error.to_string())?;
    storage
        .write_atomic_durable(&route.shard, &snapshot)
        .map_err(|error| error.to_string())?;
    Ok(PoolWriteOutcome::Committed {
        delta,
        accepted: true,
        snapshot,
    })
}

fn inbound_offer_is_well_formed(
    incoming: &Value,
    rule: &PoolRule,
    week: i64,
    sub: u16,
    offered_ids: &BTreeSet<PoolRecordId>,
) -> bool {
    let offered = pool::pool_records_of(incoming);
    incoming.get("record_format").and_then(Value::as_str) == Some(pool::POOL_RECORD_FORMAT)
        && incoming
            .get(pool::POOL_RECORDS_KEY)
            .is_some_and(Value::is_array)
        && offered.len() == offered_ids.len()
        && offered.iter().all(|record| {
            pool::verify_pool_record(record, rule, week, now_ms()).is_ok()
                && record
                    .get("tag")
                    .and_then(Value::as_str)
                    .and_then(b64_decode)
                    .is_some_and(|tag| pool::shard_sub(&tag, rule.fanout) == sub)
        })
}

fn merge_inbound_pool_shard(
    storage: &epix_xite::XiteStorage,
    merge: &InboundPoolMerge<'_>,
) -> Result<PoolWriteOutcome, String> {
    let existing = read_pool_container(storage, merge.inner_path)?;
    let (existing, removed_here) = remove_evicted_pool_records(existing, merge.evicted);
    let (merged, delta) = pool::merge_pool(
        &existing,
        merge.incoming,
        merge.rule,
        merge.week,
        merge.sub,
        now_ms(),
    );
    let survived = pool_record_ids(&merged);
    if !pool_record_ids(merge.incoming).is_subset(&survived) {
        return Ok(PoolWriteOutcome::CapacityRejected);
    }
    let snapshot = serde_json::to_vec(&merged).map_err(|error| error.to_string())?;
    let unchanged = !removed_here && merged == existing;
    if !unchanged {
        storage
            .write_atomic_durable(merge.inner_path, &snapshot)
            .map_err(|error| error.to_string())?;
    }
    Ok(PoolWriteOutcome::Committed {
        delta: if unchanged { Vec::new() } else { delta },
        accepted: merge.offer_well_formed && merge.offered_ids.is_subset(&survived),
        snapshot,
    })
}

fn deliverable_pool_records(
    records: impl IntoIterator<Item = Value>,
    suppressed: Vec<PoolRecordId>,
) -> Vec<Value> {
    let suppressed: BTreeSet<PoolRecordId> = suppressed.into_iter().collect();
    records
        .into_iter()
        .filter(|record| pool_record_id(record).is_none_or(|id| !suppressed.contains(&id)))
        .collect()
}

enum ScannedPoolRecord {
    Plain(Value),
    Rln(Value, PoolAdmissionRecord),
}

fn scan_pool_record(
    record: Value,
    rule: &PoolRule,
    week: i64,
    sub: u16,
    now: i64,
    oldest_rln_epoch: i64,
) -> Option<ScannedPoolRecord> {
    pool::verify_pool_record(&record, rule, week, now).ok()?;
    let tag = record
        .get("tag")
        .and_then(Value::as_str)
        .and_then(b64_decode)?;
    if pool::shard_sub(&tag, rule.fanout) != sub {
        return None;
    }
    if !rule.rln_required {
        return Some(ScannedPoolRecord::Plain(record));
    }
    let admission = admission_record(&record)?;
    (admission.epoch >= oldest_rln_epoch).then_some(ScannedPoolRecord::Rln(record, admission))
}

fn scan_pool_shard(
    storage: &epix_xite::XiteStorage,
    rule: &PoolRule,
    path: &str,
    now: i64,
    oldest_rln_epoch: i64,
    records: &mut Vec<Value>,
    rln_records: &mut Vec<(Value, PoolAdmissionRecord)>,
) {
    let Some((week, sub)) = pool::parse_shard_path(rule, path) else {
        return;
    };
    let Ok(bytes) = storage.read(path) else {
        return;
    };
    let Ok(container) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    for record in pool::pool_records_of(&container) {
        match scan_pool_record(record, rule, week, sub, now, oldest_rln_epoch) {
            Some(ScannedPoolRecord::Plain(record)) => records.push(record),
            Some(ScannedPoolRecord::Rln(record, admission)) => {
                rln_records.push((record, admission));
            }
            None => {}
        }
    }
}

fn scan_all_pool_records(
    storage: &epix_xite::XiteStorage,
    rules: &[PoolRule],
    now: i64,
) -> (Vec<Value>, Vec<(Value, PoolAdmissionRecord)>) {
    let current_epoch = pool::epoch_now(now);
    let oldest_rln_epoch = rln_oldest_active_epoch(current_epoch);
    let current_week = pool::week_of(current_epoch);
    let mut records = Vec::new();
    let mut rln_records = Vec::new();
    for rule in rules {
        for path in pool::sync_shard_paths(rule, current_week) {
            scan_pool_shard(
                storage,
                rule,
                &path,
                now,
                oldest_rln_epoch,
                &mut records,
                &mut rln_records,
            );
        }
    }
    (records, rln_records)
}

/// Result of a channel outbox append that reached at least one peer. A route
/// transition after the immutable snapshot was accepted is distinct from a
/// pre-publication failure so a legacy exact row can be acknowledged safely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolAppendConfirmation {
    Stable {
        shard: String,
    },
    RouteChangedAfterPeerConfirmation {
        staged_shard: String,
    },
    LocalPostconditionFailedAfterPeerConfirmation {
        staged_shard: String,
        reason: String,
    },
}

impl PoolAppendConfirmation {
    fn stable_shard(self) -> Result<String, String> {
        match self {
            Self::Stable { shard } => Ok(shard),
            Self::RouteChangedAfterPeerConfirmation { .. } => {
                Err("pool route changed during publication; retrying current route".into())
            }
            Self::LocalPostconditionFailedAfterPeerConfirmation { reason, .. } => Err(reason),
        }
    }
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Stable id used to reconcile RLN records across partitions and shards.
pub fn pool_record_id(record: &Value) -> Option<PoolRecordId> {
    record.as_object()?;
    let payload = pool::logical_record_data(record);
    Some(Sha256::digest(payload.as_bytes()).into())
}

fn admission_record(record: &Value) -> Option<PoolAdmissionRecord> {
    let rln_proof = record
        .get("rln")
        .and_then(|v| v.as_str())
        .and_then(b64_decode)?;
    let ct = record
        .get("ct")
        .and_then(|v| v.as_str())
        .and_then(b64_decode)?;
    let epoch = record.get("epoch").and_then(|v| v.as_i64())?;
    let id = pool_record_id(record)?;
    Some(PoolAdmissionRecord {
        id,
        rln_proof,
        ct,
        epoch,
    })
}

fn collect_pool_admission_shard(
    storage: &epix_xite::XiteStorage,
    rule: &PoolRule,
    week: i64,
    sub: u16,
    now: i64,
    cutoff: i64,
) -> Result<Vec<PoolAdmissionRecord>, String> {
    let path = format!("{}/w{week}/{sub:02x}.json", rule.dir);
    let container = read_pool_container(storage, &path)?;
    let mut records = Vec::new();
    for record in pool::pool_records_of(&container) {
        let epoch = record.get("epoch").and_then(Value::as_i64).unwrap_or(-1);
        if epoch < cutoff {
            continue;
        }
        pool::verify_pool_record(&record, rule, week, now)
            .map_err(|error| format!("invalid active RLN record in {path}: {error:?}"))?;
        let routed_here = record
            .get("tag")
            .and_then(Value::as_str)
            .and_then(b64_decode)
            .is_some_and(|tag| pool::shard_sub(&tag, rule.fanout) == sub);
        if !routed_here {
            return Err(format!("misrouted active RLN record in {path}"));
        }
        records.push(
            admission_record(&record)
                .ok_or_else(|| format!("malformed active RLN admission record in {path}"))?,
        );
    }
    Ok(records)
}

fn collect_pool_admission_records(
    storage: &epix_xite::XiteStorage,
    rules: &[PoolRule],
    now: i64,
) -> Result<Vec<PoolAdmissionRecord>, String> {
    let current_epoch = pool::epoch_now(now);
    let cutoff = rln_oldest_active_epoch(current_epoch);
    let oldest_week = pool::week_of(cutoff);
    let newest_week = pool::week_of(current_epoch.saturating_add(1));
    let mut records = Vec::new();
    for rule in rules.iter().filter(|rule| rule.rln_required) {
        for week in oldest_week.max(rule.since_week)..=newest_week {
            for sub in 0..rule.fanout {
                records.extend(collect_pool_admission_shard(
                    storage, rule, week, sub, now, cutoff,
                )?);
            }
        }
    }
    records.sort_by_key(|record| record.id);
    Ok(records)
}

/// Keep only the records in a pool container whose tag routes to shard `sub`.
fn filter_container_to_sub(container: Value, rule: &PoolRule, sub: u16) -> Value {
    let kept: Vec<Value> = container
        .get(pool::POOL_RECORDS_KEY)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|rec| {
                    rec.get("tag")
                        .and_then(|t| t.as_str())
                        .and_then(b64_decode)
                        .map(|t| pool::shard_sub(&t, rule.fanout) == sub)
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    pool::make_pool_container(kept)
}

fn read_pool_container(storage: &epix_xite::XiteStorage, path: &str) -> Result<Value, String> {
    let bytes = match storage.read(path) {
        Ok(bytes) => bytes,
        Err(epix_core::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(pool::make_pool_container(Vec::new()));
        }
        Err(error) => return Err(format!("could not read pool shard {path}: {error}")),
    };
    let container: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid pool shard {path}: {error}"))?;
    if container.get("record_format").and_then(Value::as_str) != Some(pool::POOL_RECORD_FORMAT)
        || !container
            .get(pool::POOL_RECORDS_KEY)
            .is_some_and(Value::is_array)
    {
        return Err(format!("invalid pool shard container {path}"));
    }
    Ok(container)
}

impl AppState {
    // --- descriptors ------------------------------------------------------

    /// The pool rules for a xite (parsed from its root content.json), cached.
    pub async fn pool_rules_for(&self, address: &str) -> Vec<PoolRule> {
        if let Some(rules) = self.pool_rules.read().await.get(address) {
            return rules.clone();
        }
        let rules =
            self.content(address).await.map(|c| pool::pool_rules_of(&c)).unwrap_or_default();
        self.pool_rules.write().await.insert(address.to_string(), rules.clone());
        rules
    }

    pub async fn pool_rule_transaction(self: &Arc<Self>, address: &str) -> PoolRuleTransaction {
        let lock = self.pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        let permit = lock.lock_owned().await;
        PoolRuleTransaction {
            state: self.clone(),
            address: address.to_string(),
            permit: Some(permit),
        }
    }

    /// Re-parse and cache a xite's pool rules (call when its content changes).
    pub async fn refresh_pool_rules(&self, address: &str) {
        let transition = self.pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        let transition_guard = transition.lock().await;
        self.refresh_pool_rules_locked(address).await;
        drop(transition_guard);
        drop(transition);
        self.release_pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
    }

    async fn refresh_pool_rules_locked(&self, address: &str) {
        let content = self.content(address).await;
        let rules = content
            .as_ref()
            .map(pool::pool_rules_of)
            .unwrap_or_default();

        // The same root content owns the RLN roster and allowance. Rebuild the
        // candidate gate before publishing the candidate rules. The refresh
        // returns with its per-address permit still held, so the cache and gate
        // become visible as one admission transaction. A sender can observe the
        // old pair or the new pair, never new descriptor bounds with the old
        // allowance gate.
        let admission = self.pool_admission.read().await.clone();
        if let Some(admission) = admission {
            let mut refreshed = self
                .refresh_pool_admission_candidate(
                    address,
                    admission,
                    content.clone(),
                    rules.clone(),
                )
                .await;
            self.pool_rules
                .write()
                .await
                .insert(address.to_string(), rules);
            if !refreshed.evict.is_empty() {
                if let Err(e) = self.remove_pool_records(address, &refreshed.evict).await {
                    self.log(
                        "ERROR",
                        format!("RLN: failed to quarantine records for {address}: {e}"),
                    )
                    .await;
                }
            }
            if let Some(e) = refreshed.error.take() {
                self.log(
                    "ERROR",
                    format!("RLN: gate build failed for {address}: {e}"),
                )
                .await;
            }
            for offender in &refreshed.offenders {
                self.log(
                    "WARN",
                    format!(
                        "RLN: quarantined a double-signal for {address}; offender commitment {offender}"
                    ),
                )
                .await;
            }
            drop(refreshed.permit.take());
        } else {
            self.pool_rules
                .write()
                .await
                .insert(address.to_string(), rules);
    }
    }

    /// Rebuild a specific admission hook under its per-address transaction
    /// permit. The retained-record scan happens inside the hook's critical
    /// section, closing the scan-to-gate-swap race.
    pub async fn refresh_pool_admission(
        &self,
        address: &str,
        admission: Arc<dyn PoolAdmission>,
    ) -> PoolAdmissionRefresh {
        let transition = self.pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        let transition_guard = transition.lock().await;
        let content = self.content(address).await;
        let rules = self.pool_rules_for(address).await;
        let refreshed = self
            .refresh_pool_admission_candidate(address, admission, content, rules)
            .await;
        drop(transition_guard);
        drop(transition);
        self.release_pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        refreshed
    }

    async fn refresh_pool_admission_candidate(
        &self,
        address: &str,
        admission: Arc<dyn PoolAdmission>,
        content: Option<Value>,
        rules: Vec<PoolRule>,
    ) -> PoolAdmissionRefresh {
        let storage = self.xite_storage(address).await;
        let owned_address = address.to_string();
        tokio::task::spawn_blocking(move || {
            let mut retained = || {
                storage
                    .as_ref()
                    .ok_or_else(|| "unknown xite storage during RLN refresh".to_string())
                    .and_then(|storage| collect_pool_admission_records(storage, &rules, now_ms()))
            };
            admission.refresh_address(&owned_address, content.as_ref(), &mut retained)
        })
        .await
        .unwrap_or_else(|e| PoolAdmissionRefresh {
            error: Some(format!("admission refresh task failed: {e}")),
            ..PoolAdmissionRefresh::default()
        })
    }

    /// Whether `inner_path` is a pool shard of `address` — the serve/write gate.
    pub async fn is_pool_shard(&self, address: &str, inner_path: &str) -> bool {
        pool::is_under_pool_dir(&self.pool_rules_for(address).await, inner_path)
    }

    /// Return a pool shard safe for `GetSigned`. RLN shards are rebuilt from a
    /// locked disk snapshot and passed through the admission layer's read-only
    /// poison check. This prevents a raw poisoned survivor from being served
    /// when durable quarantine succeeded but a later shard cleanup write failed.
    /// A malformed shard or unavailable RLN gate is refused, never served raw.
    pub async fn pool_shard_bytes_for_serve(
        self: &Arc<Self>,
        address: &str,
        inner_path: &str,
    ) -> Option<Vec<u8>> {
        let _rule_transaction = self.pool_rule_transaction(address).await;
        let rules = self.pool_rules_for(address).await;
        let (rule, week, sub) = rules.iter().find_map(|rule| {
            pool::parse_shard_path(rule, inner_path).map(|(week, sub)| (rule, week, sub))
        })?;
        let storage = self.xite_storage(address).await?;
        let path = storage.path(inner_path).ok()?;
        let shard_lock = self.pool_shard_lock(address, inner_path);
        let bytes = {
            let _guard = shard_lock.lock().await;
            (|| -> std::io::Result<Vec<u8>> {
                use std::io::Read as _;

                // The signed-object transport caps pool shards at the rule's
                // clamped max size. Read at most one byte beyond it so a corrupt
                // oversized file cannot become an unbounded GetSigned allocation.
                let mut file = std::fs::File::open(path)?
                    .take((rule.max_shard_bytes as u64).saturating_add(1));
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                if bytes.len() > rule.max_shard_bytes {
                    return Err(std::io::Error::other("pool shard exceeds serve limit"));
                }
                Ok(bytes)
            })()
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, inner_path);
        let bytes = bytes.ok()?;
        let container = serde_json::from_slice::<Value>(&bytes).ok()?;
        if container.get("record_format").and_then(Value::as_str) != Some(pool::POOL_RECORD_FORMAT)
            || !container
                .get(pool::POOL_RECORDS_KEY)
                .is_some_and(Value::is_array)
        {
            return None;
        }
        let now = now_ms();
        let mut records = Vec::new();
        let mut rln_checks = Vec::new();
        for record in pool::pool_records_of(&container) {
            if pool::verify_pool_record(&record, rule, week, now).is_err() {
                continue;
            }
            let routed_here = record
                .get("tag")
                .and_then(Value::as_str)
                .and_then(b64_decode)
                .is_some_and(|tag| pool::shard_sub(&tag, rule.fanout) == sub);
            if !routed_here {
                continue;
            }
            if rule.rln_required {
                let admission = admission_record(&record)?;
                rln_checks.push((record, admission));
            } else {
                records.push(record);
            }
        }
        if rule.rln_required {
            let admission = self.pool_admission.read().await.clone()?;
            let address = address.to_string();
            let checks: Vec<_> = rln_checks.iter().map(|(_, check)| check.clone()).collect();
            let allowed = tokio::task::spawn_blocking(move || {
                admission.allow_rescan_records(&address, &checks)
            })
            .await
            .ok()?;
            records.extend(
                rln_checks
                    .into_iter()
                    .zip(allowed)
                    .filter_map(|((record, _), allowed)| allowed.then_some(record)),
            );
        }
        serde_json::to_vec(&pool::make_pool_container(records)).ok()
    }

    /// The lock serializing one shard's read-merge-write cycle (created on first
    /// use), so a local append and a concurrent inbound merge on the same shard
    /// cannot clobber each other's records.
    fn pool_shard_lock(&self, address: &str, inner_path: &str) -> Arc<tokio::sync::Mutex<()>> {
        let key = format!("{address}\0{inner_path}");
        let mut locks = self.pool_shard_locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.entry(key).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone()
    }

    /// Drop a shard's lock-map entry once no task holds it, so the map cannot grow
    /// without bound as different shard paths are touched. The caller MUST have
    /// dropped its own guard and `Arc` clone first; the map mutex serializes this
    /// against [`Self::pool_shard_lock`], so an entry is removed only when the map
    /// is its sole owner (`strong_count == 1`) — no live holder can be stranded.
    fn release_pool_shard_lock(&self, address: &str, inner_path: &str) {
        let key = format!("{address}\0{inner_path}");
        let mut locks = self.pool_shard_locks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(arc) = locks.get(&key) {
            if Arc::strong_count(arc) == 1 {
                locks.remove(&key);
            }
        }
    }

    /// The pool rule (and its shard week) governing a shard path, if any.
    async fn pool_rule_for_path(
        &self,
        address: &str,
        inner_path: &str,
    ) -> Option<(PoolRule, i64, u16)> {
        for rule in self.pool_rules_for(address).await {
            if let Some((week, sub)) = pool::parse_shard_path(&rule, inner_path) {
                return Some((rule, week, sub));
            }
        }
        None
    }

    /// Broadcast a batch of landed records to pool consumers (no-op if none).
    fn emit_pool_delta(&self, address: &str, records: Vec<Value>) {
        if records.is_empty() {
            return;
        }
        let _ = self
            .pool_events
            .send(PoolDelta { address: address.to_string(), records: Arc::new(records) });
    }

    /// Install the RLN admission hook consulted for `rln_required` pools. Call
    /// once at node startup (the hook lives in a crate that depends on
    /// `epix-rln`; this keeps the proving stack out of `epix-ui`).
    pub async fn set_pool_admission(&self, admission: Arc<dyn PoolAdmission>) {
        *self.pool_admission.write().await = Some(admission);
    }

    /// Structurally verified, live-window RLN records retained on disk. Used to
    /// rebuild the nullifier log at startup and on roster refresh.
    pub async fn pool_admission_records(&self, address: &str) -> Vec<PoolAdmissionRecord> {
        self.pool_admission_records_checked(address)
            .await
            .unwrap_or_default()
    }

    async fn pool_admission_records_checked(
        &self,
        address: &str,
    ) -> Result<Vec<PoolAdmissionRecord>, String> {
        let rules = self.pool_rules_for(address).await;
        let Some(storage) = self.xite_storage(address).await else {
            return Err("unknown xite storage during RLN scan".into());
        };
        tokio::task::spawn_blocking(move || {
            collect_pool_admission_records(&storage, &rules, now_ms())
        })
        .await
        .map_err(|error| format!("RLN retained-record scan task failed: {error}"))?
    }

    /// Remove deterministic RLN losers from every retained shard. Conflicts are
    /// rare, so a full file-list scan keeps the admission seam independent of
    /// shard locations and also handles two colliding records routed to
    /// different sub-shards.
    pub async fn remove_pool_records(
        &self,
        address: &str,
        record_ids: &[PoolRecordId],
    ) -> Result<(), String> {
        self.remove_pool_records_except(address, record_ids, None)
            .await
    }

    async fn remove_pool_record_from_exact_shard(
        &self,
        address: &str,
        shard_path: &str,
        record_id: PoolRecordId,
    ) -> Result<(), String> {
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let shard_lock = self.pool_shard_lock(address, shard_path);
        let outcome = {
            let _guard = shard_lock.lock().await;
            (|| -> Result<(), String> {
                let existing = read_pool_container(&storage, shard_path)?;
                let before = pool::pool_records_of(&existing);
                let after: Vec<Value> = before
                    .iter()
                    .filter(|record| pool_record_id(record) != Some(record_id))
                    .cloned()
                    .collect();
                if after.len() == before.len() {
                    return Ok(());
                }
                let bytes = serde_json::to_vec(&pool::make_pool_container(after))
                    .map_err(|error| error.to_string())?;
                storage
                    .write_atomic_durable(shard_path, &bytes)
                    .map_err(|error| error.to_string())
            })()
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, shard_path);
        outcome
    }

    async fn pool_shard_contains_record(
        &self,
        address: &str,
        shard_path: &str,
        record_id: PoolRecordId,
    ) -> Result<bool, String> {
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let shard_lock = self.pool_shard_lock(address, shard_path);
        let survived = {
            let _guard = shard_lock.lock().await;
            read_pool_container(&storage, shard_path).map(|container| {
                pool::pool_records_of(&container)
                    .iter()
                    .any(|record| pool_record_id(record) == Some(record_id))
            })
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, shard_path);
        survived
    }

    async fn remove_pool_records_except(
        &self,
        address: &str,
        record_ids: &[PoolRecordId],
        exclude_path: Option<&str>,
    ) -> Result<(), String> {
        if record_ids.is_empty() {
            return Ok(());
        }
        let ids: BTreeSet<PoolRecordId> = record_ids.iter().copied().collect();
        let rules = self.pool_rules_for(address).await;
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        for path in storage.list_files().map_err(|e| e.to_string())? {
            if exclude_path == Some(path.as_str()) {
                continue;
            }
            if !rules
                .iter()
                .any(|rule| pool::parse_shard_path(rule, &path).is_some())
            {
                continue;
            }
            let shard_lock = self.pool_shard_lock(address, &path);
            let outcome: Result<(), String> = {
                let _guard = shard_lock.lock().await;
                (|| {
                    let bytes = storage.read(&path).map_err(|e| e.to_string())?;
                    let container = serde_json::from_slice::<Value>(&bytes)
                        .map_err(|e| format!("invalid pool shard {path}: {e}"))?;
                    let before = pool::pool_records_of(&container);
                    let after: Vec<Value> = before
                        .iter()
                        .filter(|record| {
                            admission_record(record).is_none_or(|record| !ids.contains(&record.id))
                        })
                        .cloned()
                        .collect();
                    if after.len() == before.len() {
                        Ok(())
                    } else {
                        let bytes = serde_json::to_vec(&pool::make_pool_container(after))
                            .map_err(|e| e.to_string())?;
                        storage
                            .write_atomic_durable(&path, &bytes)
                            .map_err(|e| e.to_string())
                    }
                })()
            };
            drop(shard_lock);
            self.release_pool_shard_lock(address, &path);
            outcome?;
        }
        Ok(())
    }

    /// Keep only the inbound records whose RLN proof the installed
    /// [`PoolAdmission`] hook accepts. If none is installed for this RLN pool,
    /// keep nothing (fail closed) — an unverified record must never be merged
    /// into a shard we store and serve.
    async fn filter_rln_admitted(
        &self,
        address: &str,
        rule: &PoolRule,
        week: i64,
        container: Value,
    ) -> FilteredRlnAdmission {
        let offered_ids: BTreeSet<PoolRecordId> = pool::pool_records_of(&container)
            .iter()
            .filter_map(pool_record_id)
            .collect();
        let mut first = self
            .filter_rln_admitted_once(address, rule, week, container.clone())
            .await;
        if offered_ids.is_empty() || !first.errors.is_empty() {
            return first;
        }
        let kept_ids: BTreeSet<PoolRecordId> = pool::pool_records_of(&first.container)
            .iter()
            .filter_map(pool_record_id)
            .collect();
        let rejected: BTreeSet<PoolRecordId> = offered_ids.difference(&kept_ids).copied().collect();
        if rejected.is_empty() {
            return first;
        }
        let durable = match self.pool_admission_records_checked(address).await {
            Ok(records) => records
                .into_iter()
                .map(|record| record.id)
                .collect::<BTreeSet<_>>(),
            Err(error) => {
                first.errors.push(error);
                return first;
            }
        };
        if rejected.iter().all(|id| durable.contains(id)) {
            return first;
        }

        // A blocking verifier can finish after its async caller is cancelled.
        // That leaves the in-memory gate mutated but no shard write. Rebuild
        // from the fallible durable scan and retry once. A genuine allowance
        // conflict remains rejected after the rebuild; a cancelled Fresh result
        // becomes admissible again.
        drop(first.permit.take());
        let Some(admission) = self.pool_admission.read().await.clone() else {
            first
                .errors
                .push("RLN admission hook disappeared during repair".into());
            return first;
        };
        // The caller already owns the rule-transition lock. Rebuild the gate
        // directly to avoid recursively acquiring that lock during cancellation
        // repair.
        let content = self.content(address).await;
        let rules = self.pool_rules_for(address).await;
        let mut refreshed = self
            .refresh_pool_admission_candidate(address, admission, content, rules)
            .await;
        if let Some(error) = refreshed.error.take() {
            drop(refreshed.permit.take());
            first.errors.push(error);
            return first;
        }
        if let Err(error) = self.remove_pool_records(address, &refreshed.evict).await {
            drop(refreshed.permit.take());
            first.errors.push(error);
            return first;
        }
        drop(refreshed.permit.take());
        self.filter_rln_admitted_once(address, rule, week, container)
            .await
    }

    async fn filter_rln_admitted_once(
        &self,
        address: &str,
        rule: &PoolRule,
        week: i64,
        container: Value,
    ) -> FilteredRlnAdmission {
        let Some(admission) = self.pool_admission.read().await.clone() else {
            return FilteredRlnAdmission {
                container: pool::make_pool_container(vec![]),
                ..FilteredRlnAdmission::default()
            };
        };
        let records = container
            .get(pool::POOL_RECORDS_KEY)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let address = address.to_string();
        let rule = rule.clone();
        let now = now_ms();
        let oldest_epoch = rln_oldest_active_epoch(pool::epoch_now(now));
        // RLN verification is a CPU-bound Groth16 check; run the whole batch on the
        // blocking pool so it never stalls an async reactor thread. Each record must
        // pass FULL verification (self-signature, PoW, 32-byte tag, ct bucket,
        // epoch↔week binding) BEFORE the nullifier-burning `admit_record`: admitting
        // an otherwise-invalid record (e.g. one with only a corrupted `sign`, which
        // `record_signed_data` strips so PoW still passes) would burn the GENUINE
        // record's RLN nullifier — which `merge_pool` then drops — permanently
        // denying delivery of the real message. This also gates the SNARK verify
        // behind cheap checks, blunting ingest DoS amplification.
        tokio::task::spawn_blocking(move || {
            // Stable order ensures opposite-first replicas pick the same survivor.
            let candidates =
                pool_admission_candidates(records, &rule, week, now, oldest_epoch);
            apply_pool_admission_batch(admission, address, candidates)
        })
        .await
        .unwrap_or_else(|_| FilteredRlnAdmission {
            container: pool::make_pool_container(Vec::new()),
            ..FilteredRlnAdmission::default()
        })
    }

    async fn prepare_pool_admission(
        &self,
        address: &str,
        rule: &PoolRule,
        week: i64,
        container: Value,
    ) -> Result<FilteredRlnAdmission, String> {
        let mut filtered = if rule.rln_required {
            self.filter_rln_admitted(address, rule, week, container)
                .await
        } else {
            FilteredRlnAdmission {
                container,
                ..FilteredRlnAdmission::default()
            }
        };
        if filtered.errors.is_empty() {
            return Ok(filtered);
        }
        let error = filtered.errors.join("; ");
        drop(filtered.permit.take());
        self.log(
            "ERROR",
            format!("RLN: admission failed for {address}: {error}"),
        )
        .await;
        Err(error)
    }

    async fn commit_outbound_pool_shard(
        &self,
        address: &str,
        rule: &PoolRule,
        route: &OutboundPoolRoute,
        incoming: &Value,
        evicted: &[PoolRecordId],
    ) -> Result<PoolWriteOutcome, String> {
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let shard_lock = self.pool_shard_lock(address, &route.shard);
        let outcome = {
            let _guard = shard_lock.lock().await;
            merge_outbound_pool_shard(&storage, rule, route, incoming, evicted)
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, &route.shard);
        outcome
    }

    async fn commit_inbound_pool_shard(
        &self,
        address: &str,
        merge: &InboundPoolMerge<'_>,
    ) -> Result<PoolWriteOutcome, String> {
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let shard_lock = self.pool_shard_lock(address, merge.inner_path);
        let outcome = {
            let _guard = shard_lock.lock().await;
            merge_inbound_pool_shard(&storage, merge)
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, merge.inner_path);
        outcome
    }

    async fn cleanup_prior_pool_routes(
        &self,
        address: &str,
        current_shard: &str,
        cleanup_shards: &[String],
        record_id: Option<PoolRecordId>,
    ) -> Result<(), String> {
        if cleanup_shards.is_empty() {
            return Ok(());
        }
        let record_id = record_id.ok_or("outbound pool record has no stable payload id")?;
        for old_shard in cleanup_shards {
            if old_shard == current_shard {
                continue;
            }
            self.remove_pool_record_from_exact_shard(address, old_shard, record_id)
                .await
                .map_err(|error| format!("could not clean prior pool route {old_shard}: {error}"))?;
        }
        Ok(())
    }

    async fn log_pool_offenders(&self, address: &str, offenders: &[String]) {
        for offender in offenders {
            self.log(
                "WARN",
                format!(
                    "RLN: quarantined a double-signal for {address}; offender commitment {offender}"
                ),
            )
            .await;
        }
    }

    // --- append (local write) --------------------------------------------

    /// Union-merge one record into its shard, persist, broadcast the delta, and
    /// flood the shard to peers. Returns the shard inner path. Mirrors
    /// [`AppState::write_file`]'s merge branch for the `epix-pool-1` class (no
    /// signer ACL — records self-verify via PoW + self-signature).
    pub async fn append_pool_record(
        self: &Arc<Self>,
        address: &str,
        record: Value,
    ) -> Result<String, String> {
        self.append_pool_record_inner(address, record, None, false)
            .await?
            .stable_shard()
    }

    /// Channel durable-outbox append. The exact precomputed shard route must
    /// still match, the record must survive shard-cap eviction, and at least one
    /// peer must confirm publication before the caller may acknowledge SQLite.
    pub async fn append_pool_record_confirmed(
        self: &Arc<Self>,
        address: &str,
        expected_shard: &str,
        record: Value,
    ) -> Result<String, String> {
        self.append_pool_record_inner(address, record, Some(expected_shard), true)
            .await?
            .stable_shard()
    }

    /// Confirm a durable outbox route migration. The new route is committed
    /// first. Every persisted prior route is then stripped by logical record id
    /// before any peer confirmation may acknowledge the outbox row.
    pub async fn append_pool_record_confirmed_migrating(
        self: &Arc<Self>,
        address: &str,
        expected_shard: &str,
        record: Value,
        cleanup_shards: &[String],
    ) -> Result<String, String> {
        self.append_pool_record_inner_with_cleanup(
            address,
            record,
            Some(expected_shard),
            true,
            cleanup_shards,
        )
        .await?
        .stable_shard()
    }

    /// Structured channel append used by durable legacy recovery. A peer may
    /// accept the immutable staged snapshot while a concurrent root transition
    /// changes its local route. That is a confirmed delivery, not a transport
    /// failure, even when a pre-v5 row lacks private material for rerouting.
    pub async fn append_pool_record_confirmed_migrating_status(
        self: &Arc<Self>,
        address: &str,
        expected_shard: &str,
        record: Value,
        cleanup_shards: &[String],
    ) -> Result<PoolAppendConfirmation, String> {
        self.append_pool_record_inner_with_cleanup(
            address,
            record,
            Some(expected_shard),
            true,
            cleanup_shards,
        )
        .await
    }

    /// Current route for an already-sealed record. The shard path is not part
    /// of the signed payload, so a delayed durable outbox row may migrate across
    /// a directory/fanout-only descriptor change without re-sealing a ratchet.
    pub async fn pool_shard_for_record(
        &self,
        address: &str,
        record: &Value,
    ) -> Result<String, String> {
        let rule = self
            .pool_rules_for(address)
            .await
            .into_iter()
            .next()
            .ok_or("no pool configured on this xite")?;
        let tag = record
            .get("tag")
            .and_then(Value::as_str)
            .and_then(b64_decode)
            .ok_or("pool record missing tag")?;
        let epoch = record
            .get("epoch")
            .and_then(Value::as_i64)
            .ok_or("pool record missing epoch")?;
        Ok(pool::shard_path(&rule, epoch, &tag))
    }

    async fn append_pool_record_inner(
        self: &Arc<Self>,
        address: &str,
        record: Value,
        expected_shard: Option<&str>,
        await_publish: bool,
    ) -> Result<PoolAppendConfirmation, String> {
        self.append_pool_record_inner_with_cleanup(
            address,
            record,
            expected_shard,
            await_publish,
            &[],
        )
        .await
    }

    async fn append_pool_record_inner_with_cleanup(
        self: &Arc<Self>,
        address: &str,
        record: Value,
        expected_shard: Option<&str>,
        await_publish: bool,
        cleanup_shards: &[String],
    ) -> Result<PoolAppendConfirmation, String> {
        let transition = self.pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        let transition_guard = transition.lock().await;
        let result = self
            .append_pool_record_under_rule_lock(address, record, expected_shard, cleanup_shards)
            .await;
        drop(transition_guard);
        drop(transition);
        self.release_pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        let (shard, snapshot, record_id) = match result {
            Ok(staged) => staged,
            Err(error) => {
                self.refresh_pool_rules(address).await;
                return Err(error);
            }
        };
        if await_publish {
            let expected = record_id.ok_or("outbound pool record has no stable payload id")?;
            let exact_record = serde_json::from_slice::<Value>(&snapshot)
                .ok()
                .and_then(|container| {
                    pool::pool_records_of(&container)
                        .into_iter()
                        .find(|record| pool_record_id(record) == Some(expected))
                })
                .ok_or("durable pool snapshot lost the exact outbound record")?;
            let published = self
                .publish_bytes_to(
                    address,
                    &shard,
                    snapshot,
                    POOL_PUSH_LIMIT,
                    true,
                    Default::default(),
                    None,
                )
                .await?;
            if published == 0 {
                return Err("pool record is durable locally but reached no peers".into());
            }
            let _rule_transaction = self.pool_rule_transaction(address).await;
            match self.pool_shard_for_record(address, &exact_record).await {
                Ok(current_shard) if current_shard != shard => {
                    return Ok(PoolAppendConfirmation::RouteChangedAfterPeerConfirmation {
                        staged_shard: shard,
                    });
                }
                Ok(_) => {}
                Err(reason) => {
                    return Ok(
                        PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
                            staged_shard: shard,
                            reason,
                        },
                    );
                }
            }
            match self
                .pool_shard_contains_record(address, &shard, expected)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(
                        PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
                            staged_shard: shard,
                            reason: "exact outbound record was evicted during publication".into(),
                        },
                    );
                }
                Err(reason) => {
                    return Ok(
                        PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
                            staged_shard: shard,
                            reason,
                        },
                    );
                }
            }
        } else {
            let this = self.clone();
            let addr = address.to_string();
            let shard_clone = shard.clone();
            tokio::spawn(async move {
                let _ = this
                    .publish_bytes_to(
                        &addr,
                        &shard_clone,
                        snapshot,
                        POOL_PUSH_LIMIT,
                        false,
                        Default::default(),
                        None,
                    )
                    .await;
            });
        }
        Ok(PoolAppendConfirmation::Stable { shard })
    }

    async fn append_pool_record_under_rule_lock(
        self: &Arc<Self>,
        address: &str,
        record: Value,
        expected_shard: Option<&str>,
        cleanup_shards: &[String],
    ) -> Result<(String, Vec<u8>, Option<PoolRecordId>), String> {
        let rule = self
            .pool_rules_for(address)
            .await
            .into_iter()
            .next()
            .ok_or("no pool configured on this xite")?;
        let route = outbound_pool_route(&rule, &record, expected_shard)?;
        let mut filtered = self
            .prepare_pool_admission(
                address,
                &rule,
                pool::week_of(route.epoch),
                pool::make_pool_container(vec![record]),
            )
            .await?;
        let admission_permit = filtered.permit.take();
        let incoming = filtered.container;
        let evicted = filtered.evicted;
        let (delta, snapshot) = match self
            .commit_outbound_pool_shard(address, &rule, &route, &incoming, &evicted)
            .await
        {
            Ok(PoolWriteOutcome::Committed {
                delta, snapshot, ..
            }) => (delta, snapshot),
            Ok(PoolWriteOutcome::CapacityRejected) => {
                drop(admission_permit);
                return Err("pool capacity dropped the exact outbound record".into());
            }
            Err(e) => {
                drop(admission_permit);
                return Err(e);
            }
        };
        if let Err(e) = self
            .remove_pool_records_except(address, &evicted, Some(&route.shard))
            .await
        {
            drop(admission_permit);
            return Err(e);
        }
        if let Err(error) = self
            .cleanup_prior_pool_routes(address, &route.shard, cleanup_shards, route.record_id)
            .await
        {
            drop(admission_permit);
            return Err(error);
        }
        drop(admission_permit);
        self.log_pool_offenders(address, &filtered.offenders).await;
        let delivered = deliverable_pool_records(delta, filtered.suppress_delivery);
        self.emit_pool_delta(address, delivered);
        Ok((route.shard, snapshot, route.record_id))
    }

    // --- inbound (peer push / sweep) -------------------------------------

    /// Apply an inbound pool shard container: union-merge into the local shard,
    /// broadcast the delta, and re-flood. Returns whether anything new landed.
    /// The pool analog of [`AppState::apply_inbound_update`], but not gated to
    /// content.json (pool shards are not content.json).
    pub async fn apply_inbound_pool_update(
        self: &Arc<Self>,
        address: &str,
        inner_path: &str,
        signed: &[u8],
    ) -> Result<bool, String> {
        let transition = self.pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        let transition_guard = transition.lock().await;
        let result = self
            .apply_inbound_pool_update_under_rule_lock(address, inner_path, signed)
            .await;
        drop(transition_guard);
        drop(transition);
        self.release_pool_shard_lock(address, POOL_RULE_TRANSITION_LOCK);
        if result.is_err()
            && self
                .pool_rule_for_path(address, inner_path)
                .await
                .is_some_and(|(rule, _, _)| rule.rln_required)
        {
            self.refresh_pool_rules(address).await;
        }
        result
    }

    async fn apply_inbound_pool_update_under_rule_lock(
        self: &Arc<Self>,
        address: &str,
        inner_path: &str,
        signed: &[u8],
    ) -> Result<bool, String> {
        let (rule, week, sub) = self
            .pool_rule_for_path(address, inner_path)
            .await
            .ok_or("not a pool shard")?;
        // Reject shards for weeks beyond the current one: no valid record can
        // target a future epoch (verify_pool_record rejects them), so accepting
        // arbitrary future weeks would only let a peer allocate per-shard state.
        let current_week = pool::week_of(pool::epoch_now(now_ms()));
        if week > current_week + 1 {
            return Err("pool shard is in the future".into());
        }
        let incoming: Value =
            serde_json::from_slice(signed).map_err(|e| format!("pool shard not JSON: {e}"))?;

        // Keep the peer's complete offer so transport acknowledgement can mean
        // "retained", rather than merely "the merge call did not fail". A
        // duplicate payload is accepted if it is already in the durable shard,
        // but a malformed, misrouted, RLN-rejected, or capacity-evicted record
        // must make the EDX request fail so the sender retains its outbox row.
        let offered_ids = pool_record_ids(&incoming);
        let offer_well_formed =
            inbound_offer_is_well_formed(&incoming, &rule, week, sub, &offered_ids);

        // Bind the incoming records to THIS shard's sub-index FIRST — before any
        // nullifier-mutating RLN admission. A record whose tag routes to a
        // different sub does not belong in this shard, and letting it reach
        // `admit_record` would BURN its RLN nullifier (poisoning the genuine copy
        // destined for the correct sub) even though `merge_pool` would then drop
        // it. `merge_pool` re-checks the sub as defense in depth.
        let incoming = filter_container_to_sub(incoming, &rule, sub);

        // Anonymous rate-limiting: for an RLN pool, drop any inbound record whose
        // proof does not verify (and let the verifier track nullifiers / evict
        // double-signallers) BEFORE it is merged into the shard we store & serve.
        let mut filtered = self
            .prepare_pool_admission(address, &rule, week, incoming)
            .await?;
        let admission_permit = filtered.permit.take();
        let incoming = filtered.container;
        let evicted = filtered.evicted;
        let merge = InboundPoolMerge {
            inner_path,
            rule: &rule,
            week,
            sub,
            incoming: &incoming,
            evicted: &evicted,
            offer_well_formed,
            offered_ids: &offered_ids,
        };
        let (delta, accepted) = match self.commit_inbound_pool_shard(address, &merge).await {
            Ok(PoolWriteOutcome::Committed {
                delta, accepted, ..
            }) => (delta, accepted),
            Ok(PoolWriteOutcome::CapacityRejected) => {
                drop(admission_permit);
                return Err("peer pool update was dropped by shard capacity".into());
            }
            Err(e) => {
                drop(admission_permit);
                return Err(e);
            }
        };
        // The current shard replacement above commits its survivor and local
        // evictions together. Remove displaced records from other shards only
        // after that write succeeds, so a storage failure never deletes the old
        // survivor before the new one is durable.
        if let Err(e) = self
            .remove_pool_records_except(address, &evicted, Some(inner_path))
            .await
        {
            drop(admission_permit);
            return Err(e);
        }
        drop(admission_permit);
        self.log_pool_offenders(address, &filtered.offenders).await;
        if !accepted {
            return Err("peer pool update was not retained exactly".into());
        }
        if delta.is_empty() {
            return Ok(false);
        }
        let delivered = deliverable_pool_records(delta, filtered.suppress_delivery);
        self.emit_pool_delta(address, delivered);

        let this = self.clone();
        let addr = address.to_string();
        let path = inner_path.to_string();
        tokio::spawn(async move {
            let _ = this
                .publish_to(
                    &addr,
                    &path,
                    crate::state::UpdatePayload::default(),
                    crate::state::PublishOptions {
                        limit: POOL_REFLOOD_LIMIT,
                        exhaustive: false,
                        expected_modified: None,
                        progress: None,
                    },
                )
                .await;
        });
        Ok(true)
    }


    /// Anti-entropy sweep of the current + previous week's shards (mirrors
    /// [`AppState::resync_merge_files_for`], enumerating shard paths from the
    /// pool descriptor rather than `declared_merge_files`).
    pub async fn resync_pool_shards_for(self: &Arc<Self>, address: &str) {
        if !self.is_serving(address).await {
            return;
        }
        let rules = self.pool_rules_for(address).await;
        if rules.is_empty() {
            return;
        }
        let cur_week = pool::week_of(pool::epoch_now(now_ms()));
        let candidates = self.fetch_candidate_peers(address, POOL_SWEEP_PEERS).await;
        if candidates.is_empty() {
            return;
        }
        let started = std::time::Instant::now();
        let total = candidates.len();
        let now = now_ms();
        let mut due = Vec::new();
        let mut skipped = 0usize;
        for rule in &rules {
            for week in [cur_week - 1, cur_week] {
                if week < rule.since_week {
                    continue;
                }
                for sub in 0..rule.fanout {
                    let path = format!("{}/w{}/{:02x}.json", rule.dir, week, sub);
                    if self.pool_shard_due(address, &path, now) {
                        due.push(path);
                    } else {
                        skipped += 1;
                    }
                }
            }
        }
        let mut pass = SweepPass::new(candidates);
        pass.sweep_paths(self, address, due, true).await;
        self.log_sweep_pass(address, total, &pass, skipped, started.elapsed()).await;

        // Reclaim disk: drop shards past the owner-set retention window.
        self.prune_expired_pool_shards(address).await;
    }

    /// Whether this shard path is due for a sweep, per its quiet-backoff.
    /// Cold shards (nothing new for several passes) are asked for far less
    /// often than the one or two that are actually receiving records.
    fn pool_shard_due(&self, address: &str, path: &str, now_ms: i64) -> bool {
        let key = format!("{address}\0{path}");
        self.pool_sweep_backoff
            .lock()
            .map(|map| map.get(&key).is_none_or(|(_, next)| now_ms >= *next))
            .unwrap_or(true)
    }

    /// Record what a swept path yielded: anything new makes it hot again, a
    /// quiet pass cools it (exponential, capped at [`POOL_SWEEP_QUIET_CAP_MS`]).
    pub(crate) fn note_pool_sweep_result(&self, address: &str, path: &str, merged: bool) {
        let key = format!("{address}\0{path}");
        let Ok(mut map) = self.pool_sweep_backoff.lock() else { return };
        if merged {
            map.remove(&key);
            return;
        }
        let entry = map.entry(key).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        let delay = POOL_SWEEP_QUIET_BASE_MS
            .saturating_mul(1i64 << entry.0.min(6))
            .min(POOL_SWEEP_QUIET_CAP_MS);
        entry.1 = now_ms().saturating_add(delay);
    }

    /// One log line per sweep pass, and a WARNING when nothing answered - a
    /// mute sweep must never be invisible (a node in that state can send but
    /// cannot receive, and nothing else surfaces it).
    async fn log_sweep_pass(
        &self,
        address: &str,
        peers: usize,
        pass: &SweepPass,
        skipped: usize,
        took: std::time::Duration,
    ) {
        let (served, merged, paths) = (pass.served, pass.merged, pass.paths);
        // A pass that asked for shards and got NOTHING back from any peer is
        // the mute-sweep signal: inbound records cannot arrive, and nothing
        // else surfaces it (this node can still send, so it feels fine).
        if paths > 0 && served == 0 {
            self.log(
                "WARNING",
                format!(
                    "pool sweep {address}: no peer served any of {paths} shard path(s) \
                     across {peers} candidate(s); inbound records cannot arrive"
                ),
            )
            .await;
        } else {
            self.log(
                "DEBUG",
                format!(
                    "pool sweep {address}: {served}/{paths} path(s) served, {merged} merged, \
                     {skipped} quiet path(s) skipped, {peers} candidate(s) in {:.1}s",
                    took.as_secs_f64()
                ),
            )
            .await;
        }
    }

    /// Delete pool shards older than the rule's retention window, set by the xite
    /// owner in content.json (`retention_weeks`; absent or `0` = keep forever, so
    /// this is a no-op then). Received messages live in each recipient's private
    /// index, so pruning the SHARED pool never loses delivered mail — it only
    /// reclaims disk. Also runs on the sweep tick.
    pub async fn prune_expired_pool_shards(self: &Arc<Self>, address: &str) {
        let rules = self.pool_rules_for(address).await;
        if rules.iter().all(|r| r.retention_weeks <= 0) {
            return; // no rule sets retention -> keep everything
        }
        let Some(storage) = self.xite_storage(address).await else {
            return;
        };
        let current_epoch = pool::epoch_now(now_ms());
        let files = storage.list_files().unwrap_or_default();
        for rule in &rules {
            let Some(keep_from) = retention_keep_from_for_rule(rule, current_epoch) else {
                continue;
            };
            for path in &files {
                if let Some((week, _sub)) = pool::parse_shard_path(rule, path) {
                    if week < keep_from {
                        let _ = storage.delete(path);
                    }
                }
            }
        }
    }

    /// Newest-first historical backfill up to `max_weeks` back (0 = all),
    /// honoring the descriptor's `sync_order`.
    pub async fn backfill_pool_shards(self: &Arc<Self>, address: &str, max_weeks: u64) {
        if !self.is_serving(address).await {
            return;
        }
        let rules = self.pool_rules_for(address).await;
        if rules.is_empty() {
            return;
        }
        let cur_week = pool::week_of(pool::epoch_now(now_ms()));
        let peers = self.fetch_candidate_peers(address, POOL_SWEEP_PEERS).await;
        if peers.is_empty() {
            return;
        }
        // One dial session for the whole history, like the periodic sweep - a
        // backfill enumerates far more paths, so per-path dialing hurt most
        // here. Order is preserved (`sync_shard_paths` is newest-first when the
        // descriptor asks for it), and the quiet-backoff is deliberately NOT
        // consulted: a backfill is the explicit "fetch history now" request.
        let mut paths = Vec::new();
        for rule in &rules {
            let start_week = if max_weeks == 0 {
                rule.since_week
            } else {
                (cur_week - max_weeks as i64 + 1).max(rule.since_week)
            };
            for path in pool::sync_shard_paths(rule, cur_week) {
                if matches!(pool::parse_shard_path(rule, &path), Some((week, _)) if week >= start_week)
                {
                    paths.push(path);
                }
            }
        }
        let mut pass = SweepPass::new(peers);
        pass.sweep_paths(self, address, paths, false).await;
    }

    /// Read every on-disk shard of `address` and return all records — the source
    /// consumers rescan from when a late-arriving record needs a second pass.
    pub async fn pool_all_records(self: &Arc<Self>, address: &str) -> Vec<Value> {
        let _rule_transaction = self.pool_rule_transaction(address).await;
        let rules = self.pool_rules_for(address).await;
        let Some(storage) = self.xite_storage(address).await else {
            return Vec::new();
        };
        let (mut records, rln_records) = scan_all_pool_records(&storage, &rules, now_ms());
        if rln_records.is_empty() {
            return records;
        }
        let Some(admission) = self.pool_admission.read().await.clone() else {
            return records;
        };
        let address = address.to_string();
        let checks: Vec<PoolAdmissionRecord> = rln_records
            .iter()
            .map(|(_, admission)| admission.clone())
            .collect();
        let allowed = tokio::task::spawn_blocking(move || {
            admission.allow_rescan_records(&address, &checks)
        })
        .await
        .unwrap_or_default();
        records.extend(
            rln_records
                .into_iter()
                .zip(allowed)
                .filter_map(|((record, _), allowed)| allowed.then_some(record)),
        );
        records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retention_rule(rln_required: bool) -> PoolRule {
        PoolRule {
            dir: "pool".into(),
            class: pool::POOL_RECORD_FORMAT.into(),
            since_week: 0,
            fanout: 1,
            pow_bits: 0,
            pad_buckets: vec![64],
            max_record_bytes: 4096,
            max_shard_bytes: 1_000_000,
            newest_first: true,
            rln_required,
            retention_weeks: 1,
        }
    }

    #[test]
    fn rln_retention_keeps_every_week_touched_by_the_active_epoch_window() {
        assert_eq!(
            retention_keep_from_for_rule(&retention_rule(false), 14),
            Some(2)
        );
        assert_eq!(
            retention_keep_from_for_rule(&retention_rule(true), 14),
            Some(1)
        );
        assert_eq!(
            retention_keep_from_for_rule(&retention_rule(true), 13),
            Some(0)
        );
    }
}
