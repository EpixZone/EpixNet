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
/// Distinct served copies to union per shard before moving on.
const POOL_SWEEP_UNION: usize = 2;
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
                let path = format!("{}/w{week}/{sub:02x}.json", rule.dir);
                let container = read_pool_container(storage, &path)?;
                for record in pool::pool_records_of(&container) {
                    let epoch = record.get("epoch").and_then(Value::as_i64).unwrap_or(-1);
                    if epoch < cutoff {
                        continue;
                    }
                    pool::verify_pool_record(&record, rule, week, now).map_err(|error| {
                        format!("invalid active RLN record in {path}: {error:?}")
                    })?;
                    let routed_here = record
                        .get("tag")
                        .and_then(Value::as_str)
                        .and_then(b64_decode)
                        .is_some_and(|tag| pool::shard_sub(&tag, rule.fanout) == sub);
                    if !routed_here {
                        return Err(format!("misrouted active RLN record in {path}"));
                    }
                    let admitted = admission_record(&record).ok_or_else(|| {
                        format!("malformed active RLN admission record in {path}")
                    })?;
                    records.push(admitted);
                }
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
        for path in storage.list_files() {
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
        let (kept, evicted, suppress_delivery, offenders, errors, permit) =
            tokio::task::spawn_blocking(move || {
                let mut candidates: Vec<(PoolRecordId, Value, PoolAdmissionRecord)> = records
                .into_iter()
                    .filter_map(|record| {
                        if pool::verify_pool_record(&record, &rule, week, now).is_err() {
                            return None;
                    }
                        let admission = admission_record(&record)?;
                        if admission.epoch < oldest_epoch {
                            return None;
                    }
                        Some((admission.id, record, admission))
                })
                    .collect();
                // Deterministic within-batch order prevents a higher id admitted
                // earlier in the same container from surviving until a later disk
                // cleanup pass.
                candidates.sort_by_key(|(id, _, _)| *id);
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
                    evicted.extend(decision.evict);
                    offenders.extend(decision.offenders);
                    if let Some(error) = decision.error {
                        errors.push(error);
                    }
                    if decision.admit {
                        if !decision.deliver {
                            suppress_delivery.insert(id);
                        }
                        kept.push((id, record));
                    }
                }
                kept.retain(|(id, _)| !evicted.contains(id));
                suppress_delivery.retain(|id| !evicted.contains(id));
                (
                    kept.into_iter()
                        .map(|(_, record)| record)
                        .collect::<Vec<Value>>(),
                    evicted.into_iter().collect::<Vec<PoolRecordId>>(),
                    suppress_delivery.into_iter().collect::<Vec<PoolRecordId>>(),
                    offenders.into_iter().collect::<Vec<String>>(),
                    errors,
                    batch.permit.take(),
                )
        })
        .await
        .unwrap_or_default();
        FilteredRlnAdmission {
            container: pool::make_pool_container(kept),
            evicted,
            suppress_delivery,
            offenders,
            errors,
            permit,
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

        let tag = record
            .get("tag")
            .and_then(|v| v.as_str())
            .and_then(b64_decode)
            .ok_or("pool record missing tag")?;
        let epoch =
            record.get("epoch").and_then(|v| v.as_i64()).ok_or("pool record missing epoch")?;
        let shard = pool::shard_path(&rule, epoch, &tag);
        if expected_shard.is_some_and(|expected| expected != shard) {
            return Err(format!(
                "staged pool route changed: expected {}, current rule routes to {shard}",
                expected_shard.unwrap_or_default()
            ));
        }
        let record_id = pool_record_id(&record);
        let mut filtered = if rule.rln_required {
            self.filter_rln_admitted(
                address,
                &rule,
                pool::week_of(epoch),
                pool::make_pool_container(vec![record]),
            )
            .await
        } else {
            FilteredRlnAdmission {
                container: pool::make_pool_container(vec![record]),
                ..FilteredRlnAdmission::default()
            }
        };
        let admission_permit = filtered.permit.take();
        if !filtered.errors.is_empty() {
            let error = filtered.errors.join("; ");
            drop(admission_permit);
            self.log(
                "ERROR",
                format!("RLN: admission failed for {address}: {error}"),
            )
            .await;
            return Err(error);
        }
        let incoming = filtered.container;
        let evicted = filtered.evicted;

        // Serialize the read-merge-write against a concurrent inbound merge on the
        // same shard, or the just-appended record could be clobbered before the
        // spawned publish re-reads the shard (and the recipient never gets it).
        // Fetch storage before the lock so the critical section holds no `?`
        // early-exit that would skip the lock-map cleanup below.
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let shard_lock = self.pool_shard_lock(address, &shard);
        let outcome: Result<PoolWriteOutcome, String> = {
            let _guard = shard_lock.lock().await;
            (|| -> Result<PoolWriteOutcome, String> {
                let existing = read_pool_container(&storage, &shard)?;
                let already_present = record_id.is_some_and(|id| {
                    pool::pool_records_of(&existing)
                        .iter()
                        .any(|record| pool_record_id(record) == Some(id))
                });
                if rule.rln_required
                    && pool::pool_records_of(&incoming).is_empty()
                    && evicted.is_empty()
                    && !already_present
                {
                    Err("local RLN record was rejected by admission".into())
                } else {
                    let evicted_here: BTreeSet<PoolRecordId> = evicted.iter().copied().collect();
                    let before = pool::pool_records_of(&existing);
                    let filtered: Vec<Value> = before
                        .iter()
                        .filter(|record| {
                            admission_record(record)
                                .is_none_or(|record| !evicted_here.contains(&record.id))
                        })
                        .cloned()
                        .collect();
                    let existing = if filtered.len() != before.len() {
                        pool::make_pool_container(filtered)
                    } else {
                        existing
                    };
            let (merged, delta) = pool::merge_pool(
                &existing,
                &incoming,
                &rule,
                pool::week_of(epoch),
                pool::shard_sub(&tag, rule.fanout),
                now_ms(),
            );
                    let expected: BTreeSet<PoolRecordId> = pool::pool_records_of(&incoming)
                        .iter()
                        .filter_map(pool_record_id)
                        .collect();
                    let survived: BTreeSet<PoolRecordId> = pool::pool_records_of(&merged)
                        .iter()
                        .filter_map(pool_record_id)
                        .collect();
                    if !expected.is_subset(&survived) {
                        Ok(PoolWriteOutcome::CapacityRejected)
                    } else {
                        let snapshot = serde_json::to_vec(&merged).map_err(|e| e.to_string())?;
                        storage
                            .write_atomic_durable(&shard, &snapshot)
                            .map_err(|e| e.to_string())?;
                        Ok(PoolWriteOutcome::Committed {
                            delta,
                            accepted: true,
                            snapshot,
                        })
                    }
                }
            })()
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, &shard);

        let (delta, snapshot) = match outcome {
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
            .remove_pool_records_except(address, &evicted, Some(&shard))
            .await
        {
            drop(admission_permit);
            return Err(e);
        }
        if !cleanup_shards.is_empty() {
            let cleanup_id = record_id.ok_or("outbound pool record has no stable payload id")?;
            for old_shard in cleanup_shards {
                if old_shard != &shard {
                    if let Err(error) = self
                        .remove_pool_record_from_exact_shard(address, old_shard, cleanup_id)
                        .await
                    {
                        drop(admission_permit);
                        return Err(format!(
                            "could not clean prior pool route {old_shard}: {error}"
                        ));
                    }
                }
            }
        }
        drop(admission_permit);
        for offender in &filtered.offenders {
            self.log(
                "WARN",
                format!(
                    "RLN: quarantined a double-signal for {address}; offender commitment {offender}"
                ),
            )
                .await;
        }
        let suppress_delivery: BTreeSet<PoolRecordId> =
            filtered.suppress_delivery.into_iter().collect();
        let delivered: Vec<Value> = delta
            .into_iter()
            .filter(|record| {
                pool_record_id(record).is_none_or(|id| !suppress_delivery.contains(&id))
            })
            .collect();
        self.emit_pool_delta(address, delivered);
        Ok((shard, snapshot, record_id))
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
        let offered = pool::pool_records_of(&incoming);
        let offered_ids: BTreeSet<PoolRecordId> =
            offered.iter().filter_map(pool_record_id).collect();
        let offer_well_formed = incoming.get("record_format").and_then(Value::as_str)
            == Some(pool::POOL_RECORD_FORMAT)
            && incoming
                .get(pool::POOL_RECORDS_KEY)
                .is_some_and(Value::is_array)
            && offered.len() == offered_ids.len()
            && offered.iter().all(|record| {
                pool::verify_pool_record(record, &rule, week, now_ms()).is_ok()
                    && record
                        .get("tag")
                        .and_then(Value::as_str)
                        .and_then(b64_decode)
                        .is_some_and(|tag| pool::shard_sub(&tag, rule.fanout) == sub)
            });

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
        let mut filtered = if rule.rln_required {
            self.filter_rln_admitted(address, &rule, week, incoming)
                .await
        } else {
            FilteredRlnAdmission {
                container: incoming,
                ..FilteredRlnAdmission::default()
            }
        };
        let admission_permit = filtered.permit.take();
        if !filtered.errors.is_empty() {
            let error = filtered.errors.join("; ");
            drop(admission_permit);
            self.log(
                "ERROR",
                format!("RLN: admission failed for {address}: {error}"),
            )
            .await;
            return Err(error);
        }
        let incoming = filtered.container;
        let evicted = filtered.evicted;

        // Fetch storage before taking the shard lock so the read-merge-write
        // critical section holds no `?` early-exit that would skip lock cleanup.
        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;

        // Serialize the read-merge-write against a concurrent local append or
        // another inbound merge on the same shard (see `pool_shard_lock`).
        let shard_lock = self.pool_shard_lock(address, inner_path);
        let outcome: Result<PoolWriteOutcome, String> = {
            let _guard = shard_lock.lock().await;
            (|| -> Result<PoolWriteOutcome, String> {
                let existing = read_pool_container(&storage, inner_path)?;
                let evicted_here: BTreeSet<PoolRecordId> = evicted.iter().copied().collect();
                let before = pool::pool_records_of(&existing);
                let filtered: Vec<Value> = before
                    .iter()
                    .filter(|record| {
                        admission_record(record)
                            .is_none_or(|record| !evicted_here.contains(&record.id))
                    })
                    .cloned()
                    .collect();
                let removed_here = filtered.len() != before.len();
                let existing = if removed_here {
                    pool::make_pool_container(filtered)
                } else {
                    existing
                };
                let (merged, delta) =
                    pool::merge_pool(&existing, &incoming, &rule, week, sub, now_ms());
                let expected: BTreeSet<PoolRecordId> = pool::pool_records_of(&incoming)
                    .iter()
                    .filter_map(pool_record_id)
                    .collect();
                let survived: BTreeSet<PoolRecordId> = pool::pool_records_of(&merged)
                    .iter()
                    .filter_map(pool_record_id)
                    .collect();
                if !expected.is_subset(&survived) {
                    Ok(PoolWriteOutcome::CapacityRejected)
                } else if !removed_here && merged == existing {
                    let snapshot = serde_json::to_vec(&merged).map_err(|e| e.to_string())?;
                    Ok(PoolWriteOutcome::Committed {
                        delta: Vec::new(),
                        accepted: offer_well_formed && offered_ids.is_subset(&survived),
                        snapshot,
                    })
            } else {
                    let snapshot = serde_json::to_vec(&merged).map_err(|e| e.to_string())?;
                    storage
                        .write_atomic_durable(inner_path, &snapshot)
                        .map_err(|e| e.to_string())?;
                    Ok(PoolWriteOutcome::Committed {
                        delta,
                        accepted: offer_well_formed && offered_ids.is_subset(&survived),
                        snapshot,
                    })
            }
            })()
        };
        drop(shard_lock);
        self.release_pool_shard_lock(address, inner_path);

        let (delta, accepted) = match outcome {
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
        for offender in &filtered.offenders {
            self.log(
                "WARN",
                format!(
                    "RLN: quarantined a double-signal for {address}; offender commitment {offender}"
                ),
            )
            .await;
        }
        if !accepted {
            return Err("peer pool update was not retained exactly".into());
        }
        if delta.is_empty() {
            return Ok(false);
        }
        let suppress_delivery: BTreeSet<PoolRecordId> =
            filtered.suppress_delivery.into_iter().collect();
        let delivered: Vec<Value> = delta
            .iter()
            .filter(|record| {
                pool_record_id(record).is_none_or(|id| !suppress_delivery.contains(&id))
            })
            .cloned()
            .collect();
        self.emit_pool_delta(address, delivered);

        let this = self.clone();
        let addr = address.to_string();
        let path = inner_path.to_string();
        tokio::spawn(async move {
            let _ = this
                .publish_to(&addr, &path, POOL_REFLOOD_LIMIT, false, Default::default(), None)
                .await;
        });
        Ok(true)
    }

    /// Fetch one shard path from up to `POOL_SWEEP_UNION` peers and merge each
    /// served copy locally.
    async fn sweep_one_shard(
        self: &Arc<Self>,
        address: &str,
        path: &str,
        peers: &[epix_core::PeerAddr],
    ) {
        let mut merged_from = 0usize;
        for peer in peers {
            if merged_from >= POOL_SWEEP_UNION {
                break;
            }
            if let Some(bytes) = self.fetch_signed_from(peer, address, path).await {
                if self.apply_inbound_pool_update(address, path, &bytes).await.unwrap_or(false) {
                    merged_from += 1;
                }
            }
        }
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
        let peers = self.fetch_candidate_peers(address, POOL_SWEEP_PEERS).await;
        if peers.is_empty() {
            return;
        }
        for rule in &rules {
            for week in [cur_week - 1, cur_week] {
                if week < rule.since_week {
                    continue;
                }
                for sub in 0..rule.fanout {
                    let path = format!("{}/w{}/{:02x}.json", rule.dir, week, sub);
                    self.sweep_one_shard(address, &path, &peers).await;
                }
            }
        }

        // Reclaim disk: drop shards past the owner-set retention window.
        self.prune_expired_pool_shards(address).await;
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
        let files = storage.list_files();
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
        for rule in &rules {
            let start_week = if max_weeks == 0 {
                rule.since_week
            } else {
                (cur_week - max_weeks as i64 + 1).max(rule.since_week)
            };
            for path in pool::sync_shard_paths(rule, cur_week) {
                match pool::parse_shard_path(rule, &path) {
                    Some((week, _)) if week >= start_week => {
                        self.sweep_one_shard(address, &path, &peers).await;
                    }
                    _ => {}
                }
            }
        }
    }

    /// Read every on-disk shard of `address` and return all records — the source
    /// consumers rescan from when a late-arriving record needs a second pass.
    pub async fn pool_all_records(self: &Arc<Self>, address: &str) -> Vec<Value> {
        let _rule_transaction = self.pool_rule_transaction(address).await;
        let rules = self.pool_rules_for(address).await;
        let Some(storage) = self.xite_storage(address).await else {
            return Vec::new();
        };
        let now = now_ms();
        let current_epoch = pool::epoch_now(now);
        let oldest_rln_epoch = rln_oldest_active_epoch(current_epoch);
        let cur_week = pool::week_of(current_epoch);
        let mut records = Vec::new();
        let mut rln_records = Vec::new();
        for rule in &rules {
            for path in pool::sync_shard_paths(rule, cur_week) {
                let Some((week, sub)) = pool::parse_shard_path(rule, &path) else {
                    continue;
                };
                if let Ok(bytes) = storage.read(&path) {
                    if let Ok(container) = serde_json::from_slice::<Value>(&bytes) {
                        for record in pool::pool_records_of(&container) {
                            if pool::verify_pool_record(&record, rule, week, now).is_err() {
                                continue;
                            }
                            let routed_here = record
                                .get("tag")
                                .and_then(|value| value.as_str())
                                .and_then(b64_decode)
                                .is_some_and(|tag| pool::shard_sub(&tag, rule.fanout) == sub);
                            if !routed_here {
                                continue;
                            }
                            if rule.rln_required {
                                let Some(admission) = admission_record(&record) else {
                                    continue;
                                };
                                if admission.epoch < oldest_rln_epoch {
                                    continue;
                                }
                                rln_records.push((record, admission));
                            } else {
                                records.push(record);
                    }
                }
            }
        }
            }
        }
        if !rln_records.is_empty() {
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
        }
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
