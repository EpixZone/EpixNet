//! Owner-signed, size-weighted RLN admission for ECX pools.
//!
//! For a pool that sets `rln_required`, the owner publishes a signed roster of
//! member commitments (`pool.<name>.rln_roster`), a per-epoch allowance in units
//! (`rln_limit`), and the padding buckets that define a record's unit cost. This:
//!
//! - **verifies** inbound records (ingest): a record's unit cost is its size
//!   bucket, computed from `ct` alone, and the proof must spend exactly that many
//!   distinct allowance units against the roster root. Over-limit reuse
//!   double-signals and is dropped; the detection is order-independent, so nodes
//!   reconciling partitioned shards reach the same verdict.
//! - **proves** on the send side, behind a **usage rail**: a persistent per-epoch
//!   cursor spends a FRESH unit range each send and REFUSES once the allowance is
//!   exhausted — so an honest client can never reuse a unit and never slash
//!   itself. Only a modified client that bypasses the rail can double-signal.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use epix_rln::rln::prelude::{CanonicalDeserialize, CanonicalSerialize, Fr, RLNProof};
use epix_rln::{
    bucket_weight, commitment_from_hex, commitment_to_hex, message_signal, Admission, NullifierId,
    PoolGate, RlnError, RlnIdentity,
};
use epix_ui::pool::{
    rln_oldest_active_epoch, PoolAdmission, PoolAdmissionBatch, PoolAdmissionDecision,
    PoolAdmissionRecord, PoolAdmissionRefresh, PoolRecordId,
};
use epix_ui::state::AppState;
use serde_json::Value;
use tempfile::NamedTempFile;

/// Capability key under which the node stores the shared admission (so the send
/// path can reach the same gates the ingest path uses).
pub const RLN_CAP: &str = "rln_admission";

/// Epochs of nullifier history the double-signal log retains (day-bucketed → ~a
/// week of active shards). Older epochs can never collide with a fresh nullifier
/// (the external nullifier binds the epoch), so forgetting them is safe.
/// One pool's admission state: the roster gate, plus the config the weight
/// calculation and the send rail need.
struct Pool {
    gate: PoolGate,
    /// Smallest padding bucket in bytes = one allowance unit.
    smallest_bucket: usize,
    /// Per-epoch allowance in units.
    limit: u32,
    /// Superseded owner-signed descriptor policies retained for active record
    /// epochs. Each root is accepted only through the epoch in which it was
    /// superseded and uses that descriptor's weight policy.
    historical_roots: Vec<HistoricalRoot>,
}

#[derive(Clone)]
struct HistoricalRoot {
    root: Fr,
    valid_through_epoch: u64,
    smallest_bucket: usize,
    limit: u32,
}

fn proof_root(blob: &[u8]) -> Result<Fr, RlnError> {
    let bundle = RLNProof::deserialize_compressed(blob)
        .map_err(|error| RlnError::Serialize(error.to_string()))?;
    Ok(bundle.values.root())
}

fn matching_root_policies(pool: &Pool, root: &Fr, epoch: u64) -> Vec<(usize, u32)> {
    let mut policies = Vec::new();
    if pool.gate.root() == *root {
        policies.push((pool.smallest_bucket, pool.limit));
    }
    for historical in &pool.historical_roots {
        if historical.root == *root && epoch <= historical.valid_through_epoch {
            let policy = (historical.smallest_bucket, historical.limit);
            if !policies.contains(&policy) {
                policies.push(policy);
            }
        }
    }
    policies
}

fn admit_with_root_history(pool: &mut Pool, record: &PoolAdmissionRecord) -> Admission {
    let root = match proof_root(&record.rln_proof) {
        Ok(root) => root,
        Err(error) => return Admission::Reject(error),
    };
    let epoch = record.epoch.max(0) as u64;
    let policies = matching_root_policies(pool, &root, epoch);
    let mut wrong_units = None;
    for (smallest_bucket, limit) in policies {
        let weight = bucket_weight(record.ct.len(), smallest_bucket);
        if weight > limit {
            continue;
        }
        match pool.gate.admit_with_id(
            record.id,
            &record.rln_proof,
            &record.ct,
            epoch,
            weight,
            &[root],
        ) {
            Admission::Reject(error @ RlnError::WrongUnits { .. }) => {
                wrong_units = Some(error);
            }
            admission => return admission,
        }
    }
    Admission::Reject(wrong_units.unwrap_or(RlnError::InvalidProof))
}

fn proof_touches_poisoned_with_root_history(
    pool: &Pool,
    record: &PoolAdmissionRecord,
) -> Result<bool, RlnError> {
    let root = proof_root(&record.rln_proof)?;
    let epoch = record.epoch.max(0) as u64;
    let policies = matching_root_policies(pool, &root, epoch);
    let mut wrong_units = None;
    for (smallest_bucket, limit) in policies {
        let weight = bucket_weight(record.ct.len(), smallest_bucket);
        if weight > limit {
            continue;
        }
        match pool.gate.proof_touches_poisoned(
            &record.rln_proof,
            &record.ct,
            epoch,
            weight,
            &[root],
        ) {
            Err(error @ RlnError::WrongUnits { .. }) => wrong_units = Some(error),
            result => return result,
        }
    }
    Err(wrong_units.unwrap_or(RlnError::InvalidProof))
}

#[derive(Default)]
struct AdmissionParts {
    persist: bool,
    deliver: bool,
    evict: Vec<PoolRecordId>,
    offenders: Vec<String>,
    error: Option<String>,
}

/// Node-side RLN admission using owner-signed rosters, one gate per pool, plus
/// the send-side usage rail.
pub struct RlnAdmission {
    pools: Mutex<HashMap<String, Pool>>,
    transactions: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    usage: Arc<UsageLedger>,
    poison: PoisonLedger,
    root_history: RootHistoryLedger,
}

pub struct ReservedRlnProof {
    pub proof: Vec<u8>,
    pub reservation: epix_envelope::RlnReservation,
}

#[derive(Clone)]
pub struct RlnReservationBatch {
    inner: Arc<RlnReservationBatchInner>,
}

#[derive(Clone)]
struct ProvisionalReservation {
    address: String,
    epoch: u64,
    reservation_id: [u8; 32],
    first_unit: u32,
    weight: u32,
}

struct RlnReservationBatchInner {
    usage: Arc<UsageLedger>,
    reservations: Mutex<Vec<ProvisionalReservation>>,
    committed: std::sync::atomic::AtomicBool,
    transaction: Mutex<Option<tokio::sync::OwnedMutexGuard<()>>>,
}

impl RlnReservationBatch {
    fn register(&self, reservation: ProvisionalReservation) {
        self.inner
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(reservation);
    }

    /// Make every provisional unit range final after the matching SQLite
    /// outbox/session batch committed, then release the pool transaction.
    pub fn commit(&self) -> Result<(), String> {
        let reservations = self
            .inner
            .reservations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let result = self.inner.usage.commit_named(&reservations);
        self.inner
            .committed
            .store(true, std::sync::atomic::Ordering::Release);
        self.inner
            .transaction
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        result
    }
}

impl Drop for RlnReservationBatchInner {
    fn drop(&mut self) {
        if !self.committed.load(std::sync::atomic::Ordering::Acquire) {
            let reservations = self
                .reservations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            self.usage.rollback_named(&reservations);
        }
    }
}

impl RlnAdmission {
    /// A new admission whose usage rail persists to `ledger_path` (or is
    /// memory-only when `None`, e.g. in tests).
    pub fn new(ledger_path: Option<PathBuf>) -> Arc<Self> {
        let poison_path = ledger_path
            .as_ref()
            .map(|path| path.with_file_name("rln_poison.json"));
        let root_history_path = ledger_path
            .as_ref()
            .map(|path| path.with_file_name("rln_roots.json"));
        Arc::new(Self {
            pools: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            usage: Arc::new(UsageLedger::load(ledger_path)),
            poison: PoisonLedger::load(poison_path),
            root_history: RootHistoryLedger::load(root_history_path),
        })
    }

    fn transaction_for(&self, address: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.transactions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(address.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Serialize a complete multi-chunk reservation/proof/staging operation
    /// against roster refresh and inbound admission for this pool.
    pub async fn send_transaction(&self, address: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.transaction_for(address).lock_owned().await
    }

    /// Begin one cancel-safe multi-record reservation batch. The owned pool
    /// permit stays alive in the shared batch object even if the async caller is
    /// cancelled while a proving closure is still running. Dropping an
    /// uncommitted batch rolls every newly-created named range back.
    pub async fn reservation_batch(&self, address: &str) -> RlnReservationBatch {
        let transaction = self.send_transaction(address).await;
        RlnReservationBatch {
            inner: Arc::new(RlnReservationBatchInner {
                usage: self.usage.clone(),
                reservations: Mutex::new(Vec::new()),
                committed: std::sync::atomic::AtomicBool::new(false),
                transaction: Mutex::new(Some(transaction)),
            }),
        }
    }

    /// Reconcile crash-left provisional reservations with the durable SQLite
    /// outbox before proving any new send. A matching queued ciphertext commits
    /// its range. A missing row rewinds the orphaned tail allocation.
    pub fn reconcile_outbox_reservations(
        &self,
        active: &[(String, u64, [u8; 32])],
    ) -> Result<(), String> {
        let active: std::collections::HashSet<String> = active
            .iter()
            .map(|(address, epoch, id)| UsageLedger::provisional_key(address, *epoch, *id))
            .collect();
        self.usage.reconcile_provisional(&active)
    }

    /// Whether the durable send-side usage ledger is available. A failed
    /// reservation commit or rollback poisons it until reconciliation reloads
    /// the durable state.
    pub fn usage_ledger_healthy(&self) -> bool {
        self.usage.is_healthy()
    }

    fn resolve_admission(
        &self,
        address: &str,
        epoch: u64,
        oldest_epoch: u64,
        gate: &mut PoolGate,
        admission: Admission,
    ) -> AdmissionParts {
        match admission {
            Admission::Admit => AdmissionParts {
                persist: true,
                deliver: true,
                ..AdmissionParts::default()
            },
            Admission::Duplicate {
                keep_record,
                replace_record,
                evicted_records,
            } => AdmissionParts {
                persist: keep_record || replace_record,
                evict: evicted_records,
                ..AdmissionParts::default()
            },
            Admission::Overlap {
                keep_record,
                evicted_records,
            } => AdmissionParts {
                persist: keep_record,
                evict: evicted_records,
                ..AdmissionParts::default()
            },
            Admission::Quarantined => AdmissionParts::default(),
            Admission::RateExceeded {
                offender_commitment,
                evicted_records,
                poisoned_nullifiers,
            } => {
                let offender = commitment_to_hex(&offender_commitment);
                match self
                    .poison
                    .add(address, epoch, &poisoned_nullifiers, oldest_epoch)
                {
                    Ok(()) => {
                        gate.poison_nullifiers(epoch, &poisoned_nullifiers);
                        AdmissionParts {
                            evict: evicted_records,
                            offenders: vec![offender],
                            ..AdmissionParts::default()
                        }
                    }
                    Err(error) => AdmissionParts {
                        offenders: vec![offender],
                        error: Some(error),
                        ..AdmissionParts::default()
                    },
                }
            }
            Admission::Reject(_) => AdmissionParts::default(),
        }
    }

    /// (Re)build the gate for `address` from its content.json roster. Call at
    /// startup and whenever the xite's content changes; drops the gate if the
    /// pool no longer requires RLN.
    pub async fn refresh(self: &Arc<Self>, state: &Arc<AppState>, address: &str) {
        let mut refreshed = state.refresh_pool_admission(address, self.clone()).await;
        if !refreshed.evict.is_empty() {
            if let Err(e) = state.remove_pool_records(address, &refreshed.evict).await {
                state
                    .log(
                        "ERROR",
                        format!("RLN: failed to quarantine records for {address}: {e}"),
                    )
                    .await;
            }
        }
        if let Some(members) = refreshed.loaded_members {
            state
                .log(
                    "INFO",
                    format!("RLN: loaded {members} members for {address}"),
                )
                .await;
        }
        for offender in &refreshed.offenders {
            state
                .log(
                    "WARN",
                    format!(
                        "RLN: quarantined a double-signal for {address}; offender commitment {offender}"
                    ),
                )
                .await;
        }
        if let Some(e) = refreshed.error.take() {
            state
                .log(
                    "ERROR",
                    format!("RLN: gate build failed for {address}: {e}"),
                )
                .await;
            }
        drop(refreshed.permit.take());
    }

    fn refresh_from_records(
        &self,
        address: &str,
        content: Option<&Value>,
        retained: &[PoolAdmissionRecord],
    ) -> PoolAdmissionRefresh {
        let descriptor = content.map(parse_rln_descriptor).transpose();
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor.flatten(),
            Err(error) => {
                self.pools
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(address);
                return PoolAdmissionRefresh {
                    error: Some(error),
                    ..PoolAdmissionRefresh::default()
                };
            }
        };
        let Some((limit, smallest_bucket, roster)) = descriptor else {
            self.pools
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(address);
            return match self.root_history.remove(address) {
                Ok(()) => PoolAdmissionRefresh::default(),
                Err(error) => PoolAdmissionRefresh {
                    error: Some(error),
                    ..PoolAdmissionRefresh::default()
                },
            };
        };
        let commitments: Vec<_> = roster
            .iter()
            .filter_map(|h| commitment_from_hex(h))
            .collect();
        if commitments.len() != roster.len() {
            self.pools
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(address);
            return PoolAdmissionRefresh {
                error: Some("roster contains an invalid identity commitment".into()),
                ..PoolAdmissionRefresh::default()
            };
        }
        // Per-pool external-nullifier domain (derived from the pool address) so an
        // identity's nullifiers never collide across pools. The send side derives
        // it the same way inside the gate.
        let domain = message_signal(address.as_bytes());
        match PoolGate::from_roster(domain, limit, &commitments) {
            Ok(mut gate) => {
                let current_epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
                let oldest_epoch = rln_oldest_active_epoch(current_epoch) as u64;
                let poisoned = match self.poison.snapshot_and_prune(address, oldest_epoch) {
                    Ok(poisoned) => poisoned,
                    Err(error) => {
                        self.pools
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(address);
                        return PoolAdmissionRefresh {
                            error: Some(error),
                            ..PoolAdmissionRefresh::default()
                        };
                    }
                };
                for (epoch, keys) in poisoned {
                    gate.poison_nullifiers(epoch, &keys);
                }
                let new_root = gate.root();
                let current_epoch = current_epoch.max(0) as u64;
                let historical_roots = match self.root_history.activate(
                    address,
                    &new_root,
                    smallest_bucket,
                    limit,
                    current_epoch,
                    oldest_epoch,
                ) {
                    Ok(history) => history,
                    Err(error) => {
                        self.pools
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(address);
                        return PoolAdmissionRefresh {
                            error: Some(error),
                            ..PoolAdmissionRefresh::default()
                        };
                    }
                };
                // The descriptor transition is durable before retained records
                // are verified. A crash cannot forget which old root and weight
                // policy admitted an immutable record.
                let mut candidate_pool = Pool {
                    gate,
                    smallest_bucket,
                    limit,
                    historical_roots,
                };
                let mut evict = BTreeSet::new();
                let mut offenders = BTreeSet::new();
                let mut observed = BTreeSet::new();
                let mut retained = retained.to_vec();
                retained.sort_by_key(|record| record.id);
                for record in retained {
                    let admission = admit_with_root_history(&mut candidate_pool, &record);
                    let parts = self.resolve_admission(
                        address,
                        record.epoch.max(0) as u64,
                        oldest_epoch,
                        &mut candidate_pool.gate,
                        admission,
                    );
                    if let Some(error) = parts.error {
                        self.pools
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .remove(address);
                        return PoolAdmissionRefresh {
                            error: Some(error),
                            ..PoolAdmissionRefresh::default()
                        };
                    }
                    offenders.extend(parts.offenders);
                    evict.extend(parts.evict.iter().copied());
                    for displaced in parts.evict {
                        observed.remove(&displaced);
                    }
                    if parts.persist {
                        observed.insert(record.id);
                    } else if !observed.contains(&record.id) {
                        evict.insert(record.id);
                    }
                }
                evict.retain(|id| !observed.contains(id));
                self.pools
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(address.to_string(), candidate_pool);
                PoolAdmissionRefresh {
                    evict: evict.into_iter().collect(),
                    offenders: offenders.into_iter().collect(),
                    loaded_members: Some(commitments.len()),
                    error: None,
                    permit: None,
                }
            }
            Err(e) => {
                self.pools
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(address);
                PoolAdmissionRefresh {
                    error: Some(e.to_string()),
                    ..PoolAdmissionRefresh::default()
                }
            }
        }
    }

    /// Produce the RLN proof blob for `identity` (a member of `address`'s pool)
    /// to attach to an outbound record with sealed payload `ct` in `epoch`.
    ///
    /// The record's unit cost is its size bucket; the usage rail reserves a fresh
    /// unit range for it and REFUSES once the epoch allowance is exhausted (so an
    /// honest client never double-signals). Errors if no roster is loaded, the
    /// identity is not a member, or the allowance is exhausted for the epoch.
    pub fn prove_for(
        &self,
        address: &str,
        identity: &RlnIdentity,
        epoch: i64,
        ct: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.reserve_proof(address, identity, epoch, ct)
            .map(|reserved| reserved.proof)
    }

    /// Reserve a fresh durable allowance range and prove against the current
    /// finalized roster root. The returned range is stored with the outbox row.
    pub fn reserve_proof(
        &self,
        address: &str,
        identity: &RlnIdentity,
        epoch: i64,
        ct: &[u8],
    ) -> Result<ReservedRlnProof, String> {
        let epoch_u = epoch.max(0) as u64;
        let mut pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        let pool = pools.get_mut(address).ok_or("no RLN roster loaded for this pool")?;
        let weight = bucket_weight(ct.len(), pool.smallest_bucket);
        let root = pool.gate.root_id().map_err(|error| error.to_string())?;
        let reservation_id = epix_content::pool::rln_reservation_id(epoch, ct);
        let (first_unit, _) = self
            .usage
            .reserve_named(address, epoch_u, weight, pool.limit, reservation_id, false)?
            .ok_or_else(|| {
                format!(
                    "epoch allowance exhausted ({} units); wait for the next window",
                    pool.limit
                )
            })?;
        // Keep the named reservation even if proving fails. A later retry of the
        // same immutable ciphertext reuses it. Releasing it here would create a
        // crash window where another send could take the range before recovery.
        match pool
            .gate
            .prove_as(identity, epoch_u, first_unit, weight, ct)
        {
            Ok(proof) => Ok(ReservedRlnProof {
                proof,
                reservation: epix_envelope::RlnReservation {
                    first_unit,
                    weight,
                    root: Some(root),
                },
            }),
            Err(e) => Err(format!(
                "{e}; durable RLN reservation retained for ciphertext retry"
            )),
            }
        }

    /// Reserve and prove as part of a cancel-safe multi-record send. The usage
    /// range is rolled back unless the caller commits `batch` after the SQLite
    /// outbox/session transaction succeeds.
    pub fn reserve_proof_batched(
        &self,
        batch: &RlnReservationBatch,
        address: &str,
        identity: &RlnIdentity,
        epoch: i64,
        ct: &[u8],
    ) -> Result<ReservedRlnProof, String> {
        let epoch_u = epoch.max(0) as u64;
        let mut pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        let pool = pools
            .get_mut(address)
            .ok_or("no RLN roster loaded for this pool")?;
        let weight = bucket_weight(ct.len(), pool.smallest_bucket);
        let root = pool.gate.root_id().map_err(|error| error.to_string())?;
        let reservation_id = epix_content::pool::rln_reservation_id(epoch, ct);
        let (first_unit, created) = self
            .usage
            .reserve_named(address, epoch_u, weight, pool.limit, reservation_id, true)?
            .ok_or_else(|| {
                format!(
                    "epoch allowance exhausted ({} units); wait for the next window",
                    pool.limit
                )
            })?;
        if created {
            batch.register(ProvisionalReservation {
                address: address.to_string(),
                epoch: epoch_u,
                reservation_id,
                first_unit,
                weight,
            });
        }
        match pool
            .gate
            .prove_as(identity, epoch_u, first_unit, weight, ct)
        {
            Ok(proof) => Ok(ReservedRlnProof {
                proof,
                reservation: epix_envelope::RlnReservation {
                    first_unit,
                    weight,
                    root: Some(root),
                },
            }),
            Err(error) => Err(error.to_string()),
        }
    }

    /// Re-prove the same ciphertext under the current root while reusing its
    /// durable unit range. No usage-ledger cursor is advanced.
    pub fn reprove_reserved(
        &self,
        address: &str,
        identity: &RlnIdentity,
        epoch: i64,
        ct: &[u8],
        reservation: &epix_envelope::RlnReservation,
    ) -> Result<Vec<u8>, String> {
        let epoch_u = epoch.max(0) as u64;
        let pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        let pool = pools
            .get(address)
            .ok_or("no RLN roster loaded for this pool")?;
        let current_weight = bucket_weight(ct.len(), pool.smallest_bucket);
        if current_weight != reservation.weight {
            return Err(format!(
                "pool size policy changed RLN weight from {} to {}; the reserved send remains blocked",
                reservation.weight, current_weight
            ));
        }
        if reservation
            .first_unit
            .checked_add(reservation.weight)
            .is_none_or(|end| end > pool.limit)
        {
            return Err(format!(
                "current RLN allowance {} no longer authorizes reserved unit range {}..{}",
                pool.limit,
                reservation.first_unit,
                reservation.first_unit.saturating_add(reservation.weight)
            ));
        }
        pool.gate
            .prove_as(
                identity,
                epoch_u,
                reservation.first_unit,
                reservation.weight,
                ct,
            )
            .map_err(|error| error.to_string())
    }

    pub fn current_root(&self, address: &str) -> Result<[u8; 32], String> {
        self.pools
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(address)
            .ok_or_else(|| "no RLN roster loaded for this pool".to_string())?
            .gate
            .root_id()
            .map_err(|error| error.to_string())
    }

    /// This node's RLN footprint for `address` at `epoch`: `(units spent this
    /// epoch, per-epoch unit allowance)`, if a roster is loaded. Feeds the
    /// footprint progress bar. Read-only.
    pub fn usage(&self, address: &str, epoch: u64) -> Option<(u32, u32)> {
        let pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        let pool = pools.get(address)?;
        Some((self.usage.spent(address, epoch), pool.limit))
    }

    /// Whether `identity` is enrolled in `address`'s roster.
    pub fn is_member(&self, address: &str, identity: &RlnIdentity) -> bool {
        self.pools.lock().unwrap_or_else(PoisonError::into_inner).get(address).map(|p| p.gate.is_member(identity)).unwrap_or(false)
    }
}

impl PoolAdmission for RlnAdmission {
    fn refresh_address(
        &self,
        address: &str,
        content: Option<&Value>,
        retained: &mut dyn FnMut() -> Result<Vec<PoolAdmissionRecord>, String>,
    ) -> PoolAdmissionRefresh {
        let permit = self.transaction_for(address).blocking_lock_owned();
        if let Err(error) = self.root_history.ensure_healthy() {
            self.pools
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(address);
            return PoolAdmissionRefresh {
                error: Some(error),
                permit: Some(permit),
                ..PoolAdmissionRefresh::default()
            };
        }
        let retained = match retained() {
            Ok(retained) => retained,
            Err(error) => {
                self.pools
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(address);
                return PoolAdmissionRefresh {
                    error: Some(error),
                    permit: Some(permit),
                    ..PoolAdmissionRefresh::default()
                };
            }
        };
        let mut refreshed = self.refresh_from_records(address, content, &retained);
        refreshed.permit = Some(permit);
        refreshed
    }

    fn admit_records(&self, address: &str, records: &[PoolAdmissionRecord]) -> PoolAdmissionBatch {
        let permit = self.transaction_for(address).blocking_lock_owned();
        let current_epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
        let oldest_epoch = rln_oldest_active_epoch(current_epoch) as u64;
        if let Err(error) = self.poison.snapshot_and_prune(address, oldest_epoch) {
            self.pools
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(address);
            return PoolAdmissionBatch {
                decisions: records
                    .iter()
                    .map(|_| PoolAdmissionDecision {
                        error: Some(error.clone()),
                        ..PoolAdmissionDecision::default()
                    })
                    .collect(),
                permit: Some(permit),
            };
        }
        let mut pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pool) = pools.get_mut(address) else {
            return PoolAdmissionBatch {
                decisions: records
                    .iter()
                    .map(|_| PoolAdmissionDecision::default())
                    .collect(),
                permit: Some(permit),
        };
        };
        let mut decisions = Vec::with_capacity(records.len());
        for record in records {
            pool.gate.prune_before(oldest_epoch);
            if record.epoch < oldest_epoch as i64 {
                decisions.push(PoolAdmissionDecision::default());
                continue;
            }
            let admission = admit_with_root_history(pool, record);
            let parts = self.resolve_admission(
                address,
                record.epoch.max(0) as u64,
                oldest_epoch,
                &mut pool.gate,
                admission,
            );
            decisions.push(PoolAdmissionDecision {
                admit: parts.persist,
                deliver: parts.deliver,
                evict: parts.evict,
                offenders: parts.offenders,
                error: parts.error,
            });
        }
        PoolAdmissionBatch {
            decisions,
            permit: Some(permit),
    }
}

    fn allow_rescan_records(&self, address: &str, records: &[PoolAdmissionRecord]) -> Vec<bool> {
        let _permit = self.transaction_for(address).blocking_lock_owned();
        let current_epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
        let oldest_epoch = rln_oldest_active_epoch(current_epoch) as u64;
        let poisoned = match self.poison.snapshot_and_prune(address, oldest_epoch) {
            Ok(poisoned) => poisoned,
            Err(_) => {
                self.pools
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(address);
                return vec![false; records.len()];
            }
        };
        let mut pools = self.pools.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pool) = pools.get_mut(address) else {
            return vec![false; records.len()];
        };
        pool.gate.prune_before(oldest_epoch);
        for (epoch, keys) in poisoned {
            pool.gate.poison_nullifiers(epoch, &keys);
        }
        records
            .iter()
            .map(|record| {
                if record.epoch < oldest_epoch as i64 {
                    return false;
                }
                matches!(
                    proof_touches_poisoned_with_root_history(pool, record),
                    Ok(false)
                )
            })
            .collect()
    }
}

/// The one RLN pool descriptor's `(rln_limit, smallest padding bucket, roster
/// hex list)`. Admission is keyed by xite address, so multiple RLN rules are
/// rejected until the cross-layer key includes the rule directory.
fn parse_rln_descriptor(content: &Value) -> Result<Option<(u32, usize, Vec<String>)>, String> {
    let Some(pools) = content.get("pool").and_then(Value::as_object) else {
        return Ok(None);
    };
    let mut found = None;
    for entry in pools.values() {
        let Some(obj) = entry.as_object() else { continue };
        if obj.get("rln_required").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let limit = obj.get("rln_limit").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        let smallest_bucket = obj
            .get("pad_buckets")
            .and_then(|v| v.as_array())
            .and_then(|a| a.iter().filter_map(|b| b.as_u64()).min())
            .unwrap_or(1) as usize;
        let roster = obj
            .get("rln_roster")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default();
        if found.is_some() {
            return Err(
                "multiple rln_required pool rules need distinct admission keys; refusing shared gate"
                    .into(),
            );
        }
        found = Some((limit, smallest_bucket, roster));
    }
    Ok(found)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DescriptorRootState {
    root: [u8; 32],
    smallest_bucket: usize,
    limit: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SupersededRootState {
    descriptor: DescriptorRootState,
    valid_through_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PoolRootHistoryState {
    current: DescriptorRootState,
    superseded: Vec<SupersededRootState>,
}

type RootHistoryState = BTreeMap<String, PoolRootHistoryState>;

/// Crash-durable owner-signed descriptor history. The current descriptor is
/// persisted too, so the first refresh after a restart can supersede it before
/// replaying retained records.
struct RootHistoryLedger {
    path: Option<PathBuf>,
    entries: Mutex<Result<RootHistoryState, String>>,
}

impl RootHistoryLedger {
    fn load(path: Option<PathBuf>) -> Self {
        let entries = match path.as_ref() {
            None => Ok(BTreeMap::new()),
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => parse_root_history(&bytes, path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
                Err(error) => Err(format!(
                    "cannot read RLN root history {}: {error}",
                    path.display()
                )),
            },
        };
        Self {
            path,
            entries: Mutex::new(entries),
        }
    }

    fn ensure_healthy(&self) -> Result<(), String> {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|_| ())
            .map_err(Clone::clone)
    }

    #[allow(clippy::too_many_arguments)]
    fn activate(
        &self,
        address: &str,
        root: &Fr,
        smallest_bucket: usize,
        limit: u32,
        current_epoch: u64,
        oldest_epoch: u64,
    ) -> Result<Vec<HistoricalRoot>, String> {
        let descriptor = DescriptorRootState {
            root: serialize_root(root)?,
            smallest_bucket,
            limit,
        };
        let mut state = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        let mut candidate = current.clone();
        for pool in candidate.values_mut() {
            pool.superseded
                .retain(|entry| entry.valid_through_epoch >= oldest_epoch);
        }
        match candidate.get_mut(address) {
            Some(pool) if pool.current != descriptor => {
                let outgoing = SupersededRootState {
                    descriptor: pool.current.clone(),
                    valid_through_epoch: current_epoch,
                };
                if let Some(existing) = pool
                    .superseded
                    .iter_mut()
                    .find(|entry| entry.descriptor == outgoing.descriptor)
                {
                    existing.valid_through_epoch = existing
                        .valid_through_epoch
                        .max(outgoing.valid_through_epoch);
                } else {
                    pool.superseded.push(outgoing);
                }
                pool.current = descriptor.clone();
                pool.superseded
                    .retain(|entry| entry.descriptor != pool.current);
            }
            Some(_) => {}
            None => {
                candidate.insert(
                    address.to_string(),
                    PoolRootHistoryState {
                        current: descriptor,
                        superseded: Vec::new(),
                    },
                );
            }
        }
        for pool in candidate.values_mut() {
            pool.superseded.sort_by(|left, right| {
                right
                    .valid_through_epoch
                    .cmp(&left.valid_through_epoch)
                    .then_with(|| left.descriptor.root.cmp(&right.descriptor.root))
                    .then_with(|| {
                        left.descriptor
                            .smallest_bucket
                            .cmp(&right.descriptor.smallest_bucket)
                    })
                    .then_with(|| left.descriptor.limit.cmp(&right.descriptor.limit))
            });
        }
        if &candidate != current {
            Self::persist(&self.path, &candidate)?;
            *state = Ok(candidate);
        }
        let pool = state
            .as_ref()
            .map_err(Clone::clone)?
            .get(address)
            .ok_or_else(|| "RLN root history lost the active descriptor".to_string())?;
        pool.superseded
            .iter()
            .filter(|entry| entry.valid_through_epoch >= oldest_epoch)
            .map(|entry| {
                Ok(HistoricalRoot {
                    root: deserialize_root(&entry.descriptor.root)?,
                    valid_through_epoch: entry.valid_through_epoch,
                    smallest_bucket: entry.descriptor.smallest_bucket,
                    limit: entry.descriptor.limit,
                })
            })
            .collect()
    }

    fn remove(&self, address: &str) -> Result<(), String> {
        let mut state = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        if !current.contains_key(address) {
            return Ok(());
        }
        let mut candidate = current.clone();
        candidate.remove(address);
        Self::persist(&self.path, &candidate)?;
        *state = Ok(candidate);
        Ok(())
    }

    fn persist(path: &Option<PathBuf>, entries: &RootHistoryState) -> Result<(), String> {
        let Some(path) = path else {
            return Ok(());
        };
        let parent = path.parent().ok_or_else(|| {
            format!(
                "RLN root history has no parent directory: {}",
                path.display()
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "cannot create RLN root history directory {}: {error}",
                parent.display()
            )
        })?;
        let bytes = encode_root_history(entries)?;
        let mut temp = NamedTempFile::new_in(parent).map_err(|error| {
            format!(
                "cannot create RLN root history temp file in {}: {error}",
                parent.display()
            )
        })?;
        temp.write_all(&bytes).map_err(|error| {
            format!(
                "cannot write RLN root history temp file {}: {error}",
                temp.path().display()
            )
        })?;
        temp.as_file().sync_all().map_err(|error| {
            format!(
                "cannot sync RLN root history temp file {}: {error}",
                temp.path().display()
            )
        })?;
        let persisted = persist_ledger_temp(temp, path, "RLN root history")?;
        persisted.sync_all().map_err(|error| {
            format!(
                "cannot sync published RLN root history {}: {error}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!(
                    "cannot sync RLN root history directory {}: {error}",
                    parent.display()
                )
            })?;
        Ok(())
    }
}

fn serialize_root(root: &Fr) -> Result<[u8; 32], String> {
    let mut bytes = Vec::with_capacity(32);
    root.serialize_compressed(&mut bytes)
        .map_err(|error| format!("cannot serialize RLN descriptor root: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("RLN descriptor root encoded to {} bytes", bytes.len()))
}

fn deserialize_root(bytes: &[u8; 32]) -> Result<Fr, String> {
    Fr::deserialize_compressed(&bytes[..])
        .map_err(|error| format!("invalid RLN descriptor root: {error}"))
}

fn parse_descriptor_root(value: &Value, label: &str) -> Result<DescriptorRootState, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    let root_hex = object
        .get("root")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}.root must be a string"))?;
    let root: [u8; 32] = hex::decode(root_hex)
        .map_err(|error| format!("{label}.root is not hex: {error}"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            format!("{label}.root has {} bytes instead of 32", bytes.len())
        })?;
    deserialize_root(&root)?;
    let smallest_bucket = object
        .get("smallest_bucket")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label}.smallest_bucket must be a positive usize"))?;
    let limit = object
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label}.limit must be a positive u32"))?;
    Ok(DescriptorRootState {
        root,
        smallest_bucket,
        limit,
    })
}

fn parse_root_history(bytes: &[u8], path: &Path) -> Result<RootHistoryState, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid RLN root history {}: {error}", path.display()))?;
    let object = value.as_object().ok_or_else(|| {
        format!(
            "invalid RLN root history {}: root must be an object",
            path.display()
        )
    })?;
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(format!(
            "invalid RLN root history {}: unsupported version",
            path.display()
        ));
    }
    let pools = object
        .get("pools")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!(
                "invalid RLN root history {}: pools must be an object",
                path.display()
            )
        })?;
    let mut entries = BTreeMap::new();
    for (address, value) in pools {
        let pool = value.as_object().ok_or_else(|| {
            format!(
                "invalid RLN root history {}: pool {address} must be an object",
                path.display()
            )
        })?;
        let current = parse_descriptor_root(
            pool.get("current").ok_or_else(|| {
                format!(
                    "invalid RLN root history {}: pool {address} has no current descriptor",
                    path.display()
                )
            })?,
            "current descriptor",
        )
        .map_err(|error| {
            format!(
                "invalid RLN root history {} for pool {address}: {error}",
                path.display()
            )
        })?;
        let history = pool
            .get("superseded")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!(
                    "invalid RLN root history {}: pool {address}.superseded must be an array",
                    path.display()
                )
            })?;
        let mut superseded = Vec::with_capacity(history.len());
        for (index, value) in history.iter().enumerate() {
            let entry = value.as_object().ok_or_else(|| {
                format!(
                    "invalid RLN root history {}: pool {address} entry {index} must be an object",
                    path.display()
                )
            })?;
            let descriptor =
                parse_descriptor_root(value, "superseded descriptor").map_err(|error| {
                    format!(
                        "invalid RLN root history {} for pool {address} entry {index}: {error}",
                        path.display()
                    )
                })?;
            let valid_through_epoch = entry
                .get("valid_through_epoch")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    format!(
                        "invalid RLN root history {}: pool {address} entry {index} has no valid-through epoch",
                        path.display()
                    )
                })?;
            superseded.push(SupersededRootState {
                descriptor,
                valid_through_epoch,
            });
        }
        entries.insert(
            address.clone(),
            PoolRootHistoryState {
                current,
                superseded,
            },
        );
    }
    Ok(entries)
}

fn encode_root_history(entries: &RootHistoryState) -> Result<Vec<u8>, String> {
    let mut pools = serde_json::Map::new();
    for (address, pool) in entries {
        let encode_descriptor = |descriptor: &DescriptorRootState| {
            serde_json::json!({
                "root": hex::encode(descriptor.root),
                "smallest_bucket": descriptor.smallest_bucket,
                "limit": descriptor.limit,
            })
        };
        let superseded: Vec<Value> = pool
            .superseded
            .iter()
            .map(|entry| {
                let mut value = encode_descriptor(&entry.descriptor);
                value
                    .as_object_mut()
                    .expect("descriptor is an object")
                    .insert(
                        "valid_through_epoch".into(),
                        Value::from(entry.valid_through_epoch),
                    );
                value
            })
            .collect();
        pools.insert(
            address.clone(),
            serde_json::json!({
                "current": encode_descriptor(&pool.current),
                "superseded": superseded,
            }),
        );
    }
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "pools": pools,
    }))
    .map_err(|error| format!("cannot serialize RLN root history: {error}"))
}

type PoisonState = HashMap<String, BTreeMap<u64, BTreeSet<NullifierId>>>;

#[cfg(not(windows))]
fn persist_ledger_temp(
    temp: NamedTempFile,
    path: &Path,
    label: &str,
) -> Result<std::fs::File, String> {
    temp.persist(path).map_err(|e| {
        format!(
            "cannot atomically replace {label} {}: {}",
            path.display(),
            e.error
        )
    })
}

#[cfg(windows)]
fn persist_ledger_temp(
    temp: NamedTempFile,
    path: &Path,
    label: &str,
) -> Result<std::fs::File, String> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let (file, temp_path) = temp.keep().map_err(|e| {
        format!(
            "cannot retain temporary {label} for {}: {}",
            path.display(),
            e.error
        )
    })?;
    let source: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers for the
    // duration of this call. The source handle permits rename sharing.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        let error = std::io::Error::last_os_error();
        drop(file);
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!(
            "cannot atomically replace {label} {}: {error}",
            path.display()
        ));
    }
    Ok(file)
}

/// Crash-durable nullifier poison. A double-signal is written here and fsynced
/// before any public shard record is evicted. Corrupt or unreadable state keeps
/// admission closed rather than forgetting proven abuse.
struct PoisonLedger {
    path: Option<PathBuf>,
    entries: Mutex<Result<PoisonState, String>>,
}

impl PoisonLedger {
    fn load(path: Option<PathBuf>) -> Self {
        let entries = match path.as_ref() {
            None => Ok(HashMap::new()),
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => serde_json::from_slice::<PoisonState>(&bytes)
                    .map_err(|e| format!("invalid RLN poison ledger {}: {e}", path.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
                Err(e) => Err(format!(
                    "cannot read RLN poison ledger {}: {e}",
                    path.display()
                )),
            },
        };
        Self {
            path,
            entries: Mutex::new(entries),
        }
    }

    fn snapshot_and_prune(
        &self,
        address: &str,
        oldest_epoch: u64,
    ) -> Result<BTreeMap<u64, Vec<NullifierId>>, String> {
        let mut state = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        let mut candidate = current.clone();
        for epochs in candidate.values_mut() {
            epochs.retain(|epoch, _| *epoch >= oldest_epoch);
        }
        candidate.retain(|_, epochs| !epochs.is_empty());
        if &candidate != current {
            Self::persist(&self.path, &candidate)?;
            *state = Ok(candidate);
        }
        Ok(state
            .as_ref()
            .map_err(Clone::clone)?
            .get(address)
            .map(|epochs| {
                epochs
                    .iter()
                    .map(|(epoch, keys)| (*epoch, keys.iter().copied().collect()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn add(
        &self,
        address: &str,
        epoch: u64,
        keys: &[NullifierId],
        oldest_epoch: u64,
    ) -> Result<(), String> {
        let mut state = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        let mut candidate = current.clone();
        for epochs in candidate.values_mut() {
            epochs.retain(|stored_epoch, _| *stored_epoch >= oldest_epoch);
        }
        candidate.retain(|_, epochs| !epochs.is_empty());
        candidate
            .entry(address.to_string())
            .or_default()
            .entry(epoch)
            .or_default()
            .extend(keys.iter().copied());
        Self::persist(&self.path, &candidate)?;
        *state = Ok(candidate);
        Ok(())
    }

    fn persist(path: &Option<PathBuf>, entries: &PoisonState) -> Result<(), String> {
        let Some(path) = path else {
            return Ok(());
        };
        let parent = path.parent().ok_or_else(|| {
            format!(
                "RLN poison ledger has no parent directory: {}",
                path.display()
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "cannot create RLN poison directory {}: {e}",
                parent.display()
            )
        })?;
        let bytes = serde_json::to_vec(entries)
            .map_err(|e| format!("cannot serialize RLN poison ledger: {e}"))?;
        let mut temp = NamedTempFile::new_in(parent).map_err(|e| {
            format!(
                "cannot create RLN poison temp file in {}: {e}",
                parent.display()
            )
        })?;
        temp.write_all(&bytes).map_err(|e| {
            format!(
                "cannot write RLN poison temp file {}: {e}",
                temp.path().display()
            )
        })?;
        temp.as_file().sync_all().map_err(|e| {
            format!(
                "cannot sync RLN poison temp file {}: {e}",
                temp.path().display()
            )
        })?;
        let persisted = persist_ledger_temp(temp, path, "RLN poison ledger")?;
        persisted.sync_all().map_err(|e| {
            format!(
                "cannot sync published RLN poison ledger {}: {e}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("cannot sync RLN poison directory {}: {e}", parent.display()))?;
        Ok(())
    }
}

/// The send-side usage rail: a persistent per-`(pool, epoch)` cursor of units
/// spent, so each send draws a fresh range and the client stops at the limit.
/// Persistence is essential — a restart that reset the cursor would let a client
/// reuse a unit and slash itself.
struct UsageLedger {
    path: Option<PathBuf>,
    // Err means the on-disk ledger could not be trusted. Proof generation stays
    // fail-closed for this process instead of silently resetting usage.
    spent: Mutex<Result<HashMap<String, u32>, String>>, // "address|epoch" -> units spent
}

impl UsageLedger {
    fn provisional_key(address: &str, epoch: u64, reservation_id: [u8; 32]) -> String {
        format!(
            "reservation-provisional|{address}|{}|{epoch}",
            hex::encode(reservation_id)
        )
    }

    fn load(path: Option<PathBuf>) -> Self {
        let spent = match path.as_ref() {
            None => Ok(HashMap::new()),
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => serde_json::from_slice::<HashMap<String, u32>>(&bytes)
                    .map_err(|e| format!("invalid RLN usage ledger {}: {e}", path.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
                Err(e) => Err(format!(
                    "cannot read RLN usage ledger {}: {e}",
                    path.display()
                )),
            },
        };
        Self {
            path,
            spent: Mutex::new(spent),
        }
    }

    fn is_healthy(&self) -> bool {
        self.spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_ok()
    }

    /// Reopen a durable ledger after a previous read or persistence error.
    /// Missing state is accepted only by the initial load. Once an operation
    /// has failed, treating a missing file as empty could reuse spent units.
    fn reload_if_poisoned(
        &self,
        state: &mut Result<HashMap<String, u32>, String>,
    ) -> Result<(), String> {
        if state.is_ok() {
            return Ok(());
        }
        let Some(path) = self.path.as_ref() else {
            return state.as_ref().map(|_| ()).map_err(Clone::clone);
        };
        let reloaded = std::fs::read(path)
            .map_err(|error| format!("cannot read RLN usage ledger {}: {error}", path.display()))
            .and_then(|bytes| {
                serde_json::from_slice::<HashMap<String, u32>>(&bytes).map_err(|error| {
                    format!("invalid RLN usage ledger {}: {error}", path.display())
                })
            });
        *state = reloaded;
        state.as_ref().map(|_| ()).map_err(Clone::clone)
    }

    /// Units spent at `(address, epoch)` so far (read-only).
    fn spent(&self, address: &str, epoch: u64) -> u32 {
        self.spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .ok()
            .and_then(|spent| spent.get(&format!("{address}|{epoch}")).copied())
            .unwrap_or(0)
    }

    /// Reserve `weight` units at `(address, epoch)`; returns the first unit index
    /// to spend, or `None` if that would exceed `limit`.
    #[cfg(test)]
    fn reserve(
        &self,
        address: &str,
        epoch: u64,
        weight: u32,
        limit: u32,
    ) -> Result<Option<u32>, String> {
        let key = format!("{address}|{epoch}");
        let mut state = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        let cur = *current.get(&key).unwrap_or(&0);
        let Some(next) = cur.checked_add(weight) else {
            return Ok(None);
        };
        if next > limit {
            return Ok(None);
        }
        let mut candidate = current.clone();
        candidate.insert(key, next);
        // Bound the ledger: past epochs can never be spent against again (the
        // external nullifier binds the epoch), so drop cursors older than the
        // retention window instead of accumulating one key per epoch forever.
        prune_old_epochs(&mut candidate, epoch);
        Self::persist(&self.path, &candidate)?;
        *state = Ok(candidate);
        Ok(Some(cur))
    }

    /// Idempotent durable reservation for one immutable ciphertext. A crash
    /// after the usage ledger commit but before SQLite staging returns the same
    /// unit range on retry instead of burning a second range.
    fn reserve_named(
        &self,
        address: &str,
        epoch: u64,
        weight: u32,
        limit: u32,
        reservation_id: [u8; 32],
        provisional: bool,
    ) -> Result<Option<(u32, bool)>, String> {
        let cursor_key = format!("{address}|{epoch}");
        let id = hex::encode(reservation_id);
        let first_key = format!("reservation|{address}|{id}|{epoch}");
        let weight_key = format!("reservation-weight|{address}|{id}|{epoch}");
        let provisional_key = Self::provisional_key(address, epoch, reservation_id);
        let mut state = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        match (current.get(&first_key), current.get(&weight_key)) {
            (Some(first), Some(stored_weight)) => {
                if *stored_weight != weight {
                    return Err(format!(
                        "RLN reservation weight changed from {stored_weight} to {weight}"
                    ));
                }
                if !provisional && current.contains_key(&provisional_key) {
                    return Err(
                        "RLN reservation is provisional and requires outbox reconciliation".into(),
                    );
                }
                return Ok(Some((*first, false)));
            }
            (None, None) => {}
            _ => return Err("RLN usage ledger has an incomplete named reservation".into()),
        }
        let cur = *current.get(&cursor_key).unwrap_or(&0);
        let Some(next) = cur.checked_add(weight) else {
            return Ok(None);
        };
        if next > limit {
            return Ok(None);
        }
        let mut candidate = current.clone();
        candidate.insert(cursor_key, next);
        candidate.insert(first_key, cur);
        candidate.insert(weight_key, weight);
        if provisional {
            candidate.insert(provisional_key, 1);
        }
        prune_old_epochs(&mut candidate, epoch);
        Self::persist(&self.path, &candidate)?;
        *state = Ok(candidate);
        Ok(Some((cur, true)))
    }

    /// Undo a `reserve` for `(address, epoch)` (a send that reserved but then
    /// failed to produce a record), returning the units to the epoch allowance.
    #[cfg(test)]
    fn release(&self, address: &str, epoch: u64, weight: u32) -> Result<(), String> {
        let key = format!("{address}|{epoch}");
        let mut state = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        let current = state.as_ref().map_err(Clone::clone)?;
        let mut candidate = current.clone();
        if let Some(cur) = candidate.get(&key).copied() {
            let back = cur.saturating_sub(weight);
            if back == 0 {
                candidate.remove(&key);
            } else {
                candidate.insert(key, back);
            }
            Self::persist(&self.path, &candidate)?;
            *state = Ok(candidate);
        }
        Ok(())
    }

    /// Atomically remove a send batch's newly-created named reservations and
    /// rewind its tail allocation. Any inconsistency or persistence failure
    /// poisons the usage ledger so later proof generation fails closed.
    fn rollback_named(&self, reservations: &[ProvisionalReservation]) {
        if reservations.is_empty() {
            return;
        }
        let mut state = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        let result = (|| -> Result<HashMap<String, u32>, String> {
            let mut candidate = state.as_ref().map_err(Clone::clone)?.clone();
            for reservation in reservations.iter().rev() {
                let cursor_key = format!("{}|{}", reservation.address, reservation.epoch);
                let id = hex::encode(reservation.reservation_id);
                let first_key = format!(
                    "reservation|{}|{}|{}",
                    reservation.address, id, reservation.epoch
                );
                let weight_key = format!(
                    "reservation-weight|{}|{}|{}",
                    reservation.address, id, reservation.epoch
                );
                let provisional_key = Self::provisional_key(
                    &reservation.address,
                    reservation.epoch,
                    reservation.reservation_id,
                );
                if candidate.get(&first_key) != Some(&reservation.first_unit)
                    || candidate.get(&weight_key) != Some(&reservation.weight)
                {
                    return Err("RLN provisional reservation changed before rollback".into());
                }
                let expected_tail = reservation
                    .first_unit
                    .checked_add(reservation.weight)
                    .ok_or("RLN provisional reservation overflow")?;
                if candidate.get(&cursor_key).copied() != Some(expected_tail) {
                    return Err("RLN provisional reservation is no longer the usage tail".into());
                }
                candidate.remove(&first_key);
                candidate.remove(&weight_key);
                candidate.remove(&provisional_key);
                if reservation.first_unit == 0 {
                    candidate.remove(&cursor_key);
                } else {
                    candidate.insert(cursor_key, reservation.first_unit);
                }
            }
            Self::persist(&self.path, &candidate)?;
            Ok(candidate)
        })();
        *state = result;
    }

    fn commit_named(&self, reservations: &[ProvisionalReservation]) -> Result<(), String> {
        if reservations.is_empty() {
            return Ok(());
        }
        let mut state = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        let result = (|| -> Result<HashMap<String, u32>, String> {
            let mut candidate = state.as_ref().map_err(Clone::clone)?.clone();
            for reservation in reservations {
                candidate.remove(&Self::provisional_key(
                    &reservation.address,
                    reservation.epoch,
                    reservation.reservation_id,
                ));
            }
            Self::persist(&self.path, &candidate)?;
            Ok(candidate)
        })();
        match result {
            Ok(candidate) => {
                *state = Ok(candidate);
                Ok(())
            }
            Err(error) => {
                *state = Err(error.clone());
                Err(error)
            }
        }
    }

    fn reconcile_provisional(
        &self,
        active: &std::collections::HashSet<String>,
    ) -> Result<(), String> {
        let mut state = self.spent.lock().unwrap_or_else(PoisonError::into_inner);
        self.reload_if_poisoned(&mut state)?;
        let result = (|| -> Result<HashMap<String, u32>, String> {
            let mut candidate = state.as_ref().map_err(Clone::clone)?.clone();
            let provisional_keys: Vec<String> = candidate
                .keys()
                .filter(|key| key.starts_with("reservation-provisional|"))
                .cloned()
                .collect();
            let mut orphaned = Vec::new();
            for key in provisional_keys {
                let mut parts = key.split('|');
                if parts.next() != Some("reservation-provisional") {
                    continue;
            }
                let address = parts
                    .next()
                    .ok_or("invalid provisional RLN reservation address")?;
                let id_hex = parts
                    .next()
                    .ok_or("invalid provisional RLN reservation id")?;
                let epoch = parts
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or("invalid provisional RLN reservation epoch")?;
                if parts.next().is_some() {
                    return Err("invalid provisional RLN reservation key".into());
                }
                let id_bytes =
                    hex::decode(id_hex).map_err(|_| "invalid provisional RLN reservation id")?;
                let reservation_id: [u8; 32] = id_bytes
                    .try_into()
                    .map_err(|_| "invalid provisional RLN reservation id")?;
                if active.contains(&key) {
                    candidate.remove(&key);
                    continue;
                }
                let first_key = format!("reservation|{address}|{id_hex}|{epoch}");
                let weight_key = format!("reservation-weight|{address}|{id_hex}|{epoch}");
                let first_unit = candidate
                    .get(&first_key)
                    .copied()
                    .ok_or("provisional RLN reservation has no first unit")?;
                let weight = candidate
                    .get(&weight_key)
                    .copied()
                    .ok_or("provisional RLN reservation has no weight")?;
                orphaned.push(ProvisionalReservation {
                    address: address.to_string(),
                    epoch,
                    reservation_id,
                    first_unit,
                    weight,
                });
            }
            orphaned.sort_by(|a, b| {
                (&a.address, a.epoch, a.first_unit).cmp(&(&b.address, b.epoch, b.first_unit))
            });
            for reservation in orphaned.into_iter().rev() {
                let cursor_key = format!("{}|{}", reservation.address, reservation.epoch);
                let expected_tail = reservation
                    .first_unit
                    .checked_add(reservation.weight)
                    .ok_or("RLN provisional reservation overflow")?;
                if candidate.get(&cursor_key).copied() != Some(expected_tail) {
                    return Err("orphaned RLN reservation is no longer the usage tail".into());
                }
                let id = hex::encode(reservation.reservation_id);
                candidate.remove(&format!(
                    "reservation|{}|{}|{}",
                    reservation.address, id, reservation.epoch
                ));
                candidate.remove(&format!(
                    "reservation-weight|{}|{}|{}",
                    reservation.address, id, reservation.epoch
                ));
                candidate.remove(&Self::provisional_key(
                    &reservation.address,
                    reservation.epoch,
                    reservation.reservation_id,
                ));
                if reservation.first_unit == 0 {
                    candidate.remove(&cursor_key);
                } else {
                    candidate.insert(cursor_key, reservation.first_unit);
            }
        }
            Self::persist(&self.path, &candidate)?;
            Ok(candidate)
        })();
        match result {
            Ok(candidate) => {
                *state = Ok(candidate);
                Ok(())
            }
            Err(error) => {
                *state = Err(error.clone());
                Err(error)
            }
        }
    }

    fn persist(path: &Option<PathBuf>, spent: &HashMap<String, u32>) -> Result<(), String> {
        let Some(path) = path else {
            return Ok(());
        };
        let parent = path.parent().ok_or_else(|| {
            format!(
                "RLN usage ledger has no parent directory: {}",
                path.display()
            )
        })?;
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "cannot create RLN usage directory {}: {e}",
                parent.display()
            )
        })?;
        let bytes = serde_json::to_vec(spent)
            .map_err(|e| format!("cannot serialize RLN usage ledger: {e}"))?;
        let mut temp = NamedTempFile::new_in(parent).map_err(|e| {
            format!(
                "cannot create RLN usage temp file in {}: {e}",
                parent.display()
            )
        })?;
        temp.write_all(&bytes).map_err(|e| {
            format!(
                "cannot write RLN usage temp file {}: {e}",
                temp.path().display()
            )
        })?;
        temp.as_file().sync_all().map_err(|e| {
            format!(
                "cannot sync RLN usage temp file {}: {e}",
                temp.path().display()
            )
        })?;
        let persisted = persist_ledger_temp(temp, path, "RLN usage ledger")?;
        persisted.sync_all().map_err(|e| {
            format!(
                "cannot sync published RLN usage ledger {}: {e}",
                path.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("cannot sync RLN usage directory {}: {e}", parent.display()))?;
        Ok(())
    }
}

/// Epochs of usage history to retain (day-bucketed epochs → ~a month).
const USAGE_RETAIN_EPOCHS: u64 = 32;

/// Drop `(address|epoch)` cursors whose epoch is older than the retention window.
fn prune_old_epochs(s: &mut HashMap<String, u32>, current_epoch: u64) {
    let cutoff = current_epoch.saturating_sub(USAGE_RETAIN_EPOCHS);
    s.retain(|k, _| {
        k.rsplit_once('|')
            .and_then(|(_, e)| e.parse::<u64>().ok())
            .is_none_or(|e| e >= cutoff)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_reservation_batch(usage: Arc<UsageLedger>) -> RlnReservationBatch {
        RlnReservationBatch {
            inner: Arc::new(RlnReservationBatchInner {
                usage,
                reservations: Mutex::new(Vec::new()),
                committed: std::sync::atomic::AtomicBool::new(false),
                transaction: Mutex::new(None),
            }),
        }
    }

    fn reserve_in_batch(
        usage: &Arc<UsageLedger>,
        batch: &RlnReservationBatch,
        id: [u8; 32],
        weight: u32,
    ) {
        let (first_unit, created) = usage
            .reserve_named("pool", 42, weight, 20, id, true)
            .unwrap()
            .unwrap();
        assert!(created);
        batch.register(ProvisionalReservation {
            address: "pool".into(),
            epoch: 42,
            reservation_id: id,
            first_unit,
            weight,
        });
    }

    #[test]
    fn usage_ledger_is_durable_across_restart_and_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private").join("rln_usage.json");
        let ledger = UsageLedger::load(Some(path.clone()));
        assert_eq!(ledger.reserve("pool", 42, 2, 4).unwrap(), Some(0));
        assert_eq!(ledger.spent("pool", 42), 2);

        let restarted = UsageLedger::load(Some(path.clone()));
        assert_eq!(restarted.spent("pool", 42), 2);
        assert_eq!(restarted.reserve("pool", 42, 2, 4).unwrap(), Some(2));
        assert_eq!(restarted.reserve("pool", 42, 1, 4).unwrap(), None);
        restarted.release("pool", 42, 2).unwrap();

        let after_release = UsageLedger::load(Some(path));
        assert_eq!(after_release.spent("pool", 42), 2);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("private"))
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic temp files leaked: {leftovers:?}"
        );
    }

    #[test]
    fn later_chunk_or_db_failure_rolls_back_the_whole_reservation_batch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private").join("rln_usage.json");
        let usage = Arc::new(UsageLedger::load(Some(path.clone())));
        let batch = test_reservation_batch(usage.clone());
        reserve_in_batch(&usage, &batch, [1; 32], 2);
        reserve_in_batch(&usage, &batch, [2; 32], 3);
        assert_eq!(usage.spent("pool", 42), 5);

        // Returning an error before commit_outbound_batch, or a DB transaction
        // failure itself, drops this uncommitted batch.
        drop(batch);
        assert_eq!(usage.spent("pool", 42), 0);
        assert_eq!(UsageLedger::load(Some(path)).spent("pool", 42), 0);
    }

    #[test]
    fn committed_reservation_batch_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private").join("rln_usage.json");
        let usage = Arc::new(UsageLedger::load(Some(path.clone())));
        let batch = test_reservation_batch(usage.clone());
        reserve_in_batch(&usage, &batch, [3; 32], 4);
        batch.commit().unwrap();
        drop(batch);
        assert_eq!(UsageLedger::load(Some(path)).spent("pool", 42), 4);
    }

    #[test]
    fn restart_reconciles_crash_left_provisional_ranges_with_sqlite_outbox() {
        let dir = tempfile::tempdir().unwrap();
        let orphan_path = dir.path().join("orphan.json");
        let orphan_usage = Arc::new(UsageLedger::load(Some(orphan_path.clone())));
        let orphan_batch = test_reservation_batch(orphan_usage.clone());
        reserve_in_batch(&orphan_usage, &orphan_batch, [8; 32], 2);
        std::mem::forget(orphan_batch); // model process death before SQLite commit
        let restarted = UsageLedger::load(Some(orphan_path));
        restarted
            .reconcile_provisional(&std::collections::HashSet::new())
            .unwrap();
        assert_eq!(restarted.spent("pool", 42), 0);

        let live_path = dir.path().join("live.json");
        let live_usage = Arc::new(UsageLedger::load(Some(live_path.clone())));
        let live_batch = test_reservation_batch(live_usage.clone());
        reserve_in_batch(&live_usage, &live_batch, [9; 32], 3);
        std::mem::forget(live_batch); // model SQLite commit before marker finalization
        let restarted = UsageLedger::load(Some(live_path));
        let active =
            std::collections::HashSet::from([UsageLedger::provisional_key("pool", 42, [9; 32])]);
        restarted.reconcile_provisional(&active).unwrap();
        assert_eq!(restarted.spent("pool", 42), 3);
        assert!(
            restarted
                .reserve_named("pool", 42, 3, 20, [9; 32], false)
                .is_ok(),
            "the reconciled live range is committed and idempotently reusable"
        );
    }

    #[test]
    fn reconciliation_reloads_after_a_transient_persistence_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rln_usage.json");
        let backup = dir.path().join("rln_usage.backup.json");
        let ledger = UsageLedger::load(Some(path.clone()));
        let reservation_id = [10; 32];
        assert_eq!(
            ledger
                .reserve_named("pool", 42, 2, 20, reservation_id, true)
                .unwrap(),
            Some((0, true))
        );

        // Keep the last durable version aside and replace the destination with
        // a directory. The next atomic publication fails after reconciliation
        // has read the provisional reservation into its candidate state.
        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        let error = ledger
            .reconcile_provisional(&std::collections::HashSet::new())
            .unwrap_err();
        assert!(error.contains("cannot atomically replace RLN usage ledger"));
        assert!(ledger
            .reserve_named("pool", 42, 1, 20, [11; 32], false)
            .is_err());

        // Restore the durable source. The same in-process ledger must reopen
        // it, finish reconciliation, and persist the released range.
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        ledger
            .reconcile_provisional(&std::collections::HashSet::new())
            .unwrap();
        assert_eq!(ledger.spent("pool", 42), 0);
        assert_eq!(ledger.reserve("pool", 42, 1, 20).unwrap(), Some(0));
        assert_eq!(UsageLedger::load(Some(path)).spent("pool", 42), 1);
    }

    #[test]
    fn reconciliation_heals_a_rollback_persistence_failure_in_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rln_usage.json");
        let backup = dir.path().join("rln_usage.backup.json");
        let usage = Arc::new(UsageLedger::load(Some(path.clone())));
        let batch = test_reservation_batch(usage.clone());
        reserve_in_batch(&usage, &batch, [12; 32], 2);

        std::fs::rename(&path, &backup).unwrap();
        std::fs::create_dir(&path).unwrap();
        drop(batch);
        assert!(!usage.is_healthy());
        assert!(usage
            .reserve_named("pool", 42, 1, 20, [13; 32], false)
            .is_err());

        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&backup, &path).unwrap();
        usage
            .reconcile_provisional(&std::collections::HashSet::new())
            .unwrap();
        assert!(usage.is_healthy());
        assert_eq!(usage.spent("pool", 42), 0);
        assert_eq!(UsageLedger::load(Some(path)).spent("pool", 42), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_waits_for_blocking_prover_then_rolls_back() {
        let usage = Arc::new(UsageLedger::load(None));
        let batch = test_reservation_batch(usage.clone());
        let proving_batch = batch.clone();
        let proving_usage = usage.clone();
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let reached_worker = reached.clone();
        let release_worker = release.clone();
        let proving = tokio::task::spawn_blocking(move || {
            reserve_in_batch(&proving_usage, &proving_batch, [4; 32], 2);
            reached_worker.wait();
            release_worker.wait();
        });
        reached.wait();
        // Model cancellation of the async caller. The blocking closure still
        // owns the batch, so cleanup occurs only after it stops touching usage.
        drop(batch);
        release.wait();
        proving.await.unwrap();
        assert_eq!(usage.spent("pool", 42), 0);
    }

    #[test]
    fn durable_unit_range_reproves_after_root_rotation_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private").join("rln_usage.json");
        let alice = RlnIdentity::from_seed(b"alice");
        let bob = RlnIdentity::from_seed(b"bob");
        let descriptor = |roster: Vec<String>| {
            serde_json::json!({
                "pool": { "channels": {
                    "rln_required": true,
                    "rln_limit": 8,
                    "pad_buckets": [64],
                    "rln_roster": roster,
                }}
            })
        };
        let first = RlnAdmission::new(Some(path.clone()));
        let first_content = descriptor(vec![commitment_to_hex(&alice.commitment())]);
        assert!(first
            .refresh_from_records("pool", Some(&first_content), &[])
            .error
            .is_none());
        let epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
        let ct = vec![5u8; 64];
        let reserved = first.reserve_proof("pool", &alice, epoch, &ct).unwrap();
        let old_root = reserved.reservation.root.unwrap();
        drop(first);

        let restarted = RlnAdmission::new(Some(path));
        let rotated = descriptor(vec![
            commitment_to_hex(&alice.commitment()),
            commitment_to_hex(&bob.commitment()),
        ]);
        assert!(restarted
            .refresh_from_records("pool", Some(&rotated), &[])
            .error
            .is_none());
        assert_ne!(restarted.current_root("pool").unwrap(), old_root);
        assert!(restarted
            .reprove_reserved("pool", &alice, epoch, &ct, &reserved.reservation)
            .is_ok());
        assert_eq!(
            restarted.usage("pool", epoch as u64).unwrap().0,
            reserved.reservation.weight,
            "reproof reuses the existing allocation instead of spending again"
        );
    }

    #[test]
    fn retained_old_root_record_survives_rotation_and_restart_with_old_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private").join("rln_usage.json");
        let alice = RlnIdentity::from_seed(b"history-alice");
        let bob = RlnIdentity::from_seed(b"history-bob");
        let descriptor = |limit: u32, bucket: usize, roster: Vec<String>| {
            serde_json::json!({
                "pool": { "channels": {
                    "rln_required": true,
                    "rln_limit": limit,
                    "pad_buckets": [bucket],
                    "rln_roster": roster,
                }}
            })
        };
        let old_content = descriptor(4, 64, vec![commitment_to_hex(&alice.commitment())]);
        let new_content = descriptor(1, 128, vec![commitment_to_hex(&bob.commitment())]);
        let epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
        let ct = vec![31u8; 96];

        let first = RlnAdmission::new(Some(path.clone()));
        assert!(first
            .refresh_from_records("pool", Some(&old_content), &[])
            .error
            .is_none());
        let proof = first
            .reserve_proof("pool", &alice, epoch, &ct)
            .unwrap()
            .proof;
        assert!(first
            .refresh_from_records("pool", Some(&new_content), &[])
            .error
            .is_none());
        drop(first);

        let record = PoolAdmissionRecord {
            id: [31; 32],
            rln_proof: proof,
            ct,
            epoch,
        };
        let restarted = RlnAdmission::new(Some(path));
        let refreshed = restarted.refresh_from_records(
            "pool",
            Some(&new_content),
            std::slice::from_ref(&record),
        );
        assert!(refreshed.error.is_none(), "{:?}", refreshed.error);
        assert!(refreshed.evict.is_empty());
        assert_eq!(
            restarted.allow_rescan_records("pool", &[record]),
            vec![true]
        );

        let persisted: Value = serde_json::from_slice(
            &std::fs::read(dir.path().join("private").join("rln_roots.json")).unwrap(),
        )
        .unwrap();
        let history = persisted["pools"]["pool"]["superseded"].as_array().unwrap();
        assert!(history.iter().any(|entry| {
            entry["smallest_bucket"].as_u64() == Some(64)
                && entry["limit"].as_u64() == Some(4)
                && entry["valid_through_epoch"].as_u64() == Some(epoch as u64)
        }));
        let leftovers: Vec<_> = std::fs::read_dir(dir.path().join("private"))
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic temp files leaked: {leftovers:?}"
        );
    }

    #[test]
    fn delayed_old_root_is_epoch_bounded_after_member_revocation() {
        let admission = RlnAdmission::new(None);
        let alice = RlnIdentity::from_seed(b"revoked-history-alice");
        let bob = RlnIdentity::from_seed(b"revoked-history-bob");
        let descriptor = |limit: u32, bucket: usize, roster: Vec<String>| {
            serde_json::json!({
                "pool": { "channels": {
                    "rln_required": true,
                    "rln_limit": limit,
                    "pad_buckets": [bucket],
                    "rln_roster": roster,
                }}
            })
        };
        let old_content = descriptor(4, 64, vec![commitment_to_hex(&alice.commitment())]);
        let new_content = descriptor(1, 128, vec![commitment_to_hex(&bob.commitment())]);
        assert!(admission
            .refresh_from_records("pool", Some(&old_content), &[])
            .error
            .is_none());
        let epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
        let current_ct = vec![41u8; 96];
        let next_ct = vec![42u8; 96];
        let current_proof = admission
            .reserve_proof("pool", &alice, epoch, &current_ct)
            .unwrap()
            .proof;
        let next_proof = admission
            .reserve_proof("pool", &alice, epoch + 1, &next_ct)
            .unwrap()
            .proof;
        assert!(admission
            .refresh_from_records("pool", Some(&new_content), &[])
            .error
            .is_none());

        let current = PoolAdmissionRecord {
            id: [41; 32],
            rln_proof: current_proof,
            ct: current_ct,
            epoch,
        };
        let admitted = admission.admit_records("pool", &[current]);
        assert!(admitted.decisions[0].admit);
        assert!(admitted.decisions[0].deliver);
        assert!(admitted.decisions[0].error.is_none());
        drop(admitted);

        let next = PoolAdmissionRecord {
            id: [42; 32],
            rln_proof: next_proof,
            ct: next_ct,
            epoch: epoch + 1,
        };
        let rejected = admission.admit_records("pool", &[next]);
        assert!(!rejected.decisions[0].admit);
        assert!(!rejected.decisions[0].deliver);
        assert!(rejected.decisions[0].error.is_none());
    }

    #[test]
    fn corrupt_root_history_fails_refresh_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rln_usage.json");
        std::fs::write(dir.path().join("rln_roots.json"), b"{not valid json").unwrap();
        let alice = RlnIdentity::from_seed(b"corrupt-history-alice");
        let content = serde_json::json!({
            "pool": { "channels": {
                "rln_required": true,
                "rln_limit": 4,
                "pad_buckets": [64],
                "rln_roster": [commitment_to_hex(&alice.commitment())],
            }}
        });
        let admission = RlnAdmission::new(Some(path));
        let refreshed = admission.refresh_from_records("pool", Some(&content), &[]);
        assert!(refreshed
            .error
            .unwrap()
            .contains("invalid RLN root history"));
        assert!(!admission.is_member("pool", &alice));
    }

    #[test]
    fn failed_root_history_persistence_does_not_open_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let blocked_parent = dir.path().join("blocked");
        let path = blocked_parent.join("rln_usage.json");
        let admission = RlnAdmission::new(Some(path));
        std::fs::write(&blocked_parent, b"not a directory").unwrap();
        let alice = RlnIdentity::from_seed(b"failed-history-alice");
        let content = serde_json::json!({
            "pool": { "channels": {
                "rln_required": true,
                "rln_limit": 4,
                "pad_buckets": [64],
                "rln_roster": [commitment_to_hex(&alice.commitment())],
            }}
        });
        let refreshed = admission.refresh_from_records("pool", Some(&content), &[]);
        assert!(refreshed
            .error
            .unwrap()
            .contains("cannot create RLN root history directory"));
        assert!(!admission.is_member("pool", &alice));
    }

    #[test]
    fn corrupt_usage_ledger_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rln_usage.json");
        std::fs::write(&path, b"{not valid json").unwrap();
        let ledger = UsageLedger::load(Some(path));
        let err = ledger.reserve("pool", 7, 1, 4).unwrap_err();
        assert!(err.contains("invalid RLN usage ledger"));
        assert_eq!(ledger.spent("pool", 7), 0);
    }

    #[test]
    fn failed_persistence_does_not_advance_in_memory_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let blocked_parent = dir.path().join("blocked");
        let path = blocked_parent.join("rln_usage.json");
        let ledger = UsageLedger::load(Some(path));
        std::fs::write(&blocked_parent, b"not a directory").unwrap();

        let err = ledger.reserve("pool", 9, 1, 4).unwrap_err();
        assert!(err.contains("cannot create RLN usage directory"));
        assert_eq!(ledger.spent("pool", 9), 0);
    }

    #[test]
    fn poison_ledger_replaces_durably_and_prunes_at_the_active_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private").join("rln_poison.json");
        let ledger = PoisonLedger::load(Some(path.clone()));
        ledger.add("pool", 10, &[[1; 32]], 3).unwrap();
        ledger.add("pool", 10, &[[2; 32]], 3).unwrap();

        let restarted = PoisonLedger::load(Some(path.clone()));
        assert_eq!(
            restarted.snapshot_and_prune("pool", 3).unwrap(),
            BTreeMap::from([(10, vec![[1; 32], [2; 32]])])
        );
        assert!(restarted.snapshot_and_prune("pool", 11).unwrap().is_empty());
        assert!(
            PoisonLedger::load(Some(path))
                .snapshot_and_prune("pool", 11)
                .unwrap()
                .is_empty(),
            "the pruned sidecar survived restart"
        );
    }

    #[test]
    fn corrupt_poison_ledger_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rln_poison.json");
        std::fs::write(&path, b"{not valid json").unwrap();
        let ledger = PoisonLedger::load(Some(path));
        assert!(ledger
            .snapshot_and_prune("pool", 0)
            .unwrap_err()
            .contains("invalid RLN poison ledger"));
        assert!(ledger.add("pool", 7, &[[1; 32]], 0).is_err());
    }

    #[test]
    fn failed_poison_persistence_does_not_commit_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let blocked_parent = dir.path().join("blocked");
        let path = blocked_parent.join("rln_poison.json");
        let ledger = PoisonLedger::load(Some(path));
        std::fs::write(&blocked_parent, b"not a directory").unwrap();

        let error = ledger.add("pool", 9, &[[1; 32]], 0).unwrap_err();
        assert!(error.contains("cannot create RLN poison directory"));
        assert!(ledger.snapshot_and_prune("pool", 0).unwrap().is_empty());
    }

    #[test]
    fn address_transaction_serializes_persistence_and_refresh_scan() {
        use std::sync::mpsc;
        use std::time::Duration;

        let admission = RlnAdmission::new(None);
        let first = admission.admit_records("pool", &[]);

        let (admit_tx, admit_rx) = mpsc::channel();
        let second_admission = admission.clone();
        let second = std::thread::spawn(move || {
            let batch = second_admission.admit_records("pool", &[]);
            admit_tx.send(()).unwrap();
            drop(batch);
        });
        assert!(
            admit_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "a second admission entered before the first persistence permit was released"
        );

        let (refresh_tx, refresh_rx) = mpsc::channel();
        let refresh_admission = admission.clone();
        let refresh = std::thread::spawn(move || {
            let mut retained = || {
                refresh_tx.send(()).unwrap();
                Ok(Vec::new())
            };
            let refreshed = refresh_admission.refresh_address("pool", None, &mut retained);
            drop(refreshed);
        });
        assert!(
            refresh_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "refresh scanned disk before the admitted write permit was released"
        );

        drop(first);
        admit_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        second.join().unwrap();
        refresh_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        refresh.join().unwrap();
    }
}
