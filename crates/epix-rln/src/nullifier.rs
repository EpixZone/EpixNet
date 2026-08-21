//! Per-epoch nullifier tracking, size-weighted, with a convergent double-signal
//! reveal.
//!
//! Each verified proof carries one nullifier PER unit it spends (a k-byte-bucket
//! record spends k units, hence k nullifiers). A unit is fresh the first time
//! its nullifier is seen in an epoch; a second, DISTINCT share for the same
//! nullifier is a double-signal that recovers the offender's secret.
//!
//! Convergence: partitioned nodes may see a record's units in any order, but the
//! reveal is a deterministic function of the two colliding shares, so every node
//! that ends up holding both derives the SAME offender — the slashing evidence
//! is a property of the replicated pool, not of arrival order.

use std::collections::{BTreeSet, HashMap};

use rln::prelude::{compute_id_secret, Fr, SecretFr};

use crate::{fr_key, RlnError, Slot};

/// Stable logical identity of a pool record. Callers keep it unchanged across
/// transport-only proof, PoW, and signature replacement.
pub type RecordId = [u8; 32];

/// Canonical serialized field element used as a nullifier key.
pub type NullifierId = [u8; 32];

/// The outcome of observing one verified proof's units for an epoch.
pub enum Observation {
    /// Every unit is fresh (none of its nullifiers seen before this epoch): the
    /// record is within allowance. Admit it.
    Fresh,
    /// Every active unit was already seen with the SAME share: a re-broadcast of
    /// an already-admitted record, not a new violation.
    Replay {
        /// Whether this wrapper is the deterministic survivor.
        keep_record: bool,
        /// Previously retained equivalent wrappers that must be removed.
        evicted_records: Vec<RecordId>,
    },
    /// Some units replay an existing share while others are new. A valid
    /// retransmission must replay the whole proof. Accepting a sliding window
    /// here would let one ciphertext consume overlapping allowance ranges.
    PartialOverlap {
        /// Whether the newly observed window is the deterministic survivor.
        keep_record: bool,
        /// Previously retained overlapping windows that must be removed.
        evicted_records: Vec<RecordId>,
    },
    /// At least one unit belongs to a previously proven double-signal
    /// component. The record is quarantined without changing live state.
    Quarantined,
    /// At least one unit collides with a DIFFERENT share: the member exceeded its
    /// allowance (reused a unit across records). Its identity secret is
    /// recovered; use [`crate::commitment_of_secret`] to identify the offender.
    DoubleSignal {
        recovered_secret: SecretFr,
        /// Previously accepted records in the conflicting component. They must
        /// all be removed from persistent shards. The offending incoming record
        /// is never retained.
        conflicting_records: Vec<RecordId>,
        /// Every nullifier in the touched conflicting component. Callers must
        /// persist these before committing shard evictions, then import them
        /// with [`NullifierLog::poison`].
        poisoned_nullifiers: Vec<NullifierId>,
    },
}

#[derive(Clone)]
struct SeenShare {
    share: (Fr, Fr),
    record_id: RecordId,
}

struct OverlapScan {
    overlap_records: BTreeSet<RecordId>,
    recovered_secret: Option<SecretFr>,
    same_share: usize,
    incoming_keys: Vec<NullifierId>,
}

/// Records the first share seen for each nullifier, per epoch, so a second
/// distinct share reveals the offender. Kept in memory over the active epoch
/// window and pruned with [`NullifierLog::prune_before`].
#[derive(Default)]
pub struct NullifierLog {
    // epoch -> nullifier bytes -> the deterministic surviving share + record.
    seen: HashMap<u64, HashMap<[u8; 32], SeenShare>>,
    // epoch -> record -> all nullifiers it owns. This reverse index lets a
    // lower record id evict every slot of an earlier conflicting record rather
    // than leaving ghost slots that make reconciliation order-dependent.
    records: HashMap<u64, HashMap<RecordId, Vec<[u8; 32]>>>,
    // epoch -> nullifiers proven to be part of a double-signal component.
    poisoned: HashMap<u64, BTreeSet<NullifierId>>,
}

impl NullifierLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn contains_record(&self, epoch: u64, record_id: &RecordId) -> bool {
        self.records
            .get(&epoch)
            .is_some_and(|records| records.contains_key(record_id))
    }

    /// Observe a verified proof's active `slots` for `epoch`. Detection is
    /// deterministic and order-independent, so nodes that reconcile partitioned
    /// shards reach the same verdict.
    pub fn observe(
        &mut self,
        epoch: u64,
        record_id: RecordId,
        slots: &[Slot],
    ) -> Result<Observation, RlnError> {
        let Some(scan) = self.scan_overlap(epoch, slots)? else {
            return Ok(Observation::Quarantined);
        };
        let OverlapScan {
            overlap_records,
            recovered_secret,
            same_share,
            incoming_keys,
        } = scan;

        if let Some(recovered_secret) = recovered_secret {
            return Ok(self.double_signal_observation(
                epoch,
                recovered_secret,
                overlap_records,
                incoming_keys,
            ));
        }

        // With no different share, only one complete wrapper or allowance
        // window may survive. Select it by stable id so opposite-first
        // partitions converge without granting extra capacity.
        if same_share == slots.len() {
            let (keep_record, evicted_records) =
                self.resolve_overlap(epoch, record_id, slots, &overlap_records)?;
            return Ok(Observation::Replay {
                keep_record,
                evicted_records,
            });
        }
        if same_share > 0 {
            let (keep_record, evicted_records) =
                self.resolve_overlap(epoch, record_id, slots, &overlap_records)?;
            return Ok(Observation::PartialOverlap {
                keep_record,
                evicted_records,
            });
        }
        self.insert_record(epoch, record_id, slots)?;
        Ok(Observation::Fresh)
    }

    /// Discover the complete overlap component before mutating live state.
    fn scan_overlap(&self, epoch: u64, slots: &[Slot]) -> Result<Option<OverlapScan>, RlnError> {
        let mut scan = OverlapScan {
            overlap_records: BTreeSet::new(),
            recovered_secret: None,
            same_share: 0,
            incoming_keys: Vec::with_capacity(slots.len()),
        };
        for slot in slots {
            let Some(key) = self.scan_slot(epoch, slot, &mut scan)? else {
                return Ok(None);
            };
            scan.incoming_keys.push(key);
        }
        Ok(Some(scan))
    }

    fn scan_slot(
        &self,
        epoch: u64,
        slot: &Slot,
        scan: &mut OverlapScan,
    ) -> Result<Option<NullifierId>, RlnError> {
        let key = fr_key(&slot.nullifier)?;
        if self
            .poisoned
            .get(&epoch)
            .is_some_and(|poisoned| poisoned.contains(&key))
        {
            return Ok(None);
        }
        let Some(first) = self.seen.get(&epoch).and_then(|seen| seen.get(&key)) else {
            return Ok(Some(key));
        };
        scan.overlap_records.insert(first.record_id);
        if first.share.0 == slot.share.0 {
            scan.same_share += 1;
            return Ok(Some(key));
        }
        Self::merge_recovered_secret(&mut scan.recovered_secret, first.share, slot.share)?;
        Ok(Some(key))
    }

    fn merge_recovered_secret(
        expected: &mut Option<SecretFr>,
        first: (Fr, Fr),
        second: (Fr, Fr),
    ) -> Result<(), RlnError> {
        let recovered = compute_id_secret(first, second)
            .map_err(|error| RlnError::Recover(error.to_string()))?;
        match expected {
            Some(expected) if **expected != *recovered => Err(RlnError::Recover(
                "colliding slots recovered different identity secrets".into(),
            )),
            Some(_) => Ok(()),
            None => {
                *expected = Some(recovered);
                Ok(())
            }
        }
    }

    fn double_signal_observation(
        &self,
        epoch: u64,
        recovered_secret: SecretFr,
        overlap_records: BTreeSet<RecordId>,
        incoming_keys: Vec<NullifierId>,
    ) -> Observation {
        // Quarantine the whole conflicting component. Keeping a deterministic
        // replacement would make each lower record id a fresh delivery.
        let mut poisoned_nullifiers: BTreeSet<NullifierId> =
            incoming_keys.into_iter().collect();
        if let Some(records) = self.records.get(&epoch) {
            for record_id in &overlap_records {
                if let Some(keys) = records.get(record_id) {
                    poisoned_nullifiers.extend(keys.iter().copied());
                }
            }
        }
        Observation::DoubleSignal {
            recovered_secret,
            conflicting_records: overlap_records.into_iter().collect(),
            poisoned_nullifiers: poisoned_nullifiers.into_iter().collect(),
        }
    }

    fn insert_record(
        &mut self,
        epoch: u64,
        record_id: RecordId,
        slots: &[Slot],
    ) -> Result<(), RlnError> {
        let epoch_map = self.seen.entry(epoch).or_default();
        let mut keys = Vec::with_capacity(slots.len());
        for slot in slots {
            let key = fr_key(&slot.nullifier)?;
            epoch_map.insert(
                key,
                SeenShare {
                    share: slot.share,
                    record_id,
                },
            );
            keys.push(key);
        }
        self.records
            .entry(epoch)
            .or_default()
            .insert(record_id, keys);
        Ok(())
    }

    fn resolve_overlap(
        &mut self,
        epoch: u64,
        record_id: RecordId,
        slots: &[Slot],
        overlap_records: &BTreeSet<RecordId>,
    ) -> Result<(bool, Vec<RecordId>), RlnError> {
        let winner = overlap_records
            .iter()
            .copied()
            .chain([record_id])
            .min()
            .unwrap();
        let already_present = self
            .records
            .get(&epoch)
            .is_some_and(|records| records.contains_key(&record_id));
        let evicted_records: Vec<RecordId> = overlap_records
            .iter()
            .copied()
            .filter(|id| *id != winner)
            .collect();
        for id in &evicted_records {
            self.remove_record(epoch, id);
        }
        let keep_record = winner == record_id && !already_present;
        if keep_record {
            self.insert_record(epoch, record_id, slots)?;
        }
        Ok((keep_record, evicted_records))
    }

    fn remove_record(&mut self, epoch: u64, record_id: &RecordId) {
        let keys = self
            .records
            .get_mut(&epoch)
            .and_then(|records| records.remove(record_id));
        if let (Some(keys), Some(seen)) = (keys, self.seen.get_mut(&epoch)) {
            for key in keys {
                if seen
                    .get(&key)
                    .is_some_and(|entry| &entry.record_id == record_id)
                {
                    seen.remove(&key);
            }
        }
        }
    }

    /// Mark nullifiers as durable double-signal evidence. The caller must
    /// persist `keys` before invoking this method. Live records touching a
    /// poisoned key are removed from the normal survivor maps.
    pub fn poison(&mut self, epoch: u64, keys: &[NullifierId]) {
        if keys.is_empty() {
            return;
        }
        self.poisoned
            .entry(epoch)
            .or_default()
            .extend(keys.iter().copied());
        let victims: Vec<RecordId> = self
            .records
            .get(&epoch)
            .into_iter()
            .flat_map(|records| records.iter())
            .filter(|(_, record_keys)| {
                self.poisoned
                    .get(&epoch)
                    .is_some_and(|poisoned| record_keys.iter().any(|key| poisoned.contains(key)))
            })
            .map(|(record_id, _)| *record_id)
            .collect();
        for record_id in victims {
            self.remove_record(epoch, &record_id);
        }
    }

    /// True when any supplied nullifier was durably poisoned.
    pub fn touches_poisoned(&self, epoch: u64, keys: &[NullifierId]) -> bool {
        self.poisoned
            .get(&epoch)
            .is_some_and(|poisoned| keys.iter().any(|key| poisoned.contains(key)))
    }

    /// Forget nullifiers for epochs strictly before `oldest`, bounding memory to
    /// the active window (paired with pool retention pruning).
    pub fn prune_before(&mut self, oldest: u64) {
        self.seen.retain(|&e, _| e >= oldest);
        self.records.retain(|&e, _| e >= oldest);
        self.poisoned.retain(|&e, _| e >= oldest);
    }
}
