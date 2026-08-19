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

use std::collections::HashMap;

use rln::prelude::{compute_id_secret, Fr, SecretFr};

use crate::{fr_key, RlnError, Slot};

/// The outcome of observing one verified proof's units for an epoch.
pub enum Observation {
    /// Every unit is fresh (none of its nullifiers seen before this epoch): the
    /// record is within allowance. Admit it.
    Fresh,
    /// Every active unit was already seen with the SAME share: a re-broadcast of
    /// an already-admitted record, not a new violation.
    Replay,
    /// At least one unit collides with a DIFFERENT share: the member exceeded its
    /// allowance (reused a unit across records). Its identity secret is
    /// recovered; use [`crate::commitment_of_secret`] to identify the offender.
    DoubleSignal { recovered_secret: SecretFr },
}

/// Records the first share seen for each nullifier, per epoch, so a second
/// distinct share reveals the offender. Kept in memory over the active epoch
/// window and pruned with [`NullifierLog::prune_before`].
#[derive(Default)]
pub struct NullifierLog {
    // epoch -> nullifier bytes -> the first (x, y) share seen
    seen: HashMap<u64, HashMap<[u8; 32], (Fr, Fr)>>,
}

impl NullifierLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a verified proof's active `slots` for `epoch`. Detection is
    /// deterministic and order-independent, so nodes that reconcile partitioned
    /// shards reach the same verdict.
    pub fn observe(&mut self, epoch: u64, slots: &[Slot]) -> Result<Observation, RlnError> {
        // First pass: does ANY unit collide with a different share? If so it is a
        // double-signal regardless of the other units, and the recovered secret
        // is the same on every node holding the pair.
        for slot in slots {
            let key = fr_key(&slot.nullifier)?;
            if let Some(&first) = self.seen.get(&epoch).and_then(|m| m.get(&key)) {
                if first.0 != slot.share.0 {
                    let recovered = compute_id_secret(first, slot.share)
                        .map_err(|e| RlnError::Recover(e.to_string()))?;
                    return Ok(Observation::DoubleSignal { recovered_secret: recovered });
                }
            }
        }
        // No collision: record any not-yet-seen units. If every unit was already
        // present (same share), it is a replay; otherwise at least one unit is new.
        let epoch_map = self.seen.entry(epoch).or_default();
        let mut any_new = false;
        for slot in slots {
            let key = fr_key(&slot.nullifier)?;
            if epoch_map.insert(key, slot.share).is_none() {
                any_new = true;
            }
        }
        Ok(if any_new { Observation::Fresh } else { Observation::Replay })
    }

    /// Forget nullifiers for epochs strictly before `oldest`, bounding memory to
    /// the active window (paired with pool retention pruning).
    pub fn prune_before(&mut self, oldest: u64) {
        self.seen.retain(|&e, _| e >= oldest);
    }
}
