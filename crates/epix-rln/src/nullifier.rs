//! Per-epoch nullifier tracking and the double-signal reveal.

use std::collections::HashMap;

use rln::prelude::{compute_id_secret, Fr, SecretFr};

use crate::{fr_key, RlnError};

/// The outcome of observing one verified proof's nullifier for an epoch.
pub enum Observation {
    /// First time this nullifier appears this epoch: the member is within its
    /// allowance. Admit the record.
    Fresh,
    /// The identical share was already seen: a duplicate record, not a new
    /// violation. (A re-broadcast of the same record.)
    Replay,
    /// A second, DISTINCT share for the same nullifier: the member exceeded its
    /// per-epoch allowance. The scheme has revealed their identity secret; pass
    /// it to [`crate::commitment_of_secret`] to find and evict the offender.
    DoubleSignal { recovered_secret: SecretFr },
}

/// Records the first share seen for each nullifier, per epoch, so a second
/// distinct share for the same nullifier recovers the offender's secret. The
/// node keeps this in memory over the active epoch window and prunes old epochs
/// with [`NullifierLog::prune_before`].
#[derive(Default)]
pub struct NullifierLog {
    // epoch -> nullifier bytes -> the first (x, y) share seen
    seen: HashMap<u64, HashMap<[u8; 32], (Fr, Fr)>>,
}

impl NullifierLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe a verified proof's `(nullifier, share)` for `epoch`.
    ///
    /// `share` is `(x, y)` from [`crate::Verified`]. `x` (the signal) is unique
    /// per record, so a repeat with the same `x` is a replay, while a repeat
    /// with a different `x` is the double-signal that reveals the secret.
    pub fn observe(
        &mut self,
        epoch: u64,
        nullifier: Fr,
        share: (Fr, Fr),
    ) -> Result<Observation, RlnError> {
        let key = fr_key(&nullifier)?;
        let epoch_map = self.seen.entry(epoch).or_default();
        match epoch_map.get(&key).copied() {
            None => {
                epoch_map.insert(key, share);
                Ok(Observation::Fresh)
            }
            Some((x0, _)) if x0 == share.0 => Ok(Observation::Replay),
            Some(first) => {
                let recovered = compute_id_secret(first, share)
                    .map_err(|e| RlnError::Recover(e.to_string()))?;
                Ok(Observation::DoubleSignal { recovered_secret: recovered })
            }
        }
    }

    /// Forget nullifiers for epochs strictly before `oldest`, bounding memory to
    /// the active window.
    pub fn prune_before(&mut self, oldest: u64) {
        self.seen.retain(|&e, _| e >= oldest);
    }
}
