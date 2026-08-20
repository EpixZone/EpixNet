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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use epix_rln::rln::prelude::Fr;
use epix_rln::{bucket_weight, commitment_from_hex, message_signal, Admission, PoolGate, RlnIdentity};
use epix_ui::pool::PoolAdmission;
use epix_ui::state::AppState;
use serde_json::Value;

/// Capability key under which the node stores the shared admission (so the send
/// path can reach the same gates the ingest path uses).
pub const RLN_CAP: &str = "rln_admission";

/// How many superseded membership roots stay honored after a roster change. A
/// proof made against a root that was current moments before a member add/remove
/// (or a peer a version behind) is still valid; without this grace window such a
/// proof is dropped fail-closed and, since pool records are immutable, is lost
/// forever, so the pool never converges across nodes with roster-version skew.
const GRACE_ROOTS: usize = 2;

/// How long a superseded root stays honored. The grace MUST be bounded by TIME,
/// not just by count: with a count-only window a removed member stays admissible
/// until two FURTHER roster edits occur, so in a low-churn pool removal would
/// never take effect. This is long enough for content.json + an in-flight proof
/// to propagate, but short enough that an owner-removed abuser is cut off quickly.
const GRACE_ROOT_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// Epochs of nullifier history the double-signal log retains (day-bucketed → ~a
/// week of active shards). Older epochs can never collide with a fresh nullifier
/// (the external nullifier binds the epoch), so forgetting them is safe.
const NULLIFIER_RETAIN_EPOCHS: i64 = 8;

/// One pool's admission state: the roster gate, plus the config the weight
/// calculation and the send rail need.
struct Pool {
    gate: PoolGate,
    /// Smallest padding bucket in bytes = one allowance unit.
    smallest_bucket: usize,
    /// Per-epoch allowance in units.
    limit: u32,
    /// Recently-superseded roots still honored (grace window), each paired with
    /// the instant it was superseded; expired past [`GRACE_ROOT_TTL`]. Most-recent
    /// first, NOT including the gate's current root.
    recent_roots: Vec<(Fr, std::time::Instant)>,
}

/// Node-side RLN admission using owner-signed rosters, one gate per pool, plus
/// the send-side usage rail.
pub struct RlnAdmission {
    pools: Mutex<HashMap<String, Pool>>,
    usage: UsageLedger,
}

impl RlnAdmission {
    /// A new admission whose usage rail persists to `ledger_path` (or is
    /// memory-only when `None`, e.g. in tests).
    pub fn new(ledger_path: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self { pools: Mutex::new(HashMap::new()), usage: UsageLedger::load(ledger_path) })
    }

    /// (Re)build the gate for `address` from its content.json roster. Call at
    /// startup and whenever the xite's content changes; drops the gate if the
    /// pool no longer requires RLN.
    pub async fn refresh(&self, state: &Arc<AppState>, address: &str) {
        let Some((limit, smallest_bucket, roster)) =
            state.content(address).await.and_then(|c| parse_rln_descriptor(&c))
        else {
            self.pools.lock().unwrap_or_else(|e| e.into_inner()).remove(address);
            return;
        };
        let commitments: Vec<_> = roster.iter().filter_map(|h| commitment_from_hex(h)).collect();
        // Per-pool external-nullifier domain (derived from the pool address) so an
        // identity's nullifiers never collide across pools. The send side derives
        // it the same way inside the gate.
        let domain = message_signal(address.as_bytes());
        match PoolGate::from_roster(domain, limit, &commitments) {
            Ok(gate) => {
                let new_root = gate.root();
                // Scope the (non-Send) std MutexGuard so it is released BEFORE the
                // await below — otherwise this future would not be `Send`.
                {
                    let mut pools = self.pools.lock().unwrap_or_else(|e| e.into_inner());
                    let now = std::time::Instant::now();
                    // Carry the outgoing root (superseded as of NOW) and the still-
                    // unexpired older grace roots forward, so a proof made against
                    // the just-superseded roster still verifies for GRACE_ROOT_TTL.
                    let mut recent: Vec<(Fr, std::time::Instant)> = Vec::new();
                    if let Some(prev) = pools.get(address) {
                        recent.push((prev.gate.root(), now));
                        recent.extend(
                            prev.recent_roots
                                .iter()
                                .copied()
                                .filter(|(_, ts)| now.duration_since(*ts) < GRACE_ROOT_TTL),
                        );
                    }
                    recent.retain(|(r, _)| *r != new_root);
                    // Dedup by root (tiny vec), keeping the newest timestamp.
                    let mut recent_roots: Vec<(Fr, std::time::Instant)> = Vec::new();
                    for (r, ts) in recent {
                        if !recent_roots.iter().any(|(er, _)| *er == r) {
                            recent_roots.push((r, ts));
                        }
                    }
                    recent_roots.truncate(GRACE_ROOTS);
                    pools.insert(
                        address.to_string(),
                        Pool { gate, smallest_bucket, limit, recent_roots },
                    );
                }
                state
                    .log("INFO", format!("RLN: loaded {} members for {address}", commitments.len()))
                    .await;
            }
            Err(e) => {
                state.log("ERROR", format!("RLN: gate build failed for {address}: {e}")).await;
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
        let epoch_u = epoch.max(0) as u64;
        let mut pools = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        let pool = pools.get_mut(address).ok_or("no RLN roster loaded for this pool")?;
        let weight = bucket_weight(ct.len(), pool.smallest_bucket);
        let first_unit = self.usage.reserve(address, epoch_u, weight, pool.limit).ok_or_else(
            || format!("epoch allowance exhausted ({} units); wait for the next window", pool.limit),
        )?;
        // Roll the reservation back if proof generation fails, so a transient error
        // (or a non-member reaching here) never permanently burns epoch allowance
        // for a record that was never produced.
        match pool.gate.prove_as(identity, epoch_u, first_unit, weight, ct) {
            Ok(proof) => Ok(proof),
            Err(e) => {
                self.usage.release(address, epoch_u, weight);
                Err(e.to_string())
            }
        }
    }

    /// This node's RLN footprint for `address` at `epoch`: `(units spent this
    /// epoch, per-epoch unit allowance)`, if a roster is loaded. Feeds the
    /// footprint progress bar. Read-only.
    pub fn usage(&self, address: &str, epoch: u64) -> Option<(u32, u32)> {
        let pools = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        let pool = pools.get(address)?;
        Some((self.usage.spent(address, epoch), pool.limit))
    }

    /// Whether `identity` is enrolled in `address`'s roster.
    pub fn is_member(&self, address: &str, identity: &RlnIdentity) -> bool {
        self.pools.lock().unwrap_or_else(|e| e.into_inner()).get(address).map(|p| p.gate.is_member(identity)).unwrap_or(false)
    }
}

impl PoolAdmission for RlnAdmission {
    fn admit_record(&self, address: &str, rln_proof: &[u8], ct: &[u8], epoch: i64) -> bool {
        let mut pools = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pool) = pools.get_mut(address) else {
            return false; // no roster loaded for this RLN pool: fail closed
        };
        // Bound the in-memory nullifier log. Prune by the record's epoch CLAMPED
        // to the local clock: clamping to `now_epoch` stops an attacker's
        // future-dated `epoch` (unverified here — merge_pool checks it later) from
        // pushing the cutoff forward and wiping live nullifiers (re-enabling
        // replay), while using the epoch actually being admitted avoids
        // over-pruning when the node processes an older epoch.
        let now_epoch = epix_content::pool::epoch_now(epix_core::time::now_ms());
        let prune_epoch = epoch.min(now_epoch);
        let cutoff = prune_epoch.saturating_sub(NULLIFIER_RETAIN_EPOCHS).max(0) as u64;
        pool.gate.prune_before(cutoff);
        // The record's cost is its size bucket, computed from ct alone, so a
        // prover cannot under-declare it.
        let weight = bucket_weight(ct.len(), pool.smallest_bucket);
        // Honor the current root plus a small, TIME-bounded grace window of
        // superseded roots, so a proof made against the roster just before a member
        // add/remove (or by a peer a content.json version behind) is still
        // admitted. Drop expired grace roots first, so an owner-removed member is
        // cut off once GRACE_ROOT_TTL elapses even if no further roster edit occurs.
        let now = std::time::Instant::now();
        pool.recent_roots.retain(|(_, ts)| now.duration_since(*ts) < GRACE_ROOT_TTL);
        let mut roots = Vec::with_capacity(1 + pool.recent_roots.len());
        roots.push(pool.gate.root());
        roots.extend(pool.recent_roots.iter().map(|(r, _)| *r));
        matches!(pool.gate.admit(rln_proof, ct, epoch.max(0) as u64, weight, &roots), Admission::Admit)
    }
}

/// A pool descriptor's `(rln_limit, smallest padding bucket, roster hex list)`,
/// for the first entry that sets `rln_required`.
fn parse_rln_descriptor(content: &Value) -> Option<(u32, usize, Vec<String>)> {
    let pools = content.get("pool")?.as_object()?;
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
        return Some((limit, smallest_bucket, roster));
    }
    None
}

/// The send-side usage rail: a persistent per-`(pool, epoch)` cursor of units
/// spent, so each send draws a fresh range and the client stops at the limit.
/// Persistence is essential — a restart that reset the cursor would let a client
/// reuse a unit and slash itself.
#[derive(Default)]
struct UsageLedger {
    path: Option<PathBuf>,
    spent: Mutex<HashMap<String, u32>>, // "address|epoch" -> units spent
}

impl UsageLedger {
    fn load(path: Option<PathBuf>) -> Self {
        let spent = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<HashMap<String, u32>>(&b).ok())
            .unwrap_or_default();
        Self { path, spent: Mutex::new(spent) }
    }

    /// Units spent at `(address, epoch)` so far (read-only).
    fn spent(&self, address: &str, epoch: u64) -> u32 {
        *self.spent.lock().unwrap_or_else(|e| e.into_inner()).get(&format!("{address}|{epoch}")).unwrap_or(&0)
    }

    /// Reserve `weight` units at `(address, epoch)`; returns the first unit index
    /// to spend, or `None` if that would exceed `limit`.
    fn reserve(&self, address: &str, epoch: u64, weight: u32, limit: u32) -> Option<u32> {
        let key = format!("{address}|{epoch}");
        let mut s = self.spent.lock().unwrap_or_else(|e| e.into_inner());
        let cur = *s.get(&key).unwrap_or(&0);
        if cur.checked_add(weight)? > limit {
            return None;
        }
        s.insert(key, cur + weight);
        // Bound the ledger: past epochs can never be spent against again (the
        // external nullifier binds the epoch), so drop cursors older than the
        // retention window instead of accumulating one key per epoch forever.
        prune_old_epochs(&mut s, epoch);
        Self::persist(&self.path, &s);
        Some(cur)
    }

    /// Undo a `reserve` for `(address, epoch)` (a send that reserved but then
    /// failed to produce a record), returning the units to the epoch allowance.
    fn release(&self, address: &str, epoch: u64, weight: u32) {
        let key = format!("{address}|{epoch}");
        let mut s = self.spent.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cur) = s.get(&key).copied() {
            let back = cur.saturating_sub(weight);
            if back == 0 {
                s.remove(&key);
            } else {
                s.insert(key, back);
            }
            Self::persist(&self.path, &s);
        }
    }

    fn persist(path: &Option<PathBuf>, s: &HashMap<String, u32>) {
        if let Some(p) = path {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(bytes) = serde_json::to_vec(s) {
                let _ = std::fs::write(p, bytes);
            }
        }
    }
}

/// Epochs of usage history to retain (day-bucketed epochs → ~a month).
const USAGE_RETAIN_EPOCHS: u64 = 32;

/// Drop `(address|epoch)` cursors whose epoch is older than the retention window.
fn prune_old_epochs(s: &mut HashMap<String, u32>, current_epoch: u64) {
    let cutoff = current_epoch.saturating_sub(USAGE_RETAIN_EPOCHS);
    s.retain(|k, _| k.rsplit_once('|').and_then(|(_, e)| e.parse::<u64>().ok()).map_or(true, |e| e >= cutoff));
}
