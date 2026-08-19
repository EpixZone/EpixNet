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

use epix_rln::{bucket_weight, commitment_from_hex, message_signal, Admission, PoolGate, RlnIdentity};
use epix_ui::pool::PoolAdmission;
use epix_ui::state::AppState;
use serde_json::Value;

/// Capability key under which the node stores the shared admission (so the send
/// path can reach the same gates the ingest path uses).
pub const RLN_CAP: &str = "rln_admission";

/// One pool's admission state: the roster gate, plus the config the weight
/// calculation and the send rail need.
struct Pool {
    gate: PoolGate,
    /// Smallest padding bucket in bytes = one allowance unit.
    smallest_bucket: usize,
    /// Per-epoch allowance in units.
    limit: u32,
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
            self.pools.lock().unwrap().remove(address);
            return;
        };
        let commitments: Vec<_> = roster.iter().filter_map(|h| commitment_from_hex(h)).collect();
        // Per-pool external-nullifier domain (derived from the pool address) so an
        // identity's nullifiers never collide across pools. The send side derives
        // it the same way inside the gate.
        let domain = message_signal(address.as_bytes());
        match PoolGate::from_roster(domain, limit, &commitments) {
            Ok(gate) => {
                self.pools
                    .lock()
                    .unwrap()
                    .insert(address.to_string(), Pool { gate, smallest_bucket, limit });
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
        let mut pools = self.pools.lock().unwrap();
        let pool = pools.get_mut(address).ok_or("no RLN roster loaded for this pool")?;
        let weight = bucket_weight(ct.len(), pool.smallest_bucket);
        let first_unit = self.usage.reserve(address, epoch_u, weight, pool.limit).ok_or_else(
            || format!("epoch allowance exhausted ({} units); wait for the next window", pool.limit),
        )?;
        pool.gate
            .prove_as(identity, epoch_u, first_unit, weight, ct)
            .map_err(|e| e.to_string())
    }

    /// This node's RLN footprint for `address` at `epoch`: `(units spent this
    /// epoch, per-epoch unit allowance)`, if a roster is loaded. Feeds the
    /// footprint progress bar. Read-only.
    pub fn usage(&self, address: &str, epoch: u64) -> Option<(u32, u32)> {
        let pools = self.pools.lock().unwrap();
        let pool = pools.get(address)?;
        Some((self.usage.spent(address, epoch), pool.limit))
    }

    /// Whether `identity` is enrolled in `address`'s roster.
    pub fn is_member(&self, address: &str, identity: &RlnIdentity) -> bool {
        self.pools.lock().unwrap().get(address).map(|p| p.gate.is_member(identity)).unwrap_or(false)
    }
}

impl PoolAdmission for RlnAdmission {
    fn admit_record(&self, address: &str, rln_proof: &[u8], ct: &[u8], epoch: i64) -> bool {
        let mut pools = self.pools.lock().unwrap();
        let Some(pool) = pools.get_mut(address) else {
            return false; // no roster loaded for this RLN pool: fail closed
        };
        // The record's cost is its size bucket, computed from ct alone, so a
        // prover cannot under-declare it.
        let weight = bucket_weight(ct.len(), pool.smallest_bucket);
        let root = pool.gate.root();
        matches!(pool.gate.admit(rln_proof, ct, epoch.max(0) as u64, weight, &[root]), Admission::Admit)
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
        *self.spent.lock().unwrap().get(&format!("{address}|{epoch}")).unwrap_or(&0)
    }

    /// Reserve `weight` units at `(address, epoch)`; returns the first unit index
    /// to spend, or `None` if that would exceed `limit`.
    fn reserve(&self, address: &str, epoch: u64, weight: u32, limit: u32) -> Option<u32> {
        let key = format!("{address}|{epoch}");
        let mut s = self.spent.lock().unwrap();
        let cur = *s.get(&key).unwrap_or(&0);
        if cur.checked_add(weight)? > limit {
            return None;
        }
        s.insert(key, cur + weight);
        if let Some(p) = &self.path {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(bytes) = serde_json::to_vec(&*s) {
                let _ = std::fs::write(p, bytes);
            }
        }
        Some(cur)
    }
}
