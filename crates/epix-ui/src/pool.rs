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
use std::sync::Arc;

/// A batch of newly-landed pool records for one xite, broadcast to consumers.
#[derive(Clone)]
pub struct PoolDelta {
    pub address: String,
    pub records: Arc<Vec<Value>>,
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
pub trait PoolAdmission: Send + Sync {
    /// Whether to admit one inbound record of `address`'s pool. `rln_proof` and
    /// `ct` are the decoded record fields and `epoch` its epoch. Implementors
    /// verify the proof against the current membership root and track the
    /// nullifier (evicting a double-signalling member as a side effect);
    /// `false` means reject/drop.
    fn admit_record(&self, address: &str, rln_proof: &[u8], ct: &[u8], epoch: i64) -> bool;
}

/// Peers to fetch from in an anti-entropy sweep.
const POOL_SWEEP_PEERS: usize = 16;
/// Distinct served copies to union per shard before moving on.
const POOL_SWEEP_UNION: usize = 2;
/// Peers to flood a freshly appended record to.
const POOL_PUSH_LIMIT: usize = 8;
/// Peers to re-flood an inbound-merged record to (smaller, anti-storm).
const POOL_REFLOOD_LIMIT: usize = 3;

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

    /// Re-parse and cache a xite's pool rules (call when its content changes).
    pub async fn refresh_pool_rules(&self, address: &str) {
        let rules =
            self.content(address).await.map(|c| pool::pool_rules_of(&c)).unwrap_or_default();
        self.pool_rules.write().await.insert(address.to_string(), rules);
    }

    /// Whether `inner_path` is a pool shard of `address` — the serve/write gate.
    pub async fn is_pool_shard(&self, address: &str, inner_path: &str) -> bool {
        pool::is_under_pool_dir(&self.pool_rules_for(address).await, inner_path)
    }

    /// The pool rule (and its shard week) governing a shard path, if any.
    async fn pool_rule_for_path(&self, address: &str, inner_path: &str) -> Option<(PoolRule, i64)> {
        for rule in self.pool_rules_for(address).await {
            if let Some((week, _sub)) = pool::parse_shard_path(&rule, inner_path) {
                return Some((rule, week));
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

    /// Keep only the inbound records whose RLN proof the installed
    /// [`PoolAdmission`] hook accepts. If none is installed for this RLN pool,
    /// keep nothing (fail closed) — an unverified record must never be merged
    /// into a shard we store and serve.
    async fn filter_rln_admitted(&self, address: &str, container: Value) -> Value {
        let Some(admission) = self.pool_admission.read().await.clone() else {
            return pool::make_pool_container(vec![]);
        };
        let records = container
            .get(pool::POOL_RECORDS_KEY)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let kept: Vec<Value> = records
            .into_iter()
            .filter(|rec| {
                match (
                    rec.get("rln").and_then(|v| v.as_str()).and_then(b64_decode),
                    rec.get("ct").and_then(|v| v.as_str()).and_then(b64_decode),
                    rec.get("epoch").and_then(|v| v.as_i64()),
                ) {
                    (Some(rln), Some(ct), Some(epoch)) => {
                        admission.admit_record(address, &rln, &ct, epoch)
                    }
                    _ => false,
                }
            })
            .collect();
        pool::make_pool_container(kept)
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

        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let existing = storage
            .read(&shard)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or_else(|| pool::make_pool_container(vec![]));
        let incoming = pool::make_pool_container(vec![record]);
        let (merged, delta) =
            pool::merge_pool(&existing, &incoming, &rule, pool::week_of(epoch), now_ms());
        storage.write(&shard, &serde_json::to_vec(&merged).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;

        self.emit_pool_delta(address, delta);

        let this = self.clone();
        let addr = address.to_string();
        let shard_clone = shard.clone();
        tokio::spawn(async move {
            let _ = this
                .publish_to(&addr, &shard_clone, POOL_PUSH_LIMIT, false, Default::default(), None)
                .await;
        });
        Ok(shard)
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
        let (rule, week) =
            self.pool_rule_for_path(address, inner_path).await.ok_or("not a pool shard")?;
        let incoming: Value =
            serde_json::from_slice(signed).map_err(|e| format!("pool shard not JSON: {e}"))?;

        // Anonymous rate-limiting: for an RLN pool, drop any inbound record whose
        // proof does not verify (and let the verifier track nullifiers / evict
        // double-signallers) BEFORE it is merged into the shard we store & serve.
        let incoming = if rule.rln_required {
            self.filter_rln_admitted(address, incoming).await
        } else {
            incoming
        };

        let storage = self.xite_storage(address).await.ok_or("unknown xite")?;
        let existing = storage
            .read(inner_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or_else(|| pool::make_pool_container(vec![]));
        let (merged, delta) = pool::merge_pool(&existing, &incoming, &rule, week, now_ms());
        if delta.is_empty() {
            return Ok(false);
        }
        storage.write(inner_path, &serde_json::to_vec(&merged).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;

        self.emit_pool_delta(address, delta);

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
        let cur_week = pool::week_of(pool::epoch_now(now_ms()));
        let files = storage.list_files();
        for rule in &rules {
            let Some(keep_from) = pool::retention_keep_from(rule, cur_week) else {
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
    pub async fn pool_all_records(&self, address: &str) -> Vec<Value> {
        let rules = self.pool_rules_for(address).await;
        let Some(storage) = self.xite_storage(address).await else { return Vec::new() };
        let cur_week = pool::week_of(pool::epoch_now(now_ms()));
        let mut records = Vec::new();
        for rule in &rules {
            for path in pool::sync_shard_paths(rule, cur_week) {
                if let Ok(bytes) = storage.read(&path) {
                    if let Ok(container) = serde_json::from_slice::<Value>(&bytes) {
                        records.extend(pool::pool_records_of(&container));
                    }
                }
            }
        }
        records
    }
}
