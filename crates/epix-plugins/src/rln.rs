//! Owner-signed RLN admission for ECX pools.
//!
//! For a pool that sets `rln_required`, the pool owner publishes a signed roster
//! of member identity commitments in its content.json (`pool.<name>.rln_roster`,
//! with `rln_limit` the per-epoch allowance). This reads that roster, builds a
//! per-pool [`PoolGate`], and installs itself as the node's
//! [`epix_ui::pool::PoolAdmission`] hook. Inbound records are then admitted only
//! if their proof verifies against the roster root and the sender is within its
//! allowance; over-limit (double-signalling) records are dropped, and the owner
//! removes repeat offenders from its roster.
//!
//! This is the verification (ingest) half. The send half — attaching a proof to
//! an outbound record — is wired separately in `channel`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use epix_rln::{commitment_from_hex, message_signal, Admission, PoolGate};
use epix_ui::pool::PoolAdmission;
use epix_ui::state::AppState;
use serde_json::Value;

/// Capability key under which the node stores the shared admission (so the send
/// path can reach the same gates the ingest path uses).
pub const RLN_CAP: &str = "rln_admission";

/// Node-side RLN admission using owner-signed member rosters, one gate per pool.
#[derive(Default)]
pub struct RlnAdmission {
    gates: Mutex<HashMap<String, PoolGate>>,
}

impl RlnAdmission {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// (Re)build the gate for `address` from its content.json roster. Call at
    /// startup and whenever the xite's content changes; drops the gate if the
    /// pool no longer requires RLN.
    pub async fn refresh(&self, state: &Arc<AppState>, address: &str) {
        let descriptor = state.content(address).await.and_then(|c| parse_rln_descriptor(&c));
        let Some((limit, roster)) = descriptor else {
            self.gates.lock().unwrap().remove(address);
            return;
        };
        let commitments: Vec<_> = roster.iter().filter_map(|h| commitment_from_hex(h)).collect();
        // Per-pool external-nullifier domain (derived from the pool address) so an
        // identity's nullifiers never collide across pools. The send side must
        // derive it the same way.
        let domain = message_signal(address.as_bytes());
        match PoolGate::from_roster(domain, limit, &commitments) {
            Ok(gate) => {
                self.gates.lock().unwrap().insert(address.to_string(), gate);
                state
                    .log(
                        "INFO",
                        format!("RLN: loaded {} members for {address}", commitments.len()),
                    )
                    .await;
            }
            Err(e) => {
                state.log("ERROR", format!("RLN: gate build failed for {address}: {e}")).await;
            }
        }
    }
}

impl PoolAdmission for RlnAdmission {
    fn admit_record(&self, address: &str, rln_proof: &[u8], ct: &[u8], epoch: i64) -> bool {
        let mut gates = self.gates.lock().unwrap();
        let Some(gate) = gates.get_mut(address) else {
            // No roster loaded for this RLN pool: fail closed.
            return false;
        };
        let root = gate.root();
        matches!(gate.admit(rln_proof, ct, epoch.max(0) as u64, &[root]), Admission::Admit)
    }
}

/// The first `rln_required` pool entry's `(user_message_limit, roster hex list)`.
fn parse_rln_descriptor(content: &Value) -> Option<(u32, Vec<String>)> {
    let pools = content.get("pool")?.as_object()?;
    for entry in pools.values() {
        let Some(obj) = entry.as_object() else { continue };
        if obj.get("rln_required").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let limit = obj.get("rln_limit").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
        let roster = obj
            .get("rln_roster")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default();
        return Some((limit, roster));
    }
    None
}
