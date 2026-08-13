//! Identity/prekey derivation and the published key bundle.
//!
//! All of a channel identity's long-lived keys are derived from its 32-byte seed
//! (the node hands the engine a per-identity seed via
//! `AppState::derive_consumer_seed`, so nothing here ever touches the master
//! seed). The identity key `IK` is permanent; the signed prekey `SPK` rotates on
//! a weekly index carried in the bundle and in each first-contact header, so a
//! recipient recomputes exactly the `SPK` a sender used.

use crate::curve;
use base64::Engine as _;
use serde_json::{json, Value};

const MS_PER_WEEK: i64 = 7 * 86_400_000;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The permanent identity private key.
pub fn ik_priv(seed: &[u8; 32]) -> [u8; 32] {
    crate::crypto::kdf32("epix-channel/ik/v1", &[], seed)
}

/// The signed prekey private key for rotation index `idx`.
pub fn spk_priv(seed: &[u8; 32], idx: u32) -> [u8; 32] {
    let mut m = seed.to_vec();
    m.extend_from_slice(&idx.to_le_bytes());
    crate::crypto::kdf32("epix-channel/spk/v1", &[], &m)
}

/// The current weekly SPK rotation index.
pub fn current_spk_idx() -> u32 {
    (now_ms() / MS_PER_WEEK).max(0) as u32
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_32(s: &str) -> Option<[u8; 32]> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()?.try_into().ok()
}

/// Build the publishable key bundle for an identity (its `data/users/<xid>/
/// data.json` payload). Public key material only.
pub fn build_bundle(seed: &[u8; 32], xid: &str) -> Value {
    let idx = current_spk_idx();
    json!({
        "v": 2,
        "xid": xid,
        "ik": b64(&curve::public_key(&ik_priv(seed))),
        "spk": b64(&curve::public_key(&spk_priv(seed, idx))),
        "spk_idx": idx,
    })
}

/// Validate a peer's published bundle's structure. Authenticity (that this
/// bundle really belongs to `xid`) rests on the signed per-user `data.json`
/// the node already verifies, plus the sealed-sender cross-check in `open_first`
/// (the first message's inner `ik` must equal this bundle's `ik`).
pub fn verify_bundle(bundle: &Value) -> bool {
    bundle.get("v").and_then(|v| v.as_i64()) == Some(2)
        && bundle.get("ik").and_then(|v| v.as_str()).and_then(b64_32).is_some()
        && bundle.get("spk").and_then(|v| v.as_str()).and_then(b64_32).is_some()
        && bundle.get("spk_idx").and_then(|v| v.as_u64()).is_some()
}

/// Extract `(ik, spk, spk_idx)` from a peer bundle.
pub fn bundle_keys(bundle: &Value) -> Option<([u8; 32], [u8; 32], u32)> {
    let ik = bundle.get("ik").and_then(|v| v.as_str()).and_then(b64_32)?;
    let spk = bundle.get("spk").and_then(|v| v.as_str()).and_then(b64_32)?;
    let idx = bundle.get("spk_idx").and_then(|v| v.as_u64())? as u32;
    Some((ik, spk, idx))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_bundle() -> Value {
        build_bundle(&[1u8; 32], "bob.epix")
    }

    #[test]
    fn build_bundle_is_verifiable_and_deterministic() {
        let b = good_bundle();
        assert!(verify_bundle(&b));
        assert_eq!(b, build_bundle(&[1u8; 32], "bob.epix"), "seed-deterministic");
        assert!(bundle_keys(&b).is_some());
    }

    #[test]
    fn verify_bundle_rejects_malformed_bundles() {
        // Wrong version (downgrade / version confusion).
        let mut b = good_bundle();
        b["v"] = json!(1);
        assert!(!verify_bundle(&b), "v != 2 rejected");
        // Missing ik / spk / spk_idx.
        for field in ["ik", "spk", "spk_idx"] {
            let mut b = good_bundle();
            b.as_object_mut().unwrap().remove(field);
            assert!(!verify_bundle(&b), "missing {field} rejected");
        }
        // Non-base64 and wrong-length key material.
        let mut b = good_bundle();
        b["ik"] = json!("not base64!!");
        assert!(!verify_bundle(&b), "bad base64 ik rejected");
        let mut b = good_bundle();
        b["spk"] = json!(b64(&[0u8; 16])); // 16 bytes, not 32
        assert!(!verify_bundle(&b), "wrong-length spk rejected");
        assert!(bundle_keys(&b).is_none(), "bundle_keys also rejects short spk");
    }

    #[test]
    fn spk_rotates_per_index_and_is_seed_derivable() {
        // Different weekly indices give different prekeys (rotation), and each is
        // recomputable from the seed alone (the no-OPK responder mechanism).
        let seed = [9u8; 32];
        assert_ne!(spk_priv(&seed, 100), spk_priv(&seed, 101));
        assert_eq!(spk_priv(&seed, 100), spk_priv(&seed, 100), "idx-deterministic");
        assert_ne!(ik_priv(&seed), spk_priv(&seed, 100));
    }
}
