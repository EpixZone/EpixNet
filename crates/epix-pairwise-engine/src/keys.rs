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
        "v": 3,
        "xid": xid,
        "ik": b64(&curve::public_key(&ik_priv(seed))),
        "spk": b64(&curve::public_key(&spk_priv(seed, idx))),
        "spk_idx": idx,
    })
}

/// Domain-separated canonical payload signed by the linked auth key. The
/// object is reconstructed field-by-field, so JSON insertion order and unknown
/// fields cannot change the signed meaning.
pub fn bundle_auth_payload(bundle: &Value) -> Option<String> {
    let payload = json!({
        "auth": bundle.get("auth")?.as_str()?,
        "ik": bundle.get("ik")?.as_str()?,
        "spk": bundle.get("spk")?.as_str()?,
        "spk_idx": bundle.get("spk_idx")?.as_u64()?,
        "v": bundle.get("v")?.as_i64()?,
        "xid": bundle.get("xid")?.as_str()?,
    });
    Some(format!(
        "epix-channel/bundle-auth/v1\n{}",
        serde_json::to_string(&payload).ok()?
    ))
}

/// Validate a peer's strict v3 bundle, including the linked auth signature over
/// its canonical xID and key tuple. The loader separately binds that signed xID
/// and auth address to the bundle's certified directory and filename.
pub fn verify_bundle(bundle: &Value) -> bool {
    const FIELDS: &[&str] = &["auth", "auth_sig", "ik", "spk", "spk_idx", "v", "xid"];
    let Some(object) = bundle.as_object() else {
        return false;
    };
    if object.len() != FIELDS.len() || !FIELDS.iter().all(|field| object.contains_key(*field)) {
        return false;
    }
    bundle.get("v").and_then(|v| v.as_i64()) == Some(3)
        && bundle.get("xid").and_then(|v| v.as_str()).is_some()
        && bundle
            .get("ik")
            .and_then(|v| v.as_str())
            .and_then(b64_32)
            .is_some()
        && bundle
            .get("spk")
            .and_then(|v| v.as_str())
            .and_then(b64_32)
            .is_some()
        && bundle.get("spk_idx").and_then(|v| v.as_u64()).is_some()
        && bundle
            .get("auth_sig")
            .and_then(Value::as_str)
            .is_some_and(epix_crypt::is_canonical_recoverable_signature)
        && bundle_auth_payload(bundle).is_some_and(|payload| {
            epix_crypt::verify_keccak(
                &payload,
                bundle
                    .get("auth")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                bundle
                    .get("auth_sig")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
        })
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

    fn high_s_recovery_variant(signature: &str) -> String {
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .unwrap();
        let order = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let low_s = raw[33..65].to_vec();
        let mut high_s = [0u8; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let value = order[index] as i16 - low_s[index] as i16 - borrow;
            if value < 0 {
                high_s[index] = (value + 256) as u8;
                borrow = 1;
            } else {
                high_s[index] = value as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0);
        raw[33..65].copy_from_slice(&high_s);
        raw[0] = 27 + ((raw[0] - 27) ^ 1);
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    fn good_bundle() -> Value {
        let key = epix_crypt::new_seed();
        let auth = epix_crypt::privatekey_to_address(&key).unwrap();
        let mut bundle = build_bundle(&[1u8; 32], "bob.epix");
        bundle["auth"] = json!(auth);
        let payload = bundle_auth_payload(&bundle).unwrap();
        bundle["auth_sig"] = json!(epix_crypt::sign_keccak(&payload, &key).unwrap());
        bundle
    }

    #[test]
    fn build_bundle_is_verifiable_and_deterministic() {
        let b = good_bundle();
        assert!(verify_bundle(&b));
        assert_eq!(b["ik"], build_bundle(&[1u8; 32], "bob.epix")["ik"]);
        assert!(bundle_keys(&b).is_some());
    }

    #[test]
    fn verify_bundle_rejects_malformed_bundles() {
        // Wrong version (downgrade / version confusion).
        let mut b = good_bundle();
        b["v"] = json!(1);
        assert!(!verify_bundle(&b), "v != 3 rejected");
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
        assert!(
            bundle_keys(&b).is_none(),
            "bundle_keys also rejects short spk"
        );

        let mut forged = good_bundle();
        let sibling = epix_crypt::new_seed();
        forged["auth"] = json!(epix_crypt::privatekey_to_address(&sibling).unwrap());
        assert!(
            !verify_bundle(&forged),
            "auth cannot be swapped without its linked key"
        );

        let mut malleated = good_bundle();
        let alternate = high_s_recovery_variant(malleated["auth_sig"].as_str().unwrap());
        assert!(epix_crypt::verify_keccak(
            &bundle_auth_payload(&malleated).unwrap(),
            malleated["auth"].as_str().unwrap(),
            &alternate,
        ));
        malleated["auth_sig"] = json!(alternate);
        assert!(!verify_bundle(&malleated), "high-S auth signature rejected");
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
