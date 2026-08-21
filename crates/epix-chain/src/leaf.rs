//! Client-side **leaf binding** — prove the returned domain data *is* the leaf the
//! Merkle proof includes.
//!
//! The Merkle inclusion proof only proves that *some* `leaf_hash` sits in the
//! finalized tree. It says nothing about whether the `domain` payload the RPC
//! returned alongside it actually *is* that leaf. Without binding the two, a
//! hostile/compromised RPC serves a genuine inclusion proof for a real leaf next
//! to arbitrary `domain` data (owner, identities, DNS, content_root) and it passes
//! — defeating the whole "a malicious RPC cannot forge" guarantee.
//!
//! The chain hashes each domain as
//! `leaf = sha256(json.Marshal(domainDigestEntry{name,tld,owner,profile,dns,
//! identities,content_root}))` (x/xid `computeLeafHash`). So it returns the exact
//! `leaf_preimage` bytes, and here we:
//! 1. check `sha256(leaf_preimage) == leaf_hash` (binds data → leaf), then
//! 2. parse the snapshot **from the preimage** (order-agnostic JSON — we hash the
//!    received bytes, never re-serialize, so Go's exact encoding doesn't matter),
//!    and
//! 3. require the entry's `name`/`tld` equal what was queried.
//!
//! The caller then verifies the inclusion proof over `leaf_hash` and that the root
//! is a finalized digest — chaining validators → digest → leaf → the data used.

use sha2::{Digest, Sha256};

use crate::types::{DnsRecord, DomainSnapshot, Identity};
use crate::{ChainError, Result};
use serde_json::Value;

/// Verify `leaf_preimage` hashes to `leaf_hash_hex` and is the canonical entry for
/// `name.tld`, then parse it into a [`DomainSnapshot`]. The returned snapshot is
/// exactly the bytes proven, so it is safe to trust once the caller has verified
/// the inclusion proof over `leaf_hash_hex`.
pub fn verify_and_parse_leaf(
    leaf_preimage: &[u8],
    leaf_hash_hex: &str,
    name: &str,
    tld: &str,
) -> Result<DomainSnapshot> {
    // (1) Bind data → leaf.
    let got = hex::encode(Sha256::digest(leaf_preimage));
    if !got.eq_ignore_ascii_case(leaf_hash_hex.trim()) {
        return Err(ChainError::LeafBindingFailed(format!(
            "preimage hashes to {got}, proof leaf is {leaf_hash_hex}"
        )));
    }
    // (2) Parse the canonical entry from the proven bytes.
    let v: Value = serde_json::from_slice(leaf_preimage)
        .map_err(|_| ChainError::LeafBindingFailed("leaf preimage is not JSON".into()))?;
    // (3) Bind the name — the leaf must be the one we asked for.
    let entry_name = v.get("name").and_then(|x| x.as_str()).unwrap_or_default();
    let entry_tld = v.get("tld").and_then(|x| x.as_str()).unwrap_or_default();
    if entry_name != name || entry_tld != tld {
        return Err(ChainError::LeafBindingFailed(format!(
            "leaf is for {entry_name}.{entry_tld}, queried {name}.{tld}"
        )));
    }
    Ok(parse_leaf_entry(name, tld, &v))
}

/// Build a [`DomainSnapshot`] from a verified `domainDigestEntry` value. Missing
/// fields (Go `omitempty` drops zero/false/empty) default correctly.
fn parse_leaf_entry(name: &str, tld: &str, v: &Value) -> DomainSnapshot {
    let owner = v.get("owner").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let content_root = v.get("content_root").and_then(|x| x.as_str()).unwrap_or_default().to_string();

    let identities = v
        .get("identities")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|id| {
                    Some(Identity {
                        address: id.get("address")?.as_str()?.to_string(),
                        label: id.get("label").and_then(|x| x.as_str()).unwrap_or_default().to_string(),
                        active: id.get("active").and_then(|x| x.as_bool()).unwrap_or(false),
                        revoked_at: as_u64(id.get("revoked_at")),
                        revoked_at_time: as_u64(id.get("revoked_at_time")),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    // The digest entry uses "dns" (not "dns_records"); each is a DNSRecord.
    let dns_records = v
        .get("dns")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    Some(DnsRecord {
                        record_type: as_u64(r.get("record_type")) as u32,
                        value: r.get("value")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let profile = v.get("profile");
    let avatar = profile
        .and_then(|p| p.get("avatar"))
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    let bio = profile.and_then(|p| p.get("bio")).and_then(|x| x.as_str()).unwrap_or_default().to_string();

    DomainSnapshot {
        name: name.to_string(),
        tld: tld.to_string(),
        owner,
        content_root,
        identities,
        dns_records,
        avatar,
        bio,
    }
}

/// Parse a u64 that may be a JSON number (stdlib `encoding/json`) or, defensively,
/// a string. Absent/other → 0.
fn as_u64(v: Option<&Value>) -> u64 {
    match v {
        Some(x) => x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())).unwrap_or(0),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A synthetic preimage in the digest-entry shape. (A real byte-exact KAT from
    /// the chain is captured during chain integration; parsing is order-agnostic so
    /// only the key names matter here.)
    fn preimage(name: &str, tld: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "name": name,
            "tld": tld,
            "owner": "epix1owner",
            "profile": { "avatar": "http://a", "bio": "hi" },
            "dns": [{ "record_type": 65280, "value": "epix1xite" }],
            "identities": [
                { "address": "epix1id1", "label": "epixnet", "added_at": 5, "active": true },
                { "address": "epix1id2", "label": "epixnet", "active": false, "revoked_at": 99, "revoked_at_time": 1234 }
            ],
            "content_root": "deadbeef"
        }))
        .unwrap()
    }

    fn leaf_hash(preimage: &[u8]) -> String {
        hex::encode(Sha256::digest(preimage))
    }

    #[test]
    fn valid_preimage_binds_and_parses() {
        let p = preimage("mud", "epix");
        let snap = verify_and_parse_leaf(&p, &leaf_hash(&p), "mud", "epix").unwrap();
        assert_eq!(snap.owner, "epix1owner");
        assert_eq!(snap.content_root, "deadbeef");
        assert_eq!(snap.avatar, "http://a");
        assert_eq!(snap.bio, "hi");
        assert_eq!(snap.xite_address(), Some("epix1xite"));
        assert_eq!(snap.active_identity(), Some("epix1id1"));
        assert_eq!(snap.identities.len(), 2);
        assert_eq!(snap.identities[1].revoked_at, 99);
        assert!(!snap.identities[1].active);
    }

    #[test]
    fn wrong_hash_is_rejected() {
        // The classic attack: genuine leaf_hash from a real leaf, but swapped data.
        let real = preimage("mud", "epix");
        let real_hash = leaf_hash(&real);
        let forged = preimage("mud", "epix"); // pretend different data
        let mut forged = forged;
        forged.extend_from_slice(b" tampered");
        let err = verify_and_parse_leaf(&forged, &real_hash, "mud", "epix").unwrap_err();
        assert!(matches!(err, ChainError::LeafBindingFailed(_)), "swapped data must not bind");
    }

    #[test]
    fn wrong_name_is_rejected() {
        // A genuine, correctly-hashing leaf — but for a DIFFERENT name than queried.
        let p = preimage("someoneelse", "epix");
        let err = verify_and_parse_leaf(&p, &leaf_hash(&p), "mud", "epix").unwrap_err();
        assert!(matches!(err, ChainError::LeafBindingFailed(_)), "leaf for another name must reject");
    }

    #[test]
    fn non_json_preimage_is_rejected() {
        let p = b"\x00\x01not json".to_vec();
        let err = verify_and_parse_leaf(&p, &leaf_hash(&p), "mud", "epix").unwrap_err();
        assert!(matches!(err, ChainError::LeafBindingFailed(_)));
    }

    #[test]
    fn omitempty_fields_default_correctly() {
        // Minimal entry (Go omitempty drops profile/dns/identities/content_root).
        let p = serde_json::to_vec(&json!({ "name": "bare", "tld": "epix", "owner": "epix1o" })).unwrap();
        let snap = verify_and_parse_leaf(&p, &leaf_hash(&p), "bare", "epix").unwrap();
        assert_eq!(snap.owner, "epix1o");
        assert!(snap.identities.is_empty());
        assert!(snap.dns_records.is_empty());
        assert_eq!(snap.content_root, "");
        assert_eq!(snap.avatar, "");
    }
}
