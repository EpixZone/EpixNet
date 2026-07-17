//! Phase-0 spike: chain-verified `.epix` resolution against the live Epix chain.
//!
//! Ports XidResolver's `_resolve_with_proof` pipeline:
//!   1. GET /xid/v1/resolve_with_proof/{tld}/{name}  -> domain + Merkle proof
//!   2. recompute Merkle root (SHA256) and check == proof.root
//!   3. GET /xid/v1/state_digest  -> require proof.root == attested digest
//!   4. GET /xid/v1/attestations?digest=..  -> require finalized == true
//!
//! Usage: xid-spike <name> [tld] [rpc_url]

use serde_json::Value;
use sha2::{Digest, Sha256};

const DEFAULT_RPC: &str = "https://api.epix.zone";

/// Recompute a Merkle root from leaf + siblings, ordering by index parity.
/// Mirrors XidResolverPlugin._verify_merkle_proof exactly.
fn verify_merkle_proof(
    leaf_hash: &str,
    leaf_index: u64,
    siblings: &[String],
    expected_root: &str,
) -> Result<bool, String> {
    let mut current = hex::decode(leaf_hash).map_err(|e| format!("leaf hex: {e}"))?;
    let mut idx = leaf_index;
    for sib_hex in siblings {
        let sib = hex::decode(sib_hex).map_err(|e| format!("sibling hex: {e}"))?;
        let combined: Vec<u8> = if idx % 2 == 0 {
            [current.as_slice(), sib.as_slice()].concat()
        } else {
            [sib.as_slice(), current.as_slice()].concat()
        };
        current = Sha256::digest(&combined).to_vec();
        idx /= 2;
    }
    Ok(hex::encode(current) == expected_root)
}

fn get_json(client: &reqwest::blocking::Client, url: &str) -> Result<Value, String> {
    client
        .get(url)
        .send()
        .map_err(|e| format!("GET {url}: {e}"))?
        .json::<Value>()
        .map_err(|e| format!("json {url}: {e}"))
}

/// Number/string-tolerant accessor (the chain returns ints as JSON strings).
fn as_u64(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn main() {
    let mut args = std::env::args().skip(1); // nosemgrep: rust.lang.security.args.args
    let name = args.next().unwrap_or_else(|| "quasin".to_string());
    let tld = args.next().unwrap_or_else(|| "epix".to_string());
    let rpc = args.next().unwrap_or_else(|| DEFAULT_RPC.to_string());
    let rpc = rpc.trim_end_matches('/');

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    println!("→ resolving {name}.{tld} via {rpc} ...");

    // Step 1: resolve_with_proof
    let data = get_json(&client, &format!("{rpc}/xid/v1/resolve_with_proof/{tld}/{name}"))
        .expect("resolve_with_proof");
    let domain = data.get("domain").filter(|d| !d.is_null()).expect("name not found");
    let proof = data.get("proof").expect("proof present");
    let chain_root = data.get("root").and_then(|v| v.as_str()).unwrap_or("");

    let leaf_hash = proof.get("leaf_hash").and_then(|v| v.as_str()).expect("leaf_hash");
    let leaf_index = proof.get("leaf_index").and_then(as_u64).unwrap_or(0);
    let proof_root = proof.get("root").and_then(|v| v.as_str()).unwrap_or(chain_root);
    let siblings: Vec<String> = proof
        .get("siblings")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();
    println!("✓ fetched proof - leaf_index={leaf_index}, {} siblings", siblings.len());

    // Step 2: Merkle proof
    let ok = verify_merkle_proof(leaf_hash, leaf_index, &siblings, proof_root).expect("merkle");
    assert!(ok, "Merkle proof verification FAILED (recomputed root != proof root)");
    println!("✓ Merkle proof valid - recomputed root == {}", &proof_root[..16]);

    // Step 3: proof root == attested state digest
    let digest_info = get_json(&client, &format!("{rpc}/xid/v1/state_digest")).expect("state_digest");
    let attested = digest_info.get("digest").and_then(|v| v.as_str()).expect("digest");
    let height = digest_info.get("height").and_then(as_u64);
    assert_eq!(proof_root, attested, "proof root != attested state digest");
    println!("✓ proof root matches attested chain digest (height={height:?})");

    // Step 4: digest finalized by validators
    let att = get_json(&client, &format!("{rpc}/xid/v1/attestations?digest={attested}"))
        .expect("attestations");
    let finalized = att.get("finalized").and_then(|v| v.as_bool()).unwrap_or(false);
    let n = att.get("attestations").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
    assert!(finalized, "state digest not finalized");
    println!("✓ digest finalized by {n} validators");

    // Resolved result: the active identity address(es) the name maps to.
    let idents = domain.get("identities").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let owner = domain.get("record").and_then(|r| r.get("owner")).and_then(|v| v.as_str()).unwrap_or("?");
    println!("\n🎉 {name}.{tld} RESOLVED & CHAIN-VERIFIED");
    println!("  owner: {owner}");
    for id in &idents {
        let addr = id.get("address").and_then(|v| v.as_str()).unwrap_or("?");
        let label = id.get("label").and_then(|v| v.as_str()).unwrap_or("");
        let active = id.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
        let valid = addr.starts_with("epix1");
        println!("  identity: {addr}  label={label:?}  active={active}  epix1_wellformed={valid}");
    }

    // Negative control: a tampered sibling must fail the proof.
    if let Some(first) = siblings.first().cloned() {
        let mut bad = siblings.clone();
        let mut chars: Vec<char> = first.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        bad[0] = chars.into_iter().collect();
        let tampered_ok = verify_merkle_proof(leaf_hash, leaf_index, &bad, proof_root).unwrap();
        assert!(!tampered_ok, "tampered proof unexpectedly verified!");
        println!("\n✓ negative control: tampered Merkle proof correctly REJECTED");
    }
}
