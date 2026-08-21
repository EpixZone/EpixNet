//! Dev helper: print a real PairwiseEngine key bundle (X3DH) for a given xid and
//! seed byte, as one line of JSON. Used to seed a test recipient's data.json so
//! the real (non-Fake) engine can be exercised end-to-end on a single node.
//!
//!   cargo run -q -p epix-pairwise-engine --example gen_bundle -- bob.epix 42 <auth-private-key>

use epix_envelope::{Engine, IdentitySecret};
use epix_pairwise_engine::PairwiseEngine;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let xid = args.get(1).cloned().unwrap_or_else(|| "bob.epix".to_string());
    let seed_byte: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(42);
    let secret = IdentitySecret::new([seed_byte; 32]);
    let auth_key = args.get(3).cloned().unwrap_or_else(epix_crypt::new_seed);
    let mut bundle = PairwiseEngine.publish_bundle(&secret, &xid);
    bundle["auth"] = serde_json::json!(epix_crypt::privatekey_to_address(&auth_key).unwrap());
    let payload = epix_pairwise_engine::keys::bundle_auth_payload(&bundle).unwrap();
    bundle["auth_sig"] = serde_json::json!(epix_crypt::sign_keccak(&payload, &auth_key).unwrap());
    // Sanity: it must pass the engine's own verifier.
    assert!(PairwiseEngine.verify_bundle(&bundle), "generated bundle failed verify_bundle");
    println!("{}", serde_json::to_string(&bundle).unwrap());
}
