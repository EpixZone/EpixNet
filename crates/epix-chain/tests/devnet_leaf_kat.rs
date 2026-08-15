//! Cross-repo leaf-binding KAT: the REAL canonical leaf preimage the EpixChain
//! devnet served for alice.epix (Go json.Marshal(domainDigestEntry)), bound + parsed
//! by the client's `verify_and_parse_leaf`. Proves the client hashes the exact Go
//! bytes to the proven leaf and parses the snapshot from them.

use epix_chain::verify_and_parse_leaf;

// hex of the exact leaf_preimage bytes the chain returned.
const LEAF_PREIMAGE_HEX: &str = "7b226e616d65223a22616c696365222c22746c64223a2265706978222c226f776e6572223a226570697831786b78676e36636e3277386c367a3536616c616468666e6c7775336535756a32367274676b6d227d";
const LEAF_HASH: &str = "afaddcdeb0c957b398985b50b8e0e8091c9a6142576fbe59fa69a147429110a6";

#[test]
fn live_devnet_leaf_binds_and_parses() {
    let preimage = hex::decode(LEAF_PREIMAGE_HEX).unwrap();
    // Correct name binds, hashes to the proven leaf, and parses.
    let snap = verify_and_parse_leaf(&preimage, LEAF_HASH, "alice", "epix").unwrap();
    assert_eq!(snap.name, "alice");
    assert_eq!(snap.tld, "epix");
    assert_eq!(snap.owner, "epix1xkxgn6cn2w8l6z56aladhfnlwu3e5uj26rtgkm");

    // Wrong queried name -> reject (a genuine leaf for a different name).
    assert!(verify_and_parse_leaf(&preimage, LEAF_HASH, "bob", "epix").is_err());
    // Tampered data (won't hash to the proven leaf) -> reject.
    let mut tampered = preimage.clone();
    tampered.extend_from_slice(b" x");
    assert!(verify_and_parse_leaf(&tampered, LEAF_HASH, "alice", "epix").is_err());
}
