//! Cross-repo leaf-binding KAT: the REAL canonical leaf preimage the EpixChain
//! devnet served for alice.epix (json.Marshal(domainDigestEntry)), bound + parsed
//! by the client's `verify_and_parse_leaf`.

use epix_chain::verify_and_parse_leaf;

const LEAF_PREIMAGE_HEX: &str = "7b226e616d65223a22616c696365222c22746c64223a2265706978222c226f776e6572223a226570697831793474673267637374676a7235613261637333667572786a77703667346566676734796c6d77227d";
const LEAF_HASH: &str = "8a7b8cc7bbc1393f9aca1b4062331b24ac8ba48cda6d7a87da3a827a345f77ee";

#[test]
fn live_devnet_leaf_binds_and_parses() {
    let preimage = hex::decode(LEAF_PREIMAGE_HEX).unwrap();
    let snap = verify_and_parse_leaf(&preimage, LEAF_HASH, "alice", "epix").unwrap();
    assert_eq!(snap.name, "alice");
    assert_eq!(snap.owner, "epix1y4tg2gcstgjr5a2acs3furxjwp6g4efgg4ylmw");
    assert!(verify_and_parse_leaf(&preimage, LEAF_HASH, "bob", "epix").is_err());
    let mut t = preimage.clone(); t.extend_from_slice(b" x");
    assert!(verify_and_parse_leaf(&t, LEAF_HASH, "alice", "epix").is_err());
}
