//! Cross-repo finality KAT: a REAL CometBFT vote-extension signature from the
//! EpixChain devnet's validator (signed by its CONSENSUS key — NO attest key, NO
//! registration), verified by the client's `verify_finality`. Proves the client
//! reproduces CanonicalVoteExtension byte-for-byte and verifies the consensus-key
//! signature against the pinned validator set. Frozen from a live devnet
//! (chain_id epix_1916-1, height 49, round 0).

use std::collections::HashMap;

use epix_chain::{
    verify_finality, AttestationEntry, FinalityBundle, PinnedSet, PinnedValidator, VerifyParams,
    DEFAULT_MIN_POWER_BPS,
};

const CONS_PUBKEY: &str = "6e6c6ee249ffc231eae88b1456cf9a82f0bc383d4565196239ca28413d9cc64c";     // validator consensus ed25519 pubkey
const SIG: &str = "78b15d0305d51c84b50b32817f47f23742e71ebcb7af39e8b894a8980ceb605fe58b53b6abfbebabd8b0410a105ed47ace62b4c3f34abe967023bdc852446c01";                // CometBFT ExtensionSignature (hex)
const VOTE_EXT: &str = "083110fac183d4061a4032646261356462633333396537333136616561323638336661663833396331623762316565323331336462373932313132353838313138646630363661613335";            // raw vote-extension payload bytes (hex)

fn pinned() -> PinnedSet {
    let pk: [u8; 32] = hex::decode(CONS_PUBKEY).unwrap().try_into().unwrap();
    let mut v = HashMap::new();
    v.insert("epixvalcons1j74cjk4r9aqq34kmyft6rffgn4mrhdwwzunqvu".to_string(), PinnedValidator { pubkey: pk, voting_power: 1000000 });
    PinnedSet::new(v, "epix_1916-1", 1786831098, 0)
}

fn bundle() -> FinalityBundle {
    FinalityBundle {
        digest_hex: "2dba5dbc339e7316aea2683faf839c1b7b1ee2313db792112588118df066aa35".into(),
        height: 49,
        round: 0,
        block_time_unix: 1786831098,
        attestations: vec![AttestationEntry {
            valcons: "epixvalcons1j74cjk4r9aqq34kmyft6rffgn4mrhdwwzunqvu".into(),
            signature: hex::decode(SIG).unwrap(),
            vote_extension: hex::decode(VOTE_EXT).unwrap(),
            round: 0,
        }],
    }
}

fn params() -> VerifyParams {
    VerifyParams { now_unix: 1786831098, skew_secs: 3600, ws_period_secs: 100_000_000,
                    min_power_bps: DEFAULT_MIN_POWER_BPS, max_height_seen: 0 }
}

#[test]
fn live_devnet_consensus_key_bundle_verifies() {
    // The client reconstructs CanonicalVoteExtension and verifies the REAL CometBFT
    // consensus-key signature -> finalized.
    assert_eq!(verify_finality(&bundle(), &pinned(), &params()), Ok(49));

    // Wrong pinned pubkey (attacker key) must NOT be credited.
    let mut bad = HashMap::new();
    bad.insert("epixvalcons1j74cjk4r9aqq34kmyft6rffgn4mrhdwwzunqvu".to_string(), PinnedValidator { pubkey: [0u8; 32], voting_power: 1000000 });
    let bad_pin = PinnedSet::new(bad, "epix_1916-1", 1786831098, 0);
    assert!(verify_finality(&bundle(), &bad_pin, &params()).is_err());

    // Wrong round -> different CanonicalVoteExtension -> signature fails. Round is
    // authoritative per-attestation now, so tamper the attestation's round.
    let mut b = bundle();
    for a in &mut b.attestations {
        a.round = 999;
    }
    assert!(verify_finality(&b, &pinned(), &params()).is_err());
}
