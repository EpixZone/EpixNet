//! Cross-repo finality KAT: a REAL bundle signed by the EpixChain devnet's
//! validator (ed25519 attest key), verified by the client's `verify_finality`.
//! Proves the Go signer and the Rust verifier agree end-to-end. Frozen vector
//! captured from a live single-validator devnet (chain_id epix_1916-1).

use std::collections::HashMap;

use epix_chain::{
    verify_finality, AttestationEntry, FinalityBundle, PinnedSet, PinnedValidator, VerifyParams,
    DEFAULT_MIN_POWER_BPS,
};

#[test]
fn live_devnet_bundle_verifies() {
    let pubkey: [u8; 32] = hex::decode("2c787544e6a7958f8f334ae9f38946846beb2f9e989d82a275ab05959b8efa6d").unwrap().try_into().unwrap();
    let mut validators = HashMap::new();
    validators.insert(
        "epixvalcons1v84ds4v3j82ttu5t64m7kmgxcr6c67geme3ygq".to_string(),
        PinnedValidator { pubkey, voting_power: 1000000 },
    );
    let pinned = PinnedSet::new(validators, "epix_1916-1", 1786829400, 0);

    let bundle = FinalityBundle {
        digest_hex: "2dba5dbc339e7316aea2683faf839c1b7b1ee2313db792112588118df066aa35".into(),
        height: 120,
        block_time_unix: 1786829400,
        attestations: vec![AttestationEntry {
            valcons: "epixvalcons1v84ds4v3j82ttu5t64m7kmgxcr6c67geme3ygq".into(),
            signature: hex::decode("0d9542d27a14f96637ad63f32f9b158e634373ab3857f72c26426f9706a8383283c0471c87b10c5ed10166fe67d9f2b2b41bc606bb49e1d15f95ebcb47c86607").unwrap(),
        }],
    };

    // now == the signed block_time (fresh); generous WS window.
    let params = VerifyParams {
        now_unix: 1786829400,
        skew_secs: 3600,
        ws_period_secs: 100_000_000,
        min_power_bps: DEFAULT_MIN_POWER_BPS,
        max_height_seen: 0,
    };

    assert_eq!(verify_finality(&bundle, &pinned, &params), Ok(120));

    // Negative: a wrong pinned pubkey (attacker key) must NOT be credited -> reject.
    let mut bad = HashMap::new();
    bad.insert(
        "epixvalcons1v84ds4v3j82ttu5t64m7kmgxcr6c67geme3ygq".to_string(),
        PinnedValidator { pubkey: [0u8; 32], voting_power: 1000000 },
    );
    let bad_pin = PinnedSet::new(bad, "epix_1916-1", 1786829400, 0);
    assert!(verify_finality(&bundle, &bad_pin, &params).is_err(), "wrong pinned key must reject");
}
