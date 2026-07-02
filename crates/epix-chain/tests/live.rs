//! Live resolution against the Epix chain (network-dependent, so `#[ignore]`d).
//! `cargo test -p epix-chain -- --ignored --nocapture`

use epix_chain::{derive_random, ChainAttestation, ChainError, Vrf, XidResolver};

#[tokio::test]
#[ignore]
async fn resolves_a_real_name_chain_verified() {
    let resolver = XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let domain = resolver.resolve("quasin", "epix").await.expect("resolve");
    println!("{} -> owner {}", domain.fqdn(), domain.owner);
    for id in &domain.identities {
        println!("  identity {} (label={:?}, active={})", id.address, id.label, id.active);
    }
    assert_eq!(domain.name, "quasin");
    assert!(domain.owner.starts_with("epix1"));
    assert!(domain.active_identity().is_some());
    // Second call hits the cache.
    let again = resolver.resolve("quasin", "epix").await.unwrap();
    assert_eq!(domain, again);
}

#[tokio::test]
#[ignore]
async fn unknown_name_is_not_found() {
    let resolver = XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let res = resolver
        .resolve("this-name-should-not-exist-xyz123", "epix")
        .await;
    assert!(matches!(res, Err(epix_chain::ChainError::NotFound(_))));
}

#[tokio::test]
#[ignore]
async fn chain_attestation_matches_finalized_state() {
    let att = ChainAttestation::new(epix_chain::DEFAULT_RPC_URL);

    // The chain's current state, finalized by validators.
    let state = att.state_digest().await.expect("state digest");
    println!("digest {} @ height {} ({} names)", state.digest, state.height, state.num_names);
    assert_eq!(state.digest.len(), 64, "digest is a 32-byte hex string");
    assert!(state.height > 0);
    assert!(att.is_finalized(&state.digest).await.expect("finality"));

    // Content carrying the real digest verifies; a bogus digest is rejected as
    // a mismatch - same accept/reject decision as the Python plugin.
    att.verify_digest(&state.digest).await.expect("real digest verifies");
    let bogus = "0".repeat(64);
    assert!(matches!(
        att.verify_digest(&bogus).await,
        Err(ChainError::DigestMismatch)
    ));

    // A name resolves through attested-state trust.
    let record = att.resolve_name("epix", "talk").await.expect("resolve talk");
    let owner = record
        .as_ref()
        .and_then(|r| r.get("owner"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    println!("talk.epix -> owner {owner}");
    assert!(owner.starts_with("epix1"));
}

#[tokio::test]
#[ignore]
async fn vrf_beacon_and_derivation() {
    let vrf = Vrf::new(epix_chain::DEFAULT_RPC_URL);

    // The latest usable beacon, and the same height fetched directly, agree.
    let latest = vrf.latest_beacon().await.expect("latest beacon");
    println!("beacon @ {} = {} (proposer {})", latest.height, latest.beacon, latest.proposer);
    assert!(!latest.beacon.is_empty());
    let same = vrf.beacon(latest.height).await.expect("beacon by height");
    assert_eq!(latest.beacon, same.beacon);

    // Derivation is deterministic and publicly reproducible from the beacon.
    let a = derive_random(&latest.beacon, "raffle", 5);
    let b = derive_random(&latest.beacon, "raffle", 5);
    assert_eq!(a, b, "same beacon+seed -> same values");
    assert_eq!(a.len(), 5);
    assert!(a.iter().all(|v| v.len() == 64));
    assert_ne!(a[0], derive_random(&latest.beacon, "different-seed", 1)[0]);

    // A multi-block beacon over a small range combines proposer entropy.
    let combined = vrf
        .multi_block_beacon(latest.height, 3)
        .await
        .expect("multi-block beacon");
    assert_eq!(combined.len(), 64);
    println!("3-block combined beacon = {combined}");
}
