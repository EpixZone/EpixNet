//! Live test of the ZERO-CONFIG cold boot: no pin file, no persisted state,
//! nothing shipped — the light client must establish trust purely from
//! network-quorum agreement among independent RPC operators, install the pin,
//! configure the checkpoint, and then advance normally.
//!
//! This is the "install and it just works / off for a year and it just works"
//! path. Ignored by default (network). Run with:
//!   cargo test -p epix-chain --test lc_bootstrap_live -- --ignored --nocapture

#[tokio::test]
#[ignore = "network: hits live independent CometBFT RPCs; mutates process-global finality state"]
async fn cold_boot_with_nothing_bootstraps_from_network_quorum() {
    // Absolutely nothing installed: verification on, no pin => fails closed.
    epix_chain::set_pinned_validators(None);
    epix_chain::set_verify_finality(true);
    assert!(epix_chain::pinned_validators().is_none());

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = epix_chain::LightClientConfig::new(dir.path().join("xid_lc_state.json"));
    cfg.checkpoint_path = Some(dir.path().join("xid_finality_checkpoint.json"));

    let advance = epix_chain::advance_trusted_set(&cfg)
        .await
        .expect("network-quorum bootstrap");
    println!("cold boot advance: {advance:?}");
    let epix_chain::Advance::Advanced { height, validators } = advance else {
        panic!("expected Advanced from a cold boot, got {advance:?}");
    };
    assert!(validators >= 1);

    // Trust is now established and durable: pin active, checkpoint configured.
    let pin = epix_chain::pinned_validators().expect("pin installed by bootstrap");
    assert_eq!(pin.pinned_at_height, height);
    assert_eq!(pin.chain_id, epix_chain::DEFAULT_CHAIN_ID);
    assert!(pin.total_power > 0);
    assert!(cfg.checkpoint_path.as_ref().unwrap().exists());
    assert!(cfg.state_path.exists());

    // Second cycle resumes from the persisted state like any warm node.
    let again = epix_chain::advance_trusted_set(&cfg).await.expect("re-advance");
    println!("second advance: {again:?}");
    match again {
        epix_chain::Advance::Advanced { height: h2, .. } => assert!(h2 >= height),
        epix_chain::Advance::UpToDate { height: h2 } => assert!(h2 >= height),
        other => panic!("unexpected: {other:?}"),
    }
}
