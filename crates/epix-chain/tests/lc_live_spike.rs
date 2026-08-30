//! De-risking spike (Risk #1 of the light-client plan): confirm tendermint-rs's
//! `ProdVerifier` reproduces THIS chain's block-proto-11 header hashing and
//! canonical-vote verification against real data from the live CometBFT RPC.
//!
//! Ignored by default (needs network). Run with:
//!   EPIX_CMT_RPC=https://rpc.epix.zone cargo test -p epix-chain --test lc_live_spike -- --ignored --nocapture
//!
//! If this passes, the audited verifier is sound for Epix and the full module
//! can be built on it. If it fails, the header format / version assumption is
//! wrong and must be fixed before anything else.

use std::time::Duration;

use tendermint::block::signed_header::SignedHeader;
use tendermint::validator::{Info, Set as ValidatorSet};
use tendermint_light_client_verifier::options::Options;
use tendermint_light_client_verifier::types::{TrustedBlockState, UntrustedBlockState};
use tendermint_light_client_verifier::{ProdVerifier, Verdict, Verifier};

fn rpc_base() -> String {
    std::env::var("EPIX_CMT_RPC")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "https://rpc.epix.zone".to_string())
}

async fn get_json(client: &reqwest::Client, url: &str) -> serde_json::Value {
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .expect("rpc send");
    resp.json().await.expect("rpc json")
}

async fn signed_header(client: &reqwest::Client, base: &str, height: u64) -> SignedHeader {
    let v = get_json(client, &format!("{base}/commit?height={height}")).await;
    let sh = v["result"]["signed_header"].clone();
    serde_json::from_value(sh).expect("deserialize SignedHeader")
}

async fn validator_set(client: &reqwest::Client, base: &str, height: u64) -> ValidatorSet {
    // Page through /validators (per_page max 100; this chain has ~19).
    let v = get_json(
        client,
        &format!("{base}/validators?height={height}&per_page=100"),
    )
    .await;
    let arr = v["result"]["validators"]
        .as_array()
        .expect("validators array")
        .clone();
    let infos: Vec<Info> = arr
        .into_iter()
        .map(|e| serde_json::from_value(e).expect("deserialize validator Info"))
        .collect();
    // Proposer is unknown from /validators alone; the verifier does not need a
    // correct proposer to check the commit, only the set + powers.
    ValidatorSet::without_proposer(infos)
}

async fn latest_height(client: &reqwest::Client, base: &str) -> u64 {
    let v = get_json(client, &format!("{base}/status")).await;
    v["result"]["sync_info"]["latest_block_height"]
        .as_str()
        .expect("latest height")
        .parse()
        .expect("height parse")
}

#[tokio::test]
#[ignore = "network: hits the live CometBFT RPC"]
async fn tendermint_rs_verifies_live_epix_headers() {
    let base = rpc_base();
    let client = reqwest::Client::new();

    let head = latest_height(&client, &base).await;
    // Stay a few blocks back so the set at target+1 exists.
    let target = head - 3;
    let trusted_h = target - 5; // a small skip gap

    let trusted_sh = signed_header(&client, &base, trusted_h).await;
    let trusted_next_vals = validator_set(&client, &base, trusted_h + 1).await;

    let untrusted_sh = signed_header(&client, &base, target).await;
    let untrusted_vals = validator_set(&client, &base, target).await;
    let untrusted_next_vals = validator_set(&client, &base, target + 1).await;

    let chain_id = untrusted_sh.header.chain_id.clone();
    println!(
        "chain_id={} trusted_h={} target={} vals={} next_vals={}",
        chain_id,
        trusted_h,
        target,
        untrusted_vals.validators().len(),
        untrusted_next_vals.validators().len()
    );

    // Sanity: the fetched set at `target` must hash to the header's validators_hash.
    assert_eq!(
        untrusted_vals.hash(),
        untrusted_sh.header.validators_hash,
        "fetched validator set does not match signed header validators_hash \
         (header hashing/version mismatch)"
    );
    assert_eq!(
        trusted_next_vals.hash(),
        trusted_sh.header.next_validators_hash,
        "trusted next-set hash mismatch"
    );

    let trusted = TrustedBlockState {
        chain_id: &chain_id,
        header_time: trusted_sh.header.time,
        height: trusted_sh.header.height,
        next_validators: &trusted_next_vals,
        next_validators_hash: trusted_sh.header.next_validators_hash,
    };
    let untrusted = UntrustedBlockState {
        signed_header: &untrusted_sh,
        validators: &untrusted_vals,
        next_validators: Some(&untrusted_next_vals),
    };

    let opts = Options {
        trust_threshold: Default::default(), // 1/3 skipping threshold
        trusting_period: Duration::from_secs(14 * 24 * 3600),
        clock_drift: Duration::from_secs(30),
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let now = tendermint::Time::from_unix_timestamp(secs, 0).unwrap();

    let verifier = ProdVerifier::default();
    let verdict = verifier.verify_update_header(untrusted, trusted, &opts, now);

    println!("verdict = {verdict:?}");
    assert_eq!(
        verdict,
        Verdict::Success,
        "tendermint-rs rejected a real Epix header"
    );
}

/// End-to-end live exercise of the whole light-client path with the PUBLIC
/// API: build a bootstrap pin from a recent height (trust-splice anchor),
/// install it + configure the checkpoint, then advance the trusted set to
/// (near) head and assert the active pin rotated forward monotonically.
#[tokio::test]
#[ignore = "network: hits the live CometBFT RPC and mutates process-global finality state"]
async fn light_client_advances_live_pin_end_to_end() {
    let base = rpc_base();
    let client = reqwest::Client::new();

    // Anchor a little behind head so there is a real gap to advance across.
    let head = latest_height(&client, &base).await;
    let anchor = head - 30;
    let sh = signed_header(&client, &base, anchor).await;
    let vals_json = get_json(
        &client,
        &format!("{base}/validators?height={anchor}&per_page=100"),
    )
    .await;

    // Build the pin JSON exactly as the capture procedure would.
    let hrp = bech32::Hrp::parse("epixvalcons").unwrap();
    let validators: Vec<serde_json::Value> = vals_json["result"]["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let addr = hex::decode(v["address"].as_str().unwrap()).unwrap();
            let valcons = bech32::encode::<bech32::Bech32>(hrp, &addr).unwrap();
            let pk_b64 = v["pub_key"]["value"].as_str().unwrap();
            use base64::Engine as _;
            let pk = base64::engine::general_purpose::STANDARD
                .decode(pk_b64)
                .unwrap();
            serde_json::json!({
                "valcons": valcons,
                "pubkey": hex::encode(pk),
                "voting_power": v["voting_power"].as_str().unwrap().parse::<u64>().unwrap(),
            })
        })
        .collect();
    let pin = serde_json::json!({
        "chain_id": sh.header.chain_id.as_str(),
        "pinned_at_height": anchor,
        "pinned_at_unix": sh.header.time.unix_timestamp(),
        "validators": validators,
    });

    let n = epix_chain::install_finality_pin(pin.to_string().as_bytes()).expect("install pin");
    println!("installed bootstrap pin: {n} validators at height {anchor}");

    let dir = tempfile::tempdir().unwrap();
    epix_chain::configure_finality_checkpoint(dir.path().join("xid_finality_checkpoint.json"))
        .expect("configure checkpoint");

    let cfg = epix_chain::LightClientConfig {
        rpc_url: base.clone(),
        state_path: dir.path().join("xid_lc_state.json"),
        trusting_period_secs: epix_chain::DEFAULT_TRUSTING_PERIOD_SECS,
        clock_drift_secs: 30,
    };

    // First advance: bootstraps from the pin (trust splice), then verifies to head.
    let advance = epix_chain::advance_trusted_set(&cfg)
        .await
        .expect("advance");
    println!("first advance: {advance:?}");
    let epix_chain::Advance::Advanced { height, validators } = advance else {
        panic!("expected Advanced, got {advance:?}");
    };
    assert!(height > anchor, "pin height must move forward");
    assert!(validators >= 1);

    let active = epix_chain::pinned_validators().expect("active pin");
    assert_eq!(active.pinned_at_height, height, "active pin follows the LC");
    assert!(active.total_power > 0);

    // Second advance: resumes from the persisted state (no bootstrap) and is
    // either up-to-date or advances a little further; never backward.
    let again = epix_chain::advance_trusted_set(&cfg)
        .await
        .expect("re-advance");
    println!("second advance: {again:?}");
    match again {
        epix_chain::Advance::Advanced { height: h2, .. } => assert!(h2 >= height),
        epix_chain::Advance::UpToDate { height: h2 } => assert!(h2 >= height),
        other => panic!("unexpected: {other:?}"),
    }
}
