//! Devnet integration: channel fan-out honors on-chain linked-identity revocation.
//!
//! This exercises the two decisions the channel send/reply path makes when it
//! picks which of a name's devices a message reaches:
//!
//!   * the Merkle-proof- and finality-verified ACTIVE linked-identity set for a
//!     name — the same `XidResolver::resolve` + `active && revoked_at == 0`
//!     filter that production `epix_chain::xid_signers::resolve` (and hence
//!     `AppState::xid_active_addrs`) applies; and
//!   * `epix_plugins::channel::refine_device_bundles(devs, active)` — the
//!     per-device filter that drops any published bundle whose `auth` address is
//!     not in the active set. `load_published_bundles` runs this fresh for EVERY
//!     `channelSend`, including replies in an existing thread, so a device
//!     revoked on-chain since the last message is excluded from the reply.
//!
//! Production always resolves against `DEFAULT_RPC_URL`; this test just points
//! its OWN resolver instance at a devnet's REST base (read from the
//! `EPIX_XID_RPC_URL` env var as a test input — the library never reads it).
//!
//! Ignored by default (needs a running devnet + a registered `mud.epix`). Driven
//! in two phases — once with both devices linked (message → both), then again
//! after one device is unlinked on-chain (reply → survivor only):
//!
//!   EPIX_XID_RPC_URL=http://127.0.0.1:1317 \
//!   DEVICE_A=epix1... DEVICE_B=epix1... EXPECT_DEVICES=epix1...,epix1... \
//!   cargo test -p epix-plugins --test devnet_channel_revocation -- --ignored --nocapture

use serde_json::{json, Value};

/// A published channel key bundle for one device, shaped like the real thing:
/// `auth` is the linked-identity (device) address stamped at publish time, `ik`
/// the identity key the dedup keys on.
fn device_bundle(auth: &str, ik: &str) -> Value {
    json!({ "auth": auth, "ik": ik, "spk_idx": 1u64, "spk": "SPK", "fck": "FCK" })
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("set {k}"))
}

#[tokio::test]
#[ignore = "requires a running devnet + EPIX_XID_RPC_URL + registered mud.epix"]
async fn reply_excludes_revoked_linked_identity() {
    let rpc = env("EPIX_XID_RPC_URL"); // devnet REST base, e.g. http://127.0.0.1:1317
    let device_a = env("DEVICE_A");
    let device_b = env("DEVICE_B");
    let expect: Vec<String> = env("EXPECT_DEVICES")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // (1) REAL active-set resolution against the devnet. `resolve` fetches
    // /xid/v1/resolve_with_proof, binds the returned leaf to the proof, verifies
    // the Merkle inclusion path to the state digest, and checks the digest is
    // finalized. We then keep only `active && revoked_at == 0` identities — the
    // exact filter production `xid_signers::resolve` applies.
    let resolver = epix_chain::XidResolver::new(&rpc);
    let domain = resolver
        .resolve("mud", "epix")
        .await
        .expect("resolve mud.epix — is the devnet up, mud.epix registered, and the digest finalized?");
    let active: Vec<String> = domain
        .identities
        .iter()
        .filter(|i| i.active && i.revoked_at == 0)
        .map(|i| i.address.clone())
        .collect();
    eprintln!("[devnet] active linked identities for mud.epix: {active:?}");
    assert!(!active.is_empty(), "no active identities resolved");

    // (2) Both devices have published channel key bundles (phone + laptop).
    let published = vec![
        device_bundle(&device_a, "IK_PHONE"),
        device_bundle(&device_b, "IK_LAPTOP"),
    ];

    // (3) REAL fan-out filter — exactly what runs before sealing a message/reply.
    let fanned = epix_plugins::channel::refine_device_bundles(published, &active);
    let mut recipients: Vec<String> = fanned
        .iter()
        .map(|b| b["auth"].as_str().unwrap().to_string())
        .collect();
    recipients.sort();
    eprintln!("[devnet] message/reply fan-out devices: {recipients:?}");

    // The fan-out must equal the chain-attested active set (the filter drops
    // exactly the revoked devices), and match this phase's expectation.
    let mut active_sorted = active.clone();
    active_sorted.sort();
    assert_eq!(
        recipients, active_sorted,
        "fan-out must equal the on-chain active linked-identity set"
    );
    let mut want = expect.clone();
    want.sort();
    assert_eq!(
        recipients, want,
        "fan-out devices did not match EXPECT_DEVICES for this phase"
    );

    // Explicit phase-2 guarantee: once device-b is revoked, it is absent.
    if !expect.iter().any(|a| a == &device_b) {
        assert!(
            !recipients.contains(&device_b),
            "revoked device {device_b} must NOT be in the reply fan-out"
        );
        eprintln!("[devnet] confirmed: revoked device {device_b} excluded from the reply");
    }
}
