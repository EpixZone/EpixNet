//! Two-node runtime proof for RLN anonymous rate-limiting.
//!
//! Unit tests cover the crypto and the gate in isolation; this exercises the
//! NODE wiring never run as a whole: a record is built through the real send
//! seam with an RLN proof (`send_multi_with_rln`), written to a pool shard, and
//! carried to a SECOND node whose `RlnAdmission` loaded the owner-signed roster
//! from served content and gates the inbound record through
//! `apply_inbound_pool_update` -> `filter_rln_admitted` -> `PoolGate`.
//!
//! It proves the three properties that matter across the network:
//!   1. a valid member's record is admitted,
//!   2. a non-member's record is rejected, and
//!   3. a second message in one epoch (a double-signal) is dropped.

use std::path::Path;
use std::sync::Arc;

use epix_channel::ChannelDb;
use epix_envelope::{send_multi_with_rln, Dest, Engine, IdentitySecret};
use epix_pairwise_engine::PairwiseEngine;
use epix_plugins::RlnAdmission;
use epix_rln::{commitment_to_hex, message_signal, PoolGate, RlnIdentity};
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";
const RLN_LIMIT: u32 = 1;

/// A pool descriptor that requires RLN, carrying the owner-signed member roster.
fn pool_descriptor(roster: &[String]) -> serde_json::Value {
    json!({
        "address": XITE,
        "pool": { "channels": {
            "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 16,
            "pow_bits": 6, "pad_buckets": [8192, 32768], "max_record_bytes": 60000,
            "max_shard_bytes": 6_000_000, "sync_order": "newest_first",
            "rln_required": true, "rln_limit": RLN_LIMIT, "rln_roster": roster
        }}
    })
}

async fn node(data_root: &Path, xite_root: &Path, roster: &[String]) -> Arc<AppState> {
    std::fs::create_dir_all(xite_root).unwrap();
    let state = AppState::with_data_dir("test", data_root);
    state
        .add_xite(
            XITE,
            XiteEntry {
                storage: XiteStorage::new(xite_root),
                content: Some(pool_descriptor(roster)),
            },
        )
        .await;
    state
}

#[tokio::test]
async fn rln_gates_records_across_two_nodes() {
    let engine = PairwiseEngine;
    let now = 1_780_000_000_000i64;
    // The per-pool nullifier domain the node derives from the pool address; the
    // prover must match it (this is exactly what RlnAdmission does internally).
    let domain = message_signal(XITE.as_bytes());

    // Alice is an enrolled member; her commitment is in the signed roster.
    let alice_rln = RlnIdentity::from_seed(b"alice-rln-seed");
    let roster = vec![commitment_to_hex(&alice_rln.commitment())];

    // --- Alice's node: build an RLN record through the real send seam. ---
    let alice_home = tempfile::tempdir().unwrap();
    let alice_root = alice_home.path().join("data").join(XITE);
    let alice_node = node(alice_home.path(), &alice_root, &roster).await;
    let rule = alice_node.pool_rules_for(XITE).await.into_iter().next().unwrap();
    assert!(rule.rln_required, "descriptor parsed as an RLN pool");

    let alice_db = ChannelDb::memory().unwrap();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1alice", 0, None).unwrap();
    let alice_secret = IdentitySecret::new([1u8; 32]);
    let bob_bundle = engine.publish_bundle(&IdentitySecret::new([2u8; 32]), "bob.epix");
    let dests = [Dest { bundle: bob_bundle.clone() }];

    // Alice's prover: a gate built from the roster (as the node's would be).
    let alice_gate = PoolGate::from_roster(domain, RLN_LIMIT, &[alice_rln.commitment()]).unwrap();
    let prove_alice = |ct: &[u8], epoch: i64| {
        alice_gate.prove_as(&alice_rln, epoch.max(0) as u64, 0, 1, ct).map_err(|e| e.to_string())
    };

    let sent = send_multi_with_rln(
        &alice_db, &engine, alice_id, &alice_secret, "alice.epix", &[], &dests, [7u8; 16],
        "Hi", "hello there", now, &rule, true, &prove_alice,
    )
    .unwrap();
    assert!(sent.record.get("rln").is_some(), "the sent record carries an RLN proof");
    let shard = alice_node.append_pool_record(XITE, sent.record.clone()).await.unwrap();
    let bytes = std::fs::read(alice_root.join(&shard)).unwrap();

    // --- Bob's node: RlnAdmission installed, roster loaded from served content. ---
    let bob_home = tempfile::tempdir().unwrap();
    let bob_root = bob_home.path().join("data").join(XITE);
    let bob_node = node(bob_home.path(), &bob_root, &roster).await;
    let rln = RlnAdmission::new(None);
    bob_node.set_pool_admission(rln.clone()).await;
    rln.refresh(&bob_node, XITE).await;

    // (1) A valid member's record is admitted across the network.
    let landed = bob_node.apply_inbound_pool_update(XITE, &shard, &bytes).await.unwrap();
    assert!(landed, "a valid member's RLN record is admitted");
    assert!(bob_root.join(&shard).exists(), "admitted record written to Bob's disk");

    // (2) A non-member's record is rejected. Mallory is NOT in the roster, so her
    //     proof verifies against her own root, not the roster root Bob honours.
    let mallory_rln = RlnIdentity::from_seed(b"mallory-rln-seed");
    let mallory_gate =
        PoolGate::from_roster(domain, RLN_LIMIT, &[mallory_rln.commitment()]).unwrap();
    let prove_mallory = |ct: &[u8], epoch: i64| {
        mallory_gate.prove_as(&mallory_rln, epoch.max(0) as u64, 0, 1, ct).map_err(|e| e.to_string())
    };
    let mallory_home = tempfile::tempdir().unwrap();
    let mallory_root = mallory_home.path().join("data").join(XITE);
    let mallory_node = node(mallory_home.path(), &mallory_root, &roster).await;
    let m_db = ChannelDb::memory().unwrap();
    let m_id = m_db.upsert_identity("mallory.epix", "epix1mallory", 0, None).unwrap();
    let m_sent = send_multi_with_rln(
        &m_db, &engine, m_id, &IdentitySecret::new([9u8; 32]), "mallory.epix", &[], &dests,
        [8u8; 16], "Spam", "spam spam", now, &rule, true, &prove_mallory,
    )
    .unwrap();
    let m_shard = mallory_node.append_pool_record(XITE, m_sent.record.clone()).await.unwrap();
    let m_bytes = std::fs::read(mallory_root.join(&m_shard)).unwrap();
    let m_landed = bob_node.apply_inbound_pool_update(XITE, &m_shard, &m_bytes).await.unwrap();
    assert!(!m_landed, "a non-member's record is rejected by RLN admission");

    // (3) A double-signal (second message in the same epoch) is dropped. Alice
    //     sends again; her nullifier collides and Bob's gate refuses the extra.
    let sent2 = send_multi_with_rln(
        &alice_db, &engine, alice_id, &alice_secret, "alice.epix", &[], &dests, [7u8; 16],
        "Hi again", "second message same epoch", now, &rule, false, &prove_alice,
    )
    .unwrap();
    let shard2 = alice_node.append_pool_record(XITE, sent2.record.clone()).await.unwrap();
    let bytes2 = std::fs::read(alice_root.join(&shard2)).unwrap();
    // Feed Bob only the second record's shard. If it shares Alice's first shard,
    // the first record is already held (a no-op) and the second is dropped; if a
    // new shard, it is created holding nothing admissible. Either way: nothing new.
    let d_landed = bob_node.apply_inbound_pool_update(XITE, &shard2, &bytes2).await.unwrap();
    if shard2 == shard {
        assert!(!d_landed, "the double-signal record is not admitted");
    } else {
        assert!(!d_landed, "the double-signal record is dropped, not landed");
    }
}

/// The sender rail: an honest client spends its allowance and is then REFUSED,
/// so it never reuses a unit and can never slash itself. Only a modified client
/// that bypasses this (like `prove_alice` above, which reuses unit 0) can
/// double-signal — and the admission side catches that.
#[tokio::test]
async fn sender_rail_refuses_past_the_allowance() {
    let alice_rln = RlnIdentity::from_seed(b"alice-rln-seed");
    let roster = vec![commitment_to_hex(&alice_rln.commitment())];
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("data").join(XITE);
    let n = node(home.path(), &root, &roster).await;
    let rln = RlnAdmission::new(None);
    rln.refresh(&n, XITE).await;

    let epoch = 500i64;
    let ct = vec![0u8; 8192]; // one smallest-bucket unit

    // First send in the epoch succeeds (spends the 1-unit allowance).
    assert!(rln.prove_for(XITE, &alice_rln, epoch, &ct).is_ok(), "first send is within allowance");
    // Second send in the SAME epoch is refused by the rail (allowance = 1 unit),
    // so the client never produces a unit-reusing proof.
    let second = rln.prove_for(XITE, &alice_rln, epoch, &ct);
    assert!(second.is_err(), "the rail refuses a second unit, preventing any self-slash");
    assert!(second.unwrap_err().contains("allowance"), "the refusal explains the limit");
    // The next epoch has a fresh allowance.
    assert!(rln.prove_for(XITE, &alice_rln, epoch + 1, &ct).is_ok(), "a new epoch resets the rail");
}
