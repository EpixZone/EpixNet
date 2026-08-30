//! Live node-wiring proof for the anonymous channel pool.
//!
//! Unit tests already cover the crypto (`epix-pairwise-engine`), the private
//! store (`epix-channel`), and the trial-decrypt indexer (`epix-envelope`) in
//! isolation. This test exercises the NODE glue that ties them together on a
//! real filesystem xite — the one layer never run as a whole before:
//!
//! - the node reads the `pool` descriptor from served content
//!   (`pool_rules_for` / `is_pool_shard`),
//! - `append_pool_record` seals → writes a real shard file to xite storage and
//!   broadcasts on the pool-delta bus (the signal the plugin's indexer consumes),
//! - the on-disk shard leaks NO metadata (the headline privacy claim),
//! - a second identity trial-decrypts the broadcast record end-to-end, and
//! - a *different* node receives the shard over the inbound path
//!   (`apply_inbound_pool_update`) idempotently.

use std::path::Path;
use std::sync::Arc;

use epix_channel::ChannelDb;
use epix_envelope::{process_record_one, send_message, Engine, IdentitySecret, ProcessOutcome};
use epix_pairwise_engine::PairwiseEngine;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

/// The live channel site's address (used only as the served-xite key here).
const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";

fn pool_descriptor() -> serde_json::Value {
    json!({
        "address": XITE,
        "pool": { "channels": {
            "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 16,
            "pow_bits": 6, "pad_buckets": [8192, 32768], "max_record_bytes": 60000,
            "max_shard_bytes": 6_000_000, "sync_order": "newest_first"
        }}
    })
}

/// A node with a data root, serving the channel xite from `xite_root` with a
/// content.json that declares the pool.
async fn node(data_root: &Path, xite_root: &Path) -> Arc<AppState> {
    std::fs::create_dir_all(xite_root).unwrap();
    let state = AppState::with_data_dir("test", data_root);
    state
        .add_xite(
            XITE,
            XiteEntry { storage: XiteStorage::new(xite_root), content: Some(pool_descriptor()) },
        )
        .await;
    state
}

fn seed(b: u8) -> IdentitySecret {
    IdentitySecret::new([b; 32])
}

#[tokio::test]
async fn channel_message_flows_through_the_pool_leaking_no_metadata() {
    let engine = PairwiseEngine;
    let now = 1_780_000_000_000i64;

    // --- Alice's node serves the channel xite; its content declares a pool. ---
    let alice_home = tempfile::tempdir().unwrap();
    let alice_root = alice_home.path().join("data").join(XITE);
    let alice_node = node(alice_home.path(), &alice_root).await;

    // The node parses the pool descriptor from served content (node glue).
    let rules = alice_node.pool_rules_for(XITE).await;
    assert_eq!(rules.len(), 1, "pool descriptor parsed from served content");
    assert!(alice_node.is_pool_shard(XITE, "pool/w2943/03.json").await, "shard path is in-pool");
    assert!(
        !alice_node.is_pool_shard(XITE, "data/users/x/data.json").await,
        "non-pool path is not in-pool"
    );
    let rule = rules.into_iter().next().unwrap();

    // --- Two identities + their private indexes. ---
    let alice = seed(1);
    let bob = seed(2);
    let alice_db = ChannelDb::memory().unwrap();
    let bob_db = ChannelDb::memory().unwrap();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1alice", 0, None).unwrap();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();
    let bob_bundle = engine.publish_bundle(&bob, "bob.epix");

    // Subscribe to the delta bus BEFORE sending — exactly what the plugin does.
    let mut deltas = alice_node.subscribe_pool_deltas();

    // --- Alice seals; the node appends the record to the pool. ---
    let conv = [7u8; 16];
    let sent = send_message(
        &alice_db, &engine, alice_id, &alice, "alice.epix", &[], &bob_bundle, conv, "Dinner?",
        "pizza at eight ZXQ1", now, &rule, true,
    )
    .unwrap();
    let shard = alice_node.append_pool_record(XITE, sent.record.clone()).await.unwrap();

    // --- The shard is a real file on disk, and it leaks no metadata. ---
    // The only large field is the opaque `ct` (encrypted body + per-slot key seals
    // + random pad); `tag`/`sign`/`author` are opaque too. A short marker can occur
    // by chance inside those random bytes — that is NOT a leak — so grepping the raw
    // base64 blob is non-deterministic. Check the two real leak vectors precisely.
    let bytes = std::fs::read(alice_root.join(&shard)).expect("shard written to disk");
    let container: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("epix-pool-1"), "shard is a pool container");
    let b64 = |s: &str| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    };
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    // (1) No plaintext CONTENT survives inside the ciphertext: decode each record's
    //     `ct` and confirm the whole body/subject bytes never appear contiguously.
    for rec in container["env"].as_array().unwrap() {
        let ct = b64(rec["ct"].as_str().unwrap());
        for secret in ["pizza at eight ZXQ1", "Dinner?"] {
            assert!(!contains(&ct, secret.as_bytes()), "ct must not expose plaintext {secret:?}");
        }
    }
    // (2) No identity/name metadata in cleartext: blank the opaque fields and grep
    //     the human-readable remainder for any name or content marker.
    let mut redacted = container.clone();
    for rec in redacted["env"].as_array_mut().unwrap() {
        for k in ["ct", "tag", "sign", "author"] {
            rec[k] = serde_json::Value::Null;
        }
    }
    let human = redacted.to_string();
    for forbidden in ["ZXQ1", "Dinner", "pizza", ".epix", "alice", "bob"] {
        assert!(!human.contains(forbidden), "cleartext structure must not contain {forbidden:?}");
    }

    // --- The append broadcast a delta (append → bus wiring). ---
    let delta = deltas.recv().await.expect("delta broadcast on append");
    assert_eq!(delta.address, XITE);
    assert_eq!(delta.records.len(), 1);

    // --- Bob (a second identity) trial-decrypts the delta record end-to-end. ---
    // The anti-spoof check resolves the sender's (Alice's) published bundle.
    let alice_bundle = engine.publish_bundle(&alice, "alice.epix");
    let resolve = |xid: &str| -> Vec<serde_json::Value> {
        if xid == "alice.epix" { vec![alice_bundle.clone()] } else { Vec::new() }
    };
    let out = process_record_one(
        &bob_db,
        &engine,
        &[(bob_id, bob.clone(), "bob.epix".into())],
        &delta.records[0],
        now + 10,
        resolve,
    )
    .unwrap();
    match out {
        ProcessOutcome::Indexed { subject, sender_xid, conv_id, .. } => {
            assert_eq!(subject, "Dinner?");
            assert_eq!(sender_xid.as_deref(), Some("alice.epix"));
            let msgs = bob_db.messages(bob_id, &conv_id).unwrap();
            assert_eq!(msgs[0]["body"].as_str(), Some("pizza at eight ZXQ1"));
        }
        other => panic!("expected Bob to index the message, got {other:?}"),
    }

    // --- A DIFFERENT node receives the shard over the inbound path. ---
    let bob_home = tempfile::tempdir().unwrap();
    let bob_root = bob_home.path().join("data").join(XITE);
    let bob_node = node(bob_home.path(), &bob_root).await;
    let mut bob_deltas = bob_node.subscribe_pool_deltas();

    let landed = bob_node.apply_inbound_pool_update(XITE, &shard, &bytes).await.unwrap();
    assert!(landed, "inbound shard brings a new record");
    assert!(bob_root.join(&shard).exists(), "inbound shard written to Bob's node disk");
    let bdelta = bob_deltas.recv().await.expect("inbound append broadcasts a delta");
    assert_eq!(bdelta.records.len(), 1);

    // Re-applying the same shard is a grow-only no-op (idempotent anti-entropy).
    let again = bob_node.apply_inbound_pool_update(XITE, &shard, &bytes).await.unwrap();
    assert!(!again, "re-applying an already-held shard changes nothing");
}
