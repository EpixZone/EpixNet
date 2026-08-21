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

use base64::Engine as _;
use epix_channel::ChannelDb;
use epix_content::pool as content_pool;
use epix_envelope::{send_multi_with_rln, Dest, Engine, IdentitySecret};
use epix_pairwise_engine::PairwiseEngine;
use epix_plugins::RlnAdmission;
use epix_rln::{commitment_to_hex, message_signal, PoolGate, RlnIdentity};
use epix_ui::pool::pool_record_id;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};

const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";
const RLN_LIMIT: u32 = 1;

/// A pool descriptor that requires RLN, carrying the owner-signed member roster.
fn pool_descriptor(roster: &[String]) -> serde_json::Value {
    pool_descriptor_with_limit(roster, RLN_LIMIT)
}

fn pool_descriptor_with_limit(roster: &[String], limit: u32) -> serde_json::Value {
    json!({
        "address": XITE,
        "pool": { "channels": {
            "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 16,
            "pow_bits": 6, "pad_buckets": [8192, 32768], "max_record_bytes": 60000,
            "max_shard_bytes": 6_000_000, "sync_order": "newest_first",
            "rln_required": true, "rln_limit": limit, "rln_roster": roster
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

fn conflicting_records(
    rule: &content_pool::PoolRule,
    identity: &RlnIdentity,
    now: i64,
) -> (Value, Value, Value) {
    let engine = PairwiseEngine;
    let db = ChannelDb::memory().unwrap();
    let sender = db
        .upsert_identity("alice.epix", "epix1alice", 0, None)
        .unwrap();
    let secret = IdentitySecret::new([1u8; 32]);
    let recipient = engine.publish_bundle(&IdentitySecret::new([2u8; 32]), "bob.epix");
    let dests = [Dest { bundle: recipient }];
    let gate = PoolGate::from_roster(
        message_signal(XITE.as_bytes()),
        RLN_LIMIT,
        &[identity.commitment()],
    )
    .unwrap();
    let prove = |ct: &[u8], epoch: i64| {
        gate.prove_as(identity, epoch.max(0) as u64, 0, 1, ct)
            .map_err(|e| e.to_string())
    };
    let first = send_multi_with_rln(
        &db,
        &engine,
        sender,
        &secret,
        "alice.epix",
        &[],
        &dests,
        [3u8; 16],
        "one",
        "first conflicting payload",
        now,
        rule,
        true,
        &prove,
    )
    .unwrap()
    .record;
    let second = send_multi_with_rln(
        &db,
        &engine,
        sender,
        &secret,
        "alice.epix",
        &[],
        &dests,
        [3u8; 16],
        "two",
        "second conflicting payload",
        now,
        rule,
        false,
        &prove,
    )
    .unwrap()
    .record;
    let third = send_multi_with_rln(
        &db,
        &engine,
        sender,
        &secret,
        "alice.epix",
        &[],
        &dests,
        [3u8; 16],
        "three",
        "third conflicting payload",
        now,
        rule,
        false,
        &prove,
    )
    .unwrap()
    .record;
    (first, second, third)
}

fn single_record_at(
    rule: &content_pool::PoolRule,
    identity: &RlnIdentity,
    sent_ms: i64,
    nonce: u8,
) -> Value {
    let engine = PairwiseEngine;
    let db = ChannelDb::memory().unwrap();
    let sender = db
        .upsert_identity("alice.epix", "epix1alice", 0, None)
        .unwrap();
    let secret = IdentitySecret::new([1u8; 32]);
    let recipient = engine.publish_bundle(&IdentitySecret::new([2u8; 32]), "bob.epix");
    let dests = [Dest { bundle: recipient }];
    let gate = PoolGate::from_roster(
        message_signal(XITE.as_bytes()),
        RLN_LIMIT,
        &[identity.commitment()],
    )
    .unwrap();
    let prove = |ct: &[u8], epoch: i64| {
        gate.prove_as(identity, epoch.max(0) as u64, 0, 1, ct)
            .map_err(|e| e.to_string())
    };
    send_multi_with_rln(
        &db,
        &engine,
        sender,
        &secret,
        "alice.epix",
        &[],
        &dests,
        [nonce; 16],
        "boundary",
        "epoch boundary payload",
        sent_ms,
        rule,
        true,
        &prove,
    )
    .unwrap()
    .record
}

fn persisted_admission(data_root: &Path) -> Arc<RlnAdmission> {
    RlnAdmission::new(Some(data_root.join("private").join("rln_usage.json")))
}

fn wire_record(rule: &content_pool::PoolRule, record: &Value) -> (String, Vec<u8>) {
    let tag = base64::engine::general_purpose::STANDARD
        .decode(record.get("tag").and_then(Value::as_str).unwrap())
        .unwrap();
    let epoch = record.get("epoch").and_then(Value::as_i64).unwrap();
    let path = content_pool::shard_path(rule, epoch, &tag);
    let bytes =
        serde_json::to_vec(&content_pool::make_pool_container(vec![record.clone()])).unwrap();
    (path, bytes)
}

fn rewrap_same_proof(rule: &content_pool::PoolRule, source: &Value, tag_fill: u8) -> Value {
    let private_key = epix_crypt::new_seed();
    let author = epix_crypt::privatekey_to_address(&private_key).unwrap();
    let mut record = source.clone();
    record["tag"] = json!(base64::engine::general_purpose::STANDARD.encode(vec![tag_fill; 32]));
    record["author"] = json!(author);
    record["pow"] = json!(0);
    record.as_object_mut().unwrap().remove("sign");
    content_pool::solve_pow(&mut record, rule.pow_bits);
    record["sign"] =
        json!(epix_crypt::sign(&epix_content::record_signed_data(&record), &private_key).unwrap());
    record
}

fn signed_rln_record(
    rule: &content_pool::PoolRule,
    epoch: i64,
    tag_fill: u8,
    ct: &[u8],
    proof: &[u8],
) -> Value {
    let private_key = epix_crypt::new_seed();
    let author = epix_crypt::privatekey_to_address(&private_key).unwrap();
    let mut record = json!({
        "v": 1,
        "epoch": epoch,
        "tag": base64::engine::general_purpose::STANDARD.encode(vec![tag_fill; 32]),
        "ct": base64::engine::general_purpose::STANDARD.encode(ct),
        "pow": 0,
        "author": author,
        "rln": base64::engine::general_purpose::STANDARD.encode(proof),
    });
    content_pool::solve_pow(&mut record, rule.pow_bits);
    record["sign"] =
        json!(epix_crypt::sign(&epix_content::record_signed_data(&record), &private_key).unwrap());
    record
}

#[tokio::test]
async fn rln_gates_records_across_two_nodes() {
    let engine = PairwiseEngine;
    let now = epix_core::time::now_ms();
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
    assert!(
        sent.record.get("rln").is_some(),
        "the sent record carries an RLN proof"
    );
    let (shard, bytes) = wire_record(&rule, &sent.record);

    // --- Bob's node: RlnAdmission installed, roster loaded from served content. ---
    let bob_home = tempfile::tempdir().unwrap();
    let bob_root = bob_home.path().join("data").join(XITE);
    let bob_node = node(bob_home.path(), &bob_root, &roster).await;
    let rln = persisted_admission(bob_home.path());
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
    let m_db = ChannelDb::memory().unwrap();
    let m_id = m_db.upsert_identity("mallory.epix", "epix1mallory", 0, None).unwrap();
    let m_sent = send_multi_with_rln(
        &m_db, &engine, m_id, &IdentitySecret::new([9u8; 32]), "mallory.epix", &[], &dests,
        [8u8; 16], "Spam", "spam spam", now, &rule, true, &prove_mallory,
    )
    .unwrap();
    let (m_shard, m_bytes) = wire_record(&rule, &m_sent.record);
    let m_rejected = bob_node
        .apply_inbound_pool_update(XITE, &m_shard, &m_bytes)
        .await;
    assert!(
        m_rejected.is_err(),
        "a non-member's record is rejected by RLN admission"
    );

    // (3) A double-signal quarantines the complete conflicting component.
    let sent2 = send_multi_with_rln(
        &alice_db, &engine, alice_id, &alice_secret, "alice.epix", &[], &dests, [7u8; 16],
        "Hi again", "second message same epoch", now, &rule, false, &prove_alice,
    )
    .unwrap();
    let (shard2, bytes2) = wire_record(&rule, &sent2.record);
    let d_rejected = bob_node
        .apply_inbound_pool_update(XITE, &shard2, &bytes2)
        .await;
    assert!(d_rejected.is_err(), "the offender record is never landed");
    let retained: Vec<_> = bob_node
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(
        retained.is_empty(),
        "all conflicting records were quarantined"
    );
    }

#[tokio::test(flavor = "multi_thread")]
async fn opposite_first_partitions_and_restart_converge_on_persisted_record() {
    let alice = RlnIdentity::from_seed(b"alice-convergence-seed");
    let roster = vec![commitment_to_hex(&alice.commitment())];
    let now = epix_core::time::now_ms();

    let a_home = tempfile::tempdir().unwrap();
    let a_root = a_home.path().join("data").join(XITE);
    let a = node(a_home.path(), &a_root, &roster).await;
    let b_home = tempfile::tempdir().unwrap();
    let b_root = b_home.path().join("data").join(XITE);
    let b = node(b_home.path(), &b_root, &roster).await;
    let rule = a.pool_rules_for(XITE).await.into_iter().next().unwrap();
    let (first, second, third) = conflicting_records(&rule, &alice, now);
    let first_id = pool_record_id(&first).unwrap();
    let second_id = pool_record_id(&second).unwrap();
    let (first_path, first_wire) = wire_record(&rule, &first);
    let (second_path, second_wire) = wire_record(&rule, &second);

    let a_rln = persisted_admission(a_home.path());
    a.set_pool_admission(a_rln.clone()).await;
    a_rln.refresh(&a, XITE).await;
    let b_rln = persisted_admission(b_home.path());
    b.set_pool_admission(b_rln.clone()).await;
    b_rln.refresh(&b, XITE).await;

    assert_eq!(
        a.append_pool_record(XITE, first.clone()).await.unwrap(),
        first_path
    );
    assert!(b
        .apply_inbound_pool_update(XITE, &second_path, &second_wire)
        .await
        .unwrap());
    assert!(a
        .apply_inbound_pool_update(XITE, &second_path, &second_wire)
        .await
        .is_err());
    assert!(b
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await
        .is_err());

    let a_ids: Vec<_> = a
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|r| r.id)
        .collect();
    let b_ids: Vec<_> = b
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(a_ids.is_empty(), "partition A quarantined the component");
    assert!(b_ids.is_empty(), "partition B quarantined the component");

    // Concurrent arrivals are serialized through admission, the target shard
    // write, and cross-shard evictions. The persisted result is still one winner.
    let concurrent_home = tempfile::tempdir().unwrap();
    let concurrent_root = concurrent_home.path().join("data").join(XITE);
    let concurrent = node(concurrent_home.path(), &concurrent_root, &roster).await;
    let concurrent_rln = persisted_admission(concurrent_home.path());
    concurrent.set_pool_admission(concurrent_rln.clone()).await;
    concurrent_rln.refresh(&concurrent, XITE).await;
    let (left, right) = tokio::join!(
        concurrent.apply_inbound_pool_update(XITE, &first_path, &first_wire),
        concurrent.apply_inbound_pool_update(XITE, &second_path, &second_wire),
    );
    assert_eq!(
        usize::from(left.is_err()) + usize::from(right.is_err()),
        1,
        "one concurrent first arrival lands and its conflicting peer is rejected"
    );
    let concurrent_ids: Vec<_> = concurrent
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|record| record.id)
        .collect();
    assert!(concurrent_ids.is_empty());

    // A member cannot grind progressively lower record ids into repeated
    // application deliveries. The first conflict poisons and removes the whole
    // component, so no replacement can surface in a later disk rescan.
    let grind_home = tempfile::tempdir().unwrap();
    let grind_root = grind_home.path().join("data").join(XITE);
    let grind = node(grind_home.path(), &grind_root, &roster).await;
    let grind_rln = persisted_admission(grind_home.path());
    grind.set_pool_admission(grind_rln.clone()).await;
    grind_rln.refresh(&grind, XITE).await;
    let mut deltas = grind.subscribe_pool_deltas();
    let (high_path, high_wire, low_path, low_wire) = if first_id > second_id {
        (&first_path, &first_wire, &second_path, &second_wire)
    } else {
        (&second_path, &second_wire, &first_path, &first_wire)
    };
    assert!(grind
        .apply_inbound_pool_update(XITE, high_path, high_wire)
        .await
        .unwrap());
    let first_delta = deltas.recv().await.unwrap();
    assert_eq!(first_delta.records.len(), 1);
    assert!(grind
        .apply_inbound_pool_update(XITE, low_path, low_wire)
        .await
        .is_err());
    assert!(
        matches!(
            deltas.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "a deterministic replacement was delivered as a second allowance use"
    );
    let grind_ids: Vec<_> = grind
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|record| record.id)
        .collect();
    assert!(grind_ids.is_empty());
    assert!(
        grind.pool_all_records(XITE).await.is_empty(),
        "a full rescan cannot resurrect a quarantined replacement"
    );

    // Poison persistence is ordered before shard eviction. A deterministic
    // not-a-directory failure leaves the previously accepted record on disk.
    let failure_home = tempfile::tempdir().unwrap();
    let failure_root = failure_home.path().join("data").join(XITE);
    let failure = node(failure_home.path(), &failure_root, &roster).await;
    let blocked_parent = failure_home.path().join("blocked");
    let failure_rln = RlnAdmission::new(Some(blocked_parent.join("rln_usage.json")));
    failure.set_pool_admission(failure_rln.clone()).await;
    failure_rln.refresh(&failure, XITE).await;
    assert!(failure
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await
        .unwrap());
    // Refresh now persists both usage and accepted-root history in this
    // directory. Replace that private sidecar directory with a file only after
    // the first record lands, so the second record deterministically exercises
    // poison-ledger persistence failure.
    std::fs::remove_dir_all(&blocked_parent).unwrap();
    std::fs::write(&blocked_parent, b"not a directory").unwrap();
    assert!(failure
        .apply_inbound_pool_update(XITE, &second_path, &second_wire)
        .await
        .is_err());
    let failure_ids: Vec<_> = failure
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|record| record.id)
        .collect();
    assert_eq!(
        failure_ids,
        vec![first_id],
        "failed poison persistence did not commit the planned eviction"
    );

    // Corrupt durable poison prevents a gate from loading and rejects all RLN
    // traffic instead of silently resetting the quarantine history.
    let corrupt_home = tempfile::tempdir().unwrap();
    let corrupt_root = corrupt_home.path().join("data").join(XITE);
    let corrupt = node(corrupt_home.path(), &corrupt_root, &roster).await;
    std::fs::create_dir_all(corrupt_home.path().join("private")).unwrap();
    std::fs::write(
        corrupt_home.path().join("private").join("rln_poison.json"),
        b"{not valid json",
    )
    .unwrap();
    let corrupt_rln = persisted_admission(corrupt_home.path());
    corrupt.set_pool_admission(corrupt_rln.clone()).await;
    corrupt_rln.refresh(&corrupt, XITE).await;
    assert!(corrupt
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await
        .is_err());
    assert!(corrupt.pool_admission_records(XITE).await.is_empty());

    // Exact same-proof wrappers also converge instead of each partition keeping
    // whichever outer signature it saw first.
    let wrapper = rewrap_same_proof(&rule, &first, 211);
    let wrapper_id = pool_record_id(&wrapper).unwrap();
    let wrapper_expected = first_id.min(wrapper_id);
    let (wrapper_path, wrapper_wire) = wire_record(&rule, &wrapper);
    let c_home = tempfile::tempdir().unwrap();
    let c_root = c_home.path().join("data").join(XITE);
    let c = node(c_home.path(), &c_root, &roster).await;
    let c_rln = persisted_admission(c_home.path());
    c.set_pool_admission(c_rln.clone()).await;
    c_rln.refresh(&c, XITE).await;
    let d_home = tempfile::tempdir().unwrap();
    let d_root = d_home.path().join("data").join(XITE);
    let d = node(d_home.path(), &d_root, &roster).await;
    let d_rln = persisted_admission(d_home.path());
    d.set_pool_admission(d_rln.clone()).await;
    d_rln.refresh(&d, XITE).await;
    assert!(c
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await
        .unwrap());
    assert!(d
        .apply_inbound_pool_update(XITE, &wrapper_path, &wrapper_wire)
        .await
        .unwrap());
    let c_result = c
        .apply_inbound_pool_update(XITE, &wrapper_path, &wrapper_wire)
        .await;
    let d_result = d
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await;
    assert_eq!(
        usize::from(c_result.is_err()) + usize::from(d_result.is_err()),
        1,
        "the weaker transport wrapper is refused while both partitions converge"
    );
    let c_ids: Vec<_> = c
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|r| r.id)
        .collect();
    let d_ids: Vec<_> = d
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(c_ids, vec![wrapper_expected]);
    assert_eq!(d_ids, vec![wrapper_expected]);
    let survivor_path = if wrapper_expected == first_id {
        &first_path
    } else {
        &wrapper_path
    };
    assert_eq!(
        std::fs::read(c_root.join(survivor_path)).unwrap(),
        std::fs::read(d_root.join(survivor_path)).unwrap(),
        "verified transport-wrapper replacement converges on disk"
    );

    // Replacing the admission object simulates a process restart. refresh()
    // must warm the nullifier log from the retained shard before the conflict
    // arrives, otherwise both records remain on disk.
    let restart_home = tempfile::tempdir().unwrap();
    let restart_root = restart_home.path().join("data").join(XITE);
    let restart = node(restart_home.path(), &restart_root, &roster).await;
    let initial = persisted_admission(restart_home.path());
    restart.set_pool_admission(initial.clone()).await;
    initial.refresh(&restart, XITE).await;
    assert!(restart
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await
        .unwrap());
    let warmed = persisted_admission(restart_home.path());
    restart.set_pool_admission(warmed.clone()).await;
    warmed.refresh(&restart, XITE).await;
    assert!(restart
        .apply_inbound_pool_update(XITE, &second_path, &second_wire)
        .await
        .is_err());
    let restart_ids: Vec<_> = restart
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert!(
        restart_ids.is_empty(),
        "the conflicting component was removed"
    );
    assert!(
        restart.pool_all_records(XITE).await.is_empty(),
        "the poisoned records are excluded from a full rescan"
    );

    // A second restart imports the durable poisoned nullifiers even though the
    // public component is now empty. A third distinct reuse remains rejected.
    let restarted_again = persisted_admission(restart_home.path());
    restart.set_pool_admission(restarted_again.clone()).await;
    restarted_again.refresh(&restart, XITE).await;
    let (third_path, third_wire) = wire_record(&rule, &third);
    assert!(restart
        .apply_inbound_pool_update(XITE, &third_path, &third_wire)
        .await
        .is_err());
    assert!(restart.pool_admission_records(XITE).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn partial_overlap_partitions_converge_on_one_persisted_window() {
    const LIMIT: u32 = 8;

    let alice = RlnIdentity::from_seed(b"alice-partial-overlap");
    let roster = vec![commitment_to_hex(&alice.commitment())];
    let now = epix_core::time::now_ms();
    let epoch = content_pool::epoch_now(now);
    let a_home = tempfile::tempdir().unwrap();
    let a_root = a_home.path().join("data").join(XITE);
    let a = node(a_home.path(), &a_root, &roster).await;
    let b_home = tempfile::tempdir().unwrap();
    let b_root = b_home.path().join("data").join(XITE);
    let b = node(b_home.path(), &b_root, &roster).await;
    let descriptor = pool_descriptor_with_limit(&roster, LIMIT);
    a.update_content(XITE, Some(descriptor.clone())).await;
    b.update_content(XITE, Some(descriptor)).await;
    a.refresh_pool_rules(XITE).await;
    b.refresh_pool_rules(XITE).await;
    let rule = a.pool_rules_for(XITE).await.into_iter().next().unwrap();

    let ct = vec![73u8; 32_768];
    let weight = epix_rln::bucket_weight(ct.len(), 8_192);
    assert_eq!(weight, 4);
    let gate = PoolGate::from_roster(
        message_signal(XITE.as_bytes()),
        LIMIT,
        &[alice.commitment()],
    )
    .unwrap();
    let first_proof = gate.prove_as(&alice, epoch as u64, 0, weight, &ct).unwrap();
    let overlap_proof = gate.prove_as(&alice, epoch as u64, 2, weight, &ct).unwrap();
    let first = signed_rln_record(&rule, epoch, 41, &ct, &first_proof);
    let overlap = signed_rln_record(&rule, epoch, 42, &ct, &overlap_proof);
    let first_id = pool_record_id(&first).unwrap();
    let overlap_id = pool_record_id(&overlap).unwrap();
    let expected = first_id.min(overlap_id);
    let (first_path, first_wire) = wire_record(&rule, &first);
    let (overlap_path, overlap_wire) = wire_record(&rule, &overlap);

    let a_rln = persisted_admission(a_home.path());
    a.set_pool_admission(a_rln.clone()).await;
    a_rln.refresh(&a, XITE).await;
    let b_rln = persisted_admission(b_home.path());
    b.set_pool_admission(b_rln.clone()).await;
    b_rln.refresh(&b, XITE).await;
    assert!(a
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await
        .unwrap());
    assert!(b
        .apply_inbound_pool_update(XITE, &overlap_path, &overlap_wire)
        .await
        .unwrap());
    let a_result = a
        .apply_inbound_pool_update(XITE, &overlap_path, &overlap_wire)
        .await;
    let b_result = b
        .apply_inbound_pool_update(XITE, &first_path, &first_wire)
        .await;
    assert_eq!(a_result.is_ok(), overlap_id < first_id);
    assert_eq!(b_result.is_ok(), first_id < overlap_id);
    let a_ids: Vec<_> = a
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|record| record.id)
        .collect();
    let b_ids: Vec<_> = b
        .pool_admission_records(XITE)
        .await
        .into_iter()
        .map(|record| record.id)
        .collect();
    assert_eq!(a_ids, vec![expected]);
    assert_eq!(b_ids, vec![expected]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rln_accepts_exact_active_epoch_window_and_filters_legacy_rescans() {
    const DAY_MS: i64 = 86_400_000;

    let alice = RlnIdentity::from_seed(b"alice-epoch-window");
    let roster = vec![commitment_to_hex(&alice.commitment())];
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("data").join(XITE);
    let state = node(home.path(), &root, &roster).await;
    let rule = state.pool_rules_for(XITE).await.into_iter().next().unwrap();
    let current_epoch = content_pool::epoch_now(epix_core::time::now_ms());
    let oldest_active = current_epoch - 7;
    let just_expired = current_epoch - 8;
    let boundary = single_record_at(&rule, &alice, oldest_active * DAY_MS + 1_000, 31);
    let expired = single_record_at(&rule, &alice, just_expired * DAY_MS + 1_000, 32);
    let (boundary_path, boundary_wire) = wire_record(&rule, &boundary);
    let (expired_path, expired_wire) = wire_record(&rule, &expired);

    let admission = persisted_admission(home.path());
    state.set_pool_admission(admission.clone()).await;
    admission.refresh(&state, XITE).await;
    assert!(state
        .apply_inbound_pool_update(XITE, &boundary_path, &boundary_wire)
        .await
        .unwrap());
    assert!(state
        .apply_inbound_pool_update(XITE, &expired_path, &expired_wire)
        .await
        .is_err());
    assert_eq!(state.pool_all_records(XITE).await.len(), 1);

    // Simulate a legacy shard written before the active-window rule existed.
    // A disk rescan still verifies routing and excludes the expired RLN row.
    let legacy_home = tempfile::tempdir().unwrap();
    let legacy_root = legacy_home.path().join("data").join(XITE);
    let legacy = node(legacy_home.path(), &legacy_root, &roster).await;
    let legacy_admission = persisted_admission(legacy_home.path());
    legacy.set_pool_admission(legacy_admission.clone()).await;
    legacy_admission.refresh(&legacy, XITE).await;
    XiteStorage::new(&legacy_root)
        .write(&expired_path, &expired_wire)
        .unwrap();
    assert!(legacy.pool_all_records(XITE).await.is_empty());
    assert!(legacy.pool_admission_records(XITE).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn root_content_change_refreshes_rln_roster_without_restart() {
    let alice = RlnIdentity::from_seed(b"alice-old-roster");
    let bob = RlnIdentity::from_seed(b"bob-new-roster");
    let alice_roster = vec![commitment_to_hex(&alice.commitment())];
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("data").join(XITE);
    let state = node(home.path(), &root, &alice_roster).await;
    let rln = persisted_admission(home.path());
    state.set_pool_admission(rln.clone()).await;
    rln.refresh(&state, XITE).await;
    assert!(rln.is_member(XITE, &alice));
    assert!(!rln.is_member(XITE, &bob));

    let bob_roster = vec![commitment_to_hex(&bob.commitment())];
    state
        .update_content(XITE, Some(pool_descriptor(&bob_roster)))
        .await;
    state.ingest_file(XITE, "content.json").await;

    assert!(
        !rln.is_member(XITE, &alice),
        "removed member left the current roster"
    );
    assert!(
        rln.is_member(XITE, &bob),
        "new member loaded on the root update"
    );

    // Admission is keyed by xite address. Until the key carries the pool rule,
    // two RLN-required rules would alias one gate, so reject that descriptor.
    let mut multiple = pool_descriptor(&bob_roster);
    let mut second_rule = multiple["pool"]["channels"].clone();
    second_rule["dir"] = json!("pool-two");
    multiple["pool"]["second"] = second_rule;
    state.update_content(XITE, Some(multiple)).await;
    state.ingest_file(XITE, "content.json").await;
    assert!(
        !rln.is_member(XITE, &bob),
        "multiple RLN rules fail closed instead of sharing one gate"
    );

    state
        .update_content(XITE, Some(pool_descriptor(&bob_roster)))
        .await;
    state.ingest_file(XITE, "content.json").await;
    assert!(rln.is_member(XITE, &bob));

    // A later malformed descriptor must remove the last good gate instead of
    // leaving Bob authorized under stale state.
    let mut invalid = pool_descriptor(&bob_roster);
    invalid["pool"]["channels"]["rln_limit"] = json!(0);
    state.update_content(XITE, Some(invalid)).await;
    state.ingest_file(XITE, "content.json").await;
    assert!(
        !rln.is_member(XITE, &bob),
        "invalid rebuild removed the stale gate"
    );
    assert!(
        rln.prove_for(
            XITE,
            &bob,
            content_pool::epoch_now(epix_core::time::now_ms()),
            &[0u8; 8192],
        )
        .unwrap_err()
        .contains("no RLN roster"),
        "send path also fails closed after an invalid rebuild"
    );
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
    let rln = persisted_admission(home.path());
    rln.refresh(&n, XITE).await;

    let epoch = 500i64;
    let ct = vec![0u8; 8192]; // one smallest-bucket unit

    // First send in the epoch succeeds (spends the 1-unit allowance).
    assert!(rln.prove_for(XITE, &alice_rln, epoch, &ct).is_ok(), "first send is within allowance");
    // Second send in the SAME epoch is refused by the rail (allowance = 1 unit),
    // so the client never produces a unit-reusing proof.
    let mut next_ct = ct.clone();
    next_ct[0] = 1;
    let second = rln.prove_for(XITE, &alice_rln, epoch, &next_ct);
    assert!(
        second.is_err(),
        "the rail refuses a second unit, preventing any self-slash"
    );
    assert!(
        second.unwrap_err().contains("allowance"),
        "the refusal explains the limit"
    );
    // The next epoch has a fresh allowance.
    assert!(rln.prove_for(XITE, &alice_rln, epoch + 1, &ct).is_ok(), "a new epoch resets the rail");
}
