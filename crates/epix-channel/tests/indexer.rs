//! End-to-end indexer tests: the generic `epix-envelope` send/receive path
//! operating over the concrete `epix_channel::ChannelDb` store, with the FakeEngine.

use epix_content::pool::{self, PoolRule};
use epix_envelope::{
    process_record, send_message, Engine, FakeEngine, IdentitySecret, ProcessOutcome,
};
use epix_channel::ChannelDb;

fn rule() -> PoolRule {
    PoolRule {
        dir: "pool".into(),
        class: pool::POOL_RECORD_FORMAT.into(),
        since_week: 0,
        fanout: 16,
        pow_bits: 6, // cheap for tests
        pad_buckets: vec![256, 1024, 4096],
        max_record_bytes: 8192,
        max_shard_bytes: 6_000_000,
        newest_first: true,
    }
}

fn rand_id() -> IdentitySecret {
    let v = hex::decode(epix_crypt::new_seed()).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&v[..32]);
    IdentitySecret::new(seed)
}

fn conv16() -> [u8; 16] {
    let v = hex::decode(epix_crypt::new_seed()).unwrap();
    let mut c = [0u8; 16];
    c.copy_from_slice(&v[..16]);
    c
}

#[test]
fn end_to_end_first_contact_and_reply() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;

    // Two nodes, two private indexes.
    let alice_db = ChannelDb::memory().unwrap();
    let bob_db = ChannelDb::memory().unwrap();

    let alice = rand_id();
    let bob = rand_id();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1alice", 0, None).unwrap();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();

    let bob_bundle = e.publish_bundle(&bob, "bob.epix");
    let alice_bundle = e.publish_bundle(&alice, "alice.epix");

    // The node's sealed-sender anti-spoof oracle: resolve a sender's published
    // bundle so process_record can bind the transcript ik_a to a name.
    let resolve = |xid: &str| -> Vec<serde_json::Value> {
        match xid {
            "alice.epix" => vec![alice_bundle.clone()],
            "bob.epix" => vec![bob_bundle.clone()],
            _ => Vec::new(),
        }
    };

    // Alice sends to Bob.
    let conv = conv16();
    let sent = send_message(
        &alice_db, &e, alice_id, &alice, "alice.epix", &[], &bob_bundle, conv, "Dinner?",
        "pizza at eight ZXQ1", now, &r, true,
    )
    .unwrap();

    // The record verifies as a real pool record for its shard.
    let (week, _sub) = pool::parse_shard_path(&r, &sent.shard_path).unwrap();
    assert_eq!(
        pool::verify_pool_record(&sent.record, &r, week, now),
        Ok(()),
        "posted record passes pool admission"
    );
    // No plaintext / xid leaks into the record.
    let raw = serde_json::to_string(&sent.record).unwrap();
    assert!(!raw.contains("ZXQ1"), "no plaintext body in the pool record");
    assert!(!raw.contains(".epix"), "no xid in the pool record");
    assert!(!raw.contains("Dinner"), "no subject in the pool record");

    // Alice sees her sent copy.
    assert_eq!(alice_db.messages(alice_id, &hex::encode(conv)).unwrap().len(), 1);

    // Bob processes the record → first contact indexed.
    let out = process_record(
        &bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &sent.record, now + 10,
        &resolve,
    )
    .unwrap();
    let (bob_conv, first) = match out {
        ProcessOutcome::Indexed { conv_id, first_contact, sender_xid, subject, unread, .. } => {
            assert!(first_contact);
            assert_eq!(sender_xid.as_deref(), Some("alice.epix"));
            assert_eq!(subject, "Dinner?");
            assert_eq!(unread, 1);
            (conv_id, first_contact)
        }
        other => panic!("expected Indexed, got {other:?}"),
    };
    assert!(first);
    // Bob's decrypted body is in his private index (and searchable).
    let msgs = bob_db.messages(bob_id, &bob_conv).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["body"].as_str(), Some("pizza at eight ZXQ1"));
    assert_eq!(bob_db.search(bob_id, "pizza", 10).unwrap().len(), 1);

    // Reprocessing is idempotent.
    assert_eq!(
        process_record(&bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &sent.record, now, &resolve)
            .unwrap(),
        ProcessOutcome::AlreadyProcessed
    );

    // Bob replies; Alice detects it via Tier-1 (her begin tags).
    let conv_arr: [u8; 16] = hex::decode(&bob_conv).unwrap().try_into().unwrap();
    let reply = send_message(
        &bob_db, &e, bob_id, &bob, "bob.epix", &[], &alice_bundle, conv_arr, "Re: Dinner?",
        "sounds good", now + 100, &r, true,
    )
    .unwrap();
    let out2 = process_record(
        &alice_db, &e, &[(alice_id, alice.clone(), "alice.epix".into())], &reply.record, now + 110,
        &resolve,
    )
    .unwrap();
    match out2 {
        ProcessOutcome::Indexed { first_contact, sender_xid, .. } => {
            assert!(!first_contact, "reply is an established-session message");
            assert_eq!(sender_xid.as_deref(), Some("bob.epix"));
        }
        other => panic!("expected Indexed reply, got {other:?}"),
    }
    // Alice's thread now has her sent + Bob's reply.
    assert_eq!(alice_db.messages(alice_id, &hex::encode(conv)).unwrap().len(), 2);
}

#[test]
fn record_addressed_to_someone_else_does_not_match() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;
    let alice = rand_id();
    let bob = rand_id();
    let eve = rand_id();
    let alice_db = ChannelDb::memory().unwrap();
    let eve_db = ChannelDb::memory().unwrap();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1alice", 0, None).unwrap();
    let eve_id = eve_db.upsert_identity("eve.epix", "epix1eve", 0, None).unwrap();

    let sent = send_message(
        &alice_db, &e, alice_id, &alice, "alice.epix", &[], &e.publish_bundle(&bob, "bob.epix"),
        conv16(), "s", "b", now, &r, true,
    )
    .unwrap();

    // Eve cannot open a record addressed to Bob.
    let out = process_record(
        &eve_db, &e, &[(eve_id, eve, "eve.epix".into())], &sent.record, now,
        |_: &str| Vec::<serde_json::Value>::new(),
    )
    .unwrap();
    assert_eq!(out, ProcessOutcome::NoMatch);
    assert!(eve_db.threads(eve_id, "all", 0, 10).unwrap().is_empty());
}

#[test]
fn group_thread_fans_out_with_shared_conv_and_members() {
    // An N-person mail thread: Alice sends ONE message to Bob AND Carol. It fans
    // out as two unlinkable pairwise envelopes that share a conv id and carry the
    // full member list, and Alice records her own copy exactly once.
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;

    let alice_db = ChannelDb::memory().unwrap();
    let bob_db = ChannelDb::memory().unwrap();
    let carol_db = ChannelDb::memory().unwrap();
    let alice = rand_id();
    let bob = rand_id();
    let carol = rand_id();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1a", 0, None).unwrap();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1b", 0, None).unwrap();
    let carol_id = carol_db.upsert_identity("carol.epix", "epix1c", 0, None).unwrap();
    let bob_bundle = e.publish_bundle(&bob, "bob.epix");
    let carol_bundle = e.publish_bundle(&carol, "carol.epix");
    let alice_bundle = e.publish_bundle(&alice, "alice.epix");

    let conv = conv16();
    let members: Vec<String> =
        vec!["alice.epix".into(), "bob.epix".into(), "carol.epix".into()];

    // Leg to Bob records the own copy; leg to Carol does not.
    let to_bob = send_message(
        &alice_db, &e, alice_id, &alice, "alice.epix", &members, &bob_bundle, conv, "Party",
        "at 8 ZXQ1", now, &r, true,
    )
    .unwrap();
    let to_carol = send_message(
        &alice_db, &e, alice_id, &alice, "alice.epix", &members, &carol_bundle, conv, "Party",
        "at 8 ZXQ1", now, &r, false,
    )
    .unwrap();

    // The two fan-out records are unlinkable from outside (different tags).
    assert_ne!(to_bob.record["tag"], to_carol.record["tag"]);
    // Alice recorded her sent copy exactly ONCE (one leg, not two).
    assert_eq!(alice_db.messages(alice_id, &hex::encode(conv)).unwrap().len(), 1);

    // Bob and Carol each open THEIR leg → same conv, and the thread carries the
    // full member list so either can reply-all.
    let recips: [(&ChannelDb, i64, IdentitySecret, &str, &serde_json::Value); 2] = [
        (&bob_db, bob_id, bob, "bob.epix", &to_bob.record),
        (&carol_db, carol_id, carol, "carol.epix", &to_carol.record),
    ];
    for (db, id, secret, my_xid, rec) in recips {
        let resolve = |xid: &str| -> Vec<serde_json::Value> { if xid == "alice.epix" { vec![alice_bundle.clone()] } else { Vec::new() } };
        let out = process_record(db, &e, &[(id, secret, my_xid.into())], rec, now + 10, &resolve)
            .unwrap();
        match out {
            ProcessOutcome::Indexed { conv_id, subject, .. } => {
                assert_eq!(subject, "Party");
                assert_eq!(conv_id, hex::encode(conv));
                let threads = db.threads(id, "all", 0, 10).unwrap();
                let m = threads[0]["members"].as_str().unwrap_or("");
                assert!(
                    m.contains("alice.epix") && m.contains("bob.epix") && m.contains("carol.epix"),
                    "thread carries the full member list for reply-all: {m}"
                );
            }
            other => panic!("expected {my_xid} to index the group message, got {other:?}"),
        }
    }
}

/// M1 regression: a first-contact record whose claimed `sender_xid` does NOT
/// match the transcript-bound `ik_a` (i.e. an impersonation of a real, published
/// user) MUST be rejected — not indexed as if it came from that user.
#[test]
fn first_contact_sender_spoof_is_rejected() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;

    let mallory_db = ChannelDb::memory().unwrap();
    let bob_db = ChannelDb::memory().unwrap();
    let mallory = rand_id();
    let alice = rand_id();
    let bob = rand_id();
    let mallory_id = mallory_db.upsert_identity("mallory.epix", "epix1m", 0, None).unwrap();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();

    // Mallory seals a first-contact to Bob but CLAIMS to be Alice.
    let bob_bundle = e.publish_bundle(&bob, "bob.epix");
    let sent = send_message(
        &mallory_db, &e, mallory_id, &mallory,
        "alice.epix", // <-- the lie: Mallory's transcript ik != Alice's published ik
        &[], &bob_bundle, conv16(), "s", "spoofed body", now, &r, true,
    )
    .unwrap();

    // Alice IS a real, published user (so her bundle resolves and its ik differs
    // from Mallory's transcript ik_a) — the check must catch the mismatch.
    let alice_bundle = e.publish_bundle(&alice, "alice.epix");
    let resolve = |xid: &str| -> Vec<serde_json::Value> { if xid == "alice.epix" { vec![alice_bundle.clone()] } else { Vec::new() } };
    let out = process_record(
        &bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &sent.record, now + 10, &resolve,
    )
    .unwrap();
    assert_eq!(out, ProcessOutcome::NoMatch, "spoofed sender must not be indexed");
    assert!(bob_db.threads(bob_id, "all", 0, 10).unwrap().is_empty(), "no thread from a spoof");

    // Control: a FRESH spoof whose claimed sender has NO published bundle is
    // deferred (NoMatch, and left unprocessed so it becomes indexable if a
    // matching bundle ever syncs) rather than trusted.
    let sent2 = send_message(
        &mallory_db, &e, mallory_id, &mallory, "ghost.epix", &[], &bob_bundle, conv16(), "s",
        "unverifiable", now, &r, true,
    )
    .unwrap();
    let out2 = process_record(
        &bob_db, &e, &[(bob_id, bob, "bob.epix".into())], &sent2.record, now + 10,
        |_: &str| Vec::<serde_json::Value>::new(),
    )
    .unwrap();
    assert_eq!(out2, ProcessOutcome::NoMatch, "unverifiable sender is deferred, not trusted");
    assert!(bob_db.threads(bob_id, "all", 0, 10).unwrap().is_empty(), "still no thread");
}

/// Multi-device delivery: a sender with MORE THAN ONE linked identity/device may
/// seal from any of them, and the receiver's anti-spoof must accept the message
/// as long as the transcript key matches ONE of the sender's published bundles
/// (not only the first). It must still refuse a device whose bundle it hasn't
/// seen — deferring (never falsely attributing), so the message indexes once
/// that device's bundle syncs.
#[test]
fn multi_device_sender_any_linked_key_accepted() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;

    let alice_db = ChannelDb::memory().unwrap();
    let bob_db = ChannelDb::memory().unwrap();

    // Alice's TWO devices: distinct secrets → distinct identity keys, same name.
    let alice_d1 = rand_id();
    let alice_d2 = rand_id();
    let bob = rand_id();
    let alice_d2_id = alice_db.upsert_identity("alice.epix", "epix1a2", 0, None).unwrap();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();

    let bob_bundle = e.publish_bundle(&bob, "bob.epix");
    let d1_bundle = e.publish_bundle(&alice_d1, "alice.epix");
    let d2_bundle = e.publish_bundle(&alice_d2, "alice.epix");
    // FakeEngine carries the identity key as `pub`; the real engine uses `ik`.
    assert_ne!(d1_bundle["pub"], d2_bundle["pub"], "two devices have distinct IKs");

    // Alice sends to Bob FROM DEVICE 2.
    let sent = send_message(
        &alice_db, &e, alice_d2_id, &alice_d2, "alice.epix", &[], &bob_bundle, conv16(),
        "hi", "from my second device ZXQ2", now, &r, true,
    )
    .unwrap();

    // Bob has synced BOTH of Alice's device bundles → the device-2 message is
    // accepted even though device 1 is listed first.
    let resolve_both = |xid: &str| -> Vec<serde_json::Value> {
        if xid == "alice.epix" { vec![d1_bundle.clone(), d2_bundle.clone()] } else { Vec::new() }
    };
    let out = process_record(
        &bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &sent.record, now + 10,
        &resolve_both,
    )
    .unwrap();
    match out {
        ProcessOutcome::Indexed { sender_xid, conv_id, .. } => {
            assert_eq!(sender_xid.as_deref(), Some("alice.epix"));
            let msgs = bob_db.messages(bob_id, &conv_id).unwrap();
            assert_eq!(msgs[0]["body"].as_str(), Some("from my second device ZXQ2"));
        }
        other => panic!("device-2 message must be accepted, got {other:?}"),
    }

    // A DIFFERENT node that has synced ONLY device 1's bundle must NOT index the
    // device-2 message (it can't yet prove the key) — and must DEFER, not drop:
    // no thread now, but re-probeable once device 2's bundle arrives.
    let bob2_db = ChannelDb::memory().unwrap();
    let bob2_id = bob2_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();
    let bob2 = rand_id();
    // Re-seal to bob2's bundle so it's addressed to this node.
    let bob2_bundle = e.publish_bundle(&bob2, "bob.epix");
    let sent2 = send_message(
        &alice_db, &e, alice_d2_id, &alice_d2, "alice.epix", &[], &bob2_bundle, conv16(),
        "hi", "second device again ZXQ3", now, &r, false,
    )
    .unwrap();
    let resolve_d1_only = |xid: &str| -> Vec<serde_json::Value> {
        if xid == "alice.epix" { vec![d1_bundle.clone()] } else { Vec::new() }
    };
    let deferred = process_record(
        &bob2_db, &e, &[(bob2_id, bob2.clone(), "bob.epix".into())], &sent2.record, now + 10,
        &resolve_d1_only,
    )
    .unwrap();
    assert_eq!(deferred, ProcessOutcome::NoMatch, "unseen device is deferred, not attributed");
    assert!(bob2_db.threads(bob2_id, "all", 0, 10).unwrap().is_empty(), "no thread while unproven");

    // Once device 2's bundle syncs, the SAME record indexes (deferred, not dropped).
    let now_indexed = process_record(
        &bob2_db, &e, &[(bob2_id, bob2, "bob.epix".into())], &sent2.record, now + 20,
        &resolve_both,
    )
    .unwrap();
    match now_indexed {
        ProcessOutcome::Indexed { sender_xid, .. } => {
            assert_eq!(sender_xid.as_deref(), Some("alice.epix"), "indexed after bundle syncs");
        }
        other => panic!("deferred message must index once the device bundle syncs, got {other:?}"),
    }
}
