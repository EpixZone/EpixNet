//! End-to-end indexer tests: the generic `epix-envelope` send/receive path
//! operating over the concrete `epix_channel::ChannelDb` store, with the FakeEngine.

use epix_content::pool::{self, PoolRule};
use epix_envelope::{
    process_record, process_record_one, send_message, send_multi, Dest, Engine, FakeEngine,
    IdentitySecret, ProcessOutcome, SLOTS,
};
use epix_channel::ChannelDb;

fn rule() -> PoolRule {
    PoolRule {
        dir: "pool".into(),
        class: pool::POOL_RECORD_FORMAT.into(),
        since_week: 0,
        fanout: 16,
        pow_bits: 6, // cheap for tests
        pad_buckets: vec![8192, 32768],
        max_record_bytes: 60000,
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
    let out = process_record_one(
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

    // Reprocessing is idempotent: the record is `processed` for bob's identity, so
    // a rescan delivers nothing new (empty → NoMatch) and no duplicate row appears.
    assert_eq!(
        process_record_one(&bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &sent.record, now, &resolve)
            .unwrap(),
        ProcessOutcome::NoMatch
    );
    assert_eq!(bob_db.messages(bob_id, &bob_conv).unwrap().len(), 1, "no duplicate on rescan");

    // Bob replies; Alice detects it via Tier-1 (her begin tags).
    let conv_arr: [u8; 16] = hex::decode(&bob_conv).unwrap().try_into().unwrap();
    let reply = send_message(
        &bob_db, &e, bob_id, &bob, "bob.epix", &[], &alice_bundle, conv_arr, "Re: Dinner?",
        "sounds good", now + 100, &r, true,
    )
    .unwrap();
    let out2 = process_record_one(
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
    let out = process_record_one(
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
        let out = process_record_one(db, &e, &[(id, secret, my_xid.into())], rec, now + 10, &resolve)
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
    let out = process_record_one(
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
    let out2 = process_record_one(
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
    let out = process_record_one(
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
    let deferred = process_record_one(
        &bob2_db, &e, &[(bob2_id, bob2.clone(), "bob.epix".into())], &sent2.record, now + 10,
        &resolve_d1_only,
    )
    .unwrap();
    assert_eq!(deferred, ProcessOutcome::NoMatch, "unseen device is deferred, not attributed");
    assert!(bob2_db.threads(bob2_id, "all", 0, 10).unwrap().is_empty(), "no thread while unproven");

    // Once device 2's bundle syncs, the SAME record indexes (deferred, not dropped).
    let now_indexed = process_record_one(
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

/// The count-hiding property: a send that reaches 1 destination and a send that
/// reaches 3 destinations produce ONE pool record each, of the SAME public size
/// (same pad bucket) with the SAME fixed number of slots — so a peer counting
/// records or measuring sizes cannot recover the recipient/device count.
#[test]
fn multislot_hides_destination_count() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;
    let alice_db = ChannelDb::memory().unwrap();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1a", 0, None).unwrap();
    let alice = rand_id();

    let d1 = e.publish_bundle(&rand_id(), "bob.epix");
    let d2 = e.publish_bundle(&rand_id(), "bob.epix");
    let d3 = e.publish_bundle(&rand_id(), "bob.epix");

    let one = send_multi(
        &alice_db, &e, alice_id, &alice, "alice.epix", &[], &[Dest { bundle: d1.clone() }],
        conv16(), "s", "hi ZXQ", now, &r, true,
    )
    .unwrap();
    let three = send_multi(
        &alice_db, &e, alice_id, &alice, "alice.epix", &[],
        &[Dest { bundle: d1 }, Dest { bundle: d2 }, Dest { bundle: d3 }],
        conv16(), "s", "hi ZXQ", now, &r, false,
    )
    .unwrap();

    // Each send is exactly ONE record...
    let ct_one = one.record["ct"].as_str().unwrap();
    let ct_three = three.record["ct"].as_str().unwrap();
    // ...of identical public size (same pad bucket) — the 3-device send is
    // byte-indistinguishable in width from the 1-device send.
    assert_eq!(ct_one.len(), ct_three.len(), "1-dest and 3-dest records are the same size");

    // And every record always carries the full fixed slot count (reals + dummies).
    let bytes = |s: &str| base64_decode(s);
    let u1 = epix_envelope::multislot::unpack_ct(&bytes(ct_one)).unwrap();
    let u3 = epix_envelope::multislot::unpack_ct(&bytes(ct_three)).unwrap();
    assert_eq!(u1.tags.len(), SLOTS);
    assert_eq!(u3.tags.len(), SLOTS);
    assert_eq!(u1.keyslots.len(), SLOTS);
    assert_eq!(u3.keyslots.len(), SLOTS);
    // Every keyslot is the same fixed length (real seals padded == random dummies).
    let lens1: std::collections::HashSet<usize> = u1.keyslots.iter().map(|k| k.len()).collect();
    assert_eq!(lens1.len(), 1, "all keyslots (real + dummy) are one fixed size");
}

/// ONE record reaches MULTIPLE recipients: alice sends to bob AND carol in a
/// single pool record; each of their nodes processes the SAME record and indexes
/// its own message. This is the mechanism that hides recipient count too.
#[test]
fn multislot_one_record_reaches_multiple_recipients() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;
    let alice_db = ChannelDb::memory().unwrap();
    let bob_db = ChannelDb::memory().unwrap();
    let carol_db = ChannelDb::memory().unwrap();
    let alice_id = alice_db.upsert_identity("alice.epix", "epix1a", 0, None).unwrap();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1b", 0, None).unwrap();
    let carol_id = carol_db.upsert_identity("carol.epix", "epix1c", 0, None).unwrap();
    let alice = rand_id();
    let bob = rand_id();
    let carol = rand_id();
    let bob_bundle = e.publish_bundle(&bob, "bob.epix");
    let carol_bundle = e.publish_bundle(&carol, "carol.epix");
    let alice_bundle = e.publish_bundle(&alice, "alice.epix");

    let members = vec!["alice.epix".to_string(), "bob.epix".into(), "carol.epix".into()];
    let sent = send_multi(
        &alice_db, &e, alice_id, &alice, "alice.epix", &members,
        &[Dest { bundle: bob_bundle }, Dest { bundle: carol_bundle }],
        conv16(), "Party", "at 8 ZXQ", now, &r, true,
    )
    .unwrap();

    let resolve = |xid: &str| -> Vec<serde_json::Value> {
        if xid == "alice.epix" { vec![alice_bundle.clone()] } else { Vec::new() }
    };
    // Bob opens HIS slot in the shared record.
    let ob = process_record_one(&bob_db, &e, &[(bob_id, bob, "bob.epix".into())], &sent.record, now + 10, &resolve).unwrap();
    match ob {
        ProcessOutcome::Indexed { sender_xid, conv_id, .. } => {
            assert_eq!(sender_xid.as_deref(), Some("alice.epix"));
            assert_eq!(bob_db.messages(bob_id, &conv_id).unwrap()[0]["body"].as_str(), Some("at 8 ZXQ"));
        }
        other => panic!("bob must index his slot of the shared record, got {other:?}"),
    }
    // Carol opens HER slot in the SAME record.
    let oc = process_record_one(&carol_db, &e, &[(carol_id, carol, "carol.epix".into())], &sent.record, now + 10, &resolve).unwrap();
    match oc {
        ProcessOutcome::Indexed { sender_xid, conv_id, .. } => {
            assert_eq!(sender_xid.as_deref(), Some("alice.epix"));
            assert_eq!(carol_db.messages(carol_id, &conv_id).unwrap()[0]["body"].as_str(), Some("at 8 ZXQ"));
        }
        other => panic!("carol must index her slot of the shared record, got {other:?}"),
    }
}

fn base64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// Re-wrap dedup: two first-contact-openable records for the SAME conversation leg
/// (a send retry, or a second opener that raced the first before this node had the
/// session) must NOT create a second session or double-index the opener. The first
/// is indexed; the second is dropped idempotently (`AlreadyProcessed`).
#[test]
fn first_contact_rewrap_does_not_duplicate_session() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;

    let bob_db = ChannelDb::memory().unwrap();
    let bob = rand_id();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();
    let bob_bundle = e.publish_bundle(&bob, "bob.epix");

    // Alice's identity is fixed (same secret/name/bundle), but each opener is sealed
    // from a FRESH sender store with no persisted session — so both are first-contact
    // openers for the SAME conversation id, exactly as a resend / raced opener is.
    let alice = rand_id();
    let alice_bundle = e.publish_bundle(&alice, "alice.epix");
    let conv = conv16();
    let seal_opener = || {
        let a_db = ChannelDb::memory().unwrap();
        let a_id = a_db.upsert_identity("alice.epix", "epix1alice", 0, None).unwrap();
        send_message(
            &a_db, &e, a_id, &alice, "alice.epix", &[], &bob_bundle, conv, "Hi",
            "first message ZXQ", now, &r, false,
        )
        .unwrap()
    };
    let r1 = seal_opener();
    let r2 = seal_opener();

    let resolve = |xid: &str| -> Vec<serde_json::Value> {
        if xid == "alice.epix" { vec![alice_bundle.clone()] } else { Vec::new() }
    };

    // First opener → a new first-contact conversation.
    let o1 = process_record_one(
        &bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &r1.record, now + 10, &resolve,
    )
    .unwrap();
    let conv_hex = match o1 {
        ProcessOutcome::Indexed { first_contact, conv_id, .. } => {
            assert!(first_contact, "the first opener is a first contact");
            conv_id
        }
        other => panic!("expected the first opener to index, got {other:?}"),
    };
    assert_eq!(bob_db.messages(bob_id, &conv_hex).unwrap().len(), 1);
    let threads_before = bob_db.threads(bob_id, "all", 0, 10).unwrap().len();

    // Second opener for the SAME leg → deduped: no new session, no duplicate row.
    let o2 = process_record_one(
        &bob_db, &e, &[(bob_id, bob.clone(), "bob.epix".into())], &r2.record, now + 20, &resolve,
    )
    .unwrap();
    assert_eq!(
        o2,
        ProcessOutcome::AlreadyProcessed,
        "a re-wrap opener for an existing leg is deduped, not re-indexed"
    );
    assert_eq!(
        bob_db.messages(bob_id, &conv_hex).unwrap().len(),
        1,
        "no duplicate message from the re-wrap opener"
    );
    assert_eq!(
        bob_db.threads(bob_id, "all", 0, 10).unwrap().len(),
        threads_before,
        "no duplicate thread/session from the re-wrap opener"
    );

    // And it stays deduped on a rescan (marked processed, not re-probed).
    let o3 = process_record_one(
        &bob_db, &e, &[(bob_id, bob, "bob.epix".into())], &r2.record, now + 30, &resolve,
    )
    .unwrap();
    assert_eq!(o3, ProcessOutcome::NoMatch, "the re-wrap opener is skipped on rescan");
    assert_eq!(bob_db.messages(bob_id, &conv_hex).unwrap().len(), 1);
}

/// The Defect-A fix: a node hosting TWO channel identities, both addressed in the
/// SAME count-hiding record, delivers the message to BOTH (one inbox row each) —
/// not just the first. Idempotency is per (record, identity), so a rescan adds no
/// duplicates and doesn't lose the second identity.
#[test]
fn one_record_delivers_to_two_local_identities() {
    let e = FakeEngine;
    let r = rule();
    let now = 1_780_000_000_000i64;

    // One node, ONE private index, TWO channel identities (two personas).
    let node_db = ChannelDb::memory().unwrap();
    let id_mud = node_db.upsert_identity("mud.epix", "epix1mud", 0, None).unwrap();
    let id_work = node_db.upsert_identity("work.epix", "epix1work", 0, None).unwrap();
    let mud = rand_id();
    let work = rand_id();
    let mud_bundle = e.publish_bundle(&mud, "mud.epix");
    let work_bundle = e.publish_bundle(&work, "work.epix");

    // Bob (separate node) sends ONE record addressed to BOTH of the node's identities.
    let bob_db = ChannelDb::memory().unwrap();
    let bob = rand_id();
    let bob_id = bob_db.upsert_identity("bob.epix", "epix1bob", 0, None).unwrap();
    let bob_bundle = e.publish_bundle(&bob, "bob.epix");
    let members = vec!["bob.epix".to_string(), "mud.epix".into(), "work.epix".into()];
    let conv = conv16();
    let conv_hex = hex::encode(conv);
    let sent = send_multi(
        &bob_db, &e, bob_id, &bob, "bob.epix", &members,
        &[Dest { bundle: mud_bundle }, Dest { bundle: work_bundle }],
        conv, "Hi", "for both personas ZXQ", now, &r, true,
    )
    .unwrap();

    let resolve = |xid: &str| -> Vec<serde_json::Value> {
        if xid == "bob.epix" { vec![bob_bundle.clone()] } else { Vec::new() }
    };
    let identities = [
        (id_mud, mud, "mud.epix".to_string()),
        (id_work, work, "work.epix".to_string()),
    ];
    let outcomes = process_record(&node_db, &e, &identities, &sent.record, now + 10, &resolve).unwrap();

    // BOTH identities got the message — one outcome each.
    assert_eq!(outcomes.len(), 2, "one record delivers to both local identities");
    let mut got: Vec<i64> = outcomes
        .iter()
        .map(|o| match o {
            ProcessOutcome::Indexed { identity_id, .. } => *identity_id,
            other => panic!("expected Indexed, got {other:?}"),
        })
        .collect();
    got.sort();
    let mut want = vec![id_mud, id_work];
    want.sort();
    assert_eq!(got, want, "both mud and work identities delivered");
    assert_eq!(node_db.messages(id_mud, &conv_hex).unwrap().len(), 1);
    assert_eq!(node_db.messages(id_work, &conv_hex).unwrap().len(), 1);

    // Rescan is idempotent for BOTH identities — no duplicates, none lost.
    let again = process_record(&node_db, &e, &identities, &sent.record, now + 20, &resolve).unwrap();
    assert!(again.is_empty(), "rescan delivers nothing new to either identity");
    assert_eq!(node_db.messages(id_mud, &conv_hex).unwrap().len(), 1);
    assert_eq!(node_db.messages(id_work, &conv_hex).unwrap().len(), 1);
}
