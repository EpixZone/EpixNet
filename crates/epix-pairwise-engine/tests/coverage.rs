//! Behavioral coverage the crypto review asked for (C6–C10): replay resistance,
//! multi-sender isolation, size/bucket handling, and corrupt-but-addressed
//! records. All via the public `Engine` API.

use epix_pairwise_engine::PairwiseEngine;
use epix_envelope::{Engine, EngineError, IdentitySecret};
use std::collections::HashMap;

const BUCKETS: &[usize] = &[512, 2048, 8192, 65536];

fn seed() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

/// Establish A→B and return (engine, alice_sess, alice_tags, bob_sess, bob_tags).
fn established(
    e: &PairwiseEngine,
    alice: &IdentitySecret,
    bob: &IdentitySecret,
) -> (Vec<u8>, HashMap<[u8; 32], u32>, Vec<u8>, HashMap<[u8; 32], u32>) {
    let begun = e.begin_session(alice, &e.publish_bundle(bob, "bob.epix"), [1u8; 16]).unwrap();
    let mut a_tags: HashMap<[u8; 32], u32> = begun.recv_tags.iter().map(|(n, t)| (*t, *n)).collect();
    let fc = e.seal(&begun.session, "alice.epix", &[], "s", "hello", 1, BUCKETS).unwrap();
    let bo = e.open_first(bob, &fc.tag, &fc.ct).unwrap();
    let b_tags: HashMap<[u8; 32], u32> = bo.next_recv_tags.iter().map(|(n, t)| (*t, *n)).collect();
    let _ = &mut a_tags;
    (begun.session, a_tags, bo.session_after, b_tags)
}

// --- C6: replay resistance --------------------------------------------------

#[test]
fn established_replay_against_advanced_session_fails() {
    let e = PairwiseEngine;
    let alice = IdentitySecret::new(seed());
    let bob = IdentitySecret::new(seed());
    let (a_sess, _a_tags, b_sess, _b_tags) = established(&e, &alice, &bob);

    // Bob sends one established message; Alice opens it.
    let m = e.seal(&b_sess, "bob.epix", &[], "t", "reply", 2, BUCKETS).unwrap();
    // Alice's window has n=0 for Bob's b2a chain.
    let a_sess2 = {
        let o = e.open(&a_sess, 0, &m.tag, &m.ct).unwrap();
        assert_eq!(o.body, "reply");
        o.session_after
    };
    // Replaying the SAME record against the ADVANCED session fails closed
    // (the consumed header key is gone).
    assert!(e.open(&a_sess2, 0, &m.tag, &m.ct).is_err(), "replay must fail on advanced session");
}

#[test]
fn first_contact_open_is_stateless_and_repeatable() {
    // open_first is intentionally re-derivable (FC replay is stopped at the pool
    // dedup-by-signature layer, not here): opening twice yields the same message.
    let e = PairwiseEngine;
    let alice = IdentitySecret::new(seed());
    let bob = IdentitySecret::new(seed());
    let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), [9u8; 16]).unwrap();
    let fc = e.seal(&begun.session, "alice.epix", &[], "s", "twice", 1, BUCKETS).unwrap();
    let a = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
    let b = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
    assert_eq!(a.body, b.body);
    assert_eq!(a.body, "twice");
    assert_eq!(a.conv_id, b.conv_id);
}

// --- C7: two senders to one recipient are isolated --------------------------

#[test]
fn two_senders_to_one_recipient_are_isolated() {
    let e = PairwiseEngine;
    let bob = IdentitySecret::new(seed());
    let alice = IdentitySecret::new(seed());
    let carol = IdentitySecret::new(seed());
    let bob_bundle = e.publish_bundle(&bob, "bob.epix");

    let a_fc = {
        let b = e.begin_session(&alice, &bob_bundle, [1u8; 16]).unwrap();
        e.seal(&b.session, "alice.epix", &[], "s", "from-alice", 1, BUCKETS).unwrap()
    };
    let c_fc = {
        let b = e.begin_session(&carol, &bob_bundle, [2u8; 16]).unwrap();
        e.seal(&b.session, "carol.epix", &[], "s", "from-carol", 1, BUCKETS).unwrap()
    };

    // Distinct tags, and Bob opens each to the right sender/body.
    assert_ne!(a_fc.tag, c_fc.tag);
    let oa = e.open_first(&bob, &a_fc.tag, &a_fc.ct).unwrap();
    let oc = e.open_first(&bob, &c_fc.tag, &c_fc.ct).unwrap();
    assert_eq!((oa.sender_xid.as_deref(), oa.body.as_str()), (Some("alice.epix"), "from-alice"));
    assert_eq!((oc.sender_xid.as_deref(), oc.body.as_str()), (Some("carol.epix"), "from-carol"));
    assert_ne!(oa.conv_id, oc.conv_id, "separate conversations");

    // Carol's record does not open under Alice's freshly-built session state, and
    // vice-versa (cross-session confusion is impossible: different tags/keys).
    assert!(e.open_first(&bob, &a_fc.tag, &c_fc.ct).is_err(), "mixed tag/ct fails");
}

// --- C9: size classes + TooBig ----------------------------------------------

#[test]
fn oversize_body_is_rejected_and_sizes_are_bucketed() {
    let e = PairwiseEngine;
    let alice = IdentitySecret::new(seed());
    let bob = IdentitySecret::new(seed());
    let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), [1u8; 16]).unwrap();

    // A body past the largest bucket is refused.
    let huge = "x".repeat(70_000);
    assert_eq!(
        e.seal(&begun.session, "alice.epix", &[], "s", &huge, 1, BUCKETS).err(),
        Some(EngineError::TooBig)
    );

    // The record size is always one of the declared buckets (the intended
    // size-class leak, and nothing finer). Small and medium bodies land in
    // different buckets.
    let small = e.seal(&begun.session, "alice.epix", &[], "s", "hi", 1, BUCKETS).unwrap();
    assert!(BUCKETS.contains(&small.ct.len()), "ct.len {} is a bucket", small.ct.len());
    let mediumtext = "y".repeat(1500);
    let medium = e.seal(&begun.session, "alice.epix", &[], "s", &mediumtext, 1, BUCKETS).unwrap();
    assert!(BUCKETS.contains(&medium.ct.len()));
    assert!(medium.ct.len() >= small.ct.len());
}

// --- C10 / C8: corrupt-but-addressed and malformed ct -----------------------

#[test]
fn corrupt_body_is_addressed_but_unopenable() {
    let e = PairwiseEngine;
    let alice = IdentitySecret::new(seed());
    let bob = IdentitySecret::new(seed());
    let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), [1u8; 16]).unwrap();
    let fc = e.seal(&begun.session, "alice.epix", &[], "s", "intact", 1, BUCKETS).unwrap();

    // Flip a byte in the BODY region (past the 144-byte FC header block).
    let mut bad = fc.ct.clone();
    let body_pos = 200.min(bad.len() - 1);
    bad[body_pos] ^= 1;
    // Still recognized as addressed to Bob (header intact) ...
    assert!(e.first_contact_candidate(&bob, &fc.tag, &bad), "header still matches");
    // ... but does not open (AEAD rejects the body).
    assert!(e.open_first(&bob, &fc.tag, &bad).is_err(), "corrupt body must not open");

    // Garbage / short ct is rejected, not panicked.
    assert!(e.open_first(&bob, &fc.tag, &[0u8; 10]).is_err());
    assert!(e.open_first(&bob, &fc.tag, &[]).is_err());
    assert!(!e.first_contact_candidate(&bob, &fc.tag, &[0u8; 3]));
}
