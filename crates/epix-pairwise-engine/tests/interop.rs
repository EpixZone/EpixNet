//! Two-state-machine interop + adversarial property tests.
//!
//! Alice (`begin`/`seal`) and Bob (`open_first`/`open`) are independent state
//! machines that communicate ONLY over the wire tuple `(tag, ct)`. These tests
//! drive them against each other under bursts, reordering, and byte-tampering,
//! and assert the wire never carries plaintext. Together with the happy-path
//! tests in `src/lib.rs` and the frozen vectors in `tests/vectors.rs`, this is
//! the interop surface a second implementation of `docs/channel-crypto-spec.md`
//! must also satisfy.

use epix_pairwise_engine::PairwiseEngine;
use epix_envelope::{Engine, IdentitySecret};
use std::collections::HashMap;

const BUCKETS: &[usize] = &[512, 2048, 8192, 65536];

/// Models the node's durable `expected_tag` set: every published receive window
/// is ACCUMULATED (not replaced), because out-of-order delivery means a later
/// window can start past tags still in flight. Consumed tags may stay — lookups
/// are by tag, and a tag is only ever produced once.
#[derive(Default)]
struct TagSet(HashMap<[u8; 32], u32>);
impl TagSet {
    fn add(&mut self, window: &[(u32, [u8; 32])]) {
        for (n, t) in window {
            self.0.insert(*t, *n);
        }
    }
    fn n_for(&self, tag: &[u8; 32]) -> Option<u32> {
        self.0.get(tag).copied()
    }
}

fn seed() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}

/// Deterministic PRNG so a failing property replay is reproducible from `state`.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn range(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn find_n(window: &[(u32, [u8; 32])], tag: &[u8; 32]) -> Option<u32> {
    window.iter().find(|(_, t)| t == tag).map(|(n, _)| *n)
}

#[test]
fn tampering_any_region_fails_to_open() {
    let e = PairwiseEngine;
    let alice = IdentitySecret::new(seed());
    let bob = IdentitySecret::new(seed());
    let conv = [1u8; 16];

    // First-contact record.
    let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), conv).unwrap();
    let fc = e.seal(&begun.session, "alice.epix", &[], "s", "hello", 1, BUCKETS).unwrap();

    // Clean open works.
    assert!(e.open_first(&bob, &fc.tag, &fc.ct).is_ok());

    // Flip one bit in the tag → not a candidate / cannot open.
    let mut bad_tag = fc.tag;
    bad_tag[0] ^= 1;
    assert!(!e.first_contact_candidate(&bob, &bad_tag, &fc.ct));
    assert!(e.open_first(&bob, &bad_tag, &fc.ct).is_err());

    // Flip a bit in the header region, then in the body region → AEAD rejects.
    for pos in [0usize, 100, fc.ct.len() - 1] {
        let mut bad = fc.ct.clone();
        bad[pos] ^= 1;
        assert!(e.open_first(&bob, &fc.tag, &bad).is_err(), "tamper at {pos} must fail");
    }
    // Truncation fails.
    assert!(e.open_first(&bob, &fc.tag, &fc.ct[..fc.ct.len() - 1]).is_err());

    // Now an established record and the same tamper checks.
    let bob_open = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
    let mut bob_sess = bob_open.session_after;
    let alice_window = begun.recv_tags.clone();
    let reply = e.seal(&bob_sess, "bob.epix", &[], "r", "world", 2, BUCKETS).unwrap();
    bob_sess = reply.session_after;
    let n = find_n(&alice_window, &reply.tag).unwrap();
    assert!(e.open(&begun.session, n, &reply.tag, &reply.ct).is_ok());
    for pos in [0usize, 30, reply.ct.len() - 1] {
        let mut bad = reply.ct.clone();
        bad[pos] ^= 1;
        assert!(e.open(&begun.session, n, &reply.tag, &bad).is_err(), "est tamper at {pos}");
    }
    let _ = &bob_sess;
}

#[test]
fn randomized_bursts_and_reordering_round_trip() {
    let e = PairwiseEngine;
    let mut rng = Rng(0x9E3779B97F4A7C15);

    for _trial in 0..8 {
        let alice = IdentitySecret::new(seed());
        let bob = IdentitySecret::new(seed());
        let conv = [rng.next() as u8; 16];

        // First contact establishes the session. `a_tags`/`b_tags` accumulate
        // every published receive window, exactly like the node's expected_tag set.
        let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), conv).unwrap();
        let mut a_sess = begun.session.clone();
        let mut a_tags = TagSet::default();
        a_tags.add(&begun.recv_tags); // tags for Bob→Alice (b2a)
        let fc = e.seal(&a_sess, "alice.epix", &[], "s", "fc-body", 1, BUCKETS).unwrap();
        a_sess = fc.session_after;
        assert!(!fc.ct.windows(7).any(|w| w == b"fc-body"), "no plaintext on the wire");
        let bo = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
        assert_eq!(bo.body, "fc-body");
        let mut b_sess = bo.session_after;
        let mut b_tags = TagSet::default();
        b_tags.add(&bo.next_recv_tags); // tags for Alice→Bob (a2b)

        // Many rounds: each side sends a burst (1..=8, under LOOKAHEAD=32), the
        // other receives them in a shuffled order.
        let mut counter = 0u64;
        for _round in 0..12 {
            // Alice → Bob burst.
            let ka = 1 + rng.range(8) as usize;
            let mut sent = Vec::new();
            for _ in 0..ka {
                counter += 1;
                let body = format!("a-{counter}");
                let s = e.seal(&a_sess, "alice.epix", &[], "t", &body, counter as i64, BUCKETS).unwrap();
                a_sess = s.session_after;
                assert!(!s.ct.windows(body.len()).any(|w| w == body.as_bytes()));
                sent.push((s.tag, s.ct, body));
            }
            shuffle(&mut rng, &mut sent);
            for (tag, ct, body) in &sent {
                let n = b_tags.n_for(tag).expect("alice tag in bob's accumulated set");
                let o = e.open(&b_sess, n, tag, ct).unwrap();
                assert_eq!(&o.body, body);
                b_sess = o.session_after;
                b_tags.add(&o.next_recv_tags);
            }

            // Bob → Alice burst.
            let kb = 1 + rng.range(8) as usize;
            let mut sent = Vec::new();
            for _ in 0..kb {
                counter += 1;
                let body = format!("b-{counter}");
                let s = e.seal(&b_sess, "bob.epix", &[], "t", &body, counter as i64, BUCKETS).unwrap();
                b_sess = s.session_after;
                sent.push((s.tag, s.ct, body));
            }
            shuffle(&mut rng, &mut sent);
            for (tag, ct, body) in &sent {
                let n = a_tags.n_for(tag).expect("bob tag in alice's accumulated set");
                let o = e.open(&a_sess, n, tag, ct).unwrap();
                assert_eq!(&o.body, body);
                a_sess = o.session_after;
                a_tags.add(&o.next_recv_tags);
            }
        }
    }
}

fn shuffle<T>(rng: &mut Rng, v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = rng.range((i + 1) as u64) as usize;
        v.swap(i, j);
    }
}
