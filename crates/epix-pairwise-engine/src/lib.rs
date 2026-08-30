//! `epix-pairwise-engine` — the real pairwise channel crypto engine.
//!
//! Implements [`epix_channel::Engine`] with X25519 X3DH key agreement, a Double
//! Ratchet (symmetric-key + DH ratchet) with header encryption, forward-secure
//! detection-tag chains, and Elligator2 first-contact tags — the metadata-private
//! equivalent of Signal's protocol, adapted to a serverless, fully-replicated
//! anonymous pool. It is a drop-in replacement for the test-only `FakeEngine`.
//!
//! Security notes / deliberate deviations (must be covered by a crypto review
//! before production): KDF chains use HKDF-SHA256 / HMAC-SHA256 (matching the
//! Signal specs' primitives, though not wire-identical — see
//! `docs/channel-crypto-spec.md`); one-time prekeys are dropped (the signed
//! prekey rotates weekly and is seed-derivable, so a seed compromise plus the
//! retained pool exposes the *first* message of a session — every later message
//! is protected by the ratchet); Elligator2 is the maintained-but-alpha
//! `curve25519-elligator2` crate. See `docs/channels.md` and the frozen vectors
//! in `tests/vectors.rs`.

pub mod crypto;
pub mod curve;
pub mod keys;
pub mod ratchet;

use epix_envelope::{Begun, Engine, EngineError, IdentitySecret, Opened, Sealed};
use serde_json::Value;

/// The real, secure pairwise channel engine. Stateless: all session state is threaded
/// through the opaque `session` blobs the node persists.
#[derive(Default, Clone)]
pub struct PairwiseEngine;

fn parse_payload(payload: &[u8]) -> Option<([u8; 16], Vec<String>, String, String, i64)> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    let conv: [u8; 16] = hex::decode(v.get("c")?.as_str()?).ok()?.try_into().ok()?;
    let members = v
        .get("m")
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let subject = v.get("s")?.as_str()?.to_string();
    let body = v.get("b")?.as_str()?.to_string();
    let ts = v.get("t")?.as_i64()?;
    Some((conv, members, subject, body, ts))
}

impl Engine for PairwiseEngine {
    fn publish_bundle(&self, id: &IdentitySecret, xid: &str) -> Value {
        keys::build_bundle(&id.seed, xid)
    }

    fn verify_bundle(&self, bundle: &Value) -> bool {
        keys::verify_bundle(bundle)
    }

    fn sender_ik(&self, bundle: &Value) -> Option<[u8; 32]> {
        keys::bundle_keys(bundle).map(|(ik, _spk, _idx)| ik)
    }

    fn begin_session(
        &self,
        id: &IdentitySecret,
        peer_bundle: &Value,
        conv_id: [u8; 16],
    ) -> Result<Begun, EngineError> {
        let (session, recv_tags) =
            ratchet::begin(&id.seed, peer_bundle, conv_id).ok_or(EngineError::Malformed)?;
        Ok(Begun { session, recv_tags })
    }

    fn seal(
        &self,
        session: &[u8],
        sender_xid: &str,
        members: &[String],
        subject: &str,
        body: &str,
        sent_ms: i64,
        buckets: &[usize],
    ) -> Result<Sealed, EngineError> {
        let (tag, ct, session_after) =
            ratchet::seal(session, sender_xid, members, subject, body, sent_ms, buckets)
                .ok_or(EngineError::TooBig)?;
        Ok(Sealed { tag, ct, session_after })
    }

    fn first_contact_candidate(&self, id: &IdentitySecret, tag: &[u8; 32], ct: &[u8]) -> bool {
        ratchet::fc_candidate(&id.seed, tag, ct)
    }

    fn open_first(
        &self,
        id: &IdentitySecret,
        tag: &[u8; 32],
        ct: &[u8],
    ) -> Result<Opened, EngineError> {
        let (session_after, conv, sender_xid, ik_a, payload, next) =
            ratchet::open_first(&id.seed, tag, ct).ok_or(EngineError::NotForMe)?;
        let (_c, members, subject, body, sent_ms) =
            parse_payload(&payload).ok_or(EngineError::Malformed)?;
        Ok(Opened {
            conv_id: conv,
            sender_xid: Some(sender_xid),
            ik_a: Some(ik_a),
            members,
            subject,
            body,
            sent_ms,
            session_after,
            next_recv_tags: next,
            pending: 0,
        })
    }

    fn open(
        &self,
        session: &[u8],
        n: u32,
        tag: &[u8; 32],
        ct: &[u8],
    ) -> Result<Opened, EngineError> {
        let (session_after, payload, sender, next, pending) =
            ratchet::open(session, n, tag, ct).ok_or(EngineError::NotForMe)?;
        let (conv, members, subject, body, sent_ms) =
            parse_payload(&payload).ok_or(EngineError::Malformed)?;
        Ok(Opened {
            conv_id: conv,
            sender_xid: sender,
            ik_a: None,
            members,
            subject,
            body,
            sent_ms,
            session_after,
            next_recv_tags: next,
            pending,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_seed() -> [u8; 32] {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        b
    }

    fn authenticate_bundle(mut bundle: Value) -> Value {
        let key = epix_crypt::new_seed();
        bundle["auth"] = serde_json::json!(epix_crypt::privatekey_to_address(&key).unwrap());
        let payload = keys::bundle_auth_payload(&bundle).unwrap();
        bundle["auth_sig"] = serde_json::json!(epix_crypt::sign_keccak(&payload, &key).unwrap());
        bundle
    }

    const BUCKETS: &[usize] = &[512, 2048, 8192, 65536];

    // Register a session's receive tags into a tiny in-memory tag→n map, like
    // the node's expected_tag table, and look up an inbound tag.
    fn find_n(window: &[(u32, [u8; 32])], tag: &[u8; 32]) -> Option<u32> {
        window.iter().find(|(_, t)| t == tag).map(|(n, _)| *n)
    }

    #[test]
    fn full_first_contact_and_ratcheting_conversation() {
        let e = PairwiseEngine;
        let alice = IdentitySecret::new(rand_seed());
        let bob = IdentitySecret::new(rand_seed());
        let bob_bundle = authenticate_bundle(e.publish_bundle(&bob, "bob.epix"));
        let alice_bundle = authenticate_bundle(e.publish_bundle(&alice, "alice.epix"));
        assert!(e.verify_bundle(&bob_bundle) && e.verify_bundle(&alice_bundle));

        let conv = [9u8; 16];

        // Alice → Bob first contact.
        let begun = e.begin_session(&alice, &bob_bundle, conv).unwrap();
        let mut alice_sess = begun.session.clone();
        let alice_recv_window = begun.recv_tags.clone(); // Bob's replies (b2a)
        let fc = e.seal(&alice_sess, "alice.epix", &[], "Hi", "meet at ZXQ1", 1000, BUCKETS).unwrap();
        alice_sess = fc.session_after;

        // No plaintext leaks in the ciphertext.
        assert!(!fc.ct.windows(4).any(|w| w == b"ZXQ1"));
        // The tag is a uniform representative (decodes to a curve point).
        assert!(curve::elligator_decode(&fc.tag).is_some());

        // Bob detects + opens.
        assert!(e.first_contact_candidate(&bob, &fc.tag, &fc.ct));
        assert!(!e.first_contact_candidate(&IdentitySecret::new(rand_seed()), &fc.tag, &fc.ct));
        let bob_open = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
        assert_eq!(bob_open.subject, "Hi");
        assert_eq!(bob_open.body, "meet at ZXQ1");
        assert_eq!(bob_open.sender_xid.as_deref(), Some("alice.epix"));
        assert_eq!(bob_open.conv_id, conv);
        let mut bob_sess = bob_open.session_after;
        let mut bob_recv_window = bob_open.next_recv_tags; // Alice's est messages (a2b)

        // Bob → Alice reply (established; triggers Alice's DH ratchet on receive).
        let reply = e.seal(&bob_sess, "bob.epix", &[], "re", "sounds good", 2000, BUCKETS).unwrap();
        bob_sess = reply.session_after;
        let n = find_n(&alice_recv_window, &reply.tag).expect("reply tag is in Alice's window");
        let a_open = e.open(&alice_sess, n, &reply.tag, &reply.ct).unwrap();
        assert_eq!(a_open.body, "sounds good");
        assert_eq!(a_open.sender_xid.as_deref(), Some("bob.epix"));
        alice_sess = a_open.session_after;
        let mut alice_recv_window = a_open.next_recv_tags;

        // Alice → Bob (established, her second send; her first after receiving,
        // so a DH ratchet step occurs on her side).
        let m2 = e.seal(&alice_sess, "alice.epix", &[], "re2", "on my way", 3000, BUCKETS).unwrap();
        alice_sess = m2.session_after;
        let n2 = find_n(&bob_recv_window, &m2.tag).expect("m2 tag in Bob's window");
        let b_open2 = e.open(&bob_sess, n2, &m2.tag, &m2.ct).unwrap();
        assert_eq!(b_open2.body, "on my way");
        bob_sess = b_open2.session_after;
        bob_recv_window = b_open2.next_recv_tags;

        // A few more back-and-forth messages to exercise multiple ratchet steps.
        for i in 0..4 {
            let msg = format!("bob-msg-{i}");
            let s = e.seal(&bob_sess, "bob.epix", &[], "t", &msg, 4000 + i, BUCKETS).unwrap();
            bob_sess = s.session_after;
            let nn = find_n(&alice_recv_window, &s.tag).expect("bob msg tag in Alice window");
            let o = e.open(&alice_sess, nn, &s.tag, &s.ct).unwrap();
            assert_eq!(o.body, msg);
            alice_sess = o.session_after;
            alice_recv_window = o.next_recv_tags;

            let msg2 = format!("alice-msg-{i}");
            let s2 = e.seal(&alice_sess, "alice.epix", &[], "t", &msg2, 5000 + i, BUCKETS).unwrap();
            alice_sess = s2.session_after;
            let nn2 = find_n(&bob_recv_window, &s2.tag).expect("alice msg tag in Bob window");
            let o2 = e.open(&bob_sess, nn2, &s2.tag, &s2.ct).unwrap();
            assert_eq!(o2.body, msg2);
            bob_sess = o2.session_after;
            bob_recv_window = o2.next_recv_tags;
        }
        let _ = &bob_sess;
    }

    #[test]
    fn out_of_order_within_window() {
        // Bob sends three messages in a row; Alice receives #3 then #1 then #2.
        let e = PairwiseEngine;
        let alice = IdentitySecret::new(rand_seed());
        let bob = IdentitySecret::new(rand_seed());
        let conv = [4u8; 16];
        let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), conv).unwrap();
        let alice_sess = begun.session.clone();
        let alice_window = begun.recv_tags.clone();
        let fc = e.seal(&alice_sess, "alice.epix", &[], "s", "b", 1, BUCKETS).unwrap();
        let bob_open = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
        let mut bob_sess = bob_open.session_after;

        let mut msgs: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        for i in 0..3 {
            let s = e.seal(&bob_sess, "bob.epix", &[], "t", &format!("m{i}"), 10 + i, BUCKETS).unwrap();
            bob_sess = s.session_after.clone();
            msgs.push((s.tag, s.ct));
        }
        // Deliver 2, 0, 1.
        let mut sess = alice_sess;
        for idx in [2usize, 0, 1] {
            let (tag, ct) = &msgs[idx];
            let n = find_n(&alice_window, tag).expect("tag in window");
            let o = e.open(&sess, n, tag, ct).unwrap();
            assert_eq!(o.body, format!("m{idx}"));
            sess = o.session_after;
        }
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let e = PairwiseEngine;
        let alice = IdentitySecret::new(rand_seed());
        let bob = IdentitySecret::new(rand_seed());
        let eve = IdentitySecret::new(rand_seed());
        let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), [1u8; 16]).unwrap();
        let fc = e.seal(&begun.session, "alice.epix", &[], "s", "secret", 1, BUCKETS).unwrap();
        assert!(!e.first_contact_candidate(&eve, &fc.tag, &fc.ct));
        assert!(e.open_first(&eve, &fc.tag, &fc.ct).is_err());
    }

    /// F3: a head-of-chain gap far larger than the OLD 32-tag window now
    /// self-heals — the widened window (== MAX_SKIP) registers the far tag, so
    /// the record is matchable and the ratchet skips to it, instead of the tag
    /// silently missing forever.
    #[test]
    fn large_head_gap_within_window_self_heals() {
        let e = PairwiseEngine;
        let alice = IdentitySecret::new(rand_seed());
        let bob = IdentitySecret::new(rand_seed());
        let begun = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), [5u8; 16]).unwrap();
        let mut a_sess = begun.session.clone();
        let fc = e.seal(&a_sess, "alice.epix", &[], "s", "fc", 1, BUCKETS).unwrap();
        a_sess = fc.session_after;
        let bo = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
        let bob_sess = bo.session_after;
        let bob_window = bo.next_recv_tags;

        // Alice sends 60 established messages; only the last reaches Bob. Its
        // tag index (~59) is past the OLD 32-window but inside the new 64.
        let mut last = None;
        for i in 0..60 {
            let s = e.seal(&a_sess, "alice.epix", &[], "t", &format!("m{i}"), 10 + i, BUCKETS).unwrap();
            a_sess = s.session_after;
            last = Some((i, s.tag, s.ct));
        }
        let (i, tag, ct) = last.unwrap();
        let n = bob_window
            .iter()
            .find(|(_, t)| *t == tag)
            .map(|(n, _)| *n)
            .expect("far tag is registered in the widened window (would miss at LOOKAHEAD=32)");
        assert!(n >= 32, "the gap exceeds the old 32-tag window (n = {n})");
        let o = e.open(&bob_sess, n, &tag, &ct).unwrap();
        assert_eq!(o.body, format!("m{i}"));
        // Receiving message #59 first reports the earlier ones as still pending.
        assert!(o.pending >= 32, "delivery-gap hint surfaced (pending = {})", o.pending);
    }

    /// The load-bearing no-OPK mechanism: a first contact against a bundle whose
    /// signed prekey is from an OLD week must still open — the responder
    /// recomputes `spk_priv(seed, idx)` from the `spk_idx` carried in the header,
    /// not from the current week. (This is also why the design has no first-message
    /// forward secrecy against seed compromise: any past idx is re-derivable.)
    #[test]
    fn first_contact_against_stale_spk_index() {
        let e = PairwiseEngine;
        let bob = IdentitySecret::new(rand_seed());
        let alice = IdentitySecret::new(rand_seed());
        let stale_idx = 1000u32; // weeks in the past, not current_spk_idx()

        // Bob's bundle as if published long ago (stale spk + spk_idx).
        let bob_bundle = authenticate_bundle(serde_json::json!({
            "v": 3, "xid": "bob.epix",
            "ik": keys::b64(&curve::public_key(&keys::ik_priv(&bob.seed))),
            "spk": keys::b64(&curve::public_key(&keys::spk_priv(&bob.seed, stale_idx))),
            "spk_idx": stale_idx,
        }));
        assert!(e.verify_bundle(&bob_bundle));

        let begun = e.begin_session(&alice, &bob_bundle, [2u8; 16]).unwrap();
        let fc = e.seal(&begun.session, "alice.epix", &[], "s", "old-week ZQ", 1, BUCKETS).unwrap();
        let opened = e.open_first(&bob, &fc.tag, &fc.ct).unwrap();
        assert_eq!(opened.body, "old-week ZQ");
        assert_eq!(opened.sender_xid.as_deref(), Some("alice.epix"));
        assert_eq!(opened.ik_a, Some(curve::public_key(&keys::ik_priv(&alice.seed))));
    }
}
