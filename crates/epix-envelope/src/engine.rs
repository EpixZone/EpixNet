//! The crypto boundary for metadata-private channels.
//!
//! [`Engine`] is the trait the indexer and send path call to seal, detect, and
//! open sealed envelopes. The REAL implementation — X3DH + a header-encrypted
//! Double Ratchet, Elligator2 first-contact tags, forward-secure detection-tag
//! chains — is the separate `epix-pairwise-engine` crate (Part 2). Keeping it behind
//! a trait lets the node ship and integration-test the entire pool → detect →
//! decrypt → index → notify pipeline against a deterministic stand-in first.
//!
//! [`FakeEngine`] is that stand-in. **It is NOT secure** and must never gate
//! real mail: its "key agreement" is a public hash of both parties' identifiers,
//! so anyone can derive the same keys. What it DOES faithfully reproduce is the
//! shape the node depends on — 32-byte detection tags, size-bucketed ciphertext
//! that never contains plaintext (bodies are XOR-masked with a keyed BLAKE3
//! stream, so the pool's "no cleartext / no xid" grep checks pass), cheap
//! first-contact detection, and ratchet-state-as-opaque-blob — so a green
//! integration test proves the plumbing, and swapping in `epix-pairwise-engine`
//! changes only this file's `impl`.

use serde_json::{json, Value};

/// An identity's secret seed. The node derives this deterministically from the
/// master seed (`identity::identity_seed`); the engine turns it into whatever
/// key material it needs. Private — never serialized into the shared pool.
/// Wiped from memory on drop (best-effort; see the crypto-review notes on
/// freed-heap remnants).
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct IdentitySecret {
    pub seed: [u8; 32],
}

impl IdentitySecret {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

/// Why an engine operation failed. Every variant means "drop / do not index".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// Ciphertext or header did not parse / authenticate.
    Malformed,
    /// This record is not addressed to the given identity.
    NotForMe,
    /// The plaintext does not fit the largest padding bucket.
    TooBig,
    /// The stored session/ratchet blob is corrupt.
    BadState,
}

/// A freshly begun session and the receive tags the initiator should register
/// so it can detect the peer's replies.
#[derive(Debug, Clone)]
pub struct Begun {
    pub session: Vec<u8>,
    pub recv_tags: Vec<(u32, [u8; 32])>,
}

/// A sealed outbound envelope: the public detection `tag`, the padded `ct`, and
/// the advanced session state to persist.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub tag: [u8; 32],
    pub ct: Vec<u8>,
    pub session_after: Vec<u8>,
}

/// A decrypted inbound envelope plus the session updates it implies.
#[derive(Debug, Clone)]
pub struct Opened {
    pub conv_id: [u8; 16],
    /// The sender's xID (present on first contact; on established messages the
    /// caller may fall back to the session's stored peer xID).
    pub sender_xid: Option<String>,
    /// The sender's transcript-bound identity key, present ONLY on first contact.
    /// The claimed `sender_xid` is attacker-controlled free text; the node MUST
    /// cross-check this `ik_a` against the published bundle for `sender_xid`
    /// before trusting the attribution (otherwise anyone can spoof "from Alice").
    /// `None` on established messages (sender is the session's verified peer).
    pub ik_a: Option<[u8; 32]>,
    /// The full participant list of the thread (so a recipient of one fan-out
    /// leg learns everyone in an N-person conversation and can reply-all).
    pub members: Vec<String>,
    pub subject: String,
    pub body: String,
    pub sent_ms: i64,
    /// Session state after opening (a brand-new session on first contact, or the
    /// advanced existing session on an established message).
    pub session_after: Vec<u8>,
    /// The next `(n, tag)` receive slots to register for this session.
    pub next_recv_tags: Vec<(u32, [u8; 32])>,
    /// Outstanding skipped messages after this open — records known to exist
    /// (their keys were stored) but not yet received. Drives a "N messages still
    /// arriving" hint in the UI; 0 on a fresh first-contact session.
    pub pending: u32,
}

/// The crypto engine. All methods are pure w.r.t. the passed-in state — the node
/// owns persistence — so an engine can be swapped without touching the indexer.
pub trait Engine: Send + Sync {
    /// Build the publishable key bundle for an identity (goes into the user's
    /// `data/users/<xid>/data.json`). Contains only public key material.
    fn publish_bundle(&self, id: &IdentitySecret, xid: &str) -> Value;

    /// Validate a peer's published bundle (structure + any self-signature).
    fn verify_bundle(&self, bundle: &Value) -> bool;

    /// Extract the identity key from a peer's published bundle, so the node can
    /// cross-check a first-contact record's transcript-bound `ik_a` (in
    /// [`Opened::ik_a`]) against the identity the sender CLAIMS to be. Returns
    /// `None` for a malformed bundle. This is the anti-spoofing hook: a
    /// first-contact message is trustworthy only if `sender_ik(published_bundle)
    /// == Some(opened.ik_a)`.
    fn sender_ik(&self, bundle: &Value) -> Option<[u8; 32]>;

    /// Begin a session to a peer as the initiator (X3DH). Returns the session
    /// state and the receive tags to register for the peer's replies.
    fn begin_session(
        &self,
        id: &IdentitySecret,
        peer_bundle: &Value,
        conv_id: [u8; 16],
    ) -> Result<Begun, EngineError>;

    /// Seal a plaintext onto an established session, advancing the ratchet. The
    /// engine decides internally whether this is the first-contact message.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        &self,
        session: &[u8],
        sender_xid: &str,
        members: &[String],
        subject: &str,
        body: &str,
        sent_ms: i64,
        buckets: &[usize],
    ) -> Result<Sealed, EngineError>;

    /// Cheap predicate: could this record be a first contact for `id`? MUST be
    /// O(1)-ish (one key agreement + a header check at most) — it runs for every
    /// pool record that misses the tag set.
    fn first_contact_candidate(&self, id: &IdentitySecret, tag: &[u8; 32], ct: &[u8]) -> bool;

    /// Open a first-contact record → a new session and the message.
    fn open_first(
        &self,
        id: &IdentitySecret,
        tag: &[u8; 32],
        ct: &[u8],
    ) -> Result<Opened, EngineError>;

    /// Open an established-session record whose `tag` matched at index `n`.
    fn open(&self, session: &[u8], n: u32, tag: &[u8; 32], ct: &[u8]) -> Result<Opened, EngineError>;
}

// ===========================================================================
// FakeEngine — deterministic, INSECURE test double.
// ===========================================================================

/// Number of lookahead receive tags a fresh session registers.
const FAKE_LOOKAHEAD: u32 = 8;

/// Magic prefix marking a first-contact header (masked on the wire).
const FC_MAGIC: [u8; 4] = *b"EMF1";

/// An insecure reference engine for pipeline tests. See the module docs.
#[derive(Default, Clone)]
pub struct FakeEngine;

/// The FakeEngine session blob (JSON): everything the fake needs to seal/open.
/// `role` is `"init"` or `"resp"`; `send_n`/`recv_n` are the next indices;
/// `fc_sent` (initiator only) tracks whether the first-contact message went out.
fn parse_session(bytes: &[u8]) -> Result<Value, EngineError> {
    serde_json::from_slice(bytes).map_err(|_| EngineError::BadState)
}

fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}
fn hex16(b: &[u8; 16]) -> String {
    hex::encode(b)
}
fn unhex32(s: &str) -> Result<[u8; 32], EngineError> {
    let v = hex::decode(s).map_err(|_| EngineError::BadState)?;
    v.try_into().map_err(|_| EngineError::BadState)
}
fn unhex16(s: &str) -> Result<[u8; 16], EngineError> {
    let v = hex::decode(s).map_err(|_| EngineError::Malformed)?;
    v.try_into().map_err(|_| EngineError::Malformed)
}

/// 32 random bytes via the crypt RNG (`new_seed` is a 32-byte hex string).
fn rand32() -> [u8; 32] {
    let v = hex::decode(epix_crypt::new_seed()).unwrap_or_else(|_| vec![0u8; 32]);
    let mut o = [0u8; 32];
    o.copy_from_slice(&v[..32]);
    o
}

fn pubid(seed: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("epix-channel-fake/pubid/v1", seed)
}

/// INSECURE symmetric "key agreement": a public hash of both identifiers. Real
/// ECDH is one-way; this exists only so both sides derive the same value in a
/// test. Do not mistake this for security.
fn fake_dh(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(lo);
    m.extend_from_slice(hi);
    blake3::derive_key("epix-channel-fake/dh/v1", &m)
}

fn keystream(context: &str, key: &[u8], len: usize) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key(context);
    h.update(key);
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

fn est_tag(conv: &[u8; 16], sender_pub: &[u8; 32], n: u32) -> [u8; 32] {
    let mut m = Vec::with_capacity(52);
    m.extend_from_slice(conv);
    m.extend_from_slice(sender_pub);
    m.extend_from_slice(&n.to_le_bytes());
    blake3::derive_key("epix-channel-fake/est-tag/v1", &m)
}
fn est_key(conv: &[u8; 16], sender_pub: &[u8; 32], n: u32) -> [u8; 32] {
    let mut m = Vec::with_capacity(52);
    m.extend_from_slice(conv);
    m.extend_from_slice(sender_pub);
    m.extend_from_slice(&n.to_le_bytes());
    blake3::derive_key("epix-channel-fake/est-key/v1", &m)
}

#[allow(clippy::too_many_arguments)]
fn payload_bytes(
    conv: &[u8; 16],
    from: &str,
    members: &[String],
    subject: &str,
    body: &str,
    sent_ms: i64,
    spub: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut o = json!({
        "c": hex16(conv), "f": from, "m": members, "s": subject, "b": body, "t": sent_ms
    });
    if let Some(p) = spub {
        o["p"] = json!(hex32(p));
    }
    serde_json::to_vec(&o).unwrap_or_default()
}

/// Pack `header || len32 || payload`, pad to the smallest fitting bucket, and
/// XOR-mask the whole thing with a keyed stream. `header` is the 4-byte FC magic
/// for first contact, empty for established.
fn pack_masked(
    context: &str,
    key: &[u8; 32],
    header: &[u8],
    payload: &[u8],
    buckets: &[usize],
) -> Result<Vec<u8>, EngineError> {
    let need = header.len() + 4 + payload.len();
    let bucket = buckets
        .iter()
        .copied()
        .filter(|&b| b >= need)
        .min()
        .ok_or(EngineError::TooBig)?;
    let mut buf = vec![0u8; bucket];
    buf[..header.len()].copy_from_slice(header);
    let len = payload.len() as u32;
    buf[header.len()..header.len() + 4].copy_from_slice(&len.to_le_bytes());
    buf[header.len() + 4..header.len() + 4 + payload.len()].copy_from_slice(payload);
    // padding bytes stay zero (before masking) — the mask hides them anyway.
    let ks = keystream(context, key, bucket);
    for (b, k) in buf.iter_mut().zip(ks.iter()) {
        *b ^= *k;
    }
    Ok(buf)
}

fn unpack_masked(
    context: &str,
    key: &[u8; 32],
    ct: &[u8],
    expect_magic: bool,
) -> Result<Value, EngineError> {
    let ks = keystream(context, key, ct.len());
    let mut plain = vec![0u8; ct.len()];
    for i in 0..ct.len() {
        plain[i] = ct[i] ^ ks[i];
    }
    let mut off = 0;
    if expect_magic {
        if plain.len() < 4 || plain[..4] != FC_MAGIC {
            return Err(EngineError::NotForMe);
        }
        off = 4;
    }
    if plain.len() < off + 4 {
        return Err(EngineError::Malformed);
    }
    let len =
        u32::from_le_bytes([plain[off], plain[off + 1], plain[off + 2], plain[off + 3]]) as usize;
    off += 4;
    if plain.len() < off + len {
        return Err(EngineError::Malformed);
    }
    serde_json::from_slice(&plain[off..off + len]).map_err(|_| EngineError::Malformed)
}

fn opened_from_payload(v: &Value, session_after: Vec<u8>) -> Result<Opened, EngineError> {
    let conv = unhex16(v.get("c").and_then(|x| x.as_str()).ok_or(EngineError::Malformed)?)?;
    Ok(Opened {
        conv_id: conv,
        sender_xid: v.get("f").and_then(|x| x.as_str()).map(String::from),
        ik_a: None,
        members: v
            .get("m")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        subject: v.get("s").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        body: v.get("b").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        sent_ms: v.get("t").and_then(|x| x.as_i64()).unwrap_or(0),
        session_after,
        next_recv_tags: Vec::new(),
        pending: 0,
    })
}

impl Engine for FakeEngine {
    fn publish_bundle(&self, id: &IdentitySecret, xid: &str) -> Value {
        json!({ "v": 0, "fake": true, "xid": xid, "pub": hex32(&pubid(&id.seed)) })
    }

    fn verify_bundle(&self, bundle: &Value) -> bool {
        bundle.get("fake").and_then(|v| v.as_bool()).unwrap_or(false)
            && bundle
                .get("pub")
                .and_then(|v| v.as_str())
                .map(|s| hex::decode(s).map(|b| b.len() == 32).unwrap_or(false))
                .unwrap_or(false)
    }

    fn sender_ik(&self, bundle: &Value) -> Option<[u8; 32]> {
        // The fake "identity key" is the bundle's `pub` (a hash of the seed) —
        // the same value carried as `ik_a` in a first-contact header.
        unhex32(bundle.get("pub").and_then(|v| v.as_str())?).ok()
    }

    fn begin_session(
        &self,
        id: &IdentitySecret,
        peer_bundle: &Value,
        conv_id: [u8; 16],
    ) -> Result<Begun, EngineError> {
        let me_pub = pubid(&id.seed);
        let peer_pub =
            unhex32(peer_bundle.get("pub").and_then(|v| v.as_str()).ok_or(EngineError::Malformed)?)?;
        let peer_xid = peer_bundle.get("xid").and_then(|v| v.as_str()).unwrap_or("");
        let session = json!({
            "c": hex16(&conv_id), "me": hex32(&me_pub), "peer": hex32(&peer_pub),
            "peer_xid": peer_xid, "role": "init", "send_n": 1, "recv_n": 0, "fc_sent": false,
        });
        // Register the responder's est replies (they start at n=0).
        let recv_tags = (0..FAKE_LOOKAHEAD)
            .map(|n| (n, est_tag(&conv_id, &peer_pub, n)))
            .collect();
        Ok(Begun { session: serde_json::to_vec(&session).unwrap(), recv_tags })
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
        let mut s = parse_session(session)?;
        let conv = unhex16(s["c"].as_str().ok_or(EngineError::BadState)?)?;
        let me_pub = unhex32(s["me"].as_str().ok_or(EngineError::BadState)?)?;
        let role = s["role"].as_str().unwrap_or("resp");
        let fc_sent = s["fc_sent"].as_bool().unwrap_or(true);
        let send_n = s["send_n"].as_u64().unwrap_or(0) as u32;

        if role == "init" && !fc_sent {
            // First-contact record: tag is the fresh ephemeral; key is the fake
            // DH of ephemeral × recipient pub; header carries the magic and the
            // sender's pub so the responder learns whom to tag replies to.
            let eph = rand32();
            let peer_pub = unhex32(s["peer"].as_str().ok_or(EngineError::BadState)?)?;
            let key = fake_dh(&eph, &peer_pub);
            let payload =
                payload_bytes(&conv, sender_xid, members, subject, body, sent_ms, Some(&me_pub));
            let ct = pack_masked("epix-channel-fake/fc", &key, &FC_MAGIC, &payload, buckets)?;
            s["fc_sent"] = json!(true);
            Ok(Sealed { tag: eph, ct, session_after: serde_json::to_vec(&s).unwrap() })
        } else {
            let tag = est_tag(&conv, &me_pub, send_n);
            let key = est_key(&conv, &me_pub, send_n);
            let payload = payload_bytes(&conv, sender_xid, members, subject, body, sent_ms, None);
            let ct = pack_masked("epix-channel-fake/est", &key, &[], &payload, buckets)?;
            s["send_n"] = json!(send_n + 1);
            Ok(Sealed { tag, ct, session_after: serde_json::to_vec(&s).unwrap() })
        }
    }

    fn first_contact_candidate(&self, id: &IdentitySecret, tag: &[u8; 32], ct: &[u8]) -> bool {
        if ct.len() < 4 {
            return false;
        }
        let key = fake_dh(tag, &pubid(&id.seed));
        let ks = keystream("epix-channel-fake/fc", &key, 4);
        let mut magic = [0u8; 4];
        for i in 0..4 {
            magic[i] = ct[i] ^ ks[i];
        }
        magic == FC_MAGIC
    }

    fn open_first(
        &self,
        id: &IdentitySecret,
        tag: &[u8; 32],
        ct: &[u8],
    ) -> Result<Opened, EngineError> {
        let me_pub = pubid(&id.seed);
        let key = fake_dh(tag, &me_pub);
        let v = unpack_masked("epix-channel-fake/fc", &key, ct, /*magic=*/ true)?;
        let peer_pub =
            unhex32(v.get("p").and_then(|x| x.as_str()).ok_or(EngineError::Malformed)?)?;
        let conv = unhex16(v.get("c").and_then(|x| x.as_str()).ok_or(EngineError::Malformed)?)?;
        let peer_xid = v.get("f").and_then(|x| x.as_str()).unwrap_or("");
        // Build the responder session; the initiator's subsequent est messages
        // start at n=1 (n=0 was this first-contact record).
        let session = json!({
            "c": hex16(&conv), "me": hex32(&me_pub), "peer": hex32(&peer_pub),
            "peer_xid": peer_xid, "role": "resp", "send_n": 0, "recv_n": 1, "fc_sent": false,
        });
        let mut opened = opened_from_payload(&v, serde_json::to_vec(&session).unwrap())?;
        // The transcript-bound sender identity, for the node's anti-spoof check.
        opened.ik_a = Some(peer_pub);
        opened.next_recv_tags = (1..1 + FAKE_LOOKAHEAD)
            .map(|n| (n, est_tag(&conv, &peer_pub, n)))
            .collect();
        Ok(opened)
    }

    fn open(&self, session: &[u8], n: u32, tag: &[u8; 32], ct: &[u8]) -> Result<Opened, EngineError> {
        let mut s = parse_session(session)?;
        let conv = unhex16(s["c"].as_str().ok_or(EngineError::BadState)?)?;
        let peer_pub = unhex32(s["peer"].as_str().ok_or(EngineError::BadState)?)?;
        // The matched tag must be the peer's est tag at n (defends the session
        // blob against a mismatched call).
        if &est_tag(&conv, &peer_pub, n) != tag {
            return Err(EngineError::NotForMe);
        }
        let key = est_key(&conv, &peer_pub, n);
        let v = unpack_masked("epix-channel-fake/est", &key, ct, /*magic=*/ false)?;
        let recv_n = s["recv_n"].as_u64().unwrap_or(0) as u32;
        let new_recv_n = recv_n.max(n + 1);
        s["recv_n"] = json!(new_recv_n);
        let mut opened = opened_from_payload(&v, serde_json::to_vec(&s).unwrap())?;
        // Sender of an established message is the session peer.
        opened.sender_xid = s["peer_xid"].as_str().map(String::from).filter(|x| !x.is_empty());
        // Top up the receive window.
        opened.next_recv_tags = (new_recv_n..new_recv_n + FAKE_LOOKAHEAD)
            .map(|m| (m, est_tag(&conv, &peer_pub, m)))
            .collect();
        Ok(opened)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_first_contact_roundtrip() {
        let e = FakeEngine;
        let alice = IdentitySecret::new(rand32());
        let bob = IdentitySecret::new(rand32());
        let bob_bundle = e.publish_bundle(&bob, "bob.epix");
        assert!(e.verify_bundle(&bob_bundle));

        let conv = [7u8; 16];
        let begun = e.begin_session(&alice, &bob_bundle, conv).unwrap();
        let buckets = [256usize, 1024, 4096];
        let sealed =
            e.seal(&begun.session, "alice.epix", &[], "Hi", "meet at ZXQ1", 1000, &buckets).unwrap();

        // Bob detects and opens.
        assert!(e.first_contact_candidate(&bob, &sealed.tag, &sealed.ct));
        // A stranger does not.
        let eve = IdentitySecret::new(rand32());
        assert!(!e.first_contact_candidate(&eve, &sealed.tag, &sealed.ct));

        let opened = e.open_first(&bob, &sealed.tag, &sealed.ct).unwrap();
        assert_eq!(opened.subject, "Hi");
        assert_eq!(opened.body, "meet at ZXQ1");
        assert_eq!(opened.sender_xid.as_deref(), Some("alice.epix"));
        assert_eq!(opened.conv_id, conv);
        assert!(!opened.next_recv_tags.is_empty());

        // The ciphertext must not contain the plaintext marker (masking works).
        assert!(!sealed.ct.windows(4).any(|w| w == b"ZXQ1"));
    }

    #[test]
    fn fake_established_reply_roundtrip() {
        let e = FakeEngine;
        let alice = IdentitySecret::new(rand32());
        let bob = IdentitySecret::new(rand32());
        let conv = [3u8; 16];
        let buckets = [256usize, 1024];

        // Alice → Bob first contact.
        let a_begin = e.begin_session(&alice, &e.publish_bundle(&bob, "bob.epix"), conv).unwrap();
        let a_fc = e.seal(&a_begin.session, "alice.epix", &[], "s", "body", 1, &buckets).unwrap();
        let b_open = e.open_first(&bob, &a_fc.tag, &a_fc.ct).unwrap();

        // Bob replies on the established session; Alice detects via her begin tags.
        let b_reply = e.seal(&b_open.session_after, "bob.epix", &[], "re", "reply-1", 2, &buckets).unwrap();
        // Alice's begin registered est_tag(conv, bob_pub, 0); the reply used n=0.
        let expected0 = a_begin.recv_tags.iter().find(|(n, _)| *n == 0).unwrap().1;
        assert_eq!(b_reply.tag, expected0, "reply tag matches Alice's expected recv tag");

        let a_open = e.open(&a_begin.session, 0, &b_reply.tag, &b_reply.ct).unwrap();
        assert_eq!(a_open.body, "reply-1");
        assert_eq!(a_open.sender_xid.as_deref(), Some("bob.epix"));
    }
}
