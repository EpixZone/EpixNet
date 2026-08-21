//! Single-record multi-key transport — the count-hiding envelope.
//!
//! A naive fan-out posts one pool record per recipient device, so the number of
//! records in a send burst leaks the recipient's (public, on-chain) linked-device
//! count to a peer who can batch-count the push — deanonymizing a recipient whose
//! count is unique (see `docs/channel-multi-device.md`, `docs/channel-count-privacy.md`).
//!
//! This module packs a send into ONE pool record with a FIXED number of slots
//! ([`SLOTS`]), so the observable width is constant regardless of how many devices
//! or recipients a message actually reaches:
//!
//! ```text
//!   ct = [ SLOTS × 32B detection-tag ]        (real device tags + random dummies)
//!        [ SLOTS × KEYSLOT_LEN keyslot ]       (per-device pairwise seal of K_msg)
//!        [ 4B body_len ][ body_ct ]            (ONE shared AEAD body under K_msg)
//!        [ random pad → the record's pad bucket ]
//! ```
//!
//! The record's public `tag` field is a FRESH RANDOM routing value (shard
//! placement only) — detection tags live inside `ct`, so the frozen `epix-pool-1`
//! primitive is unchanged. Each recipient device scans the SLOTS tags for one of
//! its own, opens the matching keyslot with its normal per-device pairwise session
//! (Double Ratchet, forward secrecy and the sealed-sender anti-spoof all
//! preserved — the ratchet engine is untouched), recovers `K_msg`, and decrypts
//! the one shared body. Dummy slots are uniform random bytes, indistinguishable
//! from real ones, so an observer sees a constant `SLOTS`-wide record every time.

use crate::engine::{Engine, IdentitySecret};
use crate::indexer::SendResult;
use crate::store::EnvelopeStore;
use base64::Engine as _;
use epix_core::{Error, Result};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use epix_content::pool::{self, PoolRule};
use epix_content::record::record_signed_data;
use serde_json::{json, Value};

/// Fixed number of slots every record carries. Hides device+recipient counts up
/// to this many destinations in one record; larger sends span multiple records
/// (leaking only ">SLOTS"). Must match on send and receive.
pub const SLOTS: usize = 8;

/// Detection-tag length (bytes).
const TAG_LEN: usize = 32;

/// Fixed per-device keyslot length. Every keyslot is a pairwise seal padded to
/// this single bucket, so first-contact and established keyslots are byte-equal
/// and indistinguishable from a random dummy. Must exceed the first-contact
/// header block (144) + AEAD tag + framing + the 64-byte key payload.
pub const KEYSLOT_LEN: usize = 512;

/// The plaintext a keyslot carries: the message key + a binding hash of the
/// shared body (so a device can't be fed a substituted body). 32 + 32.
const KEYSLOT_PAYLOAD: usize = 64;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
fn b64d(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// 32 fresh random bytes via the crypt RNG. Panics rather than degrading to a
/// zero vector on RNG failure: a zero `K_msg` under the fixed zero nonce would be
/// catastrophic keystream reuse across messages, so a silent fallback is a footgun
/// we refuse. `new_seed()` already panics on OS-RNG failure and always returns
/// valid hex, so this is unreachable in practice — but fail closed regardless.
fn rand32() -> [u8; 32] {
    let v = hex::decode(epix_crypt::new_seed()).expect("crypt RNG returned invalid hex");
    let mut o = [0u8; 32];
    o.copy_from_slice(&v[..32]);
    o
}

/// Random bytes of arbitrary length (concatenated 32-byte draws).
fn rand_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(&rand32());
    }
    out.truncate(len);
    out
}

/// Fisher-Yates shuffle of the paired (tag, keyslot) slots in lockstep, using
/// fresh RNG bytes. Only reorders positions (not a security primitive) — SLOTS is
/// small so 32 random bytes are ample.
fn shuffle_pairs(tags: &mut [[u8; 32]], keyslots: &mut [Vec<u8>]) {
    let r = rand32();
    let n = tags.len();
    for i in (1..n).rev() {
        let j = (r[i % 32] as usize) % (i + 1);
        tags.swap(i, j);
        keyslots.swap(i, j);
    }
}

// --- shared body AEAD -------------------------------------------------------
// The message (subject/body/members/sender/time) encrypted ONCE under a fresh
// per-message key `K_msg`. K_msg is single-use, so a zero nonce is safe; the body
// is bound to the keyslots by the hash carried inside each keyslot, so no AD is
// needed. ChaCha20-Poly1305 — the same primitive the ratchet uses.

fn seal_body(k_msg: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*k_msg));
    cipher
        .encrypt(&Nonce::from([0u8; 12]), Payload { msg: plaintext, aad: &[] })
        .unwrap_or_default()
}

fn open_body(k_msg: &[u8; 32], body_ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*k_msg));
    cipher.decrypt(&Nonce::from([0u8; 12]), Payload { msg: body_ct, aad: &[] }).ok()
}

/// The cleartext of the shared body: everything the engine's per-slot seal used
/// to carry, now shared across all slots. `f` = sender xID, `t` = sent_ms.
fn encode_body_plain(sender_xid: &str, members: &[String], subject: &str, body: &str, sent_ms: i64) -> Vec<u8> {
    json!({ "f": sender_xid, "m": members, "s": subject, "b": body, "t": sent_ms })
        .to_string()
        .into_bytes()
}

/// The decrypted shared body: `(sender_xid, members, subject, body, sent_ms)`.
pub struct BodyPlain {
    pub sender_xid: String,
    pub members: Vec<String>,
    pub subject: String,
    pub body: String,
    pub sent_ms: i64,
}

fn decode_body_plain(bytes: &[u8]) -> Option<BodyPlain> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    Some(BodyPlain {
        sender_xid: v.get("f").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        members: v
            .get("m")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|m| m.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        subject: v.get("s").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        body: v.get("b").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        sent_ms: v.get("t").and_then(|x| x.as_i64()).unwrap_or(0),
    })
}

/// Encode the per-slot keyslot plaintext (what the engine seals): `K_msg ‖ H(body_ct)`.
fn keyslot_plain(k_msg: &[u8; 32], body_ct: &[u8]) -> String {
    let mut p = Vec::with_capacity(KEYSLOT_PAYLOAD);
    p.extend_from_slice(k_msg);
    p.extend_from_slice(blake3::hash(body_ct).as_bytes());
    b64(&p)
}

/// Recover `(K_msg, body_hash)` from an opened keyslot's payload.
pub fn parse_keyslot_plain(opened_body: &str) -> Option<([u8; 32], [u8; 32])> {
    let raw = b64d(opened_body)?;
    if raw.len() != KEYSLOT_PAYLOAD {
        return None;
    }
    let mut k = [0u8; 32];
    let mut h = [0u8; 32];
    k.copy_from_slice(&raw[..32]);
    h.copy_from_slice(&raw[32..64]);
    Some((k, h))
}

// --- ct framing -------------------------------------------------------------

/// The parsed public structure of a multi-slot `ct`: the SLOTS detection tags,
/// the SLOTS keyslots, and the shared body ciphertext.
pub struct Unpacked {
    pub tags: Vec<[u8; 32]>,
    pub keyslots: Vec<Vec<u8>>,
    pub body_ct: Vec<u8>,
}

fn pack_ct(tags: &[[u8; 32]], keyslots: &[Vec<u8>], body_ct: &[u8], buckets: &[usize]) -> Result<Vec<u8>> {
    let header = SLOTS * TAG_LEN + SLOTS * KEYSLOT_LEN + 4;
    let need = header + body_ct.len();
    let bucket = buckets.iter().copied().filter(|&b| b >= need).min().ok_or_else(|| {
        Error::Protocol(format!("multislot ct {need}B exceeds all pad buckets"))
    })?;
    let mut ct = Vec::with_capacity(bucket);
    for t in tags {
        ct.extend_from_slice(t);
    }
    for k in keyslots {
        ct.extend_from_slice(k);
    }
    ct.extend_from_slice(&(body_ct.len() as u32).to_be_bytes());
    ct.extend_from_slice(body_ct);
    ct.extend_from_slice(&rand_bytes(bucket - ct.len()));
    Ok(ct)
}

/// Parse a multi-slot `ct`. Returns `None` if the bytes are too short to be one
/// (a foreign/legacy record) — the caller treats that as "not for me".
pub fn unpack_ct(ct: &[u8]) -> Option<Unpacked> {
    let tags_end = SLOTS * TAG_LEN;
    let keys_end = tags_end + SLOTS * KEYSLOT_LEN;
    if ct.len() < keys_end + 4 {
        return None;
    }
    let mut tags = Vec::with_capacity(SLOTS);
    for i in 0..SLOTS {
        let mut t = [0u8; 32];
        t.copy_from_slice(&ct[i * TAG_LEN..(i + 1) * TAG_LEN]);
        tags.push(t);
    }
    let mut keyslots = Vec::with_capacity(SLOTS);
    for i in 0..SLOTS {
        let off = tags_end + i * KEYSLOT_LEN;
        keyslots.push(ct[off..off + KEYSLOT_LEN].to_vec());
    }
    let body_len =
        u32::from_be_bytes([ct[keys_end], ct[keys_end + 1], ct[keys_end + 2], ct[keys_end + 3]]) as usize;
    let body_start = keys_end + 4;
    if body_start + body_len > ct.len() {
        return None;
    }
    let body_ct = ct[body_start..body_start + body_len].to_vec();
    Some(Unpacked { tags, keyslots, body_ct })
}

/// Verify a keyslot's body-binding hash against the actual shared body, then
/// decrypt it. Rejects a substituted body. Returns the decoded plaintext fields.
pub fn open_shared_body(k_msg: &[u8; 32], body_hash: &[u8; 32], body_ct: &[u8]) -> Option<BodyPlain> {
    if blake3::hash(body_ct).as_bytes() != body_hash {
        return None;
    }
    decode_body_plain(&open_body(k_msg, body_ct)?)
}

/// One recipient device destination for a send: its published key bundle.
pub struct Dest {
    pub bundle: Value,
}

/// A fully sealed record whose ratchet mutations have not been persisted yet.
/// Callers that split one logical message across several records batch-commit
/// these only after every chunk and optional RLN proof has succeeded.
#[derive(Debug, Clone)]
pub struct PreparedSend {
    pub commit: crate::store::OutboundCommit,
    pub epoch: i64,
}

/// Proof bytes plus the durable allowance range used to create them. Production
/// channel sends retain the reservation so an outbox retry can prove the same
/// ciphertext against a refreshed root without spending a new range.
pub struct RlnProofMaterial {
    pub proof: Vec<u8>,
    pub reservation: Option<crate::store::RlnReservation>,
}

/// Seal a message to MANY recipient devices as ONE count-hiding pool record.
///
/// `dests` is the flat list of recipient-device bundles (every device of every
/// recipient). Each becomes one real slot; the record is padded to [`SLOTS`]
/// with random dummy slots. All destinations share one AEAD body under a fresh
/// `K_msg`; each real slot is a normal pairwise seal of `K_msg` on that device's
/// session (so per-device forward secrecy / anti-spoof are unchanged). The
/// sender's own copy is recorded once iff `record_own`.
///
/// Fails if `dests.len() > SLOTS` (the caller chunks larger sends).
#[allow(clippy::too_many_arguments)]
fn prepare_multi_inner<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
    rln_prover: Option<&dyn Fn(&[u8], i64) -> std::result::Result<RlnProofMaterial, String>>,
) -> Result<PreparedSend> {
    if dests.is_empty() || dests.len() > SLOTS {
        return Err(Error::Protocol(format!(
            "send_multi: {} destinations, must be 1..={SLOTS}",
            dests.len()
        )));
    }

    // Validate the complete destination set before beginning any session or
    // sealing any slot. Silently dropping one malformed bundle would turn an
    // intended multi-recipient send into a partial delivery. If every bundle
    // were malformed, it would also produce a valid-looking dummy-only record.
    let peer_iks = dests
        .iter()
        .enumerate()
        .map(|(index, dest)| {
            engine
                .sender_ik(&dest.bundle)
                .map(hex::encode)
                .ok_or_else(|| {
                    Error::Protocol(format!(
                        "send_multi: destination {index} has no usable identity key"
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;
    let conv_hex = hex::encode(conv_id);

    // ONE shared body under a fresh single-use key.
    let k_msg = rand32();
    let body_plain = encode_body_plain(my_xid, members, subject, body, now_ms);
    let body_ct = seal_body(&k_msg, &body_plain);
    let ks_plain = keyslot_plain(&k_msg, &body_ct);

    // One real slot per destination device: a normal pairwise seal of the tiny
    // key payload, padded to the fixed keyslot bucket.
    let mut tags: Vec<[u8; 32]> = Vec::with_capacity(SLOTS);
    let mut keyslots: Vec<Vec<u8>> = Vec::with_capacity(SLOTS);
    let mut sessions: Vec<crate::store::OutboundSession> = Vec::with_capacity(dests.len());
    let ks_buckets = [KEYSLOT_LEN];
    for (dest, peer_ik) in dests.iter().zip(peer_iks) {
        let peer_xid = dest
            .bundle
            .get("xid")
            .and_then(|v| v.as_str())
            .map(String::from);
        let peer_auth = dest
            .bundle
            .get("auth")
            .and_then(|v| v.as_str())
            .map(String::from);
        // Leg key: the peer DEVICE's identity key. A recipient's multiple devices
        // share one human `xid` but have distinct identity keys; keying the session
        // by the device key (not the name) gives each device its own ratchet —
        // otherwise device 2 reuses device 1's session, seals a keyslot device 2
        // can't open, and double-advances this sender's ratchet. Read it through
        // the engine (matches the recv side's `ik_a` and stays engine-agnostic).
        let existing = store.session_id_for_leg(identity_id, &conv_hex, &peer_ik)?;
        let (session_id, session_blob, recv_tags) = match existing {
            Some(sid) => (Some(sid), store.session_ratchet(sid)?, Vec::new()),
            None => {
                let begun =
                    engine.begin_session(id_secret, &dest.bundle, conv_id).map_err(crate::indexer::eng_err)?;
                let recv = crate::indexer::to_tag_vecs(&begun.recv_tags);
                (None, begun.session, recv)
            }
        };
        // sender_xid / members / subject / sent_ms all travel in the SHARED body;
        // the keyslot carries only the key material, keeping every keyslot small
        // and identical in size.
        let sealed = engine
            .seal(&session_blob, "", &[], "", &ks_plain, 0, &ks_buckets)
            .map_err(crate::indexer::eng_err)?;
        if sealed.ct.len() != KEYSLOT_LEN {
            return Err(Error::Protocol(format!(
                "keyslot sealed to {}B, expected {KEYSLOT_LEN}B",
                sealed.ct.len()
            )));
        }
        // Do not persist this advance yet. The exact signed record and every
        // session mutation land together below, after all remaining fallible
        // work (padding, RLN proof, PoW, and signing) has succeeded.
        sessions.push(crate::store::OutboundSession {
            session_id,
            identity_id,
            conv_id: conv_hex.clone(),
            peer_xid,
            peer_ik,
            peer_auth,
            role: "init".into(),
            ratchet_before: session_id.map(|_| session_blob),
            ratchet_after: sealed.session_after,
            established_ms: now_ms,
            recv_tags,
        });
        tags.push(sealed.tag);
        keyslots.push(sealed.ct);
    }

    // Pad to SLOTS with indistinguishable random dummies (uniform tag + uniform
    // keyslot-sized bytes, matching the AEAD-random real ones).
    while tags.len() < SLOTS {
        tags.push(rand32());
        keyslots.push(rand_bytes(KEYSLOT_LEN));
    }

    // Defense-in-depth: shuffle real and dummy slots together so real slots are
    // NOT a fixed 0..n prefix. Count-hiding rests on real/dummy content being
    // indistinguishable; shuffling means even if that ever regressed, the count
    // could not be read off slot positions. The receiver scans all slots, so
    // order is irrelevant to delivery.
    shuffle_pairs(&mut tags, &mut keyslots);

    let ct = pack_ct(&tags, &keyslots, &body_ct, &rule.pad_buckets)?;

    // The public record: a FRESH random routing tag (detection tags are inside ct)
    // under a FRESH throwaway author.
    let epoch = pool::epoch_now(now_ms);
    let route_tag = rand32();
    let author_pk = epix_crypt::new_seed();
    let author = epix_crypt::privatekey_to_address(&author_pk).map_err(Error::Crypt)?;
    let mut record = json!({
        "v": 1,
        "epoch": epoch,
        "tag": b64(&route_tag),
        "ct": b64(&ct),
        "pow": 0,
        "author": author,
    });
    // Anonymous rate-limiting: where the pool requires it, attach the RLN proof
    // BEFORE PoW/sign so both cover it. The proof binds to `ct` + `epoch`; the
    // caller's prover produces it (it holds the member identity + membership).
    let mut rln_reservation = None;
    if rule.rln_required {
        let prove = rln_prover.ok_or_else(|| {
            Error::Protocol("pool requires an RLN proof but no prover was supplied".into())
        })?;
        let material = prove(&ct, epoch)
            .map_err(|e| Error::Protocol(format!("rln proof generation failed: {e}")))?;
        record["rln"] = json!(b64(&material.proof));
        rln_reservation = material.reservation;
    }

    pool::solve_pow(&mut record, rule.pow_bits);
    let sig = epix_crypt::sign(&record_signed_data(&record), &author_pk).map_err(Error::Crypt)?;
    record["sign"] = json!(sig);

    let shard_path = pool::shard_path(rule, epoch, &route_tag);
    let sent = record_own.then(|| crate::store::OutboundMessage {
        identity_id,
        conv_id: conv_hex,
        peer_xid: None,
        members: members.to_vec(),
        sender_xid: my_xid.to_string(),
        subject: subject.to_string(),
        body: body.to_string(),
        sent_ms: now_ms,
    });
    let commit = crate::store::OutboundCommit {
        sessions,
        record: record.clone(),
        shard_path: shard_path.clone(),
        created_ms: now_ms,
        next_attempt_ms,
        recovery: crate::store::OutboundRecovery {
            author_private_key: author_pk,
            rln: rln_reservation,
        },
        sent,
    };
    Ok(PreparedSend { commit, epoch })
}

#[allow(clippy::too_many_arguments)]
fn send_multi_inner<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
    rln_prover: Option<&dyn Fn(&[u8], i64) -> std::result::Result<RlnProofMaterial, String>>,
) -> Result<SendResult> {
    let prepared = prepare_multi_inner(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        next_attempt_ms,
        rule,
        record_own,
        rln_prover,
    )?;
    let record = prepared.commit.record.clone();
    let shard_path = prepared.commit.shard_path.clone();
    let (outbox_id, msg_id) = store.commit_outbound(&prepared.commit)?;
    Ok(SendResult {
        record,
        shard_path,
        epoch: prepared.epoch,
        msg_id,
        outbox_id,
    })
}

/// Seal to multiple destinations for a PoW-only pool. See [`send_multi_inner`]
/// for the mechanics; this is the common entry point.
#[allow(clippy::too_many_arguments)]
pub fn send_multi<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    rule: &PoolRule,
    record_own: bool,
) -> Result<SendResult> {
    send_multi_scheduled(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        now_ms,
        rule,
        record_own,
    )
}

/// [`send_multi`] with a durable earliest transport-attempt timestamp. The
/// signed record and this timestamp are committed atomically, so send-origin
/// and burst jitter survive process restart.
#[allow(clippy::too_many_arguments)]
pub fn send_multi_scheduled<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
) -> Result<SendResult> {
    send_multi_inner(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        next_attempt_ms,
        rule,
        record_own,
        None,
    )
}

/// Seal one chunk without mutating the store. A caller must commit the returned
/// value, normally with [`EnvelopeStore::commit_outbound_batch`].
#[allow(clippy::too_many_arguments)]
pub fn prepare_multi_scheduled<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
) -> Result<PreparedSend> {
    prepare_multi_inner(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        next_attempt_ms,
        rule,
        record_own,
        None,
    )
}

/// Like [`send_multi`], but for a pool whose rule sets `rln_required`:
/// `rln_prover(ct, epoch)` returns the RLN proof blob to attach to the record.
/// The proof is bound to `ct` + `epoch` and is covered by the record's PoW and
/// signature. The prover holds the member identity and membership (see
/// `epix-rln`'s `PoolGate::prove`).
#[allow(clippy::too_many_arguments)]
pub fn send_multi_with_rln<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    rule: &PoolRule,
    record_own: bool,
    rln_prover: &dyn Fn(&[u8], i64) -> std::result::Result<Vec<u8>, String>,
) -> Result<SendResult> {
    send_multi_with_rln_scheduled(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        now_ms,
        rule,
        record_own,
        rln_prover,
    )
}

/// [`send_multi_with_rln`] with a durable earliest transport-attempt timestamp.
#[allow(clippy::too_many_arguments)]
pub fn send_multi_with_rln_scheduled<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
    rln_prover: &dyn Fn(&[u8], i64) -> std::result::Result<Vec<u8>, String>,
) -> Result<SendResult> {
    let adapted = |ct: &[u8], epoch: i64| {
        rln_prover(ct, epoch).map(|proof| RlnProofMaterial {
            proof,
            reservation: None,
        })
    };
    send_multi_inner(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        next_attempt_ms,
        rule,
        record_own,
        Some(&adapted),
    )
}

/// RLN variant of [`prepare_multi_scheduled`]. Proofs and signatures are fully
/// produced, but no session or outbox state is persisted yet.
#[allow(clippy::too_many_arguments)]
pub fn prepare_multi_with_rln_scheduled<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
    rln_prover: &dyn Fn(&[u8], i64) -> std::result::Result<Vec<u8>, String>,
) -> Result<PreparedSend> {
    let adapted = |ct: &[u8], epoch: i64| {
        rln_prover(ct, epoch).map(|proof| RlnProofMaterial {
            proof,
            reservation: None,
        })
    };
    prepare_multi_inner(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        next_attempt_ms,
        rule,
        record_own,
        Some(&adapted),
    )
}

/// Production RLN prepare path with a durable allowance reservation attached
/// to the transactional outbox row.
#[allow(clippy::too_many_arguments)]
pub fn prepare_multi_with_rln_reserved_scheduled<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    dests: &[Dest],
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    next_attempt_ms: i64,
    rule: &PoolRule,
    record_own: bool,
    rln_prover: &dyn Fn(&[u8], i64) -> std::result::Result<RlnProofMaterial, String>,
) -> Result<PreparedSend> {
    prepare_multi_inner(
        store,
        engine,
        identity_id,
        id_secret,
        my_xid,
        members,
        dests,
        conv_id,
        subject,
        body,
        now_ms,
        next_attempt_ms,
        rule,
        record_own,
        Some(rln_prover),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct TrackingStore {
        session_lookups: AtomicUsize,
        outbound_commits: AtomicUsize,
    }

    fn unexpected_store_access<T>() -> Result<T> {
        panic!("unexpected store access")
    }

    impl EnvelopeStore for TrackingStore {
        fn is_processed(&self, _sign_h: &[u8], _identity_id: i64) -> Result<bool> {
            unexpected_store_access()
        }

        fn mark_processed(&self, _sign_h: &[u8], _identity_id: i64) -> Result<()> {
            unexpected_store_access()
        }

        fn session_for_tag(&self, _tag: &[u8]) -> Result<Option<crate::store::SessionMatch>> {
            unexpected_store_access()
        }

        fn session_ratchet(&self, _session_id: i64) -> Result<Vec<u8>> {
            unexpected_store_access()
        }

        fn session_id_for_leg(
            &self,
            _identity_id: i64,
            _conv_id: &str,
            _peer_ik: &str,
        ) -> Result<Option<i64>> {
            self.session_lookups.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn create_session(&self, _session: crate::store::NewSession<'_>) -> Result<i64> {
            unexpected_store_access()
        }

        fn update_session_ratchet(&self, _session_id: i64, _ratchet: &[u8]) -> Result<()> {
            unexpected_store_access()
        }

        fn commit_outbound(&self, _commit: &crate::store::OutboundCommit) -> Result<(i64, i64)> {
            self.outbound_commits.fetch_add(1, Ordering::SeqCst);
            Ok((1, 1))
        }

        fn commit_outbound_batch(
            &self,
            _commits: &[crate::store::OutboundCommit],
        ) -> Result<Vec<(i64, i64)>> {
            unexpected_store_access()
        }

        fn commit_inbound(&self, _commit: &crate::store::InboundCommit) -> Result<Option<i64>> {
            unexpected_store_access()
        }

        #[allow(clippy::too_many_arguments)]
        fn insert_sent(
            &self,
            _identity_id: i64,
            _conv_id: &str,
            _peer_xid: Option<&str>,
            _members: &[String],
            _sender_xid: &str,
            _subject: &str,
            _body: &str,
            _sent_ms: i64,
        ) -> Result<i64> {
            unexpected_store_access()
        }

        fn unread_count(&self, _identity_id: i64) -> Result<i64> {
            unexpected_store_access()
        }
    }

    fn test_rule() -> PoolRule {
        PoolRule {
            dir: "pool".into(),
            class: pool::POOL_RECORD_FORMAT.into(),
            since_week: 0,
            fanout: 16,
            pow_bits: 0,
            pad_buckets: vec![8192],
            max_record_bytes: 16_384,
            max_shard_bytes: 1_000_000,
            newest_first: true,
            rln_required: false,
            retention_weeks: 0,
        }
    }

    fn send_to_destinations(store: &TrackingStore, dests: &[Dest]) -> Result<SendResult> {
        send_multi(
            store,
            &crate::engine::FakeEngine,
            1,
            &IdentitySecret::new([1u8; 32]),
            "alice.epix",
            &["alice.epix".into(), "bob.epix".into()],
            dests,
            [7u8; 16],
            "subject",
            "body",
            1_780_000_000_000,
            &test_rule(),
            true,
        )
    }

    #[test]
    fn ct_round_trips_tags_keyslots_and_body() {
        let tags: Vec<[u8; 32]> = (0..SLOTS).map(|i| [i as u8; 32]).collect();
        let keyslots: Vec<Vec<u8>> = (0..SLOTS).map(|i| vec![i as u8; KEYSLOT_LEN]).collect();
        let body_ct = b"hello shared body".to_vec();
        let ct = pack_ct(&tags, &keyslots, &body_ct, &[8192, 32768]).unwrap();
        // Padded to the smallest fitting bucket, indistinguishable width.
        assert_eq!(ct.len(), 8192);
        let u = unpack_ct(&ct).unwrap();
        assert_eq!(u.tags, tags);
        assert_eq!(u.keyslots, keyslots);
        assert_eq!(u.body_ct, body_ct);
    }

    #[test]
    fn pack_fails_when_no_bucket_fits() {
        let tags: Vec<[u8; 32]> = (0..SLOTS).map(|_| [0u8; 32]).collect();
        let keyslots: Vec<Vec<u8>> = (0..SLOTS).map(|_| vec![0u8; KEYSLOT_LEN]).collect();
        // The fixed keyslot overhead alone exceeds a tiny bucket.
        assert!(pack_ct(&tags, &keyslots, &[], &[1024]).is_err());
    }

    #[test]
    fn shared_body_binding_rejects_a_substituted_body() {
        let k_msg = [7u8; 32];
        let plain = encode_body_plain("alice.epix", &["bob.epix".into()], "subj", "body ZXQ", 42);
        let body_ct = seal_body(&k_msg, &plain);
        let hash = *blake3::hash(&body_ct).as_bytes();

        // Correct body under the right key + hash decrypts to the right fields.
        let bp = open_shared_body(&k_msg, &hash, &body_ct).expect("authentic body opens");
        assert_eq!(bp.sender_xid, "alice.epix");
        assert_eq!(bp.body, "body ZXQ");
        assert_eq!(bp.sent_ms, 42);

        // A DIFFERENT body (attacker swap) fails the hash binding even though the
        // key is right — no substituted body is ever accepted.
        let other = seal_body(&k_msg, &encode_body_plain("alice.epix", &[], "", "EVIL", 0));
        assert!(open_shared_body(&k_msg, &hash, &other).is_none(), "swapped body rejected");

        // Wrong key fails the AEAD.
        assert!(open_shared_body(&[9u8; 32], &hash, &body_ct).is_none(), "wrong key rejected");
    }

    #[test]
    fn keyslot_payload_round_trips() {
        let k_msg = [3u8; 32];
        let body_ct = b"body".to_vec();
        let encoded = keyslot_plain(&k_msg, &body_ct);
        let (k, h) = parse_keyslot_plain(&encoded).unwrap();
        assert_eq!(k, k_msg);
        assert_eq!(&h, blake3::hash(&body_ct).as_bytes());
    }

    #[test]
    fn one_invalid_destination_aborts_before_any_recipient_state_is_touched() {
        let engine = crate::engine::FakeEngine;
        let valid = engine.publish_bundle(&IdentitySecret::new([2u8; 32]), "bob.epix");
        let dests = vec![
            Dest { bundle: valid },
            Dest {
                bundle: json!({ "xid": "carol.epix" }),
            },
        ];
        let store = TrackingStore::default();

        let err =
            send_to_destinations(&store, &dests).expect_err("mixed destination set must fail");

        assert!(matches!(err, Error::Protocol(message) if message.contains("destination 1")));
        assert_eq!(store.session_lookups.load(Ordering::SeqCst), 0);
        assert_eq!(store.outbound_commits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invalid_only_destination_cannot_create_a_dummy_only_record() {
        let dests = vec![Dest {
            bundle: json!({ "xid": "bob.epix" }),
        }];
        let store = TrackingStore::default();

        let err = send_to_destinations(&store, &dests).expect_err("dummy-only send must fail");

        assert!(matches!(err, Error::Protocol(message) if message.contains("destination 0")));
        assert_eq!(store.session_lookups.load(Ordering::SeqCst), 0);
        assert_eq!(store.outbound_commits.load(Ordering::SeqCst), 0);
    }
}
