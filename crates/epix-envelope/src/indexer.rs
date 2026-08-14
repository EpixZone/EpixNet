//! The trial-decrypt receive path and the seal-and-post send path.
//!
//! [`process_record`] is what the background indexer runs for every inbound pool
//! record: a two-tier match (O(1) detection-tag lookup for established sessions;
//! a cheap first-contact probe per identity otherwise), and on a hit it commits
//! the decrypted message + session/tag advance atomically into the private
//! index. [`send_message`] does the reverse: seal onto a session, build a valid
//! `epix-pool-1` record under a fresh throwaway author (PoW + sign), and write
//! the sender's OWN copy straight to the private index (never posted encrypted-
//! to-self). Neither ever exposes key material.

use crate::engine::{Engine, EngineError, IdentitySecret};
use crate::store::{EnvelopeStore, InboundCommit};
use base64::Engine as _;
use epix_content::pool::PoolRule;
use epix_core::{Error, Result};
use serde_json::Value;

/// The outcome of trial-processing one pool record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// The record's signature was already indexed (idempotent replay / rescan).
    AlreadyProcessed,
    /// Malformed, or not addressed to any local identity.
    NoMatch,
    /// A message was decrypted and indexed.
    Indexed {
        msg_id: i64,
        identity_id: i64,
        conv_id: String,
        sender_xid: Option<String>,
        subject: String,
        snippet: String,
        unread: i64,
        first_contact: bool,
        /// Outstanding skipped messages after this open (a delivery-gap hint).
        pending: u32,
    },
}

/// The result of sealing and posting an outbound message.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// The `epix-pool-1` record to append to the pool + flood to peers.
    pub record: Value,
    /// The inner path of the shard the record belongs in.
    pub shard_path: String,
    /// The day epoch the record was stamped with.
    pub epoch: i64,
    /// The row id of the sender's own copy in the private index.
    pub msg_id: i64,
}

pub(crate) fn eng_err(e: EngineError) -> Error {
    Error::Protocol(format!("envelope engine: {e:?}"))
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// 16-byte blake3 prefix of a pool signature — the `processed` / `sign_h` key.
fn sign_h(sign: &str) -> Vec<u8> {
    blake3::hash(sign.as_bytes()).as_bytes()[..16].to_vec()
}

pub(crate) fn to_tag_vecs(tags: &[(u32, [u8; 32])]) -> Vec<(u32, Vec<u8>)> {
    tags.iter().map(|(n, t)| (*n, t.to_vec())).collect()
}

/// Seal `subject`/`body` to a SINGLE `peer_bundle` on conversation `conv_id`.
/// A thin convenience wrapper over [`crate::multislot::send_multi`] with one
/// destination — it produces a normal fixed-width multi-slot record (one real
/// slot + dummies), so the receiver's [`process_record`] reads it unchanged.
/// Real sends fan out via `send_multi` directly (all a recipient's devices, all
/// recipients) so the record count never leaks the destination count.
#[allow(clippy::too_many_arguments)]
pub fn send_message<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    identity_id: i64,
    id_secret: &IdentitySecret,
    my_xid: &str,
    members: &[String],
    peer_bundle: &Value,
    conv_id: [u8; 16],
    subject: &str,
    body: &str,
    now_ms: i64,
    rule: &PoolRule,
    record_own: bool,
) -> Result<SendResult> {
    let dests = [crate::multislot::Dest { bundle: peer_bundle.clone() }];
    crate::multislot::send_multi(
        store, engine, identity_id, id_secret, my_xid, members, &dests, conv_id, subject, body,
        now_ms, rule, record_own,
    )
}

/// Trial-process one inbound pool record against every local identity.
///
/// `identities` is `(identity_id, secret, my_xid)`. The record is assumed to
/// have already passed [`pool::verify_pool_record`] at the node's ingest seam;
/// this only decrypts and indexes.
/// `resolve_bundle(xid)` returns ALL currently-published key bundles for `xid`
/// — one per active linked identity/device the node has synced (the node reads
/// every `data/users/<xid>/data*.json`). An empty vec means none are available
/// yet. It is the sealed-sender anti-spoof oracle: a first-contact message is
/// trusted iff the record's transcript-bound `ik_a` equals the identity key of
/// ONE of the claimed sender's published bundles (any of their devices).
pub fn process_record<E, S, R>(
    store: &S,
    engine: &E,
    identities: &[(i64, IdentitySecret, String)],
    record: &Value,
    now_ms: i64,
    resolve_bundle: R,
) -> Result<ProcessOutcome>
where
    E: Engine + ?Sized,
    S: EnvelopeStore,
    R: Fn(&str) -> Vec<Value>,
{
    let sign = match record.get("sign").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(ProcessOutcome::NoMatch),
    };
    let h = sign_h(sign);
    if store.is_processed(&h)? {
        return Ok(ProcessOutcome::AlreadyProcessed);
    }

    // The record's public `tag` is a random routing value; the real detection
    // tags live inside the multi-slot `ct` (see `multislot`). Unpack it into
    // SLOTS (tag, keyslot) pairs plus the one shared body.
    let Some(ct_vec) = record.get("ct").and_then(|v| v.as_str()).and_then(b64d) else {
        store.mark_processed(&h)?;
        return Ok(ProcessOutcome::NoMatch);
    };
    let Some(unpacked) = crate::multislot::unpack_ct(&ct_vec) else {
        // Not a well-formed multi-slot record (foreign/truncated). It can never be
        // ours; don't mark processed (a truncated sync may complete later).
        return Ok(ProcessOutcome::NoMatch);
    };
    let epoch = record.get("epoch").and_then(|v| v.as_i64()).unwrap_or(0);

    // Tier 1 — established session: scan the SLOTS detection tags (O(SLOTS)
    // hashset lookups) and open the one keyslot whose tag we expect.
    for (j, tag) in unpacked.tags.iter().enumerate() {
        let tag_vec = tag.to_vec();
        if let Some(sm) = store.session_for_tag(&tag_vec)? {
            if let Some(out) = open_established(
                store, engine, &sm, tag, &tag_vec, &unpacked.keyslots[j], &unpacked.body_ct, &h,
                epoch, now_ms,
            )? {
                return Ok(out);
            }
            // Tag matched but the ratchet couldn't open it: fall through.
        }
    }

    // Tier 2 — first contact: probe each slot for each local identity. Only a
    // record that missed Tier-1 reaches here; a dummy slot's random keyslot fails
    // `open_first` and is skipped cheaply.
    for (identity_id, secret, _my_xid) in identities {
        for (j, tag) in unpacked.tags.iter().enumerate() {
            if let Some(out) = open_first_contact(
                store, engine, *identity_id, secret, tag, &unpacked.keyslots[j], &unpacked.body_ct,
                &h, epoch, now_ms, &resolve_bundle,
            )? {
                return Ok(out);
            }
        }
    }

    // No match. Deliberately NOT marked processed: a session established later
    // (e.g. a first-contact record that arrived after this reply) makes this
    // record matchable on the next rescan.
    Ok(ProcessOutcome::NoMatch)
}

/// Tier-1 established-session open + commit. `Ok(Some(_))` = handled (indexed or
/// already-processed); `Ok(None)` = the tag matched but the ratchet couldn't open
/// it, so the caller should fall through to first-contact probing.
#[allow(clippy::too_many_arguments)]
fn open_established<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    sm: &crate::store::SessionMatch,
    tag: &[u8; 32],
    tag_vec: &[u8],
    keyslot: &[u8],
    body_ct: &[u8],
    h: &[u8],
    epoch: i64,
    now_ms: i64,
) -> Result<Option<ProcessOutcome>> {
    // The keyslot opens to `K_msg ‖ H(body)`; the message itself is the ONE shared
    // body decrypted under K_msg (bound by the hash, so no substituted body).
    let Ok(op) = engine.open(&sm.ratchet, sm.n, tag, keyslot) else { return Ok(None) };
    let Some((k_msg, body_hash)) = crate::multislot::parse_keyslot_plain(&op.body) else {
        return Ok(None);
    };
    let Some(bp) = crate::multislot::open_shared_body(&k_msg, &body_hash, body_ct) else {
        return Ok(None);
    };
    // Established sender is the verified session peer (fall back to the body's).
    let sender = sm.peer_xid.clone().or(Some(bp.sender_xid.clone()));
    let commit = InboundCommit {
        identity_id: sm.identity_id,
        session_id: sm.session_id,
        conv_id: sm.conv_id.clone(),
        peer_xid: sm.peer_xid.clone(),
        sender_xid: sender.clone(),
        members: bp.members.clone(),
        subject: bp.subject.clone(),
        body: bp.body.clone(),
        sent_ms: bp.sent_ms,
        received_ms: now_ms,
        epoch,
        sign_h: h.to_vec(),
        ratchet_after: op.session_after.clone(),
        consumed_tag: tag_vec.to_vec(),
        new_tags: to_tag_vecs(&op.next_recv_tags),
    };
    let Some(msg_id) = store.commit_inbound(&commit)? else {
        return Ok(Some(ProcessOutcome::AlreadyProcessed));
    };
    let unread = store.unread_count(sm.identity_id)?;
    Ok(Some(ProcessOutcome::Indexed {
        msg_id,
        identity_id: sm.identity_id,
        conv_id: sm.conv_id.clone(),
        sender_xid: sender,
        subject: bp.subject,
        snippet: snippet_of(&bp.body),
        unread,
        first_contact: false,
        pending: op.pending,
    }))
}

/// Tier-2 first-contact probe + anti-spoof + commit for ONE identity.
/// `Ok(None)` = not for this identity (try the next); `Ok(Some(_))` = this
/// identity handled it (indexed, already-processed, or rejected/deferred).
#[allow(clippy::too_many_arguments)]
fn open_first_contact<E, S, R>(
    store: &S,
    engine: &E,
    identity_id: i64,
    secret: &IdentitySecret,
    tag: &[u8; 32],
    keyslot: &[u8],
    body_ct: &[u8],
    h: &[u8],
    epoch: i64,
    now_ms: i64,
    resolve_bundle: &R,
) -> Result<Option<ProcessOutcome>>
where
    E: Engine + ?Sized,
    S: EnvelopeStore,
    R: Fn(&str) -> Vec<Value>,
{
    if !engine.first_contact_candidate(secret, tag, keyslot) {
        return Ok(None);
    }
    let Ok(op) = engine.open_first(secret, tag, keyslot) else { return Ok(None) };
    // The keyslot yields `K_msg ‖ H(body)` + the transcript-bound `ik_a`; the
    // message (incl. the claimed sender) is the shared body decrypted under K_msg.
    let Some((k_msg, body_hash)) = crate::multislot::parse_keyslot_plain(&op.body) else {
        return Ok(None);
    };
    let Some(bp) = crate::multislot::open_shared_body(&k_msg, &body_hash, body_ct) else {
        return Ok(None);
    };

    // M1 anti-spoof: the body carries an attacker-controlled `sender_xid`, but the
    // keyslot carries a transcript-bound `ik_a`. Trust the attribution ONLY if the
    // sender's PUBLISHED bundle proves it owns that identity key.
    if let Some(ik_a) = op.ik_a.as_ref() {
        // Authentic iff the transcript key matches ANY of the sender's published
        // device bundles (a multi-device sender may seal from any linked key).
        let matches = resolve_bundle(&bp.sender_xid)
            .iter()
            .any(|b| engine.sender_ik(b).as_ref() == Some(ik_a));
        if !matches {
            // No matching bundle: either a forgery, or a genuine message from a
            // device whose bundle this node has not synced YET. We cannot tell
            // the two apart from the transcript alone, so DEFER by returning `None`
            // (this slot didn't deliver) — NOT `Some(NoMatch)`, which would abort
            // scanning the record's OTHER slots. The record is left unprocessed by
            // process_record if nothing else delivers, so a real message becomes
            // indexable once that device's bundle syncs, while a forgery is simply
            // re-probed (a bounded, PoW-gated cost) and never trusted. The IK
            // never matches for a forgery, so it can never be indexed.
            return Ok(None);
        }
    }

    let sender = Some(bp.sender_xid.clone());
    let conv_hex = hex::encode(op.conv_id);
    let recv = to_tag_vecs(&op.next_recv_tags);
    let session_id = store.create_session(
        identity_id,
        &conv_hex,
        sender.as_deref(),
        "resp",
        &op.session_after,
        now_ms,
        &recv,
    )?;
    let commit = InboundCommit {
        identity_id,
        session_id,
        conv_id: conv_hex.clone(),
        peer_xid: sender.clone(),
        sender_xid: sender.clone(),
        members: bp.members.clone(),
        subject: bp.subject.clone(),
        body: bp.body.clone(),
        sent_ms: bp.sent_ms,
        received_ms: now_ms,
        epoch,
        sign_h: h.to_vec(),
        ratchet_after: op.session_after.clone(),
        consumed_tag: Vec::new(),
        new_tags: Vec::new(),
    };
    let Some(msg_id) = store.commit_inbound(&commit)? else {
        return Ok(Some(ProcessOutcome::AlreadyProcessed));
    };
    let unread = store.unread_count(identity_id)?;
    Ok(Some(ProcessOutcome::Indexed {
        msg_id,
        identity_id,
        conv_id: conv_hex,
        sender_xid: sender,
        subject: bp.subject,
        snippet: snippet_of(&bp.body),
        unread,
        first_contact: true,
        pending: op.pending,
    }))
}

fn snippet_of(body: &str) -> String {
    body.chars().take(120).collect()
}

/// A fresh random 16-byte conversation id (the private thread key). Uses the
/// crypt RNG via `new_seed` (a 32-byte hex string).
pub fn new_conv_id() -> [u8; 16] {
    let v = hex::decode(epix_crypt::new_seed()).unwrap_or_else(|_| vec![0u8; 32]);
    let mut c = [0u8; 16];
    c.copy_from_slice(&v[..16]);
    c
}

