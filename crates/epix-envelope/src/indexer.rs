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
) -> Result<Vec<ProcessOutcome>>
where
    E: Engine + ?Sized,
    S: EnvelopeStore,
    R: Fn(&str) -> Vec<Value>,
{
    let Some(sign) = record.get("sign").and_then(|v| v.as_str()) else {
        return Ok(Vec::new());
    };
    let h = sign_h(sign);

    // The record's public `tag` is a random routing value; the real detection
    // tags live inside the multi-slot `ct` (see `multislot`). Unpack it into
    // SLOTS (tag, keyslot) pairs plus the one shared body. A record that isn't a
    // well-formed multi-slot ct (foreign/truncated) is never ours — return nothing
    // WITHOUT marking processed (a truncated sync may complete later).
    let Some(ct_vec) = record.get("ct").and_then(|v| v.as_str()).and_then(b64d) else {
        return Ok(Vec::new());
    };
    let Some(unpacked) = crate::multislot::unpack_ct(&ct_vec) else {
        return Ok(Vec::new());
    };
    let epoch = record.get("epoch").and_then(|v| v.as_i64()).unwrap_or(0);

    // A single count-hiding record can carry slots for SEVERAL local identities, so
    // a node hosting more than one channel identity delivers one message to EACH.
    // Idempotency and "processed" are keyed per identity, so an undelivered slot for
    // one identity is re-checked independently of another's delivered slot in the
    // same record. The two tiers are factored out to keep this dispatch readable;
    // `delivered` guards against a second slot re-delivering to an already-served
    // identity.
    let mut outcomes = Vec::new();
    let mut delivered: std::collections::HashSet<i64> = std::collections::HashSet::new();

    scan_established(store, engine, &unpacked, &h, epoch, now_ms, &mut outcomes, &mut delivered)?;
    scan_first_contact(
        store, engine, identities, &unpacked, &h, epoch, now_ms, &resolve_bundle, &mut outcomes,
        &mut delivered,
    )?;

    // Empty = nothing delivered; the record is left unprocessed so a session or
    // bundle that syncs later makes it matchable on the next rescan.
    Ok(outcomes)
}

/// Tier 1 — established sessions. Each detection tag that matches a session opens
/// that session's keyslot; O(SLOTS) hashset lookups. A `None` open means the tag
/// matched but the ratchet couldn't open it (e.g. a dummy tag collision) — the
/// identity is left undelivered so Tier-2 can still probe it.
#[allow(clippy::too_many_arguments)]
fn scan_established<E: Engine + ?Sized, S: EnvelopeStore>(
    store: &S,
    engine: &E,
    unpacked: &crate::multislot::Unpacked,
    h: &[u8],
    epoch: i64,
    now_ms: i64,
    outcomes: &mut Vec<ProcessOutcome>,
    delivered: &mut std::collections::HashSet<i64>,
) -> Result<()> {
    for (j, tag) in unpacked.tags.iter().enumerate() {
        let tag_vec = tag.to_vec();
        let Some(sm) = store.session_for_tag(&tag_vec)? else { continue };
        if delivered.contains(&sm.identity_id) || store.is_processed(h, sm.identity_id)? {
            continue;
        }
        if let Some(out) = open_established(
            store, engine, &sm, tag, &tag_vec, &unpacked.keyslots[j], &unpacked.body_ct, h, epoch,
            now_ms,
        )? {
            delivered.insert(sm.identity_id);
            outcomes.push(out);
        }
    }
    Ok(())
}

/// Tier 2 — first contact. For each identity not already delivered/processed,
/// probe each slot. A dummy slot's random keyslot fails `open_first` and is
/// skipped cheaply; the anti-spoof defers by returning `None`, which lets the scan
/// continue to other slots rather than aborting the record.
#[allow(clippy::too_many_arguments)]
fn scan_first_contact<E, S, R>(
    store: &S,
    engine: &E,
    identities: &[(i64, IdentitySecret, String)],
    unpacked: &crate::multislot::Unpacked,
    h: &[u8],
    epoch: i64,
    now_ms: i64,
    resolve_bundle: &R,
    outcomes: &mut Vec<ProcessOutcome>,
    delivered: &mut std::collections::HashSet<i64>,
) -> Result<()>
where
    E: Engine + ?Sized,
    S: EnvelopeStore,
    R: Fn(&str) -> Vec<Value>,
{
    for (identity_id, secret, _my_xid) in identities {
        if delivered.contains(identity_id) || store.is_processed(h, *identity_id)? {
            continue;
        }
        for (j, tag) in unpacked.tags.iter().enumerate() {
            if let Some(out) = open_first_contact(
                store, engine, *identity_id, secret, tag, &unpacked.keyslots[j], &unpacked.body_ct,
                h, epoch, now_ms, resolve_bundle,
            )? {
                delivered.insert(*identity_id);
                outcomes.push(out);
                break; // one slot per identity
            }
        }
    }
    Ok(())
}

/// Convenience for callers/tests that expect a record to deliver to at most one
/// local identity (the single-identity-per-node norm): the first outcome, or
/// [`ProcessOutcome::NoMatch`] if nothing was delivered.
#[allow(clippy::too_many_arguments)]
pub fn process_record_one<E, S, R>(
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
    Ok(process_record(store, engine, identities, record, now_ms, resolve_bundle)?
        .into_iter()
        .next()
        .unwrap_or(ProcessOutcome::NoMatch))
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

    // Re-wrap dedup: a first-contact-openable record for a conversation leg that
    // ALREADY has a session is a re-opener — a send retry, or a second opener that
    // raced the first before this node had the session — NOT a distinct message
    // (genuine follow-ups arrive as Tier-1, tag-matched records). Creating a second
    // session here would fork the ratchet and double-index the opener. Drop it
    // idempotently: mark it processed for this identity so it is not re-probed on
    // every rescan, and report no new message.
    if !bp.sender_xid.is_empty()
        && store.session_id_for_leg(identity_id, &conv_hex, &bp.sender_xid)?.is_some()
    {
        store.mark_processed(h, identity_id)?;
        return Ok(Some(ProcessOutcome::AlreadyProcessed));
    }

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

