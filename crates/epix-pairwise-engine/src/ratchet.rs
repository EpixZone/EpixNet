//! X3DH + Double Ratchet with header encryption and forward-secure detection
//! tag chains — the session core.
//!
//! The Double Ratchet is the Signal construction (symmetric-key ratchet + DH
//! ratchet, with skipped-message-key storage), keyed by HKDF-SHA256 / HMAC-SHA256
//! (see [`crate::crypto`]). Layered on top, each direction carries a forward-secure
//! **tag chain** seeded from the X3DH secret: `tag_i = MAC(tck_i,"tag")` is the
//! record's public detection tag, `hk_i = MAC(tck_i,"hdr")` encrypts the (small)
//! ratchet header, and `tck_{i+1} = MAC(tck_i,"chain")` (deleting `tck_i`). Tags
//! are PRF outputs an observer cannot link; the header key hides the ratchet
//! public key and counters. First contact uses an Elligator2 representative of a
//! fresh ephemeral as its tag, so it is byte-indistinguishable from an
//! established record.

use crate::crypto::{aead_open, aead_seal, kdf, kdf32, mac};
use crate::curve;
use crate::keys;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Lookahead: how many future receive tags a session publishes at once. Kept
/// EQUAL to `MAX_SKIP` so the published window matches the ratchet's skip
/// tolerance — any record whose tag is registered is also openable, and vice
/// versa. (Previously 32 while the skip cap was 512, so a head-of-chain gap of
/// 33..512 records was recoverable by the ratchet but its tag was never
/// registered, so the record silently missed forever.) 64 self-heals any
/// realistic reordering/loss while keeping the per-received-message cost — the
/// node re-registers a window of this many tags on each open — modest, so a
/// large backfill stays cheap. A contiguous head loss beyond `MAX_SKIP` stalls
/// that direction until the peer resends (a rare, hard case; see the spec).
const LOOKAHEAD: u32 = 64;
/// Hard cap on skipped message keys / header keys retained per session, and the
/// largest head-of-chain gap a direction can self-heal.
const MAX_SKIP: u32 = 64;
/// Fixed plaintext width of a first-contact header.
const FC_HDR_PLAIN: usize = 128;
/// Fixed plaintext width of an established (DH-ratchet) header.
const EST_HDR_PLAIN: usize = 40;
const AEAD_TAG: usize = 16;
const FC_HDR_BLOCK: usize = FC_HDR_PLAIN + AEAD_TAG; // 144
const EST_HDR_BLOCK: usize = EST_HDR_PLAIN + AEAD_TAG; // 56

/// Pending first-contact material, computed at [`begin`] (which has the seed)
/// and consumed by the first [`seal`] (which does not).
#[derive(Serialize, Deserialize, Clone, zeroize::ZeroizeOnDrop)]
struct FcPending {
    tag: [u8; 32],
    fc_key: [u8; 32],
    ik_a: [u8; 32],
    spk_idx: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    role: u8, // 0 = initiator, 1 = responder
    conv_id: [u8; 16],
    peer_xid: String,
    // Double Ratchet
    dhs_priv: [u8; 32],
    dhs_pub: [u8; 32],
    dhr_pub: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    // Tag chains
    tck_send: [u8; 32],
    i_send: u32,
    tck_recv: [u8; 32],
    i_recv: u32,
    fc_sent: bool,
    fc: Option<FcPending>,
    // Skipped keys
    skipped_hk: Vec<(u32, [u8; 32])>,
    skipped_mk: Vec<([u8; 32], u32, [u8; 32])>,
}

impl Drop for Session {
    /// Best-effort wipe of the live session secrets when the in-memory copy is
    /// dropped (root key, chain keys, ratchet private key, tag-chain keys, and
    /// every skipped message/header key). Cannot reach the serialized blob the
    /// node persists — that at-rest concern is tracked separately (`enc` column).
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.dhs_priv.zeroize();
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
        self.tck_send.zeroize();
        self.tck_recv.zeroize();
        for (_, hk) in self.skipped_hk.iter_mut() {
            hk.zeroize();
        }
        for (dh, _, mk) in self.skipped_mk.iter_mut() {
            dh.zeroize();
            mk.zeroize();
        }
        // `fc: Option<FcPending>` wipes itself via its own ZeroizeOnDrop.
    }
}

#[cfg(test)]
thread_local! {
    /// A test-only queue of fixed randomness. When non-empty, `rand32` returns
    /// its values in order instead of OS entropy, so `begin`/`dh_ratchet`/`seal`
    /// become deterministic for byte-exact record vectors.
    static TEST_RNG: std::cell::RefCell<std::collections::VecDeque<[u8; 32]>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// Load fixed randomness for the current thread (test-only).
#[cfg(test)]
pub(crate) fn set_test_rng(vals: Vec<[u8; 32]>) {
    TEST_RNG.with(|r| *r.borrow_mut() = vals.into());
}

fn rand32() -> [u8; 32] {
    #[cfg(test)]
    {
        if let Some(v) = TEST_RNG.with(|r| r.borrow_mut().pop_front()) {
            return v;
        }
    }
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("os rng");
    b
}

fn arr32(s: &[u8]) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&s[..32]);
    a
}
fn arr12(s: &[u8]) -> [u8; 12] {
    let mut a = [0u8; 12];
    a.copy_from_slice(&s[..12]);
    a
}

fn nonce_from(label: &str, tag: &[u8; 32]) -> [u8; 12] {
    // A deterministic 12-byte AEAD nonce, domain-separated by `label`, over the
    // record's (public) tag. Uniqueness is per header key: each record's header
    // key is unique to its tag index, and the tag is unique per index, so
    // (header_key, nonce) never repeats. HKDF-SHA256 for a single hash family.
    let mut out = [0u8; 12];
    kdf(label, &[], tag, &mut out);
    out
}

// --- KDF chains -------------------------------------------------------------

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    kdf("epix-channel/rk/v1", rk, dh_out, &mut out);
    (arr32(&out[..32]), arr32(&out[32..]))
}
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (mac(ck, &[2]), mac(ck, &[1])) // (ck', mk)
}
fn mk_keynonce(mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let mut kn = [0u8; 44];
    kdf("epix-channel/mk/v1", mk, &[], &mut kn);
    (arr32(&kn[..32]), arr12(&kn[32..44]))
}

// --- tag chain --------------------------------------------------------------

fn tag_of(tck: &[u8; 32]) -> [u8; 32] {
    mac(tck, b"tag")
}
fn hk_of(tck: &[u8; 32]) -> [u8; 32] {
    mac(tck, b"hdr")
}
fn next_tck(tck: &[u8; 32]) -> [u8; 32] {
    mac(tck, b"chain")
}

/// The receive tags `[from .. from+LOOKAHEAD)` for a direction chain starting at
/// `base_tck`/`base_i` — used to publish the window to register.
fn window_tags(base_tck: &[u8; 32], base_i: u32) -> Vec<(u32, [u8; 32])> {
    let mut out = Vec::with_capacity(LOOKAHEAD as usize);
    let mut tck = *base_tck;
    for k in 0..LOOKAHEAD {
        out.push((base_i + k, tag_of(&tck)));
        tck = next_tck(&tck);
    }
    out
}

// --- payload ----------------------------------------------------------------

fn build_payload(
    conv: &[u8; 16],
    members: &[String],
    subject: &str,
    body: &str,
    sent_ms: i64,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "c": hex::encode(conv), "m": members, "s": subject, "b": body, "t": sent_ms
    }))
    .unwrap_or_default()
}

/// Pad `payload` to `width` as `LEN(4) ‖ payload ‖ zeros`.
fn pad_payload(payload: &[u8], width: usize) -> Option<Vec<u8>> {
    if payload.len() + 4 > width {
        return None;
    }
    let mut out = vec![0u8; width];
    out[..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    out[4..4 + payload.len()].copy_from_slice(payload);
    Some(out)
}
fn unpad_payload(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes(padded[..4].try_into().ok()?) as usize;
    if 4 + len > padded.len() {
        return None;
    }
    Some(padded[4..4 + len].to_vec())
}

/// The smallest bucket >= `header_block + 16 + 4 + payload_len`.
fn choose_bucket(header_block: usize, payload_len: usize, buckets: &[usize]) -> Option<usize> {
    let need = header_block + AEAD_TAG + 4 + payload_len;
    buckets.iter().copied().filter(|&b| b >= need).min()
}

// --- Double Ratchet ---------------------------------------------------------

fn dh_ratchet(s: &mut Session, header_dh: [u8; 32]) {
    s.pn = s.ns;
    s.ns = 0;
    s.nr = 0;
    s.dhr_pub = Some(header_dh);
    let (rk1, ckr) = kdf_rk(&s.rk, &curve::dh(&s.dhs_priv, &header_dh));
    s.rk = rk1;
    s.ckr = Some(ckr);
    let new_priv = rand32();
    let new_pub = curve::public_key(&new_priv);
    let (rk2, cks) = kdf_rk(&s.rk, &curve::dh(&new_priv, &header_dh));
    s.rk = rk2;
    s.cks = Some(cks);
    s.dhs_priv = new_priv;
    s.dhs_pub = new_pub;
}

fn skip_message_keys(s: &mut Session, until: u32) {
    let Some(dhr) = s.dhr_pub else { return };
    if s.nr + MAX_SKIP < until {
        return; // refuse to skip absurdly far
    }
    while s.nr < until {
        if let Some(ckr) = s.ckr {
            let (ckr1, mk) = kdf_ck(&ckr);
            s.ckr = Some(ckr1);
            s.skipped_mk.push((dhr, s.nr, mk));
            s.nr += 1;
        } else {
            break;
        }
    }
    // Bound the skipped store.
    let overflow = s.skipped_mk.len().saturating_sub(MAX_SKIP as usize);
    if overflow > 0 {
        s.skipped_mk.drain(0..overflow);
    }
}

fn take_skipped_mk(s: &mut Session, dhr: &[u8; 32], n: u32) -> Option<[u8; 32]> {
    if let Some(pos) = s.skipped_mk.iter().position(|(d, i, _)| d == dhr && *i == n) {
        Some(s.skipped_mk.remove(pos).2)
    } else {
        None
    }
}

/// The message key for a DR header `(dh, pn, n)`, advancing ratchet state.
fn ratchet_decrypt_key(s: &mut Session, dh: [u8; 32], pn: u32, n: u32) -> Option<[u8; 32]> {
    if let Some(mk) = take_skipped_mk(s, &dh, n) {
        return Some(mk);
    }
    if s.dhr_pub != Some(dh) {
        skip_message_keys(s, pn);
        dh_ratchet(s, dh);
    }
    skip_message_keys(s, n);
    // Fail closed if the skip was refused (gap > MAX_SKIP): `skip_message_keys`
    // leaves `nr` short of `n`, so deriving here would produce a wrong-index key
    // that only AEAD would (silently) reject. Return None explicitly instead.
    if s.nr < n {
        return None;
    }
    let ckr = s.ckr?;
    let (ckr1, mk) = kdf_ck(&ckr);
    s.ckr = Some(ckr1);
    s.nr += 1;
    Some(mk)
}

/// The message key for the next send, advancing the sending chain.
fn ratchet_encrypt_key(s: &mut Session) -> Option<([u8; 32], u32, u32, [u8; 32])> {
    let cks = s.cks?;
    let (cks1, mk) = kdf_ck(&cks);
    s.cks = Some(cks1);
    let header = (s.dhs_pub, s.pn, s.ns);
    s.ns += 1;
    Some((header.0, header.1, header.2, mk))
}

// --- header key management (tag chain) --------------------------------------

/// The header key for receive tag index `i`, advancing / consuming as needed.
fn header_key_for(s: &mut Session, i: u32) -> Option<[u8; 32]> {
    if i < s.i_recv {
        // A skipped (out-of-order) index whose hk we stored earlier.
        if let Some(pos) = s.skipped_hk.iter().position(|(j, _)| *j == i) {
            return Some(s.skipped_hk.remove(pos).1);
        }
        return None;
    }
    if s.i_recv + MAX_SKIP < i {
        return None;
    }
    // Fast-forward, storing hk for indices we jump over.
    while s.i_recv < i {
        let hk = hk_of(&s.tck_recv);
        s.skipped_hk.push((s.i_recv, hk));
        s.tck_recv = next_tck(&s.tck_recv);
        s.i_recv += 1;
    }
    let hk = hk_of(&s.tck_recv);
    s.tck_recv = next_tck(&s.tck_recv);
    s.i_recv += 1;
    let overflow = s.skipped_hk.len().saturating_sub(MAX_SKIP as usize);
    if overflow > 0 {
        s.skipped_hk.drain(0..overflow);
    }
    Some(hk)
}

// --- public API -------------------------------------------------------------

fn to_bytes(s: &Session) -> Vec<u8> {
    serde_json::to_vec(s).unwrap_or_default()
}
fn from_bytes(b: &[u8]) -> Option<Session> {
    serde_json::from_slice(b).ok()
}

/// Initiator X3DH + DR init. Returns the session and the receive tags to
/// register for the peer's replies (the responder's b2a chain).
pub fn begin(
    seed: &[u8; 32],
    bundle: &Value,
    conv_id: [u8; 16],
) -> Option<(Vec<u8>, Vec<(u32, [u8; 32])>)> {
    let (ik_b, spk_b, spk_idx) = keys::bundle_keys(bundle)?;
    let peer_xid = bundle.get("xid").and_then(|v| v.as_str()).unwrap_or("").to_string();

    // A representable ephemeral (its representative is the first-contact tag).
    let (eph, tag) = loop {
        let e = rand32();
        if let Some(t) = curve::elligator_encode(&e, rand32()[0]) {
            break (e, t);
        }
    };

    let ik_a_priv = keys::ik_priv(seed);
    let dh1 = curve::dh(&ik_a_priv, &spk_b);
    let dh2 = curve::dh(&eph, &ik_b);
    let dh3 = curve::dh(&eph, &spk_b);
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    let sk = kdf32("epix-channel/x3dh/v1", &[0xFFu8; 32], &ikm);
    let fc_key = kdf32("epix-channel/fc-hdr/v1", &tag, &dh2);

    // RatchetInitAlice(SK, DHr = spk_b).
    let dhs_priv = rand32();
    let dhs_pub = curve::public_key(&dhs_priv);
    let (rk, cks) = kdf_rk(&sk, &curve::dh(&dhs_priv, &spk_b));

    let tck_send = kdf32("epix-channel/tck/v1", &sk, b"a2b");
    let tck_recv = kdf32("epix-channel/tck/v1", &sk, b"b2a");
    let recv_tags = window_tags(&tck_recv, 0);

    let session = Session {
        role: 0,
        conv_id,
        peer_xid,
        dhs_priv,
        dhs_pub,
        dhr_pub: Some(spk_b),
        rk,
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        tck_send,
        i_send: 0,
        tck_recv,
        i_recv: 0,
        fc_sent: false,
        fc: Some(FcPending { tag, fc_key, ik_a: curve::public_key(&ik_a_priv), spk_idx }),
        skipped_hk: Vec::new(),
        skipped_mk: Vec::new(),
    };
    Some((to_bytes(&session), recv_tags))
}

/// Seal a message. The engine decides fc-vs-established from session state.
/// `sender_xid` is embedded only in a first-contact header.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    session_bytes: &[u8],
    sender_xid: &str,
    members: &[String],
    subject: &str,
    body: &str,
    sent_ms: i64,
    buckets: &[usize],
) -> Option<([u8; 32], Vec<u8>, Vec<u8>)> {
    let mut s = from_bytes(session_bytes)?;
    let payload = build_payload(&s.conv_id, members, subject, body, sent_ms);

    if s.role == 0 && !s.fc_sent {
        // First contact.
        let fc = s.fc.clone()?;
        let (dhs_pub, _pn, _ns, mk) = ratchet_encrypt_key(&mut s)?; // n = 0
        let bucket = choose_bucket(FC_HDR_BLOCK, payload.len(), buckets)?;
        // fc header plaintext (fixed width).
        let mut hp = vec![0u8; FC_HDR_PLAIN];
        hp[..32].copy_from_slice(&fc.ik_a);
        hp[32..64].copy_from_slice(&dhs_pub);
        hp[64..68].copy_from_slice(&fc.spk_idx.to_le_bytes());
        let xid = sender_xid.as_bytes();
        let xl = xid.len().min(FC_HDR_PLAIN - 70);
        hp[68..70].copy_from_slice(&(xl as u16).to_le_bytes());
        hp[70..70 + xl].copy_from_slice(&xid[..xl]);
        let hdr_block = aead_seal(&fc.fc_key, &nonce_from("fc-hdr", &fc.tag), &fc.tag, &hp);
        let body_plain = pad_payload(&payload, bucket - FC_HDR_BLOCK - AEAD_TAG)?;
        let (mk_key, mk_nonce) = mk_keynonce(&mk);
        let body_block = aead_seal(&mk_key, &mk_nonce, &fc.tag, &body_plain);
        let mut ct = hdr_block;
        ct.extend_from_slice(&body_block);

        let tag = fc.tag;
        s.fc_sent = true;
        s.fc = None;
        Some((tag, ct, to_bytes(&s)))
    } else {
        // Established message.
        let tag = tag_of(&s.tck_send);
        let hk = hk_of(&s.tck_send);
        s.tck_send = next_tck(&s.tck_send);
        s.i_send += 1;
        let (dhs_pub, pn, ns, mk) = ratchet_encrypt_key(&mut s)?;
        let bucket = choose_bucket(EST_HDR_BLOCK, payload.len(), buckets)?;
        let mut hp = vec![0u8; EST_HDR_PLAIN];
        hp[..32].copy_from_slice(&dhs_pub);
        hp[32..36].copy_from_slice(&pn.to_le_bytes());
        hp[36..40].copy_from_slice(&ns.to_le_bytes());
        let hdr_block = aead_seal(&hk, &nonce_from("est-hdr", &tag), &tag, &hp);
        let body_plain = pad_payload(&payload, bucket - EST_HDR_BLOCK - AEAD_TAG)?;
        let (mk_key, mk_nonce) = mk_keynonce(&mk);
        let body_block = aead_seal(&mk_key, &mk_nonce, &tag, &body_plain);
        let mut ct = hdr_block;
        ct.extend_from_slice(&body_block);
        Some((tag, ct, to_bytes(&s)))
    }
}

/// Cheap first-contact probe: 1 Elligator decode + 1 DH + 1 AEAD open.
pub fn fc_candidate(seed: &[u8; 32], tag: &[u8; 32], ct: &[u8]) -> bool {
    if ct.len() < FC_HDR_BLOCK {
        return false;
    }
    let Some(eph_pub) = curve::elligator_decode(tag) else { return false };
    let dh2 = curve::dh(&keys::ik_priv(seed), &eph_pub);
    let fc_key = kdf32("epix-channel/fc-hdr/v1", tag, &dh2);
    aead_open(&fc_key, &nonce_from("fc-hdr", tag), tag, &ct[..FC_HDR_BLOCK]).is_some()
}

/// Open a first-contact record → responder session + message. The returned
/// `ik_a` is the sender's transcript-bound identity key: the node MUST check it
/// against the published bundle for `sender_xid` before trusting the attribution
/// (the `sender_xid` in the header is attacker-controlled free text).
pub fn open_first(
    seed: &[u8; 32],
    tag: &[u8; 32],
    ct: &[u8],
) -> Option<(Vec<u8>, [u8; 16], String, [u8; 32], Vec<u8>, Vec<(u32, [u8; 32])>)> {
    if ct.len() < FC_HDR_BLOCK {
        return None;
    }
    let eph_pub = curve::elligator_decode(tag)?;
    let ik_b_priv = keys::ik_priv(seed);
    let dh2 = curve::dh(&ik_b_priv, &eph_pub);
    let fc_key = kdf32("epix-channel/fc-hdr/v1", tag, &dh2);
    let hp = aead_open(&fc_key, &nonce_from("fc-hdr", tag), tag, &ct[..FC_HDR_BLOCK])?;
    if hp.len() < 70 {
        return None;
    }
    let ik_a = arr32(&hp[..32]);
    let ratchet_pub_a = arr32(&hp[32..64]);
    let spk_idx = u32::from_le_bytes(hp[64..68].try_into().ok()?);
    let xl = u16::from_le_bytes(hp[68..70].try_into().ok()?) as usize;
    let sender_xid = String::from_utf8_lossy(&hp[70..(70 + xl).min(hp.len())]).into_owned();

    // X3DH responder.
    let spk_b_priv = keys::spk_priv(seed, spk_idx);
    let dh1 = curve::dh(&spk_b_priv, &ik_a);
    let dh3 = curve::dh(&spk_b_priv, &eph_pub);
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    let sk = kdf32("epix-channel/x3dh/v1", &[0xFFu8; 32], &ikm);

    // RatchetInitBob(SK, DHs = spk_b), then decrypt the fc body as DR n=0.
    let mut s = Session {
        role: 1,
        conv_id: [0u8; 16],
        peer_xid: sender_xid.clone(),
        dhs_priv: spk_b_priv,
        dhs_pub: curve::public_key(&spk_b_priv),
        dhr_pub: None,
        rk: sk,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        tck_send: kdf32("epix-channel/tck/v1", &sk, b"b2a"),
        i_send: 0,
        tck_recv: kdf32("epix-channel/tck/v1", &sk, b"a2b"),
        i_recv: 0,
        fc_sent: false,
        fc: None,
        skipped_hk: Vec::new(),
        skipped_mk: Vec::new(),
    };
    let mk = ratchet_decrypt_key(&mut s, ratchet_pub_a, 0, 0)?;
    let (mk_key, mk_nonce) = mk_keynonce(&mk);
    let body_plain = aead_open(&mk_key, &mk_nonce, tag, &ct[FC_HDR_BLOCK..])?;
    let payload = unpad_payload(&body_plain)?;

    // Cross-check + record conv from the payload.
    let v: Value = serde_json::from_slice(&payload).ok()?;
    let conv_hex = v.get("c").and_then(|x| x.as_str())?;
    let conv: [u8; 16] = hex::decode(conv_hex).ok()?.try_into().ok()?;
    s.conv_id = conv;

    // Surface `ik_a` so the node can enforce the sealed-sender cross-check
    // (published_bundle(sender_xid).ik == ik_a). Not authenticated here on its
    // own — a peer proves knowledge of IK_a via DH1, but the recipient can only
    // bind that to a *name* by comparing against the signed, published bundle.
    let next = window_tags(&s.tck_recv, s.i_recv);
    Some((to_bytes(&s), conv, sender_xid, ik_a, payload, next))
}

#[cfg(test)]
mod prod_vectors {
    //! Known-answer vectors that pin the PRODUCTION KDF-chain call sites (not
    //! re-typed literals): a context-string or formula change in `kdf_rk`,
    //! `kdf_ck`, `mk_keynonce`, `nonce_from`, or the tag-chain labels changes
    //! these and fails on purpose. Complements `tests/vectors.rs` (primitives)
    //! by covering the derivations layered on top. To regenerate after a
    //! DELIBERATE construction change, run `cargo test -p epix-pairwise-engine
    //! prod_vectors_print -- --ignored --nocapture` and paste the values.
    use super::*;

    fn h(b: &[u8]) -> String {
        hex::encode(b)
    }

    #[test]
    fn production_kdf_chain_vectors() {
        // Root KDF: kdf_rk(salt=rk, ikm=dh_out) via context "epix-channel/rk/v1".
        let (rk1, ck) = kdf_rk(&[1u8; 32], &[2u8; 32]);
        assert_eq!(h(&rk1), "7ea8a137b97d34098a4d31b528a3bc983cd6bb8f4e37df829fd6a0d686759373");
        assert_eq!(h(&ck), "3aef50963bbbccf466d7b5a44683d1cc4dfedcb6c401ec903e28166ae79f9107");

        // Chain KDF: ck' = MAC(ck, 0x02), mk = MAC(ck, 0x01).
        let (ck2, mk) = kdf_ck(&[3u8; 32]);
        assert_eq!(h(&ck2), "cfbf8f5595e5f186a92161efb3ebb946d3aa706c2df70eed5152741bdb1e7bde");
        assert_eq!(h(&mk), "aa6fa3f949be2b2cc7de5a18e7f65fee5fb78488f588d53196a63e66ad67ad12");

        // Message-key split: mk_keynonce via context "epix-channel/mk/v1".
        let (mk_key, mk_nonce) = mk_keynonce(&[4u8; 32]);
        assert_eq!(h(&mk_key), "3f62279b4151ff9942a2567079d2f707a493fbc8d0e1080cfdf0b384eee69b4a");
        assert_eq!(h(&mk_nonce), "c4e85114e881b1accaa1cdd8");

        // Header nonces from the public tag, per label.
        assert_eq!(h(&nonce_from("est-hdr", &[5u8; 32])), "bd867ca2e145df93259882ae");
        assert_eq!(h(&nonce_from("fc-hdr", &[5u8; 32])), "9834175c57650fa364a0d35a");

        // Tag chain: tag/hk/next via labels "tag"/"hdr"/"chain".
        assert_eq!(h(&tag_of(&[6u8; 32])), "8aeb69a9e6d6c8a5ceea4c3cb3b4bb3a3105618f4ab4c44edc0c97ed837cb019");
        assert_eq!(h(&hk_of(&[6u8; 32])), "3be96623d46e35c79610a2661f42870789da88c4e996b75f7be71cdf73a6c565");
        assert_eq!(h(&next_tck(&[6u8; 32])), "338efb5edc8126379eaca1b12416387721c20b069619768057f04a7f1be770c4");
    }

    /// A representable ephemeral + a fixed Bob bundle, so `begin`/`seal` run
    /// deterministically. Shared by the record KAT and its print helper.
    fn kat_setup() -> ([u8; 32], [u8; 32], serde_json::Value, [u8; 16]) {
        let alice_seed = [11u8; 32];
        let bob_seed = [22u8; 32];
        let idx = 2954u32;
        let eph = (0u8..=255)
            .map(|i| [i; 32])
            .find(|e| crate::curve::elligator_encode(e, 0).is_some())
            .expect("some [i;32] is elligator-representable");
        let bundle = serde_json::json!({
            "v": 2, "xid": "bob.epix",
            "ik": keys::b64(&crate::curve::public_key(&keys::ik_priv(&bob_seed))),
            "spk": keys::b64(&crate::curve::public_key(&keys::spk_priv(&bob_seed, idx))),
            "spk_idx": idx,
        });
        (alice_seed, eph, bundle, [3u8; 16])
    }

    fn kat_records() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let (alice_seed, eph, bundle, conv) = kat_setup();
        // begin consumes: ephemeral, tweak (uses [0]), dhs_priv.
        set_test_rng(vec![eph, [7u8; 32], [42u8; 32]]);
        let (session, _recv) = begin(&alice_seed, &bundle, conv).unwrap();
        let buckets = [512usize, 2048];
        // Alice's first (first-contact) record, then her second (established).
        let (t1, c1, session) = seal(&session, "alice.epix", &[], "s1", "body-one", 1000, &buckets).unwrap();
        let (t2, c2, _session) = seal(&session, "alice.epix", &[], "s2", "body-two", 2000, &buckets).unwrap();
        (t1.to_vec(), c1, t2.to_vec(), c2)
    }

    /// Byte-exact record vectors (C1). Unlike the round-trip tests, these pin the
    /// full on-wire record — Elligator tag, FC/EST header layout, `ad = tag`,
    /// nonce labels, padding, bucket choice, AND the X3DH/tck contexts that a
    /// symmetric seal/open change would otherwise hide — because `begin`/`seal`
    /// are made deterministic via the injected RNG. A second implementation must
    /// reproduce these exactly. Regenerate deliberately via `record_kat_print`.
    #[test]
    fn record_level_kat() {
        let (t1, c1, t2, c2) = kat_records();
        assert_eq!(h(&t1), "d3f7e7bd26d7c49640e15d6fa86a8d108bed3c9479479a78e2472f07044b8711", "FC tag");
        assert_eq!(h(&c1), "4cb3045e4b1c5582fae3f15887ee9fd6216e9ddaf331454bc8cbcc838a4e87c4df8eaef806f140584a45a848642c7aa101d076faaffbba3997b69ac50031626816eed8416922bdd611103cbbca9137b520e33601be58fbe54be6b7a5628d8dee161c00aa252a5457801f1425ec8345ecc29b7b84ed5d088b4208f0ca103429f3d9a27bda6c8974b10fb918c9c48e09341a198a8ebb10108a7e9ed3675e53360b9f88990baf0d2390de52ca16a112747bec569f53d11228c422f4078228d0d5727059bc8e6e59f77cb5e90a2c2e8eafb4f1abfddddb74697a05ae8d2dbb84dc933a9171f176f8141692d9d5b4fa7593c2b85dec57585dccd032d3e168ef17ca205c5f268b84ef8ad24392c0617b8599e043177e1752f32cbc56f64387340a3088385c2cc5c476f5cd2821b27c29e752f29b45acda309770aed86c88359b93069c57103cbd5e15cbcd44644416fe5813a5b27aada7f3db1abd9221e48eece88696ba1c23a5c65ee0e65e1c817ccf435bfa4bfdeea59e92559e5b8d02b97b8999fefe47bfed16882897a940835a497bdea09057f4473e8c90bac26d73babbb40d2fa8dff29aa56d022bc84fe00327329e48394a2b9e6ac700ae558514e6a473c9df319dd55b48d958e1f71ae568c3fbaeca1db6646579bb27efdcebeb8cf4a82accaf8cf21e8a89de98ee3d4ce0b12c4b0030daf63c3d6ec13a0b508d8a9e164574", "FC ct");
        assert_eq!(h(&t2), "d9aee1169f1bcb8af6c108bfb11f91a773b1fe47cc7e263b14ed19f9adc8ed3a", "EST tag");
        assert_eq!(h(&c2), "69b39dab22a48fe370ead4c1ba2e72e545d901f3085ce73529f4ac0b6ff0c468a870e8b2c795b4c096d75b68c90dc91fca7cde1fa962dd98401520a297391ab67d56b59fe0c1c658223740e56f61b137a0f0f5f446e1a7814c550d11ac8614c2d2c72b3f8e9e0b3abafe3cf31b84d2ff3e461d91e7a04fe38f48d297e3cac3a9ae8d26dfec60d523139c975ae514e0783a21fe3fd85cd859bd719bc26212b616c8ada04d3f3cff142ee1ea3cce4e9a5d9a1ea4a481b1ade0daee090a22468ea493c9a6060ad0a931315614e249f7f1e568d3e77da9feb9f58e1a0b57b5caa5387a3b1f05337211251d5381c06edd8b7d7158685589b23da66f3d6b495e7a8830f63bb86ebbae8cd6dda173e768e33c71a27529b1f609ae077a67ab5eed3fc89ecd8b096dd61ee1a445127855cef4a5a559f0f97f3d132037e68ad5e1fd72c32f1e366c2615906ba097bb63fa6e97c2bca211473e3c01237d2123ff1c76f12a43021c2d353223b72198b29720c5c75eab2a648441a628ff2dc08b7c4cb8dcddd9ece02f6cd40d3f6f58485c4ef41071059171cfd74e344faefd1b2bfec95caddd795a23baf3946a79fdb5f50a8cb729f3f77de3f1f396fe95dc862a5d358e92119a18384469c8cd0db6d765f96acf1520ddd25c28d52b01681e99b412d6e2b42bcb50e13c6ec10f399297ce4916ba1071dd69a4be1e7b7614674f5ba0a3e73cc1", "EST ct");

        // The frozen first-contact record actually decrypts for Bob (proves the
        // bytes are a valid record, not just a hash we froze).
        let bob_seed = [22u8; 32];
        let tag: [u8; 32] = t1.clone().try_into().unwrap();
        let (_s, _conv, sender, _ik_a, payload, _n) = open_first(&bob_seed, &tag, &c1).unwrap();
        assert_eq!(sender, "alice.epix");
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["b"].as_str(), Some("body-one"));
    }

    /// C4: the `MAX_SKIP` fail-closed boundary on the header-key (tag) chain.
    /// A gap of exactly `MAX_SKIP` still opens; one more is refused (`None`), so
    /// `open()` fails closed rather than skipping unboundedly. (Not reachable via
    /// the public API, which is gated by the 32-tag publish window, so it's
    /// exercised directly here.)
    #[test]
    fn header_key_for_max_skip_boundary() {
        let (alice_seed, _eph, bundle, conv) = kat_setup();
        let (session_bytes, _recv) = begin(&alice_seed, &bundle, conv).unwrap();
        let s = from_bytes(&session_bytes).unwrap();
        let base = s.i_recv; // 0 on a fresh session
        assert!(base == 0);

        // Gap == MAX_SKIP: allowed.
        let mut s_ok = s.clone();
        assert!(header_key_for(&mut s_ok, base + MAX_SKIP).is_some(), "gap == MAX_SKIP opens");
        // Gap == MAX_SKIP + 1: refused, fail-closed.
        let mut s_bad = s.clone();
        assert!(header_key_for(&mut s_bad, base + MAX_SKIP + 1).is_none(), "gap > MAX_SKIP refused");
    }

    #[test]
    #[ignore]
    fn record_kat_print() {
        let (t1, c1, t2, c2) = kat_records();
        println!("FC_TAG {}", h(&t1));
        println!("FC_CT {}", h(&c1));
        println!("EST_TAG {}", h(&t2));
        println!("EST_CT {}", h(&c2));
    }
}

/// Open an established-session record whose `tag` matched at index `n`.
pub fn open(
    session_bytes: &[u8],
    n: u32,
    tag: &[u8; 32],
    ct: &[u8],
) -> Option<(Vec<u8>, Vec<u8>, Option<String>, Vec<(u32, [u8; 32])>)> {
    let mut s = from_bytes(session_bytes)?;
    if ct.len() < EST_HDR_BLOCK {
        return None;
    }
    let hk = header_key_for(&mut s, n)?;
    let hp = aead_open(&hk, &nonce_from("est-hdr", tag), tag, &ct[..EST_HDR_BLOCK])?;
    if hp.len() < EST_HDR_PLAIN {
        return None;
    }
    let dh = arr32(&hp[..32]);
    let pn = u32::from_le_bytes(hp[32..36].try_into().ok()?);
    let ns = u32::from_le_bytes(hp[36..40].try_into().ok()?);
    let mk = ratchet_decrypt_key(&mut s, dh, pn, ns)?;
    let (mk_key, mk_nonce) = mk_keynonce(&mk);
    let body_plain = aead_open(&mk_key, &mk_nonce, tag, &ct[EST_HDR_BLOCK..])?;
    let payload = unpad_payload(&body_plain)?;
    let sender = if s.peer_xid.is_empty() { None } else { Some(s.peer_xid.clone()) };
    let next = window_tags(&s.tck_recv, s.i_recv);
    Some((to_bytes(&s), payload, sender, next))
}
