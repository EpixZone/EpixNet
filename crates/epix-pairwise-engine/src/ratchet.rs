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

/// Lookahead: how many future receive tags a session publishes at once
/// (tolerates this much reordering / loss before a chain stalls).
const LOOKAHEAD: u32 = 32;
/// Hard cap on skipped message keys / header keys retained per session.
const MAX_SKIP: u32 = 512;
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

fn rand32() -> [u8; 32] {
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
