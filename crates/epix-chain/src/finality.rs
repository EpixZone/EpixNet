//! Client-side finality verification for the xID state digest.
//!
//! Validators attest the digest with **ZERO extra setup** — CometBFT signs each
//! validator's vote-extension payload with its **consensus key** as part of the
//! precommit (the `ExtensionSignature`). So validators only upgrade; there is no
//! separate attest key and no on-chain registration. This module verifies those
//! signatures against a **config-pinned CONSENSUS validator set**, so a resolved
//! `name → digest` is proven finalized by a supermajority of voting power WITHOUT
//! a CometBFT light client (no ics23/tendermint-rs — just N ed25519 verifies + a
//! small protobuf reconstruction).
//!
//! For each attestation the client reproduces exactly what CometBFT signed —
//! `MarshalDelimited(CanonicalVoteExtension{extension, height, round, chain_id})` —
//! and verifies it against the pinned consensus pubkey (mirrors
//! `baseapp.ValidateVoteExtensions`). The `extension` bytes carry the signed
//! `(height, block_time, digest)`; the client binds `digest` to the resolved name's
//! `proof_root` and enforces freshness.
//!
//! Trust model (see `docs/xid-lightclient-finality.md`): weak subjectivity — the
//! caller pins `{valcons → (consensus pubkey, voting_power)}` + `chain_id` from a
//! signed app release, and this module fails closed when the pin is older than
//! `ws_period`. Because each attestation IS a consensus precommit, equivocation is
//! covered by CometBFT double-sign slashing. Security rules (each has a test):
//! verify against the PINNED pubkey; dedup by valcons; strict `sum*3 > total*2` +
//! a `min_power_bps` buffer; freshness + monotonic height; WS pin-expiry.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, VerifyingKey};

/// Default power safety-buffer: require ≥80% of pinned voting power (not a bare
/// 2/3), so a pinned set whose real power has partly migrated can't be cleared by
/// exactly-2/3 between re-pins.
pub const DEFAULT_MIN_POWER_BPS: u32 = 8000;

/// One pinned validator: its **consensus** ed25519 pubkey and voting power.
#[derive(Clone, Debug)]
pub struct PinnedValidator {
    pub pubkey: [u8; 32],
    pub voting_power: u64,
}

/// The pinned CONSENSUS validator set — the client's root of trust, shipped in
/// signed config and re-pinned within the weak-subjectivity window.
#[derive(Clone, Debug)]
pub struct PinnedSet {
    /// `valcons` → pinned validator.
    pub validators: HashMap<String, PinnedValidator>,
    /// Sum of `voting_power` (the finality denominator).
    pub total_power: u64,
    /// The chain id (bound into every CanonicalVoteExtension).
    pub chain_id: String,
    /// Unix seconds this pin was captured (weak-subjectivity clock).
    pub pinned_at_unix: i64,
    /// Chain height the pin was captured at; bundles older than this are rejected.
    pub pinned_at_height: u64,
}

impl PinnedSet {
    pub fn new(
        validators: HashMap<String, PinnedValidator>,
        chain_id: impl Into<String>,
        pinned_at_unix: i64,
        pinned_at_height: u64,
    ) -> Self {
        let total_power = validators.values().map(|v| v.voting_power).sum();
        Self { validators, total_power, chain_id: chain_id.into(), pinned_at_unix, pinned_at_height }
    }
}

/// One validator's attestation from the RPC: its `valcons`, CometBFT's
/// `ExtensionSignature` (64 bytes), and the raw vote-extension payload bytes that
/// were signed.
#[derive(Clone, Debug)]
pub struct AttestationEntry {
    pub valcons: String,
    pub signature: Vec<u8>,
    pub vote_extension: Vec<u8>,
}

/// The finality bundle the client fetches for a digest. `height`/`round` are the
/// consensus height/round the extensions were signed at (shared across the commit);
/// `block_time_unix` is the canonical (≥2/3-agreed) signed time.
#[derive(Clone, Debug)]
pub struct FinalityBundle {
    pub digest_hex: String,
    pub height: u64,
    pub round: u64,
    pub block_time_unix: i64,
    pub attestations: Vec<AttestationEntry>,
}

#[derive(Clone, Copy, Debug)]
pub struct VerifyParams {
    pub now_unix: i64,
    pub skew_secs: i64,
    pub ws_period_secs: i64,
    pub min_power_bps: u32,
    pub max_height_seen: u64,
}

/// Why a bundle was rejected. All fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityError {
    PinExpired,
    HeightBeforePin,
    Stale,
    HeightRollback,
    BadDigest,
    InsufficientPower { got: u64, total: u64, need_bps: u32 },
}

// --- protobuf wire helpers (just enough for CanonicalVoteExtension + the payload) ---

fn put_uvarint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

fn read_uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut x = 0u64;
    let mut s = 0u32;
    for (i, &byte) in b.iter().enumerate().take(10) {
        if byte < 0x80 {
            return Some((x | ((byte as u64) << s), i + 1));
        }
        x |= ((byte & 0x7f) as u64) << s;
        s += 7;
    }
    None
}

/// Reproduce exactly what CometBFT signs for a vote extension:
/// `MarshalDelimited(CanonicalVoteExtension{ bytes extension=1; sfixed64 height=2;
/// sfixed64 round=3; string chain_id=4 })` — proto3, so a zero `height`/`round`
/// field is OMITTED (must match the Go side, which is why round 0 drops the field).
pub fn canonical_vote_ext_bytes(extension: &[u8], height: i64, round: i64, chain_id: &str) -> Vec<u8> {
    let mut inner = Vec::new();
    if !extension.is_empty() {
        inner.push(0x0a); // field 1, wire type 2 (len-delimited)
        put_uvarint(extension.len() as u64, &mut inner);
        inner.extend_from_slice(extension);
    }
    if height != 0 {
        inner.push(0x11); // field 2, wire type 1 (64-bit)
        inner.extend_from_slice(&height.to_le_bytes());
    }
    if round != 0 {
        inner.push(0x19); // field 3, wire type 1 (64-bit)
        inner.extend_from_slice(&round.to_le_bytes());
    }
    if !chain_id.is_empty() {
        inner.push(0x22); // field 4, wire type 2 (len-delimited)
        put_uvarint(chain_id.len() as u64, &mut inner);
        inner.extend_from_slice(chain_id.as_bytes());
    }
    // MarshalDelimited = uvarint(len) ‖ message.
    let mut out = Vec::with_capacity(inner.len() + 2);
    put_uvarint(inner.len() as u64, &mut out);
    out.extend_from_slice(&inner);
    out
}

/// Parse the AttestationVoteExtension payload (`uint64 height=1; int64 block_time=2;
/// string digest=3`) → `(height, block_time, digest)`. Unknown fields are skipped.
fn parse_vote_extension(ext: &[u8]) -> Option<(u64, i64, String)> {
    let mut i = 0;
    let (mut height, mut block_time, mut digest) = (0u64, 0i64, String::new());
    while i < ext.len() {
        let tag = ext[i];
        i += 1;
        let field = tag >> 3;
        let wire = tag & 0x7;
        match (field, wire) {
            (1, 0) => {
                let (v, n) = read_uvarint(&ext[i..])?;
                height = v;
                i += n;
            }
            (2, 0) => {
                let (v, n) = read_uvarint(&ext[i..])?;
                block_time = v as i64;
                i += n;
            }
            (3, 2) => {
                let (len, n) = read_uvarint(&ext[i..])?;
                i += n;
                let end = i.checked_add(len as usize)?;
                digest = String::from_utf8(ext.get(i..end)?.to_vec()).ok()?;
                i = end;
            }
            // skip unknown fields by wire type
            (_, 0) => {
                let (_, n) = read_uvarint(&ext[i..])?;
                i += n;
            }
            (_, 2) => {
                let (len, n) = read_uvarint(&ext[i..])?;
                i += n + len as usize;
            }
            (_, 1) => i += 8,
            (_, 5) => i += 4,
            _ => return None,
        }
    }
    Some((height, block_time, digest))
}

/// Verify a finality bundle against the pinned consensus set. On success returns
/// the bundle height (the caller advances `max_height_seen`). Fails closed.
pub fn verify_finality(
    bundle: &FinalityBundle,
    pinned: &PinnedSet,
    params: &VerifyParams,
) -> Result<u64, FinalityError> {
    if params.now_unix.saturating_sub(pinned.pinned_at_unix) > params.ws_period_secs {
        return Err(FinalityError::PinExpired);
    }
    if bundle.height < pinned.pinned_at_height {
        return Err(FinalityError::HeightBeforePin);
    }
    if (params.now_unix - bundle.block_time_unix).abs() > params.skew_secs {
        return Err(FinalityError::Stale);
    }
    if bundle.height < params.max_height_seen {
        return Err(FinalityError::HeightRollback);
    }
    // The digest must be valid 32-byte hex (it is what a name's Merkle proof roots at).
    match hex::decode(&bundle.digest_hex) {
        Ok(d) if d.len() == 32 => {}
        _ => return Err(FinalityError::BadDigest),
    }

    let mut counted: HashSet<&str> = HashSet::new();
    let mut power: u64 = 0;
    for att in &bundle.attestations {
        // The payload must be for THIS bundle's digest + canonical block_time.
        let Some((_h, ext_bt, ext_digest)) = parse_vote_extension(&att.vote_extension) else {
            continue;
        };
        if ext_digest != bundle.digest_hex || ext_bt != bundle.block_time_unix {
            continue;
        }
        let Some(v) = pinned.validators.get(&att.valcons) else { continue };
        if counted.contains(att.valcons.as_str()) {
            continue;
        }
        let Ok(vk) = VerifyingKey::from_bytes(&v.pubkey) else { continue };
        let Some(sig) = sig_from_bytes(&att.signature) else { continue };
        // The exact bytes CometBFT signed, reproduced from the pinned chain_id.
        let msg = canonical_vote_ext_bytes(
            &att.vote_extension,
            bundle.height as i64,
            bundle.round as i64,
            &pinned.chain_id,
        );
        if vk.verify_strict(&msg, &sig).is_ok() {
            counted.insert(att.valcons.as_str());
            power = power.saturating_add(v.voting_power);
        }
    }

    let total = pinned.total_power;
    let strict_supermajority = (power as u128) * 3 > (total as u128) * 2;
    let meets_buffer = (power as u128) * 10_000 >= (total as u128) * (params.min_power_bps as u128);
    if total == 0 || !strict_supermajority || !meets_buffer {
        return Err(FinalityError::InsufficientPower {
            got: power,
            total,
            need_bps: params.min_power_bps,
        });
    }
    Ok(bundle.height)
}

fn sig_from_bytes(bytes: &[u8]) -> Option<Signature> {
    let arr: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::from_bytes(&arr))
}

fn num_u64(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn num_i64(v: Option<&serde_json::Value>) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn b64_or_hex(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
        .or_else(|| hex::decode(s.trim()).ok())
}

/// Parse the `/xid/v1/attestations` response into a [`FinalityBundle`] for
/// `digest_hex`. `signature` is hex; `vote_extension` is base64 (proto `bytes` via
/// the gateway); `round` is read per-attestation (shared across the commit).
/// Legacy `auto:consensus` entries (non-hex signature / empty extension) are dropped.
pub fn parse_bundle(digest_hex: &str, v: &serde_json::Value) -> Option<FinalityBundle> {
    let height = num_u64(v.get("height"))?;
    let block_time_unix = num_i64(v.get("block_time"))?;
    let atts = v.get("attestations")?.as_array()?;
    let mut round = 0u64;
    let mut attestations = Vec::with_capacity(atts.len());
    for a in atts {
        let valcons = match a.get("validator_cons_addr").and_then(|x| x.as_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        let Some(sig_hex) = a.get("signature").and_then(|x| x.as_str()) else { continue };
        let Ok(signature) = hex::decode(sig_hex.trim()) else { continue }; // drops "auto:consensus"
        let Some(vote_extension) =
            a.get("vote_extension").and_then(|x| x.as_str()).and_then(b64_or_hex)
        else {
            continue;
        };
        if let Some(r) = num_u64(a.get("round")) {
            round = r;
        }
        attestations.push(AttestationEntry { valcons, signature, vote_extension });
    }
    Some(FinalityBundle { digest_hex: digest_hex.to_string(), height, round, block_time_unix, attestations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const CHAIN: &str = "epix_1916-1";
    const HEIGHT: u64 = 200;
    const ROUND: u64 = 0;
    const BT: i64 = 1_000_090;

    /// Encode an AttestationVoteExtension payload (height=1, block_time=2, digest=3).
    fn vote_ext(height: u64, block_time: i64, digest_hex: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(0x08);
        put_uvarint(height, &mut b);
        b.push(0x10);
        put_uvarint(block_time as u64, &mut b);
        b.push(0x1a);
        put_uvarint(digest_hex.len() as u64, &mut b);
        b.extend_from_slice(digest_hex.as_bytes());
        b
    }

    /// A pinned set of `n` validators with the given powers + the signing keys.
    fn setup(powers: &[u64]) -> (PinnedSet, Vec<(String, SigningKey)>) {
        let mut validators = HashMap::new();
        let mut keys = Vec::new();
        for (i, &p) in powers.iter().enumerate() {
            let sk = key(i as u8 + 1);
            let valcons = format!("epixvalcons{i}");
            validators.insert(
                valcons.clone(),
                PinnedValidator { pubkey: sk.verifying_key().to_bytes(), voting_power: p },
            );
            keys.push((valcons, sk));
        }
        (PinnedSet::new(validators, CHAIN, 1_000_000, 100), keys)
    }

    fn params() -> VerifyParams {
        VerifyParams {
            now_unix: 1_000_100,
            skew_secs: 120,
            ws_period_secs: 100_000,
            min_power_bps: DEFAULT_MIN_POWER_BPS,
            max_height_seen: 0,
        }
    }

    /// Build a bundle where `signers` (indices) sign the CanonicalVoteExtension.
    fn bundle(
        set: &PinnedSet,
        keys: &[(String, SigningKey)],
        signers: &[usize],
        height: u64,
        round: u64,
        block_time: i64,
        digest_hex: &str,
    ) -> FinalityBundle {
        let ext = vote_ext(height, block_time, digest_hex);
        let msg = canonical_vote_ext_bytes(&ext, height as i64, round as i64, &set.chain_id);
        let attestations = signers
            .iter()
            .map(|&i| {
                let (valcons, sk) = &keys[i];
                AttestationEntry {
                    valcons: valcons.clone(),
                    signature: sk.sign(&msg).to_bytes().to_vec(),
                    vote_extension: ext.clone(),
                }
            })
            .collect();
        FinalityBundle { digest_hex: digest_hex.into(), height, round, block_time_unix: block_time, attestations }
    }

    #[test]
    fn all_validators_sign_verifies() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, BT, DIGEST);
        assert_eq!(verify_finality(&b, &set, &params()), Ok(HEIGHT));
    }

    #[test]
    fn four_of_five_meets_80_percent() {
        let (set, keys) = setup(&[1, 1, 1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2, 3], HEIGHT, ROUND, BT, DIGEST);
        assert_eq!(verify_finality(&b, &set, &params()), Ok(HEIGHT));
    }

    #[test]
    fn exactly_two_thirds_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1], HEIGHT, ROUND, BT, DIGEST);
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { .. })
        ));
    }

    #[test]
    fn power_buffer_rejects_a_strict_two_thirds_pass() {
        let (set, keys) = setup(&[100, 100, 100, 100, 600]);
        let b = bundle(&set, &keys, &[4, 0], HEIGHT, ROUND, BT, DIGEST); // 700/1000 = 70%
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 700, total: 1000, .. })
        ));
    }

    #[test]
    fn wrong_pinned_pubkey_not_credited() {
        let (mut set, keys) = setup(&[1, 1, 1]);
        // Repin validator 0 with an attacker key -> its signature won't verify.
        set.validators.get_mut(&keys[0].0).unwrap().pubkey = [9u8; 32];
        let b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, BT, DIGEST);
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 2, .. })
        ));
    }

    #[test]
    fn duplicate_valcons_counts_once() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut b = bundle(&set, &keys, &[0], HEIGHT, ROUND, BT, DIGEST);
        let dup = b.attestations[0].clone();
        b.attestations.push(dup.clone());
        b.attestations.push(dup);
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 1, .. })
        ));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, BT, DIGEST);
        b.attestations[0].signature[10] ^= 0xff;
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 2, .. })
        ));
    }

    #[test]
    fn wrong_round_breaks_signatures() {
        let (set, keys) = setup(&[1, 1, 1]);
        // Signed at round 0, but the bundle claims round 5 -> sign-bytes differ -> all fail.
        let mut b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, 0, BT, DIGEST);
        b.round = 5;
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 0, .. })
        ));
    }

    #[test]
    fn digest_not_matching_bundle_is_skipped() {
        let (set, keys) = setup(&[1, 1, 1]);
        // The signed extension is for a DIFFERENT digest than the bundle claims.
        let other = "2222222222222222222222222222222222222222222222222222222222222222";
        let mut b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, BT, other);
        b.digest_hex = DIGEST.into();
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 0, .. })
        ));
    }

    #[test]
    fn stale_and_future_block_time_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let old = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, 1_000_100 - 500, DIGEST);
        assert_eq!(verify_finality(&old, &set, &params()), Err(FinalityError::Stale));
        let fut = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, 1_000_100 + 500, DIGEST);
        assert_eq!(verify_finality(&fut, &set, &params()), Err(FinalityError::Stale));
    }

    #[test]
    fn non_monotonic_height_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut p = params();
        p.max_height_seen = 300;
        let b = bundle(&set, &keys, &[0, 1, 2], 200, ROUND, BT, DIGEST);
        assert_eq!(verify_finality(&b, &set, &p), Err(FinalityError::HeightRollback));
    }

    #[test]
    fn expired_pin_fails_closed() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut p = params();
        p.now_unix = set.pinned_at_unix + p.ws_period_secs + 1;
        let b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, p.now_unix, DIGEST);
        assert_eq!(verify_finality(&b, &set, &p), Err(FinalityError::PinExpired));
    }

    #[test]
    fn height_before_pin_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], 50, ROUND, BT, DIGEST); // pin at 100
        assert_eq!(verify_finality(&b, &set, &params()), Err(FinalityError::HeightBeforePin));
    }

    #[test]
    fn round_zero_is_omitted_from_canonical_bytes() {
        // proto3: a zero sfixed64 field is omitted. round 0 vs round 1 must differ,
        // and round 0's encoding must NOT contain the round tag (0x19).
        let ext = vote_ext(HEIGHT, BT, DIGEST);
        let r0 = canonical_vote_ext_bytes(&ext, HEIGHT as i64, 0, CHAIN);
        let r1 = canonical_vote_ext_bytes(&ext, HEIGHT as i64, 1, CHAIN);
        assert_ne!(r0, r1);
        assert!(!r0.contains(&0x19), "round 0 must be omitted");
    }

    #[test]
    fn parse_bundle_round_trips() {
        use base64::Engine as _;
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], HEIGHT, ROUND, BT, DIGEST);
        let atts: Vec<serde_json::Value> = b
            .attestations
            .iter()
            .map(|a| {
                serde_json::json!({
                    "validator_cons_addr": a.valcons,
                    "signature": hex::encode(&a.signature),
                    "vote_extension": base64::engine::general_purpose::STANDARD.encode(&a.vote_extension),
                    "round": ROUND.to_string(),
                })
            })
            .collect();
        let json = serde_json::json!({
            "height": HEIGHT.to_string(),
            "block_time": BT.to_string(),
            "attestations": atts,
        });
        let parsed = parse_bundle(DIGEST, &json).expect("parses");
        assert_eq!(parsed.attestations.len(), 3);
        assert_eq!(verify_finality(&parsed, &set, &params()), Ok(HEIGHT));
    }

    #[test]
    fn parse_bundle_drops_auto_consensus() {
        let json = serde_json::json!({
            "height": "5", "block_time": "1",
            "attestations": [{ "validator_cons_addr": "", "signature": "auto:consensus", "vote_extension": "" }],
        });
        let parsed = parse_bundle("d", &json).unwrap();
        assert!(parsed.attestations.is_empty());
    }
}
