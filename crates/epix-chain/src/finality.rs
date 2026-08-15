//! Client-side finality verification for the xID state digest.
//!
//! The chain has validators sign the current state digest (via ABCI++ vote
//! extensions, with a per-validator *attestation key* registered on-chain). This
//! module verifies that bundle **against a config-pinned validator set** so a
//! resolved `name → digest` is proven finalized by a supermajority of validator
//! voting power — WITHOUT trusting an RPC boolean, and WITHOUT a CometBFT light
//! client (no ics23/tendermint-rs). It is deliberately thin: a handful of
//! `ed25519` verifies + a power sum, so it is cheap on mobile.
//!
//! Trust model (see `docs/xid-lightclient-finality.md`): weak subjectivity. The
//! caller pins `{valcons → (pubkey, voting_power)}` + `chain_id` from a signed app
//! release; this module fails closed when the pin is older than `ws_period`. There
//! is no equivocation slashing, so the honest claim is "signed by >2/3 of a pinned
//! set", backed by a power safety-buffer (`min_power_bps`, default 80%) so a stale
//! pin whose power has drifted cannot be cleared by a bare 2/3.
//!
//! Security rules enforced here (each has a test):
//! - verify each signature against the **PINNED** pubkey, never the RPC-supplied
//!   one (else an attacker pairs a pinned valcons with its own key);
//! - **dedup by valcons** (a repeated validator counts once);
//! - **strict** supermajority `sum*3 > total*2` AND the `min_power_bps` buffer;
//! - freshness `|now − block_time| ≤ skew` and **monotonic** height;
//! - pin not expired (`now − pinned_at ≤ ws_period`) and bundle height ≥ pin height.

use std::collections::HashMap;

use ed25519_dalek::{Signature, VerifyingKey};

/// Domain tag mixed into the attestation sign-bytes — a fixed 16 bytes so a
/// validator attestation signature can never be reinterpreted as a CometBFT
/// consensus vote (which has entirely different sign-bytes) or vice versa. MUST
/// match the chain's `x/xid` signer byte-for-byte.
pub const ATTEST_DOMAIN: &[u8; 16] = b"EPIX-XID-ATTEST1";

/// Default power safety-buffer: require ≥80% of pinned voting power, not a bare
/// 2/3, so a pinned set whose real power has partly migrated away cannot be
/// cleared by exactly-2/3 of the (over-credited) pinned total between re-pins.
pub const DEFAULT_MIN_POWER_BPS: u32 = 8000;

/// One pinned validator: its attestation `ed25519` pubkey and voting power. Keyed
/// by consensus address (`valcons…`) in [`PinnedSet`].
#[derive(Clone, Debug)]
pub struct PinnedValidator {
    pub pubkey: [u8; 32],
    pub voting_power: u64,
}

/// The pinned validator set — the client's root of trust, shipped in signed
/// config and re-pinned within the weak-subjectivity window.
#[derive(Clone, Debug)]
pub struct PinnedSet {
    /// `valcons` → pinned validator.
    pub validators: HashMap<String, PinnedValidator>,
    /// Sum of `voting_power` over `validators` (the finality denominator).
    pub total_power: u64,
    /// The chain id these keys belong to (bound into every sign-bytes).
    pub chain_id: String,
    /// Unix seconds when this pin was captured (weak-subjectivity clock).
    pub pinned_at_unix: i64,
    /// Chain height the pin was captured at; bundles older than this are rejected.
    pub pinned_at_height: u64,
}

impl PinnedSet {
    /// Build a pinned set, computing `total_power`.
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

/// One validator's attestation as served by the RPC. `pubkey`/`voting_power` here
/// are UNTRUSTED (attacker-controlled); verification uses the pinned values keyed
/// by `valcons`, never these.
#[derive(Clone, Debug)]
pub struct AttestationEntry {
    pub valcons: String,
    pub signature: Vec<u8>,
}

/// The finality bundle the client fetches for a digest.
#[derive(Clone, Debug)]
pub struct FinalityBundle {
    /// The attested state digest (hex of the 32-byte tree root).
    pub digest_hex: String,
    pub height: u64,
    pub block_time_unix: i64,
    pub attestations: Vec<AttestationEntry>,
}

/// Verification parameters (client clock + policy).
#[derive(Clone, Copy, Debug)]
pub struct VerifyParams {
    pub now_unix: i64,
    /// Max |now − block_time| accepted (freshness). Size ≥ block time + consensus
    /// synchrony precision; `block_time` is BFT-time, not honest wall time.
    pub skew_secs: i64,
    /// Max pin age before finality fails closed (< unbonding/2).
    pub ws_period_secs: i64,
    /// Required fraction of pinned power, in basis points (10000 = 100%).
    pub min_power_bps: u32,
    /// Highest bundle height already accepted (monotonic anti-replay floor).
    pub max_height_seen: u64,
}

/// Why a bundle was rejected. All are fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalityError {
    /// The pin is older than `ws_period` — must re-pin from a trusted source.
    PinExpired,
    /// The bundle is for a height older than the pin (can't verify pre-pin state).
    HeightBeforePin,
    /// `block_time` is outside the freshness window.
    Stale,
    /// The bundle height is below the monotonic floor (replay of an old digest).
    HeightRollback,
    /// The digest field is not valid 32-byte hex.
    BadDigest,
    /// Verified voting power did not reach the required threshold.
    InsufficientPower { got: u64, total: u64, need_bps: u32 },
}

/// The exact bytes a validator signs for `(chain_id, height, block_time, digest)`.
/// Fully length-delimited and fixed-width so no two distinct tuples share a
/// preimage (the chain must produce identical bytes). `digest` is the raw 32-byte
/// tree root (not its hex).
pub fn attest_sign_bytes(chain_id: &str, height: u64, block_time_unix: i64, digest: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + 4 + chain_id.len() + 8 + 8 + 4 + digest.len());
    m.extend_from_slice(ATTEST_DOMAIN);
    m.extend_from_slice(&(chain_id.len() as u32).to_be_bytes());
    m.extend_from_slice(chain_id.as_bytes());
    m.extend_from_slice(&height.to_be_bytes());
    m.extend_from_slice(&block_time_unix.to_be_bytes());
    m.extend_from_slice(&(digest.len() as u32).to_be_bytes());
    m.extend_from_slice(digest);
    m
}

/// Verify a finality bundle against the pinned set. On success returns the bundle
/// height (the caller advances its `max_height_seen`). Fails closed on any rule.
///
/// `expected_digest_hex`, if given, must equal the bundle's digest — the caller
/// passes the digest it independently bound to the name's Merkle `proof_root`, so
/// a bundle for a *different* (but validly-signed) digest cannot be substituted.
pub fn verify_finality(
    bundle: &FinalityBundle,
    pinned: &PinnedSet,
    params: &VerifyParams,
) -> Result<u64, FinalityError> {
    // Weak-subjectivity: refuse to verify against a pin that may be past unbonding.
    if params.now_unix.saturating_sub(pinned.pinned_at_unix) > params.ws_period_secs {
        return Err(FinalityError::PinExpired);
    }
    // Can't prove a state older than the pin.
    if bundle.height < pinned.pinned_at_height {
        return Err(FinalityError::HeightBeforePin);
    }
    // Freshness (both directions) and monotonic height (anti-replay).
    if (params.now_unix - bundle.block_time_unix).abs() > params.skew_secs {
        return Err(FinalityError::Stale);
    }
    if bundle.height < params.max_height_seen {
        return Err(FinalityError::HeightRollback);
    }
    // The digest is the raw 32-byte tree root; decode it once for the sign-bytes.
    let digest = match hex::decode(&bundle.digest_hex) {
        Ok(d) if d.len() == 32 => d,
        _ => return Err(FinalityError::BadDigest),
    };
    let msg = attest_sign_bytes(&pinned.chain_id, bundle.height, bundle.block_time_unix, &digest);

    // Sum the voting power of PINNED validators with a valid signature, each
    // counted at most once. Validators not in the pin are ignored; the RPC-supplied
    // pubkey is never used — we verify against the pinned pubkey.
    let mut counted: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut power: u64 = 0;
    for att in &bundle.attestations {
        let Some(v) = pinned.validators.get(&att.valcons) else { continue };
        if counted.contains(att.valcons.as_str()) {
            continue; // dedup: one vote per validator
        }
        let Ok(vk) = VerifyingKey::from_bytes(&v.pubkey) else { continue };
        let sig = match sig_from_bytes(&att.signature) {
            Some(s) => s,
            None => continue,
        };
        // verify_strict rejects non-canonical signatures (malleability).
        if vk.verify_strict(&msg, &sig).is_ok() {
            counted.insert(att.valcons.as_str());
            power = power.saturating_add(v.voting_power);
        }
    }

    // Require BOTH a strict supermajority (sum*3 > total*2) and the power buffer
    // (sum*10000 ≥ total*min_power_bps). The buffer (default 80%) subsumes 2/3, but
    // the strict check is the floor if a caller lowers the buffer.
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

/// Parse a 64-byte ed25519 signature.
fn sig_from_bytes(bytes: &[u8]) -> Option<Signature> {
    let arr: [u8; 64] = bytes.try_into().ok()?;
    Some(Signature::from_bytes(&arr))
}

/// A u64 that Cosmos proto-JSON may encode as a number or a string ("5011899").
fn num_u64(v: Option<&serde_json::Value>) -> Option<u64> {
    let v = v?;
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Likewise for a signed int64 (e.g. a unix `block_time`).
fn num_i64(v: Option<&serde_json::Value>) -> Option<i64> {
    let v = v?;
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Parse the `/xid/v1/attestations` response into a [`FinalityBundle`] for
/// `digest_hex`. Signatures are hex. The per-validator RPC `ed25519_pubkey` /
/// `voting_power` are intentionally IGNORED here — [`verify_finality`] uses the
/// pinned values keyed by `valcons`, never the RPC-supplied ones — so only
/// `validator_cons_addr` + `signature` are consumed. Returns `None` if the
/// required top-level fields are missing.
pub fn parse_bundle(digest_hex: &str, v: &serde_json::Value) -> Option<FinalityBundle> {
    let height = num_u64(v.get("height"))?;
    let block_time_unix = num_i64(v.get("block_time"))?;
    let atts = v.get("attestations")?.as_array()?;
    let mut attestations = Vec::with_capacity(atts.len());
    for a in atts {
        let valcons = a.get("validator_cons_addr").and_then(|x| x.as_str())?.to_string();
        let sig_hex = a.get("signature").and_then(|x| x.as_str())?;
        let Ok(signature) = hex::decode(sig_hex.trim()) else { continue };
        attestations.push(AttestationEntry { valcons, signature });
    }
    Some(FinalityBundle { digest_hex: digest_hex.to_string(), height, block_time_unix, attestations })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Build a pinned set of `n` validators with the given powers, chain id, pinned
    /// now, at height 100. Returns (set, signing keys keyed by valcons).
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
        (PinnedSet::new(validators, "epix_1916-1", 1_000_000, 100), keys)
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

    const DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// Sign the canonical bytes for `signers` (subset of keys) at a height/time.
    fn bundle(
        set: &PinnedSet,
        keys: &[(String, SigningKey)],
        signers: &[usize],
        height: u64,
        block_time: i64,
        digest_hex: &str,
    ) -> FinalityBundle {
        let digest = hex::decode(digest_hex).unwrap();
        let msg = attest_sign_bytes(&set.chain_id, height, block_time, &digest);
        let attestations = signers
            .iter()
            .map(|&i| {
                let (valcons, sk) = &keys[i];
                AttestationEntry { valcons: valcons.clone(), signature: sk.sign(&msg).to_bytes().to_vec() }
            })
            .collect();
        FinalityBundle { digest_hex: digest_hex.into(), height, block_time_unix: block_time, attestations }
    }

    #[test]
    fn all_validators_sign_verifies() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_090, DIGEST);
        assert_eq!(verify_finality(&b, &set, &params()), Ok(200));
    }

    #[test]
    fn four_of_five_equal_power_meets_80_percent() {
        let (set, keys) = setup(&[1, 1, 1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2, 3], 200, 1_000_090, DIGEST);
        // 80% exactly, strict 2/3 (12 > 10) → accepts.
        assert_eq!(verify_finality(&b, &set, &params()), Ok(200));
    }

    #[test]
    fn exactly_two_thirds_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        // 2 of 3 = 66.6%: fails the strict supermajority (6 > 6 is false) AND the buffer.
        let b = bundle(&set, &keys, &[0, 1], 200, 1_000_090, DIGEST);
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { .. })
        ));
    }

    #[test]
    fn power_buffer_rejects_a_strict_two_thirds_pass() {
        // A(100)+B..D(100 each)+E(600) total 1000. E+A = 700 (70%): passes strict
        // 2/3 (2100 > 2000) but fails the 80% buffer → reject. This is the stale-pin
        // safety the buffer exists for.
        let (set, keys) = setup(&[100, 100, 100, 100, 600]);
        let b = bundle(&set, &keys, &[4, 0], 200, 1_000_090, DIGEST);
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 700, total: 1000, .. })
        ));
    }

    #[test]
    fn rpc_pubkey_different_from_pinned_is_not_credited() {
        let (set, keys) = setup(&[1, 1, 1]);
        // Validator 0 signs with a DIFFERENT key than pinned (attacker's key).
        let digest = hex::decode(DIGEST).unwrap();
        let msg = attest_sign_bytes(&set.chain_id, 200, 1_000_090, &digest);
        let attacker = key(200);
        let mut b = bundle(&set, &keys, &[1, 2], 200, 1_000_090, DIGEST); // 2 legit
        b.attestations.push(AttestationEntry {
            valcons: keys[0].0.clone(),
            signature: attacker.sign(&msg).to_bytes().to_vec(),
        });
        // Validator 0's forged sig is verified against the PINNED key → fails, not
        // counted. Only 2 of 3 legit remain → reject.
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 2, total: 3, .. })
        ));
    }

    #[test]
    fn duplicate_valcons_counts_once() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut b = bundle(&set, &keys, &[0], 200, 1_000_090, DIGEST);
        // List validator 0 THREE times — must still count as power 1, not 3.
        let dup = b.attestations[0].clone();
        b.attestations.push(dup.clone());
        b.attestations.push(dup);
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 1, total: 3, .. })
        ));
    }

    #[test]
    fn validator_not_in_pinned_set_is_ignored() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_090, DIGEST);
        // Add a stranger with huge claimed power — ignored (not in pin).
        let stranger = key(250);
        let digest = hex::decode(DIGEST).unwrap();
        let msg = attest_sign_bytes(&set.chain_id, 200, 1_000_090, &digest);
        b.attestations.push(AttestationEntry {
            valcons: "epixvalconsSTRANGER".into(),
            signature: stranger.sign(&msg).to_bytes().to_vec(),
        });
        // The 3 real validators still verify → accepts; stranger contributes nothing.
        assert_eq!(verify_finality(&b, &set, &params()), Ok(200));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_090, DIGEST);
        b.attestations[0].signature[10] ^= 0xff; // flip a byte
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 2, .. })
        ));
    }

    #[test]
    fn wrong_digest_breaks_every_signature() {
        let (set, keys) = setup(&[1, 1, 1]);
        // Sign over DIGEST but present a different digest → sign-bytes differ → all fail.
        let other = "2222222222222222222222222222222222222222222222222222222222222222";
        let mut b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_090, DIGEST);
        b.digest_hex = other.into();
        assert!(matches!(
            verify_finality(&b, &set, &params()),
            Err(FinalityError::InsufficientPower { got: 0, .. })
        ));
    }

    #[test]
    fn stale_block_time_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_100 - 500, DIGEST); // 500s old, skew 120
        assert_eq!(verify_finality(&b, &set, &params()), Err(FinalityError::Stale));
    }

    #[test]
    fn future_block_time_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_100 + 500, DIGEST);
        assert_eq!(verify_finality(&b, &set, &params()), Err(FinalityError::Stale));
    }

    #[test]
    fn non_monotonic_height_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut p = params();
        p.max_height_seen = 300; // we've already accepted height 300
        let b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_090, DIGEST); // replay of older 200
        assert_eq!(verify_finality(&b, &set, &p), Err(FinalityError::HeightRollback));
    }

    #[test]
    fn expired_pin_fails_closed() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut p = params();
        p.now_unix = set.pinned_at_unix + p.ws_period_secs + 1; // pin too old
        let b = bundle(&set, &keys, &[0, 1, 2], 200, p.now_unix, DIGEST);
        assert_eq!(verify_finality(&b, &set, &p), Err(FinalityError::PinExpired));
    }

    #[test]
    fn height_before_pin_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let b = bundle(&set, &keys, &[0, 1, 2], 50, 1_000_090, DIGEST); // pin at 100
        assert_eq!(verify_finality(&b, &set, &params()), Err(FinalityError::HeightBeforePin));
    }

    #[test]
    fn bad_digest_hex_is_rejected() {
        let (set, keys) = setup(&[1, 1, 1]);
        let mut b = bundle(&set, &keys, &[0, 1, 2], 200, 1_000_090, DIGEST);
        b.digest_hex = "not-hex".into();
        assert_eq!(verify_finality(&b, &set, &params()), Err(FinalityError::BadDigest));
    }

    #[test]
    fn parse_bundle_round_trips_and_verifies() {
        let (set, keys) = setup(&[1, 1, 1]);
        // Craft the RPC JSON as the gateway would (uint64 as STRINGS, sigs as hex,
        // rpc pubkey/power present but ignored).
        let digest = hex::decode(DIGEST).unwrap();
        let msg = attest_sign_bytes(&set.chain_id, 200, 1_000_090, &digest);
        let atts: Vec<serde_json::Value> = keys
            .iter()
            .map(|(valcons, sk)| {
                serde_json::json!({
                    "validator_cons_addr": valcons,
                    "ed25519_pubkey": "00", // bogus rpc-supplied key — must be ignored
                    "voting_power": "999",   // bogus rpc-supplied power — must be ignored
                    "signature": hex::encode(sk.sign(&msg).to_bytes()),
                })
            })
            .collect();
        let json = serde_json::json!({
            "digest": DIGEST,
            "height": "200",          // string, as Cosmos encodes uint64
            "block_time": "1000090",  // string
            "attestations": atts,
        });
        let bundle = parse_bundle(DIGEST, &json).expect("bundle parses");
        assert_eq!(bundle.height, 200);
        assert_eq!(bundle.block_time_unix, 1_000_090);
        assert_eq!(bundle.attestations.len(), 3);
        // And the parsed bundle verifies against the pinned set (rpc pubkey ignored).
        assert_eq!(verify_finality(&bundle, &set, &params()), Ok(200));
    }

    #[test]
    fn parse_bundle_rejects_missing_fields() {
        assert!(parse_bundle("d", &serde_json::json!({ "height": "1" })).is_none());
    }

    #[test]
    fn attest_sign_bytes_kat() {
        // Frozen cross-repo Known-Answer Test — the SAME vector is asserted in
        // EpixChain x/xid/types/attestation_signbytes_test.go. If either side's
        // encoding drifts, one of these two KATs breaks. Vector: chain_id
        // "epix_1916-1", height 200, block_time 1000090, digest = 32 bytes of 0x11.
        let digest = [0x11u8; 32];
        let got = hex::encode(attest_sign_bytes("epix_1916-1", 200, 1_000_090, &digest));
        let want = concat!(
            "455049582d5849442d41545445535431", // domain "EPIX-XID-ATTEST1"
            "0000000b",                         // len(chain_id)=11
            "657069785f313931362d31",           // "epix_1916-1"
            "00000000000000c8",                 // height=200 (u64 BE)
            "00000000000f429a",                 // block_time=1000090 (i64 BE)
            "00000020",                         // len(digest)=32
            "1111111111111111111111111111111111111111111111111111111111111111",
        );
        assert_eq!(got, want, "attest sign-bytes KAT must match the Go chain signer");
    }

    #[test]
    fn sign_bytes_are_unambiguous_across_chain_id_boundary() {
        // A boundary-shift pair must not collide (length-prefixing prevents it).
        let d = [7u8; 32];
        let a = attest_sign_bytes("epix_1916", 1, 0, &d);
        let b = attest_sign_bytes("epix_1916-1", 1, 0, &d);
        assert_ne!(a, b);
    }
}
