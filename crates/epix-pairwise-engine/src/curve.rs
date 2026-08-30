//! X25519 Diffie-Hellman and Elligator2 representative encoding, both over the
//! `curve25519-elligator2` fork so there is exactly one Montgomery point type.
//!
//! `dh`/`public_key` are ordinary x25519 (clamped-scalar mult). `elligator_*`
//! turn a fresh keypair's public key into a uniform 32-byte representative (used
//! as a first-contact detection tag) and back, so an observer cannot tell a
//! first-contact record's tag from the pseudorandom HMAC tags of established
//! records.

use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};

/// The x25519 public key for a 32-byte secret scalar.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// x25519 Diffie-Hellman: `clamp(secret) · peer_public`.
pub fn dh(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint(*peer_public).mul_clamped(*secret).to_bytes()
}

/// Try to encode the public key of `secret` as a uniform Elligator2
/// representative. `tweak` randomizes the unused high bits; returns `None` when
/// this key is not representable (~50% — the caller retries with a fresh key).
pub fn elligator_encode(secret: &[u8; 32], tweak: u8) -> Option<[u8; 32]> {
    Randomized::to_representative(secret, tweak).into()
}

/// Decode an Elligator2 representative back to the Montgomery public key it
/// encodes (for the recipient's detection DH). Always succeeds for a well-formed
/// representative produced by [`elligator_encode`].
pub fn elligator_decode(representative: &[u8; 32]) -> Option<[u8; 32]> {
    MontgomeryPoint::from_representative::<Randomized>(representative).map(|p| p.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand32() -> [u8; 32] {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).unwrap();
        b
    }

    #[test]
    fn dh_is_symmetric() {
        let a = rand32();
        let b = rand32();
        let ab = dh(&a, &public_key(&b));
        let ba = dh(&b, &public_key(&a));
        assert_eq!(ab, ba, "x25519 DH agrees from both sides");
    }

    #[test]
    fn elligator_roundtrip_preserves_dh() {
        // Find a representable ephemeral key.
        let (eph, repr) = loop {
            let e = rand32();
            if let Some(r) = elligator_encode(&e, rand32()[0]) {
                break (e, r);
            }
        };
        // The recipient decodes the representative to the ephemeral public key,
        // and DH against it must match the sender's DH against the recipient key.
        let recipient = rand32();
        let decoded = elligator_decode(&repr).expect("decode a valid representative");
        let sender_side = dh(&eph, &public_key(&recipient));
        let recipient_side = dh(&recipient, &decoded);
        assert_eq!(
            sender_side, recipient_side,
            "elligator-decoded ephemeral yields the same DH secret"
        );
    }

    #[test]
    fn representatives_look_uniform_ish() {
        // The top bit of a representative should not be pinned (unlike a raw
        // x25519 u-coordinate, which is always < 2^255). Sample a few.
        let mut high_set = 0;
        for _ in 0..16 {
            let e = rand32();
            if let Some(r) = elligator_encode(&e, rand32()[0]) {
                if r[31] & 0x80 != 0 {
                    high_set += 1;
                }
            }
        }
        // Not a statistical proof, just a smoke test that the high bit varies.
        assert!(high_set > 0, "representative high bit is randomized");
    }
}
