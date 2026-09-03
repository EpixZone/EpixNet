//! Symmetric primitives: an HKDF-SHA256 KDF, an HMAC-SHA256 MAC, and
//! ChaCha20-Poly1305 AEAD.
//!
//! The KDF/MAC match the primitives the published Signal X3DH and Double Ratchet
//! specs are written against (HKDF-SHA256 / HMAC-SHA256), so the whole session
//! core is one SHA-256 family and a security review can diff it against the
//! reference rather than re-analyse a bespoke construction. (An earlier build
//! used BLAKE3 here; that was swapped to HKDF-SHA256 for reviewability.)

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
// hmac 0.13 moved `new_from_slice` from the `Mac` trait to `KeyInit`;
// aliased because chacha20poly1305 re-exports its own `KeyInit` above.
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separated key derivation: `out ← HKDF-SHA256(salt, ikm, info = context)`.
/// i.e. `HKDF-Expand(HKDF-Extract(salt, ikm), context, out.len())`. `out.len()`
/// may be any length up to 255·32 = 8160 bytes (KDF chains take 32/44/64 at once).
pub fn kdf(context: &str, salt: &[u8], ikm: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(context.as_bytes(), out).expect("HKDF output length within 255*32 bytes");
}

/// A fixed 32-byte KDF output.
pub fn kdf32(context: &str, salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    kdf(context, salt, ikm, &mut out);
    out
}

/// Keyed MAC over `data` under a 32-byte key (HMAC-SHA256).
pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut m =
        <HmacSha256 as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// AEAD-seal `pt` under `key`/`nonce`, authenticating `ad`. Returns ct‖tag.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .encrypt(&Nonce::from(*nonce), Payload { msg: pt, aad: ad })
        .expect("chacha20poly1305 seal never fails for valid inputs")
}

/// AEAD-open `ct` (ct‖tag) under `key`/`nonce`, checking `ad`. `None` on any
/// authentication failure — the primary "is this record for me / intact" signal.
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(&Key::from(*key));
    cipher.decrypt(&Nonce::from(*nonce), Payload { msg: ct, aad: ad }).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_and_separated() {
        let a = kdf32("epix-channel/test/v1", b"salt", b"ikm");
        let b = kdf32("epix-channel/test/v1", b"salt", b"ikm");
        assert_eq!(a, b);
        // Different context / salt / ikm each change the output.
        assert_ne!(a, kdf32("epix-channel/test/v2", b"salt", b"ikm"));
        assert_ne!(a, kdf32("epix-channel/test/v1", b"salt2", b"ikm"));
        assert_ne!(a, kdf32("epix-channel/test/v1", b"salt", b"ikm2"));
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let ct = aead_seal(&key, &nonce, b"ad", b"secret ZXQ1");
        assert!(!ct.windows(4).any(|w| w == b"ZXQ1"), "plaintext not in ciphertext");
        assert_eq!(aead_open(&key, &nonce, b"ad", &ct).unwrap(), b"secret ZXQ1");
        // Wrong AD, wrong key, and tampered ct all fail to open.
        assert!(aead_open(&key, &nonce, b"other", &ct).is_none());
        assert!(aead_open(&[8u8; 32], &nonce, b"ad", &ct).is_none());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_open(&key, &nonce, b"ad", &bad).is_none());
    }
}
