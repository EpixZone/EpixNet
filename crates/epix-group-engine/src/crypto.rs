//! Symmetric primitives, matching the pairwise engine: HKDF-SHA256 KDF,
//! HMAC-SHA256 MAC, ChaCha20-Poly1305 AEAD.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// `out ← HKDF-SHA256(salt, ikm, info = context)`.
pub fn kdf(context: &str, salt: &[u8], ikm: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(context.as_bytes(), out).expect("HKDF output length within bounds");
}

/// HMAC-SHA256 over `data` under a 32-byte key.
pub fn mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], pt: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(&Nonce::from(*nonce), Payload { msg: pt, aad: ad })
        .expect("chacha20poly1305 seal never fails for valid inputs")
}

pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(&Key::from(*key))
        .decrypt(&Nonce::from(*nonce), Payload { msg: ct, aad: ad })
        .ok()
}
