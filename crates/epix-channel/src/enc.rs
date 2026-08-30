//! Optional at-rest encryption for the private channel index.
//!
//! When enabled (`channel_encrypt_at_rest`), the sensitive plaintext in
//! `channels.db` — message bodies/subjects, their thread previews, and the live
//! ratchet session blobs — is sealed with XChaCha20-Poly1305 under a key derived
//! from the node master seed, so a stolen `channels.db` yields neither past
//! message content nor the keys to continue a session. The nonce is random per
//! value (24 bytes, prepended), so there is no nonce-reuse risk. Detection tags
//! stay in the clear (they are the lookup keys and are pseudorandom); full-text
//! search falls back to a decrypt-then-scan when encryption is on.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

/// Seal `pt` under `key`; returns `nonce(24) ‖ ciphertext‖tag`.
pub fn seal(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("os rng");
    let ct = cipher
        .encrypt(&XNonce::from(nonce), pt)
        .expect("XChaCha20-Poly1305 seal never fails for valid inputs");
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Open a `nonce(24) ‖ ct` blob under `key`. `None` on any authentication failure.
pub fn open(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 24 {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&blob[..24]);
    cipher.decrypt(&XNonce::from(nonce), &blob[24..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let key = [9u8; 32];
        let blob = seal(&key, b"secret ZXQ7");
        assert!(!blob.windows(4).any(|w| w == b"ZXQ7"), "plaintext not in ciphertext");
        assert_eq!(open(&key, &blob).unwrap(), b"secret ZXQ7");
        // Wrong key and tampered blob both fail to open.
        assert!(open(&[8u8; 32], &blob).is_none());
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, &bad).is_none());
        // Two seals of the same plaintext differ (random nonce).
        assert_ne!(seal(&key, b"x"), seal(&key, b"x"));
    }
}
