//! ECIES + AES for CryptMessage, byte-for-byte compatible with EpixNet's
//! `sslcrypto` (secp256k1, `derivation="sha512"`, `aes-256-cbc`, `hmac-sha256`).
//!
//! Wire layout of an encrypted blob:
//! ```text
//! iv[16] ‖ pubkey(nid=714 ‖ len‖X ‖ len‖Y) ‖ AES-256-CBC(data) ‖ HMAC-SHA256[32]
//! ```
//! with `ecdh = X(ephem_priv · recipient_pub)` (raw 32-byte x-coordinate),
//! `key = SHA512(ecdh)`, `k_enc = key[:32]`, `k_mac = key[32:]`, and the MAC
//! computed over `iv ‖ pubkey ‖ ciphertext`.

use crate::{priv_to_scalar, scalar_from_be_reduced, uncompressed_pubkey};
use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{ProjectivePoint, PublicKey, Scalar};
use sha2::{Digest, Sha512};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<sha2::Sha256>;

/// OpenSSL curve id for secp256k1 (as sslcrypto encodes the ephemeral pubkey).
const NID_SECP256K1: u16 = 714;

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("os rng");
    b
}

/// ECDH shared secret: the raw x-coordinate (32 bytes) of `scalar · pubkey`.
fn ecdh(scalar: &Scalar, pubkey: &[u8]) -> Result<[u8; 32], String> {
    let pk = PublicKey::from_sec1_bytes(pubkey).map_err(|e| format!("bad public key: {e}"))?;
    let shared = (ProjectivePoint::from(*pk.as_affine()) * scalar).to_affine();
    let point = shared.to_sec1_point(false);
    let x = point.x().ok_or("shared point at infinity")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(x);
    Ok(out)
}

/// Encode an ephemeral pubkey (65-byte `04‖X‖Y`) the sslcrypto/OpenSSL way:
/// `nid ‖ len(X) ‖ X ‖ len(Y) ‖ Y`.
fn encode_pubkey(uncompressed: &[u8]) -> Vec<u8> {
    let x = &uncompressed[1..33];
    let y = &uncompressed[33..65];
    let mut out = Vec::with_capacity(6 + x.len() + y.len());
    out.extend_from_slice(&NID_SECP256K1.to_be_bytes());
    out.extend_from_slice(&(x.len() as u16).to_be_bytes());
    out.extend_from_slice(x);
    out.extend_from_slice(&(y.len() as u16).to_be_bytes());
    out.extend_from_slice(y);
    out
}

/// AES-256-CBC encrypt with PKCS#7 padding.
pub fn aes_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let enc = Aes256CbcEnc::new_from_slices(key, iv).map_err(|e| e.to_string())?;
    Ok(enc.encrypt_padded_vec::<Pkcs7>(data))
}

/// AES-256-CBC decrypt (PKCS#7).
pub fn aes_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let dec = Aes256CbcDec::new_from_slices(key, iv).map_err(|e| e.to_string())?;
    dec.decrypt_padded_vec::<Pkcs7>(ciphertext).map_err(|e| e.to_string())
}

/// Generate a fresh AES-256 key.
pub fn aes_new_key() -> [u8; 32] {
    random::<32>()
}

/// A fresh 16-byte IV.
pub fn aes_new_iv() -> [u8; 16] {
    random::<16>()
}

/// ECIES-encrypt `data` to `pubkey` (SEC1 compressed or uncompressed). Returns
/// the wire blob and the AES key used (so callers can re-decrypt with it).
pub fn ecies_encrypt(data: &[u8], pubkey: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    let ephemeral = scalar_from_be_reduced(&random::<32>());
    let shared_x = ecdh(&ephemeral, pubkey)?;
    let key = Sha512::digest(shared_x);
    let (k_enc, k_mac) = (&key[..32], &key[32..]);

    let iv = random::<16>();
    let ciphertext = aes_encrypt(data, k_enc, &iv)?;
    let ephem_pub = encode_pubkey(&uncompressed_pubkey(&ephemeral));

    let mut blob = Vec::new();
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&ephem_pub);
    blob.extend_from_slice(&ciphertext);

    let mut mac = HmacSha256::new_from_slice(k_mac).expect("hmac key");
    mac.update(&blob);
    blob.extend_from_slice(&mac.finalize().into_bytes());

    let mut k = [0u8; 32];
    k.copy_from_slice(k_enc);
    Ok((blob, k))
}

/// ECIES-decrypt a wire blob with `privatekey` (64-hex or WIF).
pub fn ecies_decrypt(blob: &[u8], privatekey: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 16 + 6 + 32 {
        return Err("ciphertext too short".into());
    }
    let scalar = priv_to_scalar(privatekey)?;
    let iv = &blob[0..16];

    let pubkey_region = &blob[16..];
    if u16::from_be_bytes([pubkey_region[0], pubkey_region[1]]) != NID_SECP256K1 {
        return Err("wrong curve".into());
    }
    let xlen = u16::from_be_bytes([pubkey_region[2], pubkey_region[3]]) as usize;
    let x = &pubkey_region[4..4 + xlen];
    let ylen = u16::from_be_bytes([pubkey_region[4 + xlen], pubkey_region[5 + xlen]]) as usize;
    let y = &pubkey_region[6 + xlen..6 + xlen + ylen];
    let pubkey_len = 6 + xlen + ylen;

    let ciphertext = &blob[16 + pubkey_len..blob.len() - 32];
    let tag = &blob[blob.len() - 32..];

    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(x);
    uncompressed.extend_from_slice(y);
    let shared_x = ecdh(&scalar, &uncompressed)?;
    let key = Sha512::digest(shared_x);
    let (k_enc, k_mac) = (&key[..32], &key[32..]);

    let mut mac = HmacSha256::new_from_slice(k_mac).expect("hmac key");
    mac.update(&blob[..blob.len() - 32]);
    mac.verify_slice(tag).map_err(|_| "MAC verification failed".to_string())?;

    aes_decrypt(ciphertext, k_enc, iv)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

    #[test]
    fn ecies_decrypt_matches_sslcrypto_vector() {
        // Produced by EpixNet's sslcrypto (curve.encrypt, sha512, aes-256-cbc).
        let blob = hex::decode("fcb792d6ca350e83f789c5c9cbc3841802ca00207a4b2f7e437a4201413782eace167ab12625933786a32aa7b89a7be67ce7f7a700203092082a3ab7313a53aab89b1ce986f8ffa84b2d2659d9d490ca03deeb309b4dc8a567d09a551ae72fa66526a30448df38f8b08e42c7675599e94ac60a979e28e888cd2444c0fe0158237b2c9aff777a").unwrap();
        let pt = ecies_decrypt(&blob, PRIV).unwrap();
        assert_eq!(pt, b"hello epix");
    }

    #[test]
    fn ecies_round_trips_to_our_own_pubkey() {
        let pubkey = crate::compressed_pubkey(&priv_to_scalar(PRIV).unwrap());
        let (blob, _k) = ecies_encrypt(b"round trip \xf0\x9f\x94\x92", &pubkey).unwrap();
        assert_eq!(ecies_decrypt(&blob, PRIV).unwrap(), b"round trip \xf0\x9f\x94\x92");
        // Tampering breaks the MAC.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(ecies_decrypt(&bad, PRIV).is_err());
    }

    #[test]
    fn aes_matches_sslcrypto_vector() {
        let key = [0u8; 32];
        let iv = hex::decode("6758b91d263938922ead4f7617583e4d").unwrap();
        let ct = hex::decode("080f03742c798716976a84686429a521").unwrap();
        assert_eq!(aes_decrypt(&ct, &key, &iv).unwrap(), b"aes test");
        assert_eq!(aes_encrypt(b"aes test", &key, &iv).unwrap(), ct);
    }
}
