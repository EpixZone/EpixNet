//! EpixNet cryptography, reimplemented in Rust to be **bit-for-bit compatible**
//! with the Python `CryptEpix.py` + `sslcrypto` + `Electrum.py` reference.
//!
//! Scheme summary (see EpixNet/src/Crypt/CryptEpix.py):
//! - Address: Keccak256(64-byte uncompressed pubkey X‖Y) → last 20 bytes →
//!   bech32 with HRP `epix` (`epix1…`).
//! - WIF: base58check(`0x80` ‖ priv32) — no compression flag byte.
//! - Signing: recoverable ECDSA. `dbl` path hashes with the Bitcoin
//!   "Signed Message" magic then double-SHA256; `keccak` path is bare Keccak256.
//!   Serialized as `[27+recid] ‖ r(32) ‖ s(32)`, base64.
//! - HD derivation (`derive_child`): a custom single-level, BIP32-flavored step.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;

pub mod ecies;

type HmacSha512 = Hmac<Sha512>;

/// Compressed SEC1 pubkey (33 bytes) for a private key — EpixNet's `eccPrivToPub`.
pub fn private_to_compressed_pubkey(privatekey: &str) -> Result<Vec<u8>, String> {
    Ok(compressed_pubkey(&priv_to_scalar(privatekey)?))
}

/// The epix1 address for a SEC1 pubkey (compressed or uncompressed) —
/// EpixNet's `eccPubToAddr`.
pub fn pubkey_to_address(pubkey: &[u8]) -> Result<String, String> {
    let pk = k256::PublicKey::from_sec1_bytes(pubkey).map_err(|e| e.to_string())?;
    public_key_to_address(pk.to_encoded_point(false).as_bytes())
}

/// Reduce 32 big-endian bytes into a secp256k1 scalar (mod curve order n),
/// matching Python's `BN(bytes) % order`.
fn scalar_from_be_reduced(bytes: &[u8]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(U256::from_be_slice(bytes))
}

/// secp256k1 base-point multiply: returns the affine public key for `scalar`.
fn pubkey_point(scalar: &Scalar) -> k256::AffinePoint {
    (ProjectivePoint::GENERATOR * scalar).to_affine()
}

/// Compressed SEC1 pubkey (33 bytes: `0x02|0x03 ‖ X`) for a private scalar.
fn compressed_pubkey(scalar: &Scalar) -> Vec<u8> {
    pubkey_point(scalar).to_encoded_point(true).as_bytes().to_vec()
}

/// Uncompressed SEC1 pubkey (65 bytes: `0x04 ‖ X ‖ Y`) for a private scalar.
fn uncompressed_pubkey(scalar: &Scalar) -> Vec<u8> {
    pubkey_point(scalar).to_encoded_point(false).as_bytes().to_vec()
}

/// `derive_child(seed, child)` — exact port of sslcrypto's openssl backend.
///
/// ```text
/// h     = HMAC-SHA512("Bitcoin seed", seed)
/// priv1 = h[:32];  chain = h[32:]
/// pub1  = compressed_pubkey(priv1)
/// h2    = HMAC-SHA512(chain, pub1 ‖ child_be32)
/// priv2 = h2[:32]
/// out   = (priv1 + priv2) mod n          (32-byte big-endian)
/// ```
pub fn derive_child(seed: &[u8], child: u32) -> [u8; 32] {
    // Round 1
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed").unwrap();
    mac.update(seed);
    let h = mac.finalize().into_bytes();
    let s1 = scalar_from_be_reduced(&h[..32]);
    let pub1 = compressed_pubkey(&s1);
    let chain = &h[32..];

    // Round 2
    let mut mac2 = HmacSha512::new_from_slice(chain).unwrap();
    mac2.update(&pub1);
    mac2.update(&child.to_be_bytes());
    let h2 = mac2.finalize().into_bytes();
    let s2 = scalar_from_be_reduced(&h2[..32]);

    let out = s1 + s2;
    let fb: FieldBytes = out.to_bytes();
    let mut res = [0u8; 32];
    res.copy_from_slice(&fb);
    res
}

/// WIF encode a 32-byte private key: base58check(`0x80` ‖ priv).
pub fn private_to_wif(priv32: &[u8; 32]) -> String {
    let mut payload = Vec::with_capacity(33);
    payload.push(0x80);
    payload.extend_from_slice(priv32);
    bs58::encode(payload).with_check().into_string()
}

/// WIF decode to a 32-byte private key.
pub fn wif_to_private(wif: &str) -> Result<[u8; 32], String> {
    let dec = bs58::decode(wif)
        .with_check(None)
        .into_vec()
        .map_err(|e| format!("base58check: {e}"))?;
    if dec.first() != Some(&0x80) {
        return Err("Invalid network (expected mainnet 0x80)".into());
    }
    if dec.len() != 33 {
        return Err(format!("unexpected wif payload len {}", dec.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&dec[1..33]);
    Ok(out)
}

/// `hdPrivatekey(seed_hex, child)` → WIF string.
pub fn hd_privatekey(seed_hex: &str, child: u64) -> Result<String, String> {
    let seed = hex::decode(seed_hex).map_err(|e| format!("seed hex: {e}"))?;
    let priv32 = derive_child(&seed, (child % 100_000_000) as u32);
    Ok(private_to_wif(&priv32))
}

/// Keccak256(last-20-of) → bech32 `epix` address from a 64- or 65-byte pubkey.
pub fn public_key_to_address(public_key: &[u8]) -> Result<String, String> {
    let xy: &[u8] = match public_key.len() {
        65 if public_key[0] == 0x04 => &public_key[1..],
        64 => public_key,
        n => return Err(format!("invalid public key length {n}")),
    };
    let mut k = Keccak256::new();
    k.update(xy);
    let full = k.finalize();
    let addr20 = &full[full.len() - 20..];
    bech32::encode("epix", to_base32(addr20), bech32::Variant::Bech32)
        .map_err(|e| format!("bech32: {e}"))
}

fn to_base32(data: &[u8]) -> Vec<bech32::u5> {
    use bech32::ToBase32;
    data.to_base32()
}

/// Parse a private key given as 64-hex chars or WIF into a scalar.
fn priv_to_scalar(privatekey: &str) -> Result<Scalar, String> {
    let bytes = if privatekey.len() == 64 {
        hex::decode(privatekey).map_err(|e| format!("priv hex: {e}"))?
    } else {
        wif_to_private(privatekey)?.to_vec()
    };
    Ok(scalar_from_be_reduced(&bytes))
}

/// `privatekeyToAddress` — accepts 64-hex or WIF.
pub fn privatekey_to_address(privatekey: &str) -> Result<String, String> {
    let s = priv_to_scalar(privatekey)?;
    let pubkey = uncompressed_pubkey(&s);
    public_key_to_address(&pubkey)
}

// ---- hashing for the two signing paths ----

fn bitcoin_varint(n: usize) -> Vec<u8> {
    if n < 253 {
        vec![n as u8]
    } else if n < 65536 {
        let mut v = vec![253u8];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n < 4294967296 {
        let mut v = vec![254u8];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![255u8];
        v.extend_from_slice(&(n as u64).to_le_bytes());
        v
    }
}

/// `dbl_format`: SHA256(SHA256("\x18Bitcoin Signed Message:\n" ‖ varint(len) ‖ msg)).
fn digest_dbl(data: &[u8]) -> [u8; 32] {
    let mut magic = Vec::new();
    magic.extend_from_slice(b"\x18Bitcoin Signed Message:\n");
    magic.extend_from_slice(&bitcoin_varint(data.len()));
    magic.extend_from_slice(data);
    let once = Sha256::digest(&magic);
    let twice = Sha256::digest(once);
    twice.into()
}

/// `keccak_format`: bare Keccak256(msg).
fn digest_keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak256::new();
    k.update(data);
    k.finalize().into()
}

fn sign_digest(digest: &[u8; 32], privatekey: &str) -> Result<String, String> {
    let bytes = if privatekey.len() == 64 {
        hex::decode(privatekey).map_err(|e| format!("priv hex: {e}"))?
    } else {
        wif_to_private(privatekey)?.to_vec()
    };
    let sk = SigningKey::from_slice(&bytes).map_err(|e| format!("signingkey: {e}"))?;
    let (sig, recid) = sk
        .sign_prehash_recoverable(digest)
        .map_err(|e| format!("sign: {e}"))?;
    let mut out = Vec::with_capacity(65);
    out.push(27 + recid.to_byte()); // uncompressed recid byte, matches sslcrypto
    out.extend_from_slice(&sig.to_bytes()); // r ‖ s, 64 bytes
    Ok(base64::engine::general_purpose::STANDARD.encode(out))
}

pub fn sign(data: &str, privatekey: &str) -> Result<String, String> {
    sign_digest(&digest_dbl(data.as_bytes()), privatekey)
}

pub fn sign_keccak(data: &str, privatekey: &str) -> Result<String, String> {
    sign_digest(&digest_keccak(data.as_bytes()), privatekey)
}

fn recover_address(digest: &[u8; 32], sig_b64: &str) -> Result<String, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("b64: {e}"))?;
    if raw.len() != 65 {
        return Err(format!("expected 65-byte recoverable sig, got {}", raw.len()));
    }
    let mut recid = raw[0].wrapping_sub(27);
    if recid >= 4 {
        recid -= 4; // strip the compressed-key flag
    }
    let recovery_id = RecoveryId::from_byte(recid).ok_or("bad recovery id")?;
    let signature =
        Signature::from_slice(&raw[1..65]).map_err(|e| format!("sig parse: {e}"))?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
        .map_err(|e| format!("recover: {e}"))?;
    let pubkey = vk.to_encoded_point(false);
    public_key_to_address(pubkey.as_bytes())
}

pub fn get_sign_address_64(data: &str, sig_b64: &str) -> Result<String, String> {
    recover_address(&digest_dbl(data.as_bytes()), sig_b64)
}

pub fn get_sign_address_keccak(data: &str, sig_b64: &str) -> Result<String, String> {
    recover_address(&digest_keccak(data.as_bytes()), sig_b64)
}

/// Verify a `dbl`-format signature: does it recover to `address`?
pub fn verify(data: &str, address: &str, sig_b64: &str) -> bool {
    get_sign_address_64(data, sig_b64).map(|a| a == address).unwrap_or(false)
}

/// Verify a `keccak`-format signature against `address`.
pub fn verify_keccak(data: &str, address: &str, sig_b64: &str) -> bool {
    get_sign_address_keccak(data, sig_b64).map(|a| a == address).unwrap_or(false)
}

/// True if `addr` is a well-formed `epix1…` bech32 address (20-byte payload).
pub fn is_valid_address(addr: &str) -> bool {
    match bech32::decode(addr) {
        Ok((hrp, data, variant)) => {
            if hrp != "epix" || variant != bech32::Variant::Bech32 {
                return false;
            }
            use bech32::FromBase32;
            Vec::<u8>::from_base32(&data).map(|b| b.len() == 20).unwrap_or(false)
        }
        Err(_) => false,
    }
}

/// Decode an `epix1…` address to its 20-byte hash160 payload.
pub fn address_to_hash160(addr: &str) -> Result<[u8; 20], String> {
    let (hrp, data, variant) = bech32::decode(addr).map_err(|e| format!("bech32: {e}"))?;
    if hrp != "epix" || variant != bech32::Variant::Bech32 {
        return Err("not an epix bech32 address".into());
    }
    use bech32::FromBase32;
    let bytes = Vec::<u8>::from_base32(&data).map_err(|e| format!("base32: {e}"))?;
    bytes.try_into().map_err(|_| "address payload not 20 bytes".to_string())
}

/// Fresh 64-hex-char master seed (32 random bytes).
pub fn new_seed() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("os rng");
    hex::encode(b)
}

/// Fresh random private key, WIF-encoded (reduced into the curve order).
pub fn new_private_key() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("os rng");
    let fb: FieldBytes = scalar_from_be_reduced(&b).to_bytes();
    let mut p = [0u8; 32];
    p.copy_from_slice(&fb);
    private_to_wif(&p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_validation() {
        let addr = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";
        assert!(is_valid_address(addr));
        assert_eq!(address_to_hash160(addr).unwrap().len(), 20);
        assert!(!is_valid_address("epix1notavalidaddress"));
        assert!(!is_valid_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(!is_valid_address(""));
    }

    #[test]
    fn keygen_roundtrips_to_valid_address() {
        let priv_wif = new_private_key();
        let addr = privatekey_to_address(&priv_wif).unwrap();
        assert!(is_valid_address(&addr), "generated addr invalid: {addr}");
        // A derived HD key from a fresh seed also yields a valid address.
        let seed = new_seed();
        assert_eq!(seed.len(), 64);
        let child = hd_privatekey(&seed, 0).unwrap();
        assert!(is_valid_address(&privatekey_to_address(&child).unwrap()));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let addr = privatekey_to_address(priv_hex).unwrap();
        let data = "hello epix";
        let sig = sign(data, priv_hex).unwrap();
        assert!(verify(data, &addr, &sig));
        assert!(!verify("tampered", &addr, &sig));
        let sigk = sign_keccak(data, priv_hex).unwrap();
        assert!(verify_keccak(data, &addr, &sigk));
        assert!(!verify_keccak(data, &addr, &sig)); // wrong hash format
    }
}
