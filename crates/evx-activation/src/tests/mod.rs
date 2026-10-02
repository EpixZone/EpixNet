//! Adversarial tests ported from the reference suite, plus two-phase
//! admission and cross-language envelope checks. Keys are disposable and
//! artifacts live in temporary directories.

mod activation;
mod canonical;
mod content;
mod cross_language;
mod shared;

use ed25519_dalek::SigningKey;
use serde_json::Value;

pub(crate) const PROGRAM: &[u8] =
    b"(module (memory (export \"memory\") 1) (func (export \"run\") (result i32) i32.const 42))";

pub(crate) fn updated() -> Vec<u8> {
    String::from_utf8(PROGRAM.to_vec())
        .unwrap()
        .replace("42", "43")
        .into_bytes()
}

pub(crate) fn generate_key() -> SigningKey {
    SigningKey::from_bytes(&rand::random::<[u8; 32]>())
}

pub(crate) fn public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// Thirty-two bytes that do not decode as an Ed25519 point. Roughly half of
/// all encodings are off-curve, so a constant pattern is always found.
pub(crate) fn invalid_public_key() -> [u8; 32] {
    (0u8..=255)
        .map(|byte| [byte; 32])
        .find(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).is_err())
        .expect("some constant byte pattern is not a curve point")
}

/// `dict(body, **changes)` for JSON objects.
pub(crate) fn with(body: &Value, changes: &[(&str, Value)]) -> Value {
    let mut body = body.clone();
    let object = body.as_object_mut().unwrap();
    for (key, value) in changes {
        object.insert((*key).to_string(), value.clone());
    }
    body
}
