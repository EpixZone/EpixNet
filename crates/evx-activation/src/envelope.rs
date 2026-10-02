//! Signed envelope verification and the shared field validators.
//!
//! An envelope is the canonical form of `{"body": {...}, "signature": b64}`
//! where the signature is Ed25519 over the canonical bytes of `body`. The
//! trusted key always comes from a host grant or an accepted policy, never
//! from the envelope itself.

use std::collections::BTreeSet;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use evx_api::strict;
use serde_json::{Map, Number, Value};

use crate::canonical::canonical_object_bytes;
use crate::{AuthenticationError, MAX_ENVELOPE};

/// A JSON object as decoded from an envelope.
pub(crate) type Object = Map<String, Value>;

/// Largest positive integer a version or sequence may carry (`2**63 - 1`).
const MAX_POSITIVE: u64 = i64::MAX as u64;

/// A body whose signature verified under the trusted key, with the exact
/// canonical bytes that were signed (the input to every manifest digest).
pub(crate) struct SignedBody {
    pub(crate) body: Object,
    pub(crate) bytes: Vec<u8>,
}

fn verification_failed() -> AuthenticationError {
    AuthenticationError::new("signature or envelope verification failed")
}

/// Decode and verify one envelope against `trusted_key`.
///
/// Rejects oversized input, duplicate JSON fields, non-finite numbers,
/// unexpected envelope fields, malformed base64 and any signature that does
/// not verify strictly.
pub(crate) fn verify_envelope(
    raw: &[u8],
    trusted_key: &[u8; 32],
) -> Result<SignedBody, AuthenticationError> {
    if raw.len() > MAX_ENVELOPE {
        return Err(AuthenticationError::new("envelope size or type"));
    }
    let parsed = strict::parse(raw).map_err(|_| verification_failed())?;
    let Some(Value::Object(mut envelope)) = to_serde(&parsed) else {
        return Err(verification_failed());
    };
    shape(&envelope, &["body", "signature"]).map_err(|_| verification_failed())?;
    let Some(Value::String(signature)) = envelope.remove("signature") else {
        return Err(verification_failed());
    };
    let Some(Value::Object(body)) = envelope.remove("body") else {
        return Err(verification_failed());
    };
    let signature = BASE64
        .decode(signature)
        .map_err(|_| verification_failed())?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| verification_failed())?;
    let signature = Signature::from_bytes(&signature);
    let bytes = canonical_object_bytes(&body).map_err(|_| verification_failed())?;
    let key = VerifyingKey::from_bytes(trusted_key).map_err(|_| verification_failed())?;
    key.verify_strict(&bytes, &signature)
        .map_err(|_| verification_failed())?;
    Ok(SignedBody { body, bytes })
}

/// Convert the strict tree (duplicate keys and non-finite numbers already
/// refused) into a `serde_json::Value` for canonicalization and inspection.
pub(crate) fn to_serde(value: &strict::Value) -> Option<Value> {
    Some(match value {
        strict::Value::Null => Value::Null,
        strict::Value::Bool(flag) => Value::Bool(*flag),
        strict::Value::Int(int) => Value::Number(Number::from(*int)),
        strict::Value::Float(float) => Value::Number(Number::from_f64(*float)?),
        strict::Value::Str(text) => Value::String(text.clone()),
        strict::Value::Array(items) => {
            Value::Array(items.iter().map(to_serde).collect::<Option<_>>()?)
        }
        strict::Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| Some((key.clone(), to_serde(value)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

/// Require exactly the field set `keys`.
pub(crate) fn shape(body: &Object, keys: &[&str]) -> Result<(), AuthenticationError> {
    let actual: BTreeSet<&str> = body.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = keys.iter().copied().collect();
    if actual != expected {
        return Err(AuthenticationError::new("unexpected fields"));
    }
    Ok(())
}

/// Look up a field after [`shape`] has established it exists; a missing field
/// reads as `null`, which fails every typed check.
pub(crate) fn field<'a>(body: &'a Object, name: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    body.get(name).unwrap_or(&NULL)
}

/// A string matching the shared identifier grammar.
pub(crate) fn identifier(value: &Value) -> Result<&str, AuthenticationError> {
    let text = value
        .as_str()
        .ok_or_else(|| AuthenticationError::new("invalid fixture identifier"))?;
    evx_api::validate_identifier(text)
        .map_err(|_| AuthenticationError::new("invalid fixture identifier"))?;
    Ok(text)
}

/// A JSON integer (not a float, not a bool) in `1..=2**63-1`.
pub(crate) fn positive(value: &Value) -> Result<u64, AuthenticationError> {
    let invalid = || AuthenticationError::new("invalid sequence or version");
    let int = value.as_i64().ok_or_else(invalid)?;
    let int = u64::try_from(int).map_err(|_| invalid())?;
    if int == 0 || int > MAX_POSITIVE {
        return Err(invalid());
    }
    Ok(int)
}

/// Validate a host-supplied generation the same way as a signed version.
pub(crate) fn positive_u64(value: u64) -> Result<u64, AuthenticationError> {
    if value == 0 || value > MAX_POSITIVE {
        return Err(AuthenticationError::new("invalid sequence or version"));
    }
    Ok(value)
}

/// A 64-character lowercase hex SHA-256 digest.
pub(crate) fn hex_digest(value: &Value) -> Result<&str, AuthenticationError> {
    let text = value
        .as_str()
        .filter(|text| {
            text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| AuthenticationError::new("invalid SHA-256 digest"))?;
    Ok(text)
}

/// Sign `body` with `key` and return the canonical envelope bytes.
///
/// This is the fixture publisher helper for a trusted harness or conformance
/// suite. It is compiled only for tests or with the `fixtures` feature so no
/// worker build can link a signer. Panics if `body` cannot be canonicalized,
/// which only happens for pathological nesting.
#[cfg(any(test, feature = "fixtures"))]
pub fn sign_envelope(body: &Value, key: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer as _;

    let body_bytes = crate::canonical_bytes(body).expect("fixture body must canonicalize");
    let signature = key.sign(&body_bytes);
    let envelope = serde_json::json!({
        "body": body,
        "signature": BASE64.encode(signature.to_bytes()),
    });
    crate::canonical_bytes(&envelope).expect("fixture envelope must canonicalize")
}
