//! Canonical JSON, digests and the bounded input validators shared by the
//! host state and the mock destination.
//!
//! `canonical()` mirrors the proof-of-concept exactly: nesting is capped at 16
//! levels, numbers must be integers within +/- (2^53 - 1), floats are rejected,
//! object keys are emitted in sorted order with no whitespace, strings are
//! written as UTF-8 (not ASCII-escaped) and the encoded form may not exceed
//! [`MAX_JSON`] bytes. Two values that are visually equivalent but differ in
//! code points therefore produce different digests on purpose.

use std::io::Write as _;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{Error, Result};

/// Largest canonical JSON document accepted anywhere, in bytes.
pub const MAX_JSON: usize = 16_384;
/// Deepest JSON nesting accepted (`[[...]]` of this depth is still allowed).
pub const MAX_DEPTH: usize = 16;
/// Largest magnitude an integer may have: 2^53 - 1, the JavaScript safe range.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// Largest value accepted for any positive integer limit (`10^9`).
pub const MAX_LIMIT: u64 = 1_000_000_000;

fn validate(item: &Value, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::invalid("JSON nesting limit"));
    }
    match item {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(number) => {
            let in_range = match (number.as_i64(), number.as_u64()) {
                (Some(signed), _) => signed.unsigned_abs() <= MAX_SAFE_INTEGER,
                (None, Some(unsigned)) => unsigned <= MAX_SAFE_INTEGER,
                (None, None) => false,
            };
            if in_range {
                Ok(())
            } else {
                Err(Error::invalid("unsupported JSON value"))
            }
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|child| validate(child, depth + 1)),
        Value::Object(map) => map
            .values()
            .try_for_each(|child| validate(child, depth + 1)),
    }
}

fn write(out: &mut Vec<u8>, item: &Value) -> Result<()> {
    match item {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if let Some(signed) = number.as_i64() {
                write!(out, "{signed}").map_err(|_| Error::invalid("unsupported JSON value"))?;
            } else if let Some(unsigned) = number.as_u64() {
                write!(out, "{unsigned}").map_err(|_| Error::invalid("unsupported JSON value"))?;
            } else {
                return Err(Error::invalid("unsupported JSON value"));
            }
        }
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push(b'[');
            for (index, child) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write(out, child)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                write(out, &map[key])?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// JSON string escaping identical to Python's `json.dumps(ensure_ascii=False)`
/// and to `serde_json`: only `"`, `\` and control characters below U+0020 are
/// escaped; everything else is emitted as UTF-8.
fn write_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Encode `value` as canonical JSON after validating it against the nesting,
/// integer-range and size limits. Rejected values yield [`Error::Invalid`].
pub fn canonical(value: &Value) -> Result<String> {
    validate(value, 0)?;
    let mut out = Vec::new();
    write(&mut out, value)?;
    if out.len() > MAX_JSON {
        return Err(Error::invalid("JSON size limit"));
    }
    // Every byte came from `str` slices or ASCII literals, so this cannot fail.
    String::from_utf8(out).map_err(|_| Error::invalid("unsupported JSON value"))
}

/// Lower-case hex SHA-256 of `raw`'s UTF-8 bytes.
pub fn digest(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Validate a host-selected identifier (xite, occurrence or effect key).
///
/// Delegates to [`evx_api::validate_identifier`]; a failure is an input error
/// ([`Error::Invalid`]) rather than an authority denial.
pub fn identifier(value: &str) -> Result<&str> {
    evx_api::validate_identifier(value).map_err(|_| Error::invalid("invalid identifier"))?;
    Ok(value)
}

/// Validate a positive integer limit: `1..=10^9`, or `0..=10^9` when
/// `allow_zero` is set.
pub fn positive(value: u64, allow_zero: bool) -> Result<u64> {
    let floor = if allow_zero { 0 } else { 1 };
    if value < floor || value > MAX_LIMIT {
        return Err(Error::invalid("invalid integer limit"));
    }
    Ok(value)
}

/// Validate a lower-case hex SHA-256 digest (or any 32-byte secret encoded
/// the same way, such as an allow-once token): exactly 64 characters from
/// `0-9a-f`. Upper-case hex is rejected so two spellings of one digest can
/// never both be stored.
pub fn sha256_hex(value: &str) -> Result<&str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::invalid("invalid hex digest"));
    }
    Ok(value)
}

/// Validate a workspace-relative publication path.
///
/// Delegates to [`evx_api::validate_relative_path`]; a failure is an input
/// error ([`Error::Invalid`]) rather than an authority denial.
pub fn relative_path(value: &str) -> Result<&str> {
    evx_api::validate_relative_path(value)
        .map_err(|_| Error::invalid("invalid publication path"))?;
    Ok(value)
}
