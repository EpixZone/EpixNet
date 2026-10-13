//! Canonical JSON matching the reference fixtures.
//!
//! The output is byte-identical to Python's
//! `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
//! allow_nan=False)`: object keys sort by code point, there is no whitespace,
//! every character outside `0x20..=0x7E` is written as a lowercase `\uXXXX`
//! escape (non-BMP characters as a UTF-16 surrogate pair), integers print in
//! decimal, floats use Python's `repr` form and non-finite numbers are
//! refused. This is the deliberately limited fixture canonicalization, not a
//! network format.

use serde_json::{Map, Number, Value};

use crate::AuthenticationError;

/// Nesting depth beyond which canonicalization is refused, mirroring the
/// reference implementation's `RecursionError` handling. Verified envelopes
/// never reach it because strict parsing already bounds depth.
const MAX_DEPTH: usize = 256;

/// Serialize `value` in the canonical fixture form.
///
/// Fails only for non-finite numbers (which `serde_json::Value` cannot hold)
/// and for nesting deeper than the reference implementation tolerates.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, AuthenticationError> {
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out.into_bytes())
}

/// Canonical form of one object; the body of an envelope is always an object.
pub(crate) fn canonical_object_bytes(
    object: &Map<String, Value>,
) -> Result<Vec<u8>, AuthenticationError> {
    let mut out = String::new();
    write_object(&mut out, object, 0)?;
    Ok(out.into_bytes())
}

fn invalid() -> AuthenticationError {
    AuthenticationError::new("invalid canonical JSON")
}

fn write_value(out: &mut String, value: &Value, depth: usize) -> Result<(), AuthenticationError> {
    if depth > MAX_DEPTH {
        return Err(invalid());
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(out, number)?,
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(object) => write_object(out, object, depth)?,
    }
    Ok(())
}

fn write_object(
    out: &mut String,
    object: &Map<String, Value>,
    depth: usize,
) -> Result<(), AuthenticationError> {
    if depth > MAX_DEPTH {
        return Err(invalid());
    }
    // Sort explicitly: the map's own order depends on serde_json features.
    // Byte order of UTF-8 equals code point order, which is what Python's
    // `sort_keys` uses for `str` keys.
    let mut entries: Vec<(&String, &Value)> = object.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    out.push('{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, value, depth + 1)?;
    }
    out.push('}');
    Ok(())
}

fn write_number(out: &mut String, number: &Number) -> Result<(), AuthenticationError> {
    if let Some(value) = number.as_i64() {
        out.push_str(&value.to_string());
    } else if let Some(value) = number.as_u64() {
        out.push_str(&value.to_string());
    } else if let Some(text) = number.as_f64().and_then(python_float_repr) {
        out.push_str(&text);
    } else {
        return Err(invalid());
    }
    Ok(())
}

/// Python's `json` escapes `"` and `\`, uses the short forms for the five
/// named controls, and writes every other character outside `' '..='~'` as
/// `\uXXXX` (DEL included), with non-BMP characters as surrogate pairs.
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let code = u32::from(c);
                if code < 0x1_0000 {
                    push_unicode_escape(out, code);
                } else {
                    let offset = code - 0x1_0000;
                    push_unicode_escape(out, 0xD800 | (offset >> 10));
                    push_unicode_escape(out, 0xDC00 | (offset & 0x3FF));
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        out.push(char::from(HEX[((code >> shift) & 0xF) as usize]));
    }
}

/// Format a finite float exactly as Python's `repr` does.
///
/// Rust's `{:e}` yields the shortest digit string that round-trips, the same
/// digits Python's `repr` produces; this re-lays them out with Python's rules:
/// fixed notation when the decimal exponent is in `-4 < decpt <= 16`,
/// otherwise `d.ddde+XX` with a signed, at least two-digit exponent, and a
/// trailing `.0` on integral values in fixed notation. Returns `None` for
/// non-finite input.
pub fn python_float_repr(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        return Some(
            if value.is_sign_negative() {
                "-0.0"
            } else {
                "0.0"
            }
            .to_string(),
        );
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e')?;
    let exponent: i32 = exponent.parse().ok()?;
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let count = i32::try_from(digits.len()).ok()?;
    // value = 0.d1d2...dn * 10^decpt
    let decpt = exponent.checked_add(1)?;
    let mut out = String::new();
    if value.is_sign_negative() {
        out.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if count > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let exp = decpt - 1;
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exp.abs()));
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if decpt < count {
        let split = usize::try_from(decpt).ok()?;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else {
        out.push_str(&digits);
        for _ in 0..(decpt - count) {
            out.push('0');
        }
        out.push_str(".0");
    }
    Some(out)
}
