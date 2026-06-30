//! Python-compatible `json.dumps(obj, sort_keys=True)` serialization.
//!
//! content.json signatures cover the string produced by Python's
//! `json.dumps(content, sort_keys=True)` (default `ensure_ascii=True`,
//! `", "` / `": "` separators). To verify or produce signatures we must
//! reproduce that string **byte-for-byte**, so this is hand-written rather than
//! delegated to serde_json's serializer (which uses compact separators, raw
//! UTF-8, and no key sorting).
//!
//! Keys are sorted explicitly (UTF-8 byte order equals Unicode code-point order,
//! matching Python's `sort_keys`) so the result is independent of whether
//! serde_json's `preserve_order` feature happens to be enabled.

use serde_json::Value;

/// Serialize a [`Value`] exactly as Python's `json.dumps(v, sort_keys=True)`.
pub fn dumps_sorted(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        // Integers match Python's `str(int)`. (Floats are not used in signed
        // content.json payloads; EpixNet itself special-cases float `modified`.)
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_py_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_string(out, k);
                out.push_str(": ");
                write_value(out, &map[*k]);
            }
            out.push('}');
        }
    }
}

/// Escape a string exactly as Python's json encoder with `ensure_ascii=True`:
/// short escapes for the standard set, `\u00xx` for other control chars, and
/// `\uXXXX` (lowercase, surrogate pairs for astral) for every byte > 0x7E.
fn write_py_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xFFFF {
                    let v = cp - 0x10000;
                    let hi = 0xD800 + (v >> 10);
                    let lo = 0xDC00 + (v & 0x3FF);
                    out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
