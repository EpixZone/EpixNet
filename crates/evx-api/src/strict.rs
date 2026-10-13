//! Strict JSON decoding for anything a guest or worker can send.
//!
//! `serde_json` already rejects `NaN`, `Infinity`, trailing data and inputs
//! deeper than its recursion limit. It does not reject duplicate object keys:
//! the derive keeps the last value silently. [`Value`] is a small JSON tree
//! whose `Deserialize` implementation fails on the first duplicate key, so a
//! request like `{"op":"workspace.read","op":"game.score.get"}` is refused
//! before any typed decoding sees it.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;

use crate::Denied;

/// JSON tree with duplicate-key rejection and finite numbers only.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Integers that fit in i64. Larger integers and all floats are rejected
    /// at the typed layer; they are kept here as `Float` for diagnostics.
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON value without duplicate keys")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Int(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        i64::try_from(v)
            .map(Value::Int)
            .map_err(|_| E::custom("integer out of range"))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        if !v.is_finite() {
            return Err(E::custom("non-finite number"));
        }
        Ok(Value::Float(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Str(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::Str(v))
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let value: Value = map.next_value()?;
            if object.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate JSON field"));
            }
        }
        Ok(Value::Object(object))
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

/// Parse untrusted bytes into a strict [`Value`].
pub fn parse(raw: &[u8]) -> Result<Value, Denied> {
    serde_json::from_slice::<Value>(raw).map_err(|_| Denied::new("invalid JSON"))
}

/// Parse untrusted bytes into a strict value, then into a typed structure.
///
/// The typed decode runs on the re-serialized strict tree, so a type that uses
/// `deny_unknown_fields` still sees exactly the fields the sender supplied.
pub fn parse_typed<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> Result<T, Denied> {
    let value = parse(raw)?;
    let json = to_json(&value);
    serde_json::from_str::<T>(&json).map_err(|_| Denied::new("invalid request shape"))
}

/// Canonical serialization used for the re-decode above and for diagnostics.
pub fn to_json(value: &Value) -> String {
    fn write(out: &mut String, value: &Value) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(i) => out.push_str(&i.to_string()),
            Value::Float(f) => out.push_str(&serde_json::to_string(f).unwrap_or_default()),
            Value::Str(s) => out.push_str(&serde_json::to_string(s).unwrap_or_default()),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(out, item);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap_or_default());
                    out.push(':');
                    write(out, v);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(&mut out, value);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicates_nonfinite_and_malformed() {
        assert!(parse(br#"{"op":"a","op":"b"}"#).is_err());
        assert!(parse(br#"{"x":NaN}"#).is_err());
        assert!(parse(br#"{"x":Infinity}"#).is_err());
        assert!(parse(br#"{"x":1e999}"#).is_err());
        assert!(parse(b"{").is_err());
        assert!(parse(b"").is_err());
        assert!(parse(b"\xff\xfe").is_err());
        assert!(parse(b"null trailing").is_err());
        let deep = "[".repeat(1500) + &"]".repeat(1500);
        assert!(parse(deep.as_bytes()).is_err());
    }

    #[test]
    fn accepts_ordinary_objects() {
        let v = parse(br#"{"op":"workspace.write","path":"a","text":"b"}"#).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(
            obj.get("op").and_then(Value::as_str),
            Some("workspace.write")
        );
        assert_eq!(
            to_json(&v),
            r#"{"op":"workspace.write","path":"a","text":"b"}"#
        );
    }
}
