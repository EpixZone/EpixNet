//! Minimal bencode (BitTorrent's serialization) decode/encode.
//!
//! Two things make this more than a toy:
//! - Dict keys are kept in a `BTreeMap<Vec<u8>, _>` so re-encoding is canonical
//!   (bencode requires keys sorted as raw byte strings).
//! - The decoder tracks byte offsets, so a caller can slice the EXACT bytes of a
//!   sub-value out of the original buffer. The info-hash is SHA-1 over the
//!   info dict's original bytes, and re-encoding a parsed dict is only
//!   guaranteed identical if the source was canonical - slicing the source is
//!   always correct.

use std::collections::BTreeMap;

/// A decoded bencode value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BencodeError {
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid integer")]
    BadInt,
    #[error("invalid byte-string length")]
    BadLen,
    #[error("unexpected byte 0x{0:02x} at offset {1}")]
    Unexpected(u8, usize),
    #[error("trailing bytes after value")]
    Trailing,
    #[error("dict keys must be byte strings, in sorted order")]
    BadDictKey,
}

type Result<T> = std::result::Result<T, BencodeError>;

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }
    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }
    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
    /// Look a key up in a dict value (`None` for non-dicts / missing keys).
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_dict().and_then(|d| d.get(key.as_bytes()))
    }
}

/// Decode a single value, requiring the whole buffer to be consumed.
pub fn decode(input: &[u8]) -> Result<Value> {
    let mut p = Parser { buf: input, pos: 0 };
    let v = p.value()?;
    if p.pos != input.len() {
        return Err(BencodeError::Trailing);
    }
    Ok(v)
}

/// Decode the top-level dict AND return the exact byte span of its `info`
/// value, if present - the two things metainfo parsing needs (the parsed tree
/// for fields, the raw bytes for the SHA-1 info-hash). The span is `(start,
/// end)` into `input`.
pub fn decode_torrent(input: &[u8]) -> Result<(Value, Option<(usize, usize)>)> {
    let mut p = Parser { buf: input, pos: 0 };
    let mut info_span = None;
    let v = p.value_tracking_info(&mut info_span)?;
    Ok((v, info_span))
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Result<u8> {
        self.buf.get(self.pos).copied().ok_or(BencodeError::Eof)
    }

    fn value(&mut self) -> Result<Value> {
        match self.peek()? {
            b'i' => self.integer(),
            b'l' => self.list(),
            b'd' => self.dict(None),
            b'0'..=b'9' => Ok(Value::Bytes(self.byte_string()?)),
            other => Err(BencodeError::Unexpected(other, self.pos)),
        }
    }

    /// Like [`value`], but when it decodes the top dict it records the byte
    /// span of the `info` key's value into `info_span`.
    fn value_tracking_info(&mut self, info_span: &mut Option<(usize, usize)>) -> Result<Value> {
        match self.peek()? {
            b'd' => self.dict(Some(info_span)),
            _ => self.value(),
        }
    }

    fn integer(&mut self) -> Result<Value> {
        self.pos += 1; // 'i'
        let start = self.pos;
        while self.peek()? != b'e' {
            self.pos += 1;
        }
        let s = std::str::from_utf8(&self.buf[start..self.pos]).map_err(|_| BencodeError::BadInt)?;
        // Reject leading zeros / "-0" per the spec (i0e is fine; i03e / i-0e are not).
        if s.is_empty()
            || s == "-0"
            || (s.starts_with('0') && s.len() > 1)
            || (s.starts_with("-0") && s.len() > 2)
        {
            return Err(BencodeError::BadInt);
        }
        let n: i64 = s.parse().map_err(|_| BencodeError::BadInt)?;
        self.pos += 1; // 'e'
        Ok(Value::Int(n))
    }

    fn byte_string(&mut self) -> Result<Vec<u8>> {
        let start = self.pos;
        while self.peek()? != b':' {
            if !self.buf[self.pos].is_ascii_digit() {
                return Err(BencodeError::BadLen);
            }
            self.pos += 1;
        }
        let len: usize = std::str::from_utf8(&self.buf[start..self.pos])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(BencodeError::BadLen)?;
        self.pos += 1; // ':'
        let end = self.pos.checked_add(len).ok_or(BencodeError::BadLen)?;
        if end > self.buf.len() {
            return Err(BencodeError::Eof);
        }
        let out = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(out)
    }

    fn list(&mut self) -> Result<Value> {
        self.pos += 1; // 'l'
        let mut out = Vec::new();
        while self.peek()? != b'e' {
            out.push(self.value()?);
        }
        self.pos += 1; // 'e'
        Ok(Value::List(out))
    }

    fn dict(&mut self, mut info_span: Option<&mut Option<(usize, usize)>>) -> Result<Value> {
        self.pos += 1; // 'd'
        let mut out = BTreeMap::new();
        let mut last_key: Option<Vec<u8>> = None;
        while self.peek()? != b'e' {
            if !self.buf[self.pos].is_ascii_digit() {
                return Err(BencodeError::BadDictKey);
            }
            let key = self.byte_string()?;
            // Keys must be strictly increasing (canonical bencode).
            if let Some(prev) = &last_key {
                if key <= *prev {
                    return Err(BencodeError::BadDictKey);
                }
            }
            let val_start = self.pos;
            let val = self.value()?;
            let val_end = self.pos;
            if key == b"info" {
                if let Some(span) = info_span.as_deref_mut() {
                    *span = Some((val_start, val_end));
                }
            }
            last_key = Some(key.clone());
            out.insert(key, val);
        }
        self.pos += 1; // 'e'
        Ok(Value::Dict(out))
    }
}

/// Canonically encode a value (keys sorted; the `BTreeMap` guarantees it).
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(i) => {
            out.push(b'i');
            out.extend_from_slice(i.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Value::List(l) => {
            out.push(b'l');
            for v in l {
                encode_into(v, out);
            }
            out.push(b'e');
        }
        Value::Dict(d) => {
            out.push(b'd');
            for (k, v) in d {
                out.extend_from_slice(k.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(k);
                encode_into(v, out);
            }
            out.push(b'e');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(pairs: &[(&str, Value)]) -> Value {
        Value::Dict(pairs.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.clone())).collect())
    }

    #[test]
    fn decodes_scalars() {
        assert_eq!(decode(b"i42e").unwrap(), Value::Int(42));
        assert_eq!(decode(b"i-7e").unwrap(), Value::Int(-7));
        assert_eq!(decode(b"i0e").unwrap(), Value::Int(0));
        assert_eq!(decode(b"4:spam").unwrap(), Value::Bytes(b"spam".to_vec()));
        assert_eq!(decode(b"0:").unwrap(), Value::Bytes(vec![]));
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(decode(b"i03e"), Err(BencodeError::BadInt));
        assert_eq!(decode(b"i-0e"), Err(BencodeError::BadInt));
        assert_eq!(decode(b"4:spa"), Err(BencodeError::Eof));
        assert_eq!(decode(b"i42eX"), Err(BencodeError::Trailing));
        // Out-of-order dict keys are rejected.
        assert!(decode(b"d1:b0:1:a0:e").is_err());
    }

    #[test]
    fn list_and_dict_roundtrip() {
        let v = Value::List(vec![Value::Int(1), Value::Bytes(b"ab".to_vec())]);
        assert_eq!(decode(&encode(&v)).unwrap(), v);

        let d = dict(&[("cow", Value::Bytes(b"moo".to_vec())), ("spam", Value::Int(3))]);
        let bytes = encode(&d);
        // Canonical: cow < spam, so cow first.
        assert_eq!(bytes, b"d3:cow3:moo4:spami3ee");
        assert_eq!(decode(&bytes).unwrap(), d);
    }

    #[test]
    fn info_span_slices_the_original_bytes() {
        // d 4:info d 6:length i5e e 4:name 3:foo e   (info before name: sorted)
        let torrent = b"d4:infod6:lengthi5ee4:name3:fooe";
        let (v, span) = decode_torrent(torrent).unwrap();
        let (s, e) = span.expect("info span");
        // The sliced bytes must be exactly the encoded info dict.
        assert_eq!(&torrent[s..e], b"d6:lengthi5ee");
        // And re-decoding that slice yields the same info sub-value.
        assert_eq!(decode(&torrent[s..e]).unwrap(), *v.get("info").unwrap());
    }
}
