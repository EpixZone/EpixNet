//! In-xite search without holding the corpus.
//!
//! One trust rule for both tracks: an answer is only a POINTER (a record
//! ref + `(segment_root, offset, len)`); the client always fetches the
//! record and verifies it against its BLAKE3 root, so an untrusted
//! answerer can only omit or waste a fetch — never inject a fake match.
//!
//! - [`xor8`] — Track 1: each immutable segment carries a committed XOR8
//!   filter of its terms. Walk the segment spine, pull the tiny filters,
//!   skip segments whose filter rejects all query terms (no false
//!   negatives → skipping is sound), fetch+verify only candidates.
//! - [`index`] — Track 2: a hierarchical sharded published inverted index
//!   for big corpora, term-hash-sharded posting lists of pointers.
//! - [`tokenize`] — the FROZEN tokenizer both tracks share, so any node
//!   rebuilds byte-identical filters and index shards.
//!
//! Honest bound (shipped, not hidden): soundness (no forged match) is
//! trustless via fetch-and-verify. Completeness (no true match omitted)
//! is trustless only RELATIVE TO the owner-signed committed root — a
//! malicious builder can still omit from the committed set, the same
//! owner-trust EpixNet already accepts for content.json.

#![forbid(unsafe_code)]

pub mod index;
pub mod xor8;

/// The frozen tokenizer. Changing any rule here changes every filter and
/// index shard on the network, so it is a deliberate format revision.
///
/// Rules (v1): lowercase ASCII fold, split on any non-alphanumeric, drop
/// tokens shorter than 2 or longer than 40 bytes, dedupe. Unicode is
/// folded conservatively — non-ASCII bytes are treated as token
/// separators in v1 (a later version may vendor a normalization table;
/// that is a format bump, not a silent change).
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if cur.len() >= 2 && cur.len() <= 40 {
            out.push(std::mem::take(cur));
        } else {
            cur.clear();
        }
    };
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            cur.push(ch.to_ascii_lowercase());
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    out.sort();
    out.dedup();
    out
}

/// The 64-bit hash of a term, used as the XOR8 key and index shard key.
/// Frozen: BLAKE3(term) truncated to the first 8 little-endian bytes.
pub fn term_hash(term: &str) -> u64 {
    let d = blake3::hash(term.as_bytes());
    u64::from_le_bytes(d.as_bytes()[..8].try_into().unwrap())
}

/// A verified-fetch pointer: where a matching record lives. The client
/// range-fetches these bytes and checks them against the record's own
/// BLAKE3 root before trusting the match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pointer {
    pub segment_root: [u8; 32],
    pub offset: u64,
    pub len: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_is_deterministic_and_normalizing() {
        assert_eq!(tokenize("Hello, WORLD! hello"), vec!["hello", "world"]);
        assert_eq!(tokenize("a I x"), Vec::<String>::new(), "1-char tokens dropped");
        assert_eq!(tokenize("foo123 bar-baz"), vec!["bar", "baz", "foo123"]);
        // Deterministic ordering regardless of appearance order.
        assert_eq!(tokenize("zebra apple zebra"), vec!["apple", "zebra"]);
    }

    #[test]
    fn term_hash_frozen_vector() {
        // If this changes, the frozen term-hash format changed.
        assert_eq!(term_hash("apple"), {
            let d = blake3::hash(b"apple");
            u64::from_le_bytes(d.as_bytes()[..8].try_into().unwrap())
        });
    }
}
