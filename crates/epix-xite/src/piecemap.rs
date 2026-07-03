//! Big-file piece maps.
//!
//! A big file's `<file>.piecemap.msgpack` is msgpack of
//! `{ file_name: { "sha512_pieces": [<32-byte hash>, …], "piece_size": N } }`.
//! Each piece hash is the raw first 32 bytes of the piece's SHA-512 - the same
//! value [`XiteStorage::hash_bytes`](crate::XiteStorage::hash_bytes) produces in
//! hex, so a downloaded piece is verified by comparing hex to hex.

use rmpv::Value;
use sha2::{Digest, Sha512};

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v)
}

/// One piece's hash: the first 32 bytes of its SHA-512 (`sha512t`), the same
/// value used for whole-file hashes.
fn piece_hash(piece: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(piece);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// The result of hashing a big file for upload: the merkle root (hex, the
/// file's `sha512` in content.json), the piece size, and the raw per-piece
/// hashes (for the `.piecemap.msgpack`).
pub struct BigfileHash {
    pub merkle_root: String,
    pub piece_size: usize,
    pub piece_hashes: Vec<[u8; 32]>,
}

/// Split `data` into `piece_size` chunks, hash each with `sha512t`, and combine
/// them into a merkle root exactly as EpixNet's `hashBigfile` (merkletools with
/// `sha512t`: pair adjacent leaves and hash `left||right`, promote a lone odd
/// leaf unchanged, up to a single root). A single-piece file's root is that
/// piece's hash. Returns the pieces + root for writing the piecemap and the
/// content.json `files_optional` entry.
pub fn hash_bigfile(data: &[u8], piece_size: usize) -> BigfileHash {
    let piece_size = piece_size.max(1);
    let mut piece_hashes: Vec<[u8; 32]> =
        data.chunks(piece_size).map(piece_hash).collect();
    if piece_hashes.is_empty() {
        // Empty file: one empty-piece hash (matches hashing a zero-length part).
        piece_hashes.push(piece_hash(&[]));
    }
    let merkle_root = merkle_root(piece_hashes.clone());
    BigfileHash { merkle_root, piece_size, piece_hashes }
}

/// Merkle root (hex) over raw 32-byte leaves, using merkletools' rule:
/// `sha512t(left || right)` per pair, a lone odd leaf promoted unchanged.
fn merkle_root(mut level: Vec<[u8; 32]>) -> String {
    if level.is_empty() {
        return hex::encode(piece_hash(&[]));
    }
    while level.len() > 1 {
        let n = level.len();
        let (pairs_end, solo) = if n % 2 == 1 { (n - 1, Some(level[n - 1])) } else { (n, None) };
        let mut next = Vec::with_capacity(n / 2 + 1);
        let mut i = 0;
        while i < pairs_end {
            let mut cat = Vec::with_capacity(64);
            cat.extend_from_slice(&level[i]);
            cat.extend_from_slice(&level[i + 1]);
            next.push(piece_hash(&cat));
            i += 2;
        }
        if let Some(s) = solo {
            next.push(s);
        }
        level = next;
    }
    hex::encode(level[0])
}

/// Serialize a piecemap blob for `file_name` (`{ file_name: { sha512_pieces:
/// [<raw 32-byte>…], piece_size } }`), the `.piecemap.msgpack` contents.
pub fn build_piecemap(file_name: &str, hash: &BigfileHash) -> Vec<u8> {
    let pieces: Vec<Value> =
        hash.piece_hashes.iter().map(|p| Value::Binary(p.to_vec())).collect();
    let entry = Value::Map(vec![
        (Value::from("sha512_pieces"), Value::Array(pieces)),
        (Value::from("piece_size"), Value::from(hash.piece_size as i64)),
    ]);
    let map = Value::Map(vec![(Value::from(file_name), entry)]);
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &map).expect("encode piecemap");
    buf
}

/// The per-piece SHA-512/256 hashes (hex) for `file_name` from a piecemap blob.
pub fn parse_piecemap(bytes: &[u8], file_name: &str) -> Option<Vec<String>> {
    let value = rmpv::decode::read_value(&mut &bytes[..]).ok()?;
    let root = value.as_map()?;
    let entry = map_get(root, file_name)?.as_map()?;
    let pieces = map_get(entry, "sha512_pieces")?.as_array()?;
    Some(pieces.iter().filter_map(|p| p.as_slice().map(hex::encode)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_piece_hashes() {
        // { "movie.mp4": { "sha512_pieces": [b"\x00"*32, b"\x11"*32], "piece_size": 1048576 } }
        let piecemap = Value::Map(vec![(
            Value::from("movie.mp4"),
            Value::Map(vec![
                (
                    Value::from("sha512_pieces"),
                    Value::Array(vec![
                        Value::Binary(vec![0u8; 32]),
                        Value::Binary(vec![0x11u8; 32]),
                    ]),
                ),
                (Value::from("piece_size"), Value::from(1048576)),
            ]),
        )]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &piecemap).unwrap();

        let hashes = parse_piecemap(&buf, "movie.mp4").unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], "0".repeat(64));
        assert_eq!(hashes[1], "11".repeat(32));
        assert!(parse_piecemap(&buf, "other.mp4").is_none());
    }

    #[test]
    fn single_piece_root_is_the_piece_hash() {
        let data = b"small file under one piece";
        let h = hash_bigfile(data, 1024 * 1024);
        assert_eq!(h.piece_hashes.len(), 1);
        // Root == hex of the single piece hash == whole-file sha512t.
        assert_eq!(h.merkle_root, crate::XiteStorage::hash_bytes(data));
    }

    #[test]
    fn multi_piece_root_is_stable_and_roundtrips_piecemap() {
        // 3 pieces of 4 bytes each (odd count exercises the promote path).
        let data = b"AAAABBBBCCCC";
        let h = hash_bigfile(data, 4);
        assert_eq!(h.piece_hashes.len(), 3);
        // The piecemap we build parses back to the same per-piece hashes (hex).
        let blob = build_piecemap("movie.mp4", &h);
        let parsed = parse_piecemap(&blob, "movie.mp4").unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], hex::encode(h.piece_hashes[0]));
        // Root is deterministic.
        assert_eq!(hash_bigfile(data, 4).merkle_root, h.merkle_root);
        // Different data -> different root.
        assert_ne!(hash_bigfile(b"AAAABBBBCCCD", 4).merkle_root, h.merkle_root);
    }
}
