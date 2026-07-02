//! Big-file piece maps.
//!
//! A big file's `<file>.piecemap.msgpack` is msgpack of
//! `{ file_name: { "sha512_pieces": [<32-byte hash>, …], "piece_size": N } }`.
//! Each piece hash is the raw first 32 bytes of the piece's SHA-512 — the same
//! value [`XiteStorage::hash_bytes`](crate::XiteStorage::hash_bytes) produces in
//! hex, so a downloaded piece is verified by comparing hex to hex.

use rmpv::Value;

fn map_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v)
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
}
