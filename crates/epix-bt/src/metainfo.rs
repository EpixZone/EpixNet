//! `.torrent` (metainfo) parsing: the info-hash, piece hashes, and file layout.
//!
//! A magnet gives only the info-hash; the full metainfo (piece length, the
//! SHA-1 of every piece, and the file list) comes either from an `xs=`
//! `.torrent` URL or from peers via BEP9. Either way it lands here, where we
//! recompute the info-hash from the info dict's raw bytes and check it against
//! what we asked for - so a hostile source can't feed us a different file.

use crate::bencode::{self, Value};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    /// Path components under the torrent's top dir (single-file torrents get
    /// one entry with the torrent name).
    pub path: Vec<String>,
    pub length: u64,
}

impl FileEntry {
    /// Joined display path (`a/b/c`).
    pub fn display_path(&self) -> String {
        self.path.join("/")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaInfo {
    /// 20-byte v1 info-hash (SHA-1 of the info dict's raw bencode).
    pub info_hash: [u8; 20],
    /// Suggested name (single file's name, or the top directory).
    pub name: String,
    pub piece_length: u64,
    /// SHA-1 of each piece, in order.
    pub piece_hashes: Vec<[u8; 20]>,
    pub files: Vec<FileEntry>,
    /// Sum of every file's length.
    pub total_length: u64,
    /// True when the info dict used `files` (a directory of files) rather than a
    /// single `length`. Web-seed URL construction differs between the two
    /// (BEP19): multi-file appends `<name>/<path>`, single-file appends just
    /// `<name>` (or nothing when the base is the file URL itself).
    pub multi_file: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("bencode: {0}")]
    Bencode(#[from] bencode::BencodeError),
    #[error("missing or malformed `info` dict")]
    NoInfo,
    #[error("missing `{0}` in info dict")]
    Missing(&'static str),
    #[error("`pieces` length is not a multiple of 20")]
    BadPieces,
    #[error("info-hash mismatch: metainfo describes a different torrent")]
    HashMismatch,
    #[error("torrent declares no files / zero length")]
    Empty,
}

impl MetaInfo {
    /// Total number of pieces.
    pub fn piece_count(&self) -> usize {
        self.piece_hashes.len()
    }

    /// The info-hash as lowercase hex (the canonical id, e.g. for a cache dir).
    pub fn info_hash_hex(&self) -> String {
        hex::encode(self.info_hash)
    }

    /// The info-hash as a filesystem-safe path component: exactly 40 characters
    /// drawn from a fixed `[0-9a-f]` alphabet, so it can never contain a path
    /// separator, `..`, or any other traversal token. Each output byte is read
    /// from the constant `HEX` table (the tainted nibble is only an index into
    /// it), so the result is provably a safe path segment rather than
    /// torrent-controlled data - both to a reader and to static analysis.
    pub fn cache_dir_name(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(40);
        for &byte in &self.info_hash {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }

    /// The byte length of piece `i` (the last piece is usually short).
    pub fn piece_size(&self, i: usize) -> u64 {
        if i + 1 < self.piece_count() {
            self.piece_length
        } else {
            let full = self.piece_length * (self.piece_count() as u64 - 1);
            self.total_length - full
        }
    }

    /// Verify a piece's bytes against its stored SHA-1.
    pub fn verify_piece(&self, index: usize, data: &[u8]) -> bool {
        match self.piece_hashes.get(index) {
            Some(want) => {
                let got = Sha1::digest(data);
                got.as_slice() == want
            }
            None => false,
        }
    }

    /// Parse metainfo from `.torrent` bytes, checking the recomputed info-hash
    /// against `expected` (the magnet's `xt`) when provided.
    pub fn parse(bytes: &[u8], expected: Option<[u8; 20]>) -> Result<MetaInfo, MetaError> {
        let (root, info_span) = bencode::decode_torrent(bytes)?;
        let (start, end) = info_span.ok_or(MetaError::NoInfo)?;
        let info_hash: [u8; 20] = Sha1::digest(&bytes[start..end]).into();
        if let Some(exp) = expected {
            if exp != info_hash {
                return Err(MetaError::HashMismatch);
            }
        }
        let info = root.get("info").and_then(Value::as_dict).ok_or(MetaError::NoInfo)?;

        let piece_length = info
            .get(b"piece length".as_slice())
            .and_then(Value::as_int)
            .filter(|&n| n > 0)
            .ok_or(MetaError::Missing("piece length"))? as u64;

        let pieces = info
            .get(b"pieces".as_slice())
            .and_then(Value::as_bytes)
            .ok_or(MetaError::Missing("pieces"))?;
        if pieces.len() % 20 != 0 {
            return Err(MetaError::BadPieces);
        }
        let piece_hashes: Vec<[u8; 20]> =
            pieces.chunks_exact(20).map(|c| c.try_into().unwrap()).collect();

        let name = info
            .get(b"name".as_slice())
            .and_then(Value::as_str)
            .unwrap_or("download")
            .to_string();

        // Single-file (`length`) vs multi-file (`files`).
        let multi_file = info.get(b"length".as_slice()).and_then(Value::as_int).is_none();
        let files = if let Some(len) = info.get(b"length".as_slice()).and_then(Value::as_int) {
            vec![FileEntry { path: vec![sanitize(&name)], length: len.max(0) as u64 }]
        } else if let Some(list) = info.get(b"files".as_slice()).and_then(Value::as_list) {
            let mut out = Vec::new();
            for f in list {
                let length =
                    f.get("length").and_then(Value::as_int).ok_or(MetaError::Missing("length"))?;
                let path = f
                    .get("path")
                    .and_then(Value::as_list)
                    .ok_or(MetaError::Missing("path"))?
                    .iter()
                    .filter_map(|c| c.as_str().map(sanitize))
                    .collect::<Vec<_>>();
                if path.is_empty() {
                    return Err(MetaError::Missing("path"));
                }
                out.push(FileEntry { path, length: length.max(0) as u64 });
            }
            out
        } else {
            return Err(MetaError::Missing("length/files"));
        };

        let total_length: u64 = files.iter().map(|f| f.length).sum();
        if total_length == 0 || piece_hashes.is_empty() {
            return Err(MetaError::Empty);
        }

        Ok(MetaInfo { info_hash, name, piece_length, piece_hashes, files, total_length, multi_file })
    }

    /// The global byte offset of file `i` (sum of the preceding files' lengths),
    /// and its length - the file's span in the torrent's concatenated data.
    pub fn file_span(&self, i: usize) -> (u64, u64) {
        let start: u64 = self.files[..i].iter().map(|f| f.length).sum();
        (start, self.files[i].length)
    }

    /// The largest playable file (the video, for a movie torrent) - what the
    /// streamer points the player at. Ties break on the first-listed file.
    pub fn primary_file(&self) -> (usize, &FileEntry) {
        self.files
            .iter()
            .enumerate()
            .max_by_key(|(_, f)| f.length)
            .expect("non-empty (checked in parse)")
    }
}

/// Web seeds declared inside the `.torrent` itself (BEP19 `url-list`, a
/// root-level key - a byte string or a list of them). Combined with the
/// magnet's `ws=` seeds to give the engine every HTTP source. Best-effort: a
/// malformed torrent just yields no extra seeds.
pub fn webseeds_from_torrent(bytes: &[u8]) -> Vec<String> {
    let Ok(root) = bencode::decode(bytes) else { return Vec::new() };
    let Some(list) = root.get("url-list") else { return Vec::new() };
    match list {
        Value::Bytes(_) => list.as_str().map(|s| vec![s.to_string()]).unwrap_or_default(),
        Value::List(items) => {
            items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
        }
        _ => Vec::new(),
    }
}

/// Strip path traversal from a torrent-supplied path component - a torrent
/// must never write outside its own directory.
fn sanitize(component: &str) -> String {
    let c = component.replace(['/', '\\'], "_");
    if c.is_empty() || c == "." || c == ".." {
        "_".to_string()
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bencode::{encode, Value};
    use std::collections::BTreeMap;

    fn d(pairs: Vec<(&str, Value)>) -> Value {
        Value::Dict(pairs.into_iter().map(|(k, v)| (k.as_bytes().to_vec(), v)).collect())
    }

    /// Build a minimal single-file .torrent with two 4-byte pieces.
    fn build_torrent() -> (Vec<u8>, [u8; 20]) {
        let piece_a: [u8; 20] = Sha1::digest(b"aaaa").into();
        let piece_b: [u8; 20] = Sha1::digest(b"bb").into();
        let mut pieces = Vec::new();
        pieces.extend_from_slice(&piece_a);
        pieces.extend_from_slice(&piece_b);
        let info = d(vec![
            ("length", Value::Int(6)),
            ("name", Value::Bytes(b"movie.mp4".to_vec())),
            ("piece length", Value::Int(4)),
            ("pieces", Value::Bytes(pieces)),
        ]);
        let info_bytes = encode(&info);
        let info_hash: [u8; 20] = Sha1::digest(&info_bytes).into();
        let root = Value::Dict(BTreeMap::from([(b"info".to_vec(), info)]));
        (encode(&root), info_hash)
    }

    #[test]
    fn parses_and_recomputes_info_hash() {
        let (bytes, hash) = build_torrent();
        let mi = MetaInfo::parse(&bytes, Some(hash)).unwrap();
        assert_eq!(mi.info_hash, hash);
        assert_eq!(mi.name, "movie.mp4");
        assert_eq!(mi.piece_length, 4);
        assert_eq!(mi.piece_count(), 2);
        assert_eq!(mi.total_length, 6);
        assert_eq!(mi.piece_size(0), 4);
        assert_eq!(mi.piece_size(1), 2); // short last piece
        assert!(mi.verify_piece(0, b"aaaa"));
        assert!(mi.verify_piece(1, b"bb"));
        assert!(!mi.verify_piece(0, b"xxxx"));
    }

    #[test]
    fn cache_dir_name_is_a_safe_hex_component() {
        let (bytes, hash) = build_torrent();
        let mi = MetaInfo::parse(&bytes, Some(hash)).unwrap();
        let name = mi.cache_dir_name();
        // Matches the plain hex id, and is a single safe path component.
        assert_eq!(name, mi.info_hash_hex());
        assert_eq!(name.len(), 40);
        assert!(name.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!name.contains(['/', '\\', '.']));
        assert_eq!(std::path::Path::new(&name).components().count(), 1);
    }

    #[test]
    fn rejects_wrong_expected_hash() {
        let (bytes, _) = build_torrent();
        let err = MetaInfo::parse(&bytes, Some([0u8; 20])).unwrap_err();
        assert!(matches!(err, MetaError::HashMismatch));
    }

    #[test]
    fn multi_file_sums_length_and_sanitizes_paths() {
        let info = d(vec![
            (
                "files",
                Value::List(vec![
                    d(vec![
                        ("length", Value::Int(10)),
                        ("path", Value::List(vec![Value::Bytes(b"a.txt".to_vec())])),
                    ]),
                    d(vec![
                        ("length", Value::Int(20)),
                        (
                            "path",
                            Value::List(vec![
                                Value::Bytes(b"..".to_vec()),
                                Value::Bytes(b"b.bin".to_vec()),
                            ]),
                        ),
                    ]),
                ]),
            ),
            ("name", Value::Bytes(b"pack".to_vec())),
            ("piece length", Value::Int(16)),
            ("pieces", Value::Bytes(vec![0u8; 40])),
        ]);
        let root = Value::Dict(BTreeMap::from([(b"info".to_vec(), info)]));
        let mi = MetaInfo::parse(&encode(&root), None).unwrap();
        assert_eq!(mi.total_length, 30);
        assert_eq!(mi.files[1].path, vec!["_", "b.bin"]); // ".." sanitized
        assert_eq!(mi.primary_file().1.length, 20); // largest file
    }
}
