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

        Ok(MetaInfo { info_hash, name, piece_length, piece_hashes, files, total_length })
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
