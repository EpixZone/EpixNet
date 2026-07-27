//! Verified encode/decode — the only module that touches `bao_tree`.
//!
//! Everything else in the tree talks to these wrappers, so the exact
//! bao-tree version (pinned in Cargo.toml) stays an implementation detail
//! and a future bump is a one-module audit instead of a workspace sweep.
//!
//! The byte formats produced here (outboard layout, encoded slice layout)
//! are frozen in `docs/edx-slice-format.md` and locked by the golden
//! vectors in `tests/golden.rs`.

use std::io::{self, Read, Write};
use std::ops::Range;

use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::round_up_to_chunks;
use bao_tree::io::sync::{
    decode_ranges as bao_decode_ranges, encode_ranges_validated, outboard as bao_outboard,
    valid_ranges as bao_valid_ranges,
};
use bao_tree::{BaoTree, ByteRanges, ChunkRanges};
use positioned_io::{ReadAt, WriteAt};

use crate::{ObjId, BLOCK_SIZE};

/// A computed outboard: the object's root, size, and the pre-order
/// interior-hash bytes (stored separately from the data as `.obao`).
///
/// The root of an EDX object is the plain BLAKE3 hash of its content —
/// chunk-group size only affects which interior hashes are *stored*, not
/// the root — so `root` doubles as the `b3` manifest field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboardBytes {
    pub root: ObjId,
    pub size: u64,
    pub data: Vec<u8>,
}

impl OutboardBytes {
    /// Compute the outboard for in-memory bytes.
    pub fn from_slice(data: &[u8]) -> Self {
        Self::from_reader(data, data.len() as u64).expect("in-memory io cannot fail")
    }

    /// Compute the outboard by streaming `size` bytes from `data` (used by
    /// the migration pass so multi-GB files never load into RAM).
    pub fn from_reader(data: impl Read, size: u64) -> io::Result<Self> {
        let tree = BaoTree::new(size, BLOCK_SIZE);
        let mut ob = PreOrderOutboard::<Vec<u8>> {
            tree,
            root: blake3::Hash::from_bytes([0; 32]),
            data: vec![0; tree.outboard_size() as usize],
        };
        let root = bao_outboard(data, tree, &mut ob)?;
        Ok(Self { root: ObjId(*root.as_bytes()), size, data: ob.data })
    }

    fn as_pre_order(&self) -> PreOrderOutboard<&[u8]> {
        PreOrderOutboard {
            tree: BaoTree::new(self.size, BLOCK_SIZE),
            root: blake3::Hash::from_bytes(self.root.0),
            data: &self.data,
        }
    }
}

/// Convert requested byte ranges to the chunk ranges actually transferred
/// (requests are rounded outward to 16 KiB chunk-group boundaries).
pub fn chunk_ranges(byte_ranges: &[Range<u64>]) -> ChunkRanges {
    let mut spec = ByteRanges::empty();
    for r in byte_ranges {
        if r.start < r.end {
            spec |= ByteRanges::from(r.start..r.end);
        }
    }
    round_up_to_chunks(&spec)
}

/// Encode the given byte ranges of `data` as a verified slice, validating
/// every chunk against the outboard before it is written out (a locally
/// corrupted store fails here instead of serving bad bytes).
///
/// `data` is any random-access source (a slice, a sparse file); it must
/// hold the requested ranges. The output interleaves interior hash pairs
/// and chunk-group data in the frozen pre-order slice layout.
pub fn encode_slice(
    data: impl ReadAt,
    outboard: &OutboardBytes,
    byte_ranges: &[Range<u64>],
    out: impl Write,
) -> io::Result<()> {
    let ranges = chunk_ranges(byte_ranges);
    encode_ranges_validated(data, outboard.as_pre_order(), &ranges, out)
        .map_err(io::Error::from)
}

/// Decode a verified slice, writing verified chunk-group bytes into
/// `target` at their file offsets and captured interior hashes into a
/// fresh outboard. Fails on the FIRST unverifiable byte — nothing
/// unverified ever reaches `target`.
///
/// `root` + `size` come from the signed manifest, `byte_ranges` must be
/// the ranges that were requested.
pub fn decode_slice(
    encoded: impl Read,
    root: ObjId,
    size: u64,
    byte_ranges: &[Range<u64>],
    target: impl WriteAt,
) -> io::Result<()> {
    let ranges = chunk_ranges(byte_ranges);
    let tree = BaoTree::new(size, BLOCK_SIZE);
    let ob = PreOrderOutboard::<Vec<u8>> {
        tree,
        root: blake3::Hash::from_bytes(root.0),
        data: vec![0; tree.outboard_size() as usize],
    };
    bao_decode_ranges(encoded, &ranges, target, ob).map_err(io::Error::from)
}

/// Which chunk ranges of locally stored `data` actually verify against
/// the outboard's root. Used on reopen so torn or corrupted writes are
/// distrusted instead of served: anything this doesn't return is treated
/// as absent and refetched. Recomputes chunk hashes, so scope `within` to
/// the ranges the caller cares about when possible.
pub fn valid_ranges(
    outboard: &OutboardBytes,
    data: impl ReadAt,
    within: &ChunkRanges,
) -> io::Result<ChunkRanges> {
    let ob = outboard.as_pre_order();
    let mut out = ChunkRanges::empty();
    for r in bao_valid_ranges(&ob, data, within) {
        let r = r?;
        out |= ChunkRanges::from(r.start..r.end);
    }
    Ok(out)
}

/// Verify a complete small object in one shot: true iff `data` hashes to
/// `root`. Sub-4 KiB user files skip outboards entirely and use this.
pub fn verify_whole(data: &[u8], root: ObjId) -> bool {
    blake3::hash(data) == blake3::Hash::from_bytes(root.0)
}
