//! EDX verified blob core.
//!
//! Every EDX object — a file blob, a small-file bundle, or an encrypted
//! shard — is content-addressed by its 32-byte BLAKE3 root and carries a
//! bao outboard tree so byte ranges can be fetched and verified
//! incrementally (corruption localizes to one 16 KiB chunk group, and a
//! multi-range response verifies against the same root as the whole
//! file). This crate owns:
//!
//! - the bao encode/verify wrappers (`BlockSize` fixed at 16 KiB groups),
//! - the sparse on-disk store (slab files + `redb` index + refcount/LRU),
//! - the chunk-group bitfield used for availability exchange.
//!
//! The slice format produced here is a frozen wire contract shared with
//! any future non-Rust verifier; see `docs/edx-slice-format.md` once
//! Phase A lands it.

#![forbid(unsafe_code)]

pub mod bitfield;
pub mod bundle;
pub mod manifest;
pub mod store;
pub mod verified;

use core::fmt;

/// Chunk-group size: bao validates at `1 KiB << CHUNK_GROUP_LOG` = 16 KiB
/// granularity. This constant is part of the frozen slice format — it can
/// never change without re-rooting every object on the network.
pub const CHUNK_GROUP_LOG: u8 = 4;

/// The bao block size every EDX object is encoded with.
pub const BLOCK_SIZE: bao_tree::BlockSize = bao_tree::BlockSize::from_chunk_log(CHUNK_GROUP_LOG);

/// 32-byte BLAKE3 root identifying an immutable EDX object.
///
/// For `Ns::Plain` objects this is the BLAKE3 root of the cleartext bytes;
/// for `Ns::Shard` objects it is the BLAKE3 hash of the ciphertext (the
/// shard address), so a volunteer cache can verify what it stores without
/// being able to read it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjId(pub [u8; 32]);

impl ObjId {
    /// The id of these bytes (plain BLAKE3 hash).
    pub fn of(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for ObjId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ObjId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjId({self})")
    }
}

/// Which namespace an object lives in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ns {
    /// Public cleartext bytes, verified by a bao tree over the plaintext.
    Plain,
    /// Opaque ciphertext produced by `epix-selfenc`, addressed by
    /// `BLAKE3(ciphertext)`; the holder cannot read it.
    Shard,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE3 of the empty string is a published constant; if this fails the
    /// pinned blake3 crate is not producing canonical output.
    #[test]
    fn blake3_empty_golden() {
        let h = blake3::hash(b"");
        assert_eq!(
            h.to_hex().as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn block_size_is_16k_groups() {
        assert_eq!(BLOCK_SIZE.bytes(), 16 * 1024);
    }

    #[test]
    fn objid_hex_round_trip() {
        let id = ObjId(*blake3::hash(b"epix").as_bytes());
        let s = id.to_string();
        assert_eq!(ObjId::from_hex(&s), Some(id));
        assert_eq!(ObjId::from_hex("zz"), None);
    }
}
