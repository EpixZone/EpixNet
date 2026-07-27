//! Clean-room self-encryption for EDX shards.
//!
//! A file in the shard namespace is split into sub-chunks, each encrypted
//! with a key derived from content hashes (plus an owner salt), and the
//! resulting ciphertext chunks are addressed by `BLAKE3(ciphertext)` — so
//! a volunteer cache can hold and verify shards it cannot read, and
//! identical content from the same owner deduplicates.
//!
//! Two modes exist because convergent encryption is only safe for
//! high-entropy content the owner is happy to have deduplicated:
//!
//! - [`Mode::SaltedConvergent`] — dedup-preserving; the owner salt
//!   defeats third-party known-plaintext confirmation by anyone who never
//!   learned the xite address (and only by those parties — see the EDX
//!   threat model).
//! - [`Mode::RandomKey`] — a random per-file key wrapped per recipient;
//!   no dedup, but the only sound choice for guessable/low-entropy
//!   content and the only mode that supports revocation.
//!
//! The implementation lands in Phase D of the EDX plan. This crate is a
//! clean-room implementation — see `PROVENANCE.md` before contributing.

#![forbid(unsafe_code)]

/// How a shard-namespace file is encrypted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Content-derived keys salted with the owner's xite salt.
    /// Dedup-preserving; confirmable by anyone holding the xite address.
    SaltedConvergent,
    /// Random per-file key, wrapped per recipient. Revocable; no dedup.
    RandomKey,
}

/// Domain-separation context for every key this crate derives.
/// Part of the frozen format — never change without a version bump.
pub const KDF_CONTEXT: &str = "epixnet-selfenc-v1";

#[cfg(test)]
mod tests {
    use super::*;

    /// The KDF context string is a frozen format constant; this test makes
    /// changing it a deliberate act that breaks CI, not a drive-by rename.
    #[test]
    fn kdf_context_frozen() {
        assert_eq!(KDF_CONTEXT, "epixnet-selfenc-v1");
        // Deriving with the context must be deterministic across builds.
        let k = blake3::derive_key(KDF_CONTEXT, b"probe");
        let k2 = blake3::derive_key(KDF_CONTEXT, b"probe");
        assert_eq!(k, k2);
    }
}
