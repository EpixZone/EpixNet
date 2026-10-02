//! Signed activation envelopes and immutable artifact capture for EVX.
//!
//! This crate accepts Ed25519-signed JSON fixtures and ordinary Wasm or WAT
//! bytes. It never loads native compilation caches, never compiles code and
//! never hands a worker a key. Host-provided grants and checkpoints are
//! trusted inputs; checkpoints are held in memory here and persisted by the
//! host.
//!
//! # Two paths, one admission
//!
//! [`ActivationLoader::verify`] authenticates an Ed25519 fixture envelope
//! and captures its signed closure through confined descriptors.
//! [`ActivationLoader::verify_content`] takes the real authority chain
//! instead: a root `content.json` the node has already verified against the
//! xite owner's address, a [`BoundProgram`] pinned to that manifest, and a
//! reader for the stored files. Which one a grant admits is fixed by its
//! [`PublisherAuthority`]. Both check the declared version against the
//! loader's checkpoint without mutating anything and return a
//! [`PendingActivation`] exposing the identity, runtime profile and
//! capabilities the host must compare with its *current* grant.
//! [`ActivationLoader::admit`] then re-checks the checkpoint, which a
//! concurrent admission may have moved, and only then advances it.
//!
//! The split exists because advancing the checkpoint before the host's binding
//! checks would let a signed update that the current grant does not cover be
//! refused *and* still raise the version floor, leaving the previously
//! admitted version unrunnable. Here a refused update leaves the floor where
//! it was.
//!
//! # Shared data
//!
//! [`SharedDataVerifier`] accepts owner-signed source policies that the host
//! has explicitly accepted by digest and verifies writer-signed records
//! against them. Verified payloads are inert bytes; they confer no access.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod activation;
pub mod canonical;
mod capture;
mod content;
mod envelope;
mod shared;
#[cfg(test)]
mod tests;

use sha2::{Digest as _, Sha256};

pub use activation::{
    ActivationCheckpoint, ActivationLoader, ArtifactFormat, FrozenActivation, PendingActivation,
    PublisherAuthority, XiteGrant,
};
pub use canonical::canonical_bytes;
pub use content::{sha512_prefix, BoundProgram, ContentReadFn, PinnedFile};
#[cfg(any(test, feature = "fixtures"))]
pub use envelope::sign_envelope;
pub use shared::{SharedDataVerifier, SharedReadGrant, VerifiedRecord};

/// Largest signed envelope accepted, in bytes.
pub const MAX_ENVELOPE: usize = 65_536;
/// Largest single artifact file captured into a closure, in bytes.
pub const MAX_ARTIFACT: usize = 1_048_576;
/// Largest aggregate size of one captured closure, in bytes.
pub const MAX_TOTAL: usize = 4_194_304;
/// Most files one signed closure may name.
pub const MAX_FILES: usize = 16;
/// Largest shared-data record payload, in bytes.
pub const MAX_RECORD: usize = 65_536;

/// Why an envelope, artifact, policy or record was refused.
///
/// Messages name the violated rule and never include host paths, key material
/// or captured content, so they are safe to surface to a caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticationError {
    /// The input was refused for the stated reason.
    #[error("{0}")]
    Rejected(String),
}

impl AuthenticationError {
    /// Build an error carrying `message`.
    pub fn new(message: impl Into<String>) -> Self {
        AuthenticationError::Rejected(message.into())
    }

    /// The reason the input was refused.
    pub fn message(&self) -> &str {
        match self {
            AuthenticationError::Rejected(message) => message,
        }
    }
}

impl From<evx_api::Denied> for AuthenticationError {
    fn from(denied: evx_api::Denied) -> Self {
        AuthenticationError::new(denied.to_string())
    }
}

/// Lowercase hex SHA-256 of `data`, the digest form used in every envelope.
pub fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
