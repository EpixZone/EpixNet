//! Compilation of a validated module into a host-owned artifact.
//!
//! Compilation processes hostile bytes with the largest code surface in the
//! system, and compile-time denial of service is explicitly outside
//! Wasmtime's vulnerability definition. The supervisor therefore runs
//! [`precompile`] in a dedicated confined child with no workspace access and a
//! watchdog. The resulting artifact is keyed by [`crate::engine_key`] and its
//! SHA-256; the worker refuses anything else.

use sha2::{Digest, Sha256};

use crate::engine::{engine_key, new_engine};
use crate::validate::{validate_module, ModuleSummary, ValidationError};

/// A serialized module produced by this host's engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub engine_key: String,
    pub summary: ModuleSummary,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Validate and precompile `module`.
pub fn precompile(module: &[u8]) -> Result<Artifact, ValidationError> {
    let summary = validate_module(module)?;
    let engine = new_engine().map_err(|e| ValidationError::new(format!("engine: {e}")))?;
    let bytes = engine
        .precompile_module(module)
        .map_err(|e| ValidationError::new(format!("compilation failed: {e}")))?;
    let sha256 = sha256_hex(&bytes);
    Ok(Artifact {
        bytes,
        sha256,
        engine_key: engine_key(),
        summary,
    })
}
