//! EVX runtime: validation, engine configuration, compilation and execution.
//!
//! The order of operations is fixed and mirrors the chains and sandboxes that
//! run hostile Wasm in production:
//!
//! 1. [`validate::validate_module`] parses the bytes with the exact feature
//!    set in [`features`] and enforces structural caps before any compiler
//!    sees them.
//! 2. [`compile::precompile`] turns a validated module into a serialized
//!    artifact in a separate, confined process. The artifact is keyed by
//!    engine version and configuration.
//! 3. [`exec::run`] deserializes only an artifact whose digest and engine key
//!    match, instantiates it with the store limiter, fuel and an epoch
//!    deadline, and routes the single `evx.call` import to a host callback.
//!
//! Nothing in this crate opens files, sockets or processes.

pub mod compile;
pub mod engine;
pub mod exec;
pub mod features;
pub mod validate;

pub use compile::{precompile, Artifact};
pub use engine::{engine_config, engine_key, new_engine};
pub use exec::{run, ExecReport, HostCalls, HostError, RunOptions};
pub use validate::{validate_module, ModuleSummary, ValidationError};

/// Conversion of WebAssembly text to binary for fixtures. Only compiled in
/// when the `text` feature is enabled; the worker binary never enables it.
#[cfg(feature = "text")]
pub fn text_to_binary(source: &str) -> Result<Vec<u8>, ValidationError> {
    if source.len() > evx_api::MAX_MODULE {
        return Err(ValidationError::new("module size limit"));
    }
    wat::parse_str(source).map_err(|e| ValidationError::new(format!("text format: {e}")))
}
