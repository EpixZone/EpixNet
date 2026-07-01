//! `epix-chain` — the Epix chain layer.
//!
//! Resolves `.epix` names to their on-chain records, **chain-verified**: every
//! answer is checked with a Merkle inclusion proof against a state digest that
//! has been finalized by 2/3+ validators. A malicious or buggy RPC cannot forge
//! a resolution — a tampered proof is rejected.

mod merkle;
mod resolver;
mod types;

pub use resolver::{XidResolver, DEFAULT_RPC_URL};
pub use types::{DomainSnapshot, Identity};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("rpc request failed: {0}")]
    Rpc(String),
    #[error("name not found: {0}")]
    NotFound(String),
    #[error("Merkle proof verification failed")]
    MerkleInvalid,
    #[error("proof root does not match the attested state digest")]
    DigestMismatch,
    #[error("state digest not finalized by validators")]
    NotFinalized,
    #[error("malformed chain response: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, ChainError>;
