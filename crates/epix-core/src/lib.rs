//! `epix-core` - shared domain types and the UI-agnostic `Emitter` seam.
//!
//! This crate is intentionally free of any platform, UI, async-runtime, or
//! networking dependency. Everything above it (runtime, transports, UI shells)
//! builds on these types and the [`Emitter`] trait.

pub mod address;
pub mod emitter;
pub mod error;
pub mod peer;

pub use address::Address;
pub use emitter::{CollectingEmitter, Emitter, NoopEmitter};
pub use error::{Error, Result};
pub use peer::PeerAddr;
