//! `epix-channel` — the channel app's private index.
//!
//! This crate is now just the *channel-specific* half: [`ChannelDb`], the private,
//! never-shared SQLite index (`<data_root>/private/channels.db`) holding decrypted
//! threads/messages, an FTS5 search index, ratchet sessions, and the detection-
//! tag set. It implements [`epix_envelope::EnvelopeStore`], so the app-agnostic
//! sealed-envelope engine + trial-decrypt indexer live in `epix-envelope` and a
//! future encrypted forum/DM app can reuse them over its own store.
//!
//! The web page never touches any of this — it goes through the node's `channel*`
//! WebSocket commands, and no key material crosses that boundary.

pub mod db;
pub mod enc;
pub mod legacy;

pub use db::{ChannelDb, IdentityRow, RevokedDevice, SessionPeer};
