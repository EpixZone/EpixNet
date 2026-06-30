//! `epix-protocol` — the EpixNet wire protocol over a `PeerStream`.
//!
//! Provides the msgpack framing ([`msg`]) and a client [`Connection`] that
//! performs the handshake and the FileRequest command set (`ping`, `getFile`,
//! …). The same connection logic runs over any [`epix_transport::Transport`].

pub mod connection;
pub mod msg;

pub use connection::{Connection, HandshakeInfo};
pub use msg::{vget, vmap};
