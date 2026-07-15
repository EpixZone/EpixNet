//! `epix-protocol` - the EpixNet wire protocol over a `PeerStream`.
//!
//! Provides the msgpack framing ([`msg`]) and a client [`Connection`] that
//! performs the handshake and the FileRequest command set (`ping`, `getFile`,
//! …). The same connection logic runs over any [`epix_transport::Transport`].

pub mod advert;
pub mod connection;
pub mod msg;
pub mod server;

pub use advert::{set_self_advert, update_self_advert, SelfAdvert};
pub use connection::{Connection, FindHashIdsReply, HandshakeInfo, PexReply};
pub use msg::{vget, vmap, wire_totals};
pub use server::{serve_stream, InboundHook, PeerServer, RequestHandler};
