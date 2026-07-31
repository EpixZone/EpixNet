//! `epix-protocol` - the peer plumbing every transport shares.
//!
//! EDX is the only peer protocol, so what is left here is what sits either
//! side of it: the inbound accept loop ([`server`]), the live connection
//! registry the Stats page reads ([`registry`]), and this node's dial-back
//! self-advertisement ([`advert`]).

pub mod advert;
pub mod registry;
pub mod server;

pub use advert::{self_advert_version, set_self_advert, update_self_advert, SelfAdvert};
pub use registry::{wire_totals, HandshakeInfo};
pub use server::{EdxHook, InboundHook, PeerServer};
