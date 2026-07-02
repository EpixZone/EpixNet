//! `epix-dht` - a private Kademlia DHT for EpixNet peer discovery.
//!
//! The core query is `site → its peers`: a directed lookup that works for rare
//! sites and survives tracker bans. Unlike BitTorrent's mainline DHT this is a
//! private keyspace and runs over [`crate::rpc::RpcClient`] - which, in the real
//! node, rides the peer `Connection` (epix-protocol), so it works over **TCP,
//! Tor, and Reticulum mesh** alike.

pub mod id;
pub mod node;
pub mod routing;
pub mod rpc;
pub mod store;

pub use id::{Contact, NodeId};
pub use node::Node;
pub use rpc::{Request, Response, RpcClient};

/// A site's DHT lookup key: `sha256(address)` (matches the tracker hash).
pub fn site_key(address: &str) -> NodeId {
    NodeId::hash(address.as_bytes())
}
