//! DHT RPCs. In the real node these ride the peer `Connection` (epix-protocol);
//! an in-memory implementation backs the tests.

use crate::id::{Contact, NodeId};
use async_trait::async_trait;
use epix_core::PeerAddr;

#[derive(Clone, Debug)]
pub enum Request {
    Ping,
    FindNode(NodeId),
    GetPeers(NodeId),
    Announce(NodeId, PeerAddr),
}

#[derive(Clone, Debug)]
pub enum Response {
    Pong,
    Nodes(Vec<Contact>),
    /// GetPeers: the peers hosting the key (if any), plus closer nodes to keep
    /// the lookup converging.
    Peers { peers: Vec<PeerAddr>, nodes: Vec<Contact> },
    Ack,
}

/// Sends a DHT RPC to a contact.
#[async_trait]
pub trait RpcClient: Send + Sync {
    async fn send(&self, to: &Contact, req: Request) -> Result<Response, String>;
}
