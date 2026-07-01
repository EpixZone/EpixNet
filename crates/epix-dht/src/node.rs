//! The Kademlia node: serves inbound RPCs and drives iterative lookups.

use crate::id::{Contact, NodeId};
use crate::routing::{RoutingTable, K};
use crate::rpc::{Request, Response, RpcClient};
use crate::store::PeerStore;
use epix_core::PeerAddr;
use futures::future::join_all;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::Duration;

/// Lookup parallelism (Kademlia `α`).
pub const ALPHA: usize = 3;

pub struct Node {
    pub id: NodeId,
    routing: Mutex<RoutingTable>,
    store: Mutex<PeerStore>,
}

impl Node {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            routing: Mutex::new(RoutingTable::new(id)),
            store: Mutex::new(PeerStore::new(Duration::from_secs(30 * 60))),
        }
    }

    pub fn add_contact(&self, contact: Contact) {
        self.routing.lock().unwrap().insert(contact);
    }

    pub fn routing_len(&self) -> usize {
        self.routing.lock().unwrap().len()
    }

    /// Serve an inbound RPC from `from` (whom we also learn).
    pub fn handle(&self, from: Contact, req: Request) -> Response {
        self.routing.lock().unwrap().insert(from);
        match req {
            Request::Ping => Response::Pong,
            Request::FindNode(target) => {
                Response::Nodes(self.routing.lock().unwrap().closest(&target, K))
            }
            Request::GetPeers(key) => {
                let peers = self.store.lock().unwrap().get(&key);
                let nodes = self.routing.lock().unwrap().closest(&key, K);
                Response::Peers { peers, nodes }
            }
            Request::Announce(key, peer) => {
                self.store.lock().unwrap().add(key, peer);
                Response::Ack
            }
        }
    }

    /// Iterative Kademlia lookup toward `target`. When `want_peers`, queries with
    /// GetPeers and accumulates any peers found. Returns `(closest nodes, peers)`.
    async fn iterative(
        &self,
        target: NodeId,
        rpc: &dyn RpcClient,
        want_peers: bool,
    ) -> (Vec<Contact>, Vec<PeerAddr>) {
        let mut shortlist = self.routing.lock().unwrap().closest(&target, K);
        let mut queried: HashSet<NodeId> = HashSet::new();
        let mut peers: Vec<PeerAddr> = Vec::new();

        loop {
            let batch: Vec<Contact> = shortlist
                .iter()
                .filter(|c| !queried.contains(&c.id))
                .take(ALPHA)
                .cloned()
                .collect();
            if batch.is_empty() {
                break;
            }

            let calls = batch.into_iter().map(|c| {
                let req = if want_peers {
                    Request::GetPeers(target)
                } else {
                    Request::FindNode(target)
                };
                async move {
                    let res = rpc.send(&c, req).await;
                    (c, res)
                }
            });

            for (contact, res) in join_all(calls).await {
                queried.insert(contact.id);
                self.routing.lock().unwrap().insert(contact);
                if let Ok(response) = res {
                    let nodes = match response {
                        Response::Nodes(nodes) => nodes,
                        Response::Peers { peers: p, nodes } => {
                            peers.extend(p);
                            nodes
                        }
                        _ => Vec::new(),
                    };
                    for n in nodes {
                        if n.id != self.id && !shortlist.iter().any(|c| c.id == n.id) {
                            shortlist.push(n);
                        }
                    }
                }
            }

            shortlist.sort_by(|a, b| target.distance(&a.id).cmp(&target.distance(&b.id)));
            shortlist.truncate(K);
        }

        (shortlist, peers)
    }

    /// Find the nodes closest to `target`.
    pub async fn find_node(&self, target: NodeId, rpc: &dyn RpcClient) -> Vec<Contact> {
        self.iterative(target, rpc, false).await.0
    }

    /// Look up the peers hosting `key`.
    pub async fn get_peers(&self, key: NodeId, rpc: &dyn RpcClient) -> Vec<PeerAddr> {
        let (_, mut peers) = self.iterative(key, rpc, true).await;
        peers.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        peers.dedup();
        peers
    }

    /// Announce that `self_peer` hosts `key` to the K nodes closest to `key`.
    pub async fn announce(&self, key: NodeId, self_peer: PeerAddr, rpc: &dyn RpcClient) {
        self.store.lock().unwrap().add(key, self_peer.clone());
        let closest = self.find_node(key, rpc).await;
        let sends = closest.into_iter().map(|c| {
            let peer = self_peer.clone();
            async move {
                let _ = rpc.send(&c, Request::Announce(key, peer)).await;
            }
        });
        join_all(sends).await;
    }

    /// Join the network via `seeds`, then refresh our own neighbourhood.
    pub async fn bootstrap(&self, seeds: Vec<Contact>, rpc: &dyn RpcClient) {
        for s in seeds {
            self.add_contact(s);
        }
        let _ = self.find_node(self.id, rpc).await;
    }
}
