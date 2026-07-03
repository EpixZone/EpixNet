//! Server side: answer inbound DHT RPCs against a local [`Node`].

use crate::wire::{decode_request, encode_response, KAD_CMD};
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{Node, Request};
use epix_protocol::{vmap, RequestHandler};
use rmpv::Value;
use std::sync::Arc;

/// A `RequestHandler` that serves `kad` RPCs from a shared DHT node.
pub struct DhtService {
    node: Arc<Node>,
}

impl DhtService {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }
}

/// A NAT'd node doesn't know its public IP, so it claims `0.0.0.0:<port>` (or
/// a wrong IP). Like a BitTorrent tracker, trust the connection: keep the
/// claimed port (the peer's listening port) but take the IP from where the
/// request actually came from. Onion/mesh addresses pass through as claimed
/// (there is nothing to infer).
fn rewrite_claimed_addr(claimed: PeerAddr, conn: &PeerAddr) -> PeerAddr {
    match (&claimed, conn) {
        (PeerAddr::Ip(claimed_sock), PeerAddr::Ip(conn_sock)) => {
            PeerAddr::Ip(std::net::SocketAddr::new(conn_sock.ip(), claimed_sock.port()))
        }
        _ => claimed,
    }
}

#[async_trait]
impl RequestHandler for DhtService {
    async fn handle(&self, peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        if cmd != KAD_CMD {
            return vmap(vec![("error", Value::from("unknown command"))]);
        }
        match decode_request(params) {
            Some((mut from, mut req)) => {
                from.addr = rewrite_claimed_addr(from.addr, peer);
                if let Request::Announce(key, claimed) = req {
                    req = Request::Announce(key, rewrite_claimed_addr(claimed, peer));
                }
                encode_response(&self.node.handle(from, req), &self.node.id)
            }
            None => vmap(vec![("error", Value::from("malformed kad request"))]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimed_ip_is_rewritten_to_connection_ip() {
        let claimed = PeerAddr::parse("0.0.0.0:26552").unwrap();
        let conn = PeerAddr::parse("203.0.113.9:54321").unwrap();
        // IP from the connection, port from the claim (the listening port).
        assert_eq!(
            rewrite_claimed_addr(claimed, &conn),
            PeerAddr::parse("203.0.113.9:26552").unwrap()
        );

        // Onion claims pass through (nothing to infer from the connection).
        let onion = PeerAddr::parse("abcdefghijklmnop.onion:26552").unwrap();
        assert_eq!(rewrite_claimed_addr(onion.clone(), &conn), onion);
    }
}
