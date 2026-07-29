//! Server side: answer inbound DHT RPCs against a local [`Node`].

use crate::pc;
use crate::wire::{decode_request, encode_response, KAD_CMD};
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{Contact, Node, Request, Response};
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

    /// The RPC itself, shared by both wires (msgpack and EDX): fix up what the
    /// caller claimed about itself, then answer from the node.
    fn answer(&self, peer: &PeerAddr, mut from: Contact, mut req: Request) -> Response {
        from.addr = rewrite_claimed_addr(from.addr, peer);
        if let Request::Announce(key, claimed) = req {
            req = Request::Announce(key, rewrite_claimed_addr(claimed, peer));
        }
        self.node.handle(from, req)
    }

    /// EDX entry point: the postcard payload of a `Kad` message in, the
    /// postcard reply out. Same logic as the msgpack [`RequestHandler`].
    pub fn handle_edx(&self, peer: &PeerAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
        let (from, req) = pc::decode_request(payload).ok_or("malformed kad request")?;
        let resp = self.answer(peer, from, req);
        Ok(pc::encode_response(&resp, &self.node.id))
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
            Some((from, req)) => encode_response(&self.answer(peer, from, req), &self.node.id),
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

    #[test]
    fn edx_ping_is_answered_and_the_caller_is_learned_at_its_real_ip() {
        use epix_dht::NodeId;

        let node = Arc::new(Node::new(NodeId::hash(b"local")));
        let svc = DhtService::new(node.clone());
        let conn = PeerAddr::parse("203.0.113.9:54321").unwrap();
        let claimed = PeerAddr::parse("0.0.0.0:26552").unwrap();
        let caller = Contact::new(NodeId::hash(b"caller"), claimed);

        let payload = pc::encode_request(&caller, &Request::Ping);
        let reply = svc.handle_edx(&conn, &payload).expect("answers");
        let (id, resp) = pc::decode_response(&reply).expect("decodes");
        assert_eq!(id, node.id);
        assert!(matches!(resp, Response::Pong));

        // The claimed 0.0.0.0 was rewritten before the node learned the caller:
        // ask for the closest nodes and check the address we stored.
        let payload = pc::encode_request(&caller, &Request::FindNode(caller.id));
        let reply = svc.handle_edx(&conn, &payload).expect("answers");
        match pc::decode_response(&reply).expect("decodes").1 {
            Response::Nodes(nodes) => {
                assert_eq!(nodes[0].addr, PeerAddr::parse("203.0.113.9:26552").unwrap());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn edx_rejects_a_malformed_payload() {
        let svc = DhtService::new(Arc::new(Node::new(epix_dht::NodeId::hash(b"local"))));
        let conn = PeerAddr::parse("203.0.113.9:54321").unwrap();
        assert!(svc.handle_edx(&conn, &[0xff, 0xff, 0xff]).is_err());
    }
}
