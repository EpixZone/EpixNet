//! Server side: answer inbound DHT RPCs against a local [`Node`].

use crate::pc;
use epix_core::PeerAddr;
use epix_dht::{Contact, Node, Request, Response};
use std::sync::Arc;

/// Longest onion host / i2p destination accepted from a peer. A v3 onion
/// label is 56 chars and an i2p b32 label 52 (plus its `.b32` suffix), so
/// anything longer is junk. Unbounded it would sit in the routing table or
/// the peer store until restart and push our own honest replies past the EDX
/// frame cap, which the writer cannot encode.
const MAX_HOST_LEN: usize = 64;

/// Byte budget for one reply payload. It rides a single EDX frame that is
/// hard-capped, and an oversize frame fails to encode in the writer task,
/// which tears down the WHOLE multiplexed connection and not just this
/// stream. A reply that would not fit is trimmed instead.
const MAX_REPLY_LEN: usize = 60 * 1024;

/// Serves inbound `Kad` RPCs from a shared DHT node.
pub struct DhtService {
    node: Arc<Node>,
}

impl DhtService {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    /// The RPC itself: fix up what the caller claimed about itself, then
    /// answer from the node.
    fn answer(&self, peer: &PeerAddr, mut from: Contact, mut req: Request) -> Response {
        from.addr = rewrite_claimed_addr(from.addr, peer);
        if let Request::Announce(key, claimed) = req {
            req = Request::Announce(key, rewrite_claimed_addr(claimed, peer));
        }
        self.node.handle(from, req)
    }

    /// The postcard payload of a `Kad` message in, the postcard reply out.
    pub fn handle_edx(&self, peer: &PeerAddr, payload: &[u8]) -> Result<Vec<u8>, String> {
        let (from, req) = pc::decode_request(payload).ok_or("malformed kad request")?;
        // Nothing between the wire and the routing table checks the claimed
        // address, and the table never evicts, so an unusable claim is
        // permanent and rides out again in every reply we build.
        if !usable_addr(&from.addr) {
            return Err("unusable contact address".into());
        }
        if let Request::Announce(_, claimed) = &req {
            if !usable_addr(claimed) {
                return Err("unusable announced address".into());
            }
        }
        let resp = self.answer(peer, from, req);
        Ok(self.encode_bounded(resp))
    }

    /// Encode a reply, dropping entries from the far end until it fits
    /// [`MAX_REPLY_LEN`].
    fn encode_bounded(&self, mut resp: Response) -> Vec<u8> {
        loop {
            let bytes = pc::encode_response(&resp, &self.node.id);
            if bytes.len() <= MAX_REPLY_LEN || !drop_farthest(&mut resp) {
                return bytes;
            }
        }
    }
}

/// Whether a peer-claimed address may enter the routing table or the peer
/// store: a complete, dialable shape, with a bounded overlay host.
fn usable_addr(addr: &PeerAddr) -> bool {
    if !addr.is_wellformed() {
        return false;
    }
    match addr {
        PeerAddr::Onion { host, .. } => host.len() <= MAX_HOST_LEN,
        PeerAddr::I2p { dest, .. } => dest.len() <= MAX_HOST_LEN,
        _ => true,
    }
}

/// Drop the last entry of a list-carrying response. `closest` returns nearest
/// first, so this sheds the least useful contact. False when there is nothing
/// left to drop.
fn drop_farthest(resp: &mut Response) -> bool {
    match resp {
        Response::Nodes(nodes) => nodes.pop().is_some(),
        Response::Peers { peers, nodes } => nodes.pop().is_some() || peers.pop().is_some(),
        Response::Pong | Response::Ack => false,
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
    fn an_oversized_claimed_address_never_reaches_the_routing_table() {
        use epix_dht::NodeId;

        let node = Arc::new(Node::new(NodeId::hash(b"local")));
        let svc = DhtService::new(node.clone());
        let conn = PeerAddr::parse("203.0.113.9:54321").unwrap();
        let huge = PeerAddr::Onion { host: "a".repeat(35_000), port: 1 };
        let caller = Contact::new(NodeId::hash(b"caller"), huge.clone());

        let payload = pc::encode_request(&caller, &Request::Ping);
        assert!(svc.handle_edx(&conn, &payload).is_err(), "rejected, not learned");
        assert_eq!(node.routing_len(), 0);

        // The same check covers the address an Announce claims, which would
        // otherwise come back out of the peer store in every GetPeers reply.
        let ok = Contact::new(NodeId::hash(b"caller"), PeerAddr::parse("0.0.0.0:26552").unwrap());
        let key = NodeId::hash(b"xite");
        let payload = pc::encode_request(&ok, &Request::Announce(key, huge));
        assert!(svc.handle_edx(&conn, &payload).is_err());
        let payload = pc::encode_request(&ok, &Request::GetPeers(key));
        match pc::decode_response(&svc.handle_edx(&conn, &payload).unwrap()).unwrap().1 {
            Response::Peers { peers, .. } => assert!(peers.is_empty()),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_reply_stays_inside_the_frame_budget() {
        use epix_dht::NodeId;

        // The decode paths screen oversize hosts, so a table can only hold one
        // through a path that predates that screening. This is the backstop for
        // that case: the reply is trimmed to fit rather than made unframeable.
        let node = Arc::new(Node::new(NodeId::hash(b"local")));
        for i in 0..8u8 {
            node.add_contact(Contact::new(
                NodeId::hash(&[i]),
                PeerAddr::Onion { host: "a".repeat(20_000), port: 15441 },
            ));
        }
        let svc = DhtService::new(node.clone());
        let conn = PeerAddr::parse("203.0.113.9:54321").unwrap();
        let caller =
            Contact::new(NodeId::hash(b"caller"), PeerAddr::parse("0.0.0.0:26552").unwrap());

        let payload = pc::encode_request(&caller, &Request::FindNode(caller.id));
        let reply = svc.handle_edx(&conn, &payload).expect("answers");
        assert!(reply.len() <= MAX_REPLY_LEN, "reply of {} bytes", reply.len());
        // Asserted on the bytes, not the decoded contacts: `decode_response`
        // now drops oversize hosts, so decoding this reply yields nothing even
        // though the trim kept entries in it. Each seeded contact is ~20 KB
        // against a 60 KB cap, so a trim that kept any at all lands well past
        // half the cap, while an emptied reply would be a few dozen bytes.
        assert!(reply.len() > MAX_REPLY_LEN / 2, "trimmed, not emptied: {} bytes", reply.len());
    }

    #[test]
    fn edx_rejects_a_malformed_payload() {
        let svc = DhtService::new(Arc::new(Node::new(epix_dht::NodeId::hash(b"local"))));
        let conn = PeerAddr::parse("203.0.113.9:54321").unwrap();
        assert!(svc.handle_edx(&conn, &[0xff, 0xff, 0xff]).is_err());
    }
}
