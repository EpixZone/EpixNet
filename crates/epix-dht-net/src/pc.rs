//! postcard encoding of the same DHT RPCs as [`crate::wire`], carried as the
//! opaque payload of an EDX `Kad` message. EDX is postcard end to end, so the
//! payload is postcard too - re-wrapping msgpack inside it would keep rmpv
//! alive on the peer wire, which is exactly what the migration removes.
//!
//! The `epix-dht` types are deliberately serde-free, so the wire shape lives
//! here as mirror types that convert to and from them.

use epix_core::PeerAddr;
use epix_dht::{Contact, NodeId, Request, Response};
use serde::{Deserialize, Serialize};

/// Longest onion host / i2p destination accepted from a peer. A v3 onion
/// label is 56 chars and an i2p b32 label 52 (plus its `.b32` suffix), so
/// anything longer is junk. Unbounded it would sit in the routing table or
/// the peer store until restart and push our own honest replies past the EDX
/// frame cap, which the writer cannot encode.
pub(crate) const MAX_HOST_LEN: usize = 64;

/// Whether a peer-claimed address may enter the routing table or the peer
/// store: a complete, dialable shape, with a bounded overlay host.
pub(crate) fn usable_addr(addr: &PeerAddr) -> bool {
    if !addr.is_wellformed() {
        return false;
    }
    match addr {
        PeerAddr::Onion { host, .. } => host.len() <= MAX_HOST_LEN,
        PeerAddr::I2p { dest, .. } => dest.len() <= MAX_HOST_LEN,
        _ => true,
    }
}

#[derive(Serialize, Deserialize)]
struct PcContact {
    id: [u8; 32],
    addr: PeerAddr,
}

impl PcContact {
    fn from(c: &Contact) -> Self {
        Self { id: c.id.0, addr: c.addr.clone() }
    }

    fn into_contact(self) -> Contact {
        Contact::new(NodeId::new(self.id), self.addr)
    }
}

/// Variants are APPEND-ONLY: postcard encodes an enum as its positional index,
/// so reordering or removing one silently reinterprets bytes from older nodes.
#[derive(Serialize, Deserialize)]
enum PcRequest {
    Ping,
    FindNode([u8; 32]),
    GetPeers([u8; 32]),
    Announce([u8; 32], PeerAddr),
}

/// Variants are APPEND-ONLY, for the same reason as [`PcRequest`]. Unlike the
/// msgpack decoder, which infers the variant from which fields are present,
/// this carries the variant itself.
#[derive(Serialize, Deserialize)]
enum PcResponse {
    Pong,
    Nodes(Vec<PcContact>),
    Peers { peers: Vec<PeerAddr>, nodes: Vec<PcContact> },
    Ack,
}

/// A request plus the caller's contact, so the receiver learns us.
#[derive(Serialize, Deserialize)]
struct PcReq {
    from: PcContact,
    req: PcRequest,
}

/// A response stamped with the responder's node id, so a caller that only
/// knows an address - a bootstrap probe - learns the authentic contact from
/// the reply itself. Over EDX the stamp is always present; on the msgpack wire
/// older nodes may omit it, which is why that decoder returns an `Option`.
#[derive(Serialize, Deserialize)]
struct PcResp {
    id: [u8; 32],
    resp: PcResponse,
}

fn contacts_out(nodes: &[Contact]) -> Vec<PcContact> {
    nodes.iter().map(PcContact::from).collect()
}

/// Contacts learned from a response go straight into the routing table, which
/// never evicts, so a peer that answers with junk addresses poisons us for the
/// life of the process. Same gate as the serve path, applied on the way in.
fn contacts_in(nodes: Vec<PcContact>) -> Vec<Contact> {
    nodes
        .into_iter()
        .filter(|c| usable_addr(&c.addr))
        .map(PcContact::into_contact)
        .collect()
}

/// Encode a request (with the caller's contact) for an EDX `Kad` payload.
pub fn encode_request(from: &Contact, req: &Request) -> Vec<u8> {
    let req = match req {
        Request::Ping => PcRequest::Ping,
        Request::FindNode(t) => PcRequest::FindNode(t.0),
        Request::GetPeers(k) => PcRequest::GetPeers(k.0),
        Request::Announce(k, p) => PcRequest::Announce(k.0, p.clone()),
    };
    let msg = PcReq { from: PcContact::from(from), req };
    // Plain owned data into a Vec: postcard has nothing to fail on.
    postcard::to_stdvec(&msg).expect("postcard encode of plain data cannot fail")
}

pub fn decode_request(bytes: &[u8]) -> Option<(Contact, Request)> {
    let msg: PcReq = postcard::from_bytes(bytes).ok()?;
    let req = match msg.req {
        PcRequest::Ping => Request::Ping,
        PcRequest::FindNode(t) => Request::FindNode(NodeId::new(t)),
        PcRequest::GetPeers(k) => Request::GetPeers(NodeId::new(k)),
        PcRequest::Announce(k, p) => Request::Announce(NodeId::new(k), p),
    };
    Some((msg.from.into_contact(), req))
}

/// Encode a response, stamped with the responder's node id.
pub fn encode_response(resp: &Response, me: &NodeId) -> Vec<u8> {
    let resp = match resp {
        Response::Pong => PcResponse::Pong,
        Response::Ack => PcResponse::Ack,
        Response::Nodes(nodes) => PcResponse::Nodes(contacts_out(nodes)),
        Response::Peers { peers, nodes } => {
            PcResponse::Peers { peers: peers.clone(), nodes: contacts_out(nodes) }
        }
    };
    postcard::to_stdvec(&PcResp { id: me.0, resp })
        .expect("postcard encode of plain data cannot fail")
}

/// Decode a response and the responder's node id.
pub fn decode_response(bytes: &[u8]) -> Option<(NodeId, Response)> {
    let msg: PcResp = postcard::from_bytes(bytes).ok()?;
    let resp = match msg.resp {
        PcResponse::Pong => Response::Pong,
        PcResponse::Ack => Response::Ack,
        PcResponse::Nodes(nodes) => Response::Nodes(contacts_in(nodes)),
        PcResponse::Peers { peers, nodes } => {
            Response::Peers { peers, nodes: contacts_in(nodes) }
        }
    };
    Some((NodeId::new(msg.id), resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> PeerAddr {
        PeerAddr::parse(s).unwrap()
    }

    fn me() -> Contact {
        Contact::new(NodeId::hash(b"me"), addr("203.0.113.7:26552"))
    }

    fn round_trip_req(req: Request) -> Request {
        let bytes = encode_request(&me(), &req);
        let (from, out) = decode_request(&bytes).expect("decodes");
        assert_eq!(from, me());
        out
    }

    #[test]
    fn ping_round_trips() {
        assert!(matches!(round_trip_req(Request::Ping), Request::Ping));
    }

    #[test]
    fn find_node_round_trips() {
        let target = NodeId::hash(b"target");
        match round_trip_req(Request::FindNode(target)) {
            Request::FindNode(t) => assert_eq!(t, target),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn get_peers_round_trips() {
        let key = NodeId::hash(b"key");
        match round_trip_req(Request::GetPeers(key)) {
            Request::GetPeers(k) => assert_eq!(k, key),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn announce_round_trips() {
        let key = NodeId::hash(b"key");
        // An onion peer: PeerAddr's own variants must survive the round trip.
        let peer = addr("abcdefghijklmnop.onion:26552");
        match round_trip_req(Request::Announce(key, peer.clone())) {
            Request::Announce(k, p) => {
                assert_eq!(k, key);
                assert_eq!(p, peer);
            }
            other => panic!("got {other:?}"),
        }
    }

    fn round_trip_resp(resp: Response) -> (NodeId, Response) {
        let id = NodeId::hash(b"responder");
        let bytes = encode_response(&resp, &id);
        let (stamped, out) = decode_response(&bytes).expect("decodes");
        // The responder always stamps its own id on this wire.
        assert_eq!(stamped, id);
        (stamped, out)
    }

    #[test]
    fn pong_and_ack_round_trip() {
        assert!(matches!(round_trip_resp(Response::Pong).1, Response::Pong));
        assert!(matches!(round_trip_resp(Response::Ack).1, Response::Ack));
    }

    #[test]
    fn nodes_round_trips() {
        let c = Contact::new(NodeId::hash(b"n1"), addr("198.51.100.4:26552"));
        match round_trip_resp(Response::Nodes(vec![c.clone()])).1 {
            Response::Nodes(nodes) => assert_eq!(nodes, vec![c]),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn peers_round_trips() {
        let c = Contact::new(NodeId::hash(b"n1"), addr("198.51.100.4:26552"));
        let p = addr("198.51.100.5:26552");
        let resp = Response::Peers { peers: vec![p.clone()], nodes: vec![c.clone()] };
        match round_trip_resp(resp).1 {
            Response::Peers { peers, nodes } => {
                assert_eq!(peers, vec![p]);
                assert_eq!(nodes, vec![c]);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn an_unusable_contact_in_a_response_is_dropped() {
        // A response is the other way a contact reaches the routing table, and
        // it skips the serve-path check entirely.
        let good = Contact::new(NodeId::hash(b"good"), addr("198.51.100.4:26552"));
        let huge = Contact::new(
            NodeId::hash(b"huge"),
            PeerAddr::Onion { host: "a".repeat(MAX_HOST_LEN + 1), port: 26552 },
        );
        let nodes = vec![huge, good.clone()];

        match round_trip_resp(Response::Nodes(nodes.clone())).1 {
            Response::Nodes(nodes) => assert_eq!(nodes, vec![good.clone()]),
            other => panic!("got {other:?}"),
        }

        // The nodes list of a Peers answer is the same door.
        let resp = Response::Peers { peers: vec![], nodes };
        match round_trip_resp(resp).1 {
            Response::Peers { nodes, .. } => assert_eq!(nodes, vec![good]),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn empty_peers_answer_round_trips() {
        // A GetPeers miss: no peers, only closer nodes. The msgpack decoder
        // inferred this from field presence; here the variant is explicit.
        let empty = Response::Peers { peers: vec![], nodes: vec![] };
        match round_trip_resp(empty).1 {
            Response::Peers { peers, nodes } => {
                assert!(peers.is_empty() && nodes.is_empty());
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(decode_request(&[0xff, 0xff, 0xff]).is_none());
        assert!(decode_response(&[0xff, 0xff, 0xff]).is_none());
    }

    /// Postcard encodes a variant as its positional index, so a reorder
    /// silently misdecodes against deployed nodes instead of failing to
    /// compile. Pin the assignment here (same guard as
    /// `epix_edx::msg::wire_indices_frozen`) so CI catches it.
    #[test]
    fn wire_indices_frozen() {
        let id = NodeId::new([0u8; 32]);
        let addr = PeerAddr::parse("1.2.3.4:26552").unwrap();
        let from = Contact::new(id, addr.clone());

        // PcRequest discriminants. Layout: the request struct encodes
        // `from` first, so probe the enum by comparing against a known
        // prefix - encode each and assert the variant byte.
        let reqs: Vec<(Request, u8)> = vec![
            (Request::Ping, 0),
            (Request::FindNode(id), 1),
            (Request::GetPeers(id), 2),
            (Request::Announce(id, addr.clone()), 3),
        ];
        for (req, disc) in reqs {
            let bytes = encode_request(&from, &req);
            let base = encode_request(&from, &Request::Ping);
            // The `from` prefix is identical across variants, so the byte
            // right after it is the enum discriminant.
            let at = base.len() - 1;
            assert_eq!(bytes[at], disc, "PcRequest discriminant moved: {req:?}");
        }

        let resps: Vec<(Response, u8)> = vec![
            (Response::Pong, 0),
            (Response::Nodes(vec![]), 1),
            (Response::Peers { peers: vec![], nodes: vec![] }, 2),
            (Response::Ack, 3),
        ];
        for (resp, disc) in resps {
            let bytes = encode_response(&resp, &id);
            // `me` (32 raw bytes) is encoded first, then the variant.
            assert_eq!(bytes[32], disc, "PcResponse discriminant moved: {resp:?}");
        }
    }
}
