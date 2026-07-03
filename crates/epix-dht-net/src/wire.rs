//! msgpack encoding of DHT RPCs, carried as a `kad` command over the peer wire.

use epix_core::PeerAddr;
use epix_dht::{Contact, NodeId, Request, Response};
use epix_protocol::{vget, vmap};
use rmpv::Value;

/// The wire command name for all DHT RPCs.
pub const KAD_CMD: &str = "kad";

fn id_to_value(id: &NodeId) -> Value {
    Value::from(id.to_hex())
}

fn value_to_id(v: &Value) -> Option<NodeId> {
    let bytes = hex::decode(v.as_str()?).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(NodeId::new(arr))
}

fn contact_to_value(c: &Contact) -> Value {
    vmap(vec![("id", id_to_value(&c.id)), ("addr", Value::from(c.addr.to_string()))])
}

fn value_to_contact(v: &Value) -> Option<Contact> {
    let id = value_to_id(vget(v, "id")?)?;
    let addr = PeerAddr::parse(vget(v, "addr")?.as_str()?).ok()?;
    Some(Contact::new(id, addr))
}

/// Encode a request (with the caller's contact so the receiver learns us).
pub fn encode_request(from: &Contact, req: &Request) -> Value {
    let mut pairs = vec![("from", contact_to_value(from))];
    match req {
        Request::Ping => pairs.push(("op", Value::from("ping"))),
        Request::FindNode(t) => {
            pairs.push(("op", Value::from("find")));
            pairs.push(("target", id_to_value(t)));
        }
        Request::GetPeers(k) => {
            pairs.push(("op", Value::from("get")));
            pairs.push(("target", id_to_value(k)));
        }
        Request::Announce(k, p) => {
            pairs.push(("op", Value::from("announce")));
            pairs.push(("target", id_to_value(k)));
            pairs.push(("peer", Value::from(p.to_string())));
        }
    }
    vmap(pairs)
}

pub fn decode_request(params: &Value) -> Option<(Contact, Request)> {
    let from = value_to_contact(vget(params, "from")?)?;
    let op = vget(params, "op")?.as_str()?;
    let req = match op {
        "ping" => Request::Ping,
        "find" => Request::FindNode(value_to_id(vget(params, "target")?)?),
        "get" => Request::GetPeers(value_to_id(vget(params, "target")?)?),
        "announce" => Request::Announce(
            value_to_id(vget(params, "target")?)?,
            PeerAddr::parse(vget(params, "peer")?.as_str()?).ok()?,
        ),
        _ => return None,
    };
    Some((from, req))
}

/// Encode a response, stamped with the responder's node id (`id`) so a caller
/// that only knows an address - a bootstrap probe - learns the authentic
/// contact from the reply itself.
pub fn encode_response(resp: &Response, me: &NodeId) -> Value {
    let mut pairs = vec![("id", id_to_value(me))];
    match resp {
        Response::Pong => pairs.push(("pong", Value::from(true))),
        Response::Ack => pairs.push(("ack", Value::from(true))),
        Response::Nodes(nodes) => {
            pairs.push(("nodes", Value::Array(nodes.iter().map(contact_to_value).collect())))
        }
        Response::Peers { peers, nodes } => {
            pairs.push((
                "peers",
                Value::Array(peers.iter().map(|p| Value::from(p.to_string())).collect()),
            ));
            pairs.push(("nodes", Value::Array(nodes.iter().map(contact_to_value).collect())));
        }
    }
    vmap(pairs)
}

/// The responder's node id from a response, if stamped (older nodes omit it).
pub fn decode_responder_id(body: &Value) -> Option<NodeId> {
    value_to_id(vget(body, "id")?)
}

/// Decode a response from the (already-unwrapped) response map, inferring the
/// variant from the fields present.
pub fn decode_response(body: &Value) -> Response {
    if vget(body, "pong").is_some() {
        return Response::Pong;
    }
    if vget(body, "ack").is_some() {
        return Response::Ack;
    }
    let nodes: Vec<Contact> = vget(body, "nodes")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(value_to_contact).collect())
        .unwrap_or_default();
    if let Some(peers_v) = vget(body, "peers") {
        let peers = peers_v
            .as_array()
            .map(|a| a.iter().filter_map(|p| p.as_str().and_then(|s| PeerAddr::parse(s).ok())).collect())
            .unwrap_or_default();
        return Response::Peers { peers, nodes };
    }
    Response::Nodes(nodes)
}
