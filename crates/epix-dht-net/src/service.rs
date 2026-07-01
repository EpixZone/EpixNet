//! Server side: answer inbound DHT RPCs against a local [`Node`].

use crate::wire::{decode_request, encode_response, KAD_CMD};
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::Node;
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

#[async_trait]
impl RequestHandler for DhtService {
    async fn handle(&self, _peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        if cmd != KAD_CMD {
            return vmap(vec![("error", Value::from("unknown command"))]);
        }
        match decode_request(params) {
            Some((from, req)) => encode_response(&self.node.handle(from, req)),
            None => vmap(vec![("error", Value::from("malformed kad request"))]),
        }
    }
}
