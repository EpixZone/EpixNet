//! The inbound request handler mounted on the peer server. It composes the
//! three request-serving subsystems so a single listener answers all of them:
//!
//! - [`epix_ui::fileserve::FileService`] - file/seed/pex/hashfield/update wire
//!   commands (the bulk of the protocol).
//! - [`epix_dht_net::DhtService`] - the `kad` DHT RPC, so EpixNet peers can use
//!   this node as part of the private Kademlia lookup backbone.
//! - [`epix_propagation::PropagationService`] - `meshAnnounceUpdate` /
//!   `meshGetUpdates`, so this node acts as a store-and-forward propagation node
//!   for peers that were offline when a site updated.
//!
//! Before this, only `FileService` was mounted, so the DHT and propagation
//! crates were built and tested but never reachable from the running node.

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_protocol::RequestHandler;
use rmpv::Value;
use std::sync::Arc;

/// Routes an inbound request to the file, DHT, or propagation service by command.
pub struct NodeHandler {
    files: Arc<epix_ui::fileserve::FileService>,
    dht: Arc<epix_dht_net::DhtService>,
    propagation: Arc<epix_propagation::PropagationService>,
}

impl NodeHandler {
    pub fn new(
        files: Arc<epix_ui::fileserve::FileService>,
        dht: Arc<epix_dht_net::DhtService>,
        propagation: Arc<epix_propagation::PropagationService>,
    ) -> Self {
        Self { files, dht, propagation }
    }
}

#[async_trait]
impl RequestHandler for NodeHandler {
    async fn handle(&self, peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        match cmd {
            // DHT Kademlia RPC.
            c if c == epix_dht_net::wire::KAD_CMD => self.dht.handle(peer, cmd, params).await,
            // Store-and-forward propagation (offline-first sync).
            epix_propagation::CMD_ANNOUNCE | epix_propagation::CMD_GET => {
                self.propagation.handle(peer, cmd, params).await
            }
            // Everything else: file serving, seeding, pex, hashfields, update, …
            _ => self.files.handle(peer, cmd, params).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_ui::state::AppState;
    use rmpv::Value;

    fn vget<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
        match v {
            Value::Map(m) => m.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    #[tokio::test]
    async fn routes_each_command_to_its_service() {
        let state = AppState::new("test");
        let dht = std::sync::Arc::new(epix_dht::Node::new(epix_dht::NodeId::hash(b"test-node")));
        let store = std::sync::Arc::new(tokio::sync::Mutex::new(
            epix_propagation::PropagationStore::new(),
        ));
        let handler = NodeHandler::new(
            std::sync::Arc::new(epix_ui::fileserve::FileService::new(state)),
            std::sync::Arc::new(epix_dht_net::DhtService::new(dht)),
            std::sync::Arc::new(epix_propagation::PropagationService::new(store)),
        );
        let peer = PeerAddr::parse("1.2.3.4:1").unwrap();

        // ping -> file service (Pong!).
        let r = handler.handle(&peer, "ping", &Value::Map(vec![])).await;
        assert!(vget(&r, "body").is_some());

        // meshAnnounceUpdate -> propagation service (records + returns a seq).
        let params = Value::Map(vec![
            (Value::from("xite"), Value::from("1Site")),
            (Value::from("modified"), Value::from(123i64)),
        ]);
        let r = handler.handle(&peer, epix_propagation::CMD_ANNOUNCE, &params).await;
        assert_eq!(vget(&r, "ok"), Some(&Value::from(true)));
        assert!(vget(&r, "seq").is_some());

        // meshGetUpdates -> propagation service (returns the announced update).
        let params = Value::Map(vec![(Value::from("after"), Value::from(0i64))]);
        let r = handler.handle(&peer, epix_propagation::CMD_GET, &params).await;
        assert!(vget(&r, "updates").and_then(|v| v.as_array()).is_some_and(|a| !a.is_empty()));

        // kad -> dht service (a malformed kad request still routes there and
        // returns its error, not the file service's empty map).
        let r = handler.handle(&peer, epix_dht_net::wire::KAD_CMD, &Value::Map(vec![])).await;
        assert!(vget(&r, "error").is_some());
    }
}
