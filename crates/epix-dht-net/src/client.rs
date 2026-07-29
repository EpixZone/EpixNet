//! Client side: an [`RpcClient`] that dials peers on demand and sends DHT RPCs
//! over their `Connection`, pooling connections so a lookup reuses them.

use crate::pc;
use crate::wire::{decode_responder_id, decode_response, encode_request, KAD_CMD};
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{Contact, NodeId, Request, Response, RpcClient};
use epix_protocol::Connection;
use epix_transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Sends DHT RPCs over real peer connections. This is what makes the DHT
/// functional: as a lookup learns closer nodes it dials them here.
pub struct WireRpcClient {
    me: Contact,
    transport: Arc<dyn Transport>,
    pool: Mutex<HashMap<PeerAddr, Arc<Mutex<Connection>>>>,
}

impl WireRpcClient {
    pub fn new(me: Contact, transport: Arc<dyn Transport>) -> Self {
        Self { me, transport, pool: Mutex::new(HashMap::new()) }
    }

    async fn connection(&self, addr: &PeerAddr) -> Result<Arc<Mutex<Connection>>, String> {
        if let Some(conn) = self.pool.lock().await.get(addr) {
            return Ok(conn.clone());
        }
        // Dial outside the pool lock; another task may race us - double-check.
        let mut conn = Connection::connect(self.transport.as_ref(), addr)
            .await
            .map_err(|e| e.to_string())?;
        conn.handshake().await.map_err(|e| e.to_string())?;
        let arc = Arc::new(Mutex::new(conn));
        let mut pool = self.pool.lock().await;
        Ok(pool.entry(addr.clone()).or_insert(arc).clone())
    }

    async fn drop_connection(&self, addr: &PeerAddr) {
        self.pool.lock().await.remove(addr);
    }

    /// Bootstrap probe: send `FindNode(target)` to a peer we only know by
    /// address (no node id yet). Returns the responder's authentic contact
    /// (id from the stamped response + the address we dialed) and the contacts
    /// it shared - both safe to insert into a routing table.
    pub async fn probe(
        &self,
        addr: &PeerAddr,
        target: NodeId,
    ) -> Result<(Option<Contact>, Vec<Contact>), String> {
        let conn = self.connection(addr).await?;
        let params = encode_request(&self.me, &Request::FindNode(target));
        let result = {
            let mut guard = conn.lock().await;
            guard.request(KAD_CMD, params).await
        };
        match result {
            Ok(body) => {
                let responder = decode_responder_id(&body)
                    .map(|id| Contact::new(id, addr.clone()));
                let nodes = match decode_response(&body) {
                    Response::Nodes(nodes) => nodes,
                    Response::Peers { nodes, .. } => nodes,
                    _ => Vec::new(),
                };
                Ok((responder, nodes))
            }
            Err(e) => {
                self.drop_connection(addr).await;
                Err(e.to_string())
            }
        }
    }

    /// EDX path: the same two RPCs as [`Self::send`] and [`Self::probe`], but
    /// as raw postcard bytes. The caller ships them in a `Kad` message and
    /// feeds the reply back here, so this side does no I/O and needs no pool.
    pub fn edx_request(&self, req: &Request) -> Vec<u8> {
        pc::encode_request(&self.me, req)
    }

    /// Decode a `send` reply. The responder id is dropped: `send` already
    /// knows the contact it addressed.
    pub fn edx_response(payload: &[u8]) -> Result<Response, String> {
        pc::decode_response(payload)
            .map(|(_, resp)| resp)
            .ok_or_else(|| "malformed kad response".to_string())
    }

    /// Decode a probe reply: the responder's authentic contact (its stamped
    /// id plus the address we dialed) and the contacts it shared. Unlike the
    /// msgpack wire, the stamp is always there, so the contact is not optional.
    pub fn edx_probe_reply(
        addr: &PeerAddr,
        payload: &[u8],
    ) -> Result<(Contact, Vec<Contact>), String> {
        let (id, resp) =
            pc::decode_response(payload).ok_or_else(|| "malformed kad response".to_string())?;
        let nodes = match resp {
            Response::Nodes(nodes) => nodes,
            Response::Peers { nodes, .. } => nodes,
            _ => Vec::new(),
        };
        Ok((Contact::new(id, addr.clone()), nodes))
    }
}

#[async_trait]
impl RpcClient for WireRpcClient {
    async fn send(&self, to: &Contact, req: Request) -> Result<Response, String> {
        let conn = self.connection(&to.addr).await?;
        let params = encode_request(&self.me, &req);
        let result = {
            let mut guard = conn.lock().await;
            guard.request(KAD_CMD, params).await
        };
        match result {
            Ok(resp) => Ok(decode_response(&resp)),
            Err(e) => {
                // The connection may be dead - drop it so the next call redials.
                self.drop_connection(&to.addr).await;
                Err(e.to_string())
            }
        }
    }
}
