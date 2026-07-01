//! Client side: an [`RpcClient`] that dials peers on demand and sends DHT RPCs
//! over their `Connection`, pooling connections so a lookup reuses them.

use crate::wire::{decode_response, encode_request, KAD_CMD};
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{Contact, Request, Response, RpcClient};
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
        // Dial outside the pool lock; another task may race us — double-check.
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
                // The connection may be dead — drop it so the next call redials.
                self.drop_connection(&to.addr).await;
                Err(e.to_string())
            }
        }
    }
}
