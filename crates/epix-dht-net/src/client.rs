//! Client side: an [`RpcClient`] that ships DHT RPCs to peers as EDX `Kad`
//! payloads.
//!
//! This crate owns the payload codec ([`crate::pc`]) but not the link: the
//! caller injects a [`KadSender`], so `epix-dht-net` needs no transport or
//! runtime dependency (the same seam the tracker announce uses).

use crate::pc;
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{Contact, NodeId, Request, Response, RpcClient};
use std::sync::Arc;

/// Carries one Kad payload to a peer and returns its reply payload. Every
/// failure - unreachable peer, dead link, timeout, peer-side error - is `Err`;
/// the lookup just moves on to the next contact.
#[async_trait]
pub trait KadSender: Send + Sync {
    async fn send(&self, to: &PeerAddr, payload: Vec<u8>) -> Result<Vec<u8>, String>;
}

/// Sends DHT RPCs over real peer links. This is what makes the DHT
/// functional: as a lookup learns closer nodes it reaches them here.
pub struct WireRpcClient {
    me: Contact,
    sender: Arc<dyn KadSender>,
}

impl WireRpcClient {
    pub fn new(me: Contact, sender: Arc<dyn KadSender>) -> Self {
        Self { me, sender }
    }

    /// Bootstrap probe: send `FindNode(target)` to a peer we only know by
    /// address (no node id yet). Returns the responder's authentic contact
    /// (id from the stamped response + the address we reached) and the contacts
    /// it shared - both safe to insert into a routing table.
    pub async fn probe(
        &self,
        addr: &PeerAddr,
        target: NodeId,
    ) -> Result<(Contact, Vec<Contact>), String> {
        let payload = self.encode(&Request::FindNode(target));
        let reply = self.sender.send(addr, payload).await?;
        Self::probe_reply(addr, &reply)
    }

    /// Encode one RPC as the `Kad` payload (the caller's contact rides along,
    /// so the receiver learns us).
    fn encode(&self, req: &Request) -> Vec<u8> {
        pc::encode_request(&self.me, req)
    }

    /// Decode a `send` reply. The responder id is dropped: `send` already
    /// knows the contact it addressed.
    fn response(payload: &[u8]) -> Result<Response, String> {
        pc::decode_response(payload)
            .map(|(_, resp)| resp)
            .ok_or_else(|| "malformed kad response".to_string())
    }

    /// Decode a probe reply: the responder's authentic contact (its stamped
    /// id plus the address we reached) and the contacts it shared. The stamp
    /// is always present, so the contact is not optional.
    fn probe_reply(addr: &PeerAddr, payload: &[u8]) -> Result<(Contact, Vec<Contact>), String> {
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
        let payload = self.encode(&req);
        let reply = self.sender.send(&to.addr, payload).await?;
        Self::response(&reply)
    }
}
