//! Inbound peer server: accept connections, answer the handshake, and dispatch
//! requests to a [`RequestHandler`]. This is the serving counterpart to
//! [`crate::Connection`] - the same framing, the other direction. Handlers plug
//! in `getFile`, DHT RPCs, etc.

use crate::msg::{read_msg, send_msg, vget, vmap};
use async_trait::async_trait;
use epix_core::PeerAddr;
use rmpv::Value;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Handles an inbound request and returns the response **body** (a msgpack map);
/// the server wraps it as `{cmd:"response", to:req_id, …body}`.
#[async_trait]
pub trait RequestHandler: Send + Sync {
    async fn handle(&self, peer: &PeerAddr, cmd: &str, params: &Value) -> Value;
}

/// A TCP peer server. (Tor/Reticulum listeners slot in the same way later.)
pub struct PeerServer {
    handler: Arc<dyn RequestHandler>,
    version: String,
    rev: i64,
}

impl PeerServer {
    pub fn new(handler: Arc<dyn RequestHandler>) -> Self {
        Self { handler, version: "EpixRS".into(), rev: 8192 }
    }

    /// The server's advertised version and revision, for driving
    /// [`serve_stream`] on transports other than TCP.
    pub fn banner(&self) -> (String, i64) {
        (self.version.clone(), self.rev)
    }

    /// Serve inbound TCP connections until the listener errors.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (sock, addr) = listener.accept().await?;
            let _ = sock.set_nodelay(true);
            let handler = self.handler.clone();
            let version = self.version.clone();
            let rev = self.rev;
            tokio::spawn(async move {
                let stream: epix_transport::PeerStream = Box::pin(sock);
                serve_stream(handler, PeerAddr::Ip(addr), stream, &version, rev).await;
            });
        }
    }
}

/// Run the request/response loop over one already-established peer stream,
/// whatever transport it came from (TCP, Reticulum mesh, …). Reads framed
/// requests, answers the handshake itself, dispatches the rest to `handler`,
/// and returns when the peer disconnects.
pub async fn serve_stream(
    handler: Arc<dyn RequestHandler>,
    mut peer: PeerAddr,
    mut stream: epix_transport::PeerStream,
    version: &str,
    rev: i64,
) {
    let mut buf = Vec::new();
    while let Ok(req) = read_msg(&mut stream, &mut buf).await {
        let cmd = vget(&req, "cmd").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let req_id = vget(&req, "req_id").and_then(|v| v.as_i64()).unwrap_or(0);
        let params = vget(&req, "params").cloned().unwrap_or(Value::Nil);

        let body = if cmd == "handshake" {
            // The connection arrives from an ephemeral port; the handshake
            // advertises the peer's fileserver port, so rebind the address
            // handlers see to one we can dial back (inbound `update` fetches
            // body-less updates from the sender, and adds it as a peer).
            let advertised = vget(&params, "fileserver_port").and_then(|v| v.as_i64());
            if let (PeerAddr::Ip(addr), Some(port)) = (&peer, advertised) {
                if port > 0 && port <= u16::MAX as i64 {
                    let mut dialable = *addr;
                    dialable.set_port(port as u16);
                    peer = PeerAddr::Ip(dialable);
                }
            }
            handshake_response(version, rev)
        } else {
            handler.handle(&peer, &cmd, &params).await
        };

        if send_msg(&mut stream, &response(req_id, body)).await.is_err() {
            break;
        }
    }
}

fn handshake_response(version: &str, rev: i64) -> Value {
    vmap(vec![
        ("version", Value::from(version)),
        ("rev", Value::from(rev)),
        ("protocol", Value::from("v2")),
        ("use_bin_type", Value::from(true)),
        ("peer_id", Value::from("")),
        ("crypt_supported", Value::Array(vec![])),
    ])
}

/// Wrap a handler's body map as a wire response: `{cmd:"response", to, …body}`.
fn response(req_id: i64, body: Value) -> Value {
    let mut pairs = vec![
        (Value::from("cmd"), Value::from("response")),
        (Value::from("to"), Value::from(req_id)),
    ];
    if let Value::Map(fields) = body {
        pairs.extend(fields);
    }
    Value::Map(pairs)
}
