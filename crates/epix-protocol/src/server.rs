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

/// Called once per inbound connection when it answers the handshake, with the
/// peer's dial-back-corrected address. Only the clearnet TCP server wires this
/// (a real inbound peer proves our fileserver port is reachable); onion/I2P/
/// mesh inbound do not imply clearnet reachability, so they leave it unset.
pub type InboundHook = Arc<dyn Fn(&PeerAddr) + Send + Sync>;

/// A TCP peer server. (Tor/Reticulum listeners slot in the same way later.)
pub struct PeerServer {
    handler: Arc<dyn RequestHandler>,
    version: String,
    rev: i64,
    on_inbound: Option<InboundHook>,
}

impl PeerServer {
    pub fn new(handler: Arc<dyn RequestHandler>) -> Self {
        Self { handler, version: "EpixRS".into(), rev: 8192, on_inbound: None }
    }

    /// Register a hook fired when an inbound connection answers the handshake.
    pub fn on_inbound(mut self, hook: InboundHook) -> Self {
        self.on_inbound = Some(hook);
        self
    }

    /// The server's advertised version and revision, for driving
    /// [`serve_stream`] on transports other than TCP.
    pub fn banner(&self) -> (String, i64) {
        (self.version.clone(), self.rev)
    }

    /// Serve inbound TCP connections until the listener errors. The listener's
    /// own port is advertised as `fileserver_port` in handshake replies (a
    /// Python peer requires the field and adopts it as our dial-back port).
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        loop {
            let (sock, addr) = listener.accept().await?;
            let _ = sock.set_nodelay(true);
            let handler = self.handler.clone();
            let version = self.version.clone();
            let rev = self.rev;
            let on_inbound = self.on_inbound.clone();
            tokio::spawn(async move {
                let stream: epix_transport::PeerStream = Box::pin(sock);
                serve_stream_hooked(
                    handler,
                    PeerAddr::Ip(addr),
                    stream,
                    &version,
                    rev,
                    port,
                    on_inbound.as_ref(),
                )
                .await;
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
    peer: PeerAddr,
    stream: epix_transport::PeerStream,
    version: &str,
    rev: i64,
    fileserver_port: u16,
) {
    serve_stream_hooked(handler, peer, stream, version, rev, fileserver_port, None).await
}

/// [`serve_stream`] plus an optional inbound-handshake hook (clearnet TCP only).
async fn serve_stream_hooked(
    handler: Arc<dyn RequestHandler>,
    mut peer: PeerAddr,
    mut stream: epix_transport::PeerStream,
    version: &str,
    rev: i64,
    fileserver_port: u16,
    on_inbound: Option<&InboundHook>,
) {
    let mut buf = Vec::new();
    while let Ok(req) = read_msg(&mut stream, &mut buf).await {
        let cmd = vget(&req, "cmd").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let req_id = vget(&req, "req_id").and_then(|v| v.as_i64()).unwrap_or(0);
        let params = vget(&req, "params").cloned().unwrap_or(Value::Nil);

        let body = if cmd == "handshake" {
            answer_handshake(&mut peer, &params, on_inbound, version, rev, fileserver_port)
        } else {
            handler.handle(&peer, &cmd, &params).await
        };

        // `streamFile` uses EpixNet's raw-stream framing: the msgpack reply
        // carries `stream_bytes` (no `body`) and the file bytes follow raw on
        // the socket. Handlers answer it like `getFile`; the reframe happens
        // here so it holds for every handler and transport.
        let (body, raw_tail) =
            if cmd == "streamFile" { split_stream_body(body) } else { (body, None) };

        if send_msg(&mut stream, &response(req_id, body)).await.is_err() {
            break;
        }
        if let Some(bytes) = raw_tail {
            if !send_stream_tail(&mut stream, &bytes).await {
                break;
            }
        }
    }
}

/// Answer a handshake: adopt the peer's advertised dial-back port, fire the
/// inbound hook, and build the reply body.
fn answer_handshake(
    peer: &mut PeerAddr,
    params: &Value,
    on_inbound: Option<&InboundHook>,
    version: &str,
    rev: i64,
    fileserver_port: u16,
) -> Value {
    adopt_dialback_port(peer, params);
    // A completed inbound handshake means a real peer reached us on this
    // transport - the clearnet TCP server uses it to confirm the port is open.
    if let Some(hook) = on_inbound {
        hook(peer);
    }
    handshake_response(version, rev, fileserver_port)
}

/// The connection arrives from an ephemeral port; the handshake advertises the
/// peer's fileserver port, so rebind the address handlers see to one we can
/// dial back (inbound `update` fetches body-less updates from the sender and
/// adds it as a peer). Non-IP transports and port 0 keep the original address.
fn adopt_dialback_port(peer: &mut PeerAddr, params: &Value) {
    let advertised = vget(params, "fileserver_port").and_then(|v| v.as_i64());
    if let (PeerAddr::Ip(addr), Some(port)) = (&*peer, advertised) {
        if (1..=u16::MAX as i64).contains(&port) {
            let mut dialable = *addr;
            dialable.set_port(port as u16);
            *peer = PeerAddr::Ip(dialable);
        }
    }
}

/// Write the raw file bytes that follow a `streamFile` reply. Returns false if
/// the socket errored, so the caller drops the connection.
async fn send_stream_tail(stream: &mut epix_transport::PeerStream, bytes: &[u8]) -> bool {
    use tokio::io::AsyncWriteExt;
    if stream.write_all(bytes).await.is_err() || stream.flush().await.is_err() {
        return false;
    }
    crate::msg::WIRE_SENT.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
    true
}

/// Turn a `getFile`-shaped body (`{body, size, location}`) into the
/// `streamFile` reply shape: drop `body`, add `stream_bytes`, and hand the
/// raw bytes back to be written after the msgpack message. Error replies (no
/// `body`) pass through unchanged.
fn split_stream_body(body: Value) -> (Value, Option<Vec<u8>>) {
    let Value::Map(mut fields) = body else { return (body, None) };
    let mut raw: Option<Vec<u8>> = None;
    fields.retain(|(k, v)| {
        if k.as_str() == Some("body") {
            if let Value::Binary(b) = v {
                raw = Some(b.clone());
            }
            false
        } else {
            true
        }
    });
    if let Some(bytes) = &raw {
        fields.push((Value::from("stream_bytes"), Value::from(bytes.len() as i64)));
    }
    (Value::Map(fields), raw)
}

fn handshake_response(version: &str, rev: i64, fileserver_port: u16) -> Value {
    vmap(vec![
        ("version", Value::from(version)),
        ("rev", Value::from(rev)),
        ("protocol", Value::from("v2")),
        ("use_bin_type", Value::from(true)),
        ("peer_id", Value::from("")),
        ("crypt_supported", Value::Array(vec![])),
        ("crypt", Value::Nil),
        // A Python peer requires this field (KeyError without it) and adopts
        // it as our dial-back port; 0 means "not connectable back" there.
        ("fileserver_port", Value::from(fileserver_port)),
        ("port_opened", Value::from(fileserver_port != 0)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{read_msg, send_msg};
    use std::sync::Mutex;
    use tokio::net::{TcpListener, TcpStream};

    struct NoopHandler;
    #[async_trait]
    impl RequestHandler for NoopHandler {
        async fn handle(&self, _peer: &PeerAddr, _cmd: &str, _params: &Value) -> Value {
            vmap(vec![("error", Value::from("noop"))])
        }
    }

    /// The inbound hook fires on a handshake, and the address it reports has
    /// been dial-back-corrected to the peer's advertised fileserver port (so a
    /// caller can decide reachability by the peer's real IP, not its ephemeral
    /// source port). The hook runs before the handshake reply is sent, so once
    /// the client has read the reply the hook has already run.
    #[tokio::test]
    async fn inbound_hook_fires_with_dialback_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let seen: Arc<Mutex<Option<PeerAddr>>> = Arc::new(Mutex::new(None));
        let seen_cb = seen.clone();
        let hook: InboundHook = Arc::new(move |peer: &PeerAddr| {
            *seen_cb.lock().unwrap() = Some(peer.clone());
        });
        tokio::spawn(PeerServer::new(Arc::new(NoopHandler)).on_inbound(hook).serve(listener));

        // Raw client: connect and handshake, advertising fileserver_port 12345.
        let sock = TcpStream::connect(addr).await.unwrap();
        let mut stream: epix_transport::PeerStream = Box::pin(sock);
        let hs = vmap(vec![
            ("cmd", Value::from("handshake")),
            ("req_id", Value::from(1i64)),
            ("params", vmap(vec![("fileserver_port", Value::from(12345i64))])),
        ]);
        send_msg(&mut stream, &hs).await.unwrap();
        let mut buf = Vec::new();
        let _resp = read_msg(&mut stream, &mut buf).await.unwrap();

        let recorded = seen.lock().unwrap().clone().expect("peer recorded");
        match recorded {
            PeerAddr::Ip(a) => assert_eq!(a.port(), 12345, "adopted the advertised dial-back port"),
            other => panic!("expected Ip peer, got {other:?}"),
        }
    }

    /// The plain `serve_stream` entry point (used by the Tor/I2P inbound paths)
    /// carries no hook, so those transports can never flip clearnet status.
    #[tokio::test]
    async fn plain_serve_stream_has_no_hook() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A server with NO on_inbound set: a handshake must still succeed.
        tokio::spawn(PeerServer::new(Arc::new(NoopHandler)).serve(listener));

        let sock = TcpStream::connect(addr).await.unwrap();
        let mut stream: epix_transport::PeerStream = Box::pin(sock);
        let hs = vmap(vec![
            ("cmd", Value::from("handshake")),
            ("req_id", Value::from(1i64)),
            ("params", vmap(vec![("fileserver_port", Value::from(0i64))])),
        ]);
        send_msg(&mut stream, &hs).await.unwrap();
        let mut buf = Vec::new();
        let resp = read_msg(&mut stream, &mut buf).await.unwrap();
        assert_eq!(vget(&resp, "cmd").and_then(|v| v.as_str()), Some("response"));
    }
}
