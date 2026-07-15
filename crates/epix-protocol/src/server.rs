//! Inbound peer server: accept connections, answer the handshake, and dispatch
//! requests to a [`RequestHandler`]. This is the serving counterpart to
//! [`crate::Connection`] - the same framing, the other direction. Handlers plug
//! in `getFile`, DHT RPCs, etc.

use crate::msg::{read_msg, send_msg, vget, vmap};
use async_trait::async_trait;
use epix_core::PeerAddr;
use rmpv::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// How long an inbound connection may sit before its first request. The
/// fileserver address gets announced to public BitTorrent trackers, so random
/// BT clients and scanners connect and never speak our protocol - without this
/// bound each one holds a socket (and an fd) forever.
const FIRST_MSG_TIMEOUT: Duration = Duration::from_secs(60);

/// Idle bound between requests after the first. EpixNet closes idle peer
/// connections after ~2 minutes; 5 keeps slow overlay peers safe while still
/// reclaiming dead sockets. A healthy peer just reconnects when it needs us.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum concurrent inbound connections. A guard against fd exhaustion: on
/// the public gateway, leaked BT-crawler connections once ate the process fd
/// limit, which killed the accept loop AND all outbound dials.
const MAX_INBOUND: usize = 400;

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

    /// Serve inbound TCP connections until shutdown. The listener's own port
    /// is advertised as `fileserver_port` in handshake replies (a Python peer
    /// requires the field and adopts it as our dial-back port).
    ///
    /// Accept errors (EMFILE under fd pressure, ECONNABORTED, …) are transient:
    /// retry after a short pause instead of returning, or one error would kill
    /// the accept loop and leave the node running but permanently deaf.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let inbound = Arc::new(tokio::sync::Semaphore::new(MAX_INBOUND));
        loop {
            let (sock, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            };
            // At capacity: shed the new connection instead of leaking toward
            // the process fd limit (which would also break outbound dials).
            let Ok(permit) = inbound.clone().try_acquire_owned() else {
                drop(sock);
                continue;
            };
            let _ = sock.set_nodelay(true);
            let handler = self.handler.clone();
            let version = self.version.clone();
            let rev = self.rev;
            let on_inbound = self.on_inbound.clone();
            tokio::spawn(async move {
                let _permit = permit;
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
    let mut deadline = FIRST_MSG_TIMEOUT;
    while let Ok(Ok(req)) = tokio::time::timeout(deadline, read_msg(&mut stream, &mut buf)).await {
        deadline = IDLE_TIMEOUT;
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

/// Answer a handshake: adopt the peer's advertised dial-back address, fire the
/// inbound hook, and build the reply body.
fn answer_handshake(
    peer: &mut PeerAddr,
    params: &Value,
    on_inbound: Option<&InboundHook>,
    version: &str,
    rev: i64,
    fileserver_port: u16,
) -> Value {
    // The hook sees the SOURCE address, not the adopted one: a completed
    // inbound handshake means a real peer reached us on this transport (the
    // clearnet TCP server uses it to confirm the port is open), and that is a
    // property of where the connection came from - an advertised onion must
    // not hide that a public IP just proved our port reachable.
    let source = peer.clone();
    adopt_dialback_addr(peer, params);
    if let Some(hook) = on_inbound {
        hook(&source);
    }
    handshake_response(version, rev, fileserver_port)
}

/// The connection arrives from an ephemeral port (clearnet) or a blank
/// placeholder address (onion/i2p inbound, rns link id), so rebind the address
/// handlers see to the dial-back address the handshake advertises - inbound
/// `update`/`setHashfield`/`pex` record it per site, which is how an
/// overlay-only publisher that pushes to us becomes a peer we can dial back.
///
/// The advertised self-address must match the connection's transport class:
/// an onion claim rebinds onion (and Tor-exit-sourced Ip) connections, an i2p
/// claim i2p connections, an rns claim mesh links. The claim is trusted the
/// way PEX gossip is (unauthenticated), but only when it is complete and
/// wire-packable - `pack()` base32/length-validates onion and i2p hosts, so
/// junk that could never round-trip peer exchange is never adopted.
fn adopt_dialback_addr(peer: &mut PeerAddr, params: &Value) {
    let port = advertised_port(params);
    match &*peer {
        PeerAddr::Ip(addr) => *peer = adopt_ip(*addr, params, port),
        // An overlay placeholder is replaced by its advertised self-address of
        // the matching class, or left as-is (the well-formedness filter drops
        // an un-rebound placeholder before it can enter a peer table).
        PeerAddr::Onion { .. } => {
            if let Some(p) = onion_claim(params, port) {
                *peer = p;
            }
        }
        PeerAddr::I2p { .. } => {
            if let Some(p) = i2p_claim(params, port) {
                *peer = p;
            }
        }
        PeerAddr::Rns(_) => {
            if let Some(p) = rns_claim(params) {
                *peer = p;
            }
        }
    }
}

/// Rebind an inbound clearnet peer. An advertised onion wins over the source IP
/// (a Tor-Always dialer reaches clearnet through an exit node, so its source IP
/// is the exit's, not a dialable identity - the Python client rebinds the same
/// way). Otherwise honor `port_opened` like the Python client: a public peer
/// that says its port is closed (behind NAT) is recorded non-connectable (port
/// 0) so we never dial it or gossip it as reachable - it can still reach us. A
/// LAN/loopback source is directly reachable, so it keeps the advertised port.
fn adopt_ip(addr: std::net::SocketAddr, params: &Value, port: Option<u16>) -> PeerAddr {
    if let Some(p) = onion_claim(params, port) {
        return p;
    }
    let Some(port) = port else { return PeerAddr::Ip(addr) };
    let port_opened = vget(params, "port_opened").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut dialable = addr;
    let keep = port_opened || PeerAddr::Ip(dialable).is_private();
    dialable.set_port(if keep { port } else { 0 });
    PeerAddr::Ip(dialable)
}

/// The peer's advertised fileserver port (1..=65535), or None.
fn advertised_port(params: &Value) -> Option<u16> {
    vget(params, "fileserver_port")
        .and_then(|v| v.as_i64())
        .filter(|p| (1..=u16::MAX as i64).contains(p))
        .map(|p| p as u16)
}

/// A non-empty string self-address claim from the handshake.
fn overlay_claim(params: &Value, key: &str) -> Option<String> {
    vget(params, key).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string)
}

/// Parse an advertised self-address, keeping it only when complete and
/// wire-packable - `pack()` base32/length-validates onion and i2p hosts, so
/// junk that could never round-trip peer exchange is never adopted.
fn parse_dialback(s: String) -> Option<PeerAddr> {
    PeerAddr::parse(&s).ok().filter(|p| p.is_wellformed() && p.pack().is_some())
}

fn onion_claim(params: &Value, port: Option<u16>) -> Option<PeerAddr> {
    let host = overlay_claim(params, "onion")?;
    parse_dialback(format!("{host}.onion:{}", port?))
}

fn i2p_claim(params: &Value, port: Option<u16>) -> Option<PeerAddr> {
    // I2P streams are destination-addressed; the port rides along for
    // wire-shape compatibility (0 when the peer isn't seeding).
    let dest = overlay_claim(params, "i2p")?;
    parse_dialback(format!("{dest}.i2p:{}", port.unwrap_or(0)))
}

fn rns_claim(params: &Value) -> Option<PeerAddr> {
    // The inbound address is the LINK id, not the peer's dialable destination
    // hash - the claim replaces it outright.
    let hex = overlay_claim(params, "rns")?;
    parse_dialback(format!("rns:{hex}"))
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
    // Report the node's real release version to peers that dial us (so they
    // can stat our build), falling back to the server's default banner when
    // the advert is unseeded (tests, wire-spike).
    let advertised = crate::advert::self_advert().version;
    let version = if advertised.is_empty() { version } else { &advertised };
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

    /// The inbound hook fires on a handshake with the connection's SOURCE
    /// address - a real public IP reaching us proves the port is open, and an
    /// advertised onion must not hide that. The hook runs before the handshake
    /// reply is sent, so once the client has read the reply it has run.
    #[tokio::test]
    async fn inbound_hook_sees_the_source_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let seen: Arc<Mutex<Option<PeerAddr>>> = Arc::new(Mutex::new(None));
        let seen_cb = seen.clone();
        let hook: InboundHook = Arc::new(move |peer: &PeerAddr| {
            *seen_cb.lock().unwrap() = Some(peer.clone());
        });
        tokio::spawn(PeerServer::new(Arc::new(NoopHandler)).on_inbound(hook).serve(listener));

        // Raw client: handshake advertising a dial-back port AND an onion (a
        // Tor-Always dialer's shape). The adopted address becomes the onion,
        // but the hook must still see the Ip source that proved reachability.
        let sock = TcpStream::connect(addr).await.unwrap();
        let mut stream: epix_transport::PeerStream = Box::pin(sock);
        let hs = vmap(vec![
            ("cmd", Value::from("handshake")),
            ("req_id", Value::from(1i64)),
            (
                "params",
                vmap(vec![
                    ("fileserver_port", Value::from(12345i64)),
                    ("onion", Value::from("abcdefghij234567")),
                ]),
            ),
        ]);
        send_msg(&mut stream, &hs).await.unwrap();
        let mut buf = Vec::new();
        let _resp = read_msg(&mut stream, &mut buf).await.unwrap();

        let recorded = seen.lock().unwrap().clone().expect("peer recorded");
        match recorded {
            PeerAddr::Ip(a) => {
                assert!(a.ip().is_loopback(), "hook sees the source IP, got {a}")
            }
            other => panic!("expected the Ip source, got {other:?}"),
        }
    }

    /// After the handshake adopts an advertised self-address, every subsequent
    /// request's handler sees the dialable address instead of the placeholder -
    /// the seam that lets `update`/`pex` record an overlay caller as a peer.
    #[tokio::test]
    async fn requests_after_handshake_carry_the_adopted_address() {
        struct Recording(Arc<Mutex<Option<PeerAddr>>>);
        #[async_trait]
        impl RequestHandler for Recording {
            async fn handle(&self, peer: &PeerAddr, _cmd: &str, _params: &Value) -> Value {
                *self.0.lock().unwrap() = Some(peer.clone());
                vmap(vec![("ok", Value::from("1"))])
            }
        }
        let seen: Arc<Mutex<Option<PeerAddr>>> = Arc::new(Mutex::new(None));
        let (server_side, client_side) = tokio::io::duplex(4096);
        // An inbound onion connection: blank placeholder, like the Tor accept
        // loop passes.
        tokio::spawn(serve_stream(
            Arc::new(Recording(seen.clone())),
            PeerAddr::Onion { host: String::new(), port: 0 },
            Box::pin(server_side),
            "EpixRS",
            1,
            0,
        ));

        let mut stream: epix_transport::PeerStream = Box::pin(client_side);
        let mut buf = Vec::new();
        let hs = vmap(vec![
            ("cmd", Value::from("handshake")),
            ("req_id", Value::from(1i64)),
            (
                "params",
                vmap(vec![
                    ("fileserver_port", Value::from(26552i64)),
                    ("onion", Value::from("abcdefghij234567")),
                ]),
            ),
        ]);
        send_msg(&mut stream, &hs).await.unwrap();
        let _ = read_msg(&mut stream, &mut buf).await.unwrap();
        let ping = vmap(vec![
            ("cmd", Value::from("ping")),
            ("req_id", Value::from(2i64)),
            ("params", vmap(vec![])),
        ]);
        send_msg(&mut stream, &ping).await.unwrap();
        let _ = read_msg(&mut stream, &mut buf).await.unwrap();

        let recorded = seen.lock().unwrap().clone().expect("handler saw the request");
        assert_eq!(
            recorded,
            PeerAddr::parse("abcdefghij234567.onion:26552").unwrap(),
            "the placeholder was rebound to the advertised self-address"
        );
    }

    #[test]
    fn adopt_dialback_addr_rebinds_each_transport_class() {
        let params = |pairs: Vec<(&str, Value)>| vmap(pairs);

        // Clearnet + port + port_opened: rebind to the advertised port.
        let mut peer = PeerAddr::parse("1.2.3.4:55555").unwrap();
        adopt_dialback_addr(
            &mut peer,
            &params(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("port_opened", Value::from(true)),
            ]),
        );
        assert_eq!(peer, PeerAddr::parse("1.2.3.4:26552").unwrap());

        // Clearnet + port but port_opened false (NAT'd): recorded
        // non-connectable (port 0) so it is never dialed or re-gossiped.
        let mut peer = PeerAddr::parse("1.2.3.4:55555").unwrap();
        adopt_dialback_addr(&mut peer, &params(vec![("fileserver_port", Value::from(26552i64))]));
        assert_eq!(peer, PeerAddr::parse("1.2.3.4:0").unwrap());

        // A LAN/loopback source keeps the advertised port regardless of
        // port_opened - it is directly reachable.
        let mut peer = PeerAddr::parse("192.168.1.5:55555").unwrap();
        adopt_dialback_addr(&mut peer, &params(vec![("fileserver_port", Value::from(26552i64))]));
        assert_eq!(peer, PeerAddr::parse("192.168.1.5:26552").unwrap());

        // Clearnet + onion claim: the onion wins (Tor-exit-sourced dialer).
        let mut peer = PeerAddr::parse("1.2.3.4:55555").unwrap();
        adopt_dialback_addr(
            &mut peer,
            &params(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("onion", Value::from("abcdefghij234567")),
            ]),
        );
        assert_eq!(peer, PeerAddr::parse("abcdefghij234567.onion:26552").unwrap());

        // Onion placeholder + onion claim.
        let mut peer = PeerAddr::Onion { host: String::new(), port: 0 };
        adopt_dialback_addr(
            &mut peer,
            &params(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("onion", Value::from("abcdefghij234567")),
            ]),
        );
        assert_eq!(peer, PeerAddr::parse("abcdefghij234567.onion:26552").unwrap());

        // I2p placeholder + i2p claim (a 52-char b32 short address).
        let mut peer = PeerAddr::I2p { dest: String::new(), port: 0 };
        let b32 = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq";
        adopt_dialback_addr(
            &mut peer,
            &params(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("i2p", Value::from(b32)),
            ]),
        );
        assert_eq!(peer, PeerAddr::parse(&format!("{b32}.i2p:26552")).unwrap());

        // Rns link id + rns claim: the claim replaces the link id.
        let mut peer = PeerAddr::Rns([9u8; 16]);
        adopt_dialback_addr(
            &mut peer,
            &params(vec![("rns", Value::from("0123456789abcdef0123456789abcdef"))]),
        );
        assert_eq!(peer, PeerAddr::parse("rns:0123456789abcdef0123456789abcdef").unwrap());
    }

    #[test]
    fn adopt_dialback_addr_rejects_junk_claims() {
        let placeholder = PeerAddr::Onion { host: String::new(), port: 0 };

        // No fileserver_port: an onion without a port is not dialable.
        let mut peer = placeholder.clone();
        adopt_dialback_addr(&mut peer, &vmap(vec![("onion", Value::from("abcdefghij234567"))]));
        assert_eq!(peer, placeholder);

        // Invalid base32 host: never adopted (couldn't round-trip PEX).
        let mut peer = placeholder.clone();
        adopt_dialback_addr(
            &mut peer,
            &vmap(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("onion", Value::from("not/base32!!")),
            ]),
        );
        assert_eq!(peer, placeholder);

        // Empty claim: ignored.
        let mut peer = placeholder.clone();
        adopt_dialback_addr(
            &mut peer,
            &vmap(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("onion", Value::from("")),
            ]),
        );
        assert_eq!(peer, placeholder);

        // A cross-class claim never rebinds: an i2p claim on an onion
        // connection is ignored.
        let mut peer = placeholder.clone();
        adopt_dialback_addr(
            &mut peer,
            &vmap(vec![
                ("fileserver_port", Value::from(26552i64)),
                ("i2p", Value::from("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq")),
            ]),
        );
        assert_eq!(peer, placeholder);

        // Bad rns hex keeps the link id.
        let mut peer = PeerAddr::Rns([9u8; 16]);
        adopt_dialback_addr(&mut peer, &vmap(vec![("rns", Value::from("nothex"))]));
        assert_eq!(peer, PeerAddr::Rns([9u8; 16]));
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

    /// A client that connects and never speaks the protocol (BT crawlers,
    /// port scanners) must be dropped after FIRST_MSG_TIMEOUT instead of
    /// holding a socket forever - the leak that exhausted the gateway's fd
    /// limit and killed its accept loop.
    #[tokio::test(start_paused = true)]
    async fn silent_inbound_connection_is_dropped() {
        let (server_side, _client_side) = tokio::io::duplex(1024);
        let served = serve_stream(
            Arc::new(NoopHandler),
            PeerAddr::parse("127.0.0.1:1234").unwrap(),
            Box::pin(server_side),
            "EpixRS",
            1,
            0,
        );
        // The client never sends a byte. Paused time auto-advances past
        // FIRST_MSG_TIMEOUT; the serve loop must give up rather than wait on
        // read_msg forever. The outer bound only trips if it doesn't.
        tokio::time::timeout(FIRST_MSG_TIMEOUT * 3, served)
            .await
            .expect("server should have dropped the silent connection");
    }
}
