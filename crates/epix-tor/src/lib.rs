//! `epix-tor` - in-process Tor via Arti, on every platform (no sidecar).
//!
//! One [`Tor`] node owns a bootstrapped `arti-client` [`TorClient`] and
//! provides the three surfaces the plan calls for:
//!
//! - [`TorTransport`]: an [`epix_transport::Transport`] that dials `.onion`
//!   peers (and, for "route everything via Tor" mode, plain IP peers) through
//!   the Tor network. The wire protocol runs over it unchanged.
//! - [`Tor::launch_onion_service`]: hosts our fileserver as an onion service,
//!   yielding inbound peer streams to feed `epix_protocol::serve_stream` - so
//!   peers can reach us with zero direct-IP contact.
//! - [`Tor::serve_socks`]: a local SOCKS5 listener the browser shells point
//!   page traffic at, so xite/page fetches share the same Tor client.

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use async_trait::async_trait;
use epix_core::{Error, PeerAddr, Result};
use epix_transport::{PeerStream, Transport};
use futures::StreamExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::RunningOnionService;
use tor_proto::stream::IncomingStreamRequest;

/// How much of our traffic rides Tor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TorMode {
    /// Tor off: `.onion` peers are unreachable.
    Disable,
    /// Dial `.onion` peers via Tor, everything else direct. Host an onion
    /// service so Tor-only peers can reach us. The default.
    #[default]
    Enable,
    /// Route ALL peer traffic through Tor (EpixNet `--tor always`).
    Always,
}

impl TorMode {
    /// Parse the EpixNet config value (`disable` / `enable` / `always`).
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "disable" | "disabled" | "false" | "off" => TorMode::Disable,
            "always" => TorMode::Always,
            _ => TorMode::Enable,
        }
    }
}

/// A bootstrapped in-process Tor node (Arti). Cheap to clone.
#[derive(Clone)]
pub struct Tor {
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
}

/// Install the process-wide rustls crypto provider (`ring`) once. rustls 0.23
/// refuses to pick a default when more than one provider is compiled in (both
/// `ring` and `aws-lc-rs` end up in the tree via arti's deps), so arti's TLS
/// would panic on first use without this. Idempotent and safe to call from
/// every bootstrap; a lost race just means the other thread installed it.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl Tor {
    /// Bootstrap a Tor client, keeping its state + directory cache under
    /// `data_dir` (`<data>/tor/state`, `<data>/tor/cache`) so later starts
    /// are fast. Returns once the client is usable.
    pub async fn bootstrap(data_dir: &Path) -> Result<Self> {
        install_crypto_provider();
        let state = data_dir.join("tor").join("state");
        let cache = data_dir.join("tor").join("cache");
        let config = TorClientConfigBuilder::from_directories(state, cache)
            .build()
            .map_err(|e| Error::Protocol(format!("tor config: {e}")))?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| Error::Protocol(format!("tor bootstrap: {e}")))?;
        Ok(Self { client })
    }

    /// The peer transport over this Tor client. With `route_all`, plain IP
    /// peers are dialed through Tor too (`--tor always`); otherwise only
    /// `.onion` peers use it.
    pub fn transport(&self, route_all: bool) -> TorTransport {
        TorTransport { client: self.client.clone(), route_all }
    }

    /// Launch (or resume) the onion service `nickname`, accepting streams to
    /// `virt_port`. Returns the service handle, its `.onion` host (no suffix),
    /// and a receiver of accepted inbound peer streams, ready for
    /// `epix_protocol::serve_stream`. The key is generated on first launch and
    /// persisted in the Tor state dir, so the address is stable.
    pub fn launch_onion_service(
        &self,
        nickname: &str,
        virt_port: u16,
    ) -> Result<(Arc<RunningOnionService>, String, mpsc::Receiver<PeerStream>)> {
        let svc_config = OnionServiceConfigBuilder::default()
            .nickname(
                nickname
                    .parse()
                    .map_err(|e| Error::Protocol(format!("onion nickname: {e}")))?,
            )
            .build()
            .map_err(|e| Error::Protocol(format!("onion config: {e}")))?;
        let (service, rend_requests) = self
            .client
            .launch_onion_service(svc_config)
            .map_err(|e| Error::Protocol(format!("onion launch: {e}")))?
            .ok_or_else(|| {
                Error::Protocol("onion services unavailable in this Tor client".into())
            })?;
        let onion_host = service
            .onion_address()
            .map(|id| {
                // HsId displays as `<56 chars>.onion`; peers exchange the bare host.
                use safelog::DisplayRedacted;
                id.display_unredacted().to_string().trim_end_matches(".onion").to_string()
            })
            .ok_or_else(|| Error::Protocol("onion service has no address yet".into()))?;

        let (tx, rx) = mpsc::channel::<PeerStream>(16);
        tokio::spawn(async move {
            let mut stream_requests =
                Box::pin(tor_hsservice::handle_rend_requests(rend_requests));
            while let Some(request) = stream_requests.next().await {
                let ok_port = matches!(
                    request.request(),
                    IncomingStreamRequest::Begin(begin) if begin.port() == virt_port
                );
                if !ok_port {
                    let _ = request.shutdown_circuit();
                    continue;
                }
                match request.accept(Connected::new_empty()).await {
                    Ok(stream) => {
                        if tx.send(Box::pin(stream)).await.is_err() {
                            break; // receiver dropped: stop accepting
                        }
                    }
                    Err(e) => tracing::debug!("onion accept failed: {e}"),
                }
            }
        });
        Ok((service, onion_host, rx))
    }

    /// Serve SOCKS5 (no auth, CONNECT only) on `listener`, dialing every
    /// request through this Tor client. This is the listener the browser
    /// shells route page traffic to. Runs until the listener errors.
    pub async fn serve_socks(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (sock, _) = listener.accept().await?;
            let client = self.client.clone();
            tokio::spawn(async move {
                if let Err(e) = socks5_handle(client, sock).await {
                    tracing::debug!("socks connection ended: {e}");
                }
            });
        }
    }
}

/// One SOCKS5 CONNECT exchange, then a bidirectional copy over Tor.
async fn socks5_handle(
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    mut sock: TcpStream,
) -> std::io::Result<()> {
    use std::io::{Error as IoError, ErrorKind};
    let err = |m: &str| IoError::new(ErrorKind::InvalidData, m.to_string());

    // Greeting: VER NMETHODS METHODS…; we only offer NO AUTH (0x00).
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(err("not socks5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT - CONNECT only.
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        // Command not supported.
        sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(err("socks command not supported"));
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| err("bad domain"))?
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return Err(err("bad addr type")),
    };
    let mut port_b = [0u8; 2];
    sock.read_exact(&mut port_b).await?;
    let port = u16::from_be_bytes(port_b);

    match client.connect((host.as_str(), port)).await {
        Ok(mut tor_stream) => {
            // Success reply; BND fields are irrelevant to clients.
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut tor_stream).await;
            Ok(())
        }
        Err(e) => {
            sock.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            Err(IoError::other(format!("tor connect {host}:{port}: {e}")))
        }
    }
}

/// [`Transport`] impl that dials peers through Tor.
#[derive(Clone)]
pub struct TorTransport {
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    /// Dial plain IP peers via Tor too (`--tor always`).
    route_all: bool,
}

#[async_trait]
impl Transport for TorTransport {
    fn scheme(&self) -> &'static str {
        "tor"
    }

    async fn dial(&self, addr: &PeerAddr) -> Result<PeerStream> {
        let stream: DataStream = match addr {
            PeerAddr::Onion { host, port } => self
                .client
                .connect((format!("{host}.onion").as_str(), *port))
                .await
                .map_err(|e| Error::Protocol(format!("tor connect {host}.onion:{port}: {e}")))?,
            PeerAddr::Ip(sa) if self.route_all => self
                .client
                .connect((sa.ip().to_string().as_str(), sa.port()))
                .await
                .map_err(|e| Error::Protocol(format!("tor connect {sa}: {e}")))?,
            PeerAddr::Ip(_) => {
                return Err(Error::Protocol(
                    "TorTransport dials IP peers only in route-all mode".into(),
                ))
            }
            other => {
                return Err(Error::Protocol(format!(
                    "TorTransport cannot dial a `{}` peer",
                    other.scheme()
                )))
            }
        };
        Ok(Box::pin(stream))
    }
}

/// A transport that routes each dial by peer type: `.onion` via Tor (when
/// available), IP via TCP - or everything via Tor in [`TorMode::Always`].
/// This is the transport the node runs on once Tor is wired in.
pub struct MixedTransport {
    tcp: epix_transport::TcpTransport,
    tor: Option<TorTransport>,
    mode: TorMode,
}

impl MixedTransport {
    pub fn new(tor: Option<TorTransport>, mode: TorMode) -> Self {
        Self { tcp: epix_transport::TcpTransport, tor, mode }
    }
}

#[async_trait]
impl Transport for MixedTransport {
    fn scheme(&self) -> &'static str {
        "mixed"
    }

    async fn dial(&self, addr: &PeerAddr) -> Result<PeerStream> {
        match (addr, &self.tor, self.mode) {
            // Tor-routed: every onion dial, and every dial in Always mode.
            (PeerAddr::Onion { .. }, Some(tor), _) => tor.dial(addr).await,
            (_, Some(tor), TorMode::Always) => tor.dial(addr).await,
            (PeerAddr::Onion { .. }, None, _) => {
                Err(Error::Protocol("onion peer but Tor is disabled".into()))
            }
            _ => self.tcp.dial(addr).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn tor_mode_parses_epixnet_values() {
        assert_eq!(TorMode::parse("disable"), TorMode::Disable);
        assert_eq!(TorMode::parse("off"), TorMode::Disable);
        assert_eq!(TorMode::parse("enable"), TorMode::Enable);
        assert_eq!(TorMode::parse("Always"), TorMode::Always);
        assert_eq!(TorMode::parse(""), TorMode::Enable);
    }

    #[tokio::test]
    async fn mixed_without_tor_dials_ip_direct_and_rejects_onion() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 2];
            sock.read_exact(&mut b).await.unwrap();
            sock.write_all(&b).await.unwrap();
        });

        let mixed = MixedTransport::new(None, TorMode::Disable);
        // IP peers go over plain TCP.
        let mut s = mixed.dial(&PeerAddr::Ip(addr)).await.unwrap();
        s.write_all(b"hi").await.unwrap();
        let mut back = [0u8; 2];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hi");

        // Onion peers are unreachable without Tor.
        let onion = PeerAddr::Onion { host: "a".repeat(56), port: 26552 };
        match mixed.dial(&onion).await {
            Err(e) => assert!(format!("{e}").contains("Tor is disabled")),
            Ok(_) => panic!("onion dial should fail without Tor"),
        }
    }

    /// Live-network test: bootstraps a real Tor client, dials a well-known
    /// onion service, and speaks enough HTTP to prove the circuit works.
    /// `cargo test -p epix-tor -- --ignored` (needs network + a few minutes).
    #[tokio::test]
    #[ignore]
    async fn live_bootstrap_and_onion_dial() {
        let dir = tempfile::tempdir().unwrap();
        let tor = Tor::bootstrap(dir.path()).await.expect("bootstrap");
        // DuckDuckGo's v3 onion, port 80.
        let onion = PeerAddr::Onion {
            host: "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad".into(),
            port: 80,
        };
        let mut s = tor.transport(false).dial(&onion).await.expect("dial onion");
        let req = format!(
            "GET / HTTP/1.1\r\nHost: {}.onion\r\nConnection: close\r\n\r\n",
            match &onion {
                PeerAddr::Onion { host, .. } => host.clone(),
                _ => unreachable!(),
            }
        );
        s.write_all(req.as_bytes()).await.unwrap();
        // Read whatever the onion service sends first; any bytes prove the
        // circuit carried an application-level response end to end.
        let mut buf = vec![0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        assert!(n > 0, "onion service returned no bytes");
        assert!(
            buf[..n].starts_with(b"HTTP/1."),
            "got: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
    }

    /// Live-network test: launch an onion service and connect back to
    /// ourselves through Tor (round-trip through the rendezvous protocol).
    #[tokio::test]
    #[ignore]
    async fn live_onion_service_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tor = Tor::bootstrap(dir.path()).await.expect("bootstrap");
        let (_svc, host, mut inbound) =
            tor.launch_onion_service("epix-test", 26552).expect("launch");
        assert_eq!(host.len(), 56, "v3 onion host: {host}");

        // Echo server on the onion side.
        tokio::spawn(async move {
            while let Some(mut stream) = inbound.recv().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 4];
                    if stream.read_exact(&mut b).await.is_ok() {
                        let _ = stream.write_all(&b).await;
                    }
                });
            }
        });

        // Give the descriptor time to publish, then dial ourselves.
        let addr = PeerAddr::Onion { host, port: 26552 };
        let transport = tor.transport(false);
        let mut stream = None;
        for _ in 0..30 {
            match transport.dial(&addr).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(10)).await,
            }
        }
        let mut s = stream.expect("dial our own onion service");
        s.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
    }
}
