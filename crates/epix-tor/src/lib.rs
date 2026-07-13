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

/// The onion service's ed25519 identity key, for proving onion ownership to
/// trackers (Bootstrapper's `onion_sign_this` challenge). Loaded from the
/// Arti keystore where [`Tor::launch_onion_service`] persists it.
pub struct OnionKey {
    /// Tor's expanded secret key: 32-byte scalar `a` + 32-byte hash prefix.
    expanded: [u8; 64],
    /// The identity public key - the same 32 bytes the `.onion` address encodes.
    public: [u8; 32],
}

impl OnionKey {
    /// Load the identity key of the onion service `nickname` from the Arti
    /// keystore under `data_dir` (same layout [`Tor::bootstrap`] uses). The
    /// key file is an OpenSSH envelope holding a 64-byte
    /// `ed25519-expanded@spec.torproject.org` private key.
    pub fn load(data_dir: &Path, nickname: &str) -> Result<Self> {
        let path = data_dir
            .join("tor")
            .join("state")
            .join("keystore")
            .join("hss")
            .join(nickname)
            .join("ks_hs_id.ed25519_expanded_private");
        let pem = std::fs::read_to_string(&path)
            .map_err(|e| Error::Protocol(format!("onion key {}: {e}", path.display())))?;
        let b64: String =
            pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("");
        let blob = base64_decode(&b64)
            .ok_or_else(|| Error::Protocol("onion key: bad base64".into()))?;
        parse_openssh_ed25519_expanded(&blob)
            .ok_or_else(|| Error::Protocol("onion key: unexpected OpenSSH structure".into()))
    }

    /// The 32-byte identity public key (what the `.onion` address encodes).
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Standard Ed25519 signature over `msg`, verifiable against
    /// [`Self::public_key`]. Expanded-key path (Tor keys have no seed):
    /// `r = H(prefix || msg)`, `S = r + H(R || A || msg) * a`.
    ///
    /// Built directly on curve25519 - `ed25519_dalek`'s hazmat
    /// `ExpandedSecretKey` re-clamps the scalar half, but Arti stores hs
    /// identity keys as uniform reduced scalars (low bits set, bit 254
    /// clear), so clamping silently swaps in a different key and every
    /// signature fails verification.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        use curve25519_dalek::{EdwardsPoint, Scalar};
        use sha2::{Digest, Sha512};
        let scalar_bytes: [u8; 32] = self.expanded[..32].try_into().expect("split");
        let a = Scalar::from_bytes_mod_order(scalar_bytes);
        let prefix = &self.expanded[32..];
        let r = Scalar::from_hash(Sha512::new().chain_update(prefix).chain_update(msg));
        let big_r = EdwardsPoint::mul_base(&r).compress();
        let k = Scalar::from_hash(
            Sha512::new()
                .chain_update(big_r.as_bytes())
                .chain_update(self.public)
                .chain_update(msg),
        );
        let s = k * a + r;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(big_r.as_bytes());
        sig[32..].copy_from_slice(&s.to_bytes());
        sig
    }
}

/// Minimal base64 (standard alphabet) decoder - avoids a dependency for one
/// keystore file read.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = ALPHA.iter().position(|&a| a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Pull the 64-byte expanded private key + 32-byte public key out of Arti's
/// `openssh-key-v1` envelope (algorithm `ed25519-expanded@spec.torproject.org`).
fn parse_openssh_ed25519_expanded(blob: &[u8]) -> Option<OnionKey> {
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let rest = blob.strip_prefix(MAGIC)?;
    let mut off = 0;
    let rd = |off: &mut usize| -> Option<&[u8]> {
        let n = u32::from_be_bytes(rest.get(*off..*off + 4)?.try_into().ok()?) as usize;
        let s = rest.get(*off + 4..*off + 4 + n)?;
        *off += 4 + n;
        Some(s)
    };
    let cipher = rd(&mut off)?;
    if cipher != b"none" {
        return None; // encrypted keystores are not supported
    }
    rd(&mut off)?; // kdf name
    rd(&mut off)?; // kdf options
    off += 4; // number of keys (always 1)
    rd(&mut off)?; // public key blob
    let private = rd(&mut off)?;
    // Private section: two check ints, then per-key algorithm/public/private.
    let mut poff = 8;
    let prd = |poff: &mut usize| -> Option<&[u8]> {
        let n = u32::from_be_bytes(private.get(*poff..*poff + 4)?.try_into().ok()?) as usize;
        let s = private.get(*poff + 4..*poff + 4 + n)?;
        *poff += 4 + n;
        Some(s)
    };
    let alg = prd(&mut poff)?;
    if alg != b"ed25519-expanded@spec.torproject.org" {
        return None;
    }
    let public: [u8; 32] = prd(&mut poff)?.try_into().ok()?;
    let expanded: [u8; 64] = prd(&mut poff)?.try_into().ok()?;
    Some(OnionKey { expanded, public })
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

/// Recover from a poisoned persisted guard sample.
///
/// Arti persists its guard sample in `<state>/state/guards.json` and marks
/// guards disabled after too many "indeterminate" circuit failures - which a
/// laptop accumulates by sleeping mid-circuit. Once EVERY guard in the sample
/// is disabled, no circuit can ever be built again: each start "bootstraps"
/// from the directory cache, then rejects the whole sample (`AllGuardsDown`,
/// 0 accepted) and every dial fails, while nothing ever resamples. The node
/// looks healthy (bootstrapped, onion service registered) but is mute.
///
/// Detect exactly that state - a non-empty sample with all guards disabled -
/// and delete the file so bootstrap draws a fresh sample. It holds only
/// resumable network state; onion-service keys live elsewhere (`hss/`,
/// `keystore/`), so the node's onion address is unaffected. Any parse
/// surprise (format change, missing fields) leaves the file alone.
fn clear_poisoned_guard_state(state_dir: &Path) {
    let path = state_dir.join("state").join("guards.json");
    let Ok(bytes) = std::fs::read(&path) else { return };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return };
    let Some(guards) = v.get("default").and_then(|s| s.get("guards")).and_then(|g| g.as_array())
    else {
        return;
    };
    if guards.is_empty() {
        return;
    }
    let all_disabled =
        guards.iter().all(|g| g.get("disabled").is_some_and(|d| !d.is_null()));
    if all_disabled && std::fs::remove_file(&path).is_ok() {
        tracing::warn!(
            "tor: cleared poisoned guard state ({} sampled guards, all disabled); \
             a fresh sample will be drawn",
            guards.len()
        );
    }
}

impl Tor {
    /// Bootstrap a Tor client, keeping its state + directory cache under
    /// `data_dir` (`<data>/tor/state`, `<data>/tor/cache`) so later starts
    /// are fast. Returns once the client is usable.
    pub async fn bootstrap(data_dir: &Path) -> Result<Self> {
        install_crypto_provider();
        let state = data_dir.join("tor").join("state");
        let cache = data_dir.join("tor").join("cache");
        clear_poisoned_guard_state(&state);
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

    /// Build an `openssh-key-v1` envelope holding an expanded ed25519 key the
    /// way Arti's keystore writes them, load it through [`OnionKey::load`],
    /// and check the produced signature verifies against the identity pubkey
    /// with a stock Ed25519 verifier (what Bootstrapper trackers run).
    ///
    /// The scalar is a uniform reduced scalar that is deliberately NOT in
    /// clamped form - exactly how Arti stores hs identity keys. A signer
    /// that clamps (e.g. `ed25519_dalek`'s hazmat `ExpandedSecretKey`) would
    /// change the key and fail this test.
    #[test]
    fn onion_key_loads_and_signs_tracker_challenge() {
        use curve25519_dalek::{EdwardsPoint, Scalar};
        use ed25519_dalek::Verifier;

        // A deterministic "expanded" key with an Arti-style unclamped scalar.
        let scalar = Scalar::from_bytes_mod_order([7u8; 32]);
        let scalar_bytes = scalar.to_bytes();
        assert_ne!(scalar_bytes[0] & 7, 0, "test scalar must not look clamped");
        let mut expanded = [0u8; 64];
        expanded[..32].copy_from_slice(&scalar_bytes);
        expanded[32..].copy_from_slice(&[9u8; 32]); // hash prefix
        let public = EdwardsPoint::mul_base(&scalar).compress().to_bytes();

        let str32 = |b: &[u8]| {
            let mut v = (b.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(b);
            v
        };
        let alg = b"ed25519-expanded@spec.torproject.org";
        // Private section: check ints, alg, public, private, no comment.
        let mut private = vec![0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44];
        private.extend(str32(alg));
        private.extend(str32(&public));
        private.extend(str32(&expanded));
        private.extend(str32(b""));
        while private.len() % 8 != 0 {
            private.push(0);
        }
        let mut blob = b"openssh-key-v1\0".to_vec();
        blob.extend(str32(b"none")); // cipher
        blob.extend(str32(b"none")); // kdf
        blob.extend(str32(b"")); // kdf options
        blob.extend(1u32.to_be_bytes()); // key count
        let mut pub_blob = str32(alg);
        pub_blob.extend(str32(&public));
        blob.extend(str32(&pub_blob));
        blob.extend(str32(&private));

        // Base64-wrap into the PEM-style file Arti writes.
        const ALPHA: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in blob.chunks(3) {
            let mut buf = [0u8; 3];
            buf[..chunk.len()].copy_from_slice(chunk);
            let n = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
            for i in 0..=chunk.len() {
                b64.push(ALPHA[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
            for _ in chunk.len()..3 {
                b64.push('=');
            }
        }
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{b64}\n-----END OPENSSH PRIVATE KEY-----\n"
        );

        let dir = tempfile::tempdir().unwrap();
        let key_dir = dir.path().join("tor/state/keystore/hss/epix");
        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::write(key_dir.join("ks_hs_id.ed25519_expanded_private"), pem).unwrap();

        let key = OnionKey::load(dir.path(), "epix").expect("load onion key");
        assert_eq!(key.public_key(), public);

        let msg = b"1783961332"; // tracker challenges are epoch-second strings
        let sig = key.sign(msg);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("signature verifies against the identity pubkey");
    }

    /// Write a guards.json into `<state>/state/` shaped like arti's, with the
    /// given per-guard `disabled` values (JSON `null` = healthy).
    fn write_guards(state_dir: &Path, disabled: &[serde_json::Value]) -> std::path::PathBuf {
        let dir = state_dir.join("state");
        std::fs::create_dir_all(&dir).unwrap();
        let guards: Vec<serde_json::Value> = disabled
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": {"ed25519": "x", "rsa": "y"},
                    "orports": ["192.0.2.1:443"],
                    "disabled": d,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "default": {"guards": guards, "confirmed": []},
            "restricted": {"guards": [], "confirmed": []},
        });
        let path = dir.join("guards.json");
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        path
    }

    #[test]
    fn poisoned_guard_state_is_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let poisoned = serde_json::json!({"type": "TooManyIndeterminateFailures"});
        let path = write_guards(dir.path(), &[poisoned.clone(), poisoned]);
        clear_poisoned_guard_state(dir.path());
        assert!(!path.exists(), "an all-disabled sample must be removed");
    }

    #[test]
    fn healthy_and_mixed_guard_state_is_kept() {
        // All healthy.
        let dir = tempfile::tempdir().unwrap();
        let path = write_guards(dir.path(), &[serde_json::Value::Null, serde_json::Value::Null]);
        clear_poisoned_guard_state(dir.path());
        assert!(path.exists(), "a healthy sample stays");

        // One usable guard left: arti can still build circuits - keep it.
        let dir = tempfile::tempdir().unwrap();
        let poisoned = serde_json::json!({"type": "TooManyIndeterminateFailures"});
        let path = write_guards(dir.path(), &[poisoned, serde_json::Value::Null]);
        clear_poisoned_guard_state(dir.path());
        assert!(path.exists(), "a partly-usable sample stays");
    }

    #[test]
    fn missing_empty_or_malformed_guard_state_is_left_alone() {
        // Missing file: no panic.
        let dir = tempfile::tempdir().unwrap();
        clear_poisoned_guard_state(dir.path());

        // Empty sample: nothing to judge.
        let dir = tempfile::tempdir().unwrap();
        let path = write_guards(dir.path(), &[]);
        clear_poisoned_guard_state(dir.path());
        assert!(path.exists());

        // Unparseable / unexpected format: leave it for arti.
        let dir = tempfile::tempdir().unwrap();
        let sd = dir.path().join("state");
        std::fs::create_dir_all(&sd).unwrap();
        let path = sd.join("guards.json");
        std::fs::write(&path, b"not json").unwrap();
        clear_poisoned_guard_state(dir.path());
        assert!(path.exists());
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
