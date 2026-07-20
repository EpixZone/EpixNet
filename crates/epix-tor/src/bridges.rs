//! In-process Snowflake pluggable transport for censored networks.
//!
//! On a network that blocks direct Tor (EpixNet#239), arti cannot reach any
//! guard. Snowflake gets through by rendezvousing with ephemeral volunteer
//! WebRTC proxies. We run it *in-process* via [`iptproxy_sys`] (no subprocess,
//! so it works on iOS), which exposes a local SOCKS port; arti then dials its
//! bridge through that port as an **unmanaged** pluggable transport.
//!
//! Compiled only under the `bridges` feature.

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, TorClientConfigBuilder};
use epix_core::{Error, Result};
use std::path::Path;
use std::time::Duration;

/// The arti bridge line for the Snowflake bridge. Snowflake ignores the address
/// (rendezvous is via the broker), so only the transport name + fingerprint
/// matter; the rendezvous parameters live in [`SnowflakeParams`], which drive
/// IPtProxy. Fingerprint is the public Snowflake bridge's (plan R2: it and the
/// rendezvous params rotate; keep them updatable / config-overridable).
pub const SNOWFLAKE_BRIDGE_LINE: &str =
    "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72";

/// Current Tor-Browser Snowflake rendezvous defaults (plan R2: verify + allow
/// config override at ship time; these rotate). `state_dir` is where the
/// transport keeps its state, under the node data dir.
fn default_snowflake_params(data_dir: &Path) -> iptproxy_sys::SnowflakeConfig {
    iptproxy_sys::SnowflakeConfig {
        state_dir: data_dir.join("snowflake").to_string_lossy().into_owned(),
        ice_servers: "stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,\
stun:stun.bluesip.net:3478,stun:stun.voip.blackberry.com:3478"
            .to_string(),
        broker_url: "https://snowflake-broker.torproject.net.global.prod.fastly.net/".to_string(),
        front_domains: "foursquare.com,github.githubassets.com".to_string(),
        ampcache: "https://cdn.ampproject.org/".to_string(),
    }
}

/// A running in-process Snowflake. Dropping it stops the transport.
pub struct Snowflake {
    _private: (),
}

impl Drop for Snowflake {
    fn drop(&mut self) {
        iptproxy_sys::stop_snowflake();
    }
}

/// Start Snowflake in-process and wait for its local SOCKS port. Returns the
/// running guard (hold it for as long as Tor should route through Snowflake)
/// and the port arti should dial. Errors if IPtProxy is unavailable in this
/// build (the stub) or never opens a port.
pub async fn start_snowflake(data_dir: &Path) -> Result<(Snowflake, u16)> {
    let params = default_snowflake_params(data_dir);
    iptproxy_sys::start_snowflake(&params)
        .map_err(|e| Error::Protocol(format!("snowflake start: {e}")))?;
    let guard = Snowflake { _private: () };
    // The port binds asynchronously, like the embedded I2P router's SAM port.
    for _ in 0..100 {
        let port = iptproxy_sys::snowflake_port();
        if port != 0 {
            return Ok((guard, port));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Dropping `guard` here stops the half-started transport.
    Err(Error::Protocol("snowflake did not open a SOCKS port within 10s".into()))
}

/// Add the Snowflake bridge and an unmanaged transport pointing at IPtProxy's
/// local SOCKS `port` to `builder`, so arti builds its guard channel through
/// Snowflake instead of dialing relays directly.
pub fn apply_bridge(
    builder: &mut TorClientConfigBuilder,
    bridge_line: &str,
    port: u16,
) -> Result<()> {
    let bridge: BridgeConfigBuilder =
        bridge_line.parse().map_err(|e| Error::Protocol(format!("bridge line: {e}")))?;
    builder.bridges().bridges().push(bridge);

    let mut transport = TransportConfigBuilder::default();
    transport
        .protocols(vec![
            "snowflake".parse().map_err(|e| Error::Protocol(format!("pt name: {e}")))?
        ])
        // Unmanaged: only `proxy_addr`, never `path`, so arti connects to the
        // already-running IPtProxy SOCKS listener and spawns nothing.
        .proxy_addr(
            format!("127.0.0.1:{port}")
                .parse()
                .map_err(|e| Error::Protocol(format!("pt proxy addr: {e}")))?,
        );
    builder.bridges().transports().push(transport);
    Ok(())
}
