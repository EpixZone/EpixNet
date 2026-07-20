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

/// Built-in Tor-Browser Snowflake rendezvous defaults, tracking Tor Browser's
/// current set (Bug 41609: CDN77 domain-fronting - the earlier Fastly front
/// through `foursquare.com` stopped working, and the AMP-cache method was
/// dropped). These rotate, so [`SnowflakeOverrides`] lets a node replace any of
/// them from config without waiting for a new release.
const DEFAULT_BROKER_URL: &str = "https://1098762253.rsc.cdn77.org/";
const DEFAULT_FRONT_DOMAINS: &str = "app.datapacket.com,www.datapacket.com";
const DEFAULT_ICE_SERVERS: &str = "stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,\
stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,\
stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443";

/// Operator overrides for the Snowflake rendezvous parameters, read from node
/// config so a rotation of the public defaults can be applied without a rebuild.
/// A blank field falls back to the built-in default; `ampcache` defaults to off.
#[derive(Debug, Default, Clone)]
pub struct SnowflakeOverrides {
    pub broker_url: String,
    pub front_domains: String,
    pub ice_servers: String,
    pub ampcache: String,
}

/// Trimmed `over` if non-empty, else `default`.
fn or_default(over: &str, default: &str) -> String {
    let o = over.trim();
    if o.is_empty() { default.to_string() } else { o.to_string() }
}

/// Resolve the rendezvous config from the defaults plus any operator overrides.
/// `state_dir` is where the transport keeps its state, under the node data dir.
fn snowflake_params(data_dir: &Path, ov: &SnowflakeOverrides) -> iptproxy_sys::SnowflakeConfig {
    iptproxy_sys::SnowflakeConfig {
        state_dir: data_dir.join("snowflake").to_string_lossy().into_owned(),
        ice_servers: or_default(&ov.ice_servers, DEFAULT_ICE_SERVERS),
        broker_url: or_default(&ov.broker_url, DEFAULT_BROKER_URL),
        front_domains: or_default(&ov.front_domains, DEFAULT_FRONT_DOMAINS),
        // Off unless explicitly set: the public deployment dropped AMP cache and
        // it now answers 421, which only slows rendezvous down.
        ampcache: ov.ampcache.trim().to_string(),
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
pub async fn start_snowflake(data_dir: &Path, ov: &SnowflakeOverrides) -> Result<(Snowflake, u16)> {
    let params = snowflake_params(data_dir, ov);
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
