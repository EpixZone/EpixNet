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
use std::path::{Path, PathBuf};
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
/// dropped). These rotate, so a node can replace any of them from
/// `<data_dir>/private/snowflake.json` (see [`load_overrides`]) without a new
/// release.
const DEFAULT_BROKER_URL: &str = "https://1098762253.rsc.cdn77.org/";
const DEFAULT_FRONT_DOMAINS: &str = "app.datapacket.com,www.datapacket.com";
const DEFAULT_ICE_SERVERS: &str = "stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,\
stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,\
stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443";

/// The user-editable overrides file. Lives next to `config.json` so all
/// hand-edited node settings sit in one place.
fn overrides_path(data_dir: &Path) -> PathBuf {
    data_dir.join("private").join("snowflake.json")
}

/// Contents of a fresh `snowflake.json`: every field blank (so the built-in
/// defaults apply) with a note on what to do. Blank-by-default means a later
/// build's refreshed defaults still take effect - only fields a user fills in
/// are pinned.
const OVERRIDES_TEMPLATE: &str = r#"{
  "_comment": "Override EpixNet's built-in Snowflake rendezvous parameters when they go stale. Any field left blank uses the built-in default. After editing, toggle 'Use Tor bridges' off then on (or restart). A current set is published at Tor Browser's projects/common/bridges_list.snowflake.txt.",
  "broker_url": "",
  "front_domains": "",
  "ice_servers": "",
  "ampcache": "",
  "bridge": ""
}
"#;

/// Load `snowflake.json`, seeding the blank template the first time so users
/// have something to edit. Missing file, unreadable, or malformed JSON all fall
/// back to `Null` (built-in defaults apply) rather than failing the bridge.
fn load_overrides(data_dir: &Path) -> serde_json::Value {
    let path = overrides_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
        Err(_) => {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(&path, OVERRIDES_TEMPLATE);
            serde_json::Value::Null
        }
    }
}

/// A trimmed string field from the overrides object, or "" if absent/not a string.
fn field(f: &serde_json::Value, key: &str) -> String {
    f.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Trimmed `over` if non-empty, else `default`.
fn or_default(over: &str, default: &str) -> String {
    if over.is_empty() { default.to_string() } else { over.to_string() }
}

/// The bridge line to hand arti: the overrides file's `bridge`, else the
/// built-in default fingerprint.
pub fn bridge_line(data_dir: &Path) -> String {
    or_default(&field(&load_overrides(data_dir), "bridge"), SNOWFLAKE_BRIDGE_LINE)
}

/// Resolve the rendezvous config from the built-in defaults plus any overrides
/// in `snowflake.json`. `state_dir` is where the transport keeps its state.
fn snowflake_params(data_dir: &Path) -> iptproxy_sys::SnowflakeConfig {
    let f = load_overrides(data_dir);
    iptproxy_sys::SnowflakeConfig {
        state_dir: data_dir.join("snowflake").to_string_lossy().into_owned(),
        ice_servers: or_default(&field(&f, "ice_servers"), DEFAULT_ICE_SERVERS),
        broker_url: or_default(&field(&f, "broker_url"), DEFAULT_BROKER_URL),
        front_domains: or_default(&field(&f, "front_domains"), DEFAULT_FRONT_DOMAINS),
        // Off unless explicitly set: the public deployment dropped AMP cache and
        // it now answers 421, which only slows rendezvous down.
        ampcache: field(&f, "ampcache"),
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
    let params = snowflake_params(data_dir);
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
