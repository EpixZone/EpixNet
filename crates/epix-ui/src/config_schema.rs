//! The Config page's schema: which node settings exist, how each renders, and
//! which of them the node only reads at boot.
//!
//! Split out of `state.rs` because it is a declarative table, not logic: every
//! row is the same `(section, key, label, default, kind)` shape by
//! construction. That makes it noise for copy-paste detection - each new
//! config key "duplicates" the rows around it - so this file is listed under
//! `sonar.cpd.exclusions` in sonar-project.properties. Keeping the table in
//! its own file makes that exclusion surgical: `state.rs` itself stays fully
//! covered, including the real clones worth knowing about.
//!
//! Re-exported from `state`, so `state::CONFIG_SCHEMA` keeps working.

use crate::state::DEFAULT_VOLUNTEER_QUOTA;

/// Editable node config keys shown on the Config page:
/// `(section, key, label, default, kind)`, grouped into the same sections
/// EpixNet's Config page uses (Web Interface / Network / Performance / Epix
/// Chain Config). `kind` drives the input widget:
///   - `"text"` / `"textarea"` - free text
///   - `"bool"` - checkbox
///   - `"select:Label=value|Label2=value2"` - dropdown (label defaults to value
///     when there's no `=`)
///   - `"button:actionName"` - an action button (not a stored config key)
///   - `"soon:<inner>"` - render `<inner>` disabled with a "coming soon" note,
///     for keys whose backend (Tor transport, SOCKS proxy) isn't built yet.
pub const CONFIG_SCHEMA: &[(&str, &str, &str, &str, &str)] = &[
    // --- Web Interface
    ("Web Interface", "open_browser", "Open web browser on EpixNet startup", "true", "bool"),
    ("Web Interface", "language", "Interface language", "en", "text"),
    // --- Network
    ("Network", "offline", "Offline mode", "false", "bool"),
    (
        "Network",
        "fileserver_ip_type",
        "File server network",
        "ipv4",
        "select:IPv4=ipv4|IPv6=ipv6|Dual (IPv4 & IPv6)=dual",
    ),
    ("Network", "fileserver_port", "File server port (0 to disable seeding)", "26552", "text"),
    ("Network", "ip_external", "File server external ip (blank = auto-detect via UPnP)", "", "textarea"),
    (
        "Network",
        "tor",
        "Tor (Always private routes all peer traffic over Tor/I2P only; restart EpixNet to apply)",
        "enable",
        "select:Disable=disable|Enable=enable|Always private (Tor/I2P only)=always",
    ),
    // Active only in a bridges-enabled build (Snowflake linked); otherwise shown
    // disabled with a coming-soon note, as before.
    #[cfg(feature = "bridges")]
    ("Network", "tor_use_bridges", "Use Tor bridges (Snowflake; for censored networks; also auto-enables if Tor is blocked)", "false", "bool"),
    #[cfg(not(feature = "bridges"))]
    ("Network", "tor_use_bridges", "Use Tor bridges", "false", "soon:bool"),
    (
        "Network",
        "i2p",
        "I2P (reach and host peers over I2P; the embedded router boots in the background)",
        "disable",
        "select:Disable=disable|Embedded router=embedded|External router=external",
    ),
    (
        "Network",
        "i2p_sam_port",
        "I2P external router SAM port (only used with External)",
        "7656",
        "text",
    ),
    ("Network", "trackers", "Trackers", "145.223.69.23:26959", "textarea"),
    ("Network", "trackers_file", "Trackers files (one path per line)", "", "textarea"),
    (
        "Network",
        "trackers_xite",
        "Announcer list xite (optional: <address>/<inner path> of a published tracker list)",
        "",
        "text",
    ),
    (
        "Network",
        "trackers_proxy",
        "Proxy for tracker connections",
        "disable",
        "soon:select:Custom=custom|Tor=tor|Disable=disable",
    ),
    (
        "Network",
        "tracker",
        "Act as a tracker (answer other nodes' announces, incl. onion/i2p peers)",
        "enable",
        "select:Enable=enable|Disable=disable",
    ),
    // --- Offline & Mesh: the two transports that need no internet at all, kept
    // in their own section because they are the answer to one question ("can
    // this work with no connection?") and were previously lost among the Tor /
    // I2P / tracker keys. Both are compiled into every build and default to
    // off; the entries must stay CONTIGUOUS, since the Config page opens a new
    // block each time the section name changes (a split would render the
    // heading twice).
    (
        "Offline & Mesh",
        "local_discovery",
        "Find peers on the local network (UDP broadcast; needs no internet, tracker or DNS). Off by default: while on, this node answers anyone on the network with the list of xites it serves",
        "false",
        "bool",
    ),
    (
        "Offline & Mesh",
        "mesh",
        "Reticulum mesh (reach and host peers over mesh links)",
        "disable",
        "select:Disable=disable|Enable=enable",
    ),
    (
        "Offline & Mesh",
        "mesh_peers",
        "Mesh TCP interfaces to join (host:port, one per line) - only used when the mesh is enabled",
        "",
        "textarea",
    ),
    (
        "Offline & Mesh",
        "mesh_listen",
        "Mesh TCP listen address (blank = do not accept mesh links over IP)",
        "",
        "text",
    ),
    // --- Optional Files: node-wide DEFAULTS for newly downloaded xites. Each
    // xite's own sidebar toggles override these per xite afterwards; changing
    // a default never touches xites you already have.
    (
        "Optional Files",
        "download_optional_default",
        "Allow new xites to fetch optional files you open (images, video you play)",
        "true",
        "bool",
    ),
    (
        "Optional Files",
        "autodownloadoptional_default",
        "Pre-download EVERY optional file on new xites, including ones you never open (you already share whatever you have downloaded - this is not needed to seed)",
        "false",
        "bool",
    ),
    (
        "Optional Files",
        "full_retention",
        "Keep a full copy of every xite you visit (downloads everything, not just what you view)",
        "false",
        "bool",
    ),
    // --- Storage. `data_dir` is special: the value is the live data root and
    // the setting persists to `epixnet.conf` (see `AppState::set_data_dir`),
    // not config.json - config.json lives inside the directory it would name.
    (
        "Storage",
        "data_dir",
        "Data directory (existing data is copied there; restart EpixNet to apply)",
        "",
        "text",
    ),
    (
        "Storage",
        "volunteer_quota_bytes",
        "Donate disk to hold encrypted shards you cannot read (0 = off)",
        DEFAULT_VOLUNTEER_QUOTA,
        "text",
    ),
    // --- Performance
    (
        "Performance",
        "log_level",
        "Level of logging to file",
        "INFO",
        "select:Everything=DEBUG|Only important messages=INFO|Only errors=ERROR",
    ),
    // --- Epix Chain Config
    ("Epix Chain Config", "chain_rpc_url", "Chain RPC URL", "https://api.epix.zone", "text"),
    ("Epix Chain Config", "chain_evm_rpc_url", "Chain EVM RPC URL", "https://evmrpc.epix.zone", "text"),
    ("Epix Chain Config", "chain_block_explorer_url", "Block Explorer URL", "https://scan.epix.zone", "text"),
    ("Epix Chain Config", "xid_clear_cache", "Clear xID Cache", "", "button:xidClearCache"),
];

/// True for schema entries that aren't stored config keys (action buttons), so
/// `configList` / save loops can skip them.
pub fn is_config_action(kind: &str) -> bool {
    kind.starts_with("button:")
}

/// Config keys the node only reads while booting - changing one takes effect
/// on the next start. The Config page offers a restart when one of these has
/// changed since boot (`data_dir` is tracked separately off epixnet.conf).
pub const CONFIG_RESTART_KEYS: &[&str] = &[
    "offline",
    "fileserver_ip_type",
    "fileserver_port",
    "tor",
    "i2p",
    "i2p_sam_port",
    "local_discovery",
    "mesh",
    "mesh_peers",
    "mesh_listen",
    "trackers",
];
