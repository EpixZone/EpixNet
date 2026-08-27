//! `epix-node` - the embeddable node: resolve a `.epix` name, clone + verify
//! the xite, and serve the UI + peer network. One code path for the server
//! binary, the FFI layer (mobile), and the desktop shell.
//!
//! The caller supplies platform paths and policy through [`NodeOptions`]; the
//! node owns everything else (peer discovery, cloning, the UI server, the
//! background runtime loops, and - when enabled - in-process Tor).

use epix_core::{Address, PeerAddr};
use epix_transport::{TcpTransport, Transport};
use epix_ui::{UiServer, XiteEntry};
use epix_xite::{Xite, XiteStorage};
use std::path::PathBuf;
use std::sync::Arc;

/// Re-export so embedders (FFI, shells) can name the served state without a
/// direct `epix-ui` dependency.
pub use epix_ui::{
    new_nmh_nonce, nmh_request_mac, nmh_request_mac_valid, nmh_response_mac,
    nmh_response_mac_valid, AppState, NMH_RESOLVE_PATH,
};

/// The default Epix bootstrap announcers (re-exported from epix-core; the
/// Beacon plugin seeds its book from the same list).
pub use epix_core::DEFAULT_TRACKERS;

/// The default announcer list, parsed. Epix `host:port` entries and
/// BitTorrent tracker URLs; unparseable entries are impossible (epix-core
/// tests them).
pub fn default_trackers() -> Vec<epix_xite::Tracker> {
    DEFAULT_TRACKERS.iter().filter_map(|t| epix_xite::Tracker::parse(t)).collect()
}

#[derive(Debug, Default)]
struct OfflineTransport;

#[async_trait::async_trait]
impl Transport for OfflineTransport {
    fn scheme(&self) -> &'static str {
        "offline"
    }

    async fn dial(&self, _addr: &PeerAddr) -> epix_core::Result<epix_transport::PeerStream> {
        Err(epix_core::Error::Protocol(
            "network access is disabled by offline mode".to_string(),
        ))
    }
}

fn transport_for_network_policy(offline: bool, online: Arc<dyn Transport>) -> Arc<dyn Transport> {
    if offline {
        Arc::new(OfflineTransport)
    } else {
        online
    }
}
/// Wall-clock trace of a clone's phase boundaries, on when `EPIX_TRACE_CLONE`
/// is set. A clone is a chain of discovery, dial, fetch, verify and ingest
/// steps, and only a per-phase timeline shows which one is actually costing
/// the seconds - reading the code cannot tell you.
pub(crate) fn trace_clone(t0: std::time::Instant, what: std::fmt::Arguments<'_>) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ON.get_or_init(|| std::env::var_os("EPIX_TRACE_CLONE").is_some()) {
        eprintln!("[clonetrace] {:>7.2}s {what}", t0.elapsed().as_secs_f64());
    }
}

/// [`trace_clone`] with `format!` arguments.
macro_rules! trace_clone {
    ($t0:expr, $($arg:tt)*) => { crate::trace_clone($t0, format_args!($($arg)*)) };
}

/// Epix's default UI port.
pub const DEFAULT_UI_PORT: u16 = 42222;
/// Legacy EpixNet UI port, used as a fallback when the default is taken (so a
/// fresh Epix and an old EpixNet can coexist, and old 43110 links still resolve).
pub const LEGACY_UI_PORT: u16 = 43110;
/// The default UI bind (loopback, Epix's port).
pub const DEFAULT_UI_ADDR: &str = "127.0.0.1:42222";
/// Temporary, explicit compatibility switch for the eight-day chain-upgrade
/// window before the real mainnet finality pin can be captured. Official
/// releases must never set this variable.
const ALLOW_INSECURE_XID_LEGACY_ENV: &str = "EPIX_XID_ALLOW_INSECURE_LEGACY";
/// File shared with the native-messaging process. It lives under the private
/// data directory and contains a new random secret for each node run.
pub const NMH_TOKEN_RELATIVE_PATH: &str = "private/nmh-auth-token";

/// How the embedded node should boot and serve.
#[derive(Default)]
pub struct NodeOptions {
    /// The shared data root, laid out like Python EpixNet: node files
    /// (users.json, sites.json) under `<root>/private/`, each xite under
    /// `<root>/data/<address>/`. Tor keeps its state under `<root>/tor`.
    pub data_root: PathBuf,
    /// A raw `epix1…` xite address or a `.epix` name (or bare label) to open.
    pub target: String,
    /// The UI HTTP/WebSocket bind, e.g. `127.0.0.1:43110`.
    pub ui_addr: String,
    /// Tor routing mode: `disable` / `enable` / `always`. Empty means "no
    /// explicit choice": boot uses the Config page's persisted `tor` value,
    /// defaulting to `enable`.
    pub tor_mode: String,
    /// Open the served xite in the OS browser once serving (desktop only;
    /// shells that own their own webview pass `false`).
    pub open_browser: bool,
    /// Optional gzipped GeoIP City db for the dashboard world map; expanded to
    /// `<root>/geoip-city.mmdb` in the background. `None` disables the map.
    pub geoip_gz: Option<Vec<u8>>,
    /// Optional file the node appends its log to (rotated by the caller).
    pub log_file: Option<PathBuf>,
    /// Node version string reported in `serverInfo`.
    pub version: String,
    /// Short git commit of this build, reported in `serverInfo.rev`.
    pub rev: String,
}

impl NodeOptions {
    /// Minimal options: a target and a data root, everything else defaulted.
    pub fn new(data_root: impl Into<PathBuf>, target: impl Into<String>) -> Self {
        Self {
            data_root: data_root.into(),
            target: target.into(),
            ui_addr: DEFAULT_UI_ADDR.to_string(),
            tor_mode: String::new(),
            open_browser: false,
            geoip_gz: None,
            log_file: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            rev: "0".to_string(),
        }
    }
}

/// A booted, serving node. The UI server future is returned so the caller
/// decides whether to await it (block) or drive it on its own task.
pub struct RunningNode {
    pub state: Arc<AppState>,
    /// The `.epix` display name (or raw address) the node serves under.
    pub display: String,
    /// The served xite address.
    pub address: String,
    /// The UI bind that succeeded.
    pub ui_addr: std::net::SocketAddr,
}

/// Strip a leading `scheme://` from a launch argument. Not just `epix://`:
/// a cold start can receive a full browser URL (`https://talk.epix/?x`) from
/// the command line, an OS protocol handoff, or a shortcut, and treating the
/// scheme as the host made the boot resolver look up `https:.epix` and panic.
/// Only a syntactically valid RFC 3986 scheme is stripped, so a bare name or
/// address (no `://`) passes through untouched.
fn strip_scheme(arg: &str) -> &str {
    match arg.split_once("://") {
        Some((scheme, rest))
            if scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) =>
        {
            rest
        }
        _ => arg,
    }
}

/// Normalize a launch argument into a resolver target: strip the scheme
/// (`epix://`, `https://`, ...) and any path/query so `epix://talk.epix/topic/1`
/// becomes `talk.epix` (the host is the xite; the path is opened inside the
/// wrapper afterwards). A raw address or bare name passes through unchanged.
pub fn parse_target(arg: &str) -> String {
    let s = strip_scheme(arg);
    // Host is everything up to the first `/`, `?`, or `#`.
    let host_end = s.find(['/', '?', '#']).unwrap_or(s.len());
    let host = &s[..host_end];
    if host.is_empty() {
        arg.to_string()
    } else {
        host.to_string()
    }
}

/// The in-wrapper path from an `epix://host/path?query` link (everything after
/// the host), or `""` if none. The shell navigates the wrapper here after the
/// xite loads.
pub fn parse_inner_path(arg: &str) -> String {
    let s = strip_scheme(arg);
    match s.find(['/', '?', '#']) {
        Some(i) => s[i..].to_string(),
        None => String::new(),
    }
}

/// Resolve `target` into `(xite_address, display_name, from_cache)`: pass an
/// `epix1…` address through; resolve a `.epix` name (or bare label, defaulting
/// to the `epix` TLD) from the on-disk cache, hitting the chain only when the
/// name has no cache entry or the entry expired ([`RESOLVE_CACHE_TTL_SECS`]).
/// If an expired entry can't be re-resolved (chain unreachable), the stale
/// mapping keeps serving rather than failing the boot.
async fn resolve_target(
    data_root: &std::path::Path,
    target: &str,
) -> Result<(String, String, bool), String> {
    let (name, tld) = target.rsplit_once('.').unwrap_or((target, "epix"));
    match epix_core::classify_label(name) {
        epix_core::LabelClass::Address => {
            return Ok((name.to_string(), name.to_string(), false));
        }
        epix_core::LabelClass::AddressShaped => {
            return Err(address_shaped_target_error(name, tld));
        }
        epix_core::LabelClass::Name => {}
    }
    let full = format!("{name}.{tld}");
    match validated_cached_resolution(data_root, &full) {
        Some((address, true)) => return Ok((address, full, true)),
        Some((stale, false)) => {
            // Expired: refresh from the chain; keep the stale mapping if that fails.
            return Ok(match try_resolve_on_chain_bound(name, tld).await {
                Ok((address, binding)) => {
                    write_resolve_cache_bound(data_root, &full, &address, binding.as_ref());
                    (address, full, false)
                }
                Err(_) => (stale, full, true),
            });
        }
        None => {}
    }
    let (address, binding) = try_resolve_on_chain_bound(name, tld).await?;
    write_resolve_cache_bound(data_root, &full, &address, binding.as_ref());
    Ok((address, full, false))
}

fn address_shaped_target_error(name: &str, tld: &str) -> String {
    format!(
        "{name}.{tld} looks like a mistyped epix1 address (bad checksum); refusing to resolve it as a name"
    )
}

fn validated_xite_address(address: &str, source: &str) -> Result<Address, String> {
    Address::parse(address.to_string()).map_err(|_| {
        format!("{source} contains invalid EpixNet xite address `{address}`; refusing to use it")
    })
}

fn validated_cached_resolution(data_root: &std::path::Path, full: &str) -> Option<(String, bool)> {
    let (address, fresh) = cached_resolution(data_root, full)?;
    let address = Address::parse(address).ok()?;
    Some((address.to_string(), fresh))
}

async fn try_resolve_on_chain_bound(
    name: &str,
    tld: &str,
) -> Result<(String, Option<(u64, String)>), String> {
    // Typo-space guard: an exact checksum-valid address is the dotted alias
    // and resolves to itself, never via xID (a registered same-string name is
    // inert). An address-SHAPED label with a bad checksum is a mistyped or
    // forged address and is refused outright - otherwise an attacker could
    // register the typo-space around a real address as names and phish.
        match epix_core::classify_label(name) {
        epix_core::LabelClass::Address => return Ok((name.to_string(), None)),
            epix_core::LabelClass::AddressShaped => {
            return Err(address_shaped_target_error(name, tld));
            }
            epix_core::LabelClass::Name => {}
        }
    let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let (domain, binding) = resolver
        .resolve_fresh_bound(name, tld)
        .await
        .map_err(|e| format!("could not resolve {name}.{tld}: {e}"))?;
    let address = domain
        .xite_address()
        .ok_or_else(|| format!("{name}.{tld} has no EpixNet xite address record"))?;
    let address = validated_xite_address(address, &format!("{name}.{tld} xID record"))?;
    Ok((address.to_string(), binding))
}

/// What [`serve`] should bring up as the node's launch xite (its homepage).
enum LaunchTarget {
    /// Resolved to a xite address (from cache or the chain): register it and
    /// serve whatever is already on disk.
    Resolved {
        address: String,
        display: String,
        data_dir: PathBuf,
        content: Option<serde_json::Value>,
    },
    /// Deferred: in Tor-Always mode the launch name had no cache entry, and
    /// resolving it on the chain before Tor is up would leak it over clearnet.
    /// Only the homepage name is set; the on-demand resolver clones it on first
    /// open, once Tor has bootstrapped.
    Deferred { display: String },
}

/// The default `tracing` filter when neither `EPIX_LOG` nor `RUST_LOG` is set.
/// Global `warn` (so a failing Tor bootstrap's WARN/ERROR from arti is always
/// captured) plus `info` on the transports and arti's bootstrap machinery, so
/// the ordinary "bootstrapping … bootstrapped" story is visible without the
/// per-circuit/per-cell debug flood.
const DEFAULT_LOG_FILTER: &str = "warn,epix_tor=info,epix_runtime=info,epix_node=info,\
arti_client=info,tor_dirmgr=info,tor_guardmgr=info,tor_chanmgr=info,tor_circmgr=info,\
tor_bootstrap=info";

/// Install a process-wide `tracing` subscriber the first time the node boots.
///
/// Without a subscriber every `tracing::{info,warn,error,debug}!` in the tree -
/// crucially arti's Tor bootstrap diagnostics and epix-tor's own warnings - is
/// dropped on the floor. That is why field reports of "Tor is off and there is
/// NO logging whatsoever" (EpixNet#239) were impossible to diagnose: when the
/// bootstrap stalled, the only trace was the two coarse `state.log` lines, and
/// arti's explanation went nowhere.
///
/// Output goes to stdout, which the desktop launcher has already redirected to
/// `<data>/log/epix-browser.log`, so it lands in the same file users already
/// share; the server binary keeps it on the console. The filter comes from
/// `EPIX_LOG` (or `RUST_LOG`), else [`DEFAULT_LOG_FILTER`]. `try_init` never
/// panics if a host shell (or a second `boot`) already installed a subscriber.
fn init_logging() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = std::env::var("EPIX_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| EnvFilter::try_new(&s).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_LOG_FILTER));
    // No ANSI: this stream is usually a file, and colour escapes only litter it.
    let _ = fmt().with_env_filter(filter).with_ansi(false).try_init();
}

/// Boot the node: resolve, clone + verify (unless already on disk), set up the
/// UI server and the background runtime, and return the [`UiServer`] future to
/// await plus the [`RunningNode`] handle. Cloning uses the network only when
/// the xite is not already complete on disk.
pub async fn boot(
    opts: NodeOptions,
) -> Result<(UiServer, RunningNode), String> {
    init_logging();
    std::fs::create_dir_all(&opts.data_root).map_err(|e| format!("create data root: {e}"))?;
    // A restore staged by the Backup & Restore wizard applies now, before
    // anything reads the data dir (users.json, sites.json, config).
    epix_ui::backup::apply_pending_restore(&opts.data_root);
    // Carry a Python client's epixnet.conf settings over into config.json before
    // anything reads config (the Tor-Always egress gate below, then AppState).
    migrate_legacy_conf(&opts.data_root);

    // Install the finality root of trust and restore its anti-rollback
    // checkpoint before reading a launch cache entry or contacting chain RPC.
    let xid_finality = initialize_xid_finality(&opts.data_root)?;

    // Parse the startup network policy strictly, arm its egress gate, and only
    // then select the launch target. Tor-Always and offline mode use the cache
    // only. An uncached name is deferred instead of leaking before the runtime
    // has established its final network policy.
    let (launch, startup_network_policy) = prepare_startup_launch_with(
        &opts,
        arm_startup_network_policy,
        |data_root, target| async move { resolve_target(&data_root, &target).await },
    )
    .await?;

    serve(opts, launch, xid_finality, startup_network_policy).await
}

/// The display form of a launch target: a raw `epix1…` address passes through;
/// a `.epix` name (or bare label defaulting to the `epix` TLD) is normalized to
/// `name.tld` - the same string the on-demand resolver keys on.
fn launch_display(target: &str) -> Result<String, String> {
    let (name, tld) = target.rsplit_once('.').unwrap_or((target, "epix"));
    match epix_core::classify_label(name) {
        epix_core::LabelClass::Address => Ok(name.to_string()),
        epix_core::LabelClass::AddressShaped => Err(address_shaped_target_error(name, tld)),
        epix_core::LabelClass::Name => Ok(format!("{name}.{tld}")),
    }
}

/// Resolve a launch target from the on-disk cache only (no chain query), for
/// Always mode where an uncached name must not be resolved over clearnet at
/// boot. Returns `(address, display)` on any cache hit (fresh or stale, since a
/// stale mapping keeps serving); `None` when the name has never been resolved,
/// so it defers to the on-demand resolver.
fn cached_launch(
    data_root: &std::path::Path,
    target: &str,
) -> Result<Option<(String, String)>, String> {
    let (name, tld) = target.rsplit_once('.').unwrap_or((target, "epix"));
    match epix_core::classify_label(name) {
        epix_core::LabelClass::Address => {
            return Ok(Some((name.to_string(), name.to_string())));
        }
        epix_core::LabelClass::AddressShaped => {
            return Err(address_shaped_target_error(name, tld));
        }
        epix_core::LabelClass::Name => {}
    }
    let full = format!("{name}.{tld}");
    Ok(validated_cached_resolution(data_root, &full).map(|(address, _fresh)| (address, full)))
}

/// Build a [`LaunchTarget::Resolved`] for an address we can serve now: create
/// its data dir and load any content.json already on disk. The UI server must
/// come up immediately and never block startup on a download (EpixNet's model):
///   - a verified content.json loads normally;
///   - a content.json that does not verify (authored, edited, or not yet signed
///     for this address) is parsed and served as-is - a signature is only
///     required when fetching from peers, not for local content;
///   - nothing on disk leaves `content` None, so the xite registers empty and
///     downloads on demand when first opened.
fn resolved_launch(
    opts: &NodeOptions,
    address: String,
    display: String,
) -> Result<LaunchTarget, String> {
    let parsed = validated_xite_address(&address, "launch target")?;
    let address = parsed.to_string();
    let data_dir = opts.data_root.join("data").join(parsed.as_str());
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("create data dir: {e}"))?;
    let mut xite = Xite::new(parsed, XiteStorage::new(&data_dir));
            let _ = xite.load_content(); // verified path: sets content when valid
            if xite.content.is_none() {
                xite.load_content_local(); // local unsigned/edited copy: serve as-is
            }
    let content = xite.content.clone();
    Ok(LaunchTarget::Resolved {
        address,
        display,
        data_dir,
        content,
    })
}

/// Python `epixnet.conf` keys the Rust node honors by seeding them into
/// `config.json` (paired with the config key they map to), when config.json has
/// no explicit value of its own. All three are read back through `config_get`,
/// so seeding is enough to make them take effect - and the Config page then
/// shows the imported value. `ui_ip`/`ui_port` are honored separately at the
/// server bind (they never route through config); every other key stays ignored
/// - gateway-mode switches (`ui_host`, `ui_trans_proxy`) and resolver URLs are
/// unsafe to lift blindly from a stale Python install.
const LEGACY_CONF_SEED_KEYS: &[&str] = &["tor", "fileserver_port", "language"];

/// Legacy keys the node consumes outside config.json, so they are used - not
/// "ignored" - and must not be warned about. `data_dir` relocates the root;
/// `ui_ip`/`ui_port` feed the server bind.
const LEGACY_CONF_USED_ELSEWHERE: &[&str] = &["data_dir", "ui_ip", "ui_port"];

/// Merge the mapped legacy `conf` values into `cfg` for keys `cfg` does not
/// already have, returning `(seeded_keys, ignored)`: the keys imported, and the
/// present conf keys this version does not support. Pure, so the precedence
/// (config.json always wins) and the ignore-list are unit-testable.
fn apply_legacy_conf(
    conf: &std::collections::BTreeMap<String, String>,
    cfg: &mut serde_json::Map<String, serde_json::Value>,
) -> (Vec<String>, Vec<String>) {
    let mut seeded = Vec::new();
    for &key in LEGACY_CONF_SEED_KEYS {
        if let Some(value) = conf.get(key) {
            if !cfg.contains_key(key) {
                cfg.insert(key.to_string(), serde_json::Value::String(value.clone()));
                seeded.push(key.to_string());
            }
        }
    }
    let ignored = conf
        .keys()
        .filter(|k| {
            !LEGACY_CONF_SEED_KEYS.contains(&k.as_str())
                && !LEGACY_CONF_USED_ELSEWHERE.contains(&k.as_str())
        })
        .cloned()
        .collect();
    (seeded, ignored)
}

/// Carry a Python client's `epixnet.conf` over into this node's `config.json`.
///
/// In Python EpixNet, `epixnet.conf` (INI) is *the* config file; a user coming
/// from it naturally sets `tor=`, `fileserver_port=`, etc. there. The Rust node
/// stores settings in `private/config.json` (written by the Config page) and
/// otherwise reads `epixnet.conf` only for `data_dir` - so those edits silently
/// did nothing (EpixNet#239: "it doesn't start despite the settings in the
/// config file"). Seed the mapped keys once, only where config.json has no value
/// of its own, so a hand-edit is honored while the Config page still wins.
///
/// Writes the file directly (before `AppState` loads it, and before the
/// Tor-Always egress gate reads it). Skipped when `EPIX_DATA_DIR` overrides the
/// layout: the operator is in explicit control, and it keeps tests off the
/// machine's real conf.
fn migrate_legacy_conf(data_root: &std::path::Path) {
    if std::env::var("EPIX_DATA_DIR").ok().filter(|s| !s.is_empty()).is_some() {
        return;
    }
    let conf_path = epix_ui::paths::default_conf_path();
    let conf = epix_ui::paths::read_conf(&conf_path);
    if conf.is_empty() {
        return;
    }
    let cfg_path = data_root.join("private").join("config.json");
    let mut cfg: serde_json::Map<String, serde_json::Value> = match std::fs::read(&cfg_path) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(serde_json::Value::Object(config)) => config,
            // Preserve malformed or structurally invalid existing config so
            // the strict startup parser below can reject it. Migration must
            // never replace a bad file with a permissive default object.
            _ => return,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Default::default(),
        // Preserve unreadable files too. Startup reports the I/O failure.
        Err(_) => return,
    };
    let (seeded, ignored) = apply_legacy_conf(&conf, &mut cfg);
    if !seeded.is_empty() {
        if let Some(parent) = cfg_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&cfg) {
            if std::fs::write(&cfg_path, bytes).is_ok() {
                let shown: Vec<String> =
                    seeded.iter().map(|k| format!("{k}={}", conf[k])).collect();
                // Migrate, don't copy: now the values live in config.json, drop
                // them from the INI so the two never disagree and a later edit of
                // a moved key in the INI can't silently do nothing.
                let keys: Vec<&str> = seeded.iter().map(String::as_str).collect();
                let _ = epix_ui::paths::remove_conf_keys(&conf_path, &keys);
                eprintln!(
                    "[INFO] epixnet.conf: moved legacy settings into config.json ({}). \
                     Change them from the Config page from now on.",
                    shown.join(", ")
                );
            }
        }
    }
    if !ignored.is_empty() {
        eprintln!(
            "[WARNING] epixnet.conf: these keys are not supported by this version and were \
             ignored: {}. Set options in the Config page (stored in private/config.json).",
            ignored.join(", ")
        );
    }
}

/// The UI bind address a Python client's `epixnet.conf` asks for (`ui_ip` /
/// `ui_port`), if either is set - so a headless/seedbox carry-over keeps its
/// address. `None` when neither is set or `EPIX_DATA_DIR` overrides the layout.
/// The desktop browser keeps its fixed loopback bind (its proxy depends on it);
/// only the server binary consults this.
pub fn legacy_ui_bind() -> Option<String> {
    if std::env::var("EPIX_DATA_DIR").ok().filter(|s| !s.is_empty()).is_some() {
        return None;
    }
    legacy_ui_addr(&epix_ui::paths::read_conf(&epix_ui::paths::default_conf_path()))
}

/// Build a `ip:port` bind from a conf map's `ui_ip`/`ui_port`, defaulting the
/// missing half to the standard loopback / UI port. `None` when neither is set.
/// Pure, so the defaulting is unit-testable.
fn legacy_ui_addr(conf: &std::collections::BTreeMap<String, String>) -> Option<String> {
    let ip = conf.get("ui_ip").map(String::as_str);
    let port = conf.get("ui_port").map(String::as_str);
    if ip.is_none() && port.is_none() {
        return None;
    }
    Some(format!("{}:{}", ip.unwrap_or("127.0.0.1"), port.unwrap_or("42222")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupNetworkPolicy {
    Direct,
    TorAlways,
    Offline,
}

impl StartupNetworkPolicy {
    fn defers_chain_resolution(self) -> bool {
        matches!(self, Self::TorAlways | Self::Offline)
    }
}

/// Parse the network policy before any launch-name lookup. A missing config is
/// the normal first-run case. Any present but unreadable, invalid, or
/// structurally ambiguous config fails startup instead of silently enabling
/// direct egress.
fn startup_network_policy(
    data_root: &std::path::Path,
    opts: &NodeOptions,
) -> Result<StartupNetworkPolicy, String> {
    let path = data_root.join("private").join("config.json");
    let config = match std::fs::read(&path) {
        Ok(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid node config {}: {error}", path.display()))?;
            value.as_object().cloned().ok_or_else(|| {
                format!(
                    "invalid node config {}: expected a JSON object",
                    path.display()
                )
            })?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Default::default(),
        Err(error) => {
            return Err(format!(
                "cannot read node config {}: {error}",
                path.display()
            ));
        }
    };

    let offline = match config.get("offline") {
        None => false,
        Some(serde_json::Value::Bool(value)) => *value,
        Some(serde_json::Value::String(value)) if value.eq_ignore_ascii_case("true") => true,
        Some(serde_json::Value::String(value)) if value.eq_ignore_ascii_case("false") => false,
        Some(_) => {
            return Err(format!(
                "invalid node config {}: offline must be true or false",
                path.display()
            ));
}
    };
    // Validate both sources even when offline or an explicit option wins. A
    // malformed persisted policy must never be hidden by another setting.
    let configured_tor = match config.get("tor") {
        None => None,
        Some(serde_json::Value::String(value)) => Some(parse_startup_tor_policy(
            value,
            &format!("node config {}", path.display()),
        )?),
        Some(_) => {
            return Err(format!(
                "invalid node config {}: tor must be a string",
                path.display()
            ));
        }
    };
    let explicit_tor = (!opts.tor_mode.trim().is_empty())
        .then(|| parse_startup_tor_policy(&opts.tor_mode, "node options"))
        .transpose()?;

    if offline {
        Ok(StartupNetworkPolicy::Offline)
    } else {
        Ok(explicit_tor
            .or(configured_tor)
            .unwrap_or(StartupNetworkPolicy::Direct))
    }
}

fn parse_startup_tor_policy(value: &str, source: &str) -> Result<StartupNetworkPolicy, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "always" => Ok(StartupNetworkPolicy::TorAlways),
        "disable" | "disabled" | "false" | "off" | "enable" | "enabled" | "true" | "on" => {
            Ok(StartupNetworkPolicy::Direct)
        }
        _ => Err(format!("invalid Tor mode `{value}` in {source}")),
    }
}

fn arm_startup_network_policy(policy: StartupNetworkPolicy) {
    epix_chain::set_chain_route(None, policy.defers_chain_resolution());
    #[cfg(feature = "bittorrent")]
    {
        epix_bt::http::set_socks(None);
        epix_bt::http::set_require_tor(policy.defers_chain_resolution());
    }
}

async fn prepare_startup_launch_with<A, F, Fut>(
    opts: &NodeOptions,
    arm_policy: A,
    resolve: F,
) -> Result<(LaunchTarget, StartupNetworkPolicy), String>
where
    A: FnOnce(StartupNetworkPolicy),
    F: FnOnce(PathBuf, String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, String, bool), String>>,
{
    let policy = startup_network_policy(&opts.data_root, opts)?;
    arm_policy(policy);

    if policy.defers_chain_resolution() {
        let launch = match cached_launch(&opts.data_root, &opts.target)? {
            Some((address, display)) => resolved_launch(opts, address, display),
            None => Ok(LaunchTarget::Deferred {
                display: launch_display(&opts.target)?,
            }),
        }?;
        return Ok((launch, policy));
    }
    let (address, display, _from_cache) =
        resolve(opts.data_root.clone(), opts.target.clone()).await?;
    Ok((resolved_launch(opts, address, display)?, policy))
}

/// Acquire and retain the requested UI listener. Only the default port falls
/// back to the legacy EpixNet port. This attempts the real bind once per port,
/// instead of probing and dropping a socket before the server starts.
fn bind_ui_listener_with<T>(
    requested: std::net::SocketAddr,
    default_port: u16,
    fallback_port: u16,
    mut bind: impl FnMut(std::net::SocketAddr) -> std::io::Result<T>,
) -> std::io::Result<T> {
    match bind(requested) {
        Ok(listener) => Ok(listener),
        Err(requested_error) if requested.port() == default_port => {
            let fallback = std::net::SocketAddr::new(requested.ip(), fallback_port);
            bind(fallback).map_err(|fallback_error| {
                std::io::Error::new(
                    fallback_error.kind(),
                    format!(
                        "cannot bind UI on {requested} ({requested_error}) or fallback {fallback} ({fallback_error})"
                    ),
                )
            })
        }
        Err(error) => Err(error),
    }
}

/// Bind first, then run `publish` while the returned listener still owns the
/// selected port. Native-messaging metadata must only be exposed inside this
/// callback, after a different local process can no longer impersonate the
/// node on that port.
fn bind_and_publish_ui_endpoint_with<T>(
    requested: std::net::SocketAddr,
    default_port: u16,
    fallback_port: u16,
    publish: impl FnOnce(std::net::SocketAddr) -> T,
) -> std::io::Result<(std::net::TcpListener, std::net::SocketAddr, T)> {
    let listener = bind_ui_listener_with(
        requested,
        default_port,
        fallback_port,
        std::net::TcpListener::bind,
    )?;
    listener.set_nonblocking(true)?;
    let bind = listener.local_addr()?;
    let published = publish(bind);
    Ok((listener, bind, published))
}

/// Publish the selected UI port before rotating the bearer token. If the port
/// file cannot be updated, retaining the old token fails native messaging
/// closed instead of sending the new token to a stale, attacker-owned port.
fn publish_nmh_endpoint(
    data_root: &std::path::Path,
    bind: std::net::SocketAddr,
    token: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let port_path = data_root.join("ui_port");
    if let Err(error) = std::fs::write(&port_path, bind.port().to_string()) {
        warnings.push(format!(
            "cannot publish native-messaging UI port {}: {error}; refusing to publish the current token",
            port_path.display()
        ));
        return warnings;
    }
    if let Err(error) = write_nmh_auth_token(data_root, token) {
        warnings.push(format!(
            "native-messaging name resolution is unavailable: {error}"
        ));
    }
    warnings
}

/// Boot and then serve forever (blocks). The convenience entry point for the
/// server binary and the FFI background thread.
pub async fn run(opts: NodeOptions) -> Result<(), String> {
    let (server, running) = boot(opts).await?;
    // A standalone binary can relaunch itself for the Config page's restart.
    // Shells that call `boot` directly register their own argv (the desktop
    // browser) or none at all (the mobile apps, where the node is a library
    // and a restart request is a plain shutdown).
    if let Some(exe) = epix_ui::self_exe() {
        running.state.set_restart_argv(vec![exe]);
    }
    server.serve(running.ui_addr).await.map_err(|e| format!("server: {e}"))
}

/// The inner paths of up to [`NAME_SAMPLE`] entries, with a `(+N more)` tail
/// when the list was cut. For error text that has to stay one readable line
/// while still naming the file an operator needs to look at.
fn name_sample(files: &[epix_xite::FileEntry]) -> String {
    const NAME_SAMPLE: usize = 10;
    let shown =
        files.iter().take(NAME_SAMPLE).map(|f| f.inner_path.as_str()).collect::<Vec<_>>().join(", ");
    match files.len().checked_sub(NAME_SAMPLE) {
        Some(rest) if rest > 0 => format!("{shown} (+{rest} more)"),
        _ => shown,
    }
}

/// Display counters also see local, deliberately unsigned manifests. Saturate
/// their declared totals so malformed local metadata cannot panic a debug node
/// or wrap the loading-screen byte count in release builds.
fn saturating_size_total(sizes: impl IntoIterator<Item = i64>) -> i64 {
    sizes
        .into_iter()
        .filter(|size| *size >= 0)
        .fold(0i64, i64::saturating_add)
}

type CloneFileProgress = Arc<dyn Fn(&str, usize) + Send + Sync>;

#[derive(Clone)]
struct PexSpawner {
    found: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    address: String,
    state: Option<Arc<AppState>>,
    budget: Arc<std::sync::atomic::AtomicUsize>,
}

impl PexSpawner {
    fn spawn(&self, peer: PeerAddr, tx: tokio::sync::mpsc::UnboundedSender<PeerAddr>) {
        use std::sync::atomic::Ordering;

        let Some(state) = self.state.clone() else {
            return;
        };
        if self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |budget| {
                budget.checked_sub(1)
            })
            .is_err()
        {
            return;
        }
        let found = self.found.clone();
        let address = self.address.clone();
        tokio::spawn(async move {
            let Some(Ok(learned)) = state.edx_pex(peer, &address, 10, Vec::new()).await else {
                return;
            };
            for learned_peer in learned {
                if found.lock().unwrap().insert(learned_peer.to_string()) {
                    let _ = tx.send(learned_peer);
                }
            }
        });
    }

    async fn record_peer(&self, peer: PeerAddr, count: usize, t0: Option<std::time::Instant>) {
        if let Some(t0) = t0.filter(|_| count <= 3) {
            trace_clone!(t0, "discovery: peer #{count} {peer}");
        }
        if let Some(state) = &self.state {
            state.push_clone_event(
                &self.address,
                serde_json::json!(["peers_added", count]),
                serde_json::json!({ "peers": count }),
            );
            state.add_peers(&self.address, [peer.clone()]).await;
        }
    }
}

struct CloneDiscovery {
    rx: tokio::sync::mpsc::UnboundedReceiver<PeerAddr>,
    pex_tx: tokio::sync::mpsc::UnboundedSender<PeerAddr>,
    pex: PexSpawner,
}

impl CloneDiscovery {
    fn forward_late(self, initial_count: usize) {
        let mut rx = self.rx;
        let pex_tx = self.pex_tx;
        let pex = self.pex;
        tokio::spawn(async move {
            let mut count = initial_count;
            while let Ok(Some(peer)) =
                tokio::time::timeout(std::time::Duration::from_secs(60), rx.recv()).await
            {
                count += 1;
                pex.record_peer(peer.clone(), count, None).await;
                pex.spawn(peer, pex_tx.clone());
            }
            drop(pex_tx);
        });
    }
}

async fn start_clone_discovery(
    address: &str,
    trackers: &[epix_xite::Tracker],
    progress: Option<&Arc<AppState>>,
) -> CloneDiscovery {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<PeerAddr>();
    let found = Arc::new(std::sync::Mutex::new(
        std::collections::HashSet::<String>::new(),
    ));
    for tracker in trackers.iter().cloned() {
        let tx = tx.clone();
        let found = found.clone();
        let address = address.to_string();
        let state = progress.cloned();
        tokio::spawn(async move {
            let peers = match &state {
                Some(state) => {
                    state
                        .announce_to_trackers(&address, std::slice::from_ref(&tracker))
                        .await
                }
                None => Vec::new(),
            };
            for peer in peers {
                if found.lock().unwrap().insert(peer.to_string()) {
                    let _ = tx.send(peer);
                }
            }
        });
    }
    if let Some(state) = progress {
        let dht_tx = tx.clone();
        let dht_found = found.clone();
        let dht_address = address.to_string();
        let dht_state = state.clone();
        tokio::spawn(async move {
            for peer in dht_state.find_peers_dht(&dht_address).await {
                if dht_found.lock().unwrap().insert(peer.to_string()) {
                    let _ = dht_tx.send(peer);
                }
            }
        });
        for peer in state.connectable_peers(address, 50).await {
            if found.lock().unwrap().insert(peer.to_string()) {
                let _ = tx.send(peer);
            }
        }
    }
    let pex_tx = tx.clone();
    drop(tx);
    CloneDiscovery {
        rx,
        pex_tx,
        pex: PexSpawner {
            found,
            address: address.to_string(),
            state: progress.cloned(),
            budget: Arc::new(std::sync::atomic::AtomicUsize::new(3)),
        },
    }
}

struct RootRace {
    address: String,
    progress: Option<Arc<AppState>>,
    t0: std::time::Instant,
    fetchers: tokio::task::JoinSet<(PeerAddr, Option<Vec<u8>>)>,
    in_flight: [usize; 2],
    untried: std::collections::VecDeque<PeerAddr>,
    channel_open: bool,
    staged: Option<Vec<u8>>,
    peer_count: usize,
}

impl RootRace {
    const SLOTS_PER_CLASS: usize = 4;

    fn new(address: &str, progress: Option<&Arc<AppState>>, t0: std::time::Instant) -> Self {
        Self {
            address: address.to_string(),
            progress: progress.cloned(),
            t0,
            fetchers: tokio::task::JoinSet::new(),
            in_flight: [0, 0],
            untried: std::collections::VecDeque::new(),
            channel_open: true,
            staged: None,
            peer_count: 0,
        }
    }

    fn class(peer: &PeerAddr) -> usize {
        usize::from(!peer.is_overlay())
    }

    fn spawn_or_queue(&mut self, peer: PeerAddr) {
        let class = Self::class(&peer);
        if self.in_flight[class] >= Self::SLOTS_PER_CLASS {
            self.untried.push_back(peer);
            return;
        }
        self.in_flight[class] += 1;
        self.fetchers.spawn(race_content(
            peer,
            self.address.clone(),
            self.progress.clone(),
        ));
    }

    async fn discovered(&mut self, peer: PeerAddr, discovery: &CloneDiscovery) {
        self.peer_count += 1;
        discovery
            .pex
            .record_peer(peer.clone(), self.peer_count, Some(self.t0))
            .await;
        discovery.pex.spawn(peer.clone(), discovery.pex_tx.clone());
        self.spawn_or_queue(peer);
    }

    fn finished(
        &mut self,
        result: Result<(PeerAddr, Option<Vec<u8>>), tokio::task::JoinError>,
        xite: &mut Xite,
    ) {
        let Ok((peer, bytes)) = result else {
            self.refill();
            return;
        };
        let class = Self::class(&peer);
        self.in_flight[class] = self.in_flight[class].saturating_sub(1);
        if let Some(bytes) = bytes {
            if xite.stage_content(&bytes).is_ok() {
                trace_clone!(self.t0, "content.json verified + staged from {peer}");
                self.staged = Some(bytes);
                return;
            }
        }
        self.refill();
    }

    fn refill(&mut self) {
        let Some(position) = self
            .untried
            .iter()
            .position(|peer| self.in_flight[Self::class(peer)] < Self::SLOTS_PER_CLASS)
        else {
            return;
        };
        let Some(peer) = self.untried.remove(position) else {
            return;
        };
        self.spawn_or_queue(peer);
    }

    fn exhausted(&self) -> bool {
        !self.channel_open && self.fetchers.is_empty() && self.untried.is_empty()
    }

    fn into_result(mut self) -> Result<(Vec<u8>, usize), String> {
        self.fetchers.abort_all();
        match self.staged {
            Some(bytes) => Ok((bytes, self.peer_count)),
            None if self.peer_count == 0 => {
                Err("no peers found - is the network reachable?".to_string())
            }
            None => Err("could not fetch + verify content.json from any peer".to_string()),
        }
    }
}

async fn race_clone_root(
    xite: &mut Xite,
    discovery: &mut CloneDiscovery,
    address: &str,
    progress: Option<&Arc<AppState>>,
    t0: std::time::Instant,
) -> Result<(Vec<u8>, usize), String> {
    let mut race = RootRace::new(address, progress, t0);
    while race.staged.is_none() {
        if race.exhausted() {
            break;
        }
        tokio::select! {
            next = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                discovery.rx.recv(),
            ), if race.channel_open => {
                match next {
                    Ok(Some(peer)) => race.discovered(peer, discovery).await,
                    Ok(None) | Err(_) => race.channel_open = false,
                }
            }
            Some(result) = race.fetchers.join_next(), if !race.fetchers.is_empty() => {
                race.finished(result, xite);
            }
            else => break,
        }
    }
    race.into_result()
}

fn emit_root_manifest_progress(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    peer_count: usize,
) {
    let Some(state) = progress else {
        return;
    };
    let needed = xite.files_needed();
    let total = needed.len();
    let size_needed = saturating_size_total(needed.iter().map(|file| file.size));
    let (optional_files, size_optional) = xite
        .content
        .as_ref()
        .and_then(|content| content.get("files_optional"))
        .and_then(serde_json::Value::as_object)
        .map(|files| {
            let bytes = saturating_size_total(files.values().filter_map(|metadata| {
                metadata
                    .get("size")
                    .and_then(epix_content::verify::exact_nonnegative_size)
            }));
            (files.len(), bytes)
        })
        .unwrap_or((0, 0));
    let counts = serde_json::json!({
        "peers": peer_count,
        "bad_files": total,
        "tasks": total,
        "started_task_num": total,
        "size_needed": size_needed,
        "optional_files": optional_files,
        "size_optional": size_optional,
    });
    state.push_clone_event(
        address,
        serde_json::json!(["file_done", "content.json"]),
        counts.clone(),
    );
    state.push_clone_event(address, serde_json::json!(["file_added", total]), counts);
}

async fn fetch_missing_clone_root(
    xite: &mut Xite,
    discovery: &mut CloneDiscovery,
    address: &str,
    progress: Option<&Arc<AppState>>,
    t0: std::time::Instant,
) -> Result<(Option<Vec<u8>>, usize), String> {
    if xite.content.is_some() {
        return Ok((None, 0));
    }
    let (bytes, peer_count) = race_clone_root(xite, discovery, address, progress, t0).await?;
    emit_root_manifest_progress(xite, progress, address, peer_count);
    Ok((Some(bytes), peer_count))
}

async fn load_clone_xite(
    address: &str,
    data_dir: &std::path::Path,
) -> Result<(Xite, bool), String> {
    std::fs::create_dir_all(data_dir).map_err(|error| format!("create xite dir: {error}"))?;
    let address =
        Address::parse(address.to_string()).map_err(|error| format!("bad address: {error}"))?;
    let storage = XiteStorage::new(data_dir);
    tokio::task::spawn_blocking(move || {
        let mut xite = Xite::new(address, storage);
        let complete = xite.load_content().unwrap_or(false) && xite.files_needed().is_empty();
        (xite, complete)
    })
    .await
    .map_err(|error| format!("completeness check failed: {error}"))
}

async fn begin_clone_root_transaction(
    progress: Option<&Arc<AppState>>,
    address: &str,
    staged: Option<&[u8]>,
) -> Result<Option<epix_ui::state::ManifestTransaction>, String> {
    let Some(signed) = staged else {
        return Ok(None);
    };
    let state = progress.ok_or("network clone has no AppState transaction owner")?;
    state
        .begin_staged_root_transaction(address, signed)
        .await
        .map(Some)
        .map_err(|error| format!("begin staged root transaction: {error}"))
}

fn clone_file_progress(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    peer_count: usize,
) -> Option<CloneFileProgress> {
    let clone_total = xite.files_needed().len();
    progress.map(|state| {
        let state = state.clone();
        let address = address.to_string();
        let peers = peer_count.max(1);
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let from_peers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Arc::new(move |inner: &str, serving: usize| {
            use std::sync::atomic::Ordering;

            let completed = done.fetch_add(1, Ordering::SeqCst) + 1;
            let left = clone_total.saturating_sub(completed);
            from_peers.fetch_max(serving, Ordering::SeqCst);
            if inner == "index.html" && left > 0 {
                return;
            }
            state.push_clone_event(
                &address,
                serde_json::json!(["file_done", inner]),
                serde_json::json!({
                    "peers": peers,
                    "peers_serving": from_peers.load(Ordering::SeqCst),
                    "bad_files": left,
                    "tasks": left,
                    "started_task_num": clone_total,
                }),
            );
        }) as CloneFileProgress
    })
}

#[derive(Default)]
struct CorePassState {
    dry: u32,
    empty_waits: u32,
    number: u32,
}

impl CorePassState {
    fn next(&mut self) -> u32 {
        self.number += 1;
        self.number
    }

    fn wait_for_peers(&mut self) -> bool {
        self.empty_waits += 1;
        self.empty_waits <= 20
    }

    fn peers_found(&mut self) {
        self.empty_waits = 0;
    }

    fn made_progress(&mut self, before: usize, after: usize) -> bool {
        self.dry = if after < before { 0 } else { self.dry + 1 };
        self.dry < 5
    }
}

async fn run_clone_core_pass(
    state: &Arc<AppState>,
    xite: &Xite,
    address: &str,
    before: Vec<epix_xite::FileEntry>,
    peers: Vec<PeerAddr>,
    transaction: Option<&epix_ui::state::ManifestTransaction>,
    emit: Option<CloneFileProgress>,
) {
    let staged = xite.content.clone();
    let edx_progress = emit.map(|emit| {
        Arc::new(move |inner: &str, _bytes: u64, serving: usize| emit(inner, serving))
            as epix_ui::state::EdxBatchProgress
    });
    const PASS_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);
    let _ = tokio::time::timeout(
        PASS_BUDGET,
        state.edx_first(
            address,
            before,
            peers,
            staged.as_ref(),
            transaction,
            edx_progress,
        ),
    )
    .await;
}

async fn download_clone_core(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    transaction: Option<&epix_ui::state::ManifestTransaction>,
    emit: Option<CloneFileProgress>,
    t0: std::time::Instant,
) {
    let Some(state) = progress else {
        return;
    };
    let mut passes = CorePassState::default();
    loop {
        let before = xite.files_needed();
        if before.is_empty() {
            break;
        }
        let pass = passes.next();
        trace_clone!(
            t0,
            "core pass {pass} START, {} file(s) needed",
            before.len()
        );
        let peers = state.fetch_candidate_peers(address, 50).await;
        trace_clone!(t0, "core pass {pass}: {} candidate peer(s)", peers.len());
        if peers.is_empty() {
            if !passes.wait_for_peers() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            continue;
        }
        passes.peers_found();
        run_clone_core_pass(
            state,
            xite,
            address,
            before.clone(),
            peers,
            transaction,
            emit.clone(),
        )
        .await;
        let after = xite.files_needed().len();
        trace_clone!(t0, "core pass {pass} END, {after} file(s) still needed");
        if after == 0 || !passes.made_progress(before.len(), after) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
}

async fn commit_clone_root(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    staged: Option<&[u8]>,
    transaction: Option<&epix_ui::state::ManifestTransaction>,
) -> Result<(), String> {
    let Some(_signed) = staged else {
        return Ok(());
    };
    let missing = xite.files_needed();
    if !missing.is_empty() {
        return Err(format!(
            "clone incomplete: {} core file(s) unavailable from current peers: {}",
            missing.len(),
            name_sample(&missing)
        ));
    }
    let state = progress.ok_or("network clone has no AppState transaction owner")?;
    let transaction = transaction.ok_or("network clone lost its staged root transaction")?;
    state
        .commit_staged_root(address, transaction)
        .await
        .map_err(|error| format!("commit content.json: {error}"))
}

fn finish_clone_first_paint(progress: Option<&Arc<AppState>>, address: &str, peer_count: usize) {
    let Some(state) = progress else {
        return;
    };
    state.push_clone_event(
        address,
        serde_json::json!(["file_done", "index.html"]),
        serde_json::json!({ "peers": peer_count.max(1), "bad_files": 0, "tasks": 0 }),
    );
    state.spawn_retention_completion(address);
}

async fn sync_clone_children(
    xite: &mut Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    t0: std::time::Instant,
) -> (u64, Vec<String>) {
    let peers = state_peers(progress, xite, address).await;
    if peers.is_empty() {
        return (0, Vec::new());
    }
    sync_included_content(xite, &peers, progress, address, t0).await
}

/// Clone a xite into `data_dir` from the network (skipping the fetch if it is
/// already complete on disk): discover peers, fetch + verify content.json, and
/// sync every file. Pushes wrapper loading-screen events (`peers_added`,
/// `file_done` for content.json with the pending-file counts) to `progress`
/// as the clone advances - the on-demand path, where a browser is watching
/// the loading screen. Used by the on-demand resolver (initial boot no longer
/// blocks on a download; it serves from disk and lets this run on first open).
///
/// Discovery and download run concurrently: every tracker announce and the
/// DHT lookup stream discovered peers into a channel, content.json is raced
/// against the first peers to respond, and the file download starts the
/// moment content.json verifies - while discovery keeps feeding fresh peers
/// (and replacement workers) into the running download.
async fn clone_xite_with_progress(
    address: &str,
    data_dir: &std::path::Path,
    trackers: &[epix_xite::Tracker],
    progress: Option<&Arc<AppState>>,
) -> Result<(Option<serde_json::Value>, u64, Vec<String>), String> {
    let t0 = std::time::Instant::now();
    trace_clone!(t0, "clone START {address}");
    let (mut xite, complete) = load_clone_xite(address, data_dir).await?;
    if complete {
        return Ok((xite.content.clone(), 0, Vec::new()));
    }
    if let Some(state) = progress {
        state.push_clone_event(address, serde_json::Value::Null, serde_json::json!({}));
    }

    let mut discovery = start_clone_discovery(address, trackers, progress).await;
    let (staged_bytes, peer_count) =
        fetch_missing_clone_root(&mut xite, &mut discovery, address, progress, t0).await?;
    // The transaction holds the canonical content.json manifest guard for the
    // WHOLE core download below - files materialize into its stage, so the
    // hold is structural. The cost: an inbound Req::Update (or local publish)
    // for this xite blocks on that guard until the clone commits, which can
    // be minutes over Tor, and the pushing peer scores this node down.
    // Shortening the hold means teaching the staged-promotion machinery to
    // release and revalidate the guard around the download - a design change,
    // not a patch. Bounded to a xite's first clone.
    let transaction =
        begin_clone_root_transaction(progress, address, staged_bytes.as_deref()).await?;
    discovery.forward_late(peer_count);

    let emit = clone_file_progress(&xite, progress, address, peer_count);
    download_clone_core(&xite, progress, address, transaction.as_ref(), emit, t0).await;
    commit_clone_root(
        &xite,
        progress,
        address,
        staged_bytes.as_deref(),
        transaction.as_ref(),
    )
    .await?;
    drop(transaction);
    finish_clone_first_paint(progress, address, peer_count);

    trace_clone!(t0, "CORE SET COMPLETE (first paint)");
    // User content streams in on its own task through the same entry the
    // periodic resync uses: the page is already served, each post ingests
    // and pushes its event as it lands, and a slow (or wedged) user fetch
    // can never hold the clone open or die with it. The clone itself is
    // done at first paint.
    if let Some(state) = progress {
        let state = state.clone();
        let spawn_address = address.to_string();
        tokio::spawn(async move {
            state.sync_user_content(&spawn_address).await;
        });
    } else {
        let _ = sync_clone_children(&mut xite, progress, address, t0).await;
    }
    trace_clone!(t0, "clone DONE, user content streaming in the background");
    Ok((xite.content.clone(), 0, Vec::new()))
}

/// The peer set to use for the included-content pass: the live registry when a
/// state is present (accumulated during discovery), else empty.
async fn state_peers(progress: Option<&Arc<AppState>>, _xite: &Xite, address: &str) -> Vec<PeerAddr> {
    match progress {
        Some(state) => state.connectable_peers(address, 20).await,
        None => Vec::new(),
    }
}

/// Apply one network-fetched child manifest through the same guarded update
/// path used by peer pushes. That path verifies the signature, fetches every
/// required file from `peer_fallbacks`, and exposes the child only after those
/// files verify.
async fn apply_fetched_child_manifest(
    state: &Arc<AppState>,
    address: &str,
    inner_path: &str,
    bytes: Vec<u8>,
    peer_fallbacks: Vec<PeerAddr>,
) -> Result<epix_ui::state::InboundUpdate, String> {
    let modified = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|content| content.get("modified").and_then(serde_json::Value::as_f64));
    retry_child_manifest_apply(|| {
        state.apply_inbound_update(
            address,
            inner_path,
            Some(bytes.clone()),
            modified,
            None,
            None,
            epix_ui::state::UpdatePayload {
                // The level loop must not stall on one child's slow file
                // fetch: stage the manifest, batch the files afterwards.
                defer_required_fetch: true,
                ..epix_ui::state::UpdatePayload::default()
            },
            peer_fallbacks.clone(),
        )
    })
    .await
}

// One page = one GetSigned session round. Applies no longer pull files
// inline (defer_required_fetch), so a page is cheap to consume and a whole
// level should ride a single round instead of serial sessions of 4.
const CHILD_MANIFEST_PAGE_SIZE: usize = 64;
// Straggler bounds for one level's manifest fetch: keep waiting while items
// stream, but once the level is at least GRACE old and the stream has been
// IDLE-quiet, hand the leftovers to the periodic resync.
const CHILD_MANIFEST_FETCH_GRACE: std::time::Duration = std::time::Duration::from_secs(12);
const CHILD_MANIFEST_FETCH_IDLE: std::time::Duration = std::time::Duration::from_secs(6);
const CHILD_MANIFEST_LIMIT: usize = 100_000;
const CHILD_DATA_PAGE_SIZE: usize = 32;
const CHILD_APPLY_CONCURRENCY: usize = 4;
const CHILD_APPLY_ATTEMPTS: usize = 3;

/// Retry only verification failures that fresh parent or xID signer resolution
/// can change. Availability failures already leave guarded completion work with
/// AppState, so starting another apply would duplicate those transfers.
fn should_retry_child_manifest_apply(error: &str) -> bool {
    error.contains("Valid signs:")
        || error.contains("Invalid cert signer")
        || error.contains("No rules")
}

async fn retry_child_manifest_apply<F, Fut>(
    mut apply: F,
) -> Result<epix_ui::state::InboundUpdate, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<epix_ui::state::InboundUpdate, String>>,
{
    for attempt in 0..CHILD_APPLY_ATTEMPTS {
        match apply().await {
            Err(error)
                if attempt + 1 < CHILD_APPLY_ATTEMPTS
                    && should_retry_child_manifest_apply(&error) =>
            {
                // These failures are xID/signer resolution answering empty or
                // stale - mid-clone over Tor that means circuits still
                // building, which takes seconds, not milliseconds. A path
                // that fails all attempts lands in `seen` and is not
                // revisited for the rest of the clone, so the ladder must
                // outlast a cold circuit: 2.5s then 10s.
                let delay_ms = 2_500 * (1u64 << (2 * attempt as u32));
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            }
            result => return result,
        }
    }
    unreachable!("the final child apply attempt always returns")
}

/// Required paths in a child candidate that cannot use EDX because the signed
/// entry has neither a `b3` object id nor a shard descriptor. This is only an
/// error-reporting aid. AppState remains the verifier and availability gate.
fn legacy_required_paths(inner_path: &str, bytes: &[u8]) -> Vec<String> {
    let Ok(content) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Vec::new();
    };
    let dir = inner_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .unwrap_or("");
    content
        .get("files")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flat_map(|files| files.iter())
        .filter(|(path, info)| {
            info.get("b3").and_then(serde_json::Value::as_str).is_none()
                && content
                    .get("files_shard")
                    .and_then(|shards| shards.get(path.as_str()))
                    .is_none()
        })
        .map(|(path, _)| {
            if dir.is_empty() {
                path.clone()
            } else {
                format!("{dir}/{path}")
            }
        })
        .collect()
}

fn path_sample(paths: &[String]) -> String {
    const LIMIT: usize = 10;
    let shown = paths
        .iter()
        .take(LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    match paths.len().checked_sub(LIMIT) {
        Some(rest) if rest > 0 => format!("{shown} (+{rest} more)"),
        _ => shown,
    }
}

async fn report_child_manifest_failure(
    state: &Arc<AppState>,
    address: &str,
    inner_path: &str,
    error: &str,
    legacy: &[String],
) {
    let detail = if legacy.is_empty() {
        error.to_string()
    } else {
        format!(
            "{error}; required legacy file(s) have no b3 and need a verified diff or re-sign: {}",
            path_sample(legacy)
        )
    };
    state
        .log(
            "WARNING",
            format!("Could not expose {inner_path}: {detail}"),
        )
        .await;
    // Log only: a per-child hiccup is retried by the resync (and legacy
    // no-b3 files can never arrive), while a `file_failed` clone event paints
    // the loading screen red mid-download - "download failed" over a clone
    // that is succeeding. Red stays reserved for the core set.
    let _ = address;
}

type ChildManifestResult = (Result<epix_ui::state::InboundUpdate, String>, Vec<String>);

async fn consume_bounded_child_callbacks<F, Fut>(
    mut rx: tokio::sync::mpsc::Receiver<(String, Vec<u8>)>,
    apply: F,
) -> (
    std::collections::HashSet<String>,
    Vec<(String, ChildManifestResult)>,
)
where
    F: Fn(String, Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ChildManifestResult> + Send + 'static,
{
    use std::collections::HashSet;

    let apply = Arc::new(apply);
    let mut received = HashSet::new();
    let mut outcomes = Vec::new();
    let mut tasks = tokio::task::JoinSet::new();
    while let Some((path, bytes)) = rx.recv().await {
        if !received.insert(path.clone()) {
            continue;
        }
        if tasks.len() >= CHILD_APPLY_CONCURRENCY {
            if let Some(Ok(outcome)) = tasks.join_next().await {
                outcomes.push(outcome);
            }
        }
        let apply = apply.clone();
        let output_path = path.clone();
        tasks.spawn(async move { (output_path, apply(path, bytes).await) });
    }
    while let Some(outcome) = tasks.join_next().await {
        if let Ok(outcome) = outcome {
            outcomes.push(outcome);
        }
    }
    (received, outcomes)
}

async fn fetch_child_manifest_candidates(
    state: &Arc<AppState>,
    address: &str,
    wants: Vec<String>,
    peers: &[PeerAddr],
) -> std::collections::HashMap<String, ChildManifestResult> {
    use std::collections::{HashMap, HashSet};

    if wants.len() > CHILD_MANIFEST_PAGE_SIZE {
        return wants
            .into_iter()
            .map(|path| {
                (
                    path,
                    (
                        Err(format!(
                            "child manifest page exceeds {CHILD_MANIFEST_PAGE_SIZE} paths"
                        )),
                        Vec::new(),
                    ),
                )
            })
            .collect();
    }
    let channel_capacity = wants.len().max(1);
    let (tx, rx) = tokio::sync::mpsc::channel::<(String, Vec<u8>)>(channel_capacity);
    let delivered = Arc::new(std::sync::Mutex::new(HashSet::new()));
    let delivery_failures = Arc::new(std::sync::Mutex::new(HashSet::new()));
    let callback_delivered = delivered.clone();
    let callback_failures = delivery_failures.clone();
    let progress_mark = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let callback_progress = progress_mark.clone();
    let on_item: epix_ui::state::EdxSignedProgress = Arc::new(move |path: &str, bytes: &[u8]| {
        if !callback_delivered.lock().unwrap().insert(path.to_string()) {
            return;
        }
        // Progress = a NEW manifest: duplicate re-deliveries from extra peers
        // must not keep the idle-abort from ever firing.
        *callback_progress.lock().unwrap() = std::time::Instant::now();
        if let Err(error) = tx.try_send((path.to_string(), bytes.to_vec())) {
            let (failed_path, _) = error.into_inner();
            callback_failures.lock().unwrap().insert(failed_path);
        }
    });
    // A path no reachable peer serves must not hold the whole level hostage
    // for the fetcher's full background patience: once the stream has been
    // quiet past the idle window (after a cold-session grace), abandon the
    // stragglers - everything streamed so far is already applied, and the
    // periodic resync retries the rest without blocking first paint.
    let fetch_inner = state.edx_fetch_signed_many(address, wants, peers.to_vec(), Some(on_item));
    let fetch = async {
        let started = std::time::Instant::now();
        tokio::pin!(fetch_inner);
        loop {
            tokio::select! {
                fetched = &mut fetch_inner => break fetched,
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    let idle = progress_mark.lock().unwrap().elapsed();
                    if started.elapsed() >= CHILD_MANIFEST_FETCH_GRACE
                        && idle >= CHILD_MANIFEST_FETCH_IDLE
                    {
                        break None;
                    }
                }
            }
        }
    };
    let consumer_state = state.clone();
    let consumer_address = address.to_string();
    let consumer_peers = peers.to_vec();
    let consume = consume_bounded_child_callbacks(rx, move |path, bytes| {
        let state = consumer_state.clone();
        let address = consumer_address.clone();
        let peers = consumer_peers.clone();
        async move {
            let legacy = legacy_required_paths(&path, &bytes);
            let result = apply_fetched_child_manifest(&state, &address, &path, bytes, peers).await;
            (result, legacy)
        }
    });
    let (fetched, (received, streamed_outcomes)) = tokio::join!(fetch, consume);
    let mut outcomes: HashMap<_, _> = streamed_outcomes.into_iter().collect();
    // The callback is expected for every fetched item. Keep the returned map
    // as a safety net if delivery failed or an apply task terminated.
    if let Some(fetched) = fetched {
        for (path, bytes) in fetched {
            if outcomes.contains_key(&path) {
                continue;
            }
            let legacy = legacy_required_paths(&path, &bytes);
            let result =
                apply_fetched_child_manifest(state, address, &path, bytes, peers.to_vec()).await;
            outcomes.insert(path, (result, legacy));
        }
    }
    // A callback whose worker panicked, or whose bounded channel closed, must
    // not disappear as a fake "not served" result. The returned fetch map has
    // already recovered every path it carried. Make the rest explicit.
    let mut incomplete = received;
    incomplete.extend(delivery_failures.lock().unwrap().iter().cloned());
    for path in incomplete {
        outcomes.entry(path).or_insert_with(|| {
            (
                Err("signed manifest callback delivery or apply failed".to_string()),
                Vec::new(),
            )
        });
    }
    outcomes
}

fn classify_child_level(
    xite: &Xite,
    level: Vec<(String, f64)>,
    seen: &mut std::collections::HashSet<String>,
) -> (Vec<String>, Vec<(String, bool)>) {
    let mut current = Vec::new();
    let mut fetch = Vec::new();
    for (path, peer_modified) in level {
        if !seen.insert(path.clone()) {
            continue;
        }
        let disk = xite.storage().read(&path).ok();
        let disk_modified = disk
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
            .and_then(|content| content.get("modified").and_then(|value| value.as_f64()))
            .unwrap_or(-1.0);
        let has_disk = disk.is_some();
        if has_disk && peer_modified <= disk_modified {
            current.push(path);
        } else {
            fetch.push((path, has_disk));
        }
    }
    (current, fetch)
}

async fn apply_child_manifest_results(
    state: &Arc<AppState>,
    address: &str,
    candidates: Vec<(String, bool)>,
    mut outcomes: std::collections::HashMap<String, ChildManifestResult>,
) -> (Vec<String>, Vec<String>) {
    let mut current = Vec::new();
    let mut arrived = Vec::new();
    for (path, has_old_disk) in candidates {
        match outcomes.remove(&path) {
            Some((Ok(epix_ui::state::InboundUpdate::Applied), _)) => {
                arrived.push(path.clone());
                current.push(path);
            }
            Some((Ok(epix_ui::state::InboundUpdate::NotChanged), _)) => current.push(path),
            // Staged for the post-level batch fetch: not on disk yet, and not
            // a failure - the pending relay commits it once its files land.
            Some((Ok(epix_ui::state::InboundUpdate::Deferred), _)) => {}
            Some((Err(error), legacy)) => {
                report_child_manifest_failure(state, address, &path, &error, &legacy).await;
                if has_old_disk {
                    current.push(path);
                }
            }
            None => {
                report_child_manifest_failure(
                    state,
                    address,
                    &path,
                    "no peer served the signed manifest",
                    &[],
                )
                .await;
                if has_old_disk {
                    current.push(path);
                }
            }
        }
    }
    (current, arrived)
}

async fn verify_current_child_manifests(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    mut paths: Vec<String>,
    walk: &mut epix_xite::xite::VerifiedManifestWalk,
) -> (Vec<epix_xite::FileEntry>, Vec<String>) {
    let mut files = Vec::new();
    let mut includes = Vec::new();
    paths.sort_by(|left, right| {
        left.matches('/')
            .count()
            .cmp(&right.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    if let Err(error) = xite.enqueue_verified_manifest_paths(walk, paths.clone()) {
        if let Some(state) = progress {
            state
                .log("WARNING", format!("Stored child walk refused paths: {error}"))
                .await;
        }
        return (files, includes);
    }
    for path in paths {
        let governing = match xite.next_stored_manifest_governing_path(walk, &path) {
            Ok(Some(governing)) => governing,
            Ok(None) => {
                let _ = xite.skip_next_stored_manifest(walk, &path);
                continue;
            }
            Err(error) => {
                if let Some(state) = progress {
                    state
                        .log(
                            "WARNING",
                            format!("Stored child {path} has no verified governing parent: {error}"),
                        )
                        .await;
                }
                let _ = xite.skip_next_stored_manifest(walk, &path);
                continue;
            }
        };
        let Ok(parent) = xite.storage().read(&governing) else {
            let _ = xite.skip_next_stored_manifest(walk, &path);
            continue;
        };
        let Ok(parent) = serde_json::from_slice::<serde_json::Value>(&parent) else {
            let _ = xite.skip_next_stored_manifest(walk, &path);
            continue;
        };
        let child: Option<serde_json::Value> = xite
            .storage()
            .read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let xid_map = resolve_user_signers(&parent, &path, child.as_ref()).await;
        match xite.verify_next_stored_manifest(walk, &path, &xid_map) {
            Ok(Some(manifest)) => {
                files.extend(manifest.files());
                includes.extend(manifest.includes());
            }
            Ok(None) => {}
            Err(error) => {
                if let Some(state) = progress {
                    state
                        .log(
                            "WARNING",
                            format!("Stored child {path} failed verification: {error}"),
                        )
                        .await;
                }
            }
        }
    }
    (files, includes)
}

async fn sync_child_manifest_levels(
    xite: &mut Xite,
    peers: &[PeerAddr],
    progress: Option<&Arc<AppState>>,
    address: &str,
    ordered: Vec<(String, f64)>,
    t0: std::time::Instant,
) -> (Vec<epix_xite::FileEntry>, Vec<String>) {
    use std::collections::{BTreeMap, HashSet};

    let mut child_files = Vec::new();
    let mut arrived = Vec::new();
    let mut seen = HashSet::new();
    let mut walk = match xite.begin_verified_manifest_walk(Vec::new(), CHILD_MANIFEST_LIMIT) {
        Ok(Some(walk)) => walk,
        Ok(None) => return (child_files, arrived),
        Err(error) => {
            if let Some(state) = progress {
                state
                    .log("WARNING", format!("Stored child walk refused root: {error}"))
                    .await;
            }
            return (child_files, arrived);
        }
    };
    let mut pending: BTreeMap<usize, Vec<(String, f64)>> = BTreeMap::new();
    for (path, modified) in ordered {
        pending
            .entry(path.matches('/').count())
            .or_default()
            .push((path, modified));
    }
    while let Some((depth, level)) = pending.pop_first() {
        trace_clone!(t0, "level depth={depth} START, {} path(s)", level.len());
        let (mut current, candidates) = classify_child_level(xite, level, &mut seen);
        if !candidates.is_empty() {
            match progress {
                Some(state) => {
                    let mut fetched = 0usize;
                    for page in candidates.chunks(CHILD_MANIFEST_PAGE_SIZE) {
                        let page = page.to_vec();
                        let wants = page
                            .iter()
                            .map(|(path, _)| path.clone())
                            .collect::<Vec<_>>();
                        state.push_clone_event(
                            address,
                            serde_json::json!(["file_added", wants[0].clone()]),
                            serde_json::json!({}),
                        );
                        let outcomes =
                            fetch_child_manifest_candidates(state, address, wants, peers).await;
                        fetched += outcomes.len();
                        let (mut resolved, mut page_arrived) =
                            apply_child_manifest_results(state, address, page, outcomes).await;
                        current.append(&mut resolved);
                        arrived.append(&mut page_arrived);
                    }
                    trace_clone!(t0, "level depth={depth} manifests done, {fetched} fetched");
                }
                None => current.extend(
                    candidates
                        .into_iter()
                        .filter_map(|(path, has_disk)| has_disk.then_some(path)),
                ),
            }
        }
        let (mut files, includes) =
            verify_current_child_manifests(xite, progress, current, &mut walk).await;
        child_files.append(&mut files);
        for include in includes {
            if !seen.contains(&include) {
                pending
                    .entry(include.matches('/').count())
                    .or_default()
                    .push((include, 0.0));
            }
        }
    }
    (child_files, arrived)
}

#[derive(Default)]
struct UnavailableChildFiles {
    count: usize,
    sample: Vec<String>,
    legacy_count: usize,
    legacy_sample: Vec<String>,
}

impl UnavailableChildFiles {
    async fn record(&mut self, state: &Arc<AppState>, address: &str, inner_path: String) {
        const SAMPLE_LIMIT: usize = 10;
        self.count += 1;
        if self.sample.len() < SAMPLE_LIMIT {
            self.sample.push(inner_path.clone());
        }
        if !state.file_has_b3(address, &inner_path).await {
            self.legacy_count += 1;
            if self.legacy_sample.len() < SAMPLE_LIMIT {
                self.legacy_sample.push(inner_path);
            }
        }
    }
}

fn counted_path_sample(count: usize, sample: &[String]) -> String {
    let shown = sample.join(", ");
    match count.checked_sub(sample.len()) {
        Some(rest) if rest > 0 => format!("{shown} (+{rest} more)"),
        _ => shown,
    }
}

async fn report_unavailable_child_files(
    state: &Arc<AppState>,
    address: &str,
    files: &UnavailableChildFiles,
) {
    let legacy_note = if files.legacy_count == 0 {
        String::new()
    } else {
        format!(
            "; legacy path(s) without b3 require a verified diff or re-sign: {}",
            counted_path_sample(files.legacy_count, &files.legacy_sample)
        )
    };
    let error = format!(
        "{} user-content file(s) remain unavailable: {}{legacy_note}",
        files.count,
        counted_path_sample(files.count, &files.sample)
    );
    state.log("WARNING", format!("{address}: {error}")).await;
    // Log only, same reasoning as report_child_manifest_failure: user content
    // is best-effort streaming, and most of these are legacy files that can
    // never arrive until their owner re-signs. Painting the loading screen
    // red for them misreported every clone of a xite with legacy users.
}

async fn fetch_child_data_page(
    xite: &Xite,
    state: &Arc<AppState>,
    address: &str,
    peers: &[PeerAddr],
    page: Vec<epix_xite::FileEntry>,
    staged: Option<&serde_json::Value>,
) -> (Vec<String>, Vec<epix_xite::FileEntry>) {
    use std::collections::HashSet;

    let expected = page.clone();
    let expected_paths: HashSet<_> = expected.iter().map(|file| file.inner_path.clone()).collect();
    let callback_paths = Arc::new(expected_paths);
    let delivered = Arc::new(std::sync::Mutex::new(HashSet::new()));
    let delivery_failures = Arc::new(std::sync::Mutex::new(HashSet::new()));
    let callback_delivered = delivered.clone();
    let callback_failures = delivery_failures.clone();
    let channel_capacity = page.len().clamp(1, CHILD_DATA_PAGE_SIZE);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(channel_capacity);
    let on_file: epix_ui::state::EdxBatchProgress =
        Arc::new(move |inner: &str, _bytes: u64, _serving: usize| {
            if !callback_paths.contains(inner)
                || !callback_delivered.lock().unwrap().insert(inner.to_string())
            {
                return;
            }
            if let Err(error) = tx.try_send(inner.to_string()) {
                callback_failures.lock().unwrap().insert(error.into_inner());
            }
        });
    let fetch = state.edx_first(address, page, peers.to_vec(), staged, None, Some(on_file));
    let ingest_state = state.clone();
    let ingest_address = address.to_string();
    let ingest = async move {
        let mut ingested = HashSet::new();
        while let Some(path) = rx.recv().await {
            ingest_state.ingest_file(&ingest_address, &path).await;
            ingested.insert(path);
        }
        ingested
    };
    let (missed, ingested) = tokio::join!(fetch, ingest);
    let delivery_failures = delivery_failures.lock().unwrap().clone();
    let returned_missed: HashSet<_> =
        missed.into_iter().map(|file| file.inner_path).collect();
    let mut arrived = Vec::new();
    let mut unavailable = Vec::new();
    for file in expected {
        if returned_missed.contains(&file.inner_path)
            || !xite.storage().verify(&file.inner_path, &file.sha512)
        {
            unavailable.push(file);
            continue;
        }
        // Callback delivery is an optimization. Final verification is the
        // source of truth, and explicitly ingests every landed callback miss.
        if delivery_failures.contains(&file.inner_path) || !ingested.contains(&file.inner_path) {
            state.ingest_file(address, &file.inner_path).await;
        }
        arrived.push(file.inner_path);
    }
    (arrived, unavailable)
}

fn next_child_data_page(
    needed: &mut std::vec::IntoIter<epix_xite::FileEntry>,
) -> Vec<epix_xite::FileEntry> {
    needed.by_ref().take(CHILD_DATA_PAGE_SIZE).collect()
}

async fn fetch_child_data_files(
    xite: &Xite,
    state: &Arc<AppState>,
    address: &str,
    peers: &[PeerAddr],
    needed: Vec<epix_xite::FileEntry>,
    staged: Option<&serde_json::Value>,
) -> Vec<String> {
    let total = needed.len();
    state
        .log(
            "INFO",
            format!("Fetching {total} user-content file(s) for {address}"),
        )
        .await;
    let mut arrived = Vec::new();
    let mut unavailable = UnavailableChildFiles::default();
    let mut needed = needed.into_iter();
    let mut announced = false;
    loop {
        let page = next_child_data_page(&mut needed);
        if page.is_empty() {
            break;
        }
        if !announced {
            state.push_clone_event(
                address,
                serde_json::json!(["file_added", page[0].inner_path.clone()]),
                serde_json::json!({}),
            );
            announced = true;
        }
        let (mut page_arrived, page_unavailable) =
            fetch_child_data_page(xite, state, address, peers, page, staged).await;
        arrived.append(&mut page_arrived);
        // A staged (deferred-children) batch is a store prefetch: its files
        // cannot materialize until the promote pass commits their manifests,
        // so every one of them "misses" here by design. Reporting them as
        // failed would light the dashboard's failure pill for a normal clone.
        if staged.is_none() {
            for file in page_unavailable {
                unavailable.record(state, address, file.inner_path).await;
            }
        }
    }
    if unavailable.count > 0 {
        report_unavailable_child_files(state, address, &unavailable).await;
    }
    arrived
}

fn start_child_list_probes(
    peers: &[PeerAddr],
    progress: Option<&Arc<AppState>>,
    address: &str,
) -> tokio::task::JoinSet<(PeerAddr, Option<Vec<(String, f64)>>)> {
    let mut probes = tokio::task::JoinSet::new();
    for peer in peers.iter().take(8).cloned() {
        let state = progress.cloned();
        let address = address.to_string();
        probes.spawn(async move {
            // A probe that can hang (a Tor circuit that neither answers nor
            // errors) must not stall the whole user-content pass; observed
            // live on Android. The listing race only needs ONE answer.
            let list = match state {
                Some(state) => tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    fetch_list_modified(&state, &peer, &address),
                )
                .await
                .ok()
                .flatten(),
                None => None,
            };
            (peer, list)
        });
    }
    probes
}

async fn first_child_manifest_listing(
    mut probes: tokio::task::JoinSet<(PeerAddr, Option<Vec<(String, f64)>>)>,
) -> (Option<PeerAddr>, Vec<(String, f64)>) {
    let mut live_peer = None;
    while let Some(result) = probes.join_next().await {
        let Ok((peer, Some(list))) = result else {
            continue;
        };
        if live_peer.is_none() {
            live_peer = Some(peer.clone());
        }
        if list.is_empty() {
            continue;
        }
        probes.abort_all();
        return (Some(peer), list);
    }
    probes.abort_all();
    (live_peer, Vec::new())
}

fn merge_child_manifest_listing(
    paths: &mut std::collections::HashMap<String, f64>,
    list: Vec<(String, f64)>,
) {
    for (path, modified) in list {
        if !path.ends_with("content.json") || path == "content.json" {
            continue;
        }
        let current = paths.entry(path).or_insert(0.0);
        if modified > *current {
            *current = modified;
        }
    }
}

async fn discover_child_manifest_paths(
    xite: &Xite,
    peers: &[PeerAddr],
    progress: Option<&Arc<AppState>>,
    address: &str,
    t0: std::time::Instant,
) -> (std::collections::HashMap<String, f64>, Option<PeerAddr>) {
    let mut paths: std::collections::HashMap<String, f64> = xite
        .includes()
        .into_iter()
        .map(|path| (path, 0.0))
        .collect();
    for path in walk_disk_content_json(xite.storage().root()) {
        paths.entry(path).or_insert(0.0);
    }
    let probes = start_child_list_probes(peers, progress, address);
    let (live_peer, list) = first_child_manifest_listing(probes).await;
    merge_child_manifest_listing(&mut paths, list);
    trace_clone!(t0, "listModified race done, {} path(s) known", paths.len());
    (paths, live_peer)
}

fn prioritize_child_peer(peers: &[PeerAddr], live_peer: Option<&PeerAddr>) -> Vec<PeerAddr> {
    let mut prioritized = peers.to_vec();
    let Some(live_peer) = live_peer else {
        return prioritized;
    };
    let Some(position) = prioritized
        .iter()
        .position(|peer| peer.to_string() == live_peer.to_string())
    else {
        return prioritized;
    };
    let peer = prioritized.remove(position);
    prioritized.insert(0, peer);
    prioritized
}

fn order_child_manifest_paths(
    paths: std::collections::HashMap<String, f64>,
    feed_order: Option<epix_blob::policy::FeedOrder>,
) -> Vec<(String, f64)> {
    let mut ordered: Vec<_> = paths.into_iter().collect();
    if let Some(order) = feed_order {
        ordered.sort_by(|left, right| {
            if order.newest_first() {
                right.1.total_cmp(&left.1)
            } else {
                left.1.total_cmp(&right.1)
            }
        });
    }
    ordered.sort_by_key(|(path, _)| path.matches('/').count());
    ordered
}

async fn prewarm_child_signers(ordered: &[(String, f64)], t0: std::time::Instant) {
    let mut warm = tokio::task::JoinSet::new();
    for (path, _) in ordered {
        let Some(name) = user_dir_name(path) else {
            continue;
        };
        if !name.contains('.') {
            continue;
        }
        let name = name.to_string();
        warm.spawn(async move {
            let (label, tld) = name.rsplit_once('.').unwrap_or((&name, "epix"));
            epix_chain::xid_signers::resolve(label, tld).await;
        });
    }
    let count = warm.len();
    while warm.join_next().await.is_some() {}
    trace_clone!(t0, "xID signer pre-warm done for {count} user(s)");
}

async fn fetch_changed_child_merges(
    progress: Option<&Arc<AppState>>,
    address: &str,
    arrived: &[String],
    peers: &[PeerAddr],
) {
    let Some(state) = progress else {
        return;
    };
    state.fetch_merge_for_changed(address, arrived, peers).await;
}

async fn sync_declared_child_data(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    peers: &[PeerAddr],
    mut child_files: Vec<epix_xite::FileEntry>,
    mut arrived: Vec<String>,
) -> Vec<String> {
    use std::collections::HashSet;

    let mut unique = HashSet::new();
    child_files.retain(|file| unique.insert(file.inner_path.clone()));
    let needed = child_files
        .into_iter()
        .filter(|file| !xite.storage().verify(&file.inner_path, &file.sha512))
        .collect::<Vec<_>>();
    if needed.is_empty() {
        return arrived;
    }
    let Some(state) = progress else {
        return arrived;
    };
    let mut data_arrived = fetch_child_data_files(xite, state, address, peers, needed, None).await;
    arrived.append(&mut data_arrived);
    arrived
}

/// Download every included / per-user content.json (and the data files they
/// declare) for a user_contents xite, parent-first so each verifies against
/// its parent's rules. Returns the bytes downloaded and the inner paths of
/// the files that arrived from peers (for `file_done` events after the db
/// rebuild).
async fn sync_included_content(
    xite: &mut Xite,
    peers: &[PeerAddr],
    progress: Option<&Arc<AppState>>,
    address: &str,
    t0: std::time::Instant,
) -> (u64, Vec<String>) {
    let feed_order = xite
        .content
        .as_ref()
        .and_then(|content| epix_blob::policy::OrderPolicy::from_content(content).feed_order);
    let (paths, live_peer) =
        discover_child_manifest_paths(xite, peers, progress, address, t0).await;
    if paths.is_empty() {
        return (0, Vec::new());
    }
    let swarm = prioritize_child_peer(peers, live_peer.as_ref());
    let ordered = order_child_manifest_paths(paths, feed_order);
    // Deterministic fast path: the live peer just answered listModified over
    // a warm link and (as a full seeder) holds every manifest and object, so
    // the whole pass rides that ONE link - no widen windows, no dials into
    // junk swarm peers, no sweep across dead circuits. The variance between
    // a 10-second and a 3-minute pass was exactly those extra dials. The
    // full swarm is the fallback when the single peer serves nothing.
    //
    // Above SWARM_FANOUT_CHILDREN children the pass is bandwidth-bound, not
    // dial-latency-bound, so the extra dials pay for themselves: spread the
    // levels and the batch across the whole swarm instead.
    const SWARM_FANOUT_CHILDREN: usize = 40;
    let single_live = live_peer.is_some() && ordered.len() <= SWARM_FANOUT_CHILDREN;
    let peers = match &live_peer {
        Some(live) if single_live => vec![live.clone()],
        _ => {
            if live_peer.is_some() {
                trace_clone!(
                    t0,
                    "{} children, fanning out over {} swarm peer(s)",
                    ordered.len(),
                    swarm.len()
                );
            }
            swarm.clone()
        }
    };
    prewarm_child_signers(&ordered, t0).await;

    // While the levels run, inbound pushes for this xite's children defer
    // instead of fetching inline (see active_child_syncs): a push holding a
    // child's manifest guard across a slow pull would stall the level pass.
    if let Some(state) = progress {
        state.begin_child_sync(address).await;
    }
    let (child_files, arrived) =
        sync_child_manifest_levels(xite, &peers, progress, address, ordered.clone(), t0).await;
    let (child_files, arrived) = if arrived.is_empty()
        && child_files.is_empty()
        && single_live
        && swarm.len() > 1
    {
        trace_clone!(t0, "live-peer pass served nothing, retrying over the swarm");
        sync_child_manifest_levels(xite, &swarm, progress, address, ordered, t0).await
    } else {
        (child_files, arrived)
    };
    trace_clone!(t0, "all levels done, {} manifest(s) arrived", arrived.len());
    // The merge sweep is best-effort freshness, not correctness: committed
    // children's merge files ride the declared-data batch below, deferred
    // children carry their merge payloads into the promote, and the periodic
    // anti-entropy pass (resync_merge_files) unions records on its own
    // schedule. When manifests just arrived, the sweep re-fetches what this
    // pass already carries - and its union fetch can hang (observed live:
    // 10 seconds of a 26 second clone burned on a sweep that delivered
    // nothing). Run it only on quiet passes, still bounded.
    if arrived.is_empty() {
        if tokio::time::timeout(
            std::time::Duration::from_secs(10),
            fetch_changed_child_merges(progress, address, &arrived, &peers),
        )
        .await
        .is_err()
        {
            trace_clone!(t0, "merge sweep timed out, continuing");
        } else {
            trace_clone!(t0, "merge sweep done");
        }
    } else {
        trace_clone!(t0, "merge sweep skipped, {} fresh manifest(s)", arrived.len());
    }
    let arrived =
        sync_declared_child_data(xite, progress, address, &peers, child_files, arrived).await;
    trace_clone!(t0, "declared data done");
    sync_deferred_children(xite, progress, address, &peers, t0).await;
    if let Some(state) = progress {
        state.end_child_sync(address).await;
    }
    (0, arrived)
}

/// Complete the children the level pass staged with `defer_required_fetch`:
/// pull every still-missing file in ONE batch over the proven clone peers,
/// then promote the pending relays so the manifests commit now instead of on
/// the periodic retry. Files the batch could not land stay pending; the
/// retry pass keeps working on them as before.
async fn sync_deferred_children(
    xite: &Xite,
    progress: Option<&Arc<AppState>>,
    address: &str,
    peers: &[PeerAddr],
    t0: std::time::Instant,
) {
    let Some(state) = progress else {
        return;
    };
    let (needed, staged) = state.deferred_child_batch(address).await;
    if !needed.is_empty() {
        trace_clone!(
            t0,
            "deferred child batch START, {} file(s)",
            needed.len()
        );
        let landed =
            fetch_child_data_files(xite, state, address, peers, needed, Some(&staged)).await;
        trace_clone!(t0, "deferred child batch done, {} landed", landed.len());
    }
    state.promote_deferred_children().await;
    trace_clone!(t0, "deferred children promoted");
}

/// Every non-root `content.json` under `root` (per-user / included content
/// already on disk), as inner paths.
fn walk_disk_content_json(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(std::ffi::OsStr::to_str) == Some("content.json") {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    if rel != "content.json" {
                        out.push(rel);
                    }
                }
            }
        }
    }
    out
}

/// The user-directory name in `data/users/<name>/content.json`, if the path has
/// that shape (else `None`).
fn user_dir_name(inner_path: &str) -> Option<&str> {
    let parts: Vec<&str> = inner_path.split('/').collect();
    if parts.len() >= 3 && parts[0] == "data" && parts[1] == "users" {
        Some(parts[2])
    } else {
        None
    }
}

/// Resolve every xID name that verifying `inner_path` may need to its
/// chain-linked identity records: the user directory's own name (EpixTalk
/// stores each user's posts under their xID and signs with the identity that
async fn resolve_user_signers(
    parent: &serde_json::Value,
    inner_path: &str,
    child: Option<&serde_json::Value>,
) -> epix_content::XidMap {
    let mut names = epix_content::verify::content_xid_names(parent, inner_path);
    // A chain-delegated cert on the child itself must resolve too, so the
    // cert check can match its signer against the name's linked identities.
    if let Some(child) = child {
        names.extend(epix_content::verify::chain_cert_xid_name(parent, child));
    }
    let mut map = epix_content::XidMap::new();
    for name in names {
        let (label, tld) = name.rsplit_once('.').unwrap_or((name.as_str(), "epix"));
        let identities = epix_chain::xid_signers::resolve_identities_checked(label, tld)
            .await
            .unwrap_or_default();
        if !identities.is_empty() {
            map.insert(name, chain_xid_identities(identities));
        }
    }
    map
}

/// The chain's identity records in the shape verification consumes.
fn chain_xid_identities(identities: Vec<epix_chain::Identity>) -> Vec<epix_content::XidIdentity> {
    identities
        .into_iter()
        .map(|identity| epix_content::XidIdentity {
            address: identity.address,
            active: identity.active,
            revoked_at_time: identity.revoked_at_time,
        })
        .collect()
}

/// Ask a peer for its signed files changed since 0 (EDX `ListSigned`): the
/// inner_paths of every content.json it serves, including per-user ones.
/// `None` when the peer could not be reached or served no list.
async fn fetch_list_modified(
    state: &Arc<AppState>,
    peer: &PeerAddr,
    address: &str,
) -> Option<Vec<(String, f64)>> {
    let entries = state.edx_list_signed(peer.clone(), address, 0).await?.ok()??;
    Some(entries.into_iter().map(|(path, modified, _size)| (path, modified as f64)).collect())
}

/// One bounded attempt to pull content.json from a peer (phase 1 of a clone).
/// [`fetch_content`] that hands its peer back with the result, so the
/// content.json race can free that peer's network-class slot when it settles.
async fn race_content(
    peer: PeerAddr,
    address: String,
    state: Option<Arc<AppState>>,
) -> (PeerAddr, Option<Vec<u8>>) {
    let bytes = fetch_content(peer.clone(), address, state).await;
    (peer, bytes)
}

async fn fetch_content(
    peer: PeerAddr,
    address: String,
    state: Option<Arc<AppState>>,
) -> Option<Vec<u8>> {
    // Overlay-aware budget: an Ip peer is dialed through an exit circuit in
    // Tor-always mode, so the clearnet 10s cut off every attempt before the
    // circuit finished building and the clone never got content.json.
    // connect_timeout() already folds in route_all_via_overlay.
    let budget = peer.connect_timeout();
    // EDX manifest channel: GetSigned returns the signed content.json over an
    // EDX link, and works for ANY xite (the signed bytes are served independent
    // of per-file `b3`). With no state there is no fetcher, so nothing to do.
    let state = state?;
    match tokio::time::timeout(budget, state.edx_fetch_signed(peer, &address, "content.json")).await
    {
        Ok(Some(Ok(Some(bytes)))) => Some(bytes),
        _ => None,
    }
}

/// The on-demand resolver the browser proxy path uses: given a `.epix` host not
/// yet served, resolve it on-chain, clone it, and add it as a served xite keyed
/// by its bech32 address (the name is display metadata), so typing any
/// `talk.epix` opens it live.
/// One running on-demand clone: when it started (for staleness), its task
/// handle (so a stale one can be killed), and its token (see
/// `in_flight_token`).
struct InflightClone {
    token: u64,
    started: std::time::Instant,
    abort: Option<tokio::task::AbortHandle>,
}

/// A clone that has held its slot this long without ever registering the
/// xite is treated as wedged: it is aborted and a fresh attempt takes over.
/// A healthy clone registers within seconds (the entry is created before any
/// network work), so only a stuck task or one whose xite was deleted out
/// from under it can trip this.
const STALE_CLONE_STEAL: std::time::Duration = std::time::Duration::from_secs(90);

struct OnDemand {
    state: Arc<AppState>,
    data_root: PathBuf,
    trackers: Vec<epix_xite::Tracker>,
    /// Fixed startup policy. When true, only xites already complete on disk
    /// may be opened. Resolution, announce, dialing, and resume work all fail
    /// closed without touching the network.
    network_disabled: bool,
    /// Self-handle so `ensure` can detach the clone onto its own task: the
    /// caller is an HTTP request future, and a browser that gives up on the
    /// blocked request must not cancel the clone mid-download.
    me: std::sync::Weak<OnDemand>,
    /// Clones currently running, so concurrent requests coalesce - and so a
    /// wedged one can be recognized and replaced instead of squatting its
    /// address forever (the delete-then-redownload hang: the fresh attempt
    /// waited eternally on a stuck predecessor's slot).
    in_flight: tokio::sync::Mutex<std::collections::HashMap<String, InflightClone>>,
    /// Distinguishes an entry from its replacement after a steal, so a stuck
    /// task that finally dies cannot remove the slot of the clone that took
    /// over from it.
    in_flight_token: std::sync::atomic::AtomicU64,
    /// Whether Tor is expected to come up (mode != Disable). Gates the
    /// cold-start wait in `await_tor_ready`. Set once, after the Tor mode is
    /// resolved in `serve`.
    tor_expected: std::sync::atomic::AtomicBool,
    /// Whether Tor-Always mode is active (clearnet is closed). When Tor is not
    /// up, `await_tor_ready` refuses to fall through to a clearnet clone in this
    /// mode, so a cold-start or Tor-down clone never leaks the real IP.
    tor_always: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl epix_ui::OnDemandResolver for OnDemand {
    async fn ensure(&self, host: &str) -> Result<(), String> {
        // Served already? (name -> address via display metadata / resolve cache)
        // A registered xite whose core files are still missing (an interrupted
        // clone - the periodic resync only fetches files when a NEWER
        // content.json shows up, so it never heals one) falls through and
        // resumes its download. Never for owned xites: their local edits must
        // not be overwritten with the signed versions from peers.
        let key = self.state.canonical_key(host).await;
        if self.state.has_xite(&key).await
            && (self.state.xite_owned(&key).await || self.state.xite_core_complete(&key).await)
        {
            return Ok(());
        }
        if self.network_disabled {
            return Err(format!(
                "offline mode cannot resolve or fetch incomplete site {host}"
            ));
        }
        // In Always mode, resolving a name that has no cache entry hits the
        // chain, which is gated until Tor is up. Wait for Tor first so the
        // resolve rides it (and never falls back to clearnet) - this is the path
        // a deferred launch name takes on first open. Cached names and raw
        // addresses need no chain query, so they skip the wait.
        if self.tor_always.load(std::sync::atomic::Ordering::Relaxed)
            && needs_chain_resolve(&self.data_root, host)
            && !self.await_tor_ready().await
        {
            return Err(
                "Tor is not available and Always mode forbids clearnet, so this site \
                 cannot be resolved right now"
                    .to_string(),
            );
        }
        let address = resolve_host(&self.data_root, host)
            .await
            .ok_or_else(|| format!("could not resolve {host}"))?;
        // Coalesce concurrent clones on the RESOLVED address: the first does
        // the work, the rest wait briefly for it to land. Keying on the raw
        // host string let a clone opened as `name.epix` and one opened as its
        // epix1… address run twice in parallel, interleaving two independent
        // progress streams on the loading screen - the N/M file counter
        // visibly bounced and each stream's completion reset the bar.
        let served = self.state.has_xite(&address).await;
        let Some(token) = self.claim_clone_slot(&address, served).await else {
            // A live clone is working on it (it registers the xite within
            // seconds, and re-registration after a delete restarts the clock
            // via a fresh entry): coalesce.
            return self.wait_for_inflight(&address).await;
        };
        // Run the clone on its OWN task. This future belongs to the HTTP
        // request that hit the missing xite; a browser that times out or
        // retries that request drops the future, and an inline clone died
        // with it mid-download (leaving the in-flight entry stuck, so every
        // later attempt waited on a corpse). Detached, the clone always runs
        // to completion and clears its slot; this caller just waits for the
        // xite to register, which is safe to cancel.
        let Some(this) = self.me.upgrade() else {
            self.in_flight.lock().await.remove(&address);
            return Err("node is shutting down".into());
        };
        let spawn_host = host.to_string();
        let spawn_address = address.clone();
        let handle = tokio::spawn(async move {
            let result = this.do_ensure(&spawn_host, &spawn_address).await;
            if let Err(error) = result {
                this.state
                    .log(
                        "WARNING",
                        format!("On-demand clone of {spawn_host} failed: {error}"),
                    )
                    .await;
            }
            // Only clear OUR slot: a stolen entry belongs to the replacement.
            let mut inflight = this.in_flight.lock().await;
            if inflight.get(&spawn_address).is_some_and(|entry| entry.token == token) {
                inflight.remove(&spawn_address);
            }
        });
        {
            let mut inflight = self.in_flight.lock().await;
            if let Some(entry) = inflight.get_mut(&address) {
                if entry.token == token {
                    entry.abort = Some(handle.abort_handle());
                }
            }
        }
        self.wait_for_inflight(&address).await
    }

    async fn resolve(&self, host: &str) -> Option<String> {
        if self.network_disabled {
            resolve_host_cached_only(&self.data_root, host)
        } else {
        resolve_host(&self.data_root, host).await
    }
}
}

/// Resolve without any chain access. Raw addresses pass through and cached
/// names use either a fresh or stale validated mapping.
fn resolve_host_cached_only(data_root: &std::path::Path, host: &str) -> Option<String> {
    let (name, tld) = host.rsplit_once('.').unwrap_or((host, "epix"));
    match epix_core::classify_label(name) {
        epix_core::LabelClass::Address => Some(name.to_string()),
        epix_core::LabelClass::AddressShaped => None,
        epix_core::LabelClass::Name => {
            validated_cached_resolution(data_root, &format!("{name}.{tld}"))
                .map(|(address, _fresh)| address)
        }
    }
}

/// Resolve `host` (a `.epix` name or an `epix1…` address) to a xite address,
/// consulting the on-disk cache first and the chain only on a miss/expiry.
/// A successful chain lookup is written back to the cache. Never clones.
async fn resolve_host(data_root: &std::path::Path, host: &str) -> Option<String> {
    let (name, tld) = host.rsplit_once('.').unwrap_or((host, "epix"));
    // Every label classifies against the address space, including dotless
    // inputs. Short `epix1…` branding names remain names; checksum-valid
    // addresses pass through; address-shaped bad checksums fail closed.
    match epix_core::classify_label(name) {
        epix_core::LabelClass::Address => return Some(name.to_string()),
        epix_core::LabelClass::AddressShaped => return None,
        epix_core::LabelClass::Name => {}
    }
    let full = format!("{name}.{tld}");
    match validated_cached_resolution(data_root, &full) {
        Some((address, true)) => Some(address),
        stale => match try_resolve_on_chain_bound(name, tld).await {
            Ok((address, binding)) => {
                write_resolve_cache_bound(data_root, &full, &address, binding.as_ref());
                Some(address)
            }
            Err(_) => stale.map(|(address, _)| address),
        },
    }
}

/// Whether resolving `host` will hit the chain and cannot fall back: a `.epix`
/// name (not a raw `epix1…` address) with no cache entry at all. A fresh entry
/// resolves from cache; a stale one still serves its stale mapping if the chain
/// is unreachable - only a total miss forces a chain query with nothing to fall
/// back to. Used to decide whether to wait for Tor before resolving in Always
/// mode (mirrors [`resolve_host`]'s cache key).
fn needs_chain_resolve(data_root: &std::path::Path, host: &str) -> bool {
    let (name, tld) = host.rsplit_once('.').unwrap_or((host, "epix"));
    // Only a real NAME can hit the chain. Valid addresses resolve to themselves
    // and address-shaped bad checksums are rejected without egress.
    if epix_core::classify_label(name) != epix_core::LabelClass::Name {
        return false;
    }
    validated_cached_resolution(data_root, &format!("{name}.{tld}")).is_none()
}

#[async_trait::async_trait]
impl epix_ui::ContentSyncer for OnDemand {
    async fn sync_user_content(&self, address: &str) -> (u64, Vec<String>) {
        if self.network_disabled {
            return (0, Vec::new());
        }
        let Ok(addr) = validated_xite_address(address, "user-content sync target") else {
            return (0, Vec::new());
        };
        let dir = self.data_root.join("data").join(addr.as_str());
        let mut xite = Xite::new(addr, XiteStorage::new(dir));
        // Only user_contents xites (with includes) have out-of-tree content.
        if !xite.load_content().unwrap_or(false) || xite.includes().is_empty() {
            return (0, Vec::new());
        }
        let mut peers = self.state.connectable_peers(address, 20).await;
        if peers.is_empty() {
            // A rarely-visited xite may have no warm peers yet: announce for
            // some, then fall back to the DHT. Use the full tracker set (shared
            // + Beacon-discovered), not just the bootstrap list, or a peer known
            // only to a shared tracker is never found.
            let trackers = self.state.all_trackers(&self.trackers).await;
            peers = self.state.announce_to_trackers(address, &trackers).await;
            if peers.is_empty() {
                peers = self.state.find_peers_dht(address).await;
            }
        }
        if peers.is_empty() {
            return (0, Vec::new());
        }
        sync_included_content(
            &mut xite,
            &peers,
            Some(&self.state),
            address,
            std::time::Instant::now(),
        )
        .await
    }
}

impl OnDemand {
    /// Claim the in-flight slot for `address`, stealing it from a wedged
    /// predecessor (one that never registered its xite inside
    /// `STALE_CLONE_STEAL`, or whose xite was deleted out from under it -
    /// the delete-then-redownload hang). Returns the claim token, or `None`
    /// when a live clone already owns the slot and the caller should
    /// coalesce onto it.
    async fn claim_clone_slot(&self, address: &str, served: bool) -> Option<u64> {
        let mut inflight = self.in_flight.lock().await;
        if let Some(entry) = inflight.get(address) {
            if served || entry.started.elapsed() < STALE_CLONE_STEAL {
                return None;
            }
            self.state
                .log(
                    "WARNING",
                    format!(
                        "Replacing a stuck clone of {address} ({}s old)",
                        entry.started.elapsed().as_secs()
                    ),
                )
                .await;
            if let Some(abort) = &entry.abort {
                abort.abort();
            }
            inflight.remove(address);
        }
        let token = self
            .in_flight_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        inflight.insert(
            address.to_string(),
            InflightClone {
                token,
                started: std::time::Instant::now(),
                abort: None,
            },
        );
        Some(token)
    }

    /// Block (bounded) until the in-process Tor transport is installed, so a
    /// cold-start clone of an onion-seeded xite dials through Tor instead of
    /// the plain TCP transport the node holds until Arti finishes bootstrapping.
    ///
    /// Fresh installs hit this hard, Windows worst of all: opening the
    /// dashboard right after setup fired the clone while Tor was still
    /// bootstrapping, every onion peer dial failed on the TCP-only transport,
    /// and the loading screen dead-ended at "index.html download failed"
    /// ("Peers found: 4" but none reachable). Once Tor is up (the steady
    /// state) this returns at once, so only the first cold-start open waits.
    ///
    /// Returns whether it is safe to proceed to dial. Non-Always modes get the
    /// old behaviour (true): a dual-homed Enable node may dial clearnet peers
    /// directly, and a Disable node has no Tor to wait for. In Tor-Always mode
    /// clearnet is closed, so this returns true ONLY once Tor actually comes up;
    /// if Tor fails or drags past the cap it returns false and the caller aborts
    /// the clone instead of dialing over clearnet and leaking the real IP.
    /// "Disabled" is not treated as terminal here - on a cold start the Tor loop
    /// may not have flipped the status to "Bootstrapping" yet, and `tor_expected`
    /// already told us it is coming.
    async fn await_tor_ready(&self) -> bool {
        use std::sync::atomic::Ordering;
        if !self.tor_expected.load(Ordering::Relaxed) {
            return true;
        }
        let always = self.tor_always.load(Ordering::Relaxed);
        if self.state.tor_status().await.0 {
            return true; // already up: no wait
        }
        self.state
            .log(
                "INFO",
                "Waiting for Tor to bootstrap before cloning (onion-seeded \
                 sites are unreachable until it is up)"
                    .to_string(),
            )
            .await;
        // ~2 minutes. Arti's cold bootstrap is ~10-40s, but a slow link (or a
        // Windows machine fetching a fresh consensus) can take longer.
        for _ in 0..240 {
            let (up, status) = self.state.tor_status().await;
            if up {
                return true;
            }
            if status == "Failed" {
                // Fall through to clearnet only when clearnet is allowed.
                return !always;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        // Timed out: proceed over clearnet only when Always mode isn't forcing
        // Tor. In Always mode, refuse rather than leak.
        !always
    }

    /// Wait for the clone another caller is already running for `address` to
    /// register the xite (or give up).
    async fn wait_for_inflight(&self, address: &str) -> Result<(), String> {
        // The wrapper's inner file request blocks on this while the
        // loading screen shows, so wait as long as a clone can take.
        for _ in 0..600 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if self.state.has_xite(address).await {
                return Ok(());
            }
            if !self.in_flight.lock().await.contains_key(address) {
                break; // the working clone finished (or failed)
            }
        }
        if self.state.has_xite(address).await {
            return Ok(());
        }
        Err("timed out waiting for a concurrent clone".into())
    }

    /// The clone/resume work behind [`Self::ensure`], which resolved `host`
    /// to `address` and holds the in-flight slot for it.
    async fn do_ensure(&self, host: &str, address: &str) -> Result<(), String> {
        if self.network_disabled {
            return Err(format!(
                "offline mode cannot resolve or fetch incomplete site {host}"
            ));
        }
        let parsed = validated_xite_address(address, "on-demand clone target")?;
        let data_dir = self.data_root.join("data").join(parsed.as_str());
        // Clone when the address isn't served yet, or resume when it is served
        // but its core files are incomplete (an interrupted earlier clone).
        // Owned xites never re-clone: local edits stay.
        let was_registered = self.state.has_xite(address).await;
        if was_registered && host != address {
            self.state.set_display(address, host).await;
        }
        let resume = was_registered
            && !self.state.xite_owned(address).await
            && !self.state.xite_core_complete(address).await;
        if !was_registered || resume {
            self.clone_or_resume(host, address, &data_dir, was_registered).await?;
        }
        // The `.epix` name is display metadata on the address-keyed entry.
        if host != address {
            self.state.set_display(address, host).await;
        }
        self.state.log("INFO", format!("On-demand cloned {host} -> {address}")).await;
        Ok(())
    }

    /// Run the actual download for [`Self::do_ensure`]: register the entry,
    /// wait for Tor, clone with retries, and settle the db/user-content state.
    async fn clone_or_resume(
        &self,
        host: &str,
        address: &str,
        data_dir: &std::path::Path,
        was_registered: bool,
    ) -> Result<(), String> {
        if !was_registered {
            // Register the xite empty BEFORE the download (EpixNet's
            // SiteManager.need): siteInfo/dbQuery/permissions are real for the
            // page the moment it renders progressively, peers accumulate on
            // the live entry, and the dashboard shows the row mid-clone.
            self.state
                .add_xite(
                    address,
                    XiteEntry { storage: XiteStorage::new(data_dir), content: None },
                )
                .await;
            if host != address {
                self.state.set_display(address, host).await;
            }
        }
        // Onion-seeded xites are only reachable once Tor is up. On a cold
        // start the plain TCP transport is still installed, so wait for the
        // onion-capable transport before dialing - otherwise a fresh
        // install's first open fails every peer and shows "index.html
        // download failed". No-op once Tor is up (the steady state). In
        // Always mode, if Tor never comes up, abort rather than clone over
        // clearnet and leak the real IP.
        if !self.await_tor_ready().await {
            return Err(
                "Tor is not available and Always mode forbids clearnet, so this site \
                 cannot be fetched right now"
                    .to_string(),
            );
        }
        // Mark the download in flight: the html serving gate holds the
        // page document back until the core set is on disk.
        self.state.begin_clone(address);
        let cloned = self.clone_with_retries(address, data_dir).await;
        self.state.end_clone(address);
        let (content, bytes, user_files) = match cloned {
            Ok(r) => r,
            Err(e) => {
                // Tell the loading screen ("index.html download failed",
                // "No peers found" when none). Keep the xite registered
                // even on a first-load failure: add_xite already persisted
                // it to sites.json, so it survives a restart and resumes on
                // a later visit (the resume path re-attempts an incomplete
                // clone). Dropping it here used to lose a freshly-added xite
                // whose first load failed - e.g. no peers online yet.
                self.state.push_clone_event(
                    address,
                    serde_json::json!(["file_failed", "index.html"]),
                    serde_json::json!({}),
                );
                return Err(e);
            }
        };
        self.state.update_content(address, content.clone()).await;
        self.state.add_transfer(address, bytes, 0).await;
        // Rebuild the db now that the included / per-user data files are on
        // disk, so a user_contents xite's topics/comments are queryable.
        self.state.rebuild_xite_db(address).await;
        // A merged xite (e.g. a Git Epix repo) also feeds its merger's db.
        if content.as_ref().and_then(|c| c.get("merged_type")).is_some() {
            self.state.rebuild_merger_dbs().await;
        }
        self.state.push_xite_info(address).await;
        // file_done per user-content file already fired as each file
        // landed (ingest_file), with the db updated first - the page,
        // served progressively, re-queried and showed each one live.
        //
        // A complete-on-disk core short-circuits the clone WITHOUT the
        // user-content pass - but "core complete" says nothing about the
        // per-user files. An interrupted earlier clone (crash, restart)
        // leaves exactly that state, and waiting for the next resync tick
        // (minutes) shows a working page with an empty forum. Backfill in
        // the background right away; it is one listModified when nothing
        // is missing.
        //
        // Only when the clone brought NO user content: one that did has
        // already pulled those dirs' merge files inline, newest-first as
        // each verified, and repeating the sweep here would refetch every
        // record a second time.
        if user_files.is_empty() {
            let state = self.state.clone();
            let addr = address.to_string();
            let backfill = bytes == 0;
            tokio::spawn(async move {
                if backfill {
                    state.sync_user_content(&addr).await;
                }
                state.resync_merge_files_for(&addr).await;
            });
        }
        Ok(())
    }

    /// Announce and clone, retrying a few times.
    ///
    /// content.json discovery is best-effort per attempt: a single announce
    /// round can return only dead/unreachable peers this second while the
    /// node's background announce loop keeps turning up live seeders. Each
    /// attempt re-announces and re-seeds from the node's grown peer set, so a
    /// thinly seeded xite (the dashboard has few seeders) isn't doomed by one
    /// unlucky round. Cheap when it works: a live peer makes the first try
    /// land. Announces go to the full tracker set (shared +
    /// Beacon-discovered), not just the bootstrap list, so a peer registered
    /// only on a shared tracker (e.g. an onion-only seeder) is discovered.
    async fn clone_with_retries(
        &self,
        address: &str,
        data_dir: &std::path::Path,
    ) -> Result<(Option<serde_json::Value>, u64, Vec<String>), String> {
        const CLONE_ATTEMPTS: usize = 4;
        let trackers = self.state.all_trackers(&self.trackers).await;
        let mut cloned =
            clone_xite_with_progress(address, data_dir, &trackers, Some(&self.state)).await;
        for attempt in 1..CLONE_ATTEMPTS {
            if cloned.is_ok() {
                break;
            }
            self.state
                .log(
                    "INFO",
                    format!(
                        "content.json fetch failed for {address}; \
                         retry {attempt}/{} after finding more peers",
                        CLONE_ATTEMPTS - 1
                    ),
                )
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(8)).await;
            cloned =
                clone_xite_with_progress(address, data_dir, &trackers, Some(&self.state)).await;
        }
        cloned
    }
}

/// Read the xID finality pin without silently treating an arbitrary I/O error as
/// "not installed". A missing pin is accepted only through the explicit,
/// pre-upgrade compatibility switch passed by the caller.
fn read_xid_finality_pin(
    pin_path: &std::path::Path,
    allow_insecure_legacy: bool,
) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(pin_path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && allow_insecure_legacy => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(format!(
            "required xID finality pin {} is missing. This branch must not ship or merge before the trusted post-upgrade pin is installed. For pre-upgrade development only, set {ALLOW_INSECURE_XID_LEGACY_ENV}=1 explicitly.",
            pin_path.display()
        )),
        Err(e) => Err(format!(
            "cannot read required xID finality pin {}: {e}. Refusing to downgrade to RPC-trusted resolution.",
            pin_path.display()
        )),
    }
}

#[derive(Clone, Debug)]
enum XidFinalityBoot {
    Verified {
        validator_count: usize,
        restored_height: Option<u64>,
    },
    InsecureLegacy,
}

/// Install xID finality before any launch-name cache or RPC lookup is allowed.
/// Keeping this in `boot`, rather than `serve`, closes the cold-start window in
/// which an unverified mapping could choose the xite the node serves.
fn initialize_xid_finality(data_root: &std::path::Path) -> Result<XidFinalityBoot, String> {
    let pin_path = data_root.join("xid_pin.json");
    let allow_insecure_legacy =
        std::env::var_os(ALLOW_INSECURE_XID_LEGACY_ENV).is_some_and(|value| value == "1");
    match read_xid_finality_pin(&pin_path, allow_insecure_legacy)? {
        Some(bytes) => {
            let validator_count = epix_chain::install_finality_pin(&bytes).map_err(|e| {
                format!(
                    "xID finality pin {} is present but invalid: {e}. Refusing to start with finality verification disabled; replace it with a trusted pin.",
                    pin_path.display()
                )
            })?;
            let checkpoint_path = data_root.join("xid_finality_checkpoint.json");
            let restored =
                epix_chain::configure_finality_checkpoint(&checkpoint_path).map_err(|e| {
                    format!(
                        "xID finality checkpoint {} could not be restored: {e}",
                        checkpoint_path.display()
                    )
                })?;
            Ok(XidFinalityBoot::Verified {
                validator_count,
                restored_height: restored.map(|checkpoint| checkpoint.height),
            })
        }
        None => {
            epix_chain::set_pinned_validators(None);
            epix_chain::set_verify_finality(false);
            Ok(XidFinalityBoot::InsecureLegacy)
        }
    }
}

/// Wire up the [`AppState`], plugins, background runtime, and UI server for a
/// launch target. Returns the server future + handle.
async fn serve(
    opts: NodeOptions,
    launch: LaunchTarget,
    xid_finality: XidFinalityBoot,
    startup_network_policy: StartupNetworkPolicy,
) -> Result<(UiServer, RunningNode), String> {
    let state = AppState::with_data_dir(&opts.version, &opts.data_root);
    state
        .initialize_security_tokens()
        .map_err(|error| format!("cannot initialize UI security tokens: {error}"))?;
    state.set_rev(&opts.rev).await;
    if let Some(log_file) = &opts.log_file {
        state.set_log_file(log_file);
    }
    match xid_finality {
        XidFinalityBoot::Verified {
            validator_count,
            restored_height,
        } => {
            let checkpoint_note = restored_height
                .map(|height| format!("; restored height {height}"))
                .unwrap_or_default();
            state
                .log(
                    "INFO",
                    format!(
                        "xID finality: pinned {validator_count} validators; resolution now requires >2/3 attestation{checkpoint_note}"
                    ),
                )
                .await;
        }
        XidFinalityBoot::InsecureLegacy => {
            state
                .log(
                    "WARN",
                    format!(
                        "xID finality: {ALLOW_INSECURE_XID_LEGACY_ENV}=1 explicitly enabled insecure pre-upgrade RPC-trusted resolution"
                    ),
                )
                .await;
        }
    }
    // The Config page's "Data directory" works only when the root is the
    // user-relocatable desktop one (not pinned by EPIX_DATA_DIR or set
    // programmatically by an embedding shell). The choice persists as
    // `data_dir` in the default location's epixnet.conf, Python-style.
    let env_pinned = std::env::var("EPIX_DATA_DIR").map(|v| !v.is_empty()).unwrap_or(false);
    if !env_pinned && opts.data_root == epix_ui::paths::data_root() {
        state.set_data_dir_conf(epix_ui::paths::default_data_root().join("epixnet.conf"));
    }

    // Expand the GeoIP db off the startup path (first run unzips ~62MB).
    if let Some(gz) = opts.geoip_gz.clone() {
        let state = state.clone();
        let mmdb = opts.data_root.join("geoip-city.mmdb");
        tokio::spawn(async move {
            let geoip = tokio::task::spawn_blocking(move || {
                epix_ui::geoip::GeoIp::ensure(&gz, &mmdb)
            })
            .await
            .ok()
            .flatten();
            if let Some(geoip) = geoip {
                state.set_geoip(geoip).await;
            }
        });
    }

    // Restore xites served in a previous run (from sites.json).
    let restored = state.restore_xites().await;
    if restored > 0 {
        state.log("INFO", format!("Restored {restored} xite(s) from sites.json")).await;
    }

    // Register the launch xite (keyed by the bech32 address; the `.epix` name is
    // display metadata) and mark it the homepage. A deferred launch (Always
    // mode, name not yet resolvable without leaking over clearnet) registers
    // nothing - the on-demand resolver clones it on first open once Tor is up -
    // but still records the homepage so the wrapper knows where to send the
    // browser. `address` is empty in that case.
    let (address, display) = match launch {
        LaunchTarget::Resolved { address, display, data_dir, content } => {
            state
                .add_xite(&address, XiteEntry { storage: XiteStorage::new(&data_dir), content })
                .await;
            if display != address {
                state.set_display(&address, &display).await;
            }
            (address, display)
        }
        LaunchTarget::Deferred { display } => (String::new(), display),
    };
    // The launch xite is the homepage: the wrapper's corner home button and
    // the admin pages' back link return here from any other xite.
    state.set_homepage(&display);

    // Xite dbs are in-memory, so merger databases (Git Epix, Epix Post) are
    // empty on every boot until filled from their merged xites - do it now
    // that all restored xites are registered, or merger pages show nothing
    // until some merger action happens to trigger a rebuild.
    state.rebuild_merger_dbs().await;
    // Per-xite dbs are just as boot-empty: warm them in the background so
    // the dashboard's first feedQuery finds real rows instead of racing
    // every lazy rebuild against its 10s per-feed deadline.
    state.spawn_db_warmup();

    let offline = startup_network_policy == StartupNetworkPolicy::Offline;
    let transport = transport_for_network_policy(offline, Arc::new(TcpTransport));
    state.set_transport(transport.clone()).await;

    // Trackers: configured list, else the built-in defaults. Either way this
    // is only the bootstrap set - the Beacon plugin folds in everything it
    // discovers from peers (and the optional trackers_xite list) each cycle.
    let trackers: Vec<epix_xite::Tracker> = match state
        .config_get("trackers")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
    {
        Some(list) if !list.trim().is_empty() => {
            list.split([',', '\n']).filter_map(epix_xite::Tracker::parse).collect()
        }
        _ => default_trackers(),
    };
    // State-initiated announces (ensure_optional_peers) build the same full
    // tracker set the announce loop uses - including this bootstrap list.
    state.set_bootstrap_trackers(trackers.clone()).await;
    // Background optional-file retry loop: any xite whose "Download optional
    // files" / "Help distribute" toggle is on keeps fetching its missing
    // optional files - resuming interrupted downloads at startup and retrying
    // (with backoff) until everything arrived or the node stops. Registered
    // after the bootstrap trackers so its on-demand announces have the full
    // tracker set.
    if !offline {
        state.spawn_optional_retry_loop();
    }

    // Liveness watchdog: probe the central xites lock and abort a wedged
    // process rather than let it squat the port looking alive.
    state.spawn_lock_watchdog();

    // On-demand resolve + clone: typing any `talk.epix` in the browser clones
    // and serves it live.
    let on_demand = Arc::new_cyclic(|me| OnDemand {
        state: state.clone(),
        data_root: opts.data_root.clone(),
        trackers: trackers.clone(),
        network_disabled: offline,
        me: me.clone(),
        in_flight: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        in_flight_token: std::sync::atomic::AtomicU64::new(0),
        tor_expected: std::sync::atomic::AtomicBool::new(false),
        tor_always: std::sync::atomic::AtomicBool::new(false),
    });
    state.set_on_demand(on_demand.clone()).await;
    // The same component syncs included/user content for existing xites
    // (called by the resync loop, so EpixTalk-style posts stay fresh).
    state.set_content_syncer(on_demand.clone()).await;

    // A deferred launch has no address yet; the on-demand clone adds its
    // transfer row when it registers the xite.
    if !address.is_empty() {
        state.add_transfer(&address, 0, 0).await;
    }
    state.rebuild_merger_dbs().await;

    // Seeding + offline policy. The Config page persists values as STRINGS
    // (like i2p_sam_port below), so accept both forms - reading only the
    // number form made a configured port silently fall back to the default.
    const DEFAULT_FILESERVER_PORT: u16 = 26552;
    let configured_port = state
        .config_get("fileserver_port")
        .await
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())));
    let fileserver_port = match configured_port {
        Some(0) => None,
        Some(p) => Some(p as u16),
        None => Some(DEFAULT_FILESERVER_PORT),
    };
    if let Some(port) = fileserver_port {
        state.set_fileserver_port(port).await;
    }

    // Tor mode: an explicit option (EPIX_TOR / a shell's own setting) wins;
    // otherwise the Config page's persisted choice; otherwise enable. Without
    // the config fallback the Config page's Tor select would be dead UI - the
    // desktop launcher always passes a value, so the stored choice was ignored.
    #[cfg(feature = "tor")]
    let tor_mode = if offline {
        epix_runtime::TorMode::Disable
    } else if !opts.tor_mode.is_empty() {
        epix_runtime::TorMode::parse(&opts.tor_mode)
    } else {
        let configured = state
            .config_get("tor")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "enable".to_string());
        epix_runtime::TorMode::parse(&configured)
    };

    // Let the on-demand resolver know Tor is coming, so a cold-start clone
    // waits for the onion-capable transport instead of failing every onion
    // dial on the plain TCP transport the node holds until Arti bootstraps.
    // In Always mode it must also never fall through to a clearnet clone.
    #[cfg(feature = "tor")]
    {
        on_demand.tor_expected.store(
            tor_mode != epix_runtime::TorMode::Disable,
            std::sync::atomic::Ordering::Relaxed,
        );
        on_demand.tor_always.store(
            tor_mode == epix_runtime::TorMode::Always,
            std::sync::atomic::Ordering::Relaxed,
        );
        // In Always mode, block chain RPC from egressing over clearnet until the
        // SOCKS proxy is wired (below), so name resolution never leaks the real
        // IP or the queried name to api.epix.zone during the Tor bootstrap
        // window. Set before the runtime starts, so its first resolves are gated.
        epix_chain::set_chain_route(None, offline || tor_mode == epix_runtime::TorMode::Always);
        #[cfg(feature = "bittorrent")]
        {
            epix_bt::http::set_socks(None);
            epix_bt::http::set_require_tor(offline || tor_mode == epix_runtime::TorMode::Always);
        }
        // Ip peers are dialed through exit circuits in Always mode, so every
        // dial/transfer deadline must use the overlay budget - the clearnet
        // 15s cuts off exit-circuit dials mid-build and discovery goes dark.
        epix_core::set_route_all_via_overlay(tor_mode == epix_runtime::TorMode::Always);
    }

    // Privacy by default: turn the embedded I2P router on the first time a node
    // runs with no explicit `i2p` choice (persisted so the Config page shows it
    // selected, and an explicit Disable is never overridden). On both desktop
    // and mobile - the router is a no-transit leaf, so its cost is Tor-like.
    // Gated on `i2p-autostart`; offline mode stays off.
    #[cfg(feature = "i2p-autostart")]
    if !offline && state.config_get("i2p").await.is_none() {
        state.config_set("i2p", serde_json::json!("embedded")).await;
    }

    // I2P config from the node config (Config page): mode + external SAM port.
    #[cfg(feature = "i2p")]
    let (i2p_mode, i2p_sam_port) = {
        let mode = if offline {
            "disable".to_string()
        } else {
            state
                .config_get("i2p")
                .await
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "disable".to_string())
        };
        let port = state
            .config_get("i2p_sam_port")
            .await
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(7656) as u16;
        (mode, port)
    };

    // LAN discovery from the node config (Config page). Opt-in: answering a
    // discovery request discloses which xites we serve to anyone on the
    // network, so it stays off until the operator asks for it (an isolated LAN,
    // an air-gapped test). Forced off in offline mode like every other loop.
    #[cfg(feature = "local-discovery")]
    let local_discovery = !offline && state.config_bool("local_discovery", false).await;

    // Mesh config from the node config (Config page): enable + TCP interfaces.
    #[cfg(feature = "mesh")]
    let (mesh_enabled, mesh_peers, mesh_listen) = {
        let enabled = !offline
            && state
                .config_get("mesh")
                .await
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "disable".to_string())
                == "enable";
        let peers: Vec<String> = state
            .config_get("mesh_peers")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        let listen = state
            .config_get("mesh_listen")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.trim().is_empty());
        (enabled, peers, listen)
    };

    // Route Tor through an in-process Snowflake bridge when the operator opts in
    // (Config page "Use Tor bridges"), for networks that block direct Tor.
    #[cfg(feature = "bridges")]
    let tor_use_bridges = !offline && state.config_bool("tor_use_bridges", false).await;

    let runtime_config = epix_runtime::RuntimeConfig {
        fileserver_port: if offline { None } else { fileserver_port },
        offline,
        #[cfg(feature = "tor")]
        tor_mode,
        #[cfg(feature = "tor")]
        tor_socks_port: Some(43111),
        #[cfg(feature = "bridges")]
        tor_use_bridges,
        #[cfg(feature = "i2p")]
        i2p_mode,
        #[cfg(feature = "i2p")]
        i2p_sam_port,
        #[cfg(feature = "local-discovery")]
        local_discovery,
        #[cfg(feature = "mesh")]
        mesh_enabled,
        #[cfg(feature = "mesh")]
        mesh_peers,
        #[cfg(feature = "mesh")]
        mesh_listen,
        ..Default::default()
    };
    let mut runtime =
        epix_runtime::NodeRuntime::with_config(state.clone(), trackers, runtime_config);
    #[cfg(any(feature = "tor", feature = "i2p"))]
    {
        runtime = runtime.with_data_dir(opts.data_root.clone());
    }
    runtime.start();

    // Tor-always: once the Arti SOCKS listener is up (tor_status == "Always"),
    // route all chain RPC through it, so name resolution never exposes the
    // node's IP or which `.epix` names it looks up. Peer/tracker traffic already
    // rides Tor via the always-mode transport.
    //
    // Cold-start gap: Tor takes ~10-40s to bootstrap. Any chain RPC that runs
    // before this fires (e.g. resolving the xite named on the command line at
    // startup) goes direct. Steady-state resolves - on-demand navigation, the
    // native host, re-verification - all wait until the proxy is set and route
    // through Tor.
    #[cfg(feature = "tor")]
    if tor_mode == epix_runtime::TorMode::Always {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                if state.tor_status().await.1 == "Always" {
                    epix_chain::set_chain_socks(Some("socks5h://127.0.0.1:43111".into()));
                    // Route BT web-seed / .torrent fetches through the same proxy.
                    #[cfg(feature = "bittorrent")]
                    epix_bt::http::set_socks(Some("socks5h://127.0.0.1:43111".into()));
                    state.log("INFO", "Chain RPC now routed through Tor".to_string()).await;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }

    // BitTorrent swarm peer routing. Whenever Tor is on (enable OR always) - not
    // just always mode - route peer-wire connections through the Tor SOCKS proxy
    // once it is up. The mainline DHT that discovers peers is UDP and can't be
    // tunneled, so it stays on clearnet (and the whole swarm is disabled in
    // always mode via set_require_tor above); but the actual peer connection and
    // data transfer then ride Tor, hiding the node's IP from the seeders.
    #[cfg(all(feature = "tor", feature = "bittorrent"))]
    if tor_mode != epix_runtime::TorMode::Disable {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                if state.tor_status().await.0 {
                    epix_bt::http::set_peer_socks(Some("127.0.0.1:43111".into()));
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }
    // The runtime's loops are owned by their spawned tasks; leak the handle so
    // they run for the process lifetime (the caller serves forever).
    std::mem::forget(runtime);

    // Plugins + media.
    let mut plugins = epix_plugin::PluginRegistry::new();
    plugins.register(Arc::new(epix_plugins::SidebarPlugin));
    plugins.register(Arc::new(epix_plugins::BeaconPlugin));
    plugins.register(Arc::new(epix_plugins::ChannelPlugin));
    let mut plugin_names: Vec<String> = plugins.names().iter().map(|s| s.to_string()).collect();
    plugin_names.extend(epix_ui::builtin_plugins().into_iter().map(String::from));
    plugin_names.sort();
    plugin_names.dedup();
    state.set_plugins(plugin_names).await;
    plugins.start_all(&state);

    let requested: std::net::SocketAddr = opts
        .ui_addr
        .parse()
        .map_err(|_| format!("invalid ui_addr '{}'", opts.ui_addr))?;
    let (ui_listener, bind, nmh_warnings) =
        bind_and_publish_ui_endpoint_with(requested, DEFAULT_UI_PORT, LEGACY_UI_PORT, |bind| {
            publish_nmh_endpoint(&opts.data_root, bind, state.nmh_token())
        })
        .map_err(|error| format!("bind UI endpoint: {error}"))?;
    if bind.port() != requested.port() {
        state
            .log("INFO", format!("UI port {} in use; using {}", requested.port(), bind.port()))
            .await;
    }
    state.set_ui_port(bind.port()).await;
    for warning in nmh_warnings {
        state.log("WARN", warning).await;
    }
    state.log("INFO", format!("Serving {display}")).await;

    if opts.open_browser {
        open_in_browser(&format!("http://{bind}/{display}/"));
    }

    // Boot has applied (and possibly written) every restart-only config key by
    // now; snapshot them so the Config page can tell a saved-but-not-yet-live
    // change apart and offer a restart.
    state.snapshot_boot_config().await;

    let server = UiServer::with_registry_and_media(
        state.clone(),
        plugins.command_registry(),
        plugins.media_bundle(),
    )
    .with_bound_listener(ui_listener);
    // Local operator channel: a filesystem-guarded admin socket so a locked-down
    // (restricted / NoNewSites) node can still be administered server-side.
    #[cfg(unix)]
    server.spawn_admin_socket(opts.data_root.join("admin.sock"));
    Ok((server, RunningNode { state, display, address, ui_addr: bind }))
}

fn resolve_cache_path(data_root: &std::path::Path) -> PathBuf {
    data_root.join("resolve-cache.json")
}

type ResolveCachePathLocks =
    std::sync::Mutex<std::collections::HashMap<PathBuf, std::sync::Weak<std::sync::Mutex<()>>>>;

fn canonical_resolve_cache_path(path: &std::path::Path) -> PathBuf {
    // `data_root` is normally absolute. Canonicalizing the parent also makes
    // syntactically different paths to a not-yet-created cache share a lock.
    path.canonicalize().unwrap_or_else(|_| {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())
            .and_then(|parent| path.file_name().map(|name| parent.join(name)))
            .unwrap_or_else(|| {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(path)
                }
            })
    })
}

fn resolve_cache_lock(path: &std::path::Path) -> Arc<std::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<ResolveCachePathLocks> = std::sync::OnceLock::new();

    let key = canonical_resolve_cache_path(path);
    let locks = LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut locks = locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(lock) = locks.get(&key).and_then(std::sync::Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(std::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

fn resolve_cache_process_lock(
    path: &std::path::Path,
) -> std::io::Result<fslock_guard::LockFileGuard> {
    let canonical = canonical_resolve_cache_path(path);
    let file_name = canonical.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "resolve cache path has no file name: {}",
                canonical.display()
            ),
        )
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    fslock_guard::LockFileGuard::lock(canonical.with_file_name(lock_name))
}

/// How long a cached xID resolution stays fresh. Within this window the chain
/// is never consulted for that name; after it, the next lookup re-resolves
/// (falling back to the stale entry if the chain is unreachable).
pub const RESOLVE_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Look up a name in the resolve cache: `Some((address, fresh))` where `fresh`
/// says the entry is within [`RESOLVE_CACHE_TTL_SECS`]. When finality is active,
/// a name entry is accepted only if it carries the exact height and digest of
/// the current durable checkpoint. Legacy unbound entries become cache misses.
fn cached_resolution(data_root: &std::path::Path, full: &str) -> Option<(String, bool)> {
    let cache = read_resolve_cache(data_root);
    let finality_required =
        epix_chain::verify_finality_enabled() && cache_target_requires_finality(full);
    parse_cached_resolution(cache.get(full)?, finality_required, |height, digest| {
        epix_chain::finality_checkpoint_matches(height, digest)
    })
}

fn cache_target_requires_finality(full: &str) -> bool {
    let (label, tld) = full.rsplit_once('.').unwrap_or((full, "epix"));
    !(tld == "epix" && epix_core::classify_label(label) == epix_core::LabelClass::Address)
}

fn parse_cached_resolution(
    value: &serde_json::Value,
    finality_required: bool,
    binding_current: impl Fn(u64, &str) -> bool,
) -> Option<(String, bool)> {
    match value {
        serde_json::Value::String(address) if !finality_required => Some((address.clone(), false)),
        serde_json::Value::String(_) => None,
        serde_json::Value::Object(entry) => {
            if finality_required {
                let height = entry.get("finality_height")?.as_u64()?;
                let digest = entry.get("finality_digest")?.as_str()?;
                if !binding_current(height, digest) {
                    return None;
                }
            }
            let address = entry.get("address")?.as_str()?.to_string();
            let resolved_at = entry.get("resolved_at").and_then(|v| v.as_u64()).unwrap_or(0);
            let fresh = now_secs().saturating_sub(resolved_at) < RESOLVE_CACHE_TTL_SECS;
            Some((address, fresh))
        }
        _ => None,
    }
}

fn read_resolve_cache(data_root: &std::path::Path) -> serde_json::Map<String, serde_json::Value> {
    read_resolve_cache_for_update(&resolve_cache_path(data_root)).unwrap_or_default()
}

fn read_resolve_cache_for_update(
    path: &std::path::Path,
) -> std::io::Result<serde_json::Map<String, serde_json::Value>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid resolve cache {}: {error}", path.display()),
        )
    })
}

static RESOLVE_CACHE_TEMP_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct ResolveCacheTemp {
    path: PathBuf,
}

impl Drop for ResolveCacheTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn create_resolve_cache_temp(
    destination: &std::path::Path,
) -> std::io::Result<(ResolveCacheTemp, std::fs::File)> {
    let parent = destination.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "resolve cache path has no parent: {}",
                destination.display()
            ),
        )
    })?;
    let name = destination
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("resolve-cache.json");
    for _ in 0..128 {
        let id = RESOLVE_CACHE_TEMP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = parent.join(format!(".{name}.tmp-{}-{id}", std::process::id()));
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
        {
            Ok(file) => return Ok((ResolveCacheTemp { path }, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "could not allocate a temporary resolve cache beside {}",
            destination.display()
        ),
    ))
}

#[cfg(windows)]
fn replace_resolve_cache_durable(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: both buffers are NUL-terminated and live for the duration of the
    // call. The flags request an atomic replacement with write-through.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_resolve_cache_durable(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

fn persist_resolve_cache_atomic(
    destination: &std::path::Path,
    bytes: &[u8],
    publish: impl FnOnce(&std::path::Path, &std::path::Path) -> std::io::Result<bool>,
) -> std::io::Result<bool> {
    use std::io::Write as _;

    let (temporary, mut file) = create_resolve_cache_temp(destination)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    // For finality-bound writes this callback holds the durable checkpoint lock
    // across `publish_resolve_cache_temp`, closing the check-to-rename gap.
    publish(&temporary.path, destination)
}

fn publish_resolve_cache_temp(
    temporary: &std::path::Path,
    destination: &std::path::Path,
) -> std::io::Result<()> {
    replace_resolve_cache_durable(temporary, destination)?;

    #[cfg(unix)]
    {
        let parent = destination.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "resolve cache path has no parent: {}",
                    destination.display()
                ),
            )
        })?;
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Record a fresh chain resolution: `{"address": …, "resolved_at": now}`.
/// Unbound writes remain available for explicit legacy-mode callers. They are
/// never accepted for a name after client-side finality is enabled.
#[cfg(test)]
fn write_resolve_cache(data_root: &std::path::Path, full: &str, address: &str) {
    write_resolve_cache_bound(data_root, full, address, None);
}

#[derive(Debug, Eq, PartialEq)]
enum ResolveCacheWriteOutcome {
    Published,
    Superseded,
}

fn write_resolve_cache_bound(
    data_root: &std::path::Path,
    full: &str,
    address: &str,
    binding: Option<&(u64, String)>,
) {
    let finality_required =
        epix_chain::verify_finality_enabled() && cache_target_requires_finality(full);
    let _ = write_resolve_cache_bound_checked(
        data_root,
        full,
        address,
        binding,
        finality_required,
        |height, digest, temporary, destination| {
            match epix_chain::publish_if_finality_checkpoint_current(height, digest, || {
                publish_resolve_cache_temp(temporary, destination)
            }) {
                Some(result) => {
                    result?;
                    Ok(true)
                }
                None => Ok(false),
            }
        },
    );
}

fn write_resolve_cache_bound_checked(
    data_root: &std::path::Path,
    full: &str,
    address: &str,
    binding: Option<&(u64, String)>,
    finality_required: bool,
    publish_if_current: impl FnOnce(
        u64,
        &str,
        &std::path::Path,
        &std::path::Path,
    ) -> std::io::Result<bool>,
) -> std::io::Result<ResolveCacheWriteOutcome> {
    let path = resolve_cache_path(data_root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if finality_required && binding.is_none() {
        return Ok(ResolveCacheWriteOutcome::Superseded);
    }

    let lock = resolve_cache_lock(&path);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // The Arc mutex serializes tasks in this process. The lock file extends the
    // same read-modify-write critical section across separate node processes
    // that share a data root.
    let _process_guard = resolve_cache_process_lock(&path)?;
    let mut cache = read_resolve_cache_for_update(&path)?;

    // A delayed writer must never downgrade a newer binding already published
    // for the same name, even if its caller supplies a faulty current-binding
    // predicate.
    if let Some((height, _)) = binding {
        let existing_height = cache
            .get(full)
            .and_then(serde_json::Value::as_object)
            .and_then(|entry| entry.get("finality_height"))
            .and_then(serde_json::Value::as_u64);
        if existing_height.is_some_and(|existing| existing > *height) {
            return Ok(ResolveCacheWriteOutcome::Superseded);
        }
    }

    let mut entry = serde_json::json!({
        "address": address,
        "resolved_at": now_secs(),
    });
    if let Some((height, digest)) = binding {
        entry["finality_height"] = serde_json::json!(height);
        entry["finality_digest"] = serde_json::json!(digest);
    }
    cache.insert(full.to_string(), entry);
    let bytes = serde_json::to_vec_pretty(&cache).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cannot serialize resolve cache {}: {error}", path.display()),
        )
    })?;
    let published = persist_resolve_cache_atomic(&path, &bytes, |temporary, destination| {
        if let Some((height, digest)) = binding {
            publish_if_current(*height, digest, temporary, destination)
        } else {
            publish_resolve_cache_temp(temporary, destination)?;
            Ok(true)
        }
    })?;
    Ok(if published {
        ResolveCacheWriteOutcome::Published
    } else {
        ResolveCacheWriteOutcome::Superseded
    })
}

/// Read the private per-run native-messaging token written by the node.
pub fn read_nmh_auth_token(data_root: &std::path::Path) -> Result<String, String> {
    let path = data_root.join(NMH_TOKEN_RELATIVE_PATH);
    let encoded = std::fs::read(&path)
        .map_err(|e| format!("cannot read native-messaging token {}: {e}", path.display()))?;
    let token = decode_nmh_token(&encoded)?;
    let token = token.trim().to_string();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "native-messaging token {} is malformed",
            path.display()
        ));
    }
    Ok(token)
}

fn write_nmh_auth_token(data_root: &std::path::Path, token: &str) -> Result<(), String> {
    use std::io::Write as _;

    let path = data_root.join(NMH_TOKEN_RELATIVE_PATH);
    let parent = path.parent().ok_or_else(|| {
        format!(
            "native-messaging token path has no parent: {}",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "cannot create native-messaging token directory {}: {e}",
            parent.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            format!(
                "cannot secure native-messaging token directory {}: {e}",
                parent.display()
            )
        })?;
    }

    // DPAPI can fail. Encode before opening the live file so a protection
    // failure cannot truncate the previous run's still-usable credential.
    let encoded = encode_nmh_token(token)?;

    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|e| {
        format!(
            "cannot write native-messaging token {}: {e}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                format!(
                    "cannot secure native-messaging token {}: {e}",
                    path.display()
                )
            })?;
    }
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|e| {
            format!(
                "cannot persist native-messaging token {}: {e}",
                path.display()
            )
        })
}

#[cfg(not(windows))]
fn encode_nmh_token(token: &str) -> Result<Vec<u8>, String> {
    Ok(token.as_bytes().to_vec())
}

#[cfg(not(windows))]
fn decode_nmh_token(encoded: &[u8]) -> Result<String, String> {
    String::from_utf8(encoded.to_vec())
        .map_err(|_| "native-messaging token is not valid UTF-8".to_string())
}

/// Protect the bearer token with Windows DPAPI in the current-user scope. A
/// permissive inherited ACL then reveals only ciphertext to another account.
#[cfg(windows)]
struct LocalAllocGuard(*mut core::ffi::c_void);

#[cfg(windows)]
impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        // SAFETY: this guard is constructed only from a non-null DPAPI output
        // allocation, which the API requires callers to release with LocalFree.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}

#[cfg(windows)]
fn copy_dpapi_output(
    output: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
    operation: &str,
) -> Result<Vec<u8>, String> {
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            drop(LocalAllocGuard(output.pbData.cast()));
        }
        return Err(format!(
            "{operation} returned an empty native-messaging token buffer"
        ));
    }
    let _allocation = LocalAllocGuard(output.pbData.cast());
    // SAFETY: the non-null DPAPI output remains owned by `_allocation` and is
    // valid for exactly `cbData` bytes until the copy completes.
    Ok(unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec())
}

#[cfg(windows)]
fn encode_nmh_token(token: &str) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input_len = u32::try_from(token.len())
        .map_err(|_| "native-messaging token is too large".to_string())?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: token.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the input points to `token` for this call. DPAPI allocates the
    // output with LocalAlloc; it is copied before LocalFree.
    if unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(format!(
            "cannot protect native-messaging token: {}",
            std::io::Error::last_os_error()
        ));
    }
    copy_dpapi_output(output, "CryptProtectData")
}

#[cfg(windows)]
fn decode_nmh_token(encoded: &[u8]) -> Result<String, String> {
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input_len = u32::try_from(encoded.len())
        .map_err(|_| "protected native-messaging token is too large".to_string())?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: encoded.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: the input points to `encoded` for this call. No UI or optional
    // entropy is used. Output is copied and released with LocalFree.
    if unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(format!(
            "cannot unprotect native-messaging token for this Windows user: {}",
            std::io::Error::last_os_error()
        ));
    }
    let bytes = copy_dpapi_output(output, "CryptUnprotectData")?;
    String::from_utf8(bytes)
        .map_err(|_| "unprotected native-messaging token is not valid UTF-8".to_string())
}

/// The shared data root: `EPIX_DATA_DIR` if set, else the `data_dir`
/// configured in the default location's `epixnet.conf`, else the conventional
/// per-OS application-data location (`~/Library/Application Support/EpixNet`
/// on macOS, `%APPDATA%\EpixNet` on Windows, `$XDG_DATA_HOME/EpixNet` or
/// `~/.local/share/EpixNet` on Linux). Shared by the server binary and the
/// desktop browser so they use one identity, xite set, and Tor state.
pub fn data_root() -> PathBuf {
    epix_ui::paths::data_root()
}

/// Open `url` in the default browser (best effort, platform-specific).
pub fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, &[&str]) = ("open", &[]);
    #[cfg(target_os = "windows")]
    let (cmd, args): (&str, &[&str]) = ("cmd", &["/C", "start", ""]);
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let (cmd, args): (&str, &[&str]) = ("xdg-open", &[]);
    let _ = std::process::Command::new(cmd).args(args).arg(url).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_finality_pin_requires_explicit_legacy_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("xid_pin.json");
        let err = read_xid_finality_pin(&pin, false).unwrap_err();
        assert!(err.contains(ALLOW_INSECURE_XID_LEGACY_ENV));
        assert_eq!(read_xid_finality_pin(&pin, true).unwrap(), None);
    }

    #[test]
    fn finality_pin_read_errors_never_downgrade() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("xid_pin.json");
        std::fs::create_dir(&pin).unwrap();
        let err = read_xid_finality_pin(&pin, true).unwrap_err();
        assert!(err.contains("Refusing to downgrade"));
    }

    #[test]
    fn present_finality_pin_is_returned_in_both_modes() {
        let dir = tempfile::tempdir().unwrap();
        let pin = dir.path().join("xid_pin.json");
        std::fs::write(&pin, b"trusted bytes").unwrap();
        assert_eq!(
            read_xid_finality_pin(&pin, false).unwrap(),
            Some(b"trusted bytes".to_vec())
        );
        assert_eq!(
            read_xid_finality_pin(&pin, true).unwrap(),
            Some(b"trusted bytes".to_vec())
        );
    }

    fn entries(names: &[&str]) -> Vec<epix_xite::FileEntry> {
        names
            .iter()
            .map(|n| epix_xite::FileEntry {
                inner_path: (*n).to_string(),
                size: 0,
                sha512: String::new(),
            })
            .collect()
    }

    fn signed_manifest(mut content: serde_json::Value, privatekey: &str) -> Vec<u8> {
        epix_content::sign(&mut content, privatekey).unwrap();
        serde_json::to_vec(&content).unwrap()
    }

    fn address_for_privatekey(privatekey: &str) -> String {
        let signed = signed_manifest(serde_json::json!({}), privatekey);
        let content: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        content["signs"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone()
    }

    #[test]
    fn skipped_level_name_signed_child_uses_verified_root_governor() {
        let owner_key = "01".repeat(32);
        let address = address_for_privatekey(&owner_key);
        let admin_key = "02".repeat(32);
        let admin = address_for_privatekey(&admin_key);
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed_manifest(
                    serde_json::json!({
                        "address": address,
                        "modified": 1,
                        "files": {},
                        "includes": {
                            "deep/path/content.json": {
                                "signers": ["admin.epix"],
                                "signers_required": 1
                            }
                        }
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        let child = signed_manifest(
            serde_json::json!({
                "address": address,
                "inner_path": "deep/path/content.json",
                "modified": 2,
                "files": {}
            }),
            &admin_key,
        );
        storage.write("deep/path/content.json", &child).unwrap();
        storage
            .write(
                "deep/content.json",
                br#"{"inner_path":"deep/content.json","user_contents":{}}"#,
            )
            .unwrap();

        let mut xite = Xite::new(Address::parse(address).unwrap(), storage);
        assert!(xite.load_content().unwrap());
        assert_eq!(
            xite.governing_content_path("deep/path/content.json").as_deref(),
            Some("deep/content.json"),
            "the corrupt closer manifest shadows a disk-backed parent lookup"
        );
        let mut walk = xite
            .begin_verified_manifest_walk(vec!["deep/path/content.json".to_string()], 2)
            .unwrap()
            .unwrap();
        let governing = xite
            .next_stored_manifest_governing_path(&walk, "deep/path/content.json")
            .unwrap()
            .unwrap();
        assert_eq!(governing, "content.json");
        let parent: serde_json::Value =
            serde_json::from_slice(&xite.storage().read(&governing).unwrap()).unwrap();
        assert_eq!(
            epix_content::verify::content_xid_names(&parent, "deep/path/content.json"),
            vec!["admin.epix".to_string()]
        );
        let xid_map = std::collections::HashMap::from([(
            "admin.epix".to_string(),
            vec![epix_content::XidIdentity {
                address: admin,
                active: true,
                revoked_at_time: 0,
            }],
        )]);
        let verified = xite
            .verify_next_stored_manifest(&mut walk, "deep/path/content.json", &xid_map)
            .unwrap()
            .unwrap();
        assert_eq!(verified.governing_path(), "content.json");
    }

    /// A failed clone has to name the file that blocked it: a bare count left
    /// no way to tell an unreachable seeder from a file no peer can ever
    /// serve, which is what made a single empty file so hard to track down.
    #[test]
    fn a_missing_file_error_names_the_files() {
        assert_eq!(name_sample(&entries(&["index.html"])), "index.html");
        assert_eq!(name_sample(&entries(&["a.js", "b.css"])), "a.js, b.css");
    }

    /// Bounded, so a xite missing its whole file set does not put hundreds of
    /// paths in one error line.
    #[test]
    fn a_long_missing_list_is_truncated_with_a_count() {
        let many: Vec<String> = (0..13).map(|i| format!("f{i}.bin")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let out = name_sample(&entries(&refs));
        assert!(out.starts_with("f0.bin, f1.bin, "), "keeps the first entries: {out}");
        assert!(out.ends_with("f9.bin (+3 more)"), "cuts at 10 and counts the rest: {out}");
        assert!(!out.contains("f10.bin"), "the truncated entries are not listed");
    }

    #[test]
    fn clone_display_size_totals_saturate() {
        assert_eq!(saturating_size_total([i64::MAX, 1]), i64::MAX);
        assert_eq!(saturating_size_total([-1, 2, 3]), 5);
    }

    #[tokio::test]
    async fn child_apply_retries_signer_failures_but_not_guarded_availability() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let attempts = Arc::new(AtomicUsize::new(0));
        let observed = attempts.clone();
        let outcome = retry_child_manifest_apply(|| {
            let attempt = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err("File child invalid: Valid signs: 0/1".to_string())
                } else {
                    Ok(epix_ui::state::InboundUpdate::Applied)
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(outcome, epix_ui::state::InboundUpdate::Applied);
        assert_eq!(attempts.load(Ordering::SeqCst), CHILD_APPLY_ATTEMPTS);

        let guarded_attempts = Arc::new(AtomicUsize::new(0));
        let guarded_observed = guarded_attempts.clone();
        let error = retry_child_manifest_apply(|| {
            guarded_observed.fetch_add(1, Ordering::SeqCst);
            async { Err("Child update is not yet fully available".to_string()) }
        })
        .await
        .unwrap_err();
        assert!(error.contains("not yet fully available"));
        assert_eq!(guarded_attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn child_callback_work_is_bounded_and_complete() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        const ITEMS: usize = 12;
        let (tx, rx) = tokio::sync::mpsc::channel(CHILD_MANIFEST_PAGE_SIZE);
        assert_eq!(tx.capacity(), CHILD_MANIFEST_PAGE_SIZE);
        let producer = tokio::spawn(async move {
            for item in 0..ITEMS {
                tx.send((format!("child-{item}"), Vec::new()))
                    .await
                    .unwrap();
            }
        });
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let task_active = active.clone();
        let task_max = max_active.clone();
        let (received, outcomes) = consume_bounded_child_callbacks(rx, move |_path, _bytes| {
            let active = task_active.clone();
            let max_active = task_max.clone();
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                active.fetch_sub(1, Ordering::SeqCst);
                (Ok(epix_ui::state::InboundUpdate::NotChanged), Vec::new())
            }
        })
        .await;
        producer.await.unwrap();

        assert_eq!(received.len(), ITEMS);
        assert_eq!(outcomes.len(), ITEMS);
        assert!(max_active.load(Ordering::SeqCst) <= CHILD_APPLY_CONCURRENCY);

        let names = (0..CHILD_DATA_PAGE_SIZE * 2 + 1)
            .map(|index| format!("data-{index}"))
            .collect::<Vec<_>>();
        let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let mut data = entries(&refs).into_iter();
        let mut page_sizes = Vec::new();
        loop {
            let page = next_child_data_page(&mut data);
            if page.is_empty() {
                break;
            }
            page_sizes.push(page.len());
        }
        assert_eq!(
            page_sizes,
            vec![CHILD_DATA_PAGE_SIZE, CHILD_DATA_PAGE_SIZE, 1]
        );

        let (data_tx, mut data_rx) = tokio::sync::mpsc::channel(CHILD_DATA_PAGE_SIZE);
        for index in 0..CHILD_DATA_PAGE_SIZE {
            data_tx.try_send(format!("landed-{index}")).unwrap();
        }
        let fallback = data_tx
            .try_send("verify-and-ingest".to_string())
            .unwrap_err()
            .into_inner();
        assert_eq!(fallback, "verify-and-ingest");
        assert_eq!(data_rx.len(), CHILD_DATA_PAGE_SIZE);
        drop(data_tx);
        while data_rx.recv().await.is_some() {}
    }

    #[test]
    fn legacy_child_paths_only_report_required_files_without_edx_authority() {
        let manifest = serde_json::to_vec(&serde_json::json!({
            "files": {
                "legacy.bin": { "sha512": "old", "size": 3 },
                "object.bin": { "sha512": "new", "size": 3, "b3": "abc" },
                "sharded.bin": { "sha512": "shard", "size": 3 }
            },
            "files_optional": {
                "optional.bin": { "sha512": "optional", "size": 3 }
            },
            "files_shard": {
                "sharded.bin": { "chunks": [] }
            }
        }))
        .unwrap();

        assert_eq!(
            legacy_required_paths("data/users/alice/content.json", &manifest),
            vec!["data/users/alice/legacy.bin"]
        );
        assert!(legacy_required_paths("content.json", b"not json").is_empty());
    }

    #[test]
    fn ui_bind_prefers_default_and_falls_back_to_legacy() {
        let addr = |p: u16| std::net::SocketAddr::from(([127, 0, 0, 1], p));

        // Default port free -> use it.
        assert_eq!(
            bind_ui_listener_with(
                addr(DEFAULT_UI_PORT),
                DEFAULT_UI_PORT,
                LEGACY_UI_PORT,
                |candidate| Ok::<_, std::io::Error>(candidate),
            )
            .unwrap(),
            addr(DEFAULT_UI_PORT)
        );

        // Default port taken -> fall back to the legacy EpixNet port.
        assert_eq!(
            bind_ui_listener_with(
                addr(DEFAULT_UI_PORT),
                DEFAULT_UI_PORT,
                LEGACY_UI_PORT,
                |candidate| {
                    if candidate.port() == DEFAULT_UI_PORT {
                        Err(std::io::Error::from(std::io::ErrorKind::AddrInUse))
                    } else {
                        Ok(candidate)
                    }
                },
            )
            .unwrap(),
            addr(LEGACY_UI_PORT)
        );

        // Default and legacy both taken -> fail before publishing endpoint
        // metadata instead of returning an address that is not owned.
        assert!(bind_ui_listener_with(
            addr(DEFAULT_UI_PORT),
            DEFAULT_UI_PORT,
            LEGACY_UI_PORT,
            |_candidate| Err::<std::net::SocketAddr, _>(std::io::Error::from(
                std::io::ErrorKind::AddrInUse
            )),
        )
        .is_err());

        // An explicitly chosen (non-default) port never jumps to 43110.
        let mut attempts = Vec::new();
        assert!(
            bind_ui_listener_with(addr(9999), DEFAULT_UI_PORT, LEGACY_UI_PORT, |candidate| {
                attempts.push(candidate);
                Err::<std::net::SocketAddr, _>(std::io::Error::from(std::io::ErrorKind::AddrInUse))
            },)
            .is_err()
        );
        assert_eq!(attempts, vec![addr(9999)]);
    }

    #[test]
    fn native_messaging_metadata_is_published_only_after_listener_ownership() {
        use std::cell::Cell;

        let dir = tempfile::tempdir().unwrap();
        let hijacker = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let requested = hijacker.local_addr().unwrap();
        std::fs::write(dir.path().join("ui_port"), requested.port().to_string()).unwrap();
        write_nmh_auth_token(dir.path(), &"11".repeat(32)).unwrap();

        let published = Cell::new(false);
        let token = "22".repeat(32);
        let (listener, bound, warnings) =
            bind_and_publish_ui_endpoint_with(requested, requested.port(), 0, |bound| {
                assert_ne!(bound, requested, "the occupied port must use fallback");
                assert!(
                    std::net::TcpListener::bind(bound).is_err(),
                    "publication must run only while the node owns the selected port"
                );
                published.set(true);
                publish_nmh_endpoint(dir.path(), bound, &token)
            })
            .unwrap();

        assert!(published.get());
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("ui_port")).unwrap(),
            bound.port().to_string()
        );
        assert_eq!(read_nmh_auth_token(dir.path()).unwrap(), token);
        assert!(
            std::net::TcpListener::bind(bound).is_err(),
            "UiServer must receive a retained listener, not a probe result"
        );
        drop(listener);
    }

    #[test]
    fn parse_target_strips_scheme_and_path() {
        assert_eq!(parse_target("epix://talk.epix/topic/1"), "talk.epix");
        assert_eq!(parse_target("epix://talk.epix"), "talk.epix");
        assert_eq!(parse_target("talk.epix"), "talk.epix");
        assert_eq!(parse_target("epix1abcdef"), "epix1abcdef");
        assert_eq!(parse_target("epix://dashboard.epix/?x=1#frag"), "dashboard.epix");
        // A bare scheme with no host falls back to the raw arg.
        assert_eq!(parse_target("epix://"), "epix://");
        // Full browser URLs (cold start with a URL argument, OS handoffs):
        // the scheme must never be mistaken for the host.
        assert_eq!(parse_target("https://talk.epix/?Topic:123_mud.epix"), "talk.epix");
        assert_eq!(parse_target("http://talk.epix/topic/1"), "talk.epix");
        assert_eq!(
            parse_target("https://epix1frc9dzz7paj0wqhdjc3rh9vl7zhdy3t6dcm647.epix/"),
            "epix1frc9dzz7paj0wqhdjc3rh9vl7zhdy3t6dcm647.epix"
        );
        // `://` mid-arg without a valid scheme in front is not a scheme.
        assert_eq!(parse_target("1://x"), "1:");
    }

    #[test]
    fn parse_inner_path_keeps_path_and_query() {
        assert_eq!(parse_inner_path("epix://talk.epix/topic/1"), "/topic/1");
        assert_eq!(parse_inner_path("epix://talk.epix/?q=2"), "/?q=2");
        assert_eq!(parse_inner_path("epix://talk.epix"), "");
        assert_eq!(parse_inner_path("talk.epix/a"), "/a");
        assert_eq!(parse_inner_path("https://talk.epix/?Topic:123_mud.epix"), "/?Topic:123_mud.epix");
    }

    #[test]
    fn resolve_cache_ttl_fresh_expired_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Miss.
        assert_eq!(cached_resolution(root, "talk.epix"), None);

        // A fresh write is fresh.
        write_resolve_cache(root, "talk.epix", "epix1talk");
        assert_eq!(cached_resolution(root, "talk.epix"), Some(("epix1talk".into(), true)));

        // An entry past the TTL reports expired (address still returned, so
        // callers can fall back to it when the chain is unreachable).
        let old = now_secs() - RESOLVE_CACHE_TTL_SECS - 1;
        let cache = serde_json::json!({
            "old.epix": { "address": "epix1old", "resolved_at": old },
            "legacy.epix": "epix1legacy",
        });
        std::fs::write(resolve_cache_path(root), serde_json::to_vec(&cache).unwrap()).unwrap();
        assert_eq!(cached_resolution(root, "old.epix"), Some(("epix1old".into(), false)));

        // Legacy plain-string entries: address known, treated as expired.
        assert_eq!(cached_resolution(root, "legacy.epix"), Some(("epix1legacy".into(), false)));

        // Re-writing upgrades a legacy entry to the timestamped form.
        write_resolve_cache(root, "legacy.epix", "epix1legacy");
        assert_eq!(cached_resolution(root, "legacy.epix"), Some(("epix1legacy".into(), true)));
    }

    #[test]
    fn finality_mode_rejects_unbound_or_superseded_cache_entries() {
        let unbound = serde_json::json!({
            "address": "epix1forged",
            "resolved_at": now_secs(),
        });
        assert_eq!(
            parse_cached_resolution(&unbound, true, |_height, _digest| true),
            None,
            "a fresh legacy cache entry must not bypass finality"
        );
        assert_eq!(
            parse_cached_resolution(&unbound, false, |_height, _digest| false),
            Some(("epix1forged".into(), true)),
            "explicit legacy mode keeps the compatibility cache"
        );

        let bound = serde_json::json!({
            "address": "epix1verified",
            "resolved_at": now_secs(),
            "finality_height": 42,
            "finality_digest": "11".repeat(32),
        });
        assert_eq!(
            parse_cached_resolution(&bound, true, |height, digest| {
                height == 42 && digest == "11".repeat(32)
            }),
            Some(("epix1verified".into(), true))
        );
        assert_eq!(
            parse_cached_resolution(&bound, true, |_height, _digest| false),
            None,
            "a cache binding stops being valid when the checkpoint advances"
        );

        let pinned_at = 1_000_000_i64;
        let ws_period = 7 * 24 * 3600;
        let pin_current_at = |now: i64| now.saturating_sub(pinned_at) <= ws_period;
        assert_eq!(
            parse_cached_resolution(&bound, true, |_height, _digest| {
                pin_current_at(pinned_at + ws_period)
            }),
            Some(("epix1verified".into(), true)),
            "the exact weak-subjectivity boundary is still usable"
        );
        assert_eq!(
            parse_cached_resolution(&bound, true, |_height, _digest| {
                pin_current_at(pinned_at + ws_period + 1)
            }),
            None,
            "after pin expiry a disk entry is a total miss, not a stale fallback"
        );
        assert_eq!(
            parse_cached_resolution(&bound, true, |height, _digest| height >= 43),
            None,
            "a height-42 cache must miss after a trusted repin at height 43"
        );
    }

    #[test]
    fn cross_process_resolve_cache_writer_worker() {
        if std::env::var_os("EPIX_RESOLVE_CACHE_WORKER").is_none() {
            return;
        }
        let root = PathBuf::from(std::env::var_os("EPIX_RESOLVE_CACHE_ROOT").unwrap());
        let ready = PathBuf::from(std::env::var_os("EPIX_RESOLVE_CACHE_READY").unwrap());
        let release = PathBuf::from(std::env::var_os("EPIX_RESOLVE_CACHE_RELEASE").unwrap());
        let binding = (41, "41".repeat(32));

        let outcome = write_resolve_cache_bound_checked(
            &root,
            "child.epix",
            "epix1child",
            Some(&binding),
            true,
            |_height, _digest, temporary, destination| {
                std::fs::write(&ready, b"ready")?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
                while !release.exists() {
                    if std::time::Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "parent never released resolve-cache writer",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                publish_resolve_cache_temp(temporary, destination)?;
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(outcome, ResolveCacheWriteOutcome::Published);
    }

    #[test]
    fn child_process_cache_writer_cannot_clobber_a_concurrent_update() {
        let dir = tempfile::tempdir().unwrap();
        let ready = dir.path().join("child-ready");
        let release = dir.path().join("release-child");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::cross_process_resolve_cache_writer_worker")
            .arg("--nocapture")
            .env("EPIX_RESOLVE_CACHE_WORKER", "1")
            .env("EPIX_RESOLVE_CACHE_ROOT", dir.path())
            .env("EPIX_RESOLVE_CACHE_READY", &ready)
            .env("EPIX_RESOLVE_CACHE_RELEASE", &release)
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "cache child did not become ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let root = dir.path().to_path_buf();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let parent_writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = write_resolve_cache_bound_checked(
                &root,
                "parent.epix",
                "epix1parent",
                None,
                false,
                |_height, _digest, _temporary, _destination| Ok(false),
            );
            finished_tx.send(()).unwrap();
            result
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "a second process must not pass the cache read-modify-write lock"
        );

        std::fs::write(&release, b"go").unwrap();
        assert!(child.wait().unwrap().success());
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .unwrap();
        assert_eq!(
            parent_writer.join().unwrap().unwrap(),
            ResolveCacheWriteOutcome::Published
        );

        let cache = read_resolve_cache_for_update(&resolve_cache_path(dir.path())).unwrap();
        assert_eq!(cache["child.epix"]["address"], "epix1child");
        assert_eq!(cache["parent.epix"]["address"], "epix1parent");
    }

    #[test]
    fn concurrent_resolve_cache_writers_do_not_lose_names_or_publish_partial_json() {
        let different = tempfile::tempdir().unwrap();
        let mut writers = Vec::new();
        for index in 0..24 {
            let root = different.path().to_path_buf();
            writers.push(std::thread::spawn(move || {
                write_resolve_cache_bound_checked(
                    &root,
                    &format!("name-{index}.epix"),
                    &format!("epix1address{index}"),
                    None,
                    false,
                    |_height, _digest, _temporary, _destination| Ok(false),
                )
                .unwrap()
            }));
        }
        for writer in writers {
            assert_eq!(writer.join().unwrap(), ResolveCacheWriteOutcome::Published);
        }
        let cache = read_resolve_cache_for_update(&resolve_cache_path(different.path())).unwrap();
        assert_eq!(cache.len(), 24, "read-modify-write must retain every name");
        for index in 0..24 {
            assert_eq!(
                cache[&format!("name-{index}.epix")]["address"],
                format!("epix1address{index}")
            );
        }

        let same = tempfile::tempdir().unwrap();
        let mut writers = Vec::new();
        for index in 0..24 {
            let root = same.path().to_path_buf();
            writers.push(std::thread::spawn(move || {
                write_resolve_cache_bound_checked(
                    &root,
                    "shared.epix",
                    &format!("epix1address{index}"),
                    None,
                    false,
                    |_height, _digest, _temporary, _destination| Ok(false),
                )
                .unwrap()
            }));
        }
        for writer in writers {
            assert_eq!(writer.join().unwrap(), ResolveCacheWriteOutcome::Published);
        }
        let bytes = std::fs::read(resolve_cache_path(same.path())).unwrap();
        let cache: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cache.len(), 1);
        let address = cache["shared.epix"]["address"].as_str().unwrap();
        assert!(address.starts_with("epix1address"));
    }

    #[test]
    fn superseded_resolve_cache_writer_cannot_overwrite_newer_binding() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let current_height = Arc::new(AtomicU64::new(41));
        let reached_final_check = Arc::new(std::sync::Barrier::new(2));
        let release_final_check = Arc::new(std::sync::Barrier::new(2));

        let stale_root = dir.path().to_path_buf();
        let stale_height = Arc::clone(&current_height);
        let stale_reached = Arc::clone(&reached_final_check);
        let stale_release = Arc::clone(&release_final_check);
        let stale = std::thread::spawn(move || {
            let binding = (41, "41".repeat(32));
            write_resolve_cache_bound_checked(
                &stale_root,
                "talk.epix",
                "epix1stale",
                Some(&binding),
                true,
                move |height, digest, temporary, destination| {
                    stale_reached.wait();
                    stale_release.wait();
                    if stale_height.load(Ordering::SeqCst) != height || digest != "41".repeat(32) {
                        return Ok(false);
                    }
                    publish_resolve_cache_temp(temporary, destination)?;
                    Ok(true)
                },
            )
            .unwrap()
        });

        reached_final_check.wait();
        current_height.store(42, Ordering::SeqCst);
        let fresh_root = dir.path().to_path_buf();
        let fresh_height = Arc::clone(&current_height);
        let fresh = std::thread::spawn(move || {
            let binding = (42, "42".repeat(32));
            write_resolve_cache_bound_checked(
                &fresh_root,
                "talk.epix",
                "epix1fresh",
                Some(&binding),
                true,
                move |height, digest, temporary, destination| {
                    if fresh_height.load(Ordering::SeqCst) != height || digest != "42".repeat(32) {
                        return Ok(false);
                    }
                    publish_resolve_cache_temp(temporary, destination)?;
                    Ok(true)
                },
            )
            .unwrap()
        });
        release_final_check.wait();

        assert_eq!(stale.join().unwrap(), ResolveCacheWriteOutcome::Superseded);
        assert_eq!(fresh.join().unwrap(), ResolveCacheWriteOutcome::Published);

        // The on-disk height check is a second line of defense. Even a faulty
        // caller that claims height 41 is current cannot downgrade height 42.
        let stale_binding = (41, "41".repeat(32));
        assert_eq!(
            write_resolve_cache_bound_checked(
                dir.path(),
                "talk.epix",
                "epix1late-stale",
                Some(&stale_binding),
                true,
                |_height, _digest, temporary, destination| {
                    publish_resolve_cache_temp(temporary, destination)?;
                    Ok(true)
                },
            )
            .unwrap(),
            ResolveCacheWriteOutcome::Superseded
        );
        let cache = read_resolve_cache_for_update(&resolve_cache_path(dir.path())).unwrap();
        assert_eq!(cache["talk.epix"]["address"], "epix1fresh");
        assert_eq!(cache["talk.epix"]["finality_height"], 42);
    }

    #[test]
    fn failed_or_truncated_resolve_cache_publication_retains_prior_file() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let path = resolve_cache_path(dir.path());
        assert_eq!(
            write_resolve_cache_bound_checked(
                dir.path(),
                "talk.epix",
                "epix1prior",
                None,
                false,
                |_height, _digest, _temporary, _destination| Ok(false),
            )
            .unwrap(),
            ResolveCacheWriteOutcome::Published
        );
        let prior = std::fs::read(&path).unwrap();

        let replacement = serde_json::to_vec(&serde_json::json!({
            "talk.epix": { "address": "epix1replacement", "resolved_at": now_secs() }
        }))
        .unwrap();
        let error = persist_resolve_cache_atomic(&path, &replacement, |temporary, _destination| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(temporary)?;
            file.write_all(b"{")?;
            file.sync_all()?;
            Err(std::io::Error::other("injected publication failure"))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(std::fs::read(&path).unwrap(), prior);
        assert_eq!(
            read_resolve_cache_for_update(&path).unwrap()["talk.epix"]["address"],
            "epix1prior"
        );

        // A corrupt visible cache is a miss and is not silently replaced from
        // an empty map by a later read-modify-write.
        std::fs::write(&path, b"{").unwrap();
        assert_eq!(cached_resolution(dir.path(), "talk.epix"), None);
        assert!(write_resolve_cache_bound_checked(
            dir.path(),
            "other.epix",
            "epix1other",
            None,
            false,
            |_height, _digest, _temporary, _destination| Ok(false),
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{");
    }

    #[test]
    fn native_messaging_token_is_private_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let token = "ab".repeat(32);
        write_nmh_auth_token(dir.path(), &token).unwrap();
        assert_eq!(read_nmh_auth_token(dir.path()).unwrap(), token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let path = dir.path().join(NMH_TOKEN_RELATIVE_PATH);
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(dir.path().join("private"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        let rotated = "cd".repeat(32);
        write_nmh_auth_token(dir.path(), &rotated).unwrap();
        assert_eq!(read_nmh_auth_token(dir.path()).unwrap(), rotated);

        std::fs::write(dir.path().join(NMH_TOKEN_RELATIVE_PATH), "not-a-token").unwrap();
        assert!(read_nmh_auth_token(dir.path()).is_err());
    }

    #[test]
    fn cached_launch_uses_cache_only_and_defers_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";

        // A checksum-valid address passes straight through in either form.
        assert_eq!(
            cached_launch(root, DASH).unwrap(),
            Some((DASH.into(), DASH.into()))
        );
        assert_eq!(
            cached_launch(root, &format!("{DASH}.epix")).unwrap(),
            Some((DASH.into(), DASH.into()))
        );

        // An uncached name has no cache hit -> None (boot defers it).
        assert_eq!(cached_launch(root, "talk.epix").unwrap(), None);
        assert_eq!(cached_launch(root, "epix1shop").unwrap(), None);

        // Once cached it resolves from disk without touching the chain, keyed by
        // the full name (matching how resolve_target writes it).
        write_resolve_cache(root, "talk.epix", DASH);
        assert_eq!(
            cached_launch(root, "talk.epix").unwrap(),
            Some((DASH.into(), "talk.epix".into()))
        );

        // A bare label defaults to the epix TLD for both lookup and display.
        write_resolve_cache(root, "blog.epix", DASH);
        assert_eq!(
            cached_launch(root, "blog").unwrap(),
            Some((DASH.into(), "blog.epix".into()))
        );

        // A bad-checksum address shape is rejected before a forged cache entry
        // can turn it into a name.
        let typo = format!("{}q", &DASH[..DASH.len() - 1]);
        write_resolve_cache(root, &format!("{typo}.epix"), "epix1forged");
        assert!(cached_launch(root, &typo).is_err());
    }

    #[test]
    fn needs_chain_resolve_only_on_a_total_cache_miss() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Either alias of a real address never queries the chain, and an
        // address-shaped label (bad checksum, the typo-space around real
        // addresses) is refused - neither waits on Tor.
        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        assert!(!needs_chain_resolve(root, DASH));
        assert!(!needs_chain_resolve(root, &format!("{DASH}.epix")));
        let typo = format!("{}q", &DASH[..DASH.len() - 1]);
        assert!(!needs_chain_resolve(root, &typo));
        assert!(!needs_chain_resolve(root, &format!("{typo}.epix")));

        // A short `epix1…` branding label is an ordinary NAME: with no cache
        // entry it must hit the chain (the old prefix-only check shadowed it).
        assert!(needs_chain_resolve(root, "epix1shop"));
        assert!(needs_chain_resolve(root, "epix1shop.epix"));

        // A name with no cache entry must hit the chain (and can't fall back),
        // so Always mode waits for Tor first.
        assert!(needs_chain_resolve(root, "talk.epix"));

        // A fresh entry resolves from cache - no wait.
        write_resolve_cache(root, "talk.epix", DASH);
        assert!(!needs_chain_resolve(root, "talk.epix"));

        // A stale entry still serves its stale mapping if the chain is
        // unreachable, so it needs no Tor wait either.
        let old = now_secs() - RESOLVE_CACHE_TTL_SECS - 1;
        let cache = serde_json::json!({
            "old.epix": { "address": DASH, "resolved_at": old }
        });
        std::fs::write(
            resolve_cache_path(root),
            serde_json::to_vec(&cache).unwrap(),
        )
        .unwrap();
        assert!(!needs_chain_resolve(root, "old.epix"));
    }

    #[test]
    fn launch_display_normalizes_names_and_addresses() {
        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        assert_eq!(launch_display("talk.epix").unwrap(), "talk.epix");
        assert_eq!(launch_display("blog").unwrap(), "blog.epix");
        assert_eq!(launch_display("epix1shop").unwrap(), "epix1shop.epix");
        assert_eq!(launch_display(DASH).unwrap(), DASH);
        assert_eq!(launch_display(&format!("{DASH}.epix")).unwrap(), DASH);

        let typo = format!("{}q", &DASH[..DASH.len() - 1]);
        assert!(launch_display(&typo).is_err());
    }

    #[tokio::test]
    async fn resolve_target_rejects_bad_checksum_and_resolves_bare_epix1_name() {
        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let typo = format!("{}q", &DASH[..DASH.len() - 1]);

        write_resolve_cache(root, &format!("{typo}.epix"), "epix1forged");
        let error = resolve_target(root, &typo).await.unwrap_err();
        assert!(error.contains("bad checksum"), "{error}");

        write_resolve_cache(root, "epix1shop.epix", DASH);
        assert_eq!(
            resolve_target(root, "epix1shop").await.unwrap(),
            (DASH.into(), "epix1shop.epix".into(), true)
        );
        assert_eq!(
            resolve_target(root, DASH).await.unwrap(),
            (DASH.into(), DASH.into(), false)
        );
    }

    #[test]
    fn untrusted_xid_addresses_never_escape_data_root_or_survive_cache() {
        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let container = tempfile::tempdir().unwrap();
        let data_root = container.path().join("node");
        std::fs::create_dir_all(&data_root).unwrap();
        let opts = NodeOptions::new(&data_root, DASH);
        let absolute_escape = container.path().join("absolute-escape");
        let traversal_escape = container.path().join("traversal-escape");
        let absolute = absolute_escape.to_string_lossy().into_owned();
        let traversal = "../../traversal-escape".to_string();
        let invalid_bech32 = "epix1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string();

        for invalid in [&absolute, &traversal, &invalid_bech32] {
            assert!(validated_xite_address(invalid, "test xID record").is_err());
            assert!(resolved_launch(&opts, invalid.clone(), "evil.epix".into()).is_err());
        }
        assert!(!absolute_escape.exists());
        assert!(!traversal_escape.exists());
        assert!(
            !data_root.join("data").exists(),
            "validation must run before any address-derived directory is created"
        );

        let cache = serde_json::json!({
            "absolute.epix": { "address": absolute, "resolved_at": now_secs() },
            "traversal.epix": { "address": traversal, "resolved_at": now_secs() },
            "invalid.epix": { "address": invalid_bech32, "resolved_at": now_secs() },
        });
        std::fs::write(
            resolve_cache_path(&data_root),
            serde_json::to_vec(&cache).unwrap(),
        )
        .unwrap();
        for name in ["absolute.epix", "traversal.epix", "invalid.epix"] {
            assert_eq!(validated_cached_resolution(&data_root, name), None);
            assert_eq!(cached_launch(&data_root, name).unwrap(), None);
        }

        let launch = resolved_launch(&opts, DASH.into(), "safe.epix".into()).unwrap();
        let LaunchTarget::Resolved { data_dir, .. } = launch else {
            panic!("valid address must produce a resolved launch");
        };
        assert_eq!(data_dir, data_root.join("data").join(DASH));
        assert!(data_dir.is_dir());
    }

    #[test]
    fn startup_network_policy_is_strict_and_preserves_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("private")).unwrap();
        let opts = |tor: &str| NodeOptions { tor_mode: tor.to_string(), ..Default::default() };
        let write_config = |v: serde_json::Value| {
            std::fs::write(root.join("private").join("config.json"), serde_json::to_vec(&v).unwrap())
                .unwrap();
        };

        // No config, no option -> defaults to enable (not Always).
        assert_eq!(
            startup_network_policy(root, &opts("")).unwrap(),
            StartupNetworkPolicy::Direct
        );

        // An explicit option wins over config.
        assert_eq!(
            startup_network_policy(root, &opts("always")).unwrap(),
            StartupNetworkPolicy::TorAlways
        );

        // Config chooses Always when no option is given.
        write_config(serde_json::json!({ "tor": "always" }));
        assert_eq!(
            startup_network_policy(root, &opts("")).unwrap(),
            StartupNetworkPolicy::TorAlways
        );

        // Offline forces the no-egress policy regardless of the Tor choice.
        write_config(serde_json::json!({ "tor": "always", "offline": true }));
        assert_eq!(
            startup_network_policy(root, &opts("")).unwrap(),
            StartupNetworkPolicy::Offline
        );

        // A malformed field is rejected even if offline would otherwise hide it.
        write_config(serde_json::json!({ "tor": 1, "offline": true }));
        assert!(startup_network_policy(root, &opts("")).is_err());
        write_config(serde_json::json!({ "tor": "mystery" }));
        assert!(startup_network_policy(root, &opts("")).is_err());

        let config_path = root.join("private").join("config.json");
        std::fs::remove_file(&config_path).unwrap();
        std::fs::create_dir(&config_path).unwrap();
        let error = startup_network_policy(root, &opts("")).unwrap_err();
        assert!(error.contains("cannot read node config"), "{error}");
    }

    #[tokio::test]
    async fn offline_uncached_launch_arms_no_egress_without_calling_resolver() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(
            root.join("private").join("config.json"),
            serde_json::to_vec(&serde_json::json!({ "offline": true })).unwrap(),
        )
        .unwrap();
        let opts = NodeOptions::new(root, "uncached.epix");
        let armed = Arc::new(std::sync::Mutex::new(None));
        let resolver_called = Arc::new(AtomicBool::new(false));

        let armed_for_hook = armed.clone();
        let called_for_resolver = resolver_called.clone();
        let (launch, policy) = prepare_startup_launch_with(
            &opts,
            move |policy| *armed_for_hook.lock().unwrap() = Some(policy),
            move |_data_root, _target| {
                called_for_resolver.store(true, Ordering::SeqCst);
                async { Err::<(String, String, bool), String>("resolver called".into()) }
            },
        )
        .await
        .unwrap();

        assert_eq!(policy, StartupNetworkPolicy::Offline);
        assert_eq!(*armed.lock().unwrap(), Some(StartupNetworkPolicy::Offline));
        assert!(!resolver_called.load(Ordering::SeqCst));
        let LaunchTarget::Deferred { display } = launch else {
            panic!("an uncached offline launch must remain deferred");
        };
        assert_eq!(display, "uncached.epix");
    }

    #[tokio::test]
    async fn malformed_config_stops_before_route_or_resolver_egress() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(root.join("private").join("config.json"), b"{").unwrap();
        let opts = NodeOptions::new(root, "uncached.epix");
        let route_armed = Arc::new(AtomicBool::new(false));
        let resolver_called = Arc::new(AtomicBool::new(false));

        let armed_for_hook = route_armed.clone();
        let called_for_resolver = resolver_called.clone();
        let result = prepare_startup_launch_with(
            &opts,
            move |_policy| armed_for_hook.store(true, Ordering::SeqCst),
            move |_data_root, _target| {
                called_for_resolver.store(true, Ordering::SeqCst);
                async { Err::<(String, String, bool), String>("resolver called".into()) }
            },
        )
        .await;
        let error = match result {
            Ok(_) => panic!("malformed config must stop startup"),
            Err(error) => error,
        };

        assert!(error.contains("invalid node config"), "{error}");
        assert!(!route_armed.load(Ordering::SeqCst));
        assert!(!resolver_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn offline_on_demand_never_dials_tracker_for_raw_or_incomplete_target() {
        use epix_ui::OnDemandResolver as _;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingTransport(Arc<AtomicUsize>);

        #[async_trait::async_trait]
        impl Transport for CountingTransport {
            fn scheme(&self) -> &'static str {
                "tcp"
            }

            async fn dial(
                &self,
                _addr: &PeerAddr,
            ) -> epix_core::Result<epix_transport::PeerStream> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(epix_core::Error::Other("counting transport dial".into()))
            }
        }

        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("test", dir.path());
        let dials = Arc::new(AtomicUsize::new(0));
        state
            .set_transport(Arc::new(CountingTransport(dials.clone())))
            .await;
        let tracker = epix_xite::Tracker::Epix(PeerAddr::Ip("127.0.0.1:48333".parse().unwrap()));
        let on_demand = OnDemand {
            state: state.clone(),
            data_root: dir.path().to_path_buf(),
            trackers: vec![tracker],
            network_disabled: true,
            // Offline mode fails closed before any clone detaches, so the
            // test never needs a live self-handle.
            me: std::sync::Weak::new(),
            in_flight: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            in_flight_token: std::sync::atomic::AtomicU64::new(0),
            tor_expected: std::sync::atomic::AtomicBool::new(false),
            tor_always: std::sync::atomic::AtomicBool::new(false),
        };

        // A raw address that is not local would normally announce to the Epix
        // tracker through the counting transport and then clone from peers.
        let error = on_demand.ensure(DASH).await.unwrap_err();
        assert!(error.contains("offline mode"), "{error}");
        assert!(!state.has_xite(DASH).await);

        // A registered but interrupted xite would normally resume the same
        // network flow. Offline mode must leave it untouched too.
        let data_dir = dir.path().join("data").join(DASH);
        std::fs::create_dir_all(&data_dir).unwrap();
        state
            .add_xite(
                DASH,
                XiteEntry {
                    storage: XiteStorage::new(&data_dir),
                    content: None,
                },
            )
            .await;
        assert!(!state.xite_core_complete(DASH).await);
        let error = on_demand.ensure(DASH).await.unwrap_err();
        assert!(error.contains("offline mode"), "{error}");

        // A complete local working copy still opens without networking.
        std::fs::write(data_dir.join("content.json"), br#"{"files":{}}"#).unwrap();
        assert!(state.xite_core_complete(DASH).await);
        on_demand.ensure(DASH).await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn offline_transport_blocks_restored_peer_before_any_network_dial() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingTransport(Arc<AtomicUsize>);

        #[async_trait::async_trait]
        impl Transport for CountingTransport {
            fn scheme(&self) -> &'static str {
                "tcp"
            }

            async fn dial(
                &self,
                _addr: &PeerAddr,
            ) -> epix_core::Result<epix_transport::PeerStream> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(epix_core::Error::Other("counting transport dial".into()))
            }
        }

        const DASH: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data").join(DASH);
        std::fs::create_dir_all(&data_dir).unwrap();
        let state = AppState::with_data_dir("test", dir.path());
        state
            .add_xite(
                DASH,
                XiteEntry {
                    storage: XiteStorage::new(data_dir),
                    content: None,
                },
            )
            .await;
        let peer = PeerAddr::Ip("127.0.0.1:48333".parse().unwrap());
        state.add_peers(DASH, [peer.clone()]).await;

        let dials = Arc::new(AtomicUsize::new(0));
        let selected =
            transport_for_network_policy(true, Arc::new(CountingTransport(dials.clone())));
        state.set_transport(selected).await;

        let result = state.edx_get_trackers(peer).await;
        assert!(!matches!(result, Some(Ok(_))));
        assert_eq!(
            dials.load(Ordering::SeqCst),
            0,
            "offline policy must reject before the configured network transport"
        );
    }

    #[test]
    fn apply_legacy_conf_seeds_missing_keys_and_reports_ignored() {
        use std::collections::BTreeMap;
        let conf: BTreeMap<String, String> = [
            ("tor", "always"),
            ("fileserver_port", "48333"),
            ("language", "fr"),
            ("data_dir", "/somewhere"), // used elsewhere, never "ignored"
            ("ui_port", "42222"),       // used elsewhere (server bind)
            ("ui_host", "gateway.epixnet.io"), // gateway-mode: unsupported
            ("chain_rpc_url", "https://api.epix.zone"), // resolver URL: unsupported
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        // config.json already pins `tor`: the Config page's choice must win.
        let mut cfg = serde_json::Map::new();
        cfg.insert("tor".into(), serde_json::json!("disable"));

        let (mut seeded, mut ignored) = apply_legacy_conf(&conf, &mut cfg);
        seeded.sort();
        ignored.sort();

        // `tor` was present, so it is not reseeded; the other two mapped keys are.
        assert_eq!(seeded, vec!["fileserver_port".to_string(), "language".to_string()]);
        assert_eq!(cfg.get("tor").unwrap(), &serde_json::json!("disable"), "config.json wins");
        assert_eq!(cfg.get("fileserver_port").unwrap(), &serde_json::json!("48333"));
        assert_eq!(cfg.get("language").unwrap(), &serde_json::json!("fr"));
        // Only unsupported keys are reported ignored - not data_dir / ui_port.
        assert_eq!(ignored, vec!["chain_rpc_url".to_string(), "ui_host".to_string()]);
    }

    #[test]
    fn legacy_ui_addr_defaults_the_missing_half() {
        use std::collections::BTreeMap;
        let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        assert_eq!(legacy_ui_addr(&map(&[])), None);
        assert_eq!(legacy_ui_addr(&map(&[("ui_port", "8080")])).as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(legacy_ui_addr(&map(&[("ui_ip", "0.0.0.0")])).as_deref(), Some("0.0.0.0:42222"));
        assert_eq!(
            legacy_ui_addr(&map(&[("ui_ip", "0.0.0.0"), ("ui_port", "80")])).as_deref(),
            Some("0.0.0.0:80")
        );
    }
}
