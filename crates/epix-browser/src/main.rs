//! The Epix desktop browser.
//!
//! Workstream B: a launcher that bundles the node with **real Firefox** so you
//! get a genuine browser (extensions and all), not a WebView. It:
//!
//! 1. boots the embedded node ([`epix_node`]) - the same engine the server
//!    binary runs, with in-process Tor;
//! 2. serves a browser proxy that Firefox routes every `*.epix` host to. The
//!    proxy TLS-terminates with a per-host leaf cert from a local CA Firefox
//!    trusts, so `https://dashboard.epix/` is a real secure context;
//! 3. writes a managed Firefox profile (PAC -> proxy, trust the CA, prefs) and
//!    launches Firefox at `https://<xite>/`;
//! 4. shuts the node down when Firefox exits.

mod ca;
mod ext;
mod ipc;
mod proxy;
mod tray;

use ca::LocalCa;
use std::io::Write;

// GeoIP city DB for the sidebar globe's peer-location dots. Bundled the same way
// the standalone server ships it; without it the node disables the map and no
// dots render (the desktop browser used to pass None here).
const GEOIP_CITY_GZ: &[u8] = include_bytes!("../../epix-server/assets/dbip-city-lite.mmdb.gz");
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

const UI_ADDR: &str = "127.0.0.1:42222";
const PROXY_ADDR: &str = "127.0.0.1:43112";
const SOCKS_ADDR: &str = "127.0.0.1:43111";

/// The "route clearnet through Tor" setting (persisted by the native host in
/// `<data_root>/browser-settings.json`), read at launch to build the file PAC.
/// `None` when unset - the caller applies the default (on).
fn tor_clearnet_setting(data_root: &Path) -> Option<bool> {
    std::fs::read(data_root.join("browser-settings.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("tor_clearnet").and_then(|t| t.as_bool()))
}

/// Everything the tray needs once the node is up and the browser has launched.
pub struct Ready {
    pub state: Arc<epix_ui::AppState>,
    /// The `.epix` display name (or raw address) the node serves.
    pub display: String,
    pub firefox: PathBuf,
    pub profile: PathBuf,
    pub start_url: String,
    /// The scheme the managed browser uses (`https` with a trusted CA, else
    /// `http`); used to build URLs for reopen requests from later launches.
    pub scheme: String,
    pub version: String,
    /// Whether Tor / I2P are on for this run - decided at boot; the tray
    /// omits the corresponding stat line entirely when a transport is off.
    pub tor_on: bool,
    pub i2p_on: bool,
}

fn main() {
    // Single instance: the node stays running in the background, so if EpixNet
    // is already up, hand this launch's target to it and exit instead of
    // booting a second node against the same data directory.
    let raw_arg = std::env::args().nth(1).unwrap_or_else(|| "dashboard.epix".to_string());
    let open_rx = match ipc::init(&raw_arg) {
        ipc::Role::Secondary => {
            println!("· EpixNet is already running - opened {raw_arg} in it");
            return;
        }
        ipc::Role::Primary(rx) => rx,
    };

    // The tray needs the main thread for its native event loop (macOS menu bar,
    // Windows message pump), so tokio runs on its own worker threads and the
    // main thread stays free. The node's spawned tasks keep running as long as
    // this runtime is alive - the whole process lifetime, including after the
    // browser window closes.
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("could not start the async runtime: {e}");
            std::process::exit(1);
        }
    };

    let (ready, firefox_child) = rt.block_on(boot(&raw_arg));

    // Hand the main thread to the tray. It keeps the node alive after the
    // browser closes and quits it on demand. When no tray host is available
    // (headless Linux, GTK failure, EPIX_NO_TRAY), `run` logs why and hands the
    // browser process back so we fall back to the old behaviour: run until the
    // window closes, then shut down.
    let ctx = tray::TrayContext {
        ready,
        child: firefox_child,
        rt: rt.handle().clone(),
        open_rx,
    };
    if let Err(child) = tray::run(ctx) {
        tray::wait_for_browser(child);
        println!("· browser closed - shutting down the node");
    }
}

/// Boot the node, write the managed profile, install the extension, and launch
/// Firefox (non-blocking). Returns the running state the tray watches plus the
/// browser process. Fatal setup errors exit the process directly.
async fn boot(raw_arg: &str) -> (Ready, std::process::Child) {
    let target = epix_node::parse_target(raw_arg);

    let data_root = epix_node::data_root();
    if let Err(e) = std::fs::create_dir_all(&data_root) {
        eprintln!("cannot create data dir {}: {e}", data_root.display());
        std::process::exit(1);
    }

    let firefox = match find_firefox() {
        Some(p) => p,
        None => {
            eprintln!(
                "Firefox not found. Install Firefox (or Firefox ESR), or set \
                 EPIX_FIREFOX to its executable path."
            );
            std::process::exit(1);
        }
    };

    // The local CA for secure `https://*.epix` origins.
    let ca = match LocalCa::load_or_create(&data_root.join("browser-ca")) {
        Ok(ca) => Arc::new(ca),
        Err(e) => {
            eprintln!("could not set up the local CA: {e}");
            std::process::exit(1);
        }
    };

    // Boot the node and serve the plain UI on loopback.
    println!("· starting the Epix node …");
    let tor_mode = std::env::var("EPIX_TOR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "enable".into());
    let opts = epix_node::NodeOptions {
        data_root: data_root.clone(),
        target: target.clone(),
        ui_addr: UI_ADDR.to_string(),
        tor_mode: tor_mode.clone(),
        open_browser: false,
        geoip_gz: Some(GEOIP_CITY_GZ.to_vec()),
        log_file: None,
        version: env!("EPIX_VERSION").to_string(),
        rev: env!("EPIX_GIT_REV").to_string(),
    };
    let (server, running) = match epix_node::boot(opts).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("could not start the node: {e}");
            std::process::exit(1);
        }
    };
    let display = running.display.clone();
    let ui_addr = running.ui_addr;

    // The proxy serves the same router (with the transparent-proxy host rewrite)
    // over TLS + plain http. Build it before the plain server consumes `server`.
    let proxy_app =
        tower::ServiceExt::<axum::extract::Request>::map_request(server.router(), epix_ui::rewrite_proxy_host);
    tokio::spawn(async move {
        let _ = server.serve(ui_addr).await;
    });

    let proxy_addr: SocketAddr = PROXY_ADDR.parse().unwrap();
    {
        let ca = ca.clone();
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(proxy_addr).await {
                Ok(listener) => {
                    let _ = proxy::serve(listener, proxy_app, ca).await;
                }
                Err(e) => eprintln!("browser proxy bind on {proxy_addr} failed: {e}"),
            }
        });
    }

    if !wait_for_port(ui_addr, Duration::from_secs(30)).await
        || !wait_for_port(proxy_addr, Duration::from_secs(10)).await
    {
        eprintln!("the node did not come up");
        std::process::exit(1);
    }
    println!("· node serving (xite: {display}); browser proxy on {proxy_addr}");

    // Whether this Firefox will load our unsigned extension: only ESR /
    // Developer / Nightly honor `xpinstall.signatures.required=false`. Release
    // Firefox enforces signing, so the extension silently won't load there.
    let ext_capable = firefox_allows_unsigned(&firefox);

    let socks_addr: SocketAddr = SOCKS_ADDR.parse().unwrap();
    // Route clearnet through Tor by default (opt-out), but only when Tor is on -
    // otherwise there is no SOCKS listener and clearnet would break. An explicit
    // saved setting overrides the default.
    let tor_on = tor_mode != "disable";
    let tor_clearnet = tor_on && tor_clearnet_setting(&data_root).unwrap_or(true);
    if tor_clearnet {
        println!("· routing clearnet through Tor (clearnet is slower, and needs ~40s until Tor is up)");
    }

    // Write the managed profile, then inject the CA so https://*.epix is trusted.
    let profile = data_root.join("firefox-profile");
    let secure = {
        if let Err(e) =
            write_profile(&profile, proxy_addr, socks_addr, &display, true, tor_clearnet, ext_capable)
        {
            eprintln!("could not write the Firefox profile: {e}");
            std::process::exit(1);
        }
        match install_ca(&profile, &ca) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("· note: could not install the local CA ({e}); falling back to http");
                let _ = write_profile(
                    &profile, proxy_addr, socks_addr, &display, false, tor_clearnet, ext_capable,
                );
                false
            }
        }
    };

    // Install the starter chrome theme (userChrome.css) - works on any edition,
    // and is left alone once written so edits persist.
    if let Err(e) = ext::install_theme(&profile) {
        eprintln!("· note: could not install the theme: {e}");
    }

    // Install the Epix Wallet extension (wallet + clearnet-block + Tor/I2P
    // panel) and its native host.
    if ext_capable {
        // Existing profiles: drop the retired browser-ext and give the wallet
        // its toolbar slot.
        ext::migrate_legacy_extension(&profile);
        if let Err(e) = ext::install_extension(&profile) {
            eprintln!("· note: could not install the wallet extension: {e}");
        }
        if let Err(e) = ext::install_native_host() {
            eprintln!("· note: could not install the native host: {e}");
        }
        println!("· wallet extension + native host installed");
    } else {
        println!(
            "· note: {} enforces extension signing, so the clearnet-block extension \
             won't load. Use Firefox ESR or Developer Edition (the shipping bundle \
             uses ESR).",
            firefox.display()
        );
    }

    let scheme = if secure { "https" } else { "http" };
    let start_url = format!("{scheme}://{display}/");
    println!("· launching Firefox at {start_url}");
    // Spawn (not wait): the node now outlives the browser window, anchored by
    // the tray. If Firefox fails to launch we still return - the tray keeps the
    // node running and offers "Open EpixNet" to try again.
    let child = match Command::new(&firefox)
        .arg("--profile")
        .arg(&profile)
        .arg("--no-remote")
        .arg("--new-instance")
        .arg(&start_url)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("could not launch Firefox at {}: {e}", firefox.display());
            std::process::exit(1);
        }
    };

    // I2P on/off comes from the node config (the boot above defaults it to
    // "embedded" unless the user disabled it on the Config page).
    let i2p_on = running
        .state
        .config_get("i2p")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .is_some_and(|mode| mode != "disable");

    let ready = Ready {
        state: running.state.clone(),
        display,
        firefox,
        profile,
        start_url,
        scheme: scheme.to_string(),
        version: env!("EPIX_VERSION").to_string(),
        tor_on,
        i2p_on,
    };
    (ready, child)
}

/// Locate a Firefox executable: `EPIX_FIREFOX`, a Firefox bundled inside our own
/// `.app` (the shipping case), then the usual per-OS spots.
fn find_firefox() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("EPIX_FIREFOX") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    // Bundled Firefox: `Epix.app/Contents/Resources/firefox/*.app/Contents/MacOS/firefox`,
    // relative to this launcher at `Epix.app/Contents/MacOS/epix-browser`.
    if let Some(bundled) = bundled_firefox() {
        return Some(bundled);
    }
    // Prefer editions that allow our unsigned extension (ESR / Developer /
    // Nightly) over release Firefox, since the extension is core to the
    // security contract.
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Applications/Firefox ESR.app/Contents/MacOS/firefox",
            "/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox",
            "/Applications/Firefox Nightly.app/Contents/MacOS/firefox",
            "/Applications/Firefox.app/Contents/MacOS/firefox",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            "C:\\Program Files\\Firefox ESR\\firefox.exe",
            "C:\\Program Files\\Firefox Developer Edition\\firefox.exe",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
        ]
    } else {
        &["/usr/bin/firefox-esr", "/usr/bin/firefox", "/usr/local/bin/firefox", "/snap/bin/firefox"]
    };
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

/// A Firefox bundled next to this launcher inside our `.app` / install dir.
fn bundled_firefox() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?; // .../Contents/MacOS
    // macOS: ../Resources/firefox/<Firefox…>.app/Contents/MacOS/firefox
    let fx_root = dir.parent().map(|c| c.join("Resources/firefox"));
    // Linux/Windows: ./firefox/firefox[.exe] next to the launcher.
    let sibling = dir.join("firefox");
    for base in [fx_root, Some(sibling)].into_iter().flatten() {
        if !base.exists() {
            continue;
        }
        // Direct binary?
        for name in ["firefox", "firefox.exe"] {
            let p = base.join(name);
            if p.exists() {
                return Some(p);
            }
        }
        // A nested *.app (macOS)?
        if let Ok(entries) = std::fs::read_dir(&base) {
            for e in entries.flatten() {
                let p = e.path().join("Contents/MacOS/firefox");
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Whether this Firefox honors `xpinstall.signatures.required=false` (so it can
/// load our unsigned extension): ESR, Developer Edition, and Nightly do;
/// release Firefox does not. Detected from the app path.
fn firefox_allows_unsigned(firefox: &Path) -> bool {
    if let Ok(v) = std::env::var("EPIX_FIREFOX_UNSIGNED") {
        return v != "0" && !v.is_empty();
    }
    let p = firefox.to_string_lossy();
    p.contains("ESR") || p.contains("Developer Edition") || p.contains("Nightly") || p.contains("firefox-esr")
}

/// Locate `certutil` (NSS): PATH, then keg-only Homebrew locations.
fn find_certutil() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("EPIX_CERTUTIL") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let candidates = [
        "/opt/homebrew/opt/nss/bin/certutil",
        "/usr/local/opt/nss/bin/certutil",
        "/usr/bin/certutil",
        "/usr/local/bin/certutil",
    ];
    candidates.iter().map(PathBuf::from).find(|p| p.exists()).or_else(|| {
        // Fall back to whatever is on PATH.
        std::process::Command::new("certutil")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| PathBuf::from("certutil"))
    })
}

/// Trust the local CA in the profile's NSS cert DB (`cert9.db`), so
/// `https://*.epix` loads without a warning. Idempotent (re-add by nickname).
fn install_ca(profile: &Path, ca: &LocalCa) -> Result<(), String> {
    let certutil = find_certutil().ok_or_else(|| {
        "certutil not found (install NSS, e.g. `brew install nss`, or set EPIX_CERTUTIL)".to_string()
    })?;
    let ca_path = profile.join("epix-ca.pem");
    std::fs::write(&ca_path, ca.cert_pem()).map_err(|e| format!("write ca pem: {e}"))?;

    let db = format!("sql:{}", profile.display());
    // Create the NSS db only if it doesn't exist yet - `-N` on an existing db
    // prompts for confirmation and would hang. Always give certutil a null
    // stdin so it can never block on a prompt.
    let null = || std::process::Stdio::null();
    if !profile.join("cert9.db").exists() {
        let _ = Command::new(&certutil)
            .args(["-N", "--empty-password", "-d", &db])
            .stdin(null())
            .output();
    }
    // Remove any prior copy so this is idempotent, then add as a trusted CA.
    let _ = Command::new(&certutil)
        .args(["-D", "-n", "Epix Local CA", "-d", &db])
        .stdin(null())
        .output();
    let out = Command::new(&certutil)
        .args(["-A", "-n", "Epix Local CA", "-t", "CT,C,C", "-d", &db])
        .arg("-i")
        .arg(&ca_path)
        .stdin(null())
        .output()
        .map_err(|e| format!("run certutil: {e}"))?;
    if !out.status.success() {
        return Err(format!("certutil -A failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

/// Write the managed profile: the PAC (routes `*.epix` to the proxy) and a
/// `user.js` locking the proxy and the navigate-not-search behaviour. `secure`
/// picks the homepage scheme (https when the CA is trusted, else http).
#[allow(clippy::too_many_arguments)]
fn write_profile(
    profile: &Path,
    proxy_addr: SocketAddr,
    socks_addr: SocketAddr,
    display: &str,
    secure: bool,
    tor_clearnet: bool,
    ext_capable: bool,
) -> std::io::Result<()> {
    std::fs::create_dir_all(profile)?;

    // The file PAC does all routing (the browser proxy API proved unreliable for
    // this): `.epix` -> the node's browser proxy; clearnet -> the node's Tor
    // SOCKS listener when the user has turned on "route clearnet through Tor",
    // else DIRECT. The toggle updates the persisted setting; this PAC is rebuilt
    // from it on the next launch.
    let clearnet = if tor_clearnet {
        format!("return \"SOCKS5 {socks_addr}\";")
    } else {
        "return \"DIRECT\";".to_string()
    };
    let pac_path = profile.join("epix.pac");
    let pac = format!(
        "function FindProxyForURL(url, host) {{\n\
         \x20 if (shExpMatch(host, \"*.epix\")) {{ return \"PROXY {proxy_addr}\"; }}\n\
         \x20 if (host === \"127.0.0.1\" || host === \"localhost\") {{ return \"DIRECT\"; }}\n\
         \x20 // The EPIX chain's own infrastructure (rpc/api/evmrpc.epix.zone) always\n\
         \x20 // goes direct: it is the wallet's essential backend, and the endpoints\n\
         \x20 // refuse Tor exits, so routing chain RPC through Tor would break the\n\
         \x20 // wallet. Tor-clearnet stays for general browsing.\n\
         \x20 if (shExpMatch(host, \"*.epix.zone\")) {{ return \"DIRECT\"; }}\n\
         \x20 {clearnet}\n\
         }}\n"
    );
    std::fs::write(&pac_path, pac)?;
    let pac_url = format!("file://{}", pac_path.display());

    let proxy_prefs = format!(
        "user_pref(\"network.proxy.type\", 2);\n\
         user_pref(\"network.proxy.autoconfig_url\", \"{pac_url}\");\n\
         user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n\
         user_pref(\"network.proxy.socks_remote_dns\", true);\n"
    );

    let scheme = if secure { "https" } else { "http" };
    // With a trusted CA we want https; without it, http (and disable https-first
    // so Firefox doesn't upgrade the .epix navigation to a failing https).
    let https_prefs = if secure {
        ""
    } else {
        "user_pref(\"dom.security.https_only_mode\", false);\n\
         user_pref(\"dom.security.https_first\", false);\n\
         user_pref(\"dom.security.https_first_pbm\", false);\n"
    };
    // Load and auto-enable the bundled (unsigned) extension from the profile.
    // Only on editions that allow it; harmless prefs otherwise.
    let ext_prefs = if ext_capable {
        "user_pref(\"xpinstall.signatures.required\", false);\n\
         user_pref(\"extensions.autoDisableScopes\", 0);\n\
         user_pref(\"extensions.enabledScopes\", 5);\n\
         user_pref(\"extensions.installDistroAddons\", false);\n"
    } else {
        ""
    };

    let prefs = format!(
        r#"// Managed by epix-browser - regenerated on launch.
{proxy_prefs}{https_prefs}// A dotted host like dashboard.epix should navigate, not search.
user_pref("browser.fixup.dns_first_for_single_words", false);
user_pref("keyword.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.quickactions", false);
// Skip first-run noise so it opens straight on the xite.
user_pref("browser.startup.homepage", "{scheme}://{display}/");
user_pref("browser.startup.page", 1);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
user_pref("browser.warnOnQuit", false);
// Allow userChrome.css / userContent.css styling of the browser chrome.
user_pref("toolkit.legacyUserProfileCustomizations.stylesheets", true);
{ext_prefs}"#
    );
    let mut f = std::fs::File::create(profile.join("user.js"))?;
    f.write_all(prefs.as_bytes())?;
    Ok(())
}

/// Poll `addr` until a TCP connection succeeds or `timeout` elapses.
async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}
