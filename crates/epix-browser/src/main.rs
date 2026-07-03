//! The Epix desktop browser.
//!
//! This is Workstream B: a launcher that bundles the node with **real Firefox**
//! so you get a genuine browser (extensions and all), not a WebView. It:
//!
//! 1. boots the embedded node ([`epix_node`]) - the same engine the server
//!    binary runs, with in-process Tor;
//! 2. writes a managed Firefox profile whose proxy PAC routes every `*.epix`
//!    host to the node and leaves clearnet DIRECT;
//! 3. launches Firefox on that profile at `http://<xite>/`, so the address bar
//!    reads `dashboard.epix` and the node serves it in transparent-proxy mode;
//! 4. shuts the node down when Firefox exits.
//!
//! The node change that makes this work is the transparent-proxy host rewrite in
//! `epix-ui` (a `Host: dashboard.epix` request is served as that xite). Secure
//! origins (a local CA for `https://*.epix`), the bundled extension, and the
//! CSP/clearnet-block are the next milestones; this gets the browser working
//! end to end over `http://` first.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const UI_ADDR: &str = "127.0.0.1:43110";

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .map(|a| epix_node::parse_target(&a))
        .unwrap_or_else(|| "dashboard.epix".to_string());

    let data_root = epix_node::data_root();
    if let Err(e) = std::fs::create_dir_all(&data_root) {
        eprintln!("cannot create data dir {}: {e}", data_root.display());
        std::process::exit(1);
    }

    // Find Firefox before doing any slow work, so we fail fast with guidance.
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

    // Boot the node and start serving on a background task.
    println!("· starting the Epix node …");
    let opts = epix_node::NodeOptions {
        data_root: data_root.clone(),
        target: target.clone(),
        ui_addr: UI_ADDR.to_string(),
        tor_mode: std::env::var("EPIX_TOR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "enable".into()),
        open_browser: false,
        geoip_gz: None,
        log_file: None,
        version: env!("CARGO_PKG_VERSION").to_string(),
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
    tokio::spawn(async move {
        let _ = server.serve(ui_addr).await;
    });

    // Wait for the UI port to accept connections before launching Firefox.
    if !wait_for_port(ui_addr, Duration::from_secs(30)).await {
        eprintln!("the node's UI server did not come up on {ui_addr}");
        std::process::exit(1);
    }
    println!("· node serving on http://{ui_addr}/  (xite: {display})");

    // Write the managed Firefox profile (prefs + PAC).
    let profile = data_root.join("firefox-profile");
    if let Err(e) = write_profile(&profile, ui_addr) {
        eprintln!("could not write the Firefox profile: {e}");
        std::process::exit(1);
    }

    // Launch Firefox at the xite. In transparent-proxy mode the address bar
    // shows the xite host, and the node serves it.
    let start_url = format!("http://{display}/");
    println!("· launching Firefox at {start_url}");
    let status = Command::new(&firefox)
        .arg("--profile")
        .arg(&profile)
        .arg("--no-remote")
        .arg("--new-instance")
        .arg(&start_url)
        .status();

    match status {
        Ok(_) => println!("· Firefox closed - shutting down the node"),
        Err(e) => eprintln!("could not launch Firefox at {}: {e}", firefox.display()),
    }
}

/// Locate a Firefox executable: `EPIX_FIREFOX`, then the usual per-OS spots.
fn find_firefox() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("EPIX_FIREFOX") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Applications/Firefox.app/Contents/MacOS/firefox",
            "/Applications/Firefox Developer Edition.app/Contents/MacOS/firefox",
            "/Applications/Firefox Nightly.app/Contents/MacOS/firefox",
            "/Applications/Firefox ESR.app/Contents/MacOS/firefox",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
        ]
    } else {
        &["/usr/bin/firefox", "/usr/bin/firefox-esr", "/usr/local/bin/firefox", "/snap/bin/firefox"]
    };
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

/// Write the managed profile: a PAC that routes `*.epix` to the node, and a
/// `user.js` that locks the proxy and keeps `.epix` navigations on http (no
/// HTTPS-first, no search-from-address-bar).
fn write_profile(profile: &Path, ui_addr: std::net::SocketAddr) -> std::io::Result<()> {
    std::fs::create_dir_all(profile)?;

    let pac_path = profile.join("epix.pac");
    let pac = format!(
        "function FindProxyForURL(url, host) {{\n\
         \x20 if (shExpMatch(host, \"*.epix\")) {{ return \"PROXY {ui_addr}\"; }}\n\
         \x20 return \"DIRECT\";\n\
         }}\n"
    );
    std::fs::write(&pac_path, pac)?;
    // Firefox wants a file:// URL for the PAC.
    let pac_url = format!("file://{}", pac_path.display());

    let prefs = format!(
        r#"// Managed by epix-browser - do not edit; regenerated on launch.
user_pref("network.proxy.type", 2);
user_pref("network.proxy.autoconfig_url", "{pac_url}");
user_pref("network.proxy.allow_hijacking_localhost", true);
// Keep .epix on http for now (secure-origin local CA is a later milestone).
user_pref("dom.security.https_only_mode", false);
user_pref("dom.security.https_first", false);
user_pref("dom.security.https_first_pbm", false);
// A dotted host like dashboard.epix should navigate, not search.
user_pref("browser.fixup.dns_first_for_single_words", false);
user_pref("keyword.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.quickactions", false);
// Skip first-run noise so it opens straight on the xite.
user_pref("browser.startup.homepage", "http://{ui_display}/");
user_pref("browser.startup.page", 1);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
user_pref("browser.warnOnQuit", false);
"#,
        pac_url = pac_url,
        ui_display = "dashboard.epix",
    );
    let mut f = std::fs::File::create(profile.join("user.js"))?;
    f.write_all(prefs.as_bytes())?;
    Ok(())
}

/// Poll `addr` until a TCP connection succeeds or `timeout` elapses.
async fn wait_for_port(addr: std::net::SocketAddr, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}
