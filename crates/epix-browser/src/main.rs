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

#![cfg_attr(windows, windows_subsystem = "windows")]

mod autostart;
mod ca;
mod ext;
#[cfg(windows)]
mod icon;
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
    // Must run before anything prints: as a windows-subsystem app we have no
    // console; adopt the parent's (dev runs from a terminal) or log to a file.
    #[cfg(windows)]
    attach_console_or_log(&epix_node::data_root());

    // `--background`: bring up the node + tray but no browser window (the
    // "open at login" mode). The user opens the browser from the tray. Any
    // other non-flag argument is the launch target (a xite name / epix:// URL).
    // These are the launch target and a mode flag, not used for any security
    // decision.
    // nosemgrep: rust.lang.security.args.args
    let args: Vec<String> = std::env::args().skip(1).collect();
    let background = args.iter().any(|a| a == "--background");
    let raw_arg = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| "dashboard.epix".to_string());

    // Single instance: the node stays running in the background, so if EpixNet
    // is already up, hand this launch's target to it and exit instead of
    // booting a second node against the same data directory. A background
    // launch only detects a running instance (it does not pop a window).
    let open_rx = match ipc::init(&raw_arg, !background) {
        ipc::Role::Secondary => {
            if !background {
                println!("· EpixNet is already running - opened {raw_arg} in it");
            }
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

    let (ready, firefox_child) = rt.block_on(boot(&raw_arg, background));

    // Hand the main thread to the tray. It keeps the node alive after the
    // browser closes and quits it on demand. When no tray host is available
    // (headless Linux, GTK failure, EPIX_NO_TRAY), `run` logs why and hands the
    // browser process back so we fall back to the old behaviour: run until the
    // window closes, then shut down.
    let firefox_path = ready.firefox.clone();
    let ctx = tray::TrayContext {
        ready,
        child: firefox_child,
        rt: rt.handle().clone(),
        open_rx,
    };
    if let Err(child) = tray::run(ctx) {
        match child {
            // We launched a browser: run until it closes, then shut down.
            Some(child) => {
                tray::wait_for_browser(child, &firefox_path);
                println!("· browser closed - shutting down the node");
            }
            // Background mode with no tray host and no window: keep the node
            // serving (there is nothing to wait on); the user stops it by
            // killing the process.
            None => {
                eprintln!("· running headless (no tray, no window); the node keeps serving");
                tray::park();
            }
        }
    }
}

/// The launcher has no console of its own on Windows (GUI subsystem, so no
/// terminal window pops up behind the browser). Printed output still has to
/// land somewhere: attach to the parent process's console when there is one
/// (`cargo run` / a terminal invocation keeps live output), else append both
/// std streams to `<data_root>/log/epix-browser.log` so field problems stay
/// diagnosable.
#[cfg(windows)]
fn attach_console_or_log(data_root: &Path) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{
        AttachConsole, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };
    // Launched from a terminal: adopt its console. AttachConsole also wires up
    // the std handles unless they were explicitly redirected (`> file` wins).
    // SAFETY: plain FFI call with a constant argument; no pointers involved.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } != 0 {
        return;
    }
    // Desktop launch (shortcut / epix:// / autostart): log to a file.
    let dir = data_root.join("log");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("epix-browser.log");
    // Single-file rotation keeps the log bounded across many launches.
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 2 * 1024 * 1024) {
        let old = dir.join("epix-browser.log.old");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&path, &old);
    }
    let Ok(f) = std::fs::File::options().create(true).append(true).open(&path) else {
        return;
    };
    // The file handle becomes the process's stdout/stderr for its lifetime
    // (children inherit it too). Deliberately leaked - it must outlive us.
    let raw = f.into_raw_handle();
    // SAFETY: `raw` is a valid handle we own and intentionally leak, so it
    // stays live for every later write through the std handles.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        SetStdHandle(STD_OUTPUT_HANDLE, raw as _);
        SetStdHandle(STD_ERROR_HANDLE, raw as _);
    }
}

/// Boot the node, write the managed profile, install the extension, and launch
/// Firefox (non-blocking) unless `background`. Returns the running state the
/// tray watches plus the browser process (`None` in background mode - the tray
/// opens the browser on demand). Fatal setup errors exit the process directly.
async fn boot(raw_arg: &str, background: bool) -> (Ready, Option<std::process::Child>) {
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

    // Write the managed profile (CA injected so https://*.epix is trusted), then
    // install the theme + wallet extension into it.
    let (profile, secure) = setup_profile(
        &data_root, proxy_addr, socks_addr, &display, tor_clearnet, ext_capable, &firefox, &ca,
    );
    ensure_search_policy(&firefox);
    install_addons(&profile, &firefox, ext_capable);

    let scheme = if secure { "https" } else { "http" };
    let start_url = format!("{scheme}://{display}/");
    let child = launch_browser(background, &firefox, &profile, &start_url);

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

/// Write the managed Firefox profile and install the local CA. Returns the
/// profile path and whether `https://*.epix` is trusted; a CA-install failure
/// falls back to http (re-writing the profile without secure origins). A failure
/// to write the profile at all is fatal.
#[allow(clippy::too_many_arguments)]
fn setup_profile(
    data_root: &Path,
    proxy_addr: SocketAddr,
    socks_addr: SocketAddr,
    display: &str,
    tor_clearnet: bool,
    ext_capable: bool,
    firefox: &Path,
    ca: &LocalCa,
) -> (PathBuf, bool) {
    let profile = data_root.join("firefox-profile");
    if let Err(e) =
        write_profile(&profile, proxy_addr, socks_addr, display, true, tor_clearnet, ext_capable)
    {
        eprintln!("could not write the Firefox profile: {e}");
        std::process::exit(1);
    }
    let secure = match install_ca(&profile, firefox, ca) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("· note: could not install the local CA ({e}); falling back to http");
            let _ =
                write_profile(&profile, proxy_addr, socks_addr, display, false, tor_clearnet, ext_capable);
            false
        }
    };
    (profile, secure)
}

/// Install the starter chrome theme and, when the edition allows unsigned
/// add-ons, the Epix Wallet extension + its native host. All best-effort:
/// failures are logged, never fatal (the theme persists once written).
fn install_addons(profile: &Path, firefox: &Path, ext_capable: bool) {
    if let Err(e) = ext::install_theme(profile) {
        eprintln!("· note: could not install the theme: {e}");
    }
    if !ext_capable {
        println!(
            "· note: {} enforces extension signing, so the clearnet-block extension \
             won't load. Use Firefox ESR or Developer Edition (the shipping bundle \
             uses ESR).",
            firefox.display()
        );
        return;
    }
    // Existing profiles: drop the retired browser-ext and give the wallet its
    // toolbar slot.
    ext::migrate_legacy_extension(profile);
    if let Err(e) = ext::install_extension(profile) {
        eprintln!("· note: could not install the wallet extension: {e}");
    }
    // Profiles that installed the wallet before the manifest pinned it to the
    // toolbar: move it out of the puzzle-piece menu.
    ext::ensure_wallet_pinned(profile);
    if let Err(e) = ext::install_native_host() {
        eprintln!("· note: could not install the native host: {e}");
    }
    println!("· wallet extension + native host installed");
}

/// Launch Firefox on the managed profile (spawn, not wait - the node outlives
/// the window, anchored by the tray). Returns `None` in background mode (the
/// tray opens the browser on demand) or if the launch fails; neither is fatal,
/// the tray keeps the node up and "Open EpixNet" retries.
fn launch_browser(
    background: bool,
    firefox: &Path,
    profile: &Path,
    start_url: &str,
) -> Option<std::process::Child> {
    if background {
        println!("· background mode: node + tray up, no browser window");
        return None;
    }
    println!("· launching Firefox at {start_url}");
    let mut cmd = Command::new(firefox);
    // --allow-downgrade: never let Firefox's profile-downgrade dialog block
    // startup. It fires when the profile was last opened by a NEWER Firefox
    // than this one - e.g. the user's system Firefox touched the managed
    // profile once - and would otherwise leave the managed browser stuck on a
    // modal ("You've launched an older version of Firefox") with no xite
    // loaded. We manage this profile, so just proceed.
    cmd.arg("--allow-downgrade").arg("--profile").arg(profile).arg("--no-remote").arg("--new-instance");
    // Linux: the shell picks the window icon by matching the window class /
    // app id against a .desktop entry - ours (StartupWMClass=EpixNet, with the
    // Epix icon) matches these. --class covers X11, --name the Wayland app id.
    #[cfg(all(unix, not(target_os = "macos")))]
    cmd.args(["--class", "EpixNet", "--name", "EpixNet"]);
    match cmd.arg(start_url).spawn() {
        Ok(mut child) => {
            // `--no-remote --new-instance` on a profile another Firefox already
            // holds exits at once (no window). Catch that quick exit so it is a
            // clear log line instead of a tray with no browser - the usual
            // cause is a previous EpixNet that was force-killed, orphaning its
            // Firefox, which still locks the profile.
            std::thread::sleep(Duration::from_millis(700));
            if let Ok(Some(status)) = child.try_wait() {
                eprintln!(
                    "· note: Firefox exited immediately ({status}). Another EpixNet or a \
                     Firefox on this profile is likely already running; close it (or quit \
                     EpixNet from the tray) and reopen. Profile: {}",
                    profile.display()
                );
                return None;
            }
            Some(child)
        }
        Err(e) => {
            eprintln!("could not launch Firefox at {}: {e}", firefox.display());
            None
        }
    }
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
/// release Firefox does not. Detected from the app path, with an
/// `application.ini` fallback for installs whose path doesn't say (the bundled
/// Windows/Linux tree is a plain `firefox/` directory but contains ESR).
fn firefox_allows_unsigned(firefox: &Path) -> bool {
    if let Ok(v) = std::env::var("EPIX_FIREFOX_UNSIGNED") {
        return v != "0" && !v.is_empty();
    }
    let p = firefox.to_string_lossy();
    if p.contains("ESR")
        || p.contains("Developer Edition")
        || p.contains("Nightly")
        || p.contains("firefox-esr")
    {
        return true;
    }
    firefox_is_esr_build(firefox)
}

/// Path-independent ESR detection via the `application.ini` Mozilla ships next
/// to the binary (Windows/Linux) or under `Contents/Resources` (macOS .app):
/// ESR builds carry `RemotingName=firefox-esr`, an `…esr` release repo, and
/// (on some trains) an `esr`-suffixed Version.
fn firefox_is_esr_build(firefox: &Path) -> bool {
    let Some(bin_dir) = firefox.parent() else { return false };
    let mut candidates = vec![bin_dir.join("application.ini")];
    if let Some(contents) = bin_dir.parent() {
        candidates.push(contents.join("Resources").join("application.ini"));
    }
    candidates.iter().filter_map(|p| std::fs::read_to_string(p).ok()).any(|ini| {
        ini.lines().map(str::trim).any(|l| {
            l.eq_ignore_ascii_case("remotingname=firefox-esr")
                || (l.starts_with("Version=") && l.ends_with("esr"))
                || (l.starts_with("SourceRepository=") && l.contains("esr"))
        })
    })
}

/// Build a `Command` that can never pop a console window on Windows - the
/// launcher is a GUI-subsystem app, so a spawned console tool (certutil, cmd)
/// would otherwise flash its own terminal.
fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
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
        // Fall back to whatever is on PATH. `--version` is an NSS flag, so
        // Windows' unrelated system certutil.exe fails it and is skipped.
        hidden_command("certutil")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|_| PathBuf::from("certutil"))
    })
}

/// Trust the local CA in the Firefox that will run the managed profile, so
/// `https://*.epix` loads without a warning. Two mechanisms, tried in order:
///
/// 1. NSS `certutil` into the profile's `cert9.db` - scoped to the managed
///    profile alone. Available where NSS is installed (macOS/Linux dev boxes);
///    essentially never on Windows.
/// 2. Firefox **enterprise policies** (`Certificates.Install`): write the CA
///    PEM where the policy engine searches for bare filenames, and make sure
///    the install's `distribution/policies.json` references it. Our shipped
///    bundles bake that policies.json in at package time; when it is missing
///    (dev runs, installs predating it) it is written here - possible wherever
///    the install dir is user-writable, like the per-user Windows bundle under
///    `%LOCALAPPDATA%\Epix`.
fn install_ca(profile: &Path, firefox: &Path, ca: &LocalCa) -> Result<(), String> {
    let pem = ca.cert_pem();
    let certutil_err = match install_ca_certutil(profile, &pem) {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };
    install_ca_policies(firefox, &pem)
        .map_err(|e| format!("certutil: {certutil_err}; policies: {e}"))
}

/// Mechanism 1: `certutil -A` into the profile's NSS cert DB (`cert9.db`).
/// Idempotent (re-add by nickname).
fn install_ca_certutil(profile: &Path, pem: &str) -> Result<(), String> {
    let certutil = find_certutil().ok_or_else(|| {
        "certutil not found (install NSS, e.g. `brew install nss`, or set EPIX_CERTUTIL)".to_string()
    })?;
    let ca_path = profile.join("epix-ca.pem");
    std::fs::write(&ca_path, pem).map_err(|e| format!("write ca pem: {e}"))?;

    let db = format!("sql:{}", profile.display());
    // Create the NSS db only if it doesn't exist yet - `-N` on an existing db
    // prompts for confirmation and would hang. Always give certutil a null
    // stdin so it can never block on a prompt.
    let null = || std::process::Stdio::null();
    if !profile.join("cert9.db").exists() {
        let _ = hidden_command(&certutil)
            .args(["-N", "--empty-password", "-d", &db])
            .stdin(null())
            .output();
    }
    // Remove any prior copy so this is idempotent, then add as a trusted CA.
    let _ = hidden_command(&certutil)
        .args(["-D", "-n", "Epix Local CA", "-d", &db])
        .stdin(null())
        .output();
    let out = hidden_command(&certutil)
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

/// The CA filename shared between the runtime and the packaged policies.json:
/// the policy lists it bare, and Firefox resolves bare names against the
/// per-user Mozilla certificates directories written below.
const CA_POLICY_FILE: &str = "epix-ca.pem";

/// Where Firefox's policy engine searches for a bare certificate filename
/// (mozilla/policy-templates, `Certificates.Install`).
fn mozilla_cert_dirs() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        ["LOCALAPPDATA", "APPDATA"]
            .iter()
            .filter_map(std::env::var_os)
            .map(|base| PathBuf::from(base).join("Mozilla").join("Certificates"))
            .collect()
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| {
                vec![PathBuf::from(h).join("Library/Application Support/Mozilla/Certificates")]
            })
            .unwrap_or_default()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("HOME")
            .map(|h| vec![PathBuf::from(h).join(".mozilla/certificates")])
            .unwrap_or_default()
    }
}

/// The `distribution/` dir of the given Firefox install, where the policy
/// engine reads `policies.json`: next to the binary on Windows/Linux, under
/// `Contents/Resources` inside a macOS .app.
fn firefox_distribution_dir(firefox: &Path) -> Option<PathBuf> {
    let bin_dir = firefox.parent()?;
    if cfg!(target_os = "macos") {
        Some(bin_dir.parent()?.join("Resources").join("distribution"))
    } else {
        Some(bin_dir.join("distribution"))
    }
}

/// Mechanism 2: trust the CA through Firefox enterprise policies. Writes the
/// PEM into the per-user Mozilla certificates dir(s), then makes sure this
/// install's `policies.json` lists it - reusing one baked in at package time,
/// else writing it (never inside a macOS .app: the bundle is code-signed, and
/// editing it would break the seal).
fn install_ca_policies(firefox: &Path, pem: &str) -> Result<(), String> {
    let wrote = mozilla_cert_dirs()
        .iter()
        .filter(|dir| {
            std::fs::create_dir_all(dir).is_ok()
                && std::fs::write(dir.join(CA_POLICY_FILE), pem).is_ok()
        })
        .count();
    if wrote == 0 {
        return Err("could not write the CA into a Mozilla certificates dir".to_string());
    }

    let dist = firefox_distribution_dir(firefox)
        .ok_or_else(|| "cannot locate the Firefox distribution dir".to_string())?;
    let path = dist.join("policies.json");
    // Merge into an existing policies.json (ours from the package step or a
    // previous run); an unparsable or non-object file starts fresh - the file
    // only exists in installs we manage.
    let mut root = match std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    {
        Some(v) if v.is_object() => v,
        _ => serde_json::json!({}),
    };
    let install = root
        .as_object_mut()
        .expect("root is an object")
        .entry("policies")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or("policies key is not an object")?
        .entry("Certificates")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or("Certificates policy is not an object")?
        .entry("Install")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("Certificates.Install is not a list")?;
    if install.iter().any(|v| v.as_str() == Some(CA_POLICY_FILE)) {
        return Ok(()); // already referenced (baked in, or a prior run)
    }
    install.push(serde_json::Value::String(CA_POLICY_FILE.to_string()));
    if cfg!(target_os = "macos") {
        return Err(
            "the bundled Firefox has no CA policy baked in (won't edit a signed .app; re-package)"
                .to_string(),
        );
    }
    std::fs::create_dir_all(&dist).map_err(|e| format!("create {}: {e}", dist.display()))?;
    let json = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Make DuckDuckGo the managed browser's default search engine (matching the
/// mobile apps) via the `SearchEngines` enterprise policy - ESR-only, which
/// the shipped bundle is. Merged into the same policies.json the CA lives in,
/// and only when absent, so a deliberate later change sticks. Best-effort by
/// design: never affects the https/CA decision, and macOS bundles (sealed
/// .app) get it baked in at package time instead.
fn ensure_search_policy(firefox: &Path) {
    let Some(dist) = firefox_distribution_dir(firefox) else { return };
    let path = dist.join("policies.json");
    let mut root = match std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    {
        Some(v) if v.is_object() => v,
        _ => serde_json::json!({}),
    };
    let Some(engines) = root
        .as_object_mut()
        .expect("root is an object")
        .entry("policies")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .and_then(|p| {
            p.entry("SearchEngines")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
        })
    else {
        return;
    };
    if engines.contains_key("Default") {
        return;
    }
    engines.insert("Default".to_string(), serde_json::json!("DuckDuckGo"));
    if cfg!(target_os = "macos") {
        return;
    }
    if std::fs::create_dir_all(&dist).is_ok() {
        if let Ok(json) = serde_json::to_string_pretty(&root) {
            let _ = std::fs::write(&path, json);
        }
    }
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
    let pac_url = file_url(&pac_path);

    let proxy_prefs = format!(
        "user_pref(\"network.proxy.type\", 2);\n\
         user_pref(\"network.proxy.autoconfig_url\", \"{pac_url}\");\n\
         user_pref(\"network.proxy.allow_hijacking_localhost\", true);\n\
         user_pref(\"network.proxy.socks_remote_dns\", true);\n"
    );

    let scheme = if secure { "https" } else { "http" };
    // With a trusted CA we want https; without it, http (and disable https-first
    // so Firefox doesn't upgrade the .epix navigation to a failing https).
    //
    // The secure branch must EXPLICITLY re-assert `https_first=true`, not leave
    // it unset: Firefox persists user.js prefs into prefs.js, so a profile that
    // once fell back to http (an early run before the CA was trusted, or a
    // launch that found a non-bundle Firefox) keeps `https_first=false` and an
    // `http://` homepage forever unless we overwrite them here - a healed
    // profile would still open the xite over http ("Not Secure"). We only
    // prefer https (https-first), never force it (https-only would break plain
    // http clearnet sites the user browses through Tor).
    let https_prefs = if secure {
        "user_pref(\"dom.security.https_only_mode\", false);\n\
         user_pref(\"dom.security.https_first\", true);\n\
         user_pref(\"dom.security.https_first_pbm\", true);\n"
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
{proxy_prefs}{https_prefs}// A dotted host like dashboard.epix navigates; plain terms search with the
// default engine (DuckDuckGo via the SearchEngines policy), like the mobile
// apps. keyword.enabled is set back to true explicitly: earlier builds wrote
// false, and Firefox persists user.js values into prefs.js, so merely
// dropping the line would leave existing profiles searchless.
user_pref("browser.fixup.dns_first_for_single_words", false);
user_pref("keyword.enabled", true);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.quickactions", false);
// Skip first-run noise so it opens straight on the xite.
user_pref("browser.startup.homepage", "{scheme}://{display}/");
user_pref("browser.startup.page", 1);
// Always open fresh on the xite homepage: never restore the previous session
// and never show the crash "restore session" prompt. The managed browser is an
// appliance for the current xite, and a force-killed run (or the node quitting
// under it) must not resurrect a stale tab - notably an old http:// fallback
// tab, which would then show as "Not Secure" even after the CA is trusted.
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.sessionstore.max_resumed_crashes", 0);
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

/// A `file://` URL Firefox will load for a local path. On Unix a path already
/// starts with `/`, so `file://` + `/x` is the well-formed `file:///x`. On
/// Windows the path is `C:\dir\f`, which must become `file:///C:/dir/f`
/// (forward slashes, the extra slash before the drive) - the naive
/// `file://C:\dir\f` is not a valid URL and Firefox silently ignores the PAC,
/// so `.epix` routing and clearnet-through-Tor both break. Spaces (common under
/// `C:\Users\First Last\`) are percent-encoded.
fn file_url(path: &Path) -> String {
    let p = path.display().to_string().replace('\\', "/").replace(' ', "%20");
    if p.starts_with('/') {
        format!("file://{p}")
    } else {
        format!("file:///{p}")
    }
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
