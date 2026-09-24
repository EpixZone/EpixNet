//! A cross-platform system tray for the desktop launcher.
//!
//! The launcher keeps the node running after the browser window closes, so the
//! machine stays a useful peer on the network. The tray is the anchor that
//! outlives Firefox: it shows live stats (peers, connections, transfer, Tor)
//! and is the only way to fully quit, short of killing the process.
//!
//! macOS renders it in the menu bar, Windows in the notification area, and
//! Linux through the StatusNotifier/AppIndicator host of whatever desktop is
//! running. `tao` owns the main-thread event loop all three backends need.
//!
//! Everything here is best-effort. Linux has many desktops and some have no
//! tray host at all (or no display), so if the tray can't be shown we return
//! an error and the caller falls back to running until the browser closes. The
//! launcher must never fail to start because a tray icon could not appear.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Use the menu types paired with tray-icon. A separately versioned muda
// dependency can produce incompatible ContextMenu types after an update.
use tray_icon::menu::{self as muda, CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tao::event_loop::{ControlFlow, EventLoop, EventLoopBuilder};
use tray_icon::{Icon, TrayIconBuilder};

use crate::{autostart, Ready};

/// The tray icon, decoded from the same PNG the Linux packaging ships.
const TRAY_PNG: &[u8] = include_bytes!("../../../packaging/linux/icons/epix-64.png");

/// What the launcher needs to hand the tray: the running node's state (for
/// stats) plus what it takes to reopen the browser.
pub struct TrayContext {
    pub ready: Ready,
    /// The browser process, or `None` in background mode (no window yet - the
    /// tray opens one on demand).
    pub child: Option<Child>,
    pub rt: tokio::runtime::Handle,
    /// Open-requests from later launches (single-instance): each is the raw
    /// launch argument to open in the running browser.
    pub open_rx: std::sync::mpsc::Receiver<crate::ipc::Request>,
}

/// A snapshot of node stats the menu shows, refreshed on a background task so
/// the UI thread never blocks on the node's locks.
#[derive(Clone, Default)]
struct Snapshot {
    connections: i64,
    peers_connected: u64,
    peers_total: u64,
    /// Wire-level totals (all protocol traffic, like EpixNet's counters), not
    /// just file payloads - so they move even when an update finds nothing new.
    wire_recv: u64,
    wire_sent: u64,
    port_opened: bool,
    /// The detected external IP, once the fileserver learns it.
    ip: Option<String>,
    /// Our onion service host (without `.onion`), once Tor publishes it.
    onion: Option<String>,
    /// Our I2P host (without `.i2p`), once the inbound session is ready.
    i2p: Option<String>,
    tor_status: String,
    /// Aggregate unread notification count across xites (drives the tray dot).
    notif_count: i64,
}

async fn snapshot(state: &epix_ui::AppState) -> Snapshot {
    let s = state.stats_json().await;
    let (_enabled, tor_status) = state.tor_status().await;
    let (port_opened, ip) = state.port_status().await;
    let g = |k: &str| s.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    Snapshot {
        connections: s.get("connections").and_then(serde_json::Value::as_i64).unwrap_or(0),
        peers_connected: g("peers_connected"),
        peers_total: g("peers_total"),
        wire_recv: g("wire_recv"),
        wire_sent: g("wire_sent"),
        port_opened,
        ip,
        onion: state.onion_address().await,
        i2p: state.i2p_address().await,
        tor_status,
        notif_count: 0, // filled by the refresh loop on a slower cadence
    }
}

/// Tray state driven by the application's existing main-thread event loop.
/// The native event loop must be initialized before constructing this session.
pub(crate) struct Session {
    tray: tray_icon::TrayIcon,
    // Both native objects must outlive the menu's event handling.
    _menu: Menu,
    handles: Handles,
    snap: Arc<Mutex<Snapshot>>,
    open_rx: std::sync::mpsc::Receiver<crate::ipc::Request>,
    child: Option<Child>,
    firefox: PathBuf,
    profile: PathBuf,
    start_url: String,
    scheme: String,
    badge_shown: Option<bool>,
}

impl Session {
    /// Build the tray without starting or replacing the native event loop.
    /// Return the complete context when the caller needs the no-tray fallback.
    pub(crate) fn new(ctx: TrayContext) -> Result<Self, TrayContext> {
        if let Some(reason) = unavailable_reason() {
            log_unavailable(reason);
            return Err(ctx);
        }

        // Native tray construction can panic on desktops without a usable
        // toolkit. These objects remain on this thread, so unwind safety is
        // sufficient to preserve the existing browser fallback.
        let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(&ctx)));
        let (tray, menu, handles) = match built {
            Ok(Ok(built)) => built,
            Ok(Err(reason)) => {
                log_unavailable(&reason);
                return Err(ctx);
            }
            Err(_) => {
                log_unavailable("tray init panicked");
                return Err(ctx);
            }
        };

        println!("· system tray ready");
        let snap = Arc::new(Mutex::new(Snapshot::default()));
        spawn_stats_refresh(&ctx.rt, ctx.ready.state.clone(), snap.clone());
        Ok(Self {
            tray,
            _menu: menu,
            handles,
            snap,
            open_rx: ctx.open_rx,
            child: ctx.child,
            firefox: ctx.ready.firefox,
            profile: ctx.ready.profile,
            start_url: ctx.ready.start_url,
            scheme: ctx.ready.scheme,
            // Force the first draw so an existing unread badge appears.
            badge_shown: None,
        })
    }

    /// Refresh native state and process pending actions. Return true for Quit,
    /// after closing the managed browser, so the caller can exit its event loop.
    pub(crate) fn tick(&mut self) -> bool {
        refresh_menu_stats(&self.handles, &self.snap);

        let has_unread = self.snap.lock().map(|s| s.notif_count > 0).unwrap_or(false);
        if self.badge_shown != Some(has_unread) {
            self.badge_shown = Some(has_unread);
            let _ = self.tray.set_icon(Some(icon_with_badge(has_unread)));
        }

        // Apply the Epix icon to newly opened Firefox windows as well.
        #[cfg(windows)]
        crate::icon::stamp_firefox_windows(&self.firefox);

        // Later launches hand their targets to this running node.
        while let Ok(request) = self.open_rx.try_recv() {
            match request {
                crate::ipc::Request::Open(arg) => {
                    let url = target_url(&self.scheme, &arg);
                    reopen_browser(&mut self.child, &self.firefox, &self.profile, &url);
                }
                // `epix-browser --quit` (the installer, a script): the same
                // exit as the tray's Quit item, browser first.
                crate::ipc::Request::Quit => {
                    println!("· quit requested over the control channel");
                    close_browser(&mut self.child);
                    return true;
                }
            }
        }

        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if on_menu_event(
                &ev,
                &self.handles,
                &mut self.child,
                &self.firefox,
                &self.profile,
                &self.start_url,
            ) {
                return true;
            }
        }
        false
    }
}

fn unavailable_reason() -> Option<&'static str> {
    if std::env::var("EPIX_NO_TRAY").is_ok_and(|v| v != "0" && !v.is_empty()) {
        Some("disabled by EPIX_NO_TRAY")
    } else if !display_available() {
        Some("no display (DISPLAY/WAYLAND_DISPLAY unset)")
    } else {
        None
    }
}

fn log_unavailable(reason: &str) {
    eprintln!("· system tray unavailable ({reason}); running until the browser closes");
}

/// Run the tray on the calling (main) thread. On success it takes over the
/// thread and only returns by exiting the process from the Quit item. When no
/// tray can be shown it logs why and hands the browser process back in `Err`,
/// so the caller can fall back to waiting on it.
pub fn run(ctx: TrayContext, event_loop: Option<EventLoop<()>>) -> Result<(), Option<Child>> {
    // Do not initialize a native toolkit when there is no display or the tray
    // is disabled. Session::new also checks this for the startup-window path.
    if let Some(reason) = unavailable_reason() {
        log_unavailable(reason);
        return Err(ctx.child);
    }
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        event_loop.unwrap_or_else(create_event_loop)
    }));
    let event_loop = match built {
        Ok(event_loop) => event_loop,
        Err(_) => {
            log_unavailable("event loop init panicked");
            return Err(ctx.child);
        }
    };
    let mut session = Session::new(ctx).map_err(|ctx| ctx.child)?;
    event_loop.run(move |_event, _target, control_flow| {
        *control_flow = if session.tick() {
            ControlFlow::Exit
        } else {
            ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(1000))
        };
    });
}

/// Spawn the once-a-second stats refresh onto the node runtime, writing each
/// reading into the shared snapshot the menu reads back.
fn spawn_stats_refresh(
    rt: &tokio::runtime::Handle,
    state: Arc<epix_ui::AppState>,
    snap: Arc<Mutex<Snapshot>>,
) {
    rt.spawn(async move {
        let mut tick: u64 = 0;
        let mut notif_count: i64 = 0;
        loop {
            // The unread total costs a SQL COUNT per subscribed xite; refresh it
            // every ~5s rather than on every 1s stats tick.
            if tick % 5 == 0 {
                notif_count = state.notification_total().await;
            }
            let mut s = snapshot(&state).await;
            s.notif_count = notif_count;
            if let Ok(mut g) = snap.lock() {
                *g = s;
            }
            tick = tick.wrapping_add(1);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// Refresh the dynamic menu lines (IP / Tor / I2P / peers / connections /
/// transfer) from the latest stats snapshot. Does nothing if the snapshot lock
/// is poisoned.
fn refresh_menu_stats(handles: &Handles, snap: &Mutex<Snapshot>) {
    let Ok(s) = snap.lock() else { return };
    let reach = if s.port_opened { "active" } else { "passive" };
    handles.ip.set_text(match &s.ip {
        Some(ip) => format!("IP: {ip} ({reach})"),
        None => format!("IP: - ({reach})"),
    });
    if let Some(tor) = &handles.tor {
        tor.set_text(match &s.onion {
            Some(onion) => format!("Tor: {}", short_host(onion, ".onion")),
            None => format!("Tor: {}", s.tor_status),
        });
    }
    if let Some(i2p) = &handles.i2p {
        i2p.set_text(match &s.i2p {
            Some(addr) => format!("I2P: {}", short_host(addr, ".i2p")),
            None => "I2P: starting…".to_string(),
        });
    }
    handles
        .peers
        .set_text(format!("Peers: {} connected / {} known", s.peers_connected, s.peers_total));
    handles.conns.set_text(format!("Connections: {}", s.connections));
    handles
        .transfer
        .set_text(format!("Received {} · Sent {}", human(s.wire_recv), human(s.wire_sent)));
}

/// Handle one tray menu click. Returns `true` only for Quit, so the caller
/// exits the event loop (after the browser has been taken down here).
fn on_menu_event(
    ev: &MenuEvent,
    handles: &Handles,
    child: &mut Option<Child>,
    firefox: &Path,
    profile: &Path,
    start_url: &str,
) -> bool {
    if ev.id == handles.quit {
        // Take the managed browser down with the node - without the node every
        // .epix page in it is dead anyway.
        close_browser(child);
        return true;
    }
    if ev.id == handles.open {
        reopen_browser(child, firefox, profile, start_url);
    } else if ev.id == handles.autostart {
        // Toggle "open at login", then reflect the real state back onto the
        // checkbox (a failed write leaves it where it was).
        let want = handles.autostart_item.is_checked();
        if let Err(e) = autostart::set_enabled(want) {
            eprintln!("· could not change open-at-login: {e}");
        }
        handles.autostart_item.set_checked(autostart::is_enabled());
    } else if ev.id == handles.github {
        open_external("https://github.com/EpixZone/EpixNet");
    } else if ev.id == handles.issues {
        open_external("https://github.com/EpixZone/EpixNet/issues");
    } else if ev.id == handles.x {
        open_external("https://x.com/zone_epix");
    }
    false
}

/// The dynamic menu items whose text updates, plus the ids of the actionable
/// ones. muda items are cheap handles (clone-shares the native item).
struct Handles {
    ip: MenuItem,
    /// `None` when the transport is disabled for this run - no line at all.
    tor: Option<MenuItem>,
    i2p: Option<MenuItem>,
    peers: MenuItem,
    conns: MenuItem,
    transfer: MenuItem,
    open: muda::MenuId,
    /// The "Open at Login" checkbox: its id (for click matching) and the item
    /// itself (to read/reflect the checked state).
    autostart: muda::MenuId,
    autostart_item: CheckMenuItem,
    github: muda::MenuId,
    issues: muda::MenuId,
    x: muda::MenuId,
    quit: muda::MenuId,
}

type Built = (tray_icon::TrayIcon, Menu, Handles);

pub(crate) fn display_available() -> bool {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        true
    }
}

/// One application event loop serves both the startup window and the tray.
pub(crate) fn create_event_loop() -> EventLoop<()> {
    // The event loop must exist before the tray on Linux (it inits GTK).
    #[allow(unused_mut)]
    let mut event_loop: EventLoop<()> = EventLoopBuilder::new().build();
    // macOS: run as an accessory (menu-bar only) - the default Regular policy
    // would put a windowless generic "exec" icon in the Dock; the visible app
    // is Firefox, the tray is just the background anchor.
    #[cfg(target_os = "macos")]
    {
        use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
        event_loop.set_activation_policy(ActivationPolicy::Accessory);
    }
    event_loop
}

/// Create the menu and tray after the native event loop has been initialized.
fn build(ctx: &TrayContext) -> Result<Built, String> {
    let menu = Menu::new();
    let open = MenuItem::new("Open EpixNet", true, None);
    let header = MenuItem::new(format!("EpixNet {}", ctx.ready.version), false, None);
    let ip = MenuItem::new("IP: …", false, None);
    // No Tor / I2P line at all when the transport is off for this run.
    let tor = ctx.ready.tor_on.then(|| MenuItem::new("Tor: starting…", false, None));
    let i2p = ctx.ready.i2p_on.then(|| MenuItem::new("I2P: starting…", false, None));
    let peers = MenuItem::new("Peers: …", false, None);
    let conns = MenuItem::new("Connections: …", false, None);
    let transfer = MenuItem::new("Transfer: …", false, None);
    let autostart_item =
        CheckMenuItem::new("Open at Login", true, autostart::is_enabled(), None);
    let github = MenuItem::new("GitHub", true, None);
    let issues = MenuItem::new("Report a bug", true, None);
    let x = MenuItem::new("EpixNet on X", true, None);
    let quit = MenuItem::new("Quit EpixNet", true, None);

    let sep = PredefinedMenuItem::separator;
    let s1 = sep();
    let s2 = sep();
    let s3 = sep();
    let s4 = sep();
    let mut items: Vec<&dyn muda::IsMenuItem> = vec![&open, &s1, &header, &ip];
    if let Some(t) = &tor {
        items.push(t);
    }
    if let Some(i) = &i2p {
        items.push(i);
    }
    items.extend([
        &peers as &dyn muda::IsMenuItem,
        &conns,
        &transfer,
        &s2,
        &autostart_item,
        &s3,
        &github,
        &issues,
        &x,
        &s4,
        &quit,
    ]);
    menu.append_items(&items).map_err(|e| format!("build menu: {e}"))?;

    let handles = Handles {
        open: open.id().clone(),
        autostart: autostart_item.id().clone(),
        github: github.id().clone(),
        issues: issues.id().clone(),
        x: x.id().clone(),
        quit: quit.id().clone(),
        ip,
        tor,
        i2p,
        peers,
        conns,
        transfer,
        autostart_item,
    };

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu.clone()))
        .with_tooltip("EpixNet")
        .with_icon(load_icon())
        .build()
        .map_err(|e| format!("build tray: {e}"))?;

    Ok((tray, menu, handles))
}

/// Decode the embedded PNG into a tray icon, falling back to a solid brand
/// square if decoding fails, so the tray is always visible.
fn load_icon() -> Icon {
    if let Ok(img) = image::load_from_memory(TRAY_PNG) {
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        if let Ok(icon) = Icon::from_rgba(rgba.into_raw(), w, h) {
            return icon;
        }
    }
    // Brand green, 32x32 opaque.
    let (w, h) = (32u32, 32u32);
    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    for _ in 0..w * h {
        rgba.extend_from_slice(&[0x35, 0xd0, 0x7d, 0xff]);
    }
    Icon::from_rgba(rgba, w, h).expect("static fallback icon is valid")
}

/// The tray icon, optionally with a small red "unread" dot in the top-right
/// corner. A dot (not a count) keeps it legible at 16-22px tray sizes and
/// avoids pulling in a font rasteriser; it just says "you have new mail".
fn icon_with_badge(show_badge: bool) -> Icon {
    let (mut rgba, w, h) = match image::load_from_memory(TRAY_PNG) {
        Ok(img) => {
            let r = img.to_rgba8();
            let (w, h) = r.dimensions();
            (r.into_raw(), w, h)
        }
        Err(_) => return load_icon(),
    };
    if show_badge {
        // Solid red disc near the top-right, ringed by a cleared (transparent)
        // band so it reads on any menu-bar background.
        let cx = 0.74 * w as f32;
        let cy = 0.26 * h as f32;
        let r = 0.22 * w as f32;
        let ring = r + w as f32 * 0.07;
        for y in 0..h {
            for x in 0..w {
                let dx = x as f32 + 0.5 - cx;
                let dy = y as f32 + 0.5 - cy;
                let d2 = dx * dx + dy * dy;
                let idx = ((y * w + x) * 4) as usize;
                if d2 <= r * r {
                    rgba[idx] = 0xF0;
                    rgba[idx + 1] = 0x22;
                    rgba[idx + 2] = 0x4B;
                    rgba[idx + 3] = 0xff;
                } else if d2 <= ring * ring {
                    rgba[idx + 3] = 0x00;
                }
            }
        }
    }
    Icon::from_rgba(rgba, w, h).unwrap_or_else(|_| load_icon())
}

/// Build the browser URL for a raw launch argument (`dashboard.epix`,
/// `epix://talk.epix/topic/1`, or a raw address), using the managed scheme.
fn target_url(scheme: &str, arg: &str) -> String {
    let host = epix_node::parse_target(arg);
    let inner = epix_node::parse_inner_path(arg);
    let path = if inner.is_empty() { "/" } else { &inner };
    format!("{scheme}://{host}{path}")
}

/// Reopen the browser from the tray. Starts a fresh managed instance when there
/// is no window (background mode, or the previous one was closed); if one is
/// still running, asks Firefox (remote) to raise it - best-effort.
fn reopen_browser(child: &mut Option<Child>, firefox: &Path, profile: &Path, url: &str) {
    let spawn_fresh = |child: &mut Option<Child>| {
        let mut cmd = crate::browser_process::browser_command(firefox, profile);
        if let Ok(c) = cmd.arg(url).spawn() {
            *child = Some(c);
        }
    };
    match child {
        // No window yet (background mode) or it exited: start one.
        None => spawn_fresh(child),
        Some(c) => match c.try_wait() {
            Ok(Some(_)) => spawn_fresh(child),
            // Still running: best-effort remote open to raise it.
            Ok(None) => {
                let _ = Command::new(firefox).arg("--profile").arg(profile).arg(url).spawn();
            }
            Err(_) => {}
        },
    }
}

/// Close the managed browser on quit: a graceful TERM first (unix - lets
/// Firefox flush session state), then a hard kill if it lingers. No-op when
/// there is no window or it already closed.
pub(crate) fn close_browser(child: &mut Option<Child>) {
    let Some(child) = child.as_mut() else { return };
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    #[cfg(windows)]
    crate::browser_process::close_browser_tree(child);
    #[cfg(not(windows))]
    {
        #[cfg(unix)]
        {
        let _ = Command::new("kill").arg(child.id().to_string()).status();
        for _ in 0..20 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Park the current thread forever, keeping the process (and the node) alive.
/// Used in background mode when no tray host is available: there is no window
/// to wait on, and the node should keep serving until the process is killed.
pub fn park() {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Open a clearnet URL in the user's default browser (fast; these links are
/// public web, not `.epix`).
fn open_external(url: &str) {
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: the launcher is a GUI app, so a bare `cmd` spawn
        // would flash a console window.
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]).creation_flags(0x0800_0000);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = cmd.spawn();
}

/// Compact a long overlay host for the menu: onion/i2p hosts run 52-56 chars,
/// which would stretch the whole menu. Keeps enough of both ends to recognise
/// the address; the Stats page has the full string.
fn short_host(host: &str, suffix: &str) -> String {
    if host.len() <= 22 {
        return format!("{host}{suffix}");
    }
    format!("{}…{}{}", &host[..10], &host[host.len() - 6..], suffix)
}

/// Human-readable byte size (KB/MB/GB), matching the dashboard's feel.
fn human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.1} KB", b / KB)
    } else if b < KB * KB * KB {
        format!("{:.1} MB", b / (KB * KB))
    } else {
        format!("{:.2} GB", b / (KB * KB * KB))
    }
}

/// A convenience the caller uses on the fallback path: keep the launcher alive
/// until the browser process exits, then let the node shut down. On Windows it
/// also keeps the Epix icon stamped on the browser's windows (the tray path
/// does that on its tick; this is the no-tray fallback).
pub fn wait_for_browser(mut child: Child, #[allow(unused)] firefox: &Path) {
    #[cfg(windows)]
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                crate::icon::stamp_firefox_windows(firefox);
                std::thread::sleep(Duration::from_millis(1000));
            }
            Err(_) => break,
        }
    }
    let _ = child.wait();
}
