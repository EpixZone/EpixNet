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

use std::path::Path;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use muda::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tao::event_loop::{ControlFlow, EventLoop};
use tray_icon::{Icon, TrayIconBuilder};

use crate::Ready;

/// The tray icon, decoded from the same PNG the Linux packaging ships.
const TRAY_PNG: &[u8] = include_bytes!("../../../packaging/linux/icons/epix-64.png");

/// What the launcher needs to hand the tray: the running node's state (for
/// stats) plus what it takes to reopen the browser.
pub struct TrayContext {
    pub ready: Ready,
    pub child: Child,
    pub rt: tokio::runtime::Handle,
}

/// A snapshot of node stats the menu shows, refreshed on a background task so
/// the UI thread never blocks on the node's locks.
#[derive(Clone, Default)]
struct Snapshot {
    connections: i64,
    peers_connected: u64,
    peers_total: u64,
    bytes_recv: u64,
    bytes_sent: u64,
    port_opened: bool,
    tor_status: String,
}

async fn snapshot(state: &epix_ui::AppState) -> Snapshot {
    let s = state.stats_json().await;
    let (_enabled, tor_status) = state.tor_status().await;
    let g = |k: &str| s.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    Snapshot {
        connections: s.get("connections").and_then(serde_json::Value::as_i64).unwrap_or(0),
        peers_connected: g("peers_connected"),
        peers_total: g("peers_total"),
        bytes_recv: g("bytes_recv"),
        bytes_sent: g("bytes_sent"),
        port_opened: s.get("port_opened").and_then(serde_json::Value::as_bool).unwrap_or(false),
        tor_status,
    }
}

/// Run the tray on the calling (main) thread. On success it takes over the
/// thread and only returns by exiting the process from the Quit item. When no
/// tray can be shown it logs why and hands the browser process back in `Err`,
/// so the caller can fall back to waiting on it.
pub fn run(ctx: TrayContext) -> Result<(), Child> {
    let unavailable = |reason: &str, child: Child| {
        eprintln!("· system tray unavailable ({reason}); running until the browser closes");
        Err(child)
    };

    if std::env::var("EPIX_NO_TRAY").is_ok_and(|v| v != "0" && !v.is_empty()) {
        return unavailable("disabled by EPIX_NO_TRAY", ctx.child);
    }
    // Linux/BSD without a display has no tray host; don't even try to init GTK.
    #[cfg(all(unix, not(target_os = "macos")))]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return unavailable("no display (DISPLAY/WAYLAND_DISPLAY unset)", ctx.child);
    }

    // Building the event loop + tray touches native toolkits (GTK on Linux)
    // that can panic on some setups. Catch it so we fall back instead of
    // aborting the whole launcher. The built objects never cross threads here,
    // so asserting unwind-safety is sound.
    let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(&ctx)));
    let (event_loop, tray, menu, handles) = match built {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return unavailable(&e, ctx.child),
        Err(_) => return unavailable("tray init panicked", ctx.child),
    };

    // Refresh the stats snapshot on the node's runtime every second.
    let snap = Arc::new(Mutex::new(Snapshot::default()));
    {
        let (snap, state) = (snap.clone(), ctx.ready.state.clone());
        ctx.rt.spawn(async move {
            loop {
                let s = snapshot(&state).await;
                if let Ok(mut g) = snap.lock() {
                    *g = s;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    let menu_rx = MenuEvent::receiver();
    let mut child = ctx.child;
    let display = ctx.ready.display.clone();
    let firefox = ctx.ready.firefox.clone();
    let profile = ctx.ready.profile.clone();
    let start_url = ctx.ready.start_url.clone();
    // Keep the tray and menu alive for the whole run; dropping either removes
    // the icon. The loop below diverges, so these never actually drop.
    let _tray = tray;
    let _menu = menu;

    event_loop.run(move |_event, _target, control_flow| {
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(1000));

        if let Ok(s) = snap.lock() {
            let reach = if s.port_opened { " (active)" } else { " (passive)" };
            handles.address.set_text(format!("Address: {display}{reach}"));
            handles.peers.set_text(format!(
                "Peers: {} connected / {} known",
                s.peers_connected, s.peers_total
            ));
            handles.conns.set_text(format!("Connections: {}", s.connections));
            handles
                .transfer
                .set_text(format!("Received {} · Sent {}", human(s.bytes_recv), human(s.bytes_sent)));
            let tor = if s.tor_status.is_empty() { "—" } else { s.tor_status.as_str() };
            handles.tor.set_text(format!("Tor: {tor}"));
        }

        while let Ok(ev) = menu_rx.try_recv() {
            if ev.id == handles.quit {
                // Leave any open browser window alone (the user may still be
                // reading); just stop the node by ending the process.
                *control_flow = ControlFlow::Exit;
            } else if ev.id == handles.open {
                reopen_browser(&mut child, &firefox, &profile, &start_url);
            } else if ev.id == handles.github {
                open_external("https://github.com/EpixZone/EpixNet");
            } else if ev.id == handles.issues {
                open_external("https://github.com/EpixZone/EpixNet/issues");
            } else if ev.id == handles.x {
                open_external("https://x.com/zone_epix");
            }
        }
    });
}

/// The dynamic menu items whose text updates, plus the ids of the actionable
/// ones. muda items are cheap handles (clone-shares the native item).
struct Handles {
    address: MenuItem,
    peers: MenuItem,
    conns: MenuItem,
    transfer: MenuItem,
    tor: MenuItem,
    open: muda::MenuId,
    github: muda::MenuId,
    issues: muda::MenuId,
    x: muda::MenuId,
    quit: muda::MenuId,
}

type Built = (EventLoop<()>, tray_icon::TrayIcon, Menu, Handles);

/// Create the event loop (this initialises GTK on Linux), the menu, and the
/// tray icon. Any step here may fail or panic on an unsupported host.
fn build(ctx: &TrayContext) -> Result<Built, String> {
    // The event loop must exist before the tray on Linux (it inits GTK).
    let event_loop = EventLoop::new();

    let menu = Menu::new();
    let header = MenuItem::new(format!("EpixNet {}", ctx.ready.version), false, None);
    let address = MenuItem::new("Address: …", false, None);
    let peers = MenuItem::new("Peers: …", false, None);
    let conns = MenuItem::new("Connections: …", false, None);
    let transfer = MenuItem::new("Transfer: …", false, None);
    let tor = MenuItem::new("Tor: …", false, None);
    let open = MenuItem::new("Open EpixNet", true, None);
    let github = MenuItem::new("GitHub", true, None);
    let issues = MenuItem::new("Report a bug", true, None);
    let x = MenuItem::new("EpixNet on X", true, None);
    let quit = MenuItem::new("Quit EpixNet", true, None);

    let sep = PredefinedMenuItem::separator;
    menu.append_items(&[
        &header,
        &sep(),
        &address,
        &peers,
        &conns,
        &transfer,
        &tor,
        &sep(),
        &open,
        &sep(),
        &github,
        &issues,
        &x,
        &sep(),
        &quit,
    ])
    .map_err(|e| format!("build menu: {e}"))?;

    let handles = Handles {
        open: open.id().clone(),
        github: github.id().clone(),
        issues: issues.id().clone(),
        x: x.id().clone(),
        quit: quit.id().clone(),
        address,
        peers,
        conns,
        transfer,
        tor,
    };

    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu.clone()))
        .with_tooltip("EpixNet")
        .with_icon(load_icon())
        .build()
        .map_err(|e| format!("build tray: {e}"))?;

    Ok((event_loop, tray, menu, handles))
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

/// Reopen the browser from the tray. If the previous window was closed, start a
/// fresh managed instance; if it is still running, ask Firefox (remote) to
/// raise it - best-effort, errors ignored.
fn reopen_browser(child: &mut Child, firefox: &Path, profile: &Path, url: &str) {
    match child.try_wait() {
        Ok(Some(_)) => {
            if let Ok(c) = Command::new(firefox)
                .arg("--profile")
                .arg(profile)
                .arg("--no-remote")
                .arg("--new-instance")
                .arg(url)
                .spawn()
            {
                *child = c;
            }
        }
        Ok(None) => {
            let _ = Command::new(firefox).arg("--profile").arg(profile).arg(url).spawn();
        }
        Err(_) => {}
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
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
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
/// until the browser process exits, then let the node shut down.
pub fn wait_for_browser(mut child: Child) {
    let _ = child.wait();
}
