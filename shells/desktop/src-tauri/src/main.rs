//! Epix desktop shell.
//!
//! A thin Tauri window over the embedded node ([`epix_node`]). The node serves
//! the xite UI on loopback exactly as the standalone binary does; this shell
//! adds a native window, a tray, `epix://` deep-link handling, and
//! single-instance behavior (a second launch, e.g. from a clicked link, routes
//! the URL to the already-running window instead of starting a second node).
//!
//! NOTE: building this needs the Tauri toolchain (`cargo tauri`), which is not
//! present in CI here; see `shells/README.md`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager};

/// Where the shell keeps node data (per-OS app data dir).
fn data_root(app: &tauri::AppHandle) -> std::path::PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("epix")
}

/// The last xite the shell was asked to open (default dashboard), so a deep
/// link that arrives before the node is serving is honored once it is.
#[derive(Default)]
struct Pending {
    target: Mutex<Option<String>>,
}

fn main() {
    let pending = Arc::new(Pending::default());

    tauri::Builder::default()
        // A second launch (clicked epix:// link) hands its argv here instead of
        // starting a new instance; route the URL to the running window.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if let Some(url) = argv.iter().find(|a| a.starts_with("epix://")) {
                navigate_to_target(app, &epix_node::parse_target(url));
            }
            let _ = app.get_webview_window("main").map(|w| w.set_focus());
        }))
        .plugin(tauri_plugin_deep_link::init())
        .manage(pending.clone())
        .setup(move |app| {
            let handle = app.handle().clone();

            // Register the epix:// scheme at runtime (Windows/Linux; macOS uses
            // the bundle's CFBundleURLTypes from tauri.conf.json).
            #[cfg(any(windows, target_os = "linux"))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let _ = app.deep_link().register("epix");
            }

            // A deep link delivered while running: navigate the window.
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let h = handle.clone();
                app.deep_link().on_open_url(move |event| {
                    if let Some(url) = event.urls().first() {
                        navigate_to_target(&h, &epix_node::parse_target(url.as_str()));
                    }
                });
            }

            // The launch argument, if the app was opened via an epix:// link.
            let launch_target = std::env::args()
                .nth(1)
                .filter(|a| a.starts_with("epix://"))
                .map(|a| epix_node::parse_target(&a))
                .unwrap_or_else(|| "dashboard.epix".to_string());
            *pending.target.lock().unwrap() = Some(launch_target.clone());

            // Boot the node on a background thread; navigate the window once it
            // is serving (the window starts on the loading page in dist/).
            let root = data_root(&handle);
            let h = handle.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                rt.block_on(async move {
                    let opts = epix_node::NodeOptions {
                        data_root: root,
                        target: launch_target.clone(),
                        ui_addr: epix_node::DEFAULT_UI_ADDR.to_string(),
                        tor_mode: "enable".to_string(),
                        open_browser: false,
                        geoip_gz: None,
                        log_file: None,
                        version: env!("CARGO_PKG_VERSION").to_string(),
                    };
                    match epix_node::boot(opts).await {
                        Ok((server, running)) => {
                            navigate_to_target(&h, &running.display);
                            let _ = server.serve(running.ui_addr).await;
                        }
                        Err(e) => {
                            let _ = h.emit("epix://error", e);
                        }
                    }
                });
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("run epix desktop");
}

/// Point the main window at a served xite on the local node.
fn navigate_to_target(app: &tauri::AppHandle, display: &str) {
    let url = format!("http://{}/{display}/", epix_node::DEFAULT_UI_ADDR);
    if let Some(win) = app.get_webview_window("main") {
        // Tauri v2: navigate the existing webview to the local node URL.
        if let Ok(parsed) = url.parse() {
            let _ = win.navigate(parsed);
        }
    }
}
