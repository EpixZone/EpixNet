//! The Epix native-messaging host binary.
//!
//! Firefox launches this and talks to it over stdio (4-byte LE length + JSON).
//! Each message is handled by [`epix_nmh::handle`]. Settings live next to the
//! node data so the launcher and the node see the same file.

use epix_nmh::{handle, read_frame, write_frame, Settings};
use std::io::{stdin, stdout};

/// UI ports to try when the node hasn't recorded its port yet: the current
/// default first, then the legacy port older nodes used.
const DEFAULT_UI_PORT: u16 = 42222;
const LEGACY_UI_PORT: u16 = 43110;

/// The node writes its actual UI port to `<data_root>/ui_port` at boot; read it
/// so we hit this node's status endpoint regardless of which port it bound. If
/// the file is missing (node not started, or an older build), probe the default
/// then legacy port for one that answers, else fall back to the default.
fn discover_ui_port(data_root: &std::path::Path) -> u16 {
    if let Ok(s) = std::fs::read_to_string(data_root.join("ui_port")) {
        if let Ok(port) = s.trim().parse::<u16>() {
            return port;
        }
    }
    for port in [DEFAULT_UI_PORT, LEGACY_UI_PORT] {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    DEFAULT_UI_PORT
}

fn main() {
    let data_root = epix_node::data_root();
    let settings = Settings::new(&data_root);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let mut input = stdin().lock();
    let mut output = stdout().lock();
    loop {
        match read_frame(&mut input) {
            Ok(Some(req)) => {
                // Re-read each request so a node restart on a new port is picked
                // up without relaunching Firefox.
                let ui_port = discover_ui_port(&data_root);
                let resp = rt.block_on(handle(&req, &settings, ui_port));
                if write_frame(&mut output, &resp).is_err() {
                    break;
                }
            }
            Ok(None) => break, // Firefox closed the pipe
            Err(_) => break,
        }
    }
}
