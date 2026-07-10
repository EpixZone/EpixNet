//! Single-instance control channel.
//!
//! The node now stays running in the background after the browser window
//! closes (anchored by the tray), so a second launch must not boot a second
//! node against the same data directory. On startup we try to reach an
//! already-running instance over a fixed loopback port; if one answers we hand
//! it the target to open and exit, otherwise we claim the port and become the
//! primary. The primary forwards each open-request to the tray loop, which
//! reopens the browser.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

/// Loopback control port the primary instance listens on. Kept well clear of
/// the UI (42222), proxy (43112), and SOCKS (43111) cluster - the node's UI
/// port can fall back into that range, and other Epix services roam it, so a
/// distinctive high port avoids colliding with them.
const CONTROL_ADDR: &str = "127.0.0.1:47821";
/// One-line request the secondary sends; the primary replies `OK`.
const OPEN_PREFIX: &str = "EPIX-OPEN ";
const ACK: &str = "OK";

/// Whether this process is the primary (owns the node) or a secondary that
/// handed its target to the running primary and should now exit.
pub enum Role {
    /// Another instance is already running; it was given the target to open.
    Secondary,
    /// This process owns the node; drain the receiver for open-requests
    /// (each is the raw launch argument a later launch wants opened).
    Primary(Receiver<String>),
}

/// Decide this process's role. If an instance is already running, forward the
/// launch argument to it and return [`Role::Secondary`]. Otherwise claim the
/// control port and return [`Role::Primary`] with the request receiver.
pub fn init(arg: &str) -> Role {
    if forward(arg) {
        return Role::Secondary;
    }
    match TcpListener::bind(CONTROL_ADDR) {
        Ok(listener) => Role::Primary(spawn_listener(listener)),
        Err(_) => {
            // Lost a startup race (or the port is otherwise taken). Try once
            // more to hand off; if that fails too, run as a best-effort primary
            // without a live control channel rather than refusing to start.
            if forward(arg) {
                Role::Secondary
            } else {
                eprintln!("· note: could not bind the single-instance control port; running without it");
                let (_tx, rx) = std::sync::mpsc::channel();
                Role::Primary(rx)
            }
        }
    }
}

/// Try to hand `arg` to a running primary. Returns true only if one answered
/// and acknowledged - so a stray connection to some other service on the port
/// doesn't count as a running instance.
fn forward(arg: &str) -> bool {
    let addr = match CONTROL_ADDR.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    if stream.write_all(format!("{OPEN_PREFIX}{arg}\n").as_bytes()).is_err() {
        return false;
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    match reader.read_line(&mut line) {
        Ok(_) => line.trim() == ACK,
        Err(_) => false,
    }
}

/// Accept control connections on a background thread, sending each open-request
/// (the raw launch argument) to the returned receiver.
fn spawn_listener(listener: TcpListener) -> Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            handle_conn(stream, &tx);
        }
    });
    rx
}

fn handle_conn(mut stream: TcpStream, tx: &Sender<String>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let Ok(read_half) = stream.try_clone() else { return };
    let mut line = String::new();
    if BufReader::new(read_half).read_line(&mut line).is_err() {
        return;
    }
    if let Some(arg) = line.trim().strip_prefix(OPEN_PREFIX) {
        let _ = tx.send(arg.to_string());
        let _ = writeln!(stream, "{ACK}");
    }
}
