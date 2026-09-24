//! Single-instance control channel.
//!
//! The node now stays running in the background after the browser window
//! closes (anchored by the tray), so a second launch must not boot a second
//! node against the same data directory. On startup we try to reach an
//! already-running instance over a fixed loopback port; if one answers we hand
//! it the target to open and exit, otherwise we claim the port and become the
//! primary. The primary forwards each open-request to the tray loop, which
//! reopens the browser.
//!
//! The same channel carries a quit request (`epix-browser --quit`), so an
//! installer or a script can close a running EpixNet cleanly - browser window
//! and node - instead of killing the process tree under a live data directory.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

/// Loopback control port the primary instance listens on. Kept well clear of
/// the UI (42222), proxy (43112), and SOCKS (43111) cluster - the node's UI
/// port can fall back into that range, and other Epix services roam it, so a
/// distinctive high port avoids colliding with them.
const CONTROL_ADDR: &str = "127.0.0.1:47821";
/// One-line requests the secondary sends; the primary replies `OK`.
const OPEN_PREFIX: &str = "EPIX-OPEN ";
/// Detect-only ping (background launch): primary acks but opens nothing.
const PING: &str = "EPIX-PING";
/// Ask the primary to quit: close its browser, shut the node down, exit.
const QUIT: &str = "EPIX-QUIT";
const ACK: &str = "OK";

/// How long `--quit` waits for the primary to go away after it acknowledged.
/// Covers the browser's own close plus the node's bounded shutdown grace.
const QUIT_WAIT: Duration = Duration::from_secs(30);

/// Whether this process is the primary (owns the node) or a secondary that
/// handed its target to the running primary and should now exit.
pub enum Role {
    /// Another instance is already running; it was given the target to open.
    Secondary,
    /// This process owns the node; drain the receiver for requests from later
    /// launches.
    Primary(Receiver<Request>),
}

/// One request a later launch handed to the running primary.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// Open this launch argument (a xite name / epix:// URL) in the browser.
    Open(String),
    /// Close the browser, shut the node down and exit.
    Quit,
}

/// Outcome of a `--quit` launch.
#[derive(Debug, PartialEq, Eq)]
pub enum QuitOutcome {
    /// No instance was running (or none that speaks this protocol).
    NotRunning,
    /// The primary acknowledged and its control port went silent.
    Stopped,
    /// The primary acknowledged but was still answering after the wait.
    StillRunning,
}

/// Decide this process's role. If an instance is already running, detect it and
/// return [`Role::Secondary`]; otherwise claim the control port and return
/// [`Role::Primary`] with the request receiver. When `forward_open` is true a
/// detected instance is also asked to open `arg` (a normal launch); in
/// background mode it is false, so autostart doesn't pop a window on top of
/// what the user is doing - it just detects and steps aside.
pub fn init(arg: &str, forward_open: bool) -> Role {
    if forward(arg, forward_open) {
        return Role::Secondary;
    }
    match TcpListener::bind(CONTROL_ADDR) {
        Ok(listener) => Role::Primary(spawn_listener(listener)),
        Err(_) => {
            // Lost a startup race (or the port is otherwise taken). Try once
            // more to hand off; if that fails too, run as a best-effort primary
            // without a live control channel rather than refusing to start.
            if forward(arg, forward_open) {
                Role::Secondary
            } else {
                eprintln!("· note: could not bind the single-instance control port; running without it");
                let (_tx, rx) = std::sync::mpsc::channel();
                Role::Primary(rx)
            }
        }
    }
}

/// Ask a running primary to quit and wait for it to go. Used by the Windows
/// installer before it replaces the install tree: a browser or node still
/// running from that tree keeps its DLLs locked, and a half-replaced Firefox
/// starts and exits at once ("Couldn't load XPCOM", exit 255).
pub fn request_quit() -> QuitOutcome {
    if !send(QUIT) {
        return QuitOutcome::NotRunning;
    }
    let deadline = Instant::now() + QUIT_WAIT;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if !send(PING) {
            return QuitOutcome::Stopped;
        }
    }
    QuitOutcome::StillRunning
}

/// Reach a running primary. With `open`, ask it to open `arg`; without, just
/// ping it. Returns true only if one answered and acknowledged - so a stray
/// connection to some other service on the port doesn't count as an instance.
fn forward(arg: &str, open: bool) -> bool {
    if open {
        send(&format!("{OPEN_PREFIX}{arg}"))
    } else {
        send(PING)
    }
}

/// Send one request line to the primary; true only on an acknowledgement.
fn send(request: &str) -> bool {
    let addr = match CONTROL_ADDR.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    if stream.write_all(format!("{request}\n").as_bytes()).is_err() {
        return false;
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    match reader.read_line(&mut line) {
        Ok(_) => line.trim() == ACK,
        Err(_) => false,
    }
}

/// Accept control connections on a background thread, sending each request
/// to the returned receiver.
fn spawn_listener(listener: TcpListener) -> Receiver<Request> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            handle_conn(stream, &tx);
        }
    });
    rx
}

fn handle_conn(mut stream: TcpStream, tx: &Sender<Request>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let Ok(read_half) = stream.try_clone() else { return };
    let mut line = String::new();
    if BufReader::new(read_half).read_line(&mut line).is_err() {
        return;
    }
    let (request, ack) = parse(line.trim());
    if let Some(request) = request {
        let _ = tx.send(request);
    }
    if ack {
        let _ = writeln!(stream, "{ACK}");
    }
}

/// One request line -> what to hand the tray loop (if anything) and whether
/// to acknowledge. Unknown lines get neither, so a stray client on the port
/// cannot pass for an instance.
fn parse(line: &str) -> (Option<Request>, bool) {
    if let Some(arg) = line.strip_prefix(OPEN_PREFIX) {
        (Some(Request::Open(arg.to_string())), true)
    } else if line == PING {
        // Detect-only (a background launch): acknowledge, open nothing.
        (None, true)
    } else if line == QUIT {
        (Some(Request::Quit), true)
    } else {
        (None, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_ping_and_quit_lines_parse() {
        assert_eq!(
            parse("EPIX-OPEN talk.epix"),
            (Some(Request::Open("talk.epix".to_string())), true)
        );
        assert_eq!(parse("EPIX-PING"), (None, true));
        assert_eq!(parse("EPIX-QUIT"), (Some(Request::Quit), true));
    }

    #[test]
    fn unknown_lines_are_neither_forwarded_nor_acknowledged() {
        assert_eq!(parse("GET / HTTP/1.1"), (None, false));
        assert_eq!(parse(""), (None, false));
        assert_eq!(parse("EPIX-QUIT now"), (None, false));
    }
}
