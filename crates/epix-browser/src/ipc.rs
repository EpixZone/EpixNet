//! Single-instance control channel, scoped to the selected data directory.
//!
//! Later launches confirm that they selected the same root before sending a
//! navigation target. The fixed control port still supports installer PING and
//! QUIT requests, but a different root or an older, unscoped listener cannot
//! silently receive a target or cause a second node to start.

use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const CONTROL_ADDR: &str = "127.0.0.1:47821";
const ROOT_PREFIX: &str = "EPIX-ROOT-V1 ";
const OPEN_PREFIX: &str = "EPIX-OPEN ";
const PING: &str = "EPIX-PING";
const QUIT: &str = "EPIX-QUIT";
const ACK: &str = "OK";
const DIFFERENT_ROOT: &str = "ERR-DIFFERENT-ROOT";
const PREPARING: &str = "ERR-PREPARING";
const ROOT_CHANGED: &str = "ERR-ROOT-CHANGED";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const QUIT_WAIT: Duration = Duration::from_secs(30);

type SharedScope = Arc<Mutex<ScopeState>>;
static ACTIVE_SCOPE: OnceLock<SharedScope> = OnceLock::new();

enum ScopeState {
    Preparing(String),
    Ready(String),
    Changed,
}

pub enum Role {
    Secondary,
    Primary(Receiver<Request>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    Open(String),
    Quit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QuitOutcome {
    NotRunning,
    Stopped,
    StillRunning,
}

fn root_scope(root: &Path) -> Result<String, String> {
    let resolved =
        epix_ui::data_relocation::resolve_trusted_root(root).map_err(|e| e.to_string())?;
    // Lossless OS bytes avoid making two non-Unicode directory names equal.
    // This is an identity comparison, not authentication of local processes.
    Ok(Sha256::digest(resolved.as_os_str().as_encoded_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Detect an instance for this root or claim the control listener. Never boot
/// a second node when an occupied port cannot confirm the same root.
pub fn init(arg: &str, forward_open: bool, data_root: &Path) -> Result<Role, String> {
    let requested = root_scope(data_root)?;
    let state = Arc::new(Mutex::new(ScopeState::Preparing(requested.clone())));
    let address = CONTROL_ADDR
        .parse()
        .map_err(|_| "Invalid browser control address")?;
    let role = init_at(address, arg, forward_open, &requested, state.clone())?;
    if matches!(role, Role::Primary(_)) {
        ACTIVE_SCOPE
            .set(state)
            .map_err(|_| "Browser control scope was already initialized")?;
    }
    Ok(role)
}

fn init_at(
    address: SocketAddr,
    arg: &str,
    open: bool,
    requested: &str,
    state: SharedScope,
) -> Result<Role, String> {
    validate_target(arg)?;
    // Claim first, probe second. A free port proves that no instance is
    // running, at no cost. Probing first cannot tell a closed port from a
    // stalled one on Windows: its loopback stack retries a refused connect for
    // about two seconds, so the short connect timeout expired before the
    // refusal arrived and every cold start was rejected as a timeout.
    match TcpListener::bind(address) {
        Ok(listener) => Ok(Role::Primary(spawn_listener(listener, state))),
        Err(error) => {
            // The port is owned: by a running instance, or by a simultaneous
            // launcher that won the listener. Either must still confirm the
            // selected root before receiving this target.
            if forward_at(address, arg, open, requested)? {
                Ok(Role::Secondary)
            } else {
                Err(format!(
                    "Cannot claim the Epix Browser control port: {error}"
                ))
            }
        }
    }
}

/// Call immediately after the eventual owner prepares the data directory.
/// Bind forwarding to the actual leased root, which a queued move may change
/// after preflight. Preparing never accepts navigation. An unexpected later
/// root change disables forwarding until the browser is restarted.
pub fn confirm_data_root(root: &Path) -> Result<(), String> {
    let actual = root_scope(root)?;
    if let Some(state) = ACTIVE_SCOPE.get() {
        confirm_scope(state, &actual)?;
    }
    Ok(())
}

fn confirm_scope(state: &SharedScope, actual: &str) -> Result<(), String> {
    let mut state = state
        .lock()
        .map_err(|_| "Browser control scope is unavailable")?;
    *state = match &*state {
        ScopeState::Preparing(_) => ScopeState::Ready(actual.to_string()),
        ScopeState::Ready(current) if current == actual => ScopeState::Ready(actual.to_string()),
        ScopeState::Ready(_) | ScopeState::Changed => ScopeState::Changed,
    };
    Ok(())
}

fn scope_reply(state: &SharedScope, requested: &str) -> &'static str {
    let Ok(state) = state.lock() else {
        return ROOT_CHANGED;
    };
    match &*state {
        ScopeState::Preparing(root) if root == requested => PREPARING,
        ScopeState::Ready(root) if root == requested => ACK,
        ScopeState::Preparing(_) | ScopeState::Ready(_) => DIFFERENT_ROOT,
        ScopeState::Changed => ROOT_CHANGED,
    }
}

fn validate_target(arg: &str) -> Result<(), String> {
    if arg.contains(['\r', '\n', '\0']) || arg.len() + OPEN_PREFIX.len() >= MAX_REQUEST_BYTES {
        Err("The browser launch target is invalid or too long".into())
    } else {
        Ok(())
    }
}

/// Installer quit stays compatible with old and new launchers. It deliberately
/// closes whichever managed browser owns the fixed control port.
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

fn response_error(response: &str) -> String {
    match response {
        DIFFERENT_ROOT => "Another Epix Browser instance uses a different data directory. Quit it before switching directories.",
        PREPARING => "Epix Browser is still preparing its data directory. Wait for startup to finish, then try again.",
        ROOT_CHANGED => "The running Epix Browser changed data directories during startup. Quit and restart it before opening another target.",
        _ => "The Epix Browser control port is occupied by an older or incompatible instance. Quit it before starting this version.",
    }.into()
}

fn control_stream(address: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&address, Duration::from_millis(300))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(stream)
}

/// The target is sent only after the same connection confirms the root. An
/// older listener therefore never sees a target intended for another node.
fn forward_at(address: SocketAddr, arg: &str, open: bool, requested: &str) -> Result<bool, String> {
    let mut stream = match control_stream(address) {
        Ok(stream) => stream,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => return Ok(false),
        Err(error) => {
            return Err(format!(
                "Cannot contact the Epix Browser control port: {error}"
            ))
        }
    };
    let read_half = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(read_half);
    writeln!(stream, "{ROOT_PREFIX}{requested}").map_err(|e| e.to_string())?;
    let response = read_request(&mut reader).map_err(|_| response_error(""))?;
    if response != ACK {
        return Err(response_error(&response));
    }
    let request = if open {
        format!("{OPEN_PREFIX}{arg}")
    } else {
        PING.to_string()
    };
    writeln!(stream, "{request}").map_err(|e| e.to_string())?;
    let response = read_request(&mut reader).map_err(|_| response_error(""))?;
    if response != ACK {
        return Err(response_error(&response));
    }
    Ok(true)
}

fn send(request: &str) -> bool {
    let Ok(address) = CONTROL_ADDR.parse() else {
        return false;
    };
    let Ok(mut stream) = control_stream(address) else {
        return false;
    };
    if writeln!(stream, "{request}").is_err() {
        return false;
    }
    read_request(&mut BufReader::new(stream)).is_ok_and(|response| response == ACK)
}

fn read_request(reader: &mut impl BufRead) -> std::io::Result<String> {
    let mut line = String::new();
    let size = reader
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_line(&mut line)?;
    if size > MAX_REQUEST_BYTES || !line.ends_with('\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid control request",
        ));
    }
    line.pop();
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

fn spawn_listener(listener: TcpListener, state: SharedScope) -> Receiver<Request> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            handle_conn(stream, &tx, &state);
        }
    });
    rx
}

fn handle_conn(mut stream: TcpStream, tx: &Sender<Request>, state: &SharedScope) {
    if stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .is_err()
    {
        return;
    }
    let Some((line, scoped)) = read_control_request(&mut stream, state) else {
        return;
    };
    let (request, ack) = if scoped {
        parse_scoped(&line)
    } else {
        parse(&line)
    };
    if let Some(request) = request {
        let _ = tx.send(request);
    }
    if ack {
        let _ = writeln!(stream, "{ACK}");
    }
}

/// Confirm the selected directory before accepting a navigation request.
/// Installer PING/QUIT retain their one-line protocol.
fn read_control_request(stream: &mut TcpStream, state: &SharedScope) -> Option<(String, bool)> {
    let read_half = stream.try_clone().ok()?;
    let mut reader = BufReader::new(read_half);
    let line = read_request(&mut reader).ok()?;
    if let Some(requested) = line.strip_prefix(ROOT_PREFIX) {
        let response = scope_reply(state, requested);
        if writeln!(stream, "{response}").is_err() || response != ACK {
            return None;
        }
        return Some((read_request(&mut reader).ok()?, true));
    }
    Some((line, false))
}

fn parse_scoped(line: &str) -> (Option<Request>, bool) {
    if let Some(arg) = line.strip_prefix(OPEN_PREFIX) {
        if validate_target(arg).is_ok() {
            return (Some(Request::Open(arg.to_string())), true);
        }
        return (None, false);
    }
    parse(line)
}

/// Unscoped requests are restricted to installer/liveness operations.
fn parse(line: &str) -> (Option<Request>, bool) {
    if line == PING {
        (None, true)
    } else if line == QUIT {
        (Some(Request::Quit), true)
    } else {
        (None, false)
    }
}

#[cfg(test)]
#[path = "tests/ipc.rs"]
mod tests;
