//! Minimal, in-process binding to the [epix-iptproxy] Snowflake wrapper. It runs
//! the Snowflake pluggable transport as in-process threads (no subprocess, so it
//! works on iOS) and exposes a local SOCKS port; arti then dials its bridge
//! through `127.0.0.1:<port>` as an unmanaged pluggable transport.
//!
//! The wrapper exports three C functions (`EpixStartSnowflake`,
//! `EpixSnowflakePort`, `EpixStopSnowflake`). build.rs picks how they are
//! reached for the target:
//!
//! - macOS / Linux / iOS: statically linked (`iptproxy_static`).
//! - Windows / Android: loaded at runtime from the shared library shipped beside
//!   the executable (`iptproxy_dynamic`); if the library is missing at runtime
//!   [`start_snowflake`] returns [`Error::Unavailable`].
//! - Neither artifact available: a stub (`iptproxy_stub`) whose start returns
//!   [`Error::Unavailable`], so a `bridges` build always compiles.
//!
//! In every case an unavailable Snowflake makes the node fall back to a direct
//! Tor bootstrap rather than misbehave.
//!
//! [epix-iptproxy]: https://github.com/EpixZone/epix-iptproxy

use std::fmt;

/// Snowflake rendezvous parameters plus the transport's state directory.
#[derive(Debug, Clone)]
pub struct SnowflakeConfig {
    /// Directory the transport keeps its state and log in.
    pub state_dir: String,
    /// Comma-separated ICE (STUN) servers, e.g. `stun:stun.l.google.com:19302`.
    pub ice_servers: String,
    /// Broker URL the client rendezvous through.
    pub broker_url: String,
    /// Comma-separated domain-fronting hosts for the broker request.
    pub front_domains: String,
    /// AMP cache URL (optional rendezvous method); empty to disable.
    pub ampcache: String,
    /// How many simultaneous Snowflake proxies to collect and load-balance
    /// across. One proxy is often slow; more improve throughput and resilience.
    /// The wrapper clamps this to a sane range (defaults to 3 if below 1).
    pub max_proxies: u16,
}

/// Why a Snowflake call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No IPtProxy library is available (stub, or the runtime library is missing).
    Unavailable,
    /// A config string contained an interior NUL and could not cross the FFI.
    BadArgument,
    /// The transport failed to start (broker/state error); code from the wrapper.
    StartFailed(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unavailable => f.write_str(
                "the Snowflake library is not available in this build; bridges are unavailable",
            ),
            Error::BadArgument => f.write_str("a Snowflake config value contained a NUL byte"),
            Error::StartFailed(c) => write!(f, "Snowflake failed to start (code {c})"),
        }
    }
}

impl std::error::Error for Error {}

/// Turn the config strings into NUL-terminated C strings (kept alive by caller).
#[cfg(any(iptproxy_static, iptproxy_dynamic))]
fn cstrings(cfg: &SnowflakeConfig) -> Result<[std::ffi::CString; 5], Error> {
    use std::ffi::CString;
    let mk = |s: &str| CString::new(s).map_err(|_| Error::BadArgument);
    Ok([
        mk(&cfg.state_dir)?,
        mk(&cfg.ice_servers)?,
        mk(&cfg.broker_url)?,
        mk(&cfg.front_domains)?,
        mk(&cfg.ampcache)?,
    ])
}

/// The wrapper's `EpixStartSnowflake` signature: five rendezvous strings plus the
/// proxy count. The static backend reaches it as an extern item, the dynamic one
/// as a loaded symbol, but both call it the same way.
#[cfg(any(iptproxy_static, iptproxy_dynamic))]
type StartFn = unsafe extern "C" fn(
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    *const std::os::raw::c_char,
    std::os::raw::c_int,
) -> std::os::raw::c_int;

/// Marshal the config and call `start`. Shared by the static and dynamic backends
/// so the FFI arguments are only spelled out once.
#[cfg(any(iptproxy_static, iptproxy_dynamic))]
fn invoke_start(cfg: &SnowflakeConfig, start: StartFn) -> Result<(), Error> {
    let s = cstrings(cfg)?;
    // SAFETY: five valid NUL-terminated pointers that outlive the call, plus the
    // proxy count passed by value.
    let rc = unsafe {
        start(
            s[0].as_ptr(),
            s[1].as_ptr(),
            s[2].as_ptr(),
            s[3].as_ptr(),
            s[4].as_ptr(),
            std::os::raw::c_int::from(cfg.max_proxies.min(i16::MAX as u16) as i16),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::StartFailed(rc))
    }
}

// ---------------------------------------------------------------------------
// Static: the wrapper archive is linked into this binary.
// ---------------------------------------------------------------------------
#[cfg(iptproxy_static)]
mod imp {
    use super::{invoke_start, Error, SnowflakeConfig};
    use std::os::raw::{c_char, c_int};

    extern "C" {
        fn EpixStartSnowflake(
            state_dir: *const c_char,
            ice: *const c_char,
            broker: *const c_char,
            fronts: *const c_char,
            ampcache: *const c_char,
            max: c_int,
        ) -> c_int;
        fn EpixSnowflakePort() -> c_int;
        fn EpixStopSnowflake();
    }

    pub fn start_snowflake(cfg: &SnowflakeConfig) -> Result<(), Error> {
        // The extern item coerces to the shared `StartFn` fn pointer.
        invoke_start(cfg, EpixStartSnowflake)
    }

    pub fn snowflake_port() -> u16 {
        // SAFETY: no arguments; returns the listener port (0 until it binds).
        u16::try_from(unsafe { EpixSnowflakePort() }).unwrap_or(0)
    }

    pub fn stop_snowflake() {
        // SAFETY: no arguments; idempotent in the wrapper.
        unsafe { EpixStopSnowflake() }
    }
}

// ---------------------------------------------------------------------------
// Dynamic: load the shared library at runtime (Windows / Android).
// ---------------------------------------------------------------------------
#[cfg(iptproxy_dynamic)]
mod imp {
    use super::{invoke_start, Error, SnowflakeConfig, StartFn};
    use libloading::{Library, Symbol};
    use std::os::raw::c_int;
    use std::sync::OnceLock;

    type PortFn = unsafe extern "C" fn() -> c_int;
    type StopFn = unsafe extern "C" fn();

    struct Loaded {
        // The library must outlive the resolved symbols; keep it owned.
        _lib: Library,
        start: RawStart,
        port: RawPort,
        stop: RawStop,
    }
    // Raw fn pointers copied out of the Symbols, so we do not borrow the library.
    type RawStart = StartFn;
    type RawPort = PortFn;
    type RawStop = StopFn;

    // Safe to share: the loaded fn pointers are plain code addresses; the wrapper
    // guards its own state with a mutex.
    unsafe impl Sync for Loaded {}
    unsafe impl Send for Loaded {}

    static LOADED: OnceLock<Option<Loaded>> = OnceLock::new();

    /// Candidate paths for the shared library: beside the executable (where the
    /// packaged app and `cargo run` place it), then the bare filename (OS search
    /// path), then an explicit override.
    fn candidates() -> Vec<std::path::PathBuf> {
        let name = env!("IPTPROXY_LIB_FILENAME");
        let mut v = Vec::new();
        if let Some(dir) = std::env::var_os("EPIX_IPTPROXY_LIB") {
            v.push(std::path::PathBuf::from(dir).join(name));
        }
        // current_exe only locates the app's own sibling library; an attacker
        // who could write beside the executable could replace the executable
        // itself, so this adds no privilege-escalation surface.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                v.push(dir.join(name));
            }
        }
        v.push(std::path::PathBuf::from(name));
        v
    }

    /// Open a shared library by path. On Windows a bare filename triggers the
    /// OS DLL search, which can include the current working directory - a
    /// DLL-planting vector; restrict it to the application and system directories
    /// (the library ships beside the executable, so it is still found). Other
    /// targets (Android) load through the app's own linker namespace, which
    /// consults no such hijackable search path, so the plain open is correct.
    #[cfg(windows)]
    unsafe fn open_library(path: &std::path::Path) -> Result<Library, libloading::Error> {
        use libloading::os::windows::{Library as WinLibrary, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS};
        WinLibrary::load_with_flags(path, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS).map(Library::from)
    }

    #[cfg(not(windows))]
    unsafe fn open_library(path: &std::path::Path) -> Result<Library, libloading::Error> {
        Library::new(path)
    }

    fn load() -> Option<Loaded> {
        for path in candidates() {
            // SAFETY: loading a trusted, app-shipped library; running its init.
            let Ok(lib) = (unsafe { open_library(&path) }) else { continue };
            // SAFETY: the wrapper exports exactly these C symbols/signatures.
            let loaded = unsafe {
                let start: Symbol<StartFn> = lib.get(b"EpixStartSnowflake\0").ok()?;
                let port: Symbol<PortFn> = lib.get(b"EpixSnowflakePort\0").ok()?;
                let stop: Symbol<StopFn> = lib.get(b"EpixStopSnowflake\0").ok()?;
                Loaded { start: *start, port: *port, stop: *stop, _lib: lib }
            };
            return Some(loaded);
        }
        None
    }

    fn loaded() -> Option<&'static Loaded> {
        LOADED.get_or_init(load).as_ref()
    }

    pub fn start_snowflake(cfg: &SnowflakeConfig) -> Result<(), Error> {
        let l = loaded().ok_or(Error::Unavailable)?;
        invoke_start(cfg, l.start)
    }

    pub fn snowflake_port() -> u16 {
        match loaded() {
            // SAFETY: no arguments.
            Some(l) => u16::try_from(unsafe { (l.port)() }).unwrap_or(0),
            None => 0,
        }
    }

    pub fn stop_snowflake() {
        if let Some(l) = loaded() {
            // SAFETY: no arguments; idempotent in the wrapper.
            unsafe { (l.stop)() }
        }
    }
}

// ---------------------------------------------------------------------------
// Stub: no library for this target.
// ---------------------------------------------------------------------------
#[cfg(iptproxy_stub)]
mod imp {
    use super::{Error, SnowflakeConfig};

    pub fn start_snowflake(_cfg: &SnowflakeConfig) -> Result<(), Error> {
        Err(Error::Unavailable)
    }

    pub fn snowflake_port() -> u16 {
        0
    }

    pub fn stop_snowflake() {}
}

/// Whether this build wires Snowflake at all (`false` is the stub). A `true`
/// value on a dynamic target still depends on the runtime library being present.
pub const WIRED: bool = cfg!(any(iptproxy_static, iptproxy_dynamic));

/// Start Snowflake in-process. On success it begins listening on a local SOCKS
/// port; poll [`snowflake_port`] until it is non-zero before dialing through it.
pub fn start_snowflake(cfg: &SnowflakeConfig) -> Result<(), Error> {
    imp::start_snowflake(cfg)
}

/// The local SOCKS port Snowflake listens on, or `0` if not up yet.
pub fn snowflake_port() -> u16 {
    imp::snowflake_port()
}

/// Stop Snowflake and release its listener.
pub fn stop_snowflake() {
    imp::stop_snowflake()
}

// Deterministic only for the stub: start is always `Unavailable`, with no
// network. On dynamic/static targets the outcome depends on the real library's
// presence, so the degradation contract is not unit-tested there.
#[cfg(all(test, iptproxy_stub))]
mod tests {
    use super::*;

    /// With no library the API degrades cleanly: start reports `Unavailable`
    /// and the port is 0, so a bridges build with no artifact falls back to a
    /// direct bootstrap instead of misbehaving.
    #[test]
    fn missing_library_reports_unavailable() {
        let cfg = SnowflakeConfig {
            state_dir: String::new(),
            ice_servers: String::new(),
            broker_url: String::new(),
            front_domains: String::new(),
            ampcache: String::new(),
            max_proxies: 3,
        };
        assert_eq!(start_snowflake(&cfg), Err(Error::Unavailable));
        assert_eq!(snowflake_port(), 0);
        stop_snowflake(); // must not panic
    }
}
