//! Minimal, in-process binding to [IPtProxy], the library the official iOS Tor
//! apps (Onion Browser, Orbot) use to run Snowflake and obfs4 as in-process
//! threads instead of a subprocess. We use only the Snowflake surface: start
//! it, learn the local SOCKS port it listens on, stop it. arti then dials its
//! bridge through `127.0.0.1:<port>` as an unmanaged pluggable transport, so no
//! binary is ever spawned and it works on iOS.
//!
//! When no prebuilt IPtProxy archive is vendored for the target (build.rs sets
//! `iptproxy_stub`), the same API compiles against a stub whose
//! [`start_snowflake`] returns [`Error::Unavailable`]. That keeps the `bridges`
//! feature building on every platform before the Go artifacts are in place; the
//! bootstrap watchdog treats "unavailable" like any other bridge failure.
//!
//! [IPtProxy]: https://github.com/tladesignz/IPtProxy

use std::fmt;

/// Snowflake rendezvous parameters. Strings are the same values Tor Browser
/// ships; the caller supplies the current set (they rotate).
#[derive(Debug, Clone)]
pub struct SnowflakeConfig {
    /// Comma-separated ICE (STUN) servers, e.g. `stun:stun.l.google.com:19302`.
    pub ice_servers: String,
    /// Broker URL the client rendezvous through.
    pub broker_url: String,
    /// Comma-separated domain-fronting hosts for the broker request.
    pub front_domains: String,
    /// AMP cache URL (optional rendezvous method); empty to disable.
    pub ampcache: String,
    /// Log file path; empty for none.
    pub log_file: String,
}

/// Why a Snowflake call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// This build has no IPtProxy library linked (stub), so Snowflake cannot run.
    Unavailable,
    /// A config string contained an interior NUL and could not cross the FFI.
    BadArgument,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unavailable => f.write_str(
                "IPtProxy is not bundled in this build; Snowflake bridges are unavailable",
            ),
            Error::BadArgument => f.write_str("a Snowflake config value contained a NUL byte"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Real binding: compiled only when a prebuilt IPtProxy archive is linked.
//
// NOTE (plan R1): the exact IPtProxy C signatures differ between the classic
// gomobile build and the newer C API. These are the classic gomobile symbols;
// they are reconciled against the vendored release's header when the artifact
// lands (phase 2). Only ever compiled with the real library present.
// ---------------------------------------------------------------------------
#[cfg(not(iptproxy_stub))]
mod imp {
    use super::{Error, SnowflakeConfig};
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_long};

    extern "C" {
        fn IPtProxyStartSnowflake(
            ice: *const c_char,
            url: *const c_char,
            front: *const c_char,
            ampcache: *const c_char,
            log_file: *const c_char,
            unsafe_logging: c_int,
            keep_local_addresses: c_int,
            unattended: c_int,
            max_peers: c_long,
        );
        fn IPtProxyStopSnowflake();
        fn IPtProxySnowflakePort() -> c_long;
    }

    pub fn start_snowflake(cfg: &SnowflakeConfig) -> Result<(), Error> {
        let ice = cstr(&cfg.ice_servers)?;
        let url = cstr(&cfg.broker_url)?;
        let front = cstr(&cfg.front_domains)?;
        let amp = cstr(&cfg.ampcache)?;
        let log = cstr(&cfg.log_file)?;
        // SAFETY: all pointers are valid, NUL-terminated CStrings that outlive
        // the call; IPtProxy copies what it needs. Scalars are plain values.
        unsafe {
            IPtProxyStartSnowflake(
                ice.as_ptr(),
                url.as_ptr(),
                front.as_ptr(),
                amp.as_ptr(),
                log.as_ptr(),
                0, // unsafe_logging off
                1, // keep_local_addresses (helps on some NATs)
                1, // unattended (no interactive prompts)
                1, // max_peers
            );
        }
        Ok(())
    }

    pub fn snowflake_port() -> u16 {
        // SAFETY: no arguments; returns the listener port (0 until it binds).
        let port = unsafe { IPtProxySnowflakePort() };
        u16::try_from(port).unwrap_or(0)
    }

    pub fn stop_snowflake() {
        // SAFETY: no arguments; idempotent in IPtProxy.
        unsafe { IPtProxyStopSnowflake() }
    }

    fn cstr(s: &str) -> Result<CString, Error> {
        CString::new(s).map_err(|_| Error::BadArgument)
    }
}

// ---------------------------------------------------------------------------
// Stub: no IPtProxy library for this target. Same API, no Go.
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

/// Whether this build actually links IPtProxy (`false` means the stub).
pub const AVAILABLE: bool = cfg!(not(iptproxy_stub));

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a linked IPtProxy the API degrades cleanly: start reports
    /// `Unavailable` and the port is 0, so a bridges build with no artifact
    /// simply falls back to a direct bootstrap instead of misbehaving.
    #[test]
    #[cfg(iptproxy_stub)]
    fn stub_reports_unavailable() {
        assert!(!AVAILABLE);
        let cfg = SnowflakeConfig {
            ice_servers: String::new(),
            broker_url: String::new(),
            front_domains: String::new(),
            ampcache: String::new(),
            log_file: String::new(),
        };
        assert_eq!(start_snowflake(&cfg), Err(Error::Unavailable));
        assert_eq!(snowflake_port(), 0);
        stop_snowflake(); // no-op, must not panic
    }
}
