//! Retained loopback listeners for instance-local services.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

pub const DEFAULT_TOR_SOCKS_PORT: u16 = 42322;
pub const DEFAULT_BROWSER_PROXY_PORT: u16 = 42422;
pub const DEFAULT_I2P_PROXY_PORT: u16 = 42522;

/// Bind the first available loopback port, retaining ownership in the returned
/// nonblocking listener. Only address collisions advance the search. The old
/// shared service range is skipped, so fallback cannot reclaim ZeroNet ports.
/// Port zero requests an OS-selected ephemeral port for isolated callers.
pub fn bind_loopback_listener(start: u16) -> io::Result<TcpListener> {
    let listener = bind_loopback_with(start, |port| {
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    })?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn bind_loopback_with<T>(start: u16, mut bind: impl FnMut(u16) -> io::Result<T>) -> io::Result<T> {
    let mut port = start;
    loop {
        if (43110..=43113).contains(&port) {
            port = 43114;
        }
        match bind(port) {
            Err(error) if port != 0 && error.kind() == io::ErrorKind::AddrInUse => {
                port = port.checked_add(1).ok_or(error)?;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::bind_loopback_with;
    use std::io::{Error, ErrorKind};

    #[test]
    fn collisions_advance_without_entering_legacy_range() {
        let mut attempted = Vec::new();
        let port = bind_loopback_with(43109, |port| {
            attempted.push(port);
            if port < 43115 {
                Err(Error::from(ErrorKind::AddrInUse))
            } else {
                Ok(port)
            }
        })
        .unwrap();
        assert_eq!(attempted, [43109, 43114, 43115]);
        assert_eq!(port, 43115);
    }

    #[test]
    fn non_collision_errors_do_not_scan() {
        let mut attempts = 0;
        let result = bind_loopback_with(42322, |_| {
            attempts += 1;
            Err::<(), _>(Error::from(ErrorKind::PermissionDenied))
        });
        assert_eq!(result.unwrap_err().kind(), ErrorKind::PermissionDenied);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn exhaustion_and_ephemeral_bind_errors_do_not_wrap() {
        for start in [0, u16::MAX] {
            let mut attempted = Vec::new();
            let result = bind_loopback_with(start, |port| {
                attempted.push(port);
                Err::<(), _>(Error::from(ErrorKind::AddrInUse))
            });
            assert_eq!(result.unwrap_err().kind(), ErrorKind::AddrInUse);
            assert_eq!(attempted, [start]);
        }
    }

    #[test]
    fn actual_listeners_remain_owned_and_loopback_only() {
        let first = super::bind_loopback_listener(0).unwrap();
        let address = first.local_addr().unwrap();
        let second = super::bind_loopback_listener(address.port()).unwrap();
        assert!(address.ip().is_loopback());
        assert!(second.local_addr().unwrap().ip().is_loopback());
        assert_ne!(address.port(), second.local_addr().unwrap().port());
        assert!(std::net::TcpListener::bind(address).is_err());
    }
}
