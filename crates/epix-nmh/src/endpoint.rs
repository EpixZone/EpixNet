//! Metadata selects only a numeric local address. A signed response still
//! proves that the selected socket belongs to this node, even if it is stale.

use crate::Settings;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

impl Settings {
    pub(super) fn ui_endpoint(&self, port: u16) -> SocketAddr {
        self.data_root()
            .and_then(|root| read_endpoint(&root.join("ui_addr"), port))
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
    }
}

fn read_endpoint(path: &Path, port: u16) -> Option<SocketAddr> {
    let file = std::fs::File::open(path).ok()?;
    let mut encoded = String::new();
    file.take(128).read_to_string(&mut encoded).ok()?;
    if encoded.len() == 128 {
        return None;
    }
    let address: SocketAddr = encoded.trim().parse().ok()?;
    if address.port() != port {
        return None;
    }
    if address.ip().is_loopback() {
        return Some(address);
    }
    let local = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        _ => return None,
    };
    Some(SocketAddr::new(local, port))
}

#[cfg(test)]
mod tests {
    use crate::Settings;

    #[test]
    fn endpoint_metadata_is_bounded_local_and_bound_to_selected_port() {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::new(directory.path());
        let default = "127.0.0.1:42223";
        assert_eq!(settings.ui_endpoint(42223).to_string(), default);
        for (encoded, expected) in [
            ("[::1]:42223", "[::1]:42223"),
            ("127.0.0.2:42223\n", "127.0.0.2:42223"),
            ("[::]:42223", "[::1]:42223"),
            ("0.0.0.0:42223", default),
            ("192.0.2.1:42223", default),
            ("[2001:db8::1]:42223", default),
            ("attacker.example:42223", default),
            ("http://127.0.0.1:42223/", default),
            ("[::1]:42224", default),
            ("garbage", default),
        ] {
            std::fs::write(directory.path().join("ui_addr"), encoded).unwrap();
            assert_eq!(
                settings.ui_endpoint(42223).to_string(),
                expected,
                "{encoded}"
            );
        }
        std::fs::write(
            directory.path().join("ui_addr"),
            " ".repeat(128) + "[::1]:42223",
        )
        .unwrap();
        assert_eq!(settings.ui_endpoint(42223).to_string(), default);
    }
}
