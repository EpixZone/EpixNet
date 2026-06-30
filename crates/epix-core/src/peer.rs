//! Transport-agnostic peer addressing across TCP, Tor, and Reticulum mesh.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A peer endpoint. The `Rns` variant is what makes mesh a first-class
/// transport: trackers/PEX can carry Reticulum destination hashes alongside
/// IP and onion endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerAddr {
    /// Clearnet IPv4/IPv6.
    Ip(SocketAddr),
    /// Tor onion service (`<host>.onion:<port>`), host without the `.onion`.
    Onion { host: String, port: u16 },
    /// Reticulum 16-byte destination hash.
    Rns([u8; 16]),
}

impl PeerAddr {
    pub fn scheme(&self) -> &'static str {
        match self {
            PeerAddr::Ip(_) => "tcp",
            PeerAddr::Onion { .. } => "onion",
            PeerAddr::Rns(_) => "rns",
        }
    }

    /// Parse `ip:port`, `<host>.onion:port`, or `rns:<32-hex>`.
    pub fn parse(s: &str) -> Result<Self> {
        if let Some(hash_hex) = s.strip_prefix("rns:") {
            let bytes = hex::decode(hash_hex).map_err(|_| Error::InvalidPeer(s.into()))?;
            let arr: [u8; 16] = bytes.try_into().map_err(|_| Error::InvalidPeer(s.into()))?;
            return Ok(PeerAddr::Rns(arr));
        }
        if let Some((host, port)) = s.rsplit_once(':') {
            if let Some(onion_host) = host.strip_suffix(".onion") {
                let port: u16 = port.parse().map_err(|_| Error::InvalidPeer(s.into()))?;
                return Ok(PeerAddr::Onion { host: onion_host.to_string(), port });
            }
        }
        s.parse::<SocketAddr>()
            .map(PeerAddr::Ip)
            .map_err(|_| Error::InvalidPeer(s.into()))
    }
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Ip(a) => write!(f, "{a}"),
            PeerAddr::Onion { host, port } => write!(f, "{host}.onion:{port}"),
            PeerAddr::Rns(h) => write!(f, "rns:{}", hex::encode(h)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_roundtrip_each_transport() {
        for (s, scheme) in [
            ("127.0.0.1:20790", "tcp"),
            ("[::1]:8080", "tcp"),
            ("abcdefghij234567.onion:43110", "onion"),
            ("rns:0123456789abcdef0123456789abcdef", "rns"),
        ] {
            let p = PeerAddr::parse(s).unwrap_or_else(|_| panic!("parse {s}"));
            assert_eq!(p.scheme(), scheme);
            assert_eq!(PeerAddr::parse(&p.to_string()).unwrap(), p, "roundtrip {s}");
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(PeerAddr::parse("nonsense").is_err());
        assert!(PeerAddr::parse("rns:xyz").is_err());
        assert!(PeerAddr::parse("1.2.3.4:99999").is_err());
    }
}
