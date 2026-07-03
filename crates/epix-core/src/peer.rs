//! Transport-agnostic peer addressing across TCP, Tor, and Reticulum mesh.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// The peer-address category, matching EpixNet's `helper.getIpType` and the
/// three PEX buckets (`ipv4`/`ipv6`/`onion`). Reticulum peers are `rns`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpType {
    Ipv4,
    Ipv6,
    Onion,
    Rns,
}

impl IpType {
    /// The PEX field name a peer of this type is packed into
    /// (`peers`/`peers_ipv6`/`peers_onion`), or None for types PEX doesn't carry.
    pub fn pex_field(self) -> Option<&'static str> {
        match self {
            IpType::Ipv4 => Some("peers"),
            IpType::Ipv6 => Some("peers_ipv6"),
            IpType::Onion => Some("peers_onion"),
            IpType::Rns => None,
        }
    }
}

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

    /// This peer's address category.
    pub fn ip_type(&self) -> IpType {
        match self {
            PeerAddr::Ip(SocketAddr::V4(_)) => IpType::Ipv4,
            PeerAddr::Ip(SocketAddr::V6(_)) => IpType::Ipv6,
            PeerAddr::Onion { .. } => IpType::Onion,
            PeerAddr::Rns(_) => IpType::Rns,
        }
    }

    /// True for loopback/private IPs (EpixNet skips these in PEX with
    /// `allow_private=False`).
    pub fn is_private(&self) -> bool {
        match self {
            PeerAddr::Ip(addr) => match addr.ip() {
                IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
                IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
            },
            _ => false,
        }
    }

    /// Pack to EpixNet's compact wire form: 6 bytes (ipv4) / 18 (ipv6) / onion
    /// b32-decoded host + 2, all with a little-endian port. `None` for Rns
    /// (PEX carries a separate `rns` field, added when the mesh transport lands).
    pub fn pack(&self) -> Option<Vec<u8>> {
        match self {
            PeerAddr::Ip(SocketAddr::V4(a)) => {
                let mut out = a.ip().octets().to_vec();
                out.extend_from_slice(&a.port().to_le_bytes());
                Some(out)
            }
            PeerAddr::Ip(SocketAddr::V6(a)) => {
                let mut out = a.ip().octets().to_vec();
                out.extend_from_slice(&a.port().to_le_bytes());
                Some(out)
            }
            PeerAddr::Onion { host, port } => {
                let raw = data_encoding::BASE32_NOPAD
                    .decode(host.to_uppercase().as_bytes())
                    .ok()?;
                let mut out = raw;
                out.extend_from_slice(&port.to_le_bytes());
                Some(out)
            }
            PeerAddr::Rns(_) => None,
        }
    }

    /// Unpack a compact ipv4 (6) or ipv6 (18) address (little-endian port).
    pub fn unpack_ip(packed: &[u8]) -> Option<Self> {
        match packed.len() {
            6 => {
                let ip = Ipv4Addr::new(packed[0], packed[1], packed[2], packed[3]);
                let port = u16::from_le_bytes([packed[4], packed[5]]);
                Some(PeerAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))))
            }
            18 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packed[0..16]);
                let port = u16::from_le_bytes([packed[16], packed[17]]);
                Some(PeerAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    0,
                    0,
                ))))
            }
            _ => None,
        }
    }

    /// Unpack a compact onion address (b32 host + little-endian port).
    pub fn unpack_onion(packed: &[u8]) -> Option<Self> {
        if packed.len() < 3 {
            return None;
        }
        let (host_bytes, port_bytes) = packed.split_at(packed.len() - 2);
        let host = data_encoding::BASE32_NOPAD.encode(host_bytes).to_lowercase();
        let port = u16::from_le_bytes([port_bytes[0], port_bytes[1]]);
        Some(PeerAddr::Onion { host, port })
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

    #[test]
    fn packs_and_unpacks_ipv4_ipv6_onion() {
        // ipv4: 6 bytes, little-endian port.
        let p = PeerAddr::parse("127.0.0.1:11111").unwrap();
        let packed = p.pack().unwrap();
        assert_eq!(packed.len(), 6);
        assert_eq!(&packed[4..], &11111u16.to_le_bytes());
        assert_eq!(PeerAddr::unpack_ip(&packed).unwrap(), p);

        // ipv6: 18 bytes.
        let p = PeerAddr::parse("[::1]:8080").unwrap();
        let packed = p.pack().unwrap();
        assert_eq!(packed.len(), 18);
        assert_eq!(PeerAddr::unpack_ip(&packed).unwrap(), p);

        // onion: b32 host + 2, roundtrips.
        let p = PeerAddr::parse("abcdefghij234567.onion:43110").unwrap();
        let packed = p.pack().unwrap();
        assert_eq!(PeerAddr::unpack_onion(&packed).unwrap(), p);

        // Rns doesn't pack (PEX carries it separately).
        assert!(PeerAddr::parse("rns:0123456789abcdef0123456789abcdef")
            .unwrap()
            .pack()
            .is_none());
    }

    #[test]
    fn ip_type_and_private() {
        assert_eq!(PeerAddr::parse("8.8.8.8:1").unwrap().ip_type(), IpType::Ipv4);
        assert_eq!(PeerAddr::parse("[2001:db8::1]:1").unwrap().ip_type(), IpType::Ipv6);
        assert_eq!(PeerAddr::parse("aaa.onion:1").unwrap().ip_type(), IpType::Onion);
        assert!(PeerAddr::parse("127.0.0.1:1").unwrap().is_private());
        assert!(PeerAddr::parse("192.168.1.5:1").unwrap().is_private());
        assert!(!PeerAddr::parse("8.8.8.8:1").unwrap().is_private());
    }
}
