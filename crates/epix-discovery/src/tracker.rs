//! Epix tracker (`epix://`) announce: query a tracker peer for xite peers.

use epix_core::{Error, PeerAddr, Result};
use epix_protocol::{vget, vmap, Connection};
use epix_transport::Transport;
use rmpv::Value;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

/// Parameters for an `announce` request.
pub struct AnnounceParams<'a> {
    /// Xite tracker hashes (`sha256(address)`) to query.
    pub hashes: &'a [[u8; 32]],
    /// Our fileserver port (0 if not accepting inbound).
    pub port: u16,
    /// IP types we want back, e.g. `["ipv4", "ipv6"]`.
    pub need_types: &'a [&'a str],
    /// Max peers per xite.
    pub need_num: i64,
}

/// Run an `announce` over an already-handshaked connection, returning the peers.
pub async fn announce(conn: &mut Connection, params: &AnnounceParams<'_>) -> Result<Vec<PeerAddr>> {
    let hashes = params
        .hashes
        .iter()
        .map(|h| Value::Binary(h.to_vec()))
        .collect();
    let need_types = params.need_types.iter().map(|t| Value::from(*t)).collect();
    let request = vmap(vec![
        ("hashes", Value::Array(hashes)),
        ("onions", Value::Array(vec![])),
        ("port", Value::from(params.port as i64)),
        ("need_types", Value::Array(need_types)),
        ("need_num", Value::from(params.need_num)),
        ("add", Value::Array(vec![])),
    ]);

    let res = conn.request("announce", request).await?;
    let per_xite = vget(&res, "peers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Protocol("announce response missing `peers`".into()))?;

    let mut peers = Vec::new();
    for xite in per_xite {
        for key in ["ipv4", "ip4", "ipv6"] {
            if let Some(list) = vget(xite, key).and_then(|v| v.as_array()) {
                for packed in list {
                    if let Value::Binary(bytes) = packed {
                        if let Some(p) = unpack_address(bytes) {
                            peers.push(p);
                        }
                    }
                }
            }
        }
    }
    Ok(peers)
}

/// Connect to an Epix tracker, handshake, and announce in one call.
pub async fn discover_via_epix_tracker(
    transport: &dyn Transport,
    tracker: &PeerAddr,
    params: &AnnounceParams<'_>,
) -> Result<Vec<PeerAddr>> {
    let mut conn = Connection::connect(transport, tracker).await?;
    conn.handshake().await?;
    announce(&mut conn, params).await
}

/// Unpack a 6-byte (ipv4) or 18-byte (ipv6) compact peer address.
/// Port is little-endian — EpixNet packs it with native-endian `struct.pack("H")`.
fn unpack_address(packed: &[u8]) -> Option<PeerAddr> {
    match packed.len() {
        6 => {
            let ip = Ipv4Addr::new(packed[0], packed[1], packed[2], packed[3]);
            let port = u16::from_le_bytes([packed[4], packed[5]]);
            Some(PeerAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))))
        }
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packed[0..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_le_bytes([packed[16], packed[17]]);
            Some(PeerAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpacks_ipv4_with_little_endian_port() {
        // 127.0.0.1:11111 -> port 11111 = 0x2B67 little-endian = [0x67, 0x2B]
        let packed = [127, 0, 0, 1, 0x67, 0x2B];
        let p = unpack_address(&packed).unwrap();
        assert_eq!(p, PeerAddr::parse("127.0.0.1:11111").unwrap());
    }

    #[test]
    fn rejects_bad_length() {
        assert!(unpack_address(&[1, 2, 3]).is_none());
    }
}
