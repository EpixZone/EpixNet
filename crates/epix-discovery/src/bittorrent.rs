//! AnnounceBitTorrent - announce a site to HTTP(S) BitTorrent trackers and read
//! the peers they report (compact format). The `info_hash` is `sha1(address)`,
//! matching how EpixNet maps a site onto the BitTorrent DHT/tracker space.

use epix_core::PeerAddr;
use sha1::{Digest, Sha1};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Announce `address` to a BitTorrent tracker and return the peers it reports.
/// Dispatches by URL scheme: `udp://` uses the BEP-15 UDP protocol, otherwise
/// HTTP(S). Empty on any error.
pub async fn announce_bittorrent(tracker_url: &str, address: &str, my_port: u16) -> Vec<PeerAddr> {
    if tracker_url.starts_with("udp://") {
        return announce_bittorrent_udp(tracker_url, address, my_port).await;
    }
    announce_bittorrent_http(tracker_url, address, my_port).await
}

/// Announce `address` to an HTTP(S) tracker (`http(s)://host/announce`) and
/// return the peers it reports. Empty on any error.
pub async fn announce_bittorrent_http(tracker_url: &str, address: &str, my_port: u16) -> Vec<PeerAddr> {
    let info_hash: [u8; 20] = Sha1::digest(address.as_bytes()).into();
    let peer_id = b"-EPX0001-aaaaaaaaaaaa";
    let url = format!(
        "{}?info_hash={}&peer_id={}&port={}&uploaded=0&downloaded=0&left=431&compact=1&event=started&numwant=30",
        tracker_url.trim_end_matches('/'),
        percent_encode(&info_hash),
        percent_encode(&peer_id[..20]),
        my_port,
    );
    let Ok(resp) = reqwest::get(&url).await else { return Vec::new() };
    let Ok(body) = resp.bytes().await else { return Vec::new() };
    parse_compact_peers(&extract_bstring(&body, "peers"))
}

// ---- UDP tracker protocol (BEP 15) -----------------------------------------

const UDP_PROTOCOL_ID: u64 = 0x41727101980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
/// A fixed transaction id: each announce uses its own socket, so it only has to
/// be echoed back for us to match the response.
const TXN_ID: u32 = 0x4550_4958; // "EPIX"

/// Announce over a `udp://host:port` tracker (BEP 15): connect handshake, then
/// announce, returning the compact peers. Empty on any error or timeout.
pub async fn announce_bittorrent_udp(tracker_url: &str, address: &str, my_port: u16) -> Vec<PeerAddr> {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration};

    let host_port = tracker_url.trim_start_matches("udp://").split('/').next().unwrap_or("");
    if host_port.is_empty() {
        return Vec::new();
    }
    let info_hash: [u8; 20] = Sha1::digest(address.as_bytes()).into();
    let peer_id = b"-EPX0001-aaaaaaaaaaaa";

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    if sock.connect(host_port).await.is_err() {
        return Vec::new();
    }
    let wait = Duration::from_secs(5);

    // Connect handshake -> connection_id.
    if sock.send(&build_connect_request()).await.is_err() {
        return Vec::new();
    }
    let mut buf = [0u8; 2048];
    let Ok(Ok(n)) = timeout(wait, sock.recv(&mut buf)).await else { return Vec::new() };
    let Some(connection_id) = parse_connect_response(&buf[..n]) else { return Vec::new() };

    // Announce -> peers.
    let req = build_announce_request(connection_id, &info_hash, &peer_id[..20], my_port);
    if sock.send(&req).await.is_err() {
        return Vec::new();
    }
    let Ok(Ok(n)) = timeout(wait, sock.recv(&mut buf)).await else { return Vec::new() };
    parse_announce_response(&buf[..n])
}

/// 16-byte connect request: protocol id, action=connect, transaction id.
fn build_connect_request() -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&UDP_PROTOCOL_ID.to_be_bytes());
    out[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    out[12..16].copy_from_slice(&TXN_ID.to_be_bytes());
    out
}

/// Parse a connect response, returning the `connection_id` if the action and
/// transaction id match.
fn parse_connect_response(buf: &[u8]) -> Option<u64> {
    if buf.len() < 16 {
        return None;
    }
    let action = u32::from_be_bytes(buf[0..4].try_into().ok()?);
    let txn = u32::from_be_bytes(buf[4..8].try_into().ok()?);
    if action != ACTION_CONNECT || txn != TXN_ID {
        return None;
    }
    Some(u64::from_be_bytes(buf[8..16].try_into().ok()?))
}

/// 98-byte announce request.
fn build_announce_request(
    connection_id: u64,
    info_hash: &[u8],
    peer_id: &[u8],
    port: u16,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(98);
    out.extend_from_slice(&connection_id.to_be_bytes());
    out.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    out.extend_from_slice(&TXN_ID.to_be_bytes());
    out.extend_from_slice(&info_hash[..20]);
    out.extend_from_slice(&peer_id[..20]);
    out.extend_from_slice(&0u64.to_be_bytes()); // downloaded
    out.extend_from_slice(&431u64.to_be_bytes()); // left
    out.extend_from_slice(&0u64.to_be_bytes()); // uploaded
    out.extend_from_slice(&2u32.to_be_bytes()); // event = started
    out.extend_from_slice(&0u32.to_be_bytes()); // ip (0 = use source)
    out.extend_from_slice(&0u32.to_be_bytes()); // key
    out.extend_from_slice(&30i32.to_be_bytes()); // num_want
    out.extend_from_slice(&port.to_be_bytes());
    out
}

/// Parse an announce response: skip the 20-byte header (action, txn, interval,
/// leechers, seeders) and read the trailing compact peer list.
fn parse_announce_response(buf: &[u8]) -> Vec<PeerAddr> {
    if buf.len() < 20 {
        return Vec::new();
    }
    let action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let txn = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if action != ACTION_ANNOUNCE || txn != TXN_ID {
        return Vec::new();
    }
    parse_compact_peers(&buf[20..])
}

/// Percent-encode raw bytes for a URL query value (BitTorrent `info_hash` style).
fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Compact peers: 6 bytes each - 4-byte IPv4 + 2-byte big-endian port.
fn parse_compact_peers(data: &[u8]) -> Vec<PeerAddr> {
    data.chunks_exact(6)
        .filter_map(|c| {
            let port = u16::from_be_bytes([c[4], c[5]]);
            if port == 0 {
                return None;
            }
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            Some(PeerAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
        })
        .collect()
}

/// Read a bencoded byte-string value for `key` from a tracker response body.
fn extract_bstring(body: &[u8], key: &str) -> Vec<u8> {
    let needle = format!("{}:{}", key.len(), key);
    let Some(pos) = find_subslice(body, needle.as_bytes()) else { return Vec::new() };
    let mut i = pos + needle.len();
    let mut len = 0usize;
    while i < body.len() && body[i].is_ascii_digit() {
        len = len * 10 + (body[i] - b'0') as usize;
        i += 1;
    }
    if i >= body.len() || body[i] != b':' {
        return Vec::new();
    }
    i += 1;
    body.get(i..i + len).map(|s| s.to_vec()).unwrap_or_default()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_peers_from_a_bencode_response() {
        // d ... 5:peers 12:<two 6-byte peers> e
        let mut body = b"d8:completei1e5:peers12:".to_vec();
        body.extend_from_slice(&[1, 2, 3, 4, 0x3c, 0x41]); // 1.2.3.4:15425
        body.extend_from_slice(&[10, 0, 0, 1, 0x1a, 0xe1]); // 10.0.0.1:6881
        body.extend_from_slice(b"e");

        let peers = parse_compact_peers(&extract_bstring(&body, "peers"));
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].to_string(), "1.2.3.4:15425");
        assert_eq!(peers[1].to_string(), "10.0.0.1:6881");
    }

    #[test]
    fn info_hash_style_percent_encoding() {
        assert_eq!(percent_encode(&[0x12, 0xAB, b'a', b'-']), "%12%ABa-");
    }

    #[test]
    fn udp_connect_request_and_response_roundtrip() {
        let req = build_connect_request();
        assert_eq!(u64::from_be_bytes(req[0..8].try_into().unwrap()), UDP_PROTOCOL_ID);
        assert_eq!(u32::from_be_bytes(req[8..12].try_into().unwrap()), ACTION_CONNECT);

        // A well-formed connect response yields the connection id.
        let mut resp = Vec::new();
        resp.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
        resp.extend_from_slice(&TXN_ID.to_be_bytes());
        resp.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        assert_eq!(parse_connect_response(&resp), Some(0x1122_3344_5566_7788));

        // Wrong transaction id is rejected.
        let mut bad = resp.clone();
        bad[4] ^= 0xFF;
        assert_eq!(parse_connect_response(&bad), None);
    }

    #[test]
    fn udp_announce_request_shape_and_response_peers() {
        let info_hash = [7u8; 20];
        let peer_id = b"-EPX0001-aaaaaaaaaaaa";
        let req = build_announce_request(0xABCD, &info_hash, &peer_id[..20], 26552);
        assert_eq!(req.len(), 98);
        assert_eq!(u64::from_be_bytes(req[0..8].try_into().unwrap()), 0xABCD);
        assert_eq!(u32::from_be_bytes(req[8..12].try_into().unwrap()), ACTION_ANNOUNCE);
        assert_eq!(u16::from_be_bytes(req[96..98].try_into().unwrap()), 26552);

        // Announce response: 20-byte header then two compact peers.
        let mut resp = Vec::new();
        resp.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
        resp.extend_from_slice(&TXN_ID.to_be_bytes());
        resp.extend_from_slice(&900u32.to_be_bytes()); // interval
        resp.extend_from_slice(&1u32.to_be_bytes()); // leechers
        resp.extend_from_slice(&2u32.to_be_bytes()); // seeders
        resp.extend_from_slice(&[1, 2, 3, 4, 0x3c, 0x41]); // 1.2.3.4:15425
        resp.extend_from_slice(&[10, 0, 0, 1, 0x1a, 0xe1]); // 10.0.0.1:6881
        let peers = parse_announce_response(&resp);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].to_string(), "1.2.3.4:15425");

        // A response for a different action is ignored.
        let mut wrong = resp.clone();
        wrong[3] = 9;
        assert!(parse_announce_response(&wrong).is_empty());
    }
}
