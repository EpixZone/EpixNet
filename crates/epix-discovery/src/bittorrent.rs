//! AnnounceBitTorrent - announce a site to HTTP(S) BitTorrent trackers and read
//! the peers they report (compact format). The `info_hash` is `sha1(address)`,
//! matching how EpixNet maps a site onto the BitTorrent DHT/tracker space.

use epix_core::PeerAddr;
use sha1::{Digest, Sha1};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Announce `address` to an HTTP(S) tracker (`http(s)://host/announce`) and
/// return the peers it reports. Empty on any error.
pub async fn announce_bittorrent(tracker_url: &str, address: &str, my_port: u16) -> Vec<PeerAddr> {
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
}
