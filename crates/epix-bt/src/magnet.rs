//! Magnet-link parsing (BitTorrent `magnet:?xt=urn:btih:...`).
//!
//! We keep every source a magnet can name: the info-hash (`xt`), display name
//! (`dn`), trackers (`tr`), web seeds (`ws`), and the exact `.torrent` source
//! (`xs`/`as`). The node uses these in priority order given what its transport
//! can reach - e.g. over Tor, UDP trackers and the DHT are unreachable, so the
//! HTTPS web seed and the `xs` .torrent are the usable sources.

use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagnetLink {
    /// 20-byte BitTorrent v1 info-hash (from `xt=urn:btih:`).
    pub info_hash: [u8; 20],
    /// Human display name (`dn`), if given.
    pub name: Option<String>,
    /// Announce URLs (`tr`) - http(s), udp, or ws/wss (WebRTC).
    pub trackers: Vec<String>,
    /// HTTP(S) web seeds (`ws`, BEP19) - directly streamable through the node.
    pub web_seeds: Vec<String>,
    /// Exact `.torrent` sources (`xs`/`as`) - fetch to get the full metainfo
    /// (piece hashes, file list) without asking peers.
    pub sources: Vec<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MagnetError {
    #[error("not a magnet: URI")]
    NotMagnet,
    #[error("magnet has no xt=urn:btih: info-hash")]
    NoInfoHash,
    #[error("info-hash is neither 40-hex nor 32-base32")]
    BadInfoHash,
}

impl MagnetLink {
    /// The info-hash as lowercase hex (the canonical id used everywhere).
    pub fn info_hash_hex(&self) -> String {
        hex::encode(self.info_hash)
    }
}

/// Parse a `magnet:?...` URI. Unknown/extra params are ignored; only `xt` (a
/// btih hash) is required.
pub fn parse(uri: &str) -> Result<MagnetLink, MagnetError> {
    let query = uri.strip_prefix("magnet:?").ok_or(MagnetError::NotMagnet)?;

    let mut info_hash = None;
    let mut name = None;
    let mut trackers = Vec::new();
    let mut web_seeds = Vec::new();
    let mut sources = Vec::new();

    for pair in query.split('&') {
        let Some((key, raw)) = pair.split_once('=') else { continue };
        // Values are percent-encoded; `+` is not a space in magnet queries
        // (that's form encoding), so decode percent-escapes only.
        let val = percent_decode_str(raw).decode_utf8_lossy().into_owned();
        // A param can be indexed: `tr.1`, `ws.2`. Match on the base key.
        let base = key.split('.').next().unwrap_or(key);
        match base {
            "xt" => {
                if let Some(h) = val.strip_prefix("urn:btih:") {
                    info_hash = Some(parse_btih(h)?);
                }
                // urn:btmh: (v2) is intentionally not handled yet.
            }
            "dn" => name = Some(val),
            "tr" => trackers.push(val),
            "ws" => web_seeds.push(val),
            "xs" | "as" => sources.push(val),
            _ => {}
        }
    }

    Ok(MagnetLink {
        info_hash: info_hash.ok_or(MagnetError::NoInfoHash)?,
        name,
        trackers,
        web_seeds,
        sources,
    })
}

/// A btih value is 40 hex chars or 32 base32 chars (RFC 4648, no padding).
fn parse_btih(s: &str) -> Result<[u8; 20], MagnetError> {
    let s = s.trim();
    if s.len() == 40 {
        let bytes = hex::decode(s).map_err(|_| MagnetError::BadInfoHash)?;
        return bytes.try_into().map_err(|_| MagnetError::BadInfoHash);
    }
    if s.len() == 32 {
        return base32_decode(s).ok_or(MagnetError::BadInfoHash);
    }
    Err(MagnetError::BadInfoHash)
}

/// Decode 32 base32 chars → 20 bytes (RFC 4648 alphabet, case-insensitive).
fn base32_decode(s: &str) -> Option<[u8; 20]> {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::with_capacity(20);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let up = c.to_ascii_uppercase();
        let idx = ALPHABET.iter().position(|&a| a == up)? as u32;
        buffer = (buffer << 5) | idx;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEARS: &str = "magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec&dn=Tears+of+Steel&tr=udp%3A%2F%2Fexplodie.org%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=wss%3A%2F%2Ftracker.openwebtorrent.com&ws=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2F&xs=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2Ftears-of-steel.torrent";

    #[test]
    fn parses_tears_of_steel() {
        let m = parse(TEARS).unwrap();
        assert_eq!(m.info_hash_hex(), "209c8226b299b308beaf2b9cd3fb49212dbd13ec");
        // `+` stays literal (magnet is not form-encoded).
        assert_eq!(m.name.as_deref(), Some("Tears+of+Steel"));
        assert_eq!(m.web_seeds, vec!["https://webtorrent.io/torrents/"]);
        assert_eq!(m.sources, vec!["https://webtorrent.io/torrents/tears-of-steel.torrent"]);
        assert!(m.trackers.iter().any(|t| t == "udp://explodie.org:6969"));
        assert!(m.trackers.iter().any(|t| t.starts_with("wss://")));
    }

    #[test]
    fn requires_a_btih_hash() {
        assert_eq!(parse("http://example/x"), Err(MagnetError::NotMagnet));
        assert_eq!(parse("magnet:?dn=x"), Err(MagnetError::NoInfoHash));
        assert_eq!(parse("magnet:?xt=urn:btih:zz"), Err(MagnetError::BadInfoHash));
    }

    #[test]
    fn accepts_base32_infohash() {
        // 40-hex and its base32 form must decode to the same 20 bytes.
        let hexhash = "209c8226b299b308beaf2b9cd3fb49212dbd13ec";
        let raw = hex::decode(hexhash).unwrap();
        // Encode those 20 bytes to base32 for the test input.
        const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut b32 = String::new();
        let (mut buf, mut bits) = (0u32, 0u32);
        for &byte in &raw {
            buf = (buf << 8) | byte as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                b32.push(A[((buf >> bits) & 0x1f) as usize] as char);
            }
        }
        let m = parse(&format!("magnet:?xt=urn:btih:{b32}")).unwrap();
        assert_eq!(m.info_hash_hex(), hexhash);
    }
}
