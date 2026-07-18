//! EpixNet's native BitTorrent bridge.
//!
//! The design goal is privacy-preserving, platform-gated magnet streaming: the
//! NODE (never the xite page) fetches magnet-referenced media and streams it to
//! a xite over the local Range endpoint. Because the fetch happens in the node,
//! it can route through the node's Tor SOCKS proxy (no IP leak), and because
//! the whole crate is behind the `bittorrent` cargo feature it is compiled into
//! desktop/Android builds and OUT of the iOS build (App Store 5.2.3 / 2.3.1) -
//! the lock-down is the code being absent, not switched off.
//!
//! Source priority (what the engine uses given what the transport can reach):
//! over Tor, UDP trackers and the DHT are unreachable, so the usable sources
//! are the HTTPS web seed (`ws=`, BEP19) and the `.torrent` at `xs=`. On
//! clearnet the peer-wire + trackers + DHT (later modules) join in.
//!
//! This first landing is the verified foundation: bencode, magnet + metainfo
//! parsing (with recomputed info-hash checks), and the HTTP client factory that
//! routes fetches through Tor. The piece store, web-seed source, streaming
//! engine, and peer wire build on top.

pub mod bencode;
pub mod http;
pub mod magnet;
pub mod metainfo;

pub use magnet::{parse as parse_magnet, MagnetLink};
pub use metainfo::{FileEntry, MetaInfo};

/// A magnet a xite asked to stream, resolved to its usable sources - the shape
/// the node's magnet endpoint hands to the engine. The info-hash is the id; the
/// web seeds are today's data path; the sources (`xs`) supply the metainfo.
#[derive(Debug, Clone)]
pub struct StreamRequest {
    pub magnet: MagnetLink,
}

impl StreamRequest {
    pub fn from_uri(uri: &str) -> Result<Self, magnet::MagnetError> {
        Ok(Self { magnet: magnet::parse(uri)? })
    }

    /// Whether any source the node can reach today (a web seed or an `xs`
    /// `.torrent` over HTTP) is present. Without one, over Tor there is nothing
    /// to fetch until the peer-wire lands.
    pub fn has_http_source(&self) -> bool {
        !self.magnet.web_seeds.is_empty() || !self.magnet.sources.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_request_reports_http_sources() {
        let uri = "magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec\
                   &ws=https%3A%2F%2Fwebtorrent.io%2Ftorrents%2F";
        let req = StreamRequest::from_uri(uri).unwrap();
        assert!(req.has_http_source());
        assert_eq!(req.magnet.info_hash_hex(), "209c8226b299b308beaf2b9cd3fb49212dbd13ec");

        let bare = StreamRequest::from_uri(
            "magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec",
        )
        .unwrap();
        assert!(!bare.has_http_source());
    }
}
