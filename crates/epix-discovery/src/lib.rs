//! `epix-discovery` - finding peers for a xite.
//!
//! The primary method on the live network is the **Epix tracker** (`epix://`):
//! an `announce` request over the ordinary EpixNet wire protocol (so it reuses
//! [`epix_protocol::Connection`]). BitTorrent trackers, the mainline DHT, PEX,
//! and local discovery will be added alongside it.

pub mod bittorrent;
pub mod tracker;

pub use bittorrent::announce_bittorrent;

use epix_core::PeerAddr;
use sha2::{Digest, Sha256};

/// A xite's tracker hash: `sha256(address)` (matches the reference address_hash).
pub fn address_hash(address: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(address.as_bytes());
    h.finalize().into()
}

pub use tracker::{announce, discover_via_epix_tracker, AnnounceParams};

/// One announcer, whichever protocol it speaks. The announce set mixes both
/// kinds: Epix trackers (nodes speaking the wire protocol's `announce`) and
/// public BitTorrent trackers, which serve as free rendezvous infrastructure -
/// every node announcing `sha1(address)` as an infohash finds the others, the
/// way the Python client's AnnounceBitTorrent plugin did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tracker {
    /// An Epix-protocol announcer (`epix://host:port`, any peer transport).
    Epix(PeerAddr),
    /// A BitTorrent tracker announce URL (`udp://host:port/announce`,
    /// `http(s)://host/announce`).
    Bt(String),
}

impl Tracker {
    /// Parse one announcer entry. `udp://` / `http://` / `https://` URLs are
    /// BitTorrent trackers. Epix announcers name their transport explicitly -
    /// `tcp://host:port`, `onion://…`, `i2p://…` (a node can front its
    /// announcer on any of them, so the scheme says how to reach it); the
    /// legacy blanket `epix://host:port` and a bare `host:port` still parse,
    /// with the transport inferred from the host form.
    pub fn parse(s: &str) -> Option<Tracker> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if s.starts_with("udp://") || s.starts_with("http://") || s.starts_with("https://") {
            // Minimal shape check: a host after the scheme.
            let rest = s.split_once("://").map(|(_, r)| r).unwrap_or("");
            if rest.is_empty() || rest.starts_with('/') {
                return None;
            }
            return Some(Tracker::Bt(s.to_string()));
        }
        // Transport-explicit or legacy scheme, else bare. The host form
        // itself determines the PeerAddr transport; an explicit scheme must
        // agree with it (a `tcp://x.onion:1` is a lie, not a tracker).
        let (scheme, bare) = match s.split_once("://") {
            Some((sch, rest)) if matches!(sch, "tcp" | "onion" | "i2p" | "epix") => {
                (Some(sch), rest)
            }
            Some(_) => return None,
            None => (None, s),
        };
        let addr = PeerAddr::parse(bare).ok()?;
        if let Some(scheme) = scheme {
            if scheme != "epix" && scheme != addr.scheme() {
                return None;
            }
        }
        Some(Tracker::Epix(addr))
    }
}

impl std::fmt::Display for Tracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The canonical form names the actual transport - the same key
            // the per-announcer stats use, so the two never drift apart.
            Tracker::Epix(p) => write!(f, "{}://{p}", p.scheme()),
            Tracker::Bt(url) => write!(f, "{url}"),
        }
    }
}

#[cfg(test)]
mod tracker_type_tests {
    use super::Tracker;

    #[test]
    fn every_default_tracker_parses() {
        for t in epix_core::DEFAULT_TRACKERS {
            assert!(Tracker::parse(t).is_some(), "unparseable default tracker: {t}");
        }
    }

    #[test]
    fn parses_each_kind_and_roundtrips() {
        // Transport-explicit, legacy epix://, and bare all parse; the
        // canonical (Display) form always names the real transport.
        for spelled in ["tcp://1.2.3.4:15441", "epix://1.2.3.4:15441", "1.2.3.4:15441"] {
            let t = Tracker::parse(spelled).unwrap();
            assert!(matches!(t, Tracker::Epix(_)));
            assert_eq!(t.to_string(), "tcp://1.2.3.4:15441");
        }
        let onion = "onion://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:15441";
        assert_eq!(Tracker::parse(onion).unwrap().to_string(), onion);
        // An explicit transport that contradicts the host form is a lie, not
        // a tracker.
        assert!(Tracker::parse("tcp://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:15441").is_none());
        let bt = Tracker::parse("udp://tracker.opentrackr.org:1337/announce").unwrap();
        assert!(matches!(&bt, Tracker::Bt(u) if u.starts_with("udp://")));
        assert_eq!(bt.to_string(), "udp://tracker.opentrackr.org:1337/announce");
        assert!(matches!(
            Tracker::parse("https://tracker.example.org:443/announce"),
            Some(Tracker::Bt(_))
        ));
        assert!(Tracker::parse("").is_none());
        assert!(Tracker::parse("udp://").is_none());
        assert!(Tracker::parse("not a tracker").is_none());
        assert!(Tracker::parse("ftp://1.2.3.4:15441").is_none());
    }
}
