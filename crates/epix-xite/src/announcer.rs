//! Peer announcing: discover peers for a xite across one or more trackers.

use epix_core::PeerAddr;
use epix_discovery::{address_hash, discover_via_epix_tracker, AnnounceParams};
use epix_transport::Transport;

/// How we advertise ourselves to trackers, so they hand our address to other
/// nodes. Overlay addresses are the only way onion/i2p-only nodes get found.
#[derive(Debug, Clone, Default)]
pub struct SelfAdvert {
    /// Our fileserver port (also the onion/i2p virtual port). 0 = passive.
    pub port: u16,
    /// Our onion address (b32 host, no `.onion`), if the service is up.
    pub onion: Option<String>,
    /// Our i2p address (b32 host, no `.i2p`, e.g. `<b32>.b32`), if ready.
    pub i2p: Option<String>,
    /// Whether we can dial onion peers (Tor up) - request them from trackers.
    pub want_onion: bool,
    /// Whether we can dial i2p peers (I2P up) - request them from trackers.
    pub want_i2p: bool,
}

/// Announce `xite_address` to each Epix tracker and return the de-duplicated
/// union of discovered peers. Trackers that error are skipped.
pub async fn announce(
    transport: &dyn Transport,
    xite_address: &str,
    trackers: &[PeerAddr],
    advert: &SelfAdvert,
) -> Vec<PeerAddr> {
    let hash = address_hash(xite_address);
    let mut need_types: Vec<&str> = vec!["ipv4", "ipv6"];
    if advert.want_onion {
        need_types.push("onion");
    }
    if advert.want_i2p {
        need_types.push("i2p");
    }
    // Advertise the overlay addresses we host (one entry, mapped to the hash).
    let onions: Vec<String> = advert.onion.iter().cloned().collect();
    let i2ps: Vec<String> = advert.i2p.iter().cloned().collect();
    let mut add: Vec<&str> = Vec::new();
    if !onions.is_empty() {
        add.push("onion");
    }
    if !i2ps.is_empty() {
        add.push("i2p");
    }
    let params = AnnounceParams {
        hashes: &[hash],
        port: advert.port,
        need_types: &need_types,
        need_num: 20,
        add: &add,
        onions: &onions,
        i2p: &i2ps,
    };
    let mut peers: Vec<PeerAddr> = Vec::new();
    for tracker in trackers {
        if let Ok(found) = discover_via_epix_tracker(transport, tracker, &params).await {
            for p in found {
                if !peers.contains(&p) {
                    peers.push(p);
                }
            }
        }
    }
    peers
}
