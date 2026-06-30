//! Peer announcing: discover peers for a xite across one or more trackers.

use epix_core::PeerAddr;
use epix_discovery::{address_hash, discover_via_epix_tracker, AnnounceParams};
use epix_transport::Transport;

/// Announce `xite_address` to each Epix tracker and return the de-duplicated
/// union of discovered peers. Trackers that error are skipped.
pub async fn announce(
    transport: &dyn Transport,
    xite_address: &str,
    trackers: &[PeerAddr],
    port: u16,
) -> Vec<PeerAddr> {
    let hash = address_hash(xite_address);
    let params = AnnounceParams {
        hashes: &[hash],
        port,
        need_types: &["ipv4", "ipv6"],
        need_num: 20,
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
