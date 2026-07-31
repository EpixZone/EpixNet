//! Peer announcing: discover peers for a xite across one or more trackers.

use epix_core::PeerAddr;
use epix_discovery::{address_hash, discover_via_epix_tracker, AnnounceParams, AnnounceSender};

pub use epix_discovery::Tracker;

/// How we advertise ourselves to trackers, so they hand our address to other
/// nodes. Overlay addresses are the only way onion/i2p-only nodes get found.
#[derive(Clone, Default)]
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
    /// Signs the tracker's onion-ownership challenge; without it, trackers
    /// that verify onion adverts never register ours.
    pub onion_signer: Option<std::sync::Arc<dyn epix_discovery::OnionSigner>>,
}

impl std::fmt::Debug for SelfAdvert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfAdvert")
            .field("port", &self.port)
            .field("onion", &self.onion)
            .field("i2p", &self.i2p)
            .field("want_onion", &self.want_onion)
            .field("want_i2p", &self.want_i2p)
            .field("onion_signer", &self.onion_signer.is_some())
            .finish()
    }
}

/// Announce `xite_address` to each tracker - an EDX `Announce` over `sender`
/// for `epix://` announcers, the BitTorrent announce (UDP or HTTP, infohash =
/// `sha1(address)`) for tracker URLs - and return the de-duplicated union of
/// discovered peers. `Ok` as soon as ANY tracker answered - a reachable
/// tracker that knows zero peers is a success, not an error, or a small
/// peer-tracker that nobody announced to yet would be scored dead forever.
/// `Err` (the last tracker's error) only when every tracker failed, so a
/// single-tracker call reports that tracker's reachability exactly.
pub async fn announce(
    sender: &dyn AnnounceSender,
    xite_address: &str,
    trackers: &[Tracker],
    advert: &SelfAdvert,
) -> Result<Vec<PeerAddr>, String> {
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
        onion_signer: advert.onion_signer.as_deref(),
    };
    let mut peers: Vec<PeerAddr> = Vec::new();
    let mut fold = |found: Vec<PeerAddr>| {
        for p in found {
            if !peers.contains(&p) {
                peers.push(p);
            }
        }
    };
    let mut answered = trackers.is_empty();
    let mut last_error = String::new();
    for tracker in trackers {
        let result = match tracker {
            Tracker::Epix(addr) => discover_via_epix_tracker(sender, addr, &params)
                .await
                .map_err(|e| e.to_string()),
            Tracker::Bt(url) => {
                epix_discovery::announce_bittorrent(url, xite_address, advert.port).await
            }
        };
        match result {
            Ok(found) => {
                answered = true;
                fold(found);
            }
            Err(e) => last_error = e,
        }
    }
    if answered {
        Ok(peers)
    } else {
        Err(last_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_discovery::tracker_pc::{self, AnnounceResp, PeerBuckets};

    /// A tracker that always answers, with the compact ipv4 peers it is given.
    struct Answering(Vec<Vec<u8>>);

    #[async_trait::async_trait]
    impl AnnounceSender for Answering {
        async fn send(&self, _t: &PeerAddr, _p: Vec<u8>) -> Result<Vec<u8>, String> {
            let resp = AnnounceResp {
                peers: vec![PeerBuckets { ipv4: self.0.clone(), ..Default::default() }],
                onion_sign_this: String::new(),
                error: String::new(),
            };
            tracker_pc::encode_reply(&resp).map_err(|e| e.to_string())
        }
    }

    struct Dead;

    #[async_trait::async_trait]
    impl AnnounceSender for Dead {
        async fn send(&self, _t: &PeerAddr, _p: Vec<u8>) -> Result<Vec<u8>, String> {
            Err("dial timed out".into())
        }
    }

    fn one_tracker() -> Vec<Tracker> {
        vec![Tracker::Epix(PeerAddr::parse("1.2.3.4:26959").unwrap())]
    }

    /// The distinction the whole health scoring rests on: a tracker that
    /// answers with zero peers is Ok, not an error - every node is a tracker,
    /// and a small one almost always knows nobody for a given xite.
    #[tokio::test]
    async fn a_tracker_answering_zero_peers_is_a_success() {
        let peers = announce(&Answering(Vec::new()), "epix1xyz", &one_tracker(), &SelfAdvert::default())
            .await
            .expect("an answer with no peers is not an error");
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_tracker_is_an_error() {
        let err = announce(&Dead, "epix1xyz", &one_tracker(), &SelfAdvert::default())
            .await
            .unwrap_err();
        assert!(err.contains("dial timed out"));
    }

    /// With several trackers, one answer is enough for Ok - and the peers
    /// still fold across all answering trackers.
    #[tokio::test]
    async fn one_answer_among_failures_is_ok() {
        struct Flaky(std::sync::atomic::AtomicBool);

        #[async_trait::async_trait]
        impl AnnounceSender for Flaky {
            async fn send(&self, _t: &PeerAddr, _p: Vec<u8>) -> Result<Vec<u8>, String> {
                if !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return Err("first tracker down".into());
                }
                Answering(vec![vec![1, 2, 3, 4, 0x67, 0x2B]]).send(_t, _p).await
            }
        }

        let trackers = vec![
            Tracker::Epix(PeerAddr::parse("1.2.3.4:26959").unwrap()),
            Tracker::Epix(PeerAddr::parse("5.6.7.8:26959").unwrap()),
        ];
        let peers = announce(
            &Flaky(std::sync::atomic::AtomicBool::new(false)),
            "epix1xyz",
            &trackers,
            &SelfAdvert::default(),
        )
        .await
        .expect("one live tracker carries the announce");
        assert_eq!(peers, vec![PeerAddr::parse("1.2.3.4:11111").unwrap()]);
    }
}
