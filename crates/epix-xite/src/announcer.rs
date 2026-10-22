//! Peer announcing: discover peers for a xite across one or more trackers.

use epix_core::{AttemptError, PeerAddr};
use epix_discovery::{
    address_hash, discover_via_epix_tracker_attempt, AnnounceParams, AnnounceSender,
};

pub use epix_discovery::Tracker;

/// How we advertise ourselves to trackers, so they hand our address to other
/// nodes. Overlay addresses are the only way onion/i2p-only nodes get found.
#[derive(Clone)]
pub struct SelfAdvert {
    /// Our fileserver port (also the onion/i2p virtual port). 0 = passive.
    pub port: u16,
    /// A live TCP listener of this family is available, and tracker traffic
    /// is direct (a Tor exit's source IP must never become our listen address).
    pub advertise_ipv4: bool,
    pub advertise_ipv6: bool,
    /// Our onion address (b32 host, no `.onion`), if the service is up.
    pub onion: Option<String>,
    /// Our i2p address (b32 host, no `.i2p`, e.g. `<b32>.b32`), if ready.
    pub i2p: Option<String>,
    /// Whether IP peers are dialable (directly or through Tor). An embedder
    /// with only an I2P/mesh transport must not spend its reply limit on IPs.
    pub want_clearnet: bool,
    /// Whether we can dial onion peers (Tor up) - request them from trackers.
    pub want_onion: bool,
    /// Whether we can dial i2p peers (I2P up) - request them from trackers.
    pub want_i2p: bool,
    /// Signs the tracker's onion-ownership challenge; without it, trackers
    /// that verify onion adverts never register ours.
    pub onion_signer: Option<std::sync::Arc<dyn epix_discovery::OnionSigner>>,
}

impl Default for SelfAdvert {
    fn default() -> Self {
        Self {
            port: 0,
            advertise_ipv4: false,
            advertise_ipv6: false,
            onion: None,
            i2p: None,
            // Preserve the ordinary bootstrap request before overlays start.
            want_clearnet: true,
            want_onion: false,
            want_i2p: false,
            onion_signer: None,
        }
    }
}

impl std::fmt::Debug for SelfAdvert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfAdvert")
            .field("port", &self.port)
            .field("advertise_ipv4", &self.advertise_ipv4)
            .field("advertise_ipv6", &self.advertise_ipv6)
            .field("onion", &self.onion)
            .field("i2p", &self.i2p)
            .field("want_clearnet", &self.want_clearnet)
            .field("want_onion", &self.want_onion)
            .field("want_i2p", &self.want_i2p)
            .field("onion_signer", &self.onion_signer.is_some())
            .finish()
    }
}

/// Ask one tracker: an EDX `Announce` over `sender` for `epix://`
/// announcers, the BitTorrent announce (UDP or HTTP, infohash =
/// `sha1(address)`) for tracker URLs.
async fn ask_tracker(
    sender: &dyn AnnounceSender,
    tracker: &Tracker,
    xite_address: &str,
    port: u16,
    params: &AnnounceParams<'_>,
) -> Result<Vec<PeerAddr>, AttemptError<String>> {
    match tracker {
        Tracker::Epix(addr) => discover_via_epix_tracker_attempt(sender, addr, params)
            .await
            .map_err(|error| error.map_failure(|error| error.to_string())),
        Tracker::Bt(url) => {
            #[cfg(feature = "bittorrent")]
            {
                epix_discovery::announce_bittorrent(url, xite_address, port)
                    .await
                    .map_err(AttemptError::Failed)
            }
            #[cfg(not(feature = "bittorrent"))]
            {
                // Imported configs and xite manifests may still contain BT
                // URLs. A build without BT must never contact those trackers.
                let _ = (url, xite_address, port);
                Err(AttemptError::Failed(
                    "BitTorrent tracker discovery is not available in this build".into(),
                ))
            }
        }
    }
}

/// Append the peers one tracker returned, skipping ones already known.
fn fold_peers(peers: &mut Vec<PeerAddr>, found: Vec<PeerAddr>) {
    for p in found {
        if !peers.contains(&p) {
            peers.push(p);
        }
    }
}

/// Announce `xite_address` to each tracker - an EDX `Announce` over `sender`
/// for `epix://` announcers, the BitTorrent announce (UDP or HTTP, infohash =
/// `sha1(address)`) for tracker URLs - and return the de-duplicated union of
/// discovered peers. `Ok` as soon as ANY tracker answered - a reachable
/// tracker that knows zero peers is a success, not an error, or a small
/// peer-tracker that nobody announced to yet would be scored dead forever.
/// `Err` only when no tracker answered. Genuine failures take precedence over
/// local dial deferrals, so a single-tracker call reports its result exactly.
pub async fn announce(
    sender: &dyn AnnounceSender,
    xite_address: &str,
    trackers: &[Tracker],
    advert: &SelfAdvert,
) -> Result<Vec<PeerAddr>, String> {
    announce_attempt(sender, xite_address, trackers, advert)
        .await
        .map_err(|error| match error {
            AttemptError::Failed(error) => error,
            // Deferrals originate in the Epix tracker path. Keep its legacy
            // protocol-error prefix for callers using the string API.
            AttemptError::Deferred(reason) => {
                epix_core::Error::Protocol(reason.to_string()).to_string()
            }
        })
}

/// Announce while preserving local dial deferrals for attempt accounting.
/// Any successful answer wins, even if it contains no peers. Otherwise the
/// last genuine failure wins; only an entirely deferred set returns Deferred.
pub async fn announce_attempt(
    sender: &dyn AnnounceSender,
    xite_address: &str,
    trackers: &[Tracker],
    advert: &SelfAdvert,
) -> Result<Vec<PeerAddr>, AttemptError<String>> {
    let hash = address_hash(xite_address);
    let mut need_types: Vec<&str> = if advert.want_clearnet {
        vec!["ipv4", "ipv6"]
    } else {
        Vec::new()
    };
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
    if advert.port != 0 {
        if advert.advertise_ipv4 {
            add.push("ipv4");
        }
        if advert.advertise_ipv6 {
            add.push("ipv6");
        }
    }
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
    let mut answered = trackers.is_empty();
    let mut last_failure = None;
    let mut last_deferred = None;
    for tracker in trackers {
        match ask_tracker(sender, tracker, xite_address, advert.port, &params).await {
            Ok(found) => {
                answered = true;
                fold_peers(&mut peers, found);
            }
            Err(AttemptError::Failed(error)) => last_failure = Some(error),
            Err(AttemptError::Deferred(reason)) => last_deferred = Some(reason),
        }
    }
    if answered {
        Ok(peers)
    } else if let Some(error) = last_failure {
        Err(AttemptError::Failed(error))
    } else if let Some(reason) = last_deferred {
        Err(AttemptError::Deferred(reason))
    } else {
        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_core::DeferredAttempt;
    use epix_discovery::tracker_pc::{self, AnnounceResp, PeerBuckets};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A tracker that always answers, with the compact ipv4 peers it is given.
    struct Answering(Vec<Vec<u8>>);

    #[async_trait::async_trait]
    impl AnnounceSender for Answering {
        async fn send(&self, _t: &PeerAddr, _p: Vec<u8>) -> Result<Vec<u8>, String> {
            let resp = AnnounceResp {
                peers: vec![PeerBuckets {
                    ipv4: self.0.clone(),
                    ..Default::default()
                }],
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

    #[cfg(not(feature = "bittorrent"))]
    #[tokio::test]
    async fn disabled_bittorrent_rejects_configured_trackers_without_network_access() {
        use std::time::Duration;
        use tokio::net::{TcpListener, UdpSocket};
        use tokio::time::timeout;

        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let trackers = vec![
            Tracker::Bt(format!("http://{}/announce", http.local_addr().unwrap())),
            Tracker::Bt(format!("udp://{}/announce", udp.local_addr().unwrap())),
        ];
        for tracker in &trackers {
            let err = timeout(
                Duration::from_secs(1),
                announce(
                    &Dead,
                    "epix1xyz",
                    std::slice::from_ref(tracker),
                    &SelfAdvert::default(),
                ),
            )
            .await
            .expect("unsupported trackers must fail without waiting for the network")
            .unwrap_err();
            assert!(err.contains("not available in this build"));
        }
        assert!(timeout(Duration::from_millis(20), http.accept())
            .await
            .is_err());
        let mut packet = [0; 128];
        assert!(
            timeout(Duration::from_millis(20), udp.recv_from(&mut packet))
                .await
                .is_err()
        );

        // A leftover BT URL must not prevent ordinary Epix discovery.
        let mut mixed = trackers;
        mixed.extend(one_tracker());
        let peers = announce(
            &Answering(vec![vec![1, 2, 3, 4, 0x67, 0x2B]]),
            "epix1xyz",
            &mixed,
            &SelfAdvert::default(),
        )
        .await
        .unwrap();
        assert_eq!(peers, vec![PeerAddr::parse("1.2.3.4:11111").unwrap()]);
    }

    #[cfg(feature = "bittorrent")]
    #[tokio::test]
    async fn enabled_bittorrent_still_announces_to_http_trackers() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::timeout;

        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tracker = Tracker::Bt(format!("http://{}/announce", http.local_addr().unwrap()));
        timeout(Duration::from_secs(5), async {
            let respond = async {
                let (mut stream, _) = http.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                    assert!(request.len() < 8192);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(request.starts_with("GET /announce?info_hash="));
                assert!(request.contains("&port=26552&"));
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nd5:peers0:e").await.unwrap();
            };
            let advert = SelfAdvert { port: 26552, ..Default::default() };
            let (result, ()) = tokio::join!(
                announce(&Dead, "epix1xyz", std::slice::from_ref(&tracker), &advert),
                respond,
            );
            assert!(result.unwrap().is_empty());
        })
        .await
        .expect("local tracker announce timed out");
    }

    /// The distinction the whole health scoring rests on: a tracker that
    /// answers with zero peers is Ok, not an error - every node is a tracker,
    /// and a small one almost always knows nobody for a given xite.
    #[tokio::test]
    async fn a_tracker_answering_zero_peers_is_a_success() {
        let peers = announce(
            &Answering(Vec::new()),
            "epix1xyz",
            &one_tracker(),
            &SelfAdvert::default(),
        )
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
                Answering(vec![vec![1, 2, 3, 4, 0x67, 0x2B]])
                    .send(_t, _p)
                    .await
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

    enum Outcome {
        Failed(&'static str),
        Deferred(DeferredAttempt),
        Peers(Vec<Vec<u8>>),
    }

    struct Outcomes(Mutex<VecDeque<Outcome>>);

    #[async_trait::async_trait]
    impl AnnounceSender for Outcomes {
        async fn send(&self, _tracker: &PeerAddr, _payload: Vec<u8>) -> Result<Vec<u8>, String> {
            panic!("announce must preserve typed outcomes");
        }

        async fn send_attempt(
            &self,
            tracker: &PeerAddr,
            payload: Vec<u8>,
        ) -> Result<Vec<u8>, AttemptError<String>> {
            let outcome = self
                .0
                .lock()
                .unwrap()
                .pop_front()
                .expect("one outcome per tracker");
            match outcome {
                Outcome::Failed(error) => Err(AttemptError::Failed(error.to_string())),
                Outcome::Deferred(reason) => Err(AttemptError::Deferred(reason)),
                Outcome::Peers(peers) => Answering(peers)
                    .send(tracker, payload)
                    .await
                    .map_err(AttemptError::Failed),
            }
        }
    }

    async fn announce_outcomes(
        outcomes: Vec<Outcome>,
    ) -> Result<Vec<PeerAddr>, AttemptError<String>> {
        let tracker = one_tracker().remove(0);
        let trackers = vec![tracker; outcomes.len()];
        let sender = Outcomes(Mutex::new(outcomes.into()));
        let result = announce_attempt(&sender, "epix1xyz", &trackers, &SelfAdvert::default()).await;
        assert!(
            sender.0.lock().unwrap().is_empty(),
            "all tracker replies are folded"
        );
        result
    }

    #[tokio::test]
    async fn mixed_deferred_results_do_not_hide_the_last_genuine_failure() {
        use DeferredAttempt::{FailedDialFollower, NegativeDialCache};
        for outcomes in [
            vec![
                Outcome::Failed("first dial failed"),
                Outcome::Deferred(NegativeDialCache),
            ],
            vec![
                Outcome::Deferred(FailedDialFollower),
                Outcome::Failed("first dial failed"),
            ],
            vec![
                Outcome::Failed("earlier failure"),
                Outcome::Deferred(NegativeDialCache),
                Outcome::Failed("first dial failed"),
                Outcome::Deferred(FailedDialFollower),
            ],
        ] {
            assert_eq!(
                announce_outcomes(outcomes).await.unwrap_err(),
                AttemptError::Failed("protocol: first dial failed".to_string())
            );
        }
    }

    #[tokio::test]
    async fn wholly_deferred_trackers_preserve_the_last_local_reason() {
        for reasons in [
            [
                DeferredAttempt::NegativeDialCache,
                DeferredAttempt::FailedDialFollower,
            ],
            [
                DeferredAttempt::FailedDialFollower,
                DeferredAttempt::NegativeDialCache,
            ],
        ] {
            let outcomes = reasons.iter().copied().map(Outcome::Deferred).collect();
            assert_eq!(
                announce_outcomes(outcomes).await.unwrap_err(),
                AttemptError::Deferred(reasons[1])
            );
        }
    }

    #[tokio::test]
    async fn failure_text_matching_a_local_reason_remains_a_failure() {
        for text in [
            "recent dial failure (negative cache)",
            "dial in flight failed",
        ] {
            assert_eq!(
                announce_outcomes(vec![
                    Outcome::Failed(text),
                    Outcome::Deferred(DeferredAttempt::NegativeDialCache)
                ])
                .await
                .unwrap_err(),
                AttemptError::Failed(format!("protocol: {text}"))
            );
        }
    }

    #[cfg(not(feature = "bittorrent"))]
    #[tokio::test]
    async fn unsupported_tracker_failure_is_not_hidden_by_a_deferred_epix_tracker() {
        let mut trackers = vec![Tracker::Bt("http://127.0.0.1:1/announce".to_string())];
        trackers.extend(one_tracker());
        let sender = Outcomes(Mutex::new(
            vec![Outcome::Deferred(DeferredAttempt::NegativeDialCache)].into(),
        ));
        let error = announce_attempt(&sender, "epix1xyz", &trackers, &SelfAdvert::default())
            .await
            .unwrap_err();
        assert_eq!(
            error,
            AttemptError::Failed(
                "BitTorrent tracker discovery is not available in this build".to_string()
            )
        );
        assert!(sender.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_or_successful_answers_win_over_failures_and_deferrals() {
        assert!(announce_outcomes(Vec::new()).await.unwrap().is_empty());
        for peers in [Vec::new(), vec![vec![1, 2, 3, 4, 0x67, 0x2B]]] {
            let result = announce_outcomes(vec![
                Outcome::Deferred(DeferredAttempt::NegativeDialCache),
                Outcome::Peers(peers.clone()),
                Outcome::Failed("dial failed"),
                Outcome::Peers(peers.clone()),
                Outcome::Deferred(DeferredAttempt::FailedDialFollower),
            ])
            .await
            .unwrap();
            let expected = if peers.is_empty() {
                Vec::new()
            } else {
                vec![PeerAddr::parse("1.2.3.4:11111").unwrap()]
            };
            assert_eq!(
                result, expected,
                "successful peer replies remain deduplicated"
            );
        }
    }

    #[tokio::test]
    async fn legacy_announce_preserves_deferred_protocol_diagnostics() {
        for reason in [
            DeferredAttempt::NegativeDialCache,
            DeferredAttempt::FailedDialFollower,
        ] {
            let sender = Outcomes(Mutex::new(vec![Outcome::Deferred(reason)].into()));
            assert_eq!(
                announce(&sender, "epix1xyz", &one_tracker(), &SelfAdvert::default())
                    .await
                    .unwrap_err(),
                format!("protocol: {reason}")
            );
        }
    }
}
