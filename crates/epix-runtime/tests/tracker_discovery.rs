//! Real tracker RPCs, EDX handshakes, signed manifests and verified file
//! downloads over a controlled network. Only the physical stream transport is
//! substituted, so these tests need neither a public tracker nor I2P tunnels.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use epix_blob::ObjId;
use epix_core::{PeerAddr, Result};
use epix_protocol::server::EdxHook;
use epix_runtime::edx::{ensure_edx_serve, new_serve_cell, ControlHandles};
use epix_transport::{PeerStream, Transport};
use epix_ui::{AppState, XiteEntry};
use epix_xite::{Tracker, XiteStorage};
use serde_json::json;

#[derive(Default)]
struct Network {
    routes: Mutex<HashMap<PeerAddr, EdxHook>>,
    dials: Mutex<Vec<PeerAddr>>,
}

struct Endpoint {
    network: Arc<Network>,
    source: PeerAddr,
}

#[async_trait::async_trait]
impl Transport for Endpoint {
    fn scheme(&self) -> &'static str {
        "test-network"
    }

    async fn dial(&self, target: &PeerAddr) -> Result<PeerStream> {
        self.network.dials.lock().unwrap().push(target.clone());
        let hook = self
            .network
            .routes
            .lock()
            .unwrap()
            .get(target)
            .cloned()
            .ok_or_else(|| epix_core::Error::Protocol(format!("unknown destination {target}")))?;
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(hook(self.source.clone(), Box::pin(server)));
        Ok(Box::pin(client))
    }
}

struct Node {
    state: Arc<AppState>,
    _data: tempfile::TempDir,
}

impl Node {
    async fn new(network: &Arc<Network>, listen: Option<PeerAddr>, i2p: bool, base: bool) -> Self {
        let data = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("tracker-test", data.path());
        let cell = new_serve_cell(ControlHandles::detached());
        let serve = ensure_edx_serve(&cell, &state).await.unwrap();
        let source = if i2p {
            // The SAM accept loop has no peer destination until EDX Hello.
            PeerAddr::I2p {
                dest: String::new(),
                port: 0,
            }
        } else {
            match &listen {
                Some(PeerAddr::Ip(sa)) => PeerAddr::Ip(std::net::SocketAddr::new(sa.ip(), 41000)),
                _ => PeerAddr::parse("9.9.9.9:41001").unwrap(),
            }
        };
        let transport: Arc<dyn Transport> = Arc::new(Endpoint {
            network: network.clone(),
            source,
        });
        if base {
            state.set_transport(transport.clone()).await;
        }
        if i2p {
            state.set_i2p_transport(transport).await;
            state.set_i2p_status(json!({ "phase": "Starting…" })).await;
        }
        if let Some(listen) = listen {
            match &listen {
                PeerAddr::I2p { dest, port } => {
                    state.set_fileserver_port(*port).await;
                    state.set_i2p_address(dest).await;
                }
                PeerAddr::Ip(sa) => {
                    state.set_fileserver_port(sa.port()).await;
                    state.set_clearnet_listener(Some(*sa)).await;
                }
                _ => unreachable!(),
            }
            let hook = if i2p {
                serve.overlay_hook()
            } else {
                serve.clearnet_hook(None)
            };
            network.routes.lock().unwrap().insert(listen, hook);
        }
        Self { state, _data: data }
    }

    async fn register(&self, address: &str) -> XiteStorage {
        let storage = XiteStorage::new(self._data.path().join(address));
        self.state
            .add_xite(
                address,
                XiteEntry {
                    storage: storage.clone(),
                    content: None,
                },
            )
            .await;
        storage
    }
}

async fn discover_and_download(i2p: bool, base: bool, mixed_tracker: bool) {
    let network = Arc::new(Network::default());
    let (tracker_addr, seed_addr) = if i2p {
        (
            PeerAddr::parse(&format!("{}.b32.i2p:0", "a".repeat(52))).unwrap(),
            PeerAddr::parse("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:26552")
                .unwrap(),
        )
    } else {
        (
            PeerAddr::parse("8.8.4.4:26552").unwrap(),
            PeerAddr::parse("8.8.8.8:26552").unwrap(),
        )
    };
    let tracker_url = format!("{}://{tracker_addr}", tracker_addr.scheme());
    let tracker = Tracker::parse(&tracker_url).unwrap();
    assert_eq!(tracker.to_string(), tracker_url);
    let tracker_node = Node::new(&network, Some(tracker_addr.clone()), i2p, base).await;
    let seed = Node::new(&network, Some(seed_addr.clone()), i2p, base).await;
    let client = Node::new(&network, None, i2p, base).await;
    let privatekey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privatekey).unwrap();
    let source = seed.register(&address).await;
    let destination = client.register(&address).await;
    let bytes = b"This xite was discovered through a tracker and downloaded over EDX.";
    source.write("index.html", bytes).unwrap();
    let mut signed = json!({
        "address": address, "modified": 100.0,
        "files": { "index.html": {
            "size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes),
            "b3": ObjId::of(bytes).to_string()
        }}
    });
    epix_content::sign(&mut signed, &privatekey).unwrap();
    source
        .write("content.json", &serde_json::to_vec(&signed).unwrap())
        .unwrap();
    assert!(seed.state.load_content_from_disk(&address).await);
    let trackers = [tracker];

    if i2p {
        // Startup does not spend a dial or mark the still-booting tracker dead.
        assert!(client
            .state
            .announce_to_trackers(&address, &trackers)
            .await
            .is_empty());
        assert!(network.dials.lock().unwrap().is_empty());
        for node in [&tracker_node, &seed, &client] {
            node.state.set_i2p_status(json!({ "phase": "Ready" })).await;
        }
    }

    assert!(seed
        .state
        .announce_to_trackers(&address, &trackers)
        .await
        .is_empty());
    if mixed_tracker {
        // The tracker answers at most 20 peers across all requested networks.
        // Give it newer IP peers to ensure an undialable network cannot crowd
        // this I2P-only client's sole reachable seeder out of that response.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        for host in 1..=25 {
            tracker_node
                .state
                .tracker_announce(
                    &[epix_discovery::address_hash(&address)],
                    &PeerAddr::parse(&format!("192.0.2.{host}:26552")).unwrap(),
                )
                .await;
        }
    }
    let peers = client.state.announce_to_trackers(&address, &trackers).await;
    assert_eq!(
        peers,
        vec![seed_addr.clone()],
        "a second node must discover the seeder"
    );
    assert_eq!(
        tracker_node.state.tracker_stats().await,
        (1, if mixed_tracker { 26 } else { 1 }),
        "passive lookup adds no phantom peer"
    );

    let fetched = client
        .state
        .edx_fetch_signed(seed_addr.clone(), &address, "content.json")
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    destination.write("content.json", &fetched).unwrap();
    assert!(
        client.state.load_content_from_disk(&address).await,
        "the discovered manifest verifies"
    );
    assert!(client
        .state
        .edx_fetch_file(&address, "index.html", false)
        .await
        .unwrap()
        .unwrap());
    assert_eq!(destination.read("index.html").unwrap(), bytes);
    assert!(
        network.dials.lock().unwrap().contains(&seed_addr),
        "download actually dialed the discovered peer"
    );
}

#[tokio::test]
async fn i2p_tracker_discovers_and_downloads_a_xite() {
    discover_and_download(true, true, false).await;
}

#[tokio::test]
async fn i2p_tracker_works_without_a_base_transport() {
    discover_and_download(true, false, false).await;
}

#[tokio::test]
async fn clearnet_tracker_registers_a_listening_seed() {
    discover_and_download(false, true, false).await;
}

#[tokio::test]
async fn i2p_self_address_aliases_do_not_return_the_announcer_itself() {
    use epix_discovery::tracker_pc::AnnounceReq;

    let state = AppState::new("tracker");
    let host = "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa";
    let source = PeerAddr::parse("8.8.8.8:41000").unwrap();
    let mut req = AnnounceReq {
        hashes: vec![[42; 32]],
        port: 26552,
        need_types: vec!["i2p".into()],
        need_num: 20,
        add: vec!["i2p".into()],
        i2p: vec![host.into()],
        ..Default::default()
    };
    assert!(state.announce_serve(&req, &source).await.peers[0]
        .unpack()
        .is_empty());
    req.i2p = vec![format!("{host}.b32")];
    assert!(
        state.announce_serve(&req, &source).await.peers[0]
            .unpack()
            .is_empty(),
        "both accepted spellings are the same destination, never another peer"
    );
    assert_eq!(state.tracker_stats().await, (1, 1));
}

#[tokio::test]
async fn invalid_i2p_claims_do_not_occupy_tracker_slots() {
    use epix_discovery::tracker_pc::AnnounceReq;

    let state = AppState::new("tracker");
    let req = AnnounceReq {
        hashes: vec![[42; 32]],
        port: 26552,
        add: vec!["i2p".into()],
        // Alphanumeric is not sufficient: these cannot be encoded as the
        // 32-byte destination hash carried in a tracker reply.
        i2p: vec!["0".repeat(52), "a".repeat(51) + "b"],
        ..Default::default()
    };
    state
        .announce_serve(&req, &PeerAddr::parse("8.8.8.8:41000").unwrap())
        .await;
    assert_eq!(
        state.tracker_stats().await,
        (0, 0),
        "unserializable claims must be discarded before storage"
    );
}

#[tokio::test]
async fn passive_i2p_tracker_lookup_does_not_advertise_a_seeder() {
    use epix_discovery::tracker_pc::AnnounceReq;

    let state = AppState::new("tracker");
    let source =
        PeerAddr::parse("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:26552")
            .unwrap();
    let req = AnnounceReq {
        hashes: vec![[42; 32]],
        need_types: vec!["i2p".into()],
        need_num: 20,
        ..Default::default()
    };
    state.announce_serve(&req, &source).await;
    assert_eq!(
        state.tracker_stats().await,
        (0, 0),
        "a downloader did not ask to be added as a holder"
    );
}

#[tokio::test]
async fn clearnet_announcements_follow_listener_family_and_tor_policy() {
    let state = AppState::new("announcer");
    state.set_fileserver_port(26552).await;
    let advert = state.self_advert().await;
    assert!(
        !advert.advertise_ipv4 && !advert.advertise_ipv6,
        "an overlay virtual port alone is no TCP listener"
    );

    state
        .set_clearnet_listener(Some("0.0.0.0:26552".parse().unwrap()))
        .await;
    let advert = state.self_advert().await;
    assert!(advert.advertise_ipv4 && !advert.advertise_ipv6);
    state.set_tor_status(true, "Always").await;
    let advert = state.self_advert().await;
    assert!(
        !advert.advertise_ipv4 && !advert.advertise_ipv6,
        "a tracker's observed Tor exit is not our inbound IP"
    );

    state.set_tor_status(false, "Disabled").await;
    state
        .set_clearnet_listener(Some("[::]:26552".parse().unwrap()))
        .await;
    let advert = state.self_advert().await;
    assert!(!advert.advertise_ipv4 && advert.advertise_ipv6);
    state.set_clearnet_listener(None).await;
    let advert = state.self_advert().await;
    assert!(!advert.advertise_ipv4 && !advert.advertise_ipv6);
}

#[tokio::test]
async fn i2p_only_client_discovers_its_seeder_in_a_tracker_with_newer_ip_peers() {
    discover_and_download(true, false, true).await;
}

#[tokio::test]
async fn tracker_requests_preserve_bootstrap_and_combined_network_types() {
    use epix_discovery::{tracker_pc, AnnounceSender};

    #[derive(Default)]
    struct Capture(Mutex<Vec<String>>);
    #[async_trait::async_trait]
    impl AnnounceSender for Capture {
        async fn send(
            &self,
            _: &PeerAddr,
            payload: Vec<u8>,
        ) -> std::result::Result<Vec<u8>, String> {
            *self.0.lock().unwrap() = tracker_pc::decode_request(&payload).unwrap().need_types;
            Ok(tracker_pc::encode_reply(&tracker_pc::AnnounceResp::default()).unwrap())
        }
    }
    async fn requested(advert: epix_xite::SelfAdvert) -> Vec<String> {
        let capture = Capture::default();
        epix_xite::announce(
            &capture,
            "xite",
            &[Tracker::parse("8.8.8.8:26552").unwrap()],
            &advert,
        )
        .await
        .unwrap();
        capture.0.into_inner().unwrap()
    }

    assert_eq!(
        requested(epix_xite::SelfAdvert::default()).await,
        vec!["ipv4", "ipv6"]
    );
    let state = AppState::new("network-policy");
    assert!(state.dialable_networks().await.clearnet);
    assert_eq!(
        requested(state.self_advert().await).await,
        vec!["ipv4", "ipv6"]
    );

    state
        .set_i2p_transport(Arc::new(epix_transport::TcpTransport))
        .await;
    state.set_i2p_status(json!({"phase": "Ready"})).await;
    assert!(!state.dialable_networks().await.clearnet);
    assert_eq!(requested(state.self_advert().await).await, vec!["i2p"]);

    state
        .set_transport(Arc::new(epix_transport::TcpTransport))
        .await;
    state.set_tor_status(true, "OK").await;
    assert!(state.dialable_networks().await.clearnet);
    assert_eq!(
        requested(state.self_advert().await).await,
        vec!["ipv4", "ipv6", "onion", "i2p"]
    );
}

async fn empty_listeners_do_not_hide_a_partial_seed(i2p: bool) {
    fn peer(i2p: bool, id: u8) -> PeerAddr {
        if i2p {
            let mut packed = [id; 34];
            packed[32..].copy_from_slice(&26552u16.to_le_bytes());
            PeerAddr::unpack_i2p(&packed).unwrap()
        } else {
            PeerAddr::parse(&format!("198.18.0.{id}:26552")).unwrap()
        }
    }
    async fn ready(network: &Arc<Network>, listen: Option<PeerAddr>, i2p: bool) -> Node {
        let node = Node::new(network, listen, i2p, !i2p).await;
        if i2p {
            node.state.set_i2p_status(json!({"phase": "Ready"})).await;
        }
        node
    }

    let network = Arc::new(Network::default());
    let tracker_addr = peer(i2p, 1);
    let seed_addr = peer(i2p, 2);
    let tracker = ready(&network, Some(tracker_addr.clone()), i2p).await;
    let seed = ready(&network, Some(seed_addr.clone()), i2p).await;
    let reader = ready(&network, None, i2p).await;
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let source = seed.register(&address).await;
    let destination = reader.register(&address).await;
    let available = b"A verified partial peer can serve its root and available files.";
    let missing = b"This required file has not reached the partial seeder yet.";
    source.write("index.html", available).unwrap();
    let mut root = json!({"address": address, "modified": 100.0, "files": {
        "index.html": {"size": available.len(), "sha512": XiteStorage::hash_bytes(available), "b3": ObjId::of(available).to_string()},
        "later.txt": {"size": missing.len(), "sha512": XiteStorage::hash_bytes(missing), "b3": ObjId::of(missing).to_string()}
    }});
    epix_content::sign(&mut root, &key).unwrap();
    source
        .write("content.json", &serde_json::to_vec(&root).unwrap())
        .unwrap();
    assert!(seed.state.load_content_from_disk(&address).await);
    assert!(
        source.read("later.txt").is_err(),
        "the seed is intentionally partial"
    );
    let trackers = [Tracker::Epix(tracker_addr)];
    seed.state.announce_to_trackers(&address, &trackers).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Each listening downloader requests peers before it has any signed root.
    // If these lookups advertise possession, their newer rows fill the entire
    // tracker response and a fresh node cannot fetch even content.json.
    let mut downloaders = Vec::new();
    for id in 3..=23 {
        let downloader = ready(&network, Some(peer(i2p, id)), i2p).await;
        downloader.register(&address).await;
        assert!(downloader.state.content(&address).await.is_none());
        downloader
            .state
            .announce_to_trackers(&address, &trackers)
            .await;
        downloaders.push(downloader);
    }
    let peers = reader.state.announce_to_trackers(&address, &trackers).await;
    let mut roots = Vec::new();
    for peer in &peers {
        if let Some(bytes) = reader
            .state
            .edx_fetch_signed(peer.clone(), &address, "content.json")
            .await
            .unwrap()
            .unwrap()
        {
            roots.push(bytes);
        }
    }
    assert!(
        !roots.is_empty(),
        "the tracker returned {} peers, but none could serve the signed root",
        peers.len()
    );
    assert_eq!(tracker.state.tracker_stats().await, (1, 1), "empty listeners are discovery clients, while the verified partial seeder remains advertised");
    assert_eq!(peers, vec![seed_addr]);
    destination.write("content.json", &roots[0]).unwrap();
    assert!(reader.state.load_content_from_disk(&address).await);
    assert!(reader
        .state
        .edx_fetch_file(&address, "index.html", false)
        .await
        .unwrap()
        .unwrap());
    assert_eq!(destination.read("index.html").unwrap(), available);
}

#[tokio::test]
async fn empty_clearnet_listeners_cannot_crowd_out_a_verified_partial_seed() {
    empty_listeners_do_not_hide_a_partial_seed(false).await;
}

#[tokio::test]
async fn empty_i2p_listeners_cannot_crowd_out_a_verified_partial_seed() {
    empty_listeners_do_not_hide_a_partial_seed(true).await;
}

#[tokio::test]
async fn newly_created_and_resigned_owned_xites_remain_discoverable() {
    for i2p in [false, true] {
        let network = Arc::new(Network::default());
        let (tracker_addr, seed_addr) = if i2p {
            (
                PeerAddr::parse(&format!("{}.b32.i2p:0", "a".repeat(52))).unwrap(),
                PeerAddr::parse(
                    "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:26552",
                )
                .unwrap(),
            )
        } else {
            (
                PeerAddr::parse("8.8.4.4:26552").unwrap(),
                PeerAddr::parse("8.8.8.8:26552").unwrap(),
            )
        };
        let tracker = Node::new(&network, Some(tracker_addr.clone()), i2p, !i2p).await;
        let seed = Node::new(&network, Some(seed_addr.clone()), i2p, !i2p).await;
        let reader = Node::new(&network, None, i2p, !i2p).await;
        if i2p {
            for node in [&tracker, &seed, &reader] {
                node.state.set_i2p_status(json!({"phase": "Ready"})).await;
            }
        }
        let (address, privatekey) = seed.state.create_xite().await.unwrap();
        assert!(seed.state.xite_owned(&address).await);
        reader.register(&address).await;
        let trackers = [Tracker::Epix(tracker_addr)];
        for resign in [false, true] {
            if resign {
                seed.state
                    .write_file(&address, "index.html", b"An updated owned xite.")
                    .await
                    .unwrap();
                seed.state.sign_xite(&address, &privatekey).await.unwrap();
            }
            seed.state.announce_to_trackers(&address, &trackers).await;
            let peers = reader.state.announce_to_trackers(&address, &trackers).await;
            assert_eq!(peers, vec![seed_addr.clone()]);
            let bytes = reader
                .state
                .edx_fetch_signed(seed_addr.clone(), &address, "content.json")
                .await
                .unwrap()
                .unwrap()
                .expect("owned root must be served");
            let root: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(Some(root), seed.state.content(&address).await);
        }
    }
}
