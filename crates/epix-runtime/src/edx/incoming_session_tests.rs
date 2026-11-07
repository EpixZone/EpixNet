use super::{routing_allows, IncomingSession};
use crate::edx::RuntimeEdxFetcher;
use epix_core::PeerAddr;
use epix_edx::{
    choke::Reach,
    conn::Conn,
    server::{PeerIdentity, UpdateSource},
};
use epix_protocol::registry::{ConnHandle, Direction};
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct NoDial(Arc<AtomicUsize>);

#[test]
fn tor_always_rejects_direct_sessions_but_preserves_overlay_provenance() {
    for network in [
        epix_core::IpType::Ipv4,
        epix_core::IpType::Ipv6,
        epix_core::IpType::Onion,
        epix_core::IpType::I2p,
        epix_core::IpType::Rns,
    ] {
        let peer = PeerAddr::Session {
            id: [3; 32],
            network,
        };
        assert!(routing_allows(&peer, false));
        assert_eq!(routing_allows(&peer, true), peer.is_overlay());
        assert!(postcard::to_stdvec(&peer).is_err());
    }
    assert!(postcard::from_bytes::<PeerAddr>(&[4, 0, 0, 0, 0]).is_err());
}

#[async_trait::async_trait]
impl epix_transport::Transport for NoDial {
    fn scheme(&self) -> &'static str {
        "no-dial"
    }
    async fn dial(&self, _: &PeerAddr) -> epix_core::Result<epix_transport::PeerStream> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(epix_core::Error::Protocol("unexpected dial".into()))
    }
}

struct Fixture {
    state: Arc<AppState>,
    fetcher: Arc<RuntimeEdxFetcher>,
    directory: tempfile::TempDir,
    address: String,
    identity: PeerIdentity,
    dials: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("session-test", directory.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let identity = PeerIdentity {
            node_pk: epix_crypt::private_to_compressed_pubkey(&key).unwrap(),
            address: address.clone(),
            caps: 0,
            version: "test".into(),
        };
        let fetcher = Arc::new(RuntimeEdxFetcher::new(state.clone(), key, None));
        let dials = Arc::new(AtomicUsize::new(0));
        state.set_transport(Arc::new(NoDial(dials.clone()))).await;
        Self {
            state,
            fetcher,
            directory,
            address,
            identity,
            dials,
        }
    }

    async fn register(&self) {
        self.state
            .add_xite(
                &self.address,
                XiteEntry {
                    storage: XiteStorage::new(
                        self.directory.path().join("data").join(&self.address),
                    ),
                    content: None,
                },
            )
            .await;
    }

    fn channel(&self) -> (Arc<IncomingSession>, UpdateSource, Conn) {
        let (a, b) = tokio::io::duplex(4096);
        let (conn, _requests) = Conn::start(Box::pin(a), false);
        let (other, _requests) = Conn::start(Box::pin(b), true);
        let remote = PeerAddr::parse("10.77.0.1:41329").unwrap();
        let session = IncomingSession::new(
            self.state.clone(),
            &self.fetcher,
            &remote,
            conn.clone(),
            Arc::new(ConnHandle::new(Direction::In, remote.clone())),
        );
        let source = UpdateSource {
            conn,
            identity: self.identity.clone(),
            reach: Reach::Clearnet,
        };
        (session, source, other)
    }
}

#[tokio::test]
async fn only_requested_serving_xites_gain_a_reverse_peer() {
    let f = Fixture::new().await;
    let (session, source, other) = f.channel();
    session.note_interest(&f.address, source.clone()).await;
    assert!(!f.state.has_xite(&f.address).await);
    assert!(f.fetcher.link_pool.live(&session.peer, 0).is_none());
    f.register().await;
    f.state.set_serving(&f.address, false).await;
    session.note_interest(&f.address, source.clone()).await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 0);
    f.state.set_serving(&f.address, true).await;
    session.note_interest(&f.address, source).await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 1);
    assert!(f.fetcher.link(&session.peer).await.is_ok());
    assert_eq!(f.dials.load(Ordering::SeqCst), 0);
    session.close().await;
    other.shutdown();
}

#[tokio::test]
async fn forged_identity_or_different_channel_cannot_replace_a_binding() {
    let f = Fixture::new().await;
    f.register().await;
    let (session, source, other) = f.channel();
    let (unrelated, mut bad, other_bad) = f.channel();
    session.note_interest(&f.address, bad.clone()).await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 0);
    session.note_interest(&f.address, source.clone()).await;
    bad = source.clone();
    bad.identity.node_pk = vec![9; 33];
    session.note_interest(&f.address, bad).await;
    let (_, identity, _, _) = f.fetcher.link(&session.peer).await.unwrap();
    assert_eq!(identity.node_pk, f.identity.node_pk);
    let mut wrong_reach = source;
    wrong_reach.reach = Reach::Overlay;
    session.note_interest(&f.address, wrong_reach).await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 1);
    session.close().await;
    unrelated.close().await;
    other.shutdown();
    other_bad.shutdown();
}

#[tokio::test]
async fn disconnect_never_dials_or_resurrects_a_handle_and_preserves_replacement() {
    let f = Fixture::new().await;
    f.register().await;
    let (first, source, other) = f.channel();
    first.note_interest(&f.address, source).await;
    let (replacement, source, other_new) = f.channel();
    replacement.note_interest(&f.address, source).await;
    first.close().await;
    assert!(f.fetcher.link_lane(&first.peer, 2).await.is_err());
    let forged = PeerAddr::Session {
        id: [99; 32],
        network: epix_core::IpType::Ipv4,
    };
    assert!(f.fetcher.link(&forged).await.is_err());
    f.state.add_peers(&f.address, [first.peer.clone()]).await;
    f.state
        .note_edx_dials(&f.address, vec![(first.peer.clone(), true)])
        .await;
    f.state
        .note_edx_served(&f.address, vec![first.peer.clone()])
        .await;
    f.state
        .set_peer_hashfield(&f.address, &first.peer, &[])
        .await;
    assert_eq!(
        f.state.fetch_session_peers(&f.address, 10).await,
        vec![replacement.peer.clone()]
    );
    assert_eq!(f.dials.load(Ordering::SeqCst), 0);
    replacement.close().await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 0);
    other.shutdown();
    other_new.shutdown();
}

#[tokio::test]
async fn removing_and_readding_a_xite_invalidates_the_old_session_membership() {
    let f = Fixture::new().await;
    f.register().await;
    let (session, source, other) = f.channel();
    session.note_interest(&f.address, source.clone()).await;
    let old = f
        .state
        .xite_membership_generation(&f.address)
        .await
        .unwrap();
    assert!(f.state.remove_xite(&f.address).await);
    f.register().await;
    assert_ne!(
        f.state.xite_membership_generation(&f.address).await,
        Some(old)
    );
    assert!(
        !f.state
            .record_session_peer(&f.address, old, session.peer.clone())
            .await
    );
    session.note_interest(&f.address, source).await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 0);
    session.close().await;
    other.shutdown();
}

#[tokio::test]
async fn reverse_peer_does_not_survive_persistence_or_restart() {
    let f = Fixture::new().await;
    f.register().await;
    let (session, source, other) = f.channel();
    session.note_interest(&f.address, source).await;
    f.state.persist_peers().await;
    let saved = std::fs::read_to_string(f.directory.path().join("private/peers.json")).unwrap();
    assert!(!saved.contains("session:"));
    assert!(!saved.contains("41329"));
    let restarted = AppState::with_data_dir("restart", f.directory.path());
    restarted.register_for_download(&f.address).await.unwrap();
    assert_eq!(restarted.peer_counts(&f.address).await.total, 0);
    assert!(f
        .state
        .pex_peers(&f.address, 20, &HashSet::new())
        .await
        .is_empty());
    session.close().await;
    other.shutdown();
}

#[tokio::test]
async fn repeated_interest_preserves_activity_and_only_restores_a_live_channel() {
    let f = Fixture::new().await;
    f.register().await;
    let (session, source, other) = f.channel();
    session.note_interest(&f.address, source.clone()).await;
    let first = f.fetcher.link(&session.peer).await.unwrap();
    session.note_interest(&f.address, source.clone()).await;
    let repeated = f.fetcher.link(&session.peer).await.unwrap();
    assert!(Arc::ptr_eq(&first.3, &repeated.3));
    f.fetcher.link_pool.evict(&session.peer);
    session.note_interest(&f.address, source.clone()).await;
    let restored = f.fetcher.link(&session.peer).await.unwrap();
    assert!(Arc::ptr_eq(&first.3, &restored.3));
    assert!(restored.0.same_connection(&first.0));
    assert_eq!(f.dials.load(Ordering::SeqCst), 0);
    session.close().await;
    session.note_interest(&f.address, source).await;
    assert!(f.fetcher.link(&session.peer).await.is_err());
    other.shutdown();
}

#[tokio::test]
async fn a_closed_socket_cannot_register_an_interest() {
    let f = Fixture::new().await;
    f.register().await;
    let (session, source, other) = f.channel();
    other.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !source.conn.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    session.note_interest(&f.address, source).await;
    assert_eq!(f.state.peer_counts(&f.address).await.total, 0);
    assert!(f.fetcher.link(&session.peer).await.is_err());
    assert_eq!(f.dials.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dropping_the_connection_owner_removes_its_transient_memberships() {
    let f = Fixture::new().await;
    f.register().await;
    let (session, source, other) = f.channel();
    session.note_interest(&f.address, source).await;
    let peer = session.peer.clone();
    drop(session);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while f.state.peer_counts(&f.address).await.total != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(f.fetcher.link(&peer).await.is_err());
    assert_eq!(f.dials.load(Ordering::SeqCst), 0);
    other.shutdown();
}
