use super::*;
use epix_ui::state::{
    EdxBatch, EdxBatchProgress, EdxPushError, EdxPushProgress, EdxSignedProgress, EdxWant,
    UpdatePayload,
};
use std::collections::HashMap;

struct DiscoveryFetcher {
    signed: Vec<u8>,
    seed: PeerAddr,
    slow: PeerAddr,
    release: Arc<tokio::sync::Notify>,
    started: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl epix_ui::state::EdxFetcher for DiscoveryFetcher {
    async fn fetch_file(&self, _: &str, _: &str) -> Result<bool, String> {
        Ok(false)
    }
    async fn fetch_signed(
        &self,
        peer: PeerAddr,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        Ok((peer == self.seed).then(|| self.signed.clone()))
    }
    async fn fetch_signed_many(
        &self,
        _: &str,
        _: Vec<String>,
        _: Vec<PeerAddr>,
        _: Option<EdxSignedProgress>,
    ) -> HashMap<String, Vec<u8>> {
        HashMap::new()
    }
    async fn fetch_range(
        &self,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
    async fn push_update(
        &self,
        _: PeerAddr,
        _: &str,
        _: &str,
        _: Arc<Vec<u8>>,
        _: f64,
        _: Arc<UpdatePayload>,
        _: Arc<Vec<String>>,
        _: Arc<EdxPushProgress>,
    ) -> Result<bool, EdxPushError> {
        unreachable!()
    }
    async fn fetch_files(
        &self,
        _: &str,
        want: Vec<EdxWant>,
        _: Vec<PeerAddr>,
        _: Option<serde_json::Value>,
        _: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        EdxBatch {
            done: vec![],
            missed: want.into_iter().map(|w| w.inner_path).collect(),
            bytes: 0,
        }
    }
    async fn list_signed(
        &self,
        _: PeerAddr,
        _: &str,
        _: u64,
    ) -> Result<Option<Vec<(String, u64, u64)>>, String> {
        Ok(None)
    }
    async fn pex(
        &self,
        _: PeerAddr,
        _: &str,
        _: u32,
        _: Vec<PeerAddr>,
    ) -> Result<Vec<PeerAddr>, String> {
        Ok(vec![])
    }
    async fn get_trackers(&self, _: PeerAddr) -> Result<Vec<String>, String> {
        Ok(vec![])
    }
    async fn kad(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        Err("unused".into())
    }
    async fn announce(&self, tracker: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        if tracker == self.slow {
            self.started.notify_one();
            self.release.notified().await;
        }
        // Postcard AnnounceResp: one hash, one six-byte IPv4 peer, then
        // empty IPv6/onion/I2P buckets, challenge and error strings.
        let mut reply = vec![1, 1, 6];
        reply.extend(self.seed.pack().unwrap());
        reply.extend([0, 0, 0, 0, 0]);
        Ok(reply)
    }
    async fn updates_since(
        &self,
        _: PeerAddr,
        _: u64,
    ) -> Result<(Vec<(String, i64)>, u64), String> {
        Ok((vec![], 0))
    }
}

async fn fixture() -> (
    tempfile::TempDir,
    Arc<AppState>,
    String,
    Arc<DiscoveryFetcher>,
) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("test", dir.path());
    let key = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
    let mut content = serde_json::json!({"files":{}, "modified":1, "inner_path":"content.json"});
    epix_content::sign(&mut content, key).unwrap();
    let address = content["signs"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    content["address"] = serde_json::json!(address);
    epix_content::sign(&mut content, key).unwrap();
    let path = dir.path().join("data").join(&address);
    std::fs::create_dir_all(&path).unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: XiteStorage::new(path),
                content: None,
            },
        )
        .await;
    let fetcher = Arc::new(DiscoveryFetcher {
        signed: serde_json::to_vec(&content).unwrap(),
        seed: PeerAddr::Ip("203.0.113.41:15441".parse().unwrap()),
        slow: PeerAddr::Ip("203.0.113.43:15441".parse().unwrap()),
        release: Arc::new(tokio::sync::Notify::new()),
        started: Arc::new(tokio::sync::Notify::new()),
    });
    state.set_edx_fetcher(fetcher.clone()).await;
    (dir, state, address, fetcher)
}

#[tokio::test]
async fn clone_retry_fast_tracker_root_wins_before_slow_tracker_finishes() {
    let (dir, state, address, fetcher) = fixture().await;
    let trackers = [
        epix_xite::Tracker::Epix(PeerAddr::Ip("203.0.113.42:15441".parse().unwrap())),
        epix_xite::Tracker::Epix(fetcher.slow.clone()),
    ];
    let mut discovery = start_clone_discovery(&address, &trackers, Some(&state)).await;
    let mut xite = Xite::new(
        Address::parse(address.clone()).unwrap(),
        XiteStorage::new(dir.path().join("data").join(&address)),
    );
    let (signed, peers) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        race_clone_root(
            &mut xite,
            &mut discovery,
            &address,
            Some(&state),
            std::time::Instant::now(),
        ),
    )
    .await
    .expect("the slow tracker must not delay the fast seeder")
    .unwrap();
    assert_eq!(signed, fetcher.signed);
    assert_eq!(peers, 1);
    fetcher.release.notify_one();
}

#[tokio::test]
async fn clone_retry_late_peer_automatically_finishes_waiting_xite() {
    let (dir, state, address, fetcher) = fixture().await;
    let resolver = Arc::new_cyclic(|me| OnDemand {
        state: state.clone(),
        data_root: dir.path().to_path_buf(),
        trackers: vec![],
        network_disabled: false,
        me: me.clone(),
        in_flight: tokio::sync::Mutex::new(HashMap::new()),
        in_flight_token: std::sync::atomic::AtomicU64::new(0),
        tor_expected: std::sync::atomic::AtomicBool::new(false),
        tor_always: std::sync::atomic::AtomicBool::new(false),
        resolving: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        verifier_wake: tokio::sync::Notify::new(),
    });
    state.set_on_demand(resolver).await;
    state.begin_clone(&address);
    state.push_clone_event(
        &address,
        serde_json::json!(["file_failed", "index.html"]),
        serde_json::json!({"reason":"no_peers", "peers":0}),
    );
    state.end_clone(&address);
    state.spawn_optional_retry_loop();
    state.add_peers(&address, [fetcher.seed.clone()]).await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !state.xite_core_complete(&address).await {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a newly discovered peer must resume the clone without a page reload");
    assert!(state.content(&address).await.is_some());
}

#[tokio::test]
async fn clone_retry_finished_producer_does_not_wait_for_sender_drop_race() {
    let dir = tempfile::tempdir().unwrap();
    let mut xite = Xite::new(
        Address::parse(DASHBOARD_XITE_ADDRESS.to_string()).unwrap(),
        XiteStorage::new(dir.path()),
    );
    let mut discovery = start_clone_discovery(DASHBOARD_XITE_ADDRESS, &[], None).await;
    let source = DiscoverySource::new(discovery.pex_tx.clone(), discovery.pex.pending.clone());
    let tx = source.tx.clone();
    tokio::spawn(async move {
        drop(source);
        // The receiver can consume the completion message before this task
        // is rescheduled to drop the last real producer's sender.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        drop(tx);
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        race_clone_root(
            &mut xite,
            &mut discovery,
            DASHBOARD_XITE_ADDRESS,
            None,
            std::time::Instant::now(),
        ),
    )
    .await;
    assert!(
        result.is_ok(),
        "producer completion must not depend on when its sender is dropped"
    );
}

#[tokio::test]
async fn clone_retry_delete_cancels_the_previous_detached_download() {
    let (dir, state, address, _) = fixture().await;
    let resolver = Arc::new_cyclic(|me| OnDemand {
        state: state.clone(),
        data_root: dir.path().to_path_buf(),
        trackers: vec![],
        network_disabled: false,
        me: me.clone(),
        in_flight: tokio::sync::Mutex::new(HashMap::new()),
        in_flight_token: std::sync::atomic::AtomicU64::new(0),
        tor_expected: std::sync::atomic::AtomicBool::new(false),
        tor_always: std::sync::atomic::AtomicBool::new(false),
        resolving: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        verifier_wake: tokio::sync::Notify::new(),
    });
    state.set_on_demand(resolver.clone()).await;
    let token = resolver.claim_clone_slot(&address, true).await.unwrap();
    let task = tokio::spawn(std::future::pending::<()>());
    resolver
        .in_flight
        .lock()
        .await
        .get_mut(&address)
        .unwrap()
        .abort = Some(task.abort_handle());
    assert!(state.remove_xite(&address).await);
    let obsolete = resolver
        .in_flight
        .lock()
        .await
        .get(&address)
        .is_some_and(|slot| slot.token == token);
    task.abort();
    assert!(
        !obsolete,
        "a deleted xite's detached download must not retain its slot or publish stale progress"
    );
}

#[tokio::test]
async fn clone_retry_late_discovery_cannot_recreate_deleted_progress() {
    let (dir, state, address, fetcher) = fixture().await;
    let discovery = start_clone_discovery(&address, &[], Some(&state)).await;
    assert!(state.remove_xite(&address).await);
    discovery
        .pex
        .record_peer(fetcher.seed.clone(), 1, None)
        .await;
    assert!(
        state.clone_status(&address).is_null(),
        "late discovery must not resurrect deleted progress"
    );
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: XiteStorage::new(dir.path().join("data").join(&address)),
                content: None,
            },
        )
        .await;
    discovery
        .pex
        .record_peer(fetcher.seed.clone(), 1, None)
        .await;
    assert!(
        state.clone_status(&address).is_null(),
        "an old discovery must not mutate the re-added xite"
    );
    assert_eq!(state.peer_counts(&address).await.total, 0);
}

#[tokio::test]
async fn clone_retry_late_tracker_answer_cannot_mutate_a_readded_xite() {
    let (dir, state, address, fetcher) = fixture().await;
    let announcing = state.clone();
    let old_address = address.clone();
    let tracker = epix_xite::Tracker::Epix(fetcher.slow.clone());
    let task = tokio::spawn(async move {
        announcing
            .announce_to_trackers(&old_address, &[tracker])
            .await
    });
    fetcher.started.notified().await;
    assert!(state.remove_xite(&address).await);
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: XiteStorage::new(dir.path().join("data").join(&address)),
                content: None,
            },
        )
        .await;
    fetcher.release.notify_one();
    task.await.unwrap();
    assert_eq!(
        state.peer_counts(&address).await.total,
        0,
        "old tracker results belong to the deleted registration"
    );
}
