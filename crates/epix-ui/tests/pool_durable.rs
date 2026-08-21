use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use epix_content::pool;
use epix_content::record_signed_data;
use epix_core::peer::PeerAddr;
use epix_ui::pool::{
    pool_record_id, PoolAdmission, PoolAdmissionBatch, PoolAdmissionDecision, PoolAdmissionRecord,
    PoolAdmissionRefresh, PoolAppendConfirmation, PoolRecordId,
};
use epix_ui::state::{
    AppState, EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxSignedProgress, EdxWant,
    PushJob, XiteEntry,
};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn descriptor(max_shard_bytes: usize) -> Value {
    json!({
        "address": XITE,
        "pool": { "channels": {
            "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 1,
            "pow_bits": 0, "pad_buckets": [64], "max_record_bytes": 4096,
            "max_shard_bytes": max_shard_bytes
        }}
    })
}

fn rln_descriptor() -> Value {
    let mut descriptor = descriptor(1_000_000);
    descriptor["pool"]["channels"]["rln_required"] = json!(true);
    descriptor
}

async fn node(home: &Path, root: &Path, max_shard_bytes: usize) -> Arc<AppState> {
    std::fs::create_dir_all(root).unwrap();
    let state = AppState::with_data_dir("pool-durable-test", home);
    state
        .add_xite(
            XITE,
            XiteEntry {
                storage: XiteStorage::new(root),
                content: Some(descriptor(max_shard_bytes)),
            },
        )
        .await;
    state
}

fn record(private_key: &str, marker: u8, keccak: bool) -> Value {
    let epoch = pool::epoch_now(now_ms());
    let tag = [marker; 32];
    let ct = [marker.wrapping_add(1); 64];
    let author = epix_crypt::privatekey_to_address(private_key).unwrap();
    let mut record = json!({
        "v": 1,
        "epoch": epoch,
        "tag": base64::engine::general_purpose::STANDARD.encode(tag),
        "ct": base64::engine::general_purpose::STANDARD.encode(ct),
        "pow": 0,
        "author": author,
    });
    let payload = record_signed_data(&record);
    let sign = if keccak {
        epix_crypt::sign_keccak(&payload, private_key).unwrap()
    } else {
        epix_crypt::sign(&payload, private_key).unwrap()
    };
    record["sign"] = json!(sign);
    record
}

fn rln_record(private_key: &str, marker: u8) -> Value {
    let mut value = record(private_key, marker, false);
    value.as_object_mut().unwrap().remove("sign");
    value["rln"] = json!(base64::engine::general_purpose::STANDARD.encode([marker; 8]));
    value["sign"] = json!(epix_crypt::sign(&record_signed_data(&value), private_key).unwrap());
    value
}

struct EvictAdmission(PoolRecordId);

impl PoolAdmission for EvictAdmission {
    fn refresh_address(
        &self,
        _address: &str,
        _content: Option<&Value>,
        _retained: &mut dyn FnMut() -> Result<Vec<PoolAdmissionRecord>, String>,
    ) -> PoolAdmissionRefresh {
        PoolAdmissionRefresh::default()
    }

    fn admit_records(&self, _address: &str, records: &[PoolAdmissionRecord]) -> PoolAdmissionBatch {
        PoolAdmissionBatch {
            decisions: records
                .iter()
                .map(|_| PoolAdmissionDecision {
                    admit: false,
                    deliver: false,
                    evict: vec![self.0],
                    ..PoolAdmissionDecision::default()
                })
                .collect(),
            permit: None,
        }
    }

    fn allow_rescan_records(&self, _address: &str, records: &[PoolAdmissionRecord]) -> Vec<bool> {
        vec![true; records.len()]
    }
}

struct CancelOnceAdmission {
    seen: Mutex<std::collections::BTreeSet<PoolRecordId>>,
    entered: AtomicBool,
    pause_once: AtomicBool,
}

struct PausingRefreshAdmission {
    entered: AtomicBool,
    release: AtomicBool,
}

struct PausingPush {
    entered: AtomicBool,
    release: AtomicBool,
}

#[async_trait::async_trait]
impl EdxFetcher for PausingPush {
    async fn fetch_file(&self, _: &str, _: &str) -> Result<bool, String> {
        unreachable!()
    }

    async fn fetch_signed(&self, _: PeerAddr, _: &str, _: &str) -> Result<Option<Vec<u8>>, String> {
        unreachable!()
    }

    async fn fetch_signed_many(
        &self,
        _: &str,
        _: Vec<String>,
        _: Vec<PeerAddr>,
        _: Option<EdxSignedProgress>,
    ) -> std::collections::HashMap<String, Vec<u8>> {
        unreachable!()
    }

    async fn fetch_range(
        &self,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        unreachable!()
    }

    async fn push_update(
        &self,
        _: PeerAddr,
        _: PushJob<'_>,
        _: Arc<AtomicBool>,
    ) -> Result<(), EdxPushError> {
        self.entered.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        Ok(())
    }

    async fn fetch_files(
        &self,
        _: &str,
        _: Vec<EdxWant>,
        _: Vec<PeerAddr>,
        _: Option<Value>,
        _: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        unreachable!()
    }

    async fn list_signed(
        &self,
        _: PeerAddr,
        _: &str,
        _: u64,
    ) -> Result<Option<Vec<(String, u64, u64)>>, String> {
        unreachable!()
    }

    async fn pex(
        &self,
        _: PeerAddr,
        _: &str,
        _: u32,
        _: Vec<PeerAddr>,
    ) -> Result<Vec<PeerAddr>, String> {
        unreachable!()
    }

    async fn get_trackers(&self, _: PeerAddr) -> Result<Vec<String>, String> {
        unreachable!()
    }

    async fn kad(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        unreachable!()
    }

    async fn announce(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        unreachable!()
    }

    async fn updates_since(
        &self,
        _: PeerAddr,
        _: u64,
    ) -> Result<(Vec<(String, i64)>, u64), String> {
        unreachable!()
    }
}

impl PausingRefreshAdmission {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            release: AtomicBool::new(false),
        }
    }
}

impl PoolAdmission for PausingRefreshAdmission {
    fn refresh_address(
        &self,
        _address: &str,
        _content: Option<&Value>,
        retained: &mut dyn FnMut() -> Result<Vec<PoolAdmissionRecord>, String>,
    ) -> PoolAdmissionRefresh {
        self.entered.store(true, Ordering::SeqCst);
        while !self.release.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        match retained() {
            Ok(_) => PoolAdmissionRefresh::default(),
            Err(error) => PoolAdmissionRefresh {
                error: Some(error),
                ..PoolAdmissionRefresh::default()
            },
        }
    }

    fn admit_records(&self, _address: &str, records: &[PoolAdmissionRecord]) -> PoolAdmissionBatch {
        PoolAdmissionBatch {
            decisions: records
                .iter()
                .map(|_| PoolAdmissionDecision {
                    admit: true,
                    deliver: true,
                    ..PoolAdmissionDecision::default()
                })
                .collect(),
            permit: None,
        }
    }

    fn allow_rescan_records(&self, _address: &str, records: &[PoolAdmissionRecord]) -> Vec<bool> {
        vec![true; records.len()]
    }
}

impl CancelOnceAdmission {
    fn new() -> Self {
        Self {
            seen: Mutex::new(std::collections::BTreeSet::new()),
            entered: AtomicBool::new(false),
            pause_once: AtomicBool::new(true),
        }
    }
}

impl PoolAdmission for CancelOnceAdmission {
    fn refresh_address(
        &self,
        _address: &str,
        _content: Option<&Value>,
        retained: &mut dyn FnMut() -> Result<Vec<PoolAdmissionRecord>, String>,
    ) -> PoolAdmissionRefresh {
        let mut seen = self.seen.lock().unwrap();
        seen.clear();
        let retained = match retained() {
            Ok(retained) => retained,
            Err(error) => {
                return PoolAdmissionRefresh {
                    error: Some(error),
                    ..PoolAdmissionRefresh::default()
                };
            }
        };
        seen.extend(retained.into_iter().map(|record| record.id));
        PoolAdmissionRefresh::default()
    }

    fn admit_records(&self, _address: &str, records: &[PoolAdmissionRecord]) -> PoolAdmissionBatch {
        let decisions = {
            let mut seen = self.seen.lock().unwrap();
            records
                .iter()
                .map(|record| {
                    let fresh = seen.insert(record.id);
                    PoolAdmissionDecision {
                        admit: fresh,
                        deliver: fresh,
                        ..PoolAdmissionDecision::default()
                    }
                })
                .collect()
        };
        self.entered.store(true, Ordering::SeqCst);
        if self.pause_once.swap(false, Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        PoolAdmissionBatch {
            decisions,
            permit: None,
        }
    }

    fn allow_rescan_records(&self, _address: &str, records: &[PoolAdmissionRecord]) -> Vec<bool> {
        vec![true; records.len()]
    }
}

fn work_id(record: &Value) -> [u8; 32] {
    let first = Sha256::digest(record_signed_data(record).as_bytes());
    Sha256::digest(first).into()
}

#[tokio::test]
async fn exact_outbound_rejected_by_capacity_leaves_live_shard_unchanged() {
    let key = epix_crypt::new_seed();
    let mut candidates: Vec<Value> = (1..=12).map(|marker| record(&key, marker, false)).collect();
    candidates.sort_by_key(work_id);
    let existing = candidates.first().unwrap().clone();
    let outbound = candidates.last().unwrap().clone();
    let one_len = serde_json::to_vec(&pool::make_pool_container(vec![existing.clone()]))
        .unwrap()
        .len();
    let two_len = serde_json::to_vec(&pool::make_pool_container(vec![
        existing.clone(),
        outbound.clone(),
    ]))
    .unwrap()
    .len();
    let cap = one_len + (two_len - one_len) / 2;

    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, cap).await;
    let shard = state.append_pool_record(XITE, existing).await.unwrap();
    let before = std::fs::read(root.join(&shard)).unwrap();

    let error = state
        .append_pool_record_confirmed(XITE, &shard, outbound.clone())
        .await
        .unwrap_err();
    assert!(error.contains("capacity dropped the exact outbound record"));
    assert_eq!(
        std::fs::read(root.join(&shard)).unwrap(),
        before,
        "capacity rejection must not mutate the prior durable shard"
    );

    let peer_error = state
        .apply_inbound_pool_update(
            XITE,
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![outbound])).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(peer_error.contains("dropped by shard capacity"));
    assert_eq!(
        std::fs::read(root.join(&shard)).unwrap(),
        before,
        "a saturated peer must reject the push so the sender retains its outbox row"
    );
}

#[tokio::test]
async fn oversized_singleton_is_rejected_locally_and_inbound() {
    let key = epix_crypt::new_seed();
    let offered = record(&key, 90, false);
    let singleton = serde_json::to_vec(&pool::make_pool_container(vec![offered.clone()]))
        .unwrap()
        .len();
    let cap = singleton.saturating_sub(1);
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, cap).await;
    let rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(offered["tag"].as_str().unwrap())
        .unwrap();
    let shard = pool::shard_path(&rule, offered["epoch"].as_i64().unwrap(), &tag);

    let local = state
        .append_pool_record_confirmed(XITE, &shard, offered.clone())
        .await
        .unwrap_err();
    assert!(local.contains("capacity dropped the exact outbound record"));

    let inbound = state
        .apply_inbound_pool_update(
            XITE,
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![offered])).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(inbound.contains("dropped by shard capacity"));
    assert!(!root.join(shard).exists());
}

#[tokio::test]
async fn descriptor_and_gate_refresh_block_old_rule_writers() {
    let key = epix_crypt::new_seed();
    let stale_pow_only = record(&key, 91, false);
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, 1_000_000).await;
    assert!(!state.pool_rules_for(XITE).await[0].rln_required);
    let admission = Arc::new(PausingRefreshAdmission::new());
    state.set_pool_admission(admission.clone()).await;
    state
        .add_xite(
            XITE,
            XiteEntry {
                storage: XiteStorage::new(&root),
                content: Some(rln_descriptor()),
            },
        )
        .await;

    let refresh_state = state.clone();
    let refresh = tokio::spawn(async move { refresh_state.refresh_pool_rules(XITE).await });
    while !admission.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    assert!(
        !state.pool_rules_for(XITE).await[0].rln_required,
        "candidate rules stay private until the candidate gate is ready"
    );

    let append_state = state.clone();
    let mut append =
        tokio::spawn(async move { append_state.append_pool_record(XITE, stale_pow_only).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(40), &mut append)
            .await
            .is_err(),
        "an old-rule writer waits behind the descriptor transition"
    );
    admission.release.store(true, Ordering::SeqCst);
    refresh.await.unwrap();
    let error = append.await.unwrap().unwrap_err();
    assert!(error.contains("RLN record was rejected"));
    assert!(state.pool_rules_for(XITE).await[0].rln_required);
}

#[tokio::test]
async fn malformed_existing_shard_is_never_replaced_by_local_or_inbound_merge() {
    let key = epix_crypt::new_seed();
    let offered = record(&key, 41, false);
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, 1_000_000).await;
    let rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(offered["tag"].as_str().unwrap())
        .unwrap();
    let shard = pool::shard_path(&rule, offered["epoch"].as_i64().unwrap(), &tag);
    let storage = XiteStorage::new(&root);
    let corrupt = b"{not-a-valid-pool-shard";
    storage.write_atomic_durable(&shard, corrupt).unwrap();

    let local_error = state
        .append_pool_record_confirmed(XITE, &shard, offered.clone())
        .await
        .unwrap_err();
    assert!(local_error.contains("invalid pool shard"));
    assert_eq!(storage.read(&shard).unwrap(), corrupt);

    let inbound_error = state
        .apply_inbound_pool_update(
            XITE,
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![offered])).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(inbound_error.contains("invalid pool shard"));
    assert_eq!(storage.read(&shard).unwrap(), corrupt);
}

#[tokio::test]
async fn inbound_canonical_resigning_is_persisted_without_redelivery() {
    let key = epix_crypt::new_seed();
    let sha = record(&key, 33, false);
    let keccak = record(&key, 33, true);
    assert_eq!(record_signed_data(&sha), record_signed_data(&keccak));
    let (local, canonical) = if sha["sign"].as_str() > keccak["sign"].as_str() {
        (sha, keccak)
    } else {
        (keccak, sha)
    };

    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, 1_000_000).await;
    let rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(local["tag"].as_str().unwrap())
        .unwrap();
    let shard = pool::shard_path(&rule, local["epoch"].as_i64().unwrap(), &tag);
    let storage = XiteStorage::new(&root);
    storage
        .write_atomic_durable(
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![local])).unwrap(),
        )
        .unwrap();

    let changed_delivery = state
        .apply_inbound_pool_update(
            XITE,
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![canonical.clone()])).unwrap(),
        )
        .await
        .unwrap();
    assert!(
        !changed_delivery,
        "same payload must not be delivered twice"
    );
    let persisted: Value = serde_json::from_slice(&storage.read(&shard).unwrap()).unwrap();
    assert_eq!(
        pool::pool_records_of(&persisted)[0]["sign"],
        canonical["sign"]
    );
}

#[tokio::test]
async fn current_shard_quarantine_is_persisted_when_incoming_is_not_admitted() {
    let key = epix_crypt::new_seed();
    let existing = rln_record(&key, 71);
    let incoming = rln_record(&key, 72);
    let existing_id = pool_record_id(&existing).unwrap();

    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    std::fs::create_dir_all(&root).unwrap();
    let state = AppState::with_data_dir("pool-quarantine-test", home.path());
    state
        .add_xite(
            XITE,
            XiteEntry {
                storage: XiteStorage::new(&root),
                content: Some(rln_descriptor()),
            },
        )
        .await;
    state
        .set_pool_admission(Arc::new(EvictAdmission(existing_id)))
        .await;
    let rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(existing["tag"].as_str().unwrap())
        .unwrap();
    let shard = pool::shard_path(&rule, existing["epoch"].as_i64().unwrap(), &tag);
    let storage = XiteStorage::new(&root);
    storage
        .write_atomic_durable(
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![existing])).unwrap(),
        )
        .unwrap();

    let error = state
        .apply_inbound_pool_update(
            XITE,
            &shard,
            &serde_json::to_vec(&pool::make_pool_container(vec![incoming])).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(error.contains("not retained exactly"));
    let persisted: Value = serde_json::from_slice(&storage.read(&shard).unwrap()).unwrap();
    assert!(
        pool::pool_records_of(&persisted).is_empty(),
        "current-shard eviction must be durable even with no delivery delta"
    );
}

#[tokio::test]
async fn cancelled_rln_admission_is_rebuilt_from_disk_before_retry() {
    let key = epix_crypt::new_seed();
    let incoming = rln_record(&key, 81);
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    std::fs::create_dir_all(&root).unwrap();
    let state = AppState::with_data_dir("pool-cancel-test", home.path());
    state
        .add_xite(
            XITE,
            XiteEntry {
                storage: XiteStorage::new(&root),
                content: Some(rln_descriptor()),
            },
        )
        .await;
    let admission = Arc::new(CancelOnceAdmission::new());
    state.set_pool_admission(admission.clone()).await;
    let rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(incoming["tag"].as_str().unwrap())
        .unwrap();
    let shard = pool::shard_path(&rule, incoming["epoch"].as_i64().unwrap(), &tag);
    let wire = serde_json::to_vec(&pool::make_pool_container(vec![incoming.clone()])).unwrap();

    let task = {
        let state = state.clone();
        let shard = shard.clone();
        let wire = wire.clone();
        tokio::spawn(async move { state.apply_inbound_pool_update(XITE, &shard, &wire).await })
    };
    for _ in 0..100 {
        if admission.entered.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert!(admission.entered.load(Ordering::SeqCst));
    task.abort();
    let _ = task.await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!XiteStorage::new(&root).exists(&shard));

    assert!(state
        .apply_inbound_pool_update(XITE, &shard, &wire)
        .await
        .unwrap());
    let persisted: Value =
        serde_json::from_slice(&XiteStorage::new(&root).read(&shard).unwrap()).unwrap();
    assert_eq!(pool::pool_records_of(&persisted).len(), 1);
}

#[tokio::test]
async fn peer_confirmation_survives_a_concurrent_route_refresh() {
    let key = epix_crypt::new_seed();
    let outbound = record(&key, 91, false);
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, 1_000_000).await;
    let old_rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(outbound["tag"].as_str().unwrap())
        .unwrap();
    let old_shard = pool::shard_path(&old_rule, outbound["epoch"].as_i64().unwrap(), &tag);
    let push = Arc::new(PausingPush {
        entered: AtomicBool::new(false),
        release: AtomicBool::new(false),
    });
    state.set_edx_fetcher(push.clone()).await;
    state
        .add_peers(XITE, [PeerAddr::parse("1.2.3.4:26959").unwrap()])
        .await;

    let append_state = state.clone();
    let append_shard = old_shard.clone();
    let append = tokio::spawn(async move {
        append_state
            .append_pool_record_confirmed_migrating_status(XITE, &append_shard, outbound, &[])
            .await
    });
    while !push.entered.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    let mut changed = descriptor(1_000_000);
    changed["pool"]["channels"]["fanout"] = json!(2);
    state.update_content(XITE, Some(changed)).await;
    state.refresh_pool_rules(XITE).await;
    push.release.store(true, Ordering::Release);

    assert!(matches!(
        append.await.unwrap().unwrap(),
        PoolAppendConfirmation::RouteChangedAfterPeerConfirmation { staged_shard }
            if staged_shard == old_shard
    ));
}

#[tokio::test]
async fn peer_confirmation_survives_a_concurrent_route_lookup_failure() {
    let key = epix_crypt::new_seed();
    let outbound = record(&key, 92, false);
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, 1_000_000).await;
    let old_rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(outbound["tag"].as_str().unwrap())
        .unwrap();
    let old_shard = pool::shard_path(&old_rule, outbound["epoch"].as_i64().unwrap(), &tag);
    let push = Arc::new(PausingPush {
        entered: AtomicBool::new(false),
        release: AtomicBool::new(false),
    });
    state.set_edx_fetcher(push.clone()).await;
    state
        .add_peers(XITE, [PeerAddr::parse("1.2.3.4:26959").unwrap()])
        .await;

    let append_state = state.clone();
    let append_shard = old_shard.clone();
    let append = tokio::spawn(async move {
        append_state
            .append_pool_record_confirmed_migrating_status(XITE, &append_shard, outbound, &[])
            .await
    });
    while !push.entered.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    state
        .update_content(XITE, Some(json!({ "address": XITE })))
        .await;
    state.refresh_pool_rules(XITE).await;
    push.release.store(true, Ordering::Release);

    assert!(matches!(
        append.await.unwrap().unwrap(),
        PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
            staged_shard,
            reason,
        } if staged_shard == old_shard && reason.contains("no pool configured")
    ));
}

#[tokio::test]
async fn peer_confirmation_survives_a_concurrent_capacity_eviction() {
    let key = epix_crypt::new_seed();
    let mut candidates: Vec<Value> = (1..=12).map(|marker| record(&key, marker, false)).collect();
    candidates.sort_by_key(work_id);
    let better = candidates.first().unwrap().clone();
    let outbound = candidates.last().unwrap().clone();
    let one_len = serde_json::to_vec(&pool::make_pool_container(vec![outbound.clone()]))
        .unwrap()
        .len();
    let two_len = serde_json::to_vec(&pool::make_pool_container(vec![
        better.clone(),
        outbound.clone(),
    ]))
    .unwrap()
    .len();
    let cap = one_len + (two_len - one_len) / 2;

    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("xite");
    let state = node(home.path(), &root, cap).await;
    let rule = state.pool_rules_for(XITE).await.remove(0);
    let tag = base64::engine::general_purpose::STANDARD
        .decode(outbound["tag"].as_str().unwrap())
        .unwrap();
    let shard = pool::shard_path(&rule, outbound["epoch"].as_i64().unwrap(), &tag);
    let push = Arc::new(PausingPush {
        entered: AtomicBool::new(false),
        release: AtomicBool::new(false),
    });
    state.set_edx_fetcher(push.clone()).await;
    state
        .add_peers(XITE, [PeerAddr::parse("1.2.3.4:26959").unwrap()])
        .await;

    let append_state = state.clone();
    let append_shard = shard.clone();
    let append = tokio::spawn(async move {
        append_state
            .append_pool_record_confirmed_migrating_status(XITE, &append_shard, outbound, &[])
            .await
    });
    while !push.entered.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    let wire = serde_json::to_vec(&pool::make_pool_container(vec![better.clone()])).unwrap();
    assert!(state
        .apply_inbound_pool_update(XITE, &shard, &wire)
        .await
        .unwrap());
    push.release.store(true, Ordering::Release);

    assert!(matches!(
        append.await.unwrap().unwrap(),
        PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
            staged_shard,
            reason,
        } if staged_shard == shard && reason.contains("evicted")
    ));
    let persisted: Value =
        serde_json::from_slice(&XiteStorage::new(&root).read(&shard).unwrap()).unwrap();
    assert_eq!(pool::pool_records_of(&persisted), vec![better]);
}
