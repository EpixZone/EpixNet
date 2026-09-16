//! Fresh alias checks run separately from address-based discovery. Each case
//! owns a child process because chain routing and finality are process-wide.

use super::*;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use epix_ui::OnDemandResolver as _;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const NAME: &str = "navigation.epix";
const ADDRESS: &str = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
const CHAIN: &str = "epix_1917-1";
const SNAPSHOT: &str = "/xid/v1/state_snapshot?pagination.limit=10";
const NEXT_SNAPSHOT: &str =
    "/xid/v1/state_snapshot?pagination.limit=10&pagination.key=next%2F%2B%3D";

#[derive(Default)]
struct RegistryFixture {
    paths: std::sync::Mutex<Vec<String>>,
    pages: std::sync::Mutex<std::collections::HashMap<String, Value>>,
}

struct RpcSignals {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    registry: Arc<RegistryFixture>,
}

struct Rpc {
    requests: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    registry: Arc<RegistryFixture>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Rpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn put_uvarint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn attestations(key: &SigningKey, digest: &str, now: i64) -> Value {
    let height = 12;
    let mut extension = vec![0x08];
    put_uvarint(height, &mut extension);
    extension.push(0x10);
    put_uvarint(now as u64, &mut extension);
    extension.push(0x1a);
    put_uvarint(digest.len() as u64, &mut extension);
    extension.extend_from_slice(digest.as_bytes());
    let signed = epix_chain::canonical_vote_ext_bytes(&extension, height as i64, 0, CHAIN);
    json!({
        "height": height.to_string(), "block_time": now.to_string(),
        "finalized": false,
        "attestations": [{
            "validator_cons_addr": "epixvalcons1navigation",
            "signature": hex::encode(key.sign(&signed).to_bytes()),
            "vote_extension": base64::engine::general_purpose::STANDARD.encode(extension),
            "round": "0",
        }],
    })
}

impl Rpc {
    async fn start(root: &std::path::Path) -> Self {
        let seed: [u8; 32] = hex::decode(epix_crypt::new_seed())
            .unwrap()
            .try_into()
            .unwrap();
        let key = SigningKey::from_bytes(&seed);
        let now = now_secs() as i64;
        let pin = epix_chain::PinnedSet::new(
            std::collections::HashMap::from([(
                "epixvalcons1navigation".to_string(),
                epix_chain::PinnedValidator {
                    pubkey: key.verifying_key().to_bytes(),
                    voting_power: 1,
                },
            )]),
            CHAIN,
            now,
            1,
        )
        .unwrap();
        epix_chain::set_pinned_validators(Some(pin));
        epix_chain::set_verify_finality(true);
        epix_chain::configure_finality_checkpoint(root.join("checkpoint.json")).unwrap();
        epix_chain::set_chain_route(None, false);
        let leaf = serde_json::to_vec(&json!({
            "name":"navigation", "tld":"epix", "owner":ADDRESS,
            "dns":[{"record_type":65280,"value":ADDRESS}],
            "identities":[],
        }))
        .unwrap();
        let digest = hex::encode(Sha256::digest(&leaf));
        let proof = json!({
            "proof":{"leaf_hash":digest,"root":digest,"leaf_index":0,"siblings":[]},
            "leaf_preimage":hex::encode(leaf),
            // A consumer must use the signed leaf, not this contradictory payload.
            "domain":{"dns_records":[{"record_type":65280,"value":DASHBOARD_XITE_ADDRESS}]},
        });
        let attestation = attestations(&key, &digest, now);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        epix_chain::set_chain_rpc_urls(std::slice::from_ref(&url));
        let requests = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let registry = Arc::new(RegistryFixture::default());
        let task = tokio::spawn(Self::serve(
            listener,
            proof.clone(),
            attestation,
            requests.clone(),
            fail.clone(),
            pause.clone(),
            RpcSignals {
                entered: entered.clone(),
                release: release.clone(),
                registry: registry.clone(),
            },
        ));
        Self {
            requests,
            fail,
            pause,
            entered,
            release,
            registry,
            task,
        }
    }

    async fn serve(
        listener: tokio::net::TcpListener,
        proof: Value,
        attestation: Value,
        requests: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
        pause: Arc<AtomicBool>,
        signals: RpcSignals,
    ) {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).await.is_err() {
                    break;
                }
                request.push(byte[0]);
            }
            requests.fetch_add(1, Ordering::SeqCst);
            signals.entered.notify_one();
            if pause.load(Ordering::SeqCst) {
                signals.release.notified().await;
            }
            let request = String::from_utf8_lossy(&request);
            let path = request
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            signals
                .registry
                .paths
                .lock()
                .unwrap()
                .push(path.to_string());
            let body = if fail.load(Ordering::SeqCst) {
                json!({"code":14,"message":"fixture unavailable"})
            } else if path.contains("/attestations?") {
                attestation.clone()
            } else if path.starts_with("/xid/v1/state_snapshot") {
                signals
                    .registry
                    .pages
                    .lock()
                    .unwrap()
                    .get(path)
                    .cloned()
                    .unwrap_or_else(|| json!({"code":14,"message":"fixture unavailable"}))
            } else {
                proof.clone()
            };
            let bytes = serde_json::to_vec(&body).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len(),
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&bytes).await;
        }
    }

    fn page(&self, path: &str, domains: Value, next: &str) {
        self.registry.pages.lock().unwrap().insert(
            path.to_string(),
            json!({
                "domains": domains, "pagination": {"next_key": next},
            }),
        );
    }

    fn paths(&self) -> Vec<String> {
        self.registry.paths.lock().unwrap().clone()
    }

    async fn seed_cache(&self, root: &std::path::Path, address: &str) {
        let (_, binding) = epix_chain::shared_resolver()
            .resolve_fresh_bound("navigation", "epix")
            .await
            .unwrap();
        write_resolve_cache_bound(root, NAME, address, binding.as_ref());
    }
}

fn resolver(root: &std::path::Path, offline: bool) -> Arc<OnDemand> {
    let state = AppState::with_data_dir("navigation-test", root);
    Arc::new_cyclic(|me| OnDemand {
        state,
        data_root: root.to_path_buf(),
        trackers: vec![epix_xite::Tracker::Epix(
            PeerAddr::parse("8.8.8.8:26552").unwrap(),
        )],
        network_disabled: offline,
        me: me.clone(),
        in_flight: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        in_flight_token: std::sync::atomic::AtomicU64::new(0),
        tor_expected: AtomicBool::new(false),
        tor_always: AtomicBool::new(false),
        resolving: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        verifier_wake: tokio::sync::Notify::new(),
    })
}

fn isolated(case: &'static str) {
    const WORKER: &str = "EPIX_NAVIGATION_TEST_WORKER";
    if std::env::var(WORKER).as_deref() == Ok(case) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(run_case(case));
        return;
    }
    let test_name = format!("navigation_tests::{case}");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test_name, "--nocapture"])
        .env(WORKER, case)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "isolated navigation case failed: {case}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated navigation case timed out: {case}");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

async fn run_case(case: &str) {
    let dir = tempfile::tempdir().unwrap();
    let rpc = Rpc::start(dir.path()).await;
    let node = resolver(
        dir.path(),
        case == "fresh_alias_offline_never_queries" || case == "registry_offline_never_queries",
    );
    if case.starts_with("registry_") {
        run_registry_case(case, &rpc, &node).await;
        return;
    }
    match case {
        "fresh_alias_uses_proven_dns_instead_of_cached_address" => {
            rpc.seed_cache(dir.path(), DASHBOARD_XITE_ADDRESS).await;
            assert_eq!(
                node.resolve(NAME).await.unwrap().address,
                DASHBOARD_XITE_ADDRESS
            );
            let fresh = node
                .resolve_verified_name(NAME)
                .await
                .expect("fresh name lookup must succeed");
            assert_eq!(fresh.address, ADDRESS);
            assert!(fresh.verified);
            assert_eq!(
                node.state.resolve_name_verified(NAME).await,
                Some((ADDRESS.into(), true))
            );
            assert!(
                !node.state.has_xite(ADDRESS).await,
                "name checking must never clone"
            );
        }
        "fresh_alias_outage_never_reuses_cached_answer" => {
            rpc.seed_cache(dir.path(), ADDRESS).await;
            epix_chain::clear_xid_caches().await;
            rpc.fail.store(true, Ordering::SeqCst);
            let before = rpc.requests.load(Ordering::SeqCst);
            assert!(node.resolve_verified_name(NAME).await.is_none());
            assert!(
                rpc.requests.load(Ordering::SeqCst) > before,
                "fresh lookup must contact chain"
            );
        }
        "fresh_alias_reuses_current_shared_proof_cache" => {
            assert!(node.resolve_verified_name(NAME).await.is_some());
            let before = rpc.requests.load(Ordering::SeqCst);
            assert!(node.resolve_verified_name(NAME).await.is_some());
            assert_eq!(
                rpc.requests.load(Ordering::SeqCst),
                before,
                "a current proof in the shared xID cache must avoid another RPC"
            );
        }
        "fresh_alias_offline_never_queries"
        | "fresh_alias_tor_required_never_queries"
        | "fresh_alias_without_trust_never_queries" => {
            rpc.seed_cache(dir.path(), ADDRESS).await;
            if case == "fresh_alias_tor_required_never_queries" {
                epix_chain::clear_xid_caches().await;
                epix_chain::set_chain_route(None, true);
            }
            if case == "fresh_alias_without_trust_never_queries" {
                epix_chain::set_pinned_validators(None);
            }
            let before = rpc.requests.load(Ordering::SeqCst);
            assert!(node.resolve_verified_name(NAME).await.is_none());
            assert_eq!(rpc.requests.load(Ordering::SeqCst), before);
        }
        "fresh_alias_superseded_cache_publication_is_not_verified" => {
            let newer = json!({ NAME: {
                "address": ADDRESS, "resolved_at": now_secs(),
                "finality_height": 1000, "finality_digest": "ab".repeat(32),
            }});
            tokio::fs::write(
                resolve_cache_path(dir.path()),
                serde_json::to_vec(&newer).unwrap(),
            )
            .await
            .unwrap();
            assert!(node.resolve_verified_name(NAME).await.is_none());
            assert_eq!(
                read_resolve_cache(dir.path())[NAME]["finality_height"],
                1000
            );
        }
        "fresh_alias_slow_rpc_does_not_delay_address_discovery" => {
            slow_alias_keeps_discovery_independent(&rpc, &node).await;
        }
        "fresh_alias_rejects_unsupported_and_address_shaped_names" => {
            for name in [
                ADDRESS,
                "epix.talk",
                "sub.navigation.epix",
                "bad/name.epix",
                "-navigation.epix",
                "navigation-.epix",
            ] {
                assert!(node.resolve_verified_name(name).await.is_none(), "{name}");
            }
            assert!(node
                .resolve_verified_name(&format!("{ADDRESS}.epix"))
                .await
                .is_none());
            let typo = format!("{}q.epix", &ADDRESS[..ADDRESS.len() - 1]);
            assert!(node.resolve_verified_name(&typo).await.is_none());
            assert_eq!(rpc.requests.load(Ordering::SeqCst), 0);
        }
        _ => panic!("unknown test case: {case}"),
    }
}

fn registry_domain(address: &str) -> Value {
    json!({
        "record":{"name":"navigation","tld":"epix"},
        "dns_records":[{"record_type":65280,"value":address}],
        "identities":[],
    })
}

async fn run_registry_case(case: &str, rpc: &Rpc, node: &Arc<OnDemand>) {
    rpc.page(SNAPSHOT, json!([]), "next/+=");
    rpc.page(NEXT_SNAPSHOT, json!([registry_domain(ADDRESS)]), "");
    match case {
        "registry_finds_xite_without_metadata_or_linked_identity" => {
            assert!(!node.state.has_xite(ADDRESS).await);
            assert_eq!(node.reverse_xite(ADDRESS).await.as_deref(), Some(NAME));
            assert!(
                !node.state.has_xite(ADDRESS).await,
                "registry lookup must not clone"
            );
            assert_eq!(&rpc.paths()[..2], &[SNAPSHOT, NEXT_SNAPSHOT]);
            assert!(!rpc
                .paths()
                .iter()
                .any(|path| path.contains("reverse_identity")));
        }
        "registry_candidate_must_match_forward_proof" => {
            rpc.page(
                NEXT_SNAPSHOT,
                json!([registry_domain(DASHBOARD_XITE_ADDRESS)]),
                "",
            );
            assert!(node.reverse_xite(DASHBOARD_XITE_ADDRESS).await.is_none());
            assert!(
                rpc.paths()
                    .iter()
                    .any(|path| path.contains("resolve_with_proof")),
                "a registry hint requires forward verification"
            );
        }
        "registry_finds_epixnet_record_after_other_dns_records" => {
            let mut domain = registry_domain(ADDRESS);
            let mut records: Vec<Value> = (0..64)
                .map(|i| json!({"record_type":16,"value":i.to_string()}))
                .collect();
            records.push(json!({"record_type":65280,"value":ADDRESS}));
            domain["dns_records"] = json!(records);
            rpc.page(SNAPSHOT, json!([domain]), "");
            assert_eq!(node.reverse_xite(ADDRESS).await.as_deref(), Some(NAME));
        }
        "registry_rejected_hint_does_not_hide_a_later_verified_name" => {
            let mut forged = registry_domain(ADDRESS);
            forged["record"]["name"] = json!("forged");
            rpc.page(SNAPSHOT, json!([forged]), "next/+=");
            assert_eq!(node.reverse_xite(ADDRESS).await.as_deref(), Some(NAME));
            assert!(rpc.paths().iter().any(|path| path == NEXT_SNAPSHOT));
        }
        "registry_clear_cancels_an_inflight_scan_without_waiting_for_rpc" => {
            let resolver = epix_chain::shared_resolver();
            rpc.pause.store(true, Ordering::SeqCst);
            let pending = {
                let resolver = resolver.clone();
                tokio::spawn(async move { resolver.xite_name_candidates(ADDRESS).await })
            };
            tokio::time::timeout(std::time::Duration::from_secs(3), rpc.entered.notified())
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(1), resolver.clear())
                .await
                .expect("clearing xID caches must cancel pending registry work promptly");
            assert!(
                pending.await.unwrap().is_err(),
                "pre-clear index work cannot publish"
            );
            rpc.pause.store(false, Ordering::SeqCst);
            rpc.release.notify_one();
            assert_eq!(
                resolver.xite_name_candidates(ADDRESS).await.unwrap(),
                vec![NAME]
            );
        }
        "registry_coalesces_pagination_and_caches_negative_results" => {
            let resolver = epix_chain::shared_resolver();
            let mut joins = tokio::task::JoinSet::new();
            for _ in 0..8 {
                let resolver = resolver.clone();
                joins.spawn(async move { resolver.xite_name_candidates(ADDRESS).await.unwrap() });
            }
            while let Some(result) = joins.join_next().await {
                assert_eq!(result.unwrap(), vec![NAME]);
            }
            assert!(resolver
                .xite_name_candidates(DASHBOARD_XITE_ADDRESS)
                .await
                .unwrap()
                .is_empty());
            assert!(resolver
                .xite_name_candidates(DASHBOARD_XITE_ADDRESS)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(rpc.paths(), vec![SNAPSHOT, NEXT_SNAPSHOT]);
        }
        "registry_partial_failure_resumes_at_the_unfinished_page" => {
            rpc.registry.pages.lock().unwrap().remove(NEXT_SNAPSHOT);
            let resolver = epix_chain::shared_resolver();
            assert!(resolver.xite_name_candidates(ADDRESS).await.is_err());
            rpc.page(NEXT_SNAPSHOT, json!([registry_domain(ADDRESS)]), "");
            tokio::time::sleep(std::time::Duration::from_millis(5100)).await;
            assert_eq!(
                resolver.xite_name_candidates(ADDRESS).await.unwrap(),
                vec![NAME]
            );
            assert_eq!(
                rpc.paths()
                    .iter()
                    .filter(|path| path.as_str() == SNAPSHOT)
                    .count(),
                1
            );
        }
        "registry_page_budget_resumes_without_a_false_negative" => {
            rpc.page(SNAPSHOT, json!([]), "1");
            for page in 1..64 {
                rpc.page(
                    &format!("{SNAPSHOT}&pagination.key={page}"),
                    json!([]),
                    &(page + 1).to_string(),
                );
            }
            rpc.page(
                &format!("{SNAPSHOT}&pagination.key=64"),
                json!([registry_domain(ADDRESS)]),
                "",
            );
            let resolver = epix_chain::shared_resolver();
            assert!(
                resolver.xite_name_candidates(ADDRESS).await.is_err(),
                "partial scans are not negative results"
            );
            assert_eq!(
                resolver.xite_name_candidates(ADDRESS).await.unwrap(),
                vec![NAME]
            );
            assert_eq!(rpc.paths().len(), 65);
        }
        "registry_rejects_oversized_pages_and_repeated_cursors" => {
            rpc.page(SNAPSHOT, json!([{"padding":"x".repeat(600_000)}]), "");
            let resolver = epix_chain::shared_resolver();
            assert!(resolver.xite_name_candidates(ADDRESS).await.is_err());
            resolver.clear().await;
            rpc.page(SNAPSHOT, json!([]), "next/+=");
            rpc.page(NEXT_SNAPSHOT, json!([]), "next/+=");
            assert!(resolver.xite_name_candidates(ADDRESS).await.is_err());
        }
        "registry_offline_never_queries"
        | "registry_tor_required_never_queries"
        | "registry_without_trust_never_queries" => {
            if case == "registry_tor_required_never_queries" {
                epix_chain::set_chain_route(None, true);
            }
            if case == "registry_without_trust_never_queries" {
                epix_chain::set_pinned_validators(None);
            }
            assert!(node.reverse_xite(ADDRESS).await.is_none());
            assert!(rpc.paths().is_empty());
        }
        _ => panic!("unknown registry case: {case}"),
    }
}

async fn slow_alias_keeps_discovery_independent(rpc: &Rpc, node: &Arc<OnDemand>) {
    let cell = epix_runtime::edx::new_serve_cell(epix_runtime::edx::ControlHandles::detached());
    epix_runtime::edx::ensure_edx_serve(&cell, &node.state)
        .await
        .unwrap();
    struct CountingTransport(Arc<tokio::sync::Notify>);
    #[async_trait::async_trait]
    impl Transport for CountingTransport {
        fn scheme(&self) -> &'static str {
            "tcp"
        }
        async fn dial(&self, _: &PeerAddr) -> epix_core::Result<epix_transport::PeerStream> {
            self.0.notify_one();
            Err(epix_core::Error::Other("fixture has no seed yet".into()))
        }
    }
    let dialed = Arc::new(tokio::sync::Notify::new());
    node.state
        .set_transport(Arc::new(CountingTransport(dialed.clone())))
        .await;
    rpc.pause.store(true, Ordering::SeqCst);
    let resolving = {
        let node = node.clone();
        tokio::spawn(async move { node.resolve_verified_name(NAME).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), rpc.entered.notified())
        .await
        .expect("fresh alias must start a chain query");
    let ensuring = {
        let node = node.clone();
        tokio::spawn(async move { node.ensure(ADDRESS).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), dialed.notified())
        .await
        .expect("raw address must discover peers while alias RPC is blocked");
    assert!(!resolving.is_finished());
    assert!(node.state.has_xite(ADDRESS).await);
    node.cancel(ADDRESS).await;
    ensuring.abort();
    resolving.abort();
}

#[test]
fn fresh_alias_uses_proven_dns_instead_of_cached_address() {
    isolated("fresh_alias_uses_proven_dns_instead_of_cached_address");
}

#[test]
fn fresh_alias_reuses_current_shared_proof_cache() {
    isolated("fresh_alias_reuses_current_shared_proof_cache");
}

#[test]
fn registry_finds_xite_without_metadata_or_linked_identity() {
    isolated("registry_finds_xite_without_metadata_or_linked_identity");
}

#[test]
fn registry_candidate_must_match_forward_proof() {
    isolated("registry_candidate_must_match_forward_proof");
}

#[test]
fn registry_finds_epixnet_record_after_other_dns_records() {
    isolated("registry_finds_epixnet_record_after_other_dns_records");
}

#[test]
fn registry_rejected_hint_does_not_hide_a_later_verified_name() {
    isolated("registry_rejected_hint_does_not_hide_a_later_verified_name");
}

#[test]
fn registry_clear_cancels_an_inflight_scan_without_waiting_for_rpc() {
    isolated("registry_clear_cancels_an_inflight_scan_without_waiting_for_rpc");
}

#[test]
fn registry_coalesces_pagination_and_caches_negative_results() {
    isolated("registry_coalesces_pagination_and_caches_negative_results");
}

#[test]
fn registry_partial_failure_resumes_at_the_unfinished_page() {
    isolated("registry_partial_failure_resumes_at_the_unfinished_page");
}

#[test]
fn registry_page_budget_resumes_without_a_false_negative() {
    isolated("registry_page_budget_resumes_without_a_false_negative");
}

#[test]
fn registry_rejects_oversized_pages_and_repeated_cursors() {
    isolated("registry_rejects_oversized_pages_and_repeated_cursors");
}

#[test]
fn registry_offline_never_queries() {
    isolated("registry_offline_never_queries");
}

#[test]
fn registry_tor_required_never_queries() {
    isolated("registry_tor_required_never_queries");
}

#[test]
fn registry_without_trust_never_queries() {
    isolated("registry_without_trust_never_queries");
}

#[test]
fn fresh_alias_outage_never_reuses_cached_answer() {
    isolated("fresh_alias_outage_never_reuses_cached_answer");
}

#[test]
fn fresh_alias_offline_never_queries() {
    isolated("fresh_alias_offline_never_queries");
}

#[test]
fn fresh_alias_tor_required_never_queries() {
    isolated("fresh_alias_tor_required_never_queries");
}

#[test]
fn fresh_alias_without_trust_never_queries() {
    isolated("fresh_alias_without_trust_never_queries");
}

#[test]
fn fresh_alias_rejects_unsupported_and_address_shaped_names() {
    isolated("fresh_alias_rejects_unsupported_and_address_shaped_names");
}

#[test]
fn fresh_alias_superseded_cache_publication_is_not_verified() {
    isolated("fresh_alias_superseded_cache_publication_is_not_verified");
}

#[test]
fn fresh_alias_slow_rpc_does_not_delay_address_discovery() {
    isolated("fresh_alias_slow_rpc_does_not_delay_address_discovery");
}
