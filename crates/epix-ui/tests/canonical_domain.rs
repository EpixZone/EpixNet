//! Address browsing starts immediately; verified xID names arrive independently.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use epix_ui::state::XiteEntry;
use epix_ui::{rewrite_proxy_host, AppState, OnDemandResolver, ResolvedHost, UiServer};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tower::ServiceExt;

static KEY: std::sync::LazyLock<String> = std::sync::LazyLock::new(epix_crypt::new_seed);
static XITE_ADDRESS: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| epix_crypt::privatekey_to_address(&KEY).unwrap());
fn address() -> &'static str {
    XITE_ADDRESS.as_str()
}
fn manifest() -> Value {
    let mut content = json!({
        "address": address(), "domain": DOMAIN, "modified": 1,
        "files": {"index.html": {"size": 7, "sha512": XiteStorage::hash_bytes(b"fixture")}},
    });
    epix_content::sign(&mut content, &KEY).unwrap();
    content
}
const OTHER: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
const DOMAIN: &str = "navigation-fixture.epix";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn cache(root: &std::path::Path, address: &str, resolved_at: u64) {
    // This integration binary uses the resolver's explicit legacy default.
    // Cryptographic finality and rejected cache publication are covered by
    // the node's signed-proof tests and the compiled-browser fixture.
    tokio::fs::write(
        root.join("resolve-cache.json"),
        json!({DOMAIN: {"address": address, "resolved_at": resolved_at}}).to_string(),
    )
    .await
    .unwrap();
}

async fn fixture(complete: bool) -> (tempfile::TempDir, Arc<AppState>, axum::Router) {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("canonical-domain-test", root.path());
    let path = root.path().join("data").join(address());
    tokio::fs::create_dir_all(&path).await.unwrap();
    if complete {
        tokio::fs::write(path.join("index.html"), b"fixture")
            .await
            .unwrap();
    }
    tokio::fs::write(
        path.join("content.json"),
        epix_content::dumps_content(&manifest()),
    )
    .await
    .unwrap();
    state
        .add_xite(
            address(),
            XiteEntry {
                storage: XiteStorage::new(path),
                content: Some(manifest()),
            },
        )
        .await;
    let router = UiServer::new(state.clone()).router();
    (root, state, router)
}

async fn open(router: &axum::Router) -> axum::response::Response {
    let request = Request::builder()
        .uri("/")
        .header("host", format!("{}.epix", address()))
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .body(Body::empty())
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        router.clone().oneshot(rewrite_proxy_host(request)),
    )
    .await
    .expect("a name lookup must not delay the address wrapper")
    .unwrap()
}

struct SlowResolver {
    root: PathBuf,
    answer: &'static str,
    clones: AtomicUsize,
    lookups: AtomicUsize,
    reverse_lookups: AtomicUsize,
    active_lookups: AtomicUsize,
    registry_answer: AtomicBool,
    release: Semaphore,
}

struct ActiveLookup<'a>(&'a AtomicUsize);

impl<'a> ActiveLookup<'a> {
    fn new(active: &'a AtomicUsize) -> Self {
        active.fetch_add(1, Ordering::SeqCst);
        Self(active)
    }
}

impl Drop for ActiveLookup<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl OnDemandResolver for SlowResolver {
    async fn ensure(&self, host: &str) -> Result<(), String> {
        assert_eq!(host, format!("{}.epix", address()));
        self.clones.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn resolve(&self, _host: &str) -> Option<ResolvedHost> {
        None
    }

    async fn resolve_verified_name(&self, host: &str) -> Option<ResolvedHost> {
        assert_eq!(host, DOMAIN);
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveLookup::new(&self.active_lookups);
        self.release.acquire().await.unwrap().forget();
        cache(&self.root, self.answer, now()).await;
        Some(ResolvedHost {
            address: self.answer.into(),
            verified: true,
        })
    }

    async fn reverse_xite(&self, address: &str) -> Option<String> {
        assert_eq!(address, XITE_ADDRESS.as_str());
        self.reverse_lookups.fetch_add(1, Ordering::SeqCst);
        if !self.registry_answer.load(Ordering::SeqCst) {
            return None;
        }
        let _active = ActiveLookup::new(&self.active_lookups);
        self.release.acquire().await.unwrap().forget();
        cache(&self.root, self.answer, now()).await;
        Some(DOMAIN.into())
    }
}

async fn install_slow(
    state: &Arc<AppState>,
    root: &std::path::Path,
    answer: &'static str,
) -> Arc<SlowResolver> {
    let resolver = Arc::new(SlowResolver {
        root: root.to_path_buf(),
        answer,
        clones: AtomicUsize::new(0),
        lookups: AtomicUsize::new(0),
        reverse_lookups: AtomicUsize::new(0),
        active_lookups: AtomicUsize::new(0),
        registry_answer: AtomicBool::new(false),
        release: Semaphore::new(0),
    });
    state.set_on_demand(resolver.clone()).await;
    state.register_bound_conn(address(), 1);
    resolver
}

#[tokio::test]
async fn site_info_exposes_a_verified_cached_domain_for_an_address() {
    let (root, state, _router) = fixture(true).await;
    cache(root.path(), address(), now()).await;
    assert_eq!(state.xite_info(address()).await["canonical_domain"], DOMAIN);
}

#[tokio::test]
async fn display_metadata_alone_cannot_promote_the_browser_origin() {
    let (_root, state, router) = fixture(true).await;
    state.set_display(address(), DOMAIN).await;
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    assert!(state.xite_info(address()).await["canonical_domain"].is_null());
}

#[tokio::test]
async fn expired_cache_cannot_promote_the_browser_origin() {
    let (root, state, router) = fixture(true).await;
    cache(root.path(), address(), 1).await;
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    assert!(state.xite_info(address()).await["canonical_domain"].is_null());
}

#[tokio::test]
async fn address_discovery_and_wrapper_continue_while_the_domain_lookup_waits() {
    let (root, state, router) = fixture(false).await;
    let resolver = install_slow(&state, root.path(), address()).await;
    let mut events = state.subscribe_events();
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.clones.load(Ordering::SeqCst) == 0
            || resolver.lookups.load(Ordering::SeqCst) == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("address discovery and independent xID verification must both start");
    for _ in 0..4 {
        assert_eq!(open(&router).await.status(), StatusCode::OK);
    }
    assert_eq!(
        resolver.lookups.load(Ordering::SeqCst),
        1,
        "concurrent tabs coalesce the name check"
    );
    assert!(state.xite_info(address()).await["canonical_domain"].is_null());
    resolver.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = events.recv().await.unwrap();
            let message: Value = serde_json::from_str(&event.payload).unwrap();
            if message["cmd"] == "setSiteInfo" && message["params"]["canonical_domain"] == DOMAIN {
                assert_eq!(event.target.as_deref(), Some(address()));
                break;
            }
        }
    })
    .await
    .expect("verified name must reach the already-open wrapper");
}

#[tokio::test]
async fn a_domain_pointing_at_another_address_never_promotes_this_xite() {
    let (root, state, router) = fixture(true).await;
    let resolver = install_slow(&state, root.path(), OTHER).await;
    resolver.release.add_permits(1);
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.lookups.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the configured name must be checked");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(state.xite_info(address()).await["canonical_domain"].is_null());
    assert_eq!(open(&router).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn metadata_arriving_during_discovery_starts_the_name_check() {
    let (root, state, router) = fixture(false).await;
    state.update_content(address(), None).await;
    let resolver = install_slow(&state, root.path(), address()).await;
    resolver.release.add_permits(1);
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
    state
        .add_xite(
            address(),
            XiteEntry {
                storage: XiteStorage::new(root.path().join("data").join(address())),
                content: Some(manifest()),
            },
        )
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.xite_info(address()).await["canonical_domain"] != DOMAIN {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("newly discovered metadata must trigger domain verification without a reload");
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn registry_lookup_starts_before_any_metadata_or_peer_response() {
    let (root, state, router) = fixture(false).await;
    state.update_content(address(), None).await;
    tokio::fs::remove_file(
        root.path()
            .join("data")
            .join(address())
            .join("content.json"),
    )
    .await
    .unwrap();
    let resolver = install_slow(&state, root.path(), address()).await;
    resolver.registry_answer.store(true, Ordering::SeqCst);
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.reverse_lookups.load(Ordering::SeqCst) == 0
            || resolver.clones.load(Ordering::SeqCst) == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("registry lookup and address discovery must start independently");
    assert!(state.content(address()).await.is_none());
    resolver.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.xite_info(address()).await["canonical_domain"] != DOMAIN {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the domain must be available before xite metadata");
    assert!(state.content(address()).await.is_none());
}

#[tokio::test]
async fn downloaded_xite_uses_current_xid_cache_without_requerying_or_cloning() {
    let (root, state, router) = fixture(true).await;
    cache(root.path(), address(), now()).await;
    let resolver = install_slow(&state, root.path(), address()).await;
    assert_eq!(open(&router).await.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(state.xite_info(address()).await["canonical_domain"], DOMAIN);
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
    assert_eq!(resolver.reverse_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(resolver.clones.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_late_websocket_rearms_name_verification_after_the_initial_grace_period() {
    let (root, state, router) = fixture(true).await;
    let resolver = install_slow(&state, root.path(), OTHER).await;
    state.unregister_bound_conn(address(), 1);
    resolver.release.add_permits(1);
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_secs(11)).await;
    let mut events = state.subscribe_events();
    state.register_bound_conn(address(), 2);
    cache(root.path(), address(), now()).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = events.recv().await.unwrap();
            let message: Value = serde_json::from_str(&event.payload).unwrap();
            if message["params"]["canonical_domain"] == DOMAIN {
                break;
            }
        }
    })
    .await
    .expect("a late WebSocket must receive the newly verified name");
}

enum EndView {
    Closed,
    Deleted,
}

async fn stopped_view_cancels_lookup(registry: bool, end: EndView) {
    let (root, state, router) = fixture(false).await;
    if registry {
        state.update_content(address(), None).await;
        tokio::fs::remove_file(
            root.path()
                .join("data")
                .join(address())
                .join("content.json"),
        )
        .await
        .unwrap();
    }
    let resolver = install_slow(&state, root.path(), address()).await;
    resolver.registry_answer.store(registry, Ordering::SeqCst);
    let mut events = state.subscribe_events();
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.active_lookups.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the lookup must be in flight before ending this view");
    assert_eq!(
        resolver.lookups.load(Ordering::SeqCst),
        usize::from(!registry)
    );
    assert_eq!(
        resolver.reverse_lookups.load(Ordering::SeqCst),
        usize::from(registry)
    );

    if matches!(end, EndView::Closed) {
        state.unregister_bound_conn(address(), 1);
    } else {
        assert!(state.remove_xite(address()).await);
        assert!(!state.has_xite(address()).await);
        // A deleted xite can still have its old browser tab open. Cancellation
        // must survive the brief deleting phase without a WebSocket close.
        assert!(state.has_bound_conn(address()));
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while resolver.active_lookups.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ending the view must drop the pending registry/proof future");

    // Making the former RPC ready must not publish its answer or let a later
    // watcher tick restart this abandoned lookup.
    resolver.release.add_permits(8);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(
        resolver.lookups.load(Ordering::SeqCst),
        usize::from(!registry)
    );
    assert_eq!(
        resolver.reverse_lookups.load(Ordering::SeqCst),
        usize::from(registry)
    );
    assert!(!root.path().join("resolve-cache.json").exists());
    assert!(state.display_of(address()).await.is_none());
    assert!(state.verified_xite_domain(address()).await.is_none());
    while let Ok(event) = events.try_recv() {
        let message: Value = serde_json::from_str(&event.payload).unwrap();
        assert_ne!(
            message["params"]["canonical_domain"], DOMAIN,
            "a canceled lookup must not publish a late browser-origin change"
        );
    }
}

#[tokio::test]
async fn closing_the_view_cancels_an_in_flight_registry_lookup() {
    stopped_view_cancels_lookup(true, EndView::Closed).await;
}

#[tokio::test]
async fn closing_the_view_cancels_an_in_flight_proof_lookup() {
    stopped_view_cancels_lookup(false, EndView::Closed).await;
}

#[tokio::test]
async fn deleting_the_xite_cancels_an_in_flight_registry_lookup() {
    stopped_view_cancels_lookup(true, EndView::Deleted).await;
}

#[tokio::test]
async fn deleting_the_xite_cancels_an_in_flight_proof_lookup() {
    stopped_view_cancels_lookup(false, EndView::Deleted).await;
}

#[tokio::test]
async fn a_late_websocket_cannot_restart_lookup_for_a_deleted_xite() {
    let (root, state, _router) = fixture(false).await;
    assert!(state.remove_xite(address()).await);
    let resolver = install_slow(&state, root.path(), address()).await;
    resolver.registry_answer.store(true, Ordering::SeqCst);
    state.request_xite_domain(address()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 0);
    assert_eq!(resolver.reverse_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(resolver.active_lookups.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_readded_xite_keeps_its_new_lookup_when_the_old_one_is_canceled() {
    let (root, state, router) = fixture(false).await;
    let resolver = install_slow(&state, root.path(), address()).await;
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.active_lookups.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(state.remove_xite(address()).await);
    state
        .add_xite(
            address(),
            XiteEntry {
                storage: XiteStorage::new(root.path().join("data").join(address())),
                content: Some(manifest()),
            },
        )
        .await;
    state.request_xite_domain(address()).await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while resolver.lookups.load(Ordering::SeqCst) != 2
            || resolver.active_lookups.load(Ordering::SeqCst) != 1
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the new lookup survives cancellation of its predecessor");
    // Wait across the new watcher's next observation too: an old task's Drop
    // must not accidentally remove the replacement task's registration.
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(resolver.active_lookups.load(Ordering::SeqCst), 1);
    resolver.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.display_of(address()).await.as_deref() != Some(DOMAIN) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the replacement view receives its own verified result");
}

#[tokio::test]
async fn a_delayed_placeholder_starts_registry_lookup_for_an_already_bound_viewer() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("delayed-placeholder-test", root.path());
    let resolver = install_slow(&state, root.path(), address()).await;
    resolver.registry_answer.store(true, Ordering::SeqCst);
    let router = UiServer::new(state.clone()).router();
    assert_eq!(open(&router).await.status(), StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.clones.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("address discovery starts before its placeholder is registered");
    // Both the wrapper and its WebSocket reach the node before add_xite.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!state.has_xite(address()).await);
    assert_eq!(resolver.reverse_lookups.load(Ordering::SeqCst), 0);
    resolver.release.add_permits(1);
    state
        .add_xite(
            address(),
            XiteEntry {
                storage: XiteStorage::new(root.path().join("data").join(address())),
                content: None,
            },
        )
        .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while state.display_of(address()).await.as_deref() != Some(DOMAIN) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("placeholder arrival must start registry lookup without another page/WS load");
    assert!(state.content(address()).await.is_none());
    assert_eq!(resolver.reverse_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(resolver.clones.load(Ordering::SeqCst), 1);
}
