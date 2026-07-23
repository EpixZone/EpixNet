//! Tier 1 UI security, ported from EpixNet's `UiRequest.route` entry checks:
//! the Host allowlist (DNS-rebinding protection), the OPTIONS preflight
//! answer, and the cross-origin request gate with its `Cors:<target>`
//! permission escape hatch.

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

async fn test_server() -> (Arc<AppState>, axum::Router) {
    let state = AppState::new("sec-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("data.json", b"{}").unwrap();
    for addr in ["1Source", "1Target"] {
        let storage = storage.clone();
        state
            .add_xite(addr, XiteEntry { storage, content: Some(json!({ "address": addr })) })
            .await;
    }
    std::mem::forget(dir); // keep files for the router's lifetime
    let router = UiServer::new(state.clone()).router();
    (state, router)
}

fn get(uri: &str, headers: &[(&str, &str)]) -> axum::extract::Request {
    let mut req = axum::extract::Request::builder().uri(uri).method("GET");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.body(axum::body::Body::empty()).unwrap()
}

#[tokio::test]
async fn host_allowlist_blocks_dns_rebinding() {
    let (_state, router) = test_server().await;

    // A rebinding attacker's DNS name is refused outright.
    let resp = router
        .clone()
        .oneshot(get("/", &[("host", "evil.example.com")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // IPs, localhost, and `.epix` proxy hosts pass.
    for host in ["127.0.0.1:42222", "localhost", "[::1]:8080", "talk.epix"] {
        let resp = router.clone().oneshot(get("/", &[("host", host)])).await.unwrap();
        assert_ne!(resp.status(), 403, "host {host} must be allowed");
    }
}

#[tokio::test]
async fn cross_origin_gate_canonicalizes_name_origins() {
    // A page on its clean name origin (https://dashboard.epix/) identifies
    // itself by NAME in the referer, while xites and their permissions are
    // keyed by ADDRESS. The gate must canonicalize both sides, or the
    // name-origin dashboard's ADMIN never resolves and every cross-xite
    // favicon load 403s (the address origin worked, the name origin didn't).
    let dash = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
    let talk = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
    let state = AppState::new("sec-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("data.json", b"{}").unwrap();
    for addr in [dash, talk] {
        let storage = storage.clone();
        state
            .add_xite(addr, XiteEntry { storage, content: Some(json!({ "address": addr })) })
            .await;
    }
    std::mem::forget(dir);
    state.set_display(dash, "dashboard.epix").await;
    state.set_display(talk, "talk.epix").await;
    state.config_set("ui_check_cors", json!(true)).await;
    let router = UiServer::new(state.clone()).router();

    // Without a permission the name-origin cross-xite read is still blocked.
    let name_referer = ("referer", "https://dashboard.epix/index.html");
    let cross = |uri: &str| get(uri, &[("host", "dashboard.epix"), name_referer]);
    let resp = router.clone().oneshot(cross(&format!("/{talk}/data.json"))).await.unwrap();
    assert_eq!(resp.status(), 403, "no permission, still blocked");

    // ADMIN on the dashboard (looked up via the NAME) unlocks any target...
    state.add_permission(dash, "ADMIN").await;
    let resp = router.clone().oneshot(cross(&format!("/{talk}/data.json"))).await.unwrap();
    assert_ne!(resp.status(), 403, "ADMIN resolves through the display name");

    // ...including a target referenced by NAME (canonicalized before the
    // Cors grant comparison too).
    let resp = router.clone().oneshot(cross("/talk.epix/data.json")).await.unwrap();
    assert_ne!(resp.status(), 403, "name-form target canonicalizes");
}

#[tokio::test]
async fn options_preflight_is_answered_directly() {
    let (_state, router) = test_server().await;
    let req = axum::extract::Request::builder()
        .uri("/1Target/data.json")
        .method("OPTIONS")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let h = resp.headers();
    assert_eq!(h.get("access-control-allow-origin").unwrap(), "null");
    assert!(h
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("X-Requested-With"));
    assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
}

#[tokio::test]
async fn cross_origin_gate_and_cors_permission() {
    let (state, router) = test_server().await;
    // The gate defaults on for loopback binds; force it on for the test.
    state.config_set("ui_check_cors", json!(true)).await;
    let host = ("host", "127.0.0.1:42222");

    // Navigation is always allowed.
    let resp = router
        .clone()
        .oneshot(get("/1Target/data.json", &[host, ("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "navigation passes");

    // An untraceable request (no origin, no referer) for a xite is blocked.
    let resp = router.clone().oneshot(get("/1Target/data.json", &[host])).await.unwrap();
    assert_eq!(resp.status(), 403);

    // A foreign origin is blocked.
    let resp = router
        .clone()
        .oneshot(get("/1Target/data.json", &[host, ("origin", "https://evil.example")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Same-xite subresource fetches pass.
    let resp = router
        .clone()
        .oneshot(get(
            "/1Target/data.json",
            &[host, ("referer", "http://127.0.0.1:42222/1Target/")],
        ))
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "same-xite read passes");

    // A cross-xite read is blocked without the Cors permission...
    let cross = || {
        get("/1Target/data.json", &[host, ("referer", "http://127.0.0.1:42222/1Source/")])
    };
    let resp = router.clone().oneshot(cross()).await.unwrap();
    assert_eq!(resp.status(), 403, "cross-xite read blocked");

    // ...and allowed once the source xite holds Cors:<target>.
    state.add_permission("1Source", "Cors:1Target").await;
    let resp = router.clone().oneshot(cross()).await.unwrap();
    assert_ne!(resp.status(), 403, "Cors permission unlocks the read");

    // Global routes carry nothing to probe and stay reachable.
    let resp = router
        .clone()
        .oneshot(get("/EpixNet-Internal/Status", &[host]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // /StatsJson is fetched cross-origin by the marketing site (through a
    // reverse proxy that adds the CORS headers), so a foreign Origin passes
    // the gate for this one path...
    let resp = router
        .clone()
        .oneshot(get("/StatsJson", &[host, ("origin", "https://epixnet.io")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "/StatsJson is exempt from the gate");

    // ...while the same foreign Origin stays blocked for xite content.
    let resp = router
        .clone()
        .oneshot(get("/1Target/data.json", &[host, ("origin", "https://epixnet.io")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "xite content still gated");
}

#[tokio::test]
async fn backup_page_is_gated() {
    // /Backup serves the node's keys, so unlike /Config it must NOT be exempt
    // from the cross-origin gate, and it must not exist at all on a
    // restricted / NoNewSites (public gateway) node.
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("sec-test", dir.path());
    let xite_dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(xite_dir.path());
    storage.write("data.json", b"{}").unwrap();
    state
        .add_xite("1Source", XiteEntry { storage, content: Some(json!({ "address": "1Source" })) })
        .await;
    std::mem::forget(xite_dir);
    state.config_set("ui_check_cors", json!(true)).await;
    let router = UiServer::new(state.clone()).router();
    let host = ("host", "127.0.0.1:42222");

    // User navigation reaches the page.
    let resp = router
        .clone()
        .oneshot(get("/Backup", &[host, ("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "navigation reaches /Backup");

    // A xite's same-origin fetch() is blocked - it must never read backups.
    let xite_fetch = |uri: &str| {
        get(uri, &[host, ("referer", "http://127.0.0.1:42222/1Source/")])
    };
    let resp = router.clone().oneshot(xite_fetch("/Backup")).await.unwrap();
    assert_eq!(resp.status(), 403, "xite fetch to /Backup blocked");

    // An untraceable request is blocked too (unlike /Config, which is public).
    let resp = router.clone().oneshot(get("/Backup", &[host])).await.unwrap();
    assert_eq!(resp.status(), 403, "untraceable /Backup request blocked");

    // A POST without the page's CSRF token is refused.
    let post = axum::extract::Request::builder()
        .uri("/Backup")
        .method("POST")
        .header("host", "127.0.0.1:42222")
        .header("sec-fetch-mode", "navigate")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from("action=create&comp_keys=on"))
        .unwrap();
    let resp = router.clone().oneshot(post).await.unwrap();
    assert_eq!(resp.status(), 403, "POST without CSRF token refused");

    // A restricted (public gateway) node refuses the page outright...
    state.config_set("ui_restrict", json!(true)).await;
    let resp = router
        .clone()
        .oneshot(get("/Backup", &[host, ("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "restricted node has no /Backup");
    state.config_set("ui_restrict", json!(false)).await;

    // ...as does one with NoNewSites (the gateway's locked-site-set mode)...
    state.set_plugin_enabled("NoNewSites", true).await;
    let resp = router
        .clone()
        .oneshot(get("/Backup", &[host, ("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "NoNewSites node has no /Backup");
    state.set_plugin_enabled("NoNewSites", false).await;

    // ...and one where the UiBackup plugin is turned off.
    state.set_plugin_enabled("UiBackup", false).await;
    let resp = router
        .clone()
        .oneshot(get("/Backup", &[host, ("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "disabled UiBackup removes the page");
}

#[tokio::test]
async fn proxy_mode_subresource_with_epix_in_query_referer_passes() {
    // Regression: in transparent-proxy (host) mode a client-routed xite's own
    // referer carries its route in the query, and that route can hold both a
    // `.epix` and a `/` (e.g. `?Topic:1780270617_user.epix/Epix+Topic+…`). The
    // request path there is just `index.html?<query>`, so the cross-origin
    // gate used to split the query into the referer's "first path segment",
    // read `index.html?Topic:…_user.epix` as a foreign `.epix` source xite, and
    // 403 the xite's own stylesheet - loading it unstyled. It must pass as a
    // same-xite read. `rewrite_proxy_host` runs before routing in production.
    let talk = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
    let state = AppState::new("sec-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("data.json", b"{}").unwrap();
    storage.write("css/all.css", b"body{}").unwrap();
    state
        .add_xite(talk, XiteEntry { storage, content: Some(json!({ "address": talk })) })
        .await;
    std::mem::forget(dir);
    state.config_set("ui_check_cors", json!(true)).await;
    let router = UiServer::new(state.clone()).router();

    let referer = format!(
        "http://{talk}/index.html?Topic:1780270617_user.epix/Epix+Topic"
    );
    let req = epix_ui::rewrite_proxy_host(get(
        "/css/all.css",
        &[("host", talk), ("referer", &referer), ("sec-fetch-mode", "no-cors")],
    ));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_ne!(resp.status(), 403, "xite's own stylesheet must not be 403'd in proxy mode");

    // A genuinely foreign proxy-mode referer is still blocked.
    let cross = epix_ui::rewrite_proxy_host(get(
        "/css/all.css",
        &[
            ("host", talk),
            ("referer", "http://epix1p0stmcza0xjkvv0vnjlk0ypr7xsunt4lxkhgcm/index.html"),
            ("sec-fetch-mode", "no-cors"),
        ],
    ));
    let resp = router.clone().oneshot(cross).await.unwrap();
    assert_eq!(resp.status(), 403, "cross-xite proxy-mode read still blocked");
}
