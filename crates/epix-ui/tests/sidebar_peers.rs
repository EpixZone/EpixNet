//! Peer share URLs must bootstrap the real registry without forwarding peer
//! endpoints into a publisher's iframe or importing private network addresses.
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

async fn fixture() -> (tempfile::TempDir, Arc<AppState>, String) {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("share-test", root.path());
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(root.path().join("data").join(&address));
    let bytes = b"<!doctype html><h1>Shared xite</h1>";
    storage.write("index.html", bytes).unwrap();
    let mut content = json!({"address":address,"modified":1,"files":{"index.html":{
        "size":bytes.len(),"sha512":XiteStorage::hash_bytes(bytes)}}});
    epix_content::sign(&mut content, &key).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&content).as_bytes(),
        )
        .unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    state.set_ui_port(42222).await;
    (root, state, address)
}

#[tokio::test]
async fn share_link_and_wrapper_import_round_trip_with_privacy_filtering() {
    let (_source_dir, source, address) = fixture().await;
    for peer in [
        "8.8.8.8:26552",
        "[2606:4700:4700::1111]:26552",
        "192.168.2.7:26552",
        "127.0.0.1:9000",
    ] {
        source.add_peer_endpoint(&address, peer).await.unwrap();
    }
    let link = source.sidebar_peer_share_url(&address).await;
    let url = reqwest::Url::parse(&link).unwrap();
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    assert_eq!(url.port(), Some(42222));
    let endpoints = url
        .query_pairs()
        .find(|(key, _)| key == "epixnet_peers")
        .unwrap()
        .1;
    assert!(endpoints.contains("8.8.8.8:26552"));
    assert!(endpoints.contains("[2606:4700:4700::1111]:26552"));
    assert!(!endpoints.contains("192.168") && !endpoints.contains("127.0.0.1"));

    let destination_dir = tempfile::tempdir().unwrap();
    let destination = AppState::with_data_dir("receiver", destination_dir.path());
    let storage = XiteStorage::new(destination_dir.path().join("data").join(&address));
    for name in ["index.html", "content.json"] {
        storage
            .write(name, &source.read_file(&address, name).await.unwrap())
            .unwrap();
    }
    destination
        .add_xite(
            &address,
            XiteEntry {
                storage,
                content: source.content(&address).await,
            },
        )
        .await;
    let uri = format!(
        "/{address}/?view=a%2Fb&{}&epixnet_peers=127.0.0.1:1,10.0.0.1:1,bad&Topic:raw+value",
        url.query().unwrap()
    );
    let response = UiServer::new(destination.clone())
        .router()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("host", "127.0.0.1:42222")
                .header("sec-fetch-dest", "document")
                .header("sec-fetch-mode", "navigate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let html = String::from_utf8(
        to_bytes(response.into_body(), 2 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        !html.contains("epixnet_peers"),
        "bootstrap addresses cannot reach iframe query string"
    );
    assert!(
        html.contains("view=a%2Fb") && html.contains("Topic:raw+value"),
        "unrelated router bytes are preserved"
    );
    let actual: Vec<_> = destination
        .connectable_peers(&address, 100)
        .await
        .into_iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(
        actual.len(),
        2,
        "only the two public endpoints are imported: {actual:?}"
    );
    assert!(actual.iter().all(|p| endpoints.contains(p)));
    let restarted = AppState::with_data_dir("receiver-restart", destination_dir.path());
    restarted.restore_xites().await;
    assert_eq!(
        restarted.peer_counts(&address).await.total,
        2,
        "accepted bootstrap peers survive restart"
    );
}

#[tokio::test]
async fn imports_are_bounded_and_respect_disabled_networks_and_gateway_policy() {
    let (_root, state, address) = fixture().await;
    let mut endpoints: Vec<_> = (1..=30).map(|n| format!("8.8.4.{n}:26552")).collect();
    endpoints.insert(0, format!("{}.onion:26552", "a".repeat(56)));
    assert_eq!(
        state.import_sidebar_peers(&address, &endpoints).await,
        19,
        "disabled onion and inputs after the cap are ignored"
    );
    assert_eq!(state.peer_counts(&address).await.total, 19);
    state.config_set("ui_restrict", json!(true)).await;
    assert_eq!(
        state
            .import_sidebar_peers(&address, &["1.1.1.1:26552".into()])
            .await,
        0
    );
    assert_eq!(
        state
            .import_sidebar_peers("missing", &["1.1.1.1:26552".into()])
            .await,
        0
    );
}

#[tokio::test]
async fn outgoing_links_do_not_use_undialable_fallback_peers() {
    let (_root, state, address) = fixture().await;
    let onion = format!("{}.onion:26552", "b".repeat(56));
    state.add_peer_endpoint(&address, &onion).await.unwrap();
    // General peer selection may return a recovery candidate on an unavailable
    // network. Sharing must still apply the active transport filter.
    assert!(!state
        .sidebar_peer_share_url(&address)
        .await
        .contains("epixnet_peers"));
    state.set_tor_status(true, "OK").await;
    state.set_fileserver_port(26552).await;
    state.set_onion_address(&"a".repeat(56)).await;
    let url = reqwest::Url::parse(&state.sidebar_peer_share_url(&address).await).unwrap();
    let peers = url
        .query_pairs()
        .find(|(key, _)| key == "epixnet_peers")
        .unwrap()
        .1;
    assert!(peers.contains(&onion));
    assert!(peers.contains(&format!("{}.onion:26552", "a".repeat(56))));
}

#[tokio::test]
async fn globe_self_marker_uses_real_geoip_and_respects_overlay_privacy() {
    let (root, state, address) = fixture().await;
    let compressed = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../epix-server/assets/dbip-city-lite.mmdb.gz"),
    )
    .unwrap();
    let geoip = epix_ui::geoip::GeoIp::ensure(&compressed, root.path().join("test.mmdb")).unwrap();
    let location = geoip
        .locate("1.1.1.1".parse().unwrap())
        .expect("bundled GeoIP covers the test self address");
    state.set_geoip(geoip).await;
    state.set_port_status(true, Some("1.1.1.1".into())).await;
    assert_eq!(
        state.peer_globe_data(&address).await,
        vec![location.lat, location.lon, -0.135]
    );
    state.set_tor_status(true, "Always").await;
    assert!(
        state.peer_globe_data(&address).await.is_empty(),
        "Tor-only mode does not reveal the clearnet self location"
    );
}
