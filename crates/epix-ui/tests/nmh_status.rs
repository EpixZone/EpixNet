use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use epix_ui::{nmh_request_mac, nmh_response_mac_valid, AppState, UiServer, NMH_STATUS_PATH};
use serde_json::{json, Value};
use tower::ServiceExt as _;

fn request(token: &str, peer: &str, scope: &str) -> Request<Body> {
    let nonce = "22".repeat(32);
    let mac = nmh_request_mac(token, &nonce, scope).unwrap();
    let mut request = Request::builder()
        .method("POST")
        .uri(NMH_STATUS_PATH)
        .header("content-type", "application/json")
        .body(Body::from(json!({"nonce": nonce, "mac": mac}).to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
    request
}

#[tokio::test]
async fn owned_endpoint_is_only_in_authenticated_status() {
    let state = AppState::new("nmh-status");
    state.set_tor_socks_port(Some(42324)).await;
    let token = state.nmh_token();
    let router = UiServer::new(state.clone()).router();
    for (credential, peer, scope) in [
        ("33".repeat(32), "127.0.0.1:30000", NMH_STATUS_PATH),
        (token.to_string(), "192.0.2.1:30000", NMH_STATUS_PATH),
        (
            token.to_string(),
            "127.0.0.1:30000",
            epix_ui::NMH_RESOLVE_PATH,
        ),
    ] {
        let result = router
            .clone()
            .oneshot(request(&credential, peer, scope))
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
    }
    let result = router
        .clone()
        .oneshot(request(token, "127.0.0.1:30000", NMH_STATUS_PATH))
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(result.into_body(), 16384).await.unwrap()).unwrap();
    let payload = body["payload"].as_str().unwrap();
    assert!(nmh_response_mac_valid(
        token,
        &"22".repeat(32),
        NMH_STATUS_PATH,
        200,
        Some(payload),
        None,
        body["mac"].as_str().unwrap()
    ));
    assert_eq!(
        serde_json::from_str::<Value>(payload).unwrap()["tor_socks_port"],
        42324
    );
    let public = router
        .oneshot(
            Request::builder()
                .uri("/EpixNet-Internal/Status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let public: Value =
        serde_json::from_slice(&to_bytes(public.into_body(), 16384).await.unwrap()).unwrap();
    assert!(public.get("tor_socks_port").is_none());
}

#[tokio::test]
async fn absent_endpoint_reports_unavailable_even_with_valid_authentication() {
    let state = AppState::new("nmh-status");
    let result = UiServer::new(state.clone())
        .router()
        .oneshot(request(
            state.nmh_token(),
            "127.0.0.1:30000",
            NMH_STATUS_PATH,
        ))
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[cfg(feature = "ui-password")]
#[tokio::test]
async fn native_status_uses_its_own_authentication_with_ui_password_enabled() {
    let state = AppState::new("nmh-password");
    state
        .config_set("ui_password", json!("disposable-qa-password"))
        .await;
    assert!(state.ui_password().await.is_some());
    state.set_tor_socks_port(Some(42324)).await;
    let router = UiServer::new(state.clone()).router();
    let authenticated = router
        .clone()
        .oneshot(request(
            state.nmh_token(),
            "127.0.0.1:30000",
            NMH_STATUS_PATH,
        ))
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
    let unauthenticated = router
        .oneshot(request(
            &"33".repeat(32),
            "127.0.0.1:30000",
            NMH_STATUS_PATH,
        ))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::FORBIDDEN);
}
