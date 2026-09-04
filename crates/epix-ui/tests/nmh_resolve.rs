use async_trait::async_trait;
use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use epix_ui::{
    nmh_request_mac, nmh_response_mac_valid, AppState, OnDemandResolver, ResolvedHost, UiServer,
    NMH_RESOLVE_PATH,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt as _;

struct FixedResolver;

#[async_trait]
impl OnDemandResolver for FixedResolver {
    async fn ensure(&self, _host: &str) -> Result<(), String> {
        Ok(())
    }

    async fn resolve(&self, host: &str) -> Option<ResolvedHost> {
        (host == "talk.epix")
            .then(|| ResolvedHost { address: "epix1verified".to_string(), verified: true })
    }
}

fn request_from(token: Option<&str>, peer: &str) -> Request<Body> {
    let name = "talk.epix";
    let nonce = "44".repeat(32);
    let mac = token
        .and_then(|token| nmh_request_mac(token, &nonce, name).ok())
        .unwrap_or_default();
    let builder = Request::builder()
        .method("POST")
        .uri(NMH_RESOLVE_PATH)
        .header("content-type", "application/json");
    let mut request = builder
        .body(Body::from(
            json!({ "name": name, "nonce": nonce, "mac": mac }).to_string(),
        ))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
    request
}

fn request(token: Option<&str>) -> Request<Body> {
    request_from(token, "127.0.0.1:49152")
}

#[tokio::test]
async fn native_resolve_requires_private_token_and_uses_node_resolver() {
    let state = AppState::new("test");
    state.set_on_demand(Arc::new(FixedResolver)).await;
    let router = UiServer::new(state.clone()).router();

    let missing = router.clone().oneshot(request(None)).await.unwrap();
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);

    let ui_token = state.ui_csrf_token().to_string();
    let wrong = router
        .clone()
        .oneshot(request(Some(&ui_token)))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

    let token = state.nmh_token().to_string();
    let remote = router
        .clone()
        .oneshot(request_from(Some(&token), "192.0.2.10:49152"))
        .await
        .unwrap();
    assert_eq!(remote.status(), StatusCode::FORBIDDEN);

    let response = router.oneshot(request(Some(&token))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["address"], "epix1verified");
    assert!(nmh_response_mac_valid(
        &token,
        &"44".repeat(32),
        "talk.epix",
        200,
        Some("epix1verified"),
        None,
        body["mac"].as_str().unwrap(),
    ));
}

#[tokio::test]
async fn served_endpoint_receives_loopback_connection_info() {
    let state = AppState::new("test");
    state.set_on_demand(Arc::new(FixedResolver)).await;
    let token = state.nmh_token().to_string();
    let nonce = "55".repeat(32);
    let request_mac = nmh_request_mac(&token, &nonce, "talk.epix").unwrap();
    let server = UiServer::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(server.serve_on(listener));

    let response = reqwest::Client::new()
        .post(format!("http://{address}{NMH_RESOLVE_PATH}"))
        .header("content-type", "application/json")
        .body(json!({ "name": "talk.epix", "nonce": nonce, "mac": request_mac }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(body["address"], "epix1verified");
    assert!(nmh_response_mac_valid(
        &token,
        &"55".repeat(32),
        "talk.epix",
        200,
        Some("epix1verified"),
        None,
        body["mac"].as_str().unwrap(),
    ));

    task.abort();
}
