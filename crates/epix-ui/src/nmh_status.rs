//! Authenticate instance-local routing metadata without sending the secret.

use super::{nmh_request_mac_valid, nmh_response_mac, status_body, Ctx, NMH_STATUS_PATH};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

#[derive(Deserialize)]
pub(super) struct Request {
    nonce: String,
    mac: String,
}

pub(super) async fn serve(
    State(ctx): State<Ctx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<Request>,
) -> Response {
    let token = ctx.state.nmh_token();
    if !peer.ip().is_loopback()
        || !nmh_request_mac_valid(token, &request.nonce, NMH_STATUS_PATH, &request.mac)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "native-messaging authentication failed"})),
        )
            .into_response();
    }
    let mut payload = status_body(&ctx.state).await;
    let port = ctx.state.tor_socks_port().await;
    payload["tor_socks_port"] = json!(port);
    let status = if port.is_some_and(|port| port != 0) {
        StatusCode::OK
    } else {
        payload["serving"] = json!(false);
        StatusCode::SERVICE_UNAVAILABLE
    };
    let payload = payload.to_string();
    // The fixed path separates this operation from name resolution. Sign the
    // exact wire payload, not a potentially re-serialized JSON representation.
    match nmh_response_mac(
        token,
        &request.nonce,
        NMH_STATUS_PATH,
        status.as_u16(),
        Some(&payload),
        None,
    ) {
        Ok(mac) => (
            status,
            Json(json!({"nonce": request.nonce, "payload": payload, "mac": mac})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "native-messaging response authentication failed"})),
        )
            .into_response(),
    }
}
