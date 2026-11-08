use super::Settings;
use serde_json::{json, Value};

pub(super) async fn handle(settings: &Settings, ui_port: u16) -> Value {
    let result = match settings.data_root() {
        Some(root) => match epix_node::read_nmh_auth_token(root) {
            Ok(token) => query(settings.ui_endpoint(ui_port), &token).await,
            Err(error) => Err(error),
        },
        None => Err("native-messaging data root is unavailable".into()),
    };
    match result {
        Ok(mut value) => {
            value["ui_port"] = json!(ui_port);
            value["tor_clearnet"] = json!(settings.tor_clearnet());
            value
        }
        Err(error) => json!({
            "serving": false,
            "ui_port": ui_port,
            "tor_clearnet": settings.tor_clearnet(),
            "error": error,
        }),
    }
}

async fn query(endpoint: std::net::SocketAddr, token: &str) -> Result<Value, String> {
    let nonce = epix_node::new_nmh_nonce()?;
    let path = epix_node::NMH_STATUS_PATH;
    let mac = epix_node::nmh_request_mac(token, &nonce, path)?;
    // A stale listener must not redirect an authenticated request or receive
    // the secret; environment proxies must not see local metadata either.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .map_err(|error| error.to_string())?;
    let response = client
        .post(format!("http://{endpoint}{path}"))
        .json(&json!({"nonce": nonce, "mac": mac}))
        .send()
        .await
        .map_err(|error| format!("node status unavailable: {error}"))?;
    let status = response.status();
    let body = bounded_body(response).await?;
    authenticate(token, &nonce, status.as_u16(), &body)
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Value, String> {
    const MAX_BODY: usize = 16 * 1024;
    let too_large = || "node status response is too large".to_string();
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY as u64)
    {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if chunk.len() > MAX_BODY - bytes.len() {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("invalid node status: {error}"))
}

fn authenticate(token: &str, nonce: &str, status: u16, body: &Value) -> Result<Value, String> {
    let payload = body.get("payload").and_then(Value::as_str);
    let mac = body.get("mac").and_then(Value::as_str).unwrap_or_default();
    if body.get("nonce").and_then(Value::as_str) != Some(nonce)
        || !epix_node::nmh_response_mac_valid(
            token,
            nonce,
            epix_node::NMH_STATUS_PATH,
            status,
            payload,
            None,
            mac,
        )
    {
        return Err("node status response authentication failed".into());
    }
    if status != 200 {
        return Err("node routing endpoint is unavailable".into());
    }
    let value: Value = serde_json::from_str(payload.unwrap_or_default())
        .map_err(|error| format!("invalid node status payload: {error}"))?;
    let port = value.get("tor_socks_port").and_then(Value::as_u64);
    if value.get("serving").and_then(Value::as_bool) != Some(true)
        || !port.is_some_and(|port| (1..=u16::MAX as u64).contains(&port))
    {
        return Err("node status has no usable SOCKS endpoint".into());
    }
    Ok(value)
}

#[cfg(test)]
#[path = "status/tests.rs"]
mod tests;
