use super::{authenticate, query};
use serde_json::{json, Value};
use std::io::Write as _;

#[tokio::test]
async fn unavailable_node_preserves_trusted_local_routing_policy() {
    let directory = tempfile::tempdir().unwrap();
    let settings = crate::Settings::new(directory.path());
    for enabled in [true, false] {
        settings.set_tor_clearnet(enabled);
        let response = super::handle(&settings, 1).await;
        assert_eq!(response["serving"], false);
        assert_eq!(response["tor_clearnet"], enabled);
        assert!(response.get("tor_socks_port").is_none());
        assert!(response.get("tor_status").is_none());
    }
}

fn signed(token: &str, nonce: &str, status: u16, payload: Value) -> Value {
    let payload = payload.to_string();
    let mac = epix_node::nmh_response_mac(
        token,
        nonce,
        epix_node::NMH_STATUS_PATH,
        status,
        Some(&payload),
        None,
    )
    .unwrap();
    json!({"nonce": nonce, "payload": payload, "mac": mac})
}

#[test]
fn authentication_binds_nonce_http_code_and_exact_routing_payload() {
    let token = "66".repeat(32);
    let nonce = "77".repeat(32);
    let body = signed(
        &token,
        &nonce,
        200,
        json!({"serving": true, "tor_socks_port": 42325}),
    );
    assert_eq!(
        authenticate(&token, &nonce, 200, &body).unwrap()["tor_socks_port"],
        42325
    );
    assert!(authenticate(&"55".repeat(32), &nonce, 200, &body).is_err());
    assert!(authenticate(&token, &"88".repeat(32), 200, &body).is_err());
    assert!(authenticate(&token, &nonce, 503, &body).is_err());
    let mut changed = body.clone();
    changed["payload"] = json!("{\"serving\":true,\"tor_socks_port\":43111}");
    assert!(authenticate(&token, &nonce, 200, &changed).is_err());
}

#[test]
fn unavailable_or_invalid_endpoints_never_become_routing_metadata() {
    let token = "66".repeat(32);
    let nonce = "77".repeat(32);
    for port in [
        Value::Null,
        json!(0),
        json!(65536),
        json!(-1),
        json!("42322"),
    ] {
        let body = signed(
            &token,
            &nonce,
            200,
            json!({"serving": true, "tor_socks_port": port}),
        );
        assert!(authenticate(&token, &nonce, 200, &body).is_err());
    }
    let body = signed(
        &token,
        &nonce,
        503,
        json!({"serving": false, "tor_socks_port": null}),
    );
    assert!(authenticate(&token, &nonce, 503, &body).is_err());
}

async fn respond(
    make_response: impl FnOnce(&Value) -> String + Send + 'static,
) -> (Result<Value, String>, Vec<u8>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::task::spawn_blocking(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = crate::tests::read_http_request(&mut stream);
        let index = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let parsed = serde_json::from_slice(&request[index..]).unwrap();
        stream.write_all(make_response(&parsed).as_bytes()).unwrap();
        request
    });
    let result = query(port, &"66".repeat(32)).await;
    (result, task.await.unwrap())
}

fn http(body: Value) -> String {
    let body = body.to_string();
    format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
}

#[tokio::test]
async fn stale_listener_cannot_supply_port_or_receive_secret() {
    let (result, request) = respond(|request| http(json!({
        "nonce": request["nonce"], "payload": "{\"serving\":true,\"tor_socks_port\":43111}", "mac": "00".repeat(32)
    }))).await;
    assert!(result.unwrap_err().contains("authentication failed"));
    assert!(!String::from_utf8(request)
        .unwrap()
        .contains(&"66".repeat(32)));
}

#[tokio::test]
async fn actual_authenticated_response_supplies_its_selected_port() {
    let (result, _) = respond(|request| {
        http(signed(
            &"66".repeat(32),
            request["nonce"].as_str().unwrap(),
            200,
            json!({"serving": true, "tor_socks_port": 42329}),
        ))
    })
    .await;
    assert_eq!(result.unwrap()["tor_socks_port"], 42329);
}

#[tokio::test]
async fn oversized_response_is_rejected_before_body_arrives() {
    let (result, _) = respond(|_| {
        "HTTP/1.1 200 OK\r\ncontent-length: 99999999\r\nconnection: close\r\n\r\n".into()
    })
    .await;
    assert!(result.unwrap_err().contains("too large"));
}

#[tokio::test]
async fn status_requests_never_follow_a_stale_listener_redirect() {
    let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    other.set_nonblocking(true).unwrap();
    let port = other.local_addr().unwrap().port();
    let (result, _) = respond(move |_| format!("HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{port}/trap\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")).await;
    assert!(result.is_err());
    assert_eq!(
        other.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
