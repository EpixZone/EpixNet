//! `streamFile` answers with EpixNet's raw-stream framing: a msgpack reply
//! carrying `stream_bytes` (and no inline `body`), immediately followed by
//! that many raw file bytes on the socket - the shape a Python peer's
//! streaming download expects. `getFile` keeps the inline-body shape.

use epix_ui::fileserve::FileService;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use rmpv::Value;
use serde_json::json;
use std::io::Read;
use std::sync::Arc;

fn vmap(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

fn field<'a>(resp: &'a Value, name: &str) -> Option<&'a Value> {
    resp.as_map()?.iter().find(|(k, _)| k.as_str() == Some(name)).map(|(_, v)| v)
}

#[tokio::test]
async fn stream_file_sends_raw_bytes_after_the_reply() {
    let content = b"stream me, byte for byte".to_vec();

    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("big.bin", &content).unwrap();
    let state = AppState::new("stream-test");
    state
        .add_xite("1Stream", XiteEntry {
            storage,
            content: Some(json!({ "address": "1Stream", "files": {} })),
        })
        .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = epix_protocol::PeerServer::new(Arc::new(FileService::new(state)));
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    let expected = content.clone();
    tokio::task::spawn_blocking(move || {
        let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();

        // streamFile: msgpack reply + raw tail.
        let req = vmap(vec![
            ("cmd", Value::from("streamFile")),
            ("req_id", Value::from(1)),
            (
                "params",
                vmap(vec![
                    ("site", Value::from("1Stream")),
                    ("inner_path", Value::from("big.bin")),
                    ("location", Value::from(0)),
                ]),
            ),
        ]);
        rmpv::encode::write_value(&mut sock, &req).unwrap();
        let resp = rmpv::decode::read_value(&mut sock).unwrap();
        assert!(field(&resp, "body").is_none(), "no inline body: {resp}");
        assert_eq!(
            field(&resp, "stream_bytes").and_then(|v| v.as_i64()),
            Some(expected.len() as i64),
            "{resp}"
        );
        assert_eq!(field(&resp, "size").and_then(|v| v.as_i64()), Some(expected.len() as i64));
        let mut raw = vec![0u8; expected.len()];
        sock.read_exact(&mut raw).unwrap();
        assert_eq!(raw, expected, "raw tail is the file");

        // getFile on the same connection still answers inline.
        let req = vmap(vec![
            ("cmd", Value::from("getFile")),
            ("req_id", Value::from(2)),
            (
                "params",
                vmap(vec![
                    ("site", Value::from("1Stream")),
                    ("inner_path", Value::from("big.bin")),
                    ("location", Value::from(0)),
                ]),
            ),
        ]);
        rmpv::encode::write_value(&mut sock, &req).unwrap();
        let resp = rmpv::decode::read_value(&mut sock).unwrap();
        assert_eq!(
            field(&resp, "body").and_then(|v| v.as_slice()),
            Some(expected.as_slice()),
            "{resp}"
        );
        assert!(field(&resp, "stream_bytes").is_none());
    })
    .await
    .unwrap();
}
