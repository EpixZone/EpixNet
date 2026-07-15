//! End-to-end: a `Connection` (over `TcpTransport`) handshakes with a mock
//! EpixNet peer, downloads a signed content.json, and `epix-content` verifies
//! the signature - exercising transport + protocol + content + crypto together.
//!
//! Also includes an `#[ignore]`d test against a real local node on :20790.

use epix_core::PeerAddr;
use epix_protocol::msg::{read_msg, send_msg, vget, vmap};
use epix_protocol::Connection;
use epix_transport::TcpTransport;
use rmpv::Value;
use serde_json::json;
use tokio::net::TcpListener;

/// A minimal mock peer: answers handshake / ping / getFile(content.json).
async fn spawn_mock_peer(content_bytes: Vec<u8>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut stream: epix_transport::PeerStream = Box::pin(sock);
        let mut buf = Vec::new();
        loop {
            let req = match read_msg(&mut stream, &mut buf).await {
                Ok(v) => v,
                Err(_) => break, // client closed
            };
            let cmd = vget(&req, "cmd").and_then(|v| v.as_str()).unwrap_or("");
            let req_id = vget(&req, "req_id").and_then(|v| v.as_i64()).unwrap_or(0);
            let resp = match cmd {
                "handshake" => vmap(vec![
                    ("cmd", Value::from("response")),
                    ("to", Value::from(req_id)),
                    ("version", Value::from("MockEpix")),
                    ("rev", Value::from(8192i64)),
                    ("protocol", Value::from("v2")),
                    ("peer_id", Value::from("-Mock-000000000001")),
                    ("fileserver_port", Value::from(20790i64)),
                    ("crypt_supported", Value::Array(vec![])),
                ]),
                "ping" => vmap(vec![
                    ("cmd", Value::from("response")),
                    ("to", Value::from(req_id)),
                    ("body", Value::from("Pong!")),
                ]),
                "getFile" => vmap(vec![
                    ("cmd", Value::from("response")),
                    ("to", Value::from(req_id)),
                    ("body", Value::Binary(content_bytes.clone())),
                    ("size", Value::from(content_bytes.len() as i64)),
                    ("location", Value::from(content_bytes.len() as i64)),
                ]),
                _ => vmap(vec![
                    ("cmd", Value::from("response")),
                    ("to", Value::from(req_id)),
                    ("error", Value::from("Unknown command")),
                ]),
            };
            if send_msg(&mut stream, &resp).await.is_err() {
                break;
            }
        }
    });
    addr
}

#[tokio::test]
async fn download_and_verify_signed_content_over_loopback() {
    // A content.json signed with a throwaway key.
    let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
    let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();
    let mut content = json!({
        "address": "epix1testsite",
        "files": { "index.html": { "size": 12, "sha512": "deadbeef" } },
        "inner_path": "content.json",
        "modified": 1777992697,
        "title": "café 😀",   // exercise unicode through canonicalization
    });
    epix_content::sign(&mut content, priv_hex).unwrap();
    let body = serde_json::to_vec(&content).unwrap();

    let addr = spawn_mock_peer(body.clone()).await;

    // Client: dial → handshake → ping → getFile.
    let mut conn = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    let hs = conn.handshake().await.unwrap();
    assert_eq!(hs.version, "MockEpix");
    assert_eq!(hs.protocol, "v2");
    assert!(conn.ping().await.unwrap());

    let downloaded = conn.get_file("epix1testsite", "content.json").await.unwrap();
    assert_eq!(downloaded, body, "bytes survived the protocol intact");

    // The downloaded content's signature verifies end-to-end.
    let json: serde_json::Value = serde_json::from_slice(&downloaded).unwrap();
    assert!(
        epix_content::verify_signer(&json, &address),
        "signature on downloaded content.json must verify"
    );
}

/// Manual: run against a live local node (`epixnet.py ... --fileserver-port 20790`).
/// `cargo test -p epix-protocol -- --ignored live_node`
#[tokio::test]
#[ignore]
async fn live_node_handshake_and_getfile() {
    let xite = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
    let addr: std::net::SocketAddr = "127.0.0.1:20790".parse().unwrap();
    let mut conn = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    let hs = conn.handshake().await.unwrap();
    println!("peer: {} rev {}", hs.version, hs.rev);
    let bytes = conn.get_file(xite, "content.json").await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let signs = json.get("signs").and_then(|s| s.as_object()).unwrap();
    let signer = signs.keys().next().unwrap();
    assert!(epix_content::verify_signer(&json, signer), "live signature verifies");
    println!("downloaded {} bytes, signature by {signer} verified", bytes.len());
}
