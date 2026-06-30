//! Clone a xite's files through the worker: a reproducible mock peer, plus an
//! `#[ignore]`d test that clones the Dashboard from the live network.

use epix_core::{Address, PeerAddr};
use epix_protocol::msg::{read_msg, send_msg, vget, vmap};
use epix_protocol::Connection;
use epix_transport::{TcpTransport, Transport};
use epix_xite::{Xite, XiteStorage};
use rmpv::Value;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;

const DASH: &str = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";
const LIVE_TRACKER: &str = "145.223.69.23:26959";

/// Mock peer that serves a fixed set of files by `inner_path`.
async fn spawn_mock_peer(files: HashMap<String, Vec<u8>>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else { break };
            let files = files.clone();
            tokio::spawn(async move {
                let mut stream: epix_transport::PeerStream = Box::pin(sock);
                let mut buf = Vec::new();
                while let Ok(req) = read_msg(&mut stream, &mut buf).await {
                    let cmd = vget(&req, "cmd").and_then(|v| v.as_str()).unwrap_or("");
                    let to = vget(&req, "req_id").and_then(|v| v.as_i64()).unwrap_or(0);
                    let resp = match cmd {
                        "handshake" => vmap(vec![
                            ("cmd", Value::from("response")),
                            ("to", Value::from(to)),
                            ("version", Value::from("Mock")),
                            ("protocol", Value::from("v2")),
                            ("rev", Value::from(8192i64)),
                        ]),
                        "getFile" => {
                            let inner = vget(&req, "params")
                                .and_then(|p| vget(p, "inner_path"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            match files.get(inner) {
                                Some(bytes) => vmap(vec![
                                    ("cmd", Value::from("response")),
                                    ("to", Value::from(to)),
                                    ("body", Value::Binary(bytes.clone())),
                                    ("size", Value::from(bytes.len() as i64)),
                                    ("location", Value::from(bytes.len() as i64)),
                                ]),
                                None => vmap(vec![
                                    ("cmd", Value::from("response")),
                                    ("to", Value::from(to)),
                                    ("error", Value::from("File not found")),
                                ]),
                            }
                        }
                        _ => vmap(vec![
                            ("cmd", Value::from("response")),
                            ("to", Value::from(to)),
                            ("error", Value::from("Unknown command")),
                        ]),
                    };
                    if send_msg(&mut stream, &resp).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn clones_a_xite_from_a_peer() {
    let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
    let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();
    let a = b"hello from file a".to_vec();
    let b = b"and this is file b, in a subdir".to_vec();

    let mut content = json!({
        "address": address,
        "inner_path": "content.json",
        "modified": 1777992697,
        "files": {
            "a.txt": { "size": a.len(), "sha512": XiteStorage::hash_bytes(&a) },
            "dir/b.txt": { "size": b.len(), "sha512": XiteStorage::hash_bytes(&b) },
        },
    });
    epix_content::sign(&mut content, priv_hex).unwrap();
    let content_bytes = serde_json::to_vec(&content).unwrap();

    let mut files = HashMap::new();
    files.insert("content.json".to_string(), content_bytes.clone());
    files.insert("a.txt".to_string(), a.clone());
    files.insert("dir/b.txt".to_string(), b.clone());
    let peer = spawn_mock_peer(files).await;

    let dir = tempfile::tempdir().unwrap();
    let mut xite = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
    xite.set_content(&content_bytes).unwrap();
    assert_eq!(xite.files_needed().len(), 2);

    let report = epix_worker::sync_files(
        &xite,
        &[PeerAddr::Ip(peer)],
        Arc::new(TcpTransport),
        4,
    )
    .await
    .unwrap();

    assert_eq!(report.downloaded, 2);
    assert!(report.failed.is_empty(), "failed: {:?}", report.failed);
    assert_eq!(xite.storage.read("a.txt").unwrap(), a);
    assert_eq!(xite.storage.read("dir/b.txt").unwrap(), b);
    assert!(xite.files_needed().is_empty(), "all files verified on disk");
}

/// Capstone: clone the whole Dashboard xite from the live network.
/// `cargo test -p epix-worker -- --ignored live_clone --nocapture`
#[tokio::test]
#[ignore]
async fn live_clone_dashboard_from_network() {
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);

    // 1. Discover peers via the Epix tracker.
    let peers = epix_xite::announce(
        transport.as_ref(),
        DASH,
        &[PeerAddr::parse(LIVE_TRACKER).unwrap()],
        0,
    )
    .await;
    println!("discovered {} peers", peers.len());
    assert!(!peers.is_empty());

    // 2. Fetch + verify content.json from some peer.
    let dir = tempfile::tempdir().unwrap();
    let mut xite = Xite::new(Address::parse(DASH).unwrap(), XiteStorage::new(dir.path()));
    let mut got = false;
    for peer in &peers {
        if let Ok(mut conn) = Connection::connect(transport.as_ref(), peer).await {
            if conn.handshake().await.is_ok() {
                if let Ok(bytes) = conn.get_file(DASH, "content.json").await {
                    if xite.set_content(&bytes).is_ok() {
                        got = true;
                        break;
                    }
                }
            }
        }
    }
    assert!(got, "could not fetch + verify content.json from any peer");
    let to_sync = xite.files_needed().len();
    println!("content.json verified; syncing {to_sync} files…");

    // 3. Download every file in parallel, verifying each hash.
    let report = epix_worker::sync_files(&xite, &peers, transport.clone(), 8)
        .await
        .unwrap();
    println!(
        "synced {} files ({} bytes); {} failed",
        report.downloaded, report.bytes, report.failed.len()
    );
    assert!(report.downloaded > 0);
    assert!(report.failed.is_empty(), "failed: {:?}", report.failed);
    assert!(xite.files_needed().is_empty(), "entire xite cloned + verified");
}
