//! Interop probe: sign a bumped content.json IN RUST and push it to a peer
//! (normally a Python EpixNet node) over the wire protocol. Verifies the
//! flagship interop assertion: a Python peer accepts a Rust-signed update.
//!
//! Usage:
//!   cargo run -p epix-runtime --example interop_push -- \
//!     <site_dir> <address> <privkey_wif> <peer_ip:port> [<new_index_html>]
//!
//! Reads <site_dir>/content.json, optionally rewrites index.html (rehashing
//! it into `files`), bumps `modified`, signs with the WIF key, writes both
//! files back, then connects to the peer and sends `update`. Prints the
//! peer's verbatim reply.

use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [site_dir, address, privkey, peer] = &args[..4] else {
        eprintln!("usage: interop_push <site_dir> <address> <privkey_wif> <ip:port> [<html>]");
        std::process::exit(2);
    };
    let dir = std::path::Path::new(site_dir);

    let mut content: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("content.json")).expect("content.json"))
            .expect("parse content.json");

    // Optionally change index.html and re-declare it.
    if let Some(html) = args.get(4) {
        std::fs::write(dir.join("index.html"), html).expect("write index.html");
        let hash = epix_xite::XiteStorage::hash_bytes(html.as_bytes());
        content["files"]["index.html"] =
            serde_json::json!({ "size": html.len(), "sha512": hash });
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let prev = content["modified"].as_f64().unwrap_or(0.0);
    let modified = (now as f64).max(prev + 1.0);
    if modified.fract() == 0.0 {
        content["modified"] = serde_json::json!(modified as i64);
    } else {
        content["modified"] = serde_json::json!(modified);
    }

    epix_content::sign(&mut content, privkey).expect("sign");
    let body = serde_json::to_vec(&content).expect("serialize");
    std::fs::write(dir.join("content.json"), &body).expect("write content.json");
    println!("signed content.json at modified={modified} ({} bytes)", body.len());

    let addr = epix_core::PeerAddr::parse(peer).expect("peer addr");
    let transport = epix_transport::TcpTransport;
    let mut conn =
        epix_protocol::Connection::connect(&transport, &addr).await.expect("connect");
    conn.handshake().await.expect("handshake");
    let reply = conn.update(address, "content.json", &body, modified, None, &[]).await;
    println!("peer reply: {reply:?}");
}
