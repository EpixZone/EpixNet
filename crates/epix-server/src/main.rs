//! Runnable Epix node: discover peers, clone a xite from the live EpixNet
//! network, and serve it in a browser through the UI server.

use epix_core::{Address, PeerAddr};
use epix_protocol::Connection;
use epix_transport::{TcpTransport, Transport};
use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::{Xite, XiteStorage};
use std::sync::Arc;

const DASH: &str = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";
const TRACKER: &str = "145.223.69.23:26959";
const BIND: &str = "127.0.0.1:43110";

#[tokio::main]
async fn main() {
    let address = std::env::args().nth(1).unwrap_or_else(|| DASH.to_string());
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);

    let data_dir = std::env::temp_dir().join("epix-data").join(&address);
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let mut xite = Xite::new(
        Address::parse(address.clone()).expect("valid address"),
        XiteStorage::new(&data_dir),
    );

    // 0. If already cloned + verified, skip the network fetch (fast restarts).
    if xite.load_content().unwrap_or(false) && xite.files_needed().is_empty() {
        println!("· {address} already cloned + verified — serving from cache");
        serve(address, data_dir, xite.content.clone()).await;
        return;
    }

    // 1. Discover peers via the Epix tracker.
    println!("· discovering peers for {address} …");
    let peers = epix_xite::announce(
        transport.as_ref(),
        &address,
        &[PeerAddr::parse(TRACKER).unwrap()],
        0,
    )
    .await;
    println!("  found {} peers", peers.len());
    if peers.is_empty() {
        eprintln!("no peers found — is the network reachable?");
        std::process::exit(1);
    }

    // 2. Fetch + verify content.json.
    let mut ok = false;
    for peer in &peers {
        if let Ok(mut conn) = Connection::connect(transport.as_ref(), peer).await {
            if conn.handshake().await.is_ok() {
                if let Ok(bytes) = conn.get_file(&address, "content.json").await {
                    if xite.set_content(&bytes).is_ok() {
                        ok = true;
                        break;
                    }
                }
            }
        }
    }
    if !ok {
        eprintln!("could not fetch + verify content.json from any peer");
        std::process::exit(1);
    }

    // 3. Sync every file, verifying each hash.
    let needed = xite.files_needed().len();
    println!("· content.json verified — downloading {needed} files …");
    let report = epix_worker::sync_files(&xite, &peers, transport.clone(), 8)
        .await
        .expect("sync");
    println!(
        "  downloaded {} files ({} bytes); {} failed",
        report.downloaded,
        report.bytes,
        report.failed.len()
    );

    // 4. Serve it.
    serve(address, data_dir, xite.content.clone()).await;
}

async fn serve(address: String, data_dir: std::path::PathBuf, content: Option<serde_json::Value>) {
    let state = AppState::new(env!("CARGO_PKG_VERSION"));
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: XiteStorage::new(&data_dir),
                content,
            },
        )
        .await;

    let bind: std::net::SocketAddr = BIND.parse().unwrap();
    println!("\n┌──────────────────────────────────────────────");
    println!("│ Epix node serving a xite cloned from the network");
    println!("│ Open in your browser:");
    println!("│   http://{BIND}/{address}/");
    println!("└──────────────────────────────────────────────\n");
    UiServer::new(state).serve(bind).await.expect("server");
}
