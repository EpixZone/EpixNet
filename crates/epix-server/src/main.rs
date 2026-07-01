//! Runnable Epix node: discover peers, clone a xite from the live EpixNet
//! network, and serve it in a browser through the UI server.

use epix_core::{Address, PeerAddr};
use epix_protocol::Connection;
use epix_transport::{TcpTransport, Transport};
use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::{Xite, XiteStorage};
use std::sync::Arc;

const TRACKER: &str = "145.223.69.23:26959";
const BIND: &str = "127.0.0.1:43110";

#[tokio::main]
async fn main() {
    // Accept a raw `epix1…` xite address, or a `.epix` name to resolve on-chain.
    let arg = std::env::args().nth(1).unwrap_or_else(|| "dashboard.epix".to_string());
    let address = resolve_target(&arg).await;
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

/// Turn a CLI argument into a xite address: pass `epix1…` through; resolve a
/// `.epix` name (or bare label, defaulting to the `epix` tld) on the chain.
async fn resolve_target(arg: &str) -> String {
    if arg.starts_with("epix1") && !arg.contains('.') {
        return arg.to_string();
    }
    let (name, tld) = arg.rsplit_once('.').unwrap_or((arg, "epix"));
    println!("· resolving {name}.{tld} on the Epix chain …");
    let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let domain = resolver
        .resolve(name, tld)
        .await
        .unwrap_or_else(|e| panic!("could not resolve {name}.{tld}: {e}"));
    let address = domain
        .xite_address()
        .unwrap_or_else(|| panic!("{name}.{tld} has no EpixNet xite address record"))
        .to_string();
    println!("  {name}.{tld} → {address} (chain-verified)");
    address
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
