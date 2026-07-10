//! Probe BitTorrent trackers with a real announce for the dashboard xite and
//! report which ones answer with peers - used to pick the built-in defaults.
//!
//!     cargo run -p epix-discovery --example bt_probe
//!     cargo run -p epix-discovery --example bt_probe -- udp://host:port/announce ...

const DASHBOARD: &str = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";

/// Well-known public trackers (hostname form, stable across IP churn) plus
/// whatever is passed on the command line.
const CANDIDATES: &[&str] = &[
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.tracker.cl:1337/announce",
    "udp://open.stealth.si:80/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://explodie.org:6969/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://tracker.openbittorrent.com:6969/announce",
    "udp://opentracker.io:6969/announce",
    "udp://tracker.dler.org:6969/announce",
    "http://tracker.opentrackr.org:1337/announce",
    "http://open.tracker.cl:1337/announce",
];

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let list: Vec<String> = if args.is_empty() {
        CANDIDATES.iter().map(|s| s.to_string()).collect()
    } else {
        args
    };
    let mut tasks = tokio::task::JoinSet::new();
    for url in list {
        tasks.spawn(async move {
            // Two-phase: register with one port, then re-announce with another
            // - a live tracker hands the first registration back, so "alive
            // with zero other peers" and "dead" are distinguishable.
            let first = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                epix_discovery::announce_bittorrent(&url, DASHBOARD, 26552),
            )
            .await
            .unwrap_or_default();
            let second = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                epix_discovery::announce_bittorrent(&url, DASHBOARD, 26553),
            )
            .await
            .unwrap_or_default();
            (url, first, second)
        });
    }
    let mut up = 0;
    while let Some(Ok((url, first, second))) = tasks.join_next().await {
        let alive = !first.is_empty() || !second.is_empty();
        if alive {
            up += 1;
        }
        let mark = if alive { "OK  " } else { "dead" };
        let all: Vec<String> = second.iter().chain(first.iter()).map(|p| p.to_string()).collect();
        println!("{mark} {url}  ({} peers: {})", all.len(), all.join(", "));
    }
    println!("--- {up} responding");
}
