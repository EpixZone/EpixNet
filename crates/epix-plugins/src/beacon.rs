//! Beacon - announcer discovery. Keeps the node's announcer (tracker) set
//! alive without anyone shipping a list: peers exchange their working
//! announcers over the `getTrackers` wire request (EpixNet's AnnounceShare),
//! Beacon remembers them in `trackers.json` at the data root - the same file
//! and schema the Python client uses, so an upgrade carries the list over -
//! health-checks them against announce results, prunes the dead, and folds
//! the live set into every announce pass.
//!
//! A community can still publish a curated list on a xite (the old Syncronite
//! bootstrap): point the `trackers_xite` config at
//! `<address>/<inner_path>` (e.g.
//! `epix1syncas…/cache/1/Syncronite.html`) and Beacon keeps that xite synced
//! and folds its list in each cycle. Optional - peer exchange is the default.

use epix_core::PeerAddr;
use epix_plugin::Plugin;
use epix_protocol::Connection;
use epix_ui::AppState;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

/// Discovery cadence (EpixNet's AnnounceShare discovers every 5 minutes).
const REFRESH: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// Stop asking peers for more once this many announcers work
/// (EpixNet's `--working-shared-trackers-limit`).
const WORKING_LIMIT: usize = 5;
/// How many peers to ask per discovery pass.
const DISCOVER_PEERS: usize = 5;

pub struct BeaconPlugin;

impl Plugin for BeaconPlugin {
    fn name(&self) -> &str {
        "Beacon"
    }

    fn start(&self, state: &Arc<AppState>) {
        let state = state.clone();
        tokio::spawn(async move {
            let Some(path) = state.data_root_path().map(|r| r.join("trackers.json")) else {
                return; // in-memory node: nothing to persist or announce for
            };
            let mut book = TrackerBook::load(&path);
            loop {
                if state.plugin_enabled("Beacon").await {
                    run_cycle(&state, &mut book, &path).await;
                } else {
                    state.set_extra_trackers(Vec::new()).await;
                }
                tokio::time::sleep(REFRESH).await;
            }
        });
    }
}

/// One Beacon pass: fold announce results into the book, discover more
/// announcers from peers when short, fold in the optional xite list, and hand
/// the live set to the announcer.
async fn run_cycle(state: &Arc<AppState>, book: &mut TrackerBook, path: &PathBuf) {
    book.absorb_stats(&state.announcer_stats().await);

    if book.working().len() < WORKING_LIMIT {
        discover_from_peers(state, book).await;
    }

    // The optional community list published on a xite.
    if let Some(spec) = state
        .config_get("trackers_xite")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.trim().is_empty())
    {
        for addr in load_xite_list(state, spec.trim()).await {
            book.found(&format!("epix://{addr}"));
        }
    }

    let live = book.addresses();
    let prev = state.extra_trackers().await;
    if live != prev {
        state
            .log("INFO", format!("Beacon: {} announcer(s) live ({} working)", live.len(), book.working().len()))
            .await;
    }
    state.set_extra_trackers(live).await;
    book.save(path);
}

/// Ask a few connected/known peers for their working announcers - one new
/// entry accepted per peer, like EpixNet, so a single peer can't flood the
/// book.
async fn discover_from_peers(state: &Arc<AppState>, book: &mut TrackerBook) {
    let Some(transport) = state.transport().await else { return };
    let mut peers: Vec<PeerAddr> = Vec::new();
    for address in state.xite_addresses().await {
        for p in state.connectable_peers(&address, 3).await {
            if !peers.contains(&p) {
                peers.push(p);
            }
        }
        if peers.len() >= DISCOVER_PEERS {
            break;
        }
    }
    for peer in peers.into_iter().take(DISCOVER_PEERS) {
        let ask = async {
            let mut conn = Connection::connect(transport.as_ref(), &peer).await.ok()?;
            conn.handshake().await.ok()?;
            conn.get_trackers().await.ok()
        };
        let Ok(Some(reply)) = tokio::time::timeout(std::time::Duration::from_secs(10), ask).await
        else {
            continue;
        };
        let Some(list) = epix_protocol::vget(&reply, "trackers").and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in list {
            let Some(s) = entry.as_str() else { continue };
            if parse_tracker_line(s).is_some() && book.found(s) {
                break; // one new announcer per peer per pass
            }
        }
    }
}

/// Read + parse a tracker list published on a xite (`<address>/<inner_path>`),
/// cloning the xite on demand the first time so the list keeps syncing.
async fn load_xite_list(state: &Arc<AppState>, spec: &str) -> Vec<PeerAddr> {
    let Some((address, inner_path)) = spec.split_once('/') else { return Vec::new() };
    if !state.has_xite(address).await {
        state.ensure_xite(address).await;
    }
    let Some(bytes) = state.read_file(address, inner_path).await else { return Vec::new() };
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&bytes).lines() {
        if let Some(addr) = parse_tracker_line(line) {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

/// Parse one `epix://host:port` line into a [`PeerAddr`]. Tolerates published
/// quirks: unbracketed IPv6 hosts and stray spaces. Entries on transports we
/// don't dial (i2p) are skipped.
fn parse_tracker_line(line: &str) -> Option<PeerAddr> {
    let s = line.trim();
    let s = s.strip_prefix("epix://").unwrap_or(s);
    let s = s.replace(' ', "");
    if s.is_empty() || s.contains(".i2p") {
        return None;
    }
    if let Ok(addr) = PeerAddr::parse(&s) {
        return Some(addr);
    }
    // A bare IPv6 host: the last colon separates the port; bracket the rest.
    let (host, port) = s.rsplit_once(':')?;
    if host.contains(':') && !host.starts_with('[') {
        return PeerAddr::parse(&format!("[{host}]:{port}")).ok();
    }
    None
}

/// The persistent announcer book: EpixNet AnnounceShare's `trackers.json`
/// (`{"shared": {"epix://host:port": {time_added, time_success, num_error,
/// …}}}`), read and written in place so a Python install's book carries over.
pub struct TrackerBook {
    content: Value,
    /// Announce-stats counters already folded in, so each cycle only judges
    /// the announces made since the last one.
    seen: std::collections::HashMap<String, (i64, i64)>,
}

impl TrackerBook {
    pub fn load(path: &PathBuf) -> Self {
        let content = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(|v| v.is_object())
            .unwrap_or_else(|| json!({}));
        Self { content, seen: Default::default() }
    }

    pub fn save(&self, path: &PathBuf) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&self.content) {
            let _ = std::fs::write(path, bytes);
        }
    }

    fn shared(&mut self) -> &mut serde_json::Map<String, Value> {
        let obj = self.content.as_object_mut().expect("book is an object");
        obj.entry("shared").or_insert_with(|| json!({}));
        obj.get_mut("shared").and_then(|v| v.as_object_mut()).expect("shared is an object")
    }

    /// Record an announcer (an `epix://host:port` string). True if new.
    pub fn found(&mut self, address: &str) -> bool {
        if parse_tracker_line(address).is_none() {
            return false;
        }
        let now = now_secs();
        let shared = self.shared();
        let new = !shared.contains_key(address);
        let entry = shared.entry(address.to_string()).or_insert_with(|| {
            json!({ "time_added": now, "time_success": 0, "latency": 99.0, "num_error": 0, "my": false })
        });
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("time_found".into(), json!(now));
        }
        new
    }

    /// Fold the node's announce stats in: an announcer that added peers since
    /// the last cycle is a success; one that was tried without result is an
    /// error. Errored-out entries are pruned like EpixNet (persistently
    /// failing and no success for an hour).
    pub fn absorb_stats(&mut self, stats: &Value) {
        let Some(stats) = stats.as_object() else { return };
        let now = now_secs();
        let error_limit = if self.working().len() >= WORKING_LIMIT { 5 } else { 30 };

        // Judge each announcer's announces since the last cycle...
        let mut successes: Vec<String> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        for address in self.shared().keys().cloned().collect::<Vec<_>>() {
            let Some(stat) = stats.get(&address).and_then(|v| v.as_object()) else { continue };
            let requests = stat.get("num_request").and_then(|v| v.as_i64()).unwrap_or(0);
            let added = stat.get("num_added").and_then(|v| v.as_i64()).unwrap_or(0);
            let (seen_req, seen_added) = self.seen.get(&address).copied().unwrap_or((0, 0));
            if requests <= seen_req {
                continue; // not announced to since last cycle
            }
            self.seen.insert(address.clone(), (requests, added));
            if added > seen_added {
                successes.push(address);
            } else {
                failures.push(address);
            }
        }

        // ...then apply the verdicts.
        for address in successes {
            if let Some(obj) = self.shared().get_mut(&address).and_then(|v| v.as_object_mut()) {
                obj.insert("time_success".into(), json!(now));
                obj.insert("num_error".into(), json!(0));
            }
        }
        for address in failures {
            let mut drop = false;
            if let Some(obj) = self.shared().get_mut(&address).and_then(|v| v.as_object_mut()) {
                let errors = obj.get("num_error").and_then(|v| v.as_i64()).unwrap_or(0) + 1;
                obj.insert("num_error".into(), json!(errors));
                obj.insert("time_error".into(), json!(now));
                let last_success = obj.get("time_success").and_then(|v| v.as_f64()).unwrap_or(0.0);
                drop = errors > error_limit && last_success < (now as f64) - 3600.0;
            }
            if drop {
                self.shared().remove(&address);
                self.seen.remove(&address);
            }
        }
    }

    /// Announcers that succeeded within the last hour (EpixNet's "working").
    pub fn working(&mut self) -> Vec<String> {
        let cutoff = (now_secs() as f64) - 3600.0;
        self.shared()
            .iter()
            .filter(|(_, v)| v.get("time_success").and_then(|t| t.as_f64()).unwrap_or(0.0) > cutoff)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Every remembered announcer, parsed for the announce pass.
    pub fn addresses(&mut self) -> Vec<PeerAddr> {
        self.shared().keys().filter_map(|k| parse_tracker_line(k)).collect()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn book_reads_and_extends_the_python_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trackers.json");
        std::fs::write(
            &path,
            br#"{"shared": {"epix://145.223.69.23:26959": {"latency": 1.2, "my": false,
                "num_error": 0, "time_added": 1776060225.2, "time_success": 1782860321.6}}}"#,
        )
        .unwrap();
        let mut book = TrackerBook::load(&path.clone());
        assert_eq!(book.addresses().len(), 1, "python entry parsed");
        assert!(book.found("epix://1.2.3.4:15441"), "new announcer added");
        assert!(!book.found("epix://1.2.3.4:15441"), "duplicate not re-added");
        assert!(!book.found("garbage"), "unparseable rejected");
        book.save(&path);
        let reloaded: Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(reloaded["shared"]["epix://145.223.69.23:26959"]["latency"].is_number());
        assert!(reloaded["shared"]["epix://1.2.3.4:15441"].is_object());
    }

    #[test]
    fn stats_mark_success_and_prune_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trackers.json");
        let mut book = TrackerBook::load(&path);
        book.found("epix://1.2.3.4:1");
        book.found("epix://5.6.7.8:2");

        // 1.2.3.4 answered with peers; 5.6.7.8 was tried and gave nothing.
        let stats = json!({
            "epix://1.2.3.4:1": { "num_request": 1, "num_added": 3 },
            "epix://5.6.7.8:2": { "num_request": 1, "num_added": 0 },
        });
        book.absorb_stats(&stats);
        assert_eq!(book.working(), vec!["epix://1.2.3.4:1".to_string()]);

        // Keep failing 5.6.7.8 past the limit: it gets pruned.
        for i in 2..40 {
            book.absorb_stats(&json!({
                "epix://5.6.7.8:2": { "num_request": i, "num_added": 0 },
            }));
        }
        assert_eq!(book.addresses().len(), 1, "dead announcer pruned");
    }

    #[test]
    fn parses_the_published_line_formats() {
        assert!(matches!(
            parse_tracker_line("epix://145.223.69.23:26959"),
            Some(PeerAddr::Ip(a)) if a.port() == 26959
        ));
        assert!(matches!(
            parse_tracker_line("epix://[201:57:d3b2:6291:174e:5643:413c:6c51]:15441"),
            Some(PeerAddr::Ip(_))
        ));
        assert!(matches!(
            parse_tracker_line("epix://2a05:dfc1:4000:1e00::a:15441"),
            Some(PeerAddr::Ip(a)) if a.port() == 15441
        ));
        assert!(matches!(
            parse_tracker_line(
                "epix://5vczpwawviukvd7grfhsfxp7a6huz77hlis4fstjkym5kmf4pu7i7myd.onion:15441"
            ),
            Some(PeerAddr::Onion { port: 15441, .. })
        ));
        assert!(parse_tracker_line(
            "epix://gv54ndn4fbtj3ermicvbapilptjmts3qosf7xmxuorybsvz7bbva.i2p :15441"
        )
        .is_none());
        assert!(parse_tracker_line("").is_none());
    }
}
