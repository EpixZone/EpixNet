//! Beacon - announcer discovery. Keeps the node's announcer (tracker) set
//! alive without anyone shipping a list: the book starts from the built-in
//! bootstrap defaults ([`epix_core::DEFAULT_TRACKERS`]), peers exchange their
//! working announcers over the `getTrackers` wire request (EpixNet's
//! AnnounceShare), Beacon remembers them in `trackers.json` at the data root -
//! the same file and schema the Python client uses, so an upgrade carries the
//! list over (legacy `epix://` keys are re-spelled to the transport-explicit
//! form on load) - health-checks them against announce results, prunes the
//! dead, and folds the live set into every announce pass.
//!
//! A community can still publish a curated list on a xite (the old Syncronite
//! bootstrap): point the `trackers_xite` config at
//! `<address>/<inner_path>` (e.g.
//! `epix1syncas…/cache/1/Syncronite.html`) and Beacon keeps that xite synced
//! and folds its list in each cycle. Optional - peer exchange is the default.
//!
//! And when this node OWNS that xite (its private key is stored), Beacon
//! maintains the published list itself: every [`PUBLISH_INTERVAL`] it writes
//! the currently-working announcers to the configured file (as JSON grouped
//! by kind: `{"updated": …, "epix": ["tcp://…", "onion://…"],
//! "bittorrent": ["udp://…"]}`), signs, and publishes - the job the old
//! Syncronite setup did with a python script on a cron, now built in.
//! Consuming accepts that JSON, a flat `{"trackers": […]}`/bare array, and
//! the legacy line format.

use epix_core::PeerAddr;
use epix_plugin::Plugin;
use epix_discovery::Tracker;
use epix_protocol::Connection;
use epix_ui::AppState;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

/// Discovery cadence (EpixNet's AnnounceShare discovers every 5 minutes).
const REFRESH: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// How often an owned tracker-list xite is re-published (when changed). The
/// old Syncronite cron ran its updater hourly.
const PUBLISH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
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
            // Seed the book with the bootstrap defaults so they are
            // health-tracked (and pruned/revived) like every discovered
            // announcer. found() keeps existing entries' stats and stores
            // the canonical form (transport-explicit for Epix announcers,
            // BitTorrent URLs as-is).
            for t in epix_core::DEFAULT_TRACKERS {
                if let Some(tracker) = Tracker::parse(t) {
                    book.found(&tracker.to_string());
                }
            }
            let mut last_publish = std::time::Instant::now() - PUBLISH_INTERVAL;
            loop {
                if state.plugin_enabled("Beacon").await {
                    run_cycle(&state, &mut book, &path).await;
                    if last_publish.elapsed() >= PUBLISH_INTERVAL
                        && publish_owned_list(&state, &mut book).await
                    {
                        last_publish = std::time::Instant::now();
                    }
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
        for tracker in load_xite_list(state, spec.trim()).await {
            book.found(&tracker.to_string());
        }
    }

    // I2P trackers (`.b32.i2p`) are only reachable when I2P is enabled; drop
    // them from the announce set otherwise so they don't pile up as failures.
    let i2p_enabled = state
        .config_get("i2p")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .map(|m| m != "disable" && !m.is_empty())
        .unwrap_or(false);
    let live: Vec<Tracker> = book
        .addresses()
        .into_iter()
        .filter(|t| i2p_enabled || !matches!(t, Tracker::Epix(PeerAddr::I2p { .. })))
        .collect();
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

/// Maintain the tracker list this node publishes: when `trackers_xite` names
/// a xite whose private key we hold, write the currently-working announcers
/// to the configured file, sign, and publish - the old Syncronite cron job,
/// built in. Returns true when the preconditions held (configured + owned +
/// something to publish), so the caller only re-runs it each
/// [`PUBLISH_INTERVAL`]; the write/sign/publish is skipped when the list is
/// unchanged.
async fn publish_owned_list(state: &Arc<AppState>, book: &mut TrackerBook) -> bool {
    let Some(spec) = state
        .config_get("trackers_xite")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.trim().is_empty())
    else {
        return false;
    };
    let Some((address, inner_path)) = spec.trim().split_once('/') else { return false };
    // Consume-only unless this node holds the xite's signing key.
    let Some(key) = state.site_privatekey(address).await else { return false };

    let (epix, bt) = canonical_groups(&book.working());
    if epix.is_empty() && bt.is_empty() {
        // Nothing verified this hour: keep the last published list rather
        // than wiping it (a restart or offline stretch shouldn't empty the
        // community's bootstrap).
        return false;
    }
    // Compare entries, not bytes: the JSON body carries an `updated` stamp
    // that must not force an hourly re-sign of an unchanged list.
    let flat: Vec<String> = epix.iter().chain(bt.iter()).cloned().collect();
    let current = state.read_file(address, inner_path).await;
    if current.as_deref().map(list_entries) == Some(flat.clone()) {
        // Up to date - re-checked next interval. Logged (at most hourly) so
        // an operator can see the maintenance ran.
        state
            .log(
                "INFO",
                format!(
                    "Beacon: published list at {spec} is up to date ({} announcer(s))",
                    flat.len()
                ),
            )
            .await;
        return true;
    }
    let body = render_list(&epix, &bt);
    if let Err(e) = state.write_file(address, inner_path, body.as_bytes()).await {
        state.log("WARNING", format!("Beacon: could not write {spec}: {e}")).await;
        return true;
    }
    if let Err(e) = state.sign_xite(address, &key).await {
        state.log("WARNING", format!("Beacon: could not sign {address}: {e}")).await;
        return true;
    }
    let peers = state.publish(address, "content.json", None).await.unwrap_or(0);
    state
        .log(
            "INFO",
            format!(
                "Beacon: published {} working announcer(s) to {spec} ({peers} peer(s) notified)",
                flat.len()
            ),
        )
        .await;
    true
}

/// Read + parse a tracker list published on a xite (`<address>/<inner_path>`),
/// cloning the xite on demand the first time so the list keeps syncing.
async fn load_xite_list(state: &Arc<AppState>, spec: &str) -> Vec<Tracker> {
    let Some((address, inner_path)) = spec.split_once('/') else { return Vec::new() };
    if !state.has_xite(address).await {
        state.ensure_xite(address).await;
    }
    let Some(bytes) = state.read_file(address, inner_path).await else { return Vec::new() };
    let mut out = Vec::new();
    for entry in list_entries(&bytes) {
        if let Some(addr) = parse_tracker_line(&entry) {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

/// The raw entries of a published tracker list, whichever format it is in: a
/// JSON document (the grouped `{"epix": […], "bittorrent": […]}` shape, a
/// flat `{"trackers": […]}`, or a bare array) or the classic line-per-entry
/// text (Syncronite.html).
fn list_entries(bytes: &[u8]) -> Vec<String> {
    if let Ok(v) = serde_json::from_slice::<Value>(bytes) {
        let mut out: Vec<String> = Vec::new();
        for key in ["epix", "bittorrent", "trackers"] {
            if let Some(arr) = v.get(key).and_then(|t| t.as_array()) {
                out.extend(arr.iter().filter_map(|e| e.as_str().map(str::to_string)));
            }
        }
        if !out.is_empty() {
            return out;
        }
        if let Some(arr) = v.as_array() {
            return arr.iter().filter_map(|e| e.as_str().map(str::to_string)).collect();
        }
    }
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Canonicalize + group a working set for publishing: entries parse through
/// [`Tracker`] (so legacy `epix://` book keys come out transport-explicit),
/// split into Epix announcers and BitTorrent trackers, each group deduplicated
/// and sorted the old updater's way (short first, then alphabetical).
fn canonical_groups(working: &[String]) -> (Vec<String>, Vec<String>) {
    let mut epix: Vec<String> = Vec::new();
    let mut bt: Vec<String> = Vec::new();
    for w in working {
        match parse_tracker_line(w) {
            Some(t @ Tracker::Epix(_)) => {
                let s = t.to_string();
                if !epix.contains(&s) {
                    epix.push(s);
                }
            }
            Some(t @ Tracker::Bt(_)) => {
                let s = t.to_string();
                if !bt.contains(&s) {
                    bt.push(s);
                }
            }
            None => {}
        }
    }
    let ord = |a: &String, b: &String| a.len().cmp(&b.len()).then(a.cmp(b));
    epix.sort_by(ord);
    bt.sort_by(ord);
    (epix, bt)
}

/// Render the published list: a JSON document with an `updated` stamp and the
/// entries grouped by kind - the type is part of the document, not inferred
/// from schemes. The automated publisher is new to the Rust network, so there
/// is exactly one output format (the legacy line format is still ACCEPTED
/// when consuming, for lists like the old Syncronite.html).
fn render_list(epix: &[String], bt: &[String]) -> String {
    let doc = json!({ "updated": now_secs(), "epix": epix, "bittorrent": bt });
    serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n"
}

/// Parse one announcer line into a [`Tracker`]: an Epix announcer
/// (transport-explicit `tcp://`/`onion://`/`i2p://`, legacy `epix://`, or a
/// bare `host:port`), or a BitTorrent tracker URL (`udp://`, `http(s)://` -
/// the old Syncronite lists are mostly these). Tolerates published quirks:
/// unbracketed IPv6 hosts and stray spaces.
fn parse_tracker_line(line: &str) -> Option<Tracker> {
    let s = line.trim();
    if s.starts_with("udp://") || s.starts_with("http://") || s.starts_with("https://") {
        return Tracker::parse(s);
    }
    // Split a declared Epix-side scheme off before host parsing, so the
    // quirk handling below applies to every spelling alike.
    let (scheme, rest) = match s.split_once("://") {
        Some((sch, rest)) if matches!(sch, "tcp" | "onion" | "i2p" | "epix") => (Some(sch), rest),
        Some(_) => return None,
        None => (None, s),
    };
    let rest = rest.replace(' ', "");
    if rest.is_empty() {
        return None;
    }
    // i2p is kept (parsed into PeerAddr::I2p); whether it's announced to is
    // gated on the I2P config at announce-set build time (run_cycle).
    let addr = if let Ok(addr) = PeerAddr::parse(&rest) {
        addr
    } else {
        // A bare IPv6 host: the last colon separates the port; bracket the rest.
        let (host, port) = rest.rsplit_once(':')?;
        if host.contains(':') && !host.starts_with('[') {
            PeerAddr::parse(&format!("[{host}]:{port}")).ok()?
        } else {
            return None;
        }
    };
    // A declared transport must agree with what the host form actually is.
    if let Some(sch) = scheme {
        if sch != "epix" && sch != addr.scheme() {
            return None;
        }
    }
    // Skip addresses that can't serve as anyone's announcer: mesh overlays we
    // have no transport for (a node only reaches Yggdrasil or Lokinet if it
    // runs that daemon, which we don't) and non-routable ranges (loopback,
    // RFC1918, CGNAT, link-local - the old community list accumulated
    // exactly this junk). Including them would just pile up as permanent
    // announce failures on the dashboard. i2p is skipped above for the same
    // reason. Public IPv4/IPv6 and Tor onion are kept - those we can reach.
    if is_unreachable(&addr) {
        return None;
    }
    Some(Tracker::Epix(addr))
}

/// True for an IP no one can dial as a shared announcer: a mesh overlay we
/// don't run - Yggdrasil (`0200::/7`) or the Lokinet/ULA range (`fc00::/7`) -
/// or a non-routable range (loopback, unspecified, RFC1918 private, CGNAT
/// `100.64/10`, link-local, IETF-reserved `192.0.0/24`, documentation,
/// broadcast).
fn is_unreachable(addr: &PeerAddr) -> bool {
    use std::net::SocketAddr;
    match addr {
        PeerAddr::Ip(SocketAddr::V4(a)) => {
            let ip = a.ip();
            let o = ip.octets();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT 100.64.0.0/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // IETF 192.0.0.0/24
        }
        PeerAddr::Ip(SocketAddr::V6(a)) => {
            let ip = a.ip();
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (first & 0xfe00) == 0x0200 // Yggdrasil 0200::/7
                || (first & 0xfe00) == 0xfc00 // ULA fc00::/7 (incl. Lokinet fd00::/8)
                || (first & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
        _ => false,
    }
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
        let mut book = Self { content, seen: Default::default() };
        // Canonicalize keys carried over from older books (a Python upgrade
        // wrote `epix://host:port`): re-key to the transport-explicit form,
        // keeping the existing stats. Duplicates collapse to one entry.
        let legacy: Vec<String> = book
            .shared()
            .keys()
            .filter(|k| {
                parse_tracker_line(k).map(|t| t.to_string() != **k).unwrap_or(false)
            })
            .cloned()
            .collect();
        for old in legacy {
            let Some(stats) = book.shared().remove(&old) else { continue };
            let Some(tracker) = parse_tracker_line(&old) else { continue };
            book.shared().entry(tracker.to_string()).or_insert(stats);
        }
        book
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

    /// Record an announcer. The stored key is the canonical form
    /// (transport-explicit for Epix announcers, the URL for BitTorrent), so
    /// one tracker cannot appear under two spellings. True if new.
    pub fn found(&mut self, address: &str) -> bool {
        let Some(tracker) = parse_tracker_line(address) else {
            return false;
        };
        let key = tracker.to_string();
        let now = now_secs();
        let shared = self.shared();
        let new = !shared.contains_key(&key);
        let entry = shared.entry(key).or_insert_with(|| {
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
            // Book keys and announce-stats keys share the canonical
            // transport-explicit form; parsing normalizes any legacy
            // `epix://` entry that predates the canonical book. (The health
            // check was once silently dead because these two disagreed -
            // keep them derived from the same Display.)
            let Some(stat_key) = parse_tracker_line(&address).map(|t| t.to_string()) else {
                continue;
            };
            let Some(stat) = stats.get(&stat_key).and_then(|v| v.as_object()) else { continue };
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
    pub fn addresses(&mut self) -> Vec<Tracker> {
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
        assert!(!book.found("epix://1.2.3.4:15441"), "legacy-spelled duplicate not re-added");
        assert!(!book.found("tcp://1.2.3.4:15441"), "canonical-spelled duplicate not re-added");
        assert!(!book.found("garbage"), "unparseable rejected");
        book.save(&path);
        let reloaded: Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        // The python-era `epix://` key is migrated to the transport-explicit
        // canonical form on load, its stats intact.
        assert!(reloaded["shared"]["tcp://145.223.69.23:26959"]["latency"].is_number());
        assert!(reloaded["shared"].get("epix://145.223.69.23:26959").is_none());
        assert!(reloaded["shared"]["tcp://1.2.3.4:15441"].is_object());
    }

    #[test]
    fn stats_mark_success_and_prune_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trackers.json");
        let mut book = TrackerBook::load(&path);
        book.found("epix://1.2.3.4:1");
        book.found("epix://5.6.7.8:2");

        // 1.2.3.4 answered with peers; 5.6.7.8 was tried and gave nothing.
        // Stats are keyed by real transport (`tcp://…`), the way
        // record_tracker writes them - the same canonical form the book now
        // keys entries with (the health check was silently dead when the two
        // disagreed).
        let stats = json!({
            "tcp://1.2.3.4:1": { "num_request": 1, "num_added": 3 },
            "tcp://5.6.7.8:2": { "num_request": 1, "num_added": 0 },
        });
        book.absorb_stats(&stats);
        assert_eq!(book.working(), vec!["tcp://1.2.3.4:1".to_string()]);

        // Keep failing 5.6.7.8 past the limit: it gets pruned.
        for i in 2..40 {
            book.absorb_stats(&json!({
                "tcp://5.6.7.8:2": { "num_request": i, "num_added": 0 },
            }));
        }
        assert_eq!(book.addresses().len(), 1, "dead announcer pruned");
    }

    #[test]
    fn parses_the_published_line_formats() {
        assert!(matches!(
            parse_tracker_line("epix://145.223.69.23:26959"),
            Some(Tracker::Epix(PeerAddr::Ip(a))) if a.port() == 26959
        ));
        // Real global IPv6 (a RIR-allocated 2a05::) is kept - reachable given
        // IPv6 connectivity.
        assert!(matches!(
            parse_tracker_line("epix://2a05:dfc1:4000:1e00::a:15441"),
            Some(Tracker::Epix(PeerAddr::Ip(a))) if a.port() == 15441
        ));
        // Tor onion is kept - we route it through arti.
        assert!(matches!(
            parse_tracker_line(
                "epix://5vczpwawviukvd7grfhsfxp7a6huz77hlis4fstjkym5kmf4pu7i7myd.onion:15441"
            ),
            Some(Tracker::Epix(PeerAddr::Onion { port: 15441, .. }))
        ));
        // Yggdrasil (0200::/7, bracketed and bare) and Lokinet (fd00::/8) have
        // no transport - always skipped.
        assert!(parse_tracker_line("epix://[201:57:d3b2:6291:174e:5643:413c:6c51]:15441").is_none());
        assert!(parse_tracker_line("epix://202:7d01:9137:6c29:afea:ce96:300e:336e:15441").is_none());
        assert!(parse_tracker_line("epix://[fd00::1]:15441").is_none());
        // Non-routable ranges no one can dial as an announcer (all of these
        // appeared in the old community list): loopback, RFC1918, CGNAT,
        // IETF-reserved 192.0.0/24, IPv6 loopback.
        assert!(parse_tracker_line("epix://127.0.0.1:15441").is_none());
        assert!(parse_tracker_line("epix://192.168.1.10:15441").is_none());
        assert!(parse_tracker_line("epix://10.0.0.5:15441").is_none());
        assert!(parse_tracker_line("epix://100.125.125.74:34899").is_none());
        assert!(parse_tracker_line("epix://192.0.0.4:20781").is_none());
        assert!(parse_tracker_line("epix://[::1]:15441").is_none());
        // i2p now parses (we have an I2P transport); whether it's announced to
        // is gated on the I2P config at announce time, not here.
        assert!(matches!(
            parse_tracker_line(
                "epix://gv54ndn4fbtj3ermicvbapilptjmts3qosf7xmxuorybsvz7bbva.i2p :15441"
            ),
            Some(Tracker::Epix(PeerAddr::I2p { .. }))
        ));
        assert!(parse_tracker_line("").is_none());
    }

    #[test]
    fn defaults_seed_the_book_and_survive_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trackers.json");
        let mut book = TrackerBook::load(&path);
        for t in epix_core::DEFAULT_TRACKERS {
            let canon = Tracker::parse(t).unwrap().to_string();
            assert!(book.found(&canon), "default {t} seeds as new");
        }
        assert_eq!(book.addresses().len(), epix_core::DEFAULT_TRACKERS.len());
        book.save(&path);

        // A reload + reseed keeps them (with stats) rather than duplicating.
        let mut book = TrackerBook::load(&path);
        for t in epix_core::DEFAULT_TRACKERS {
            let canon = Tracker::parse(t).unwrap().to_string();
            assert!(!book.found(&canon), "reseed of {t} is a no-op");
        }
        assert_eq!(book.addresses().len(), epix_core::DEFAULT_TRACKERS.len());
    }

    #[test]
    fn published_list_roundtrips_and_accepts_legacy_lines() {
        // A working set as book keys: a legacy epix:// spelling, a canonical
        // onion, and a BitTorrent URL. Canonicalization groups and re-keys.
        let working = vec![
            "epix://1.2.3.4:15441".to_string(),
            "onion://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:15441"
                .to_string(),
            "udp://tracker.example.org:1337/announce".to_string(),
        ];
        let (epix, bt) = canonical_groups(&working);
        assert_eq!(
            epix,
            vec![
                "tcp://1.2.3.4:15441".to_string(),
                "onion://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:15441"
                    .to_string(),
            ]
        );
        assert_eq!(bt, vec!["udp://tracker.example.org:1337/announce".to_string()]);

        // The published document is JSON grouped by kind with an `updated`
        // stamp, and parses back to the same flat entries (unchanged-detection
        // relies on this).
        let body = render_list(&epix, &bt);
        let doc: Value = serde_json::from_str(&body).unwrap();
        assert!(doc["updated"].as_i64().unwrap() > 0);
        assert_eq!(doc["epix"].as_array().unwrap().len(), 2);
        assert_eq!(doc["bittorrent"].as_array().unwrap().len(), 1);
        let flat: Vec<String> = epix.iter().chain(bt.iter()).cloned().collect();
        assert_eq!(list_entries(body.as_bytes()), flat);

        // Consuming still accepts a flat trackers object, a bare JSON array,
        // and the legacy line-per-entry file (the old Syncronite.html).
        assert_eq!(
            list_entries(br#"{"trackers": ["tcp://1.2.3.4:15441"]}"#),
            vec!["tcp://1.2.3.4:15441".to_string()]
        );
        assert_eq!(
            list_entries(br#"["epix://1.2.3.4:15441"]"#),
            vec!["epix://1.2.3.4:15441".to_string()]
        );
        assert_eq!(
            list_entries(b"epix://1.2.3.4:15441\n\nepix://5.6.7.8:1 \n"),
            vec!["epix://1.2.3.4:15441".to_string(), "epix://5.6.7.8:1".to_string()]
        );
    }
}
