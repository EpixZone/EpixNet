//! Live transfer telemetry: what the EDX fetcher is doing to a file, right now.
//!
//! A media element asking for the next 4 MiB of a film sets off a dial, a
//! peer session, a sliding window of striped requests and a background
//! read-ahead - and until now every bit of that was invisible from outside
//! the node. When playback stalls the only observable was "buffering", which
//! says nothing about WHY: no peers, one slow onion circuit, a peer that
//! accepts requests and sends nothing, or a film whose bitrate is simply
//! above what the swarm can deliver.
//!
//! This module keeps the answer in memory, per object, in the shape a
//! torrent client's transfer pane shows it: per-peer rates and byte counts,
//! what is in flight, what failed, what the browser actually got. It is
//! bounded (a fixed number of files, a rolling rate window, idle peers
//! pruned) and lossy by design - it is a diagnostic view, not accounting.

use std::collections::HashMap;
use std::sync::Mutex;

use epix_blob::bitfield::bytes_of_group;
use epix_blob::ObjId;
use epix_edx::sim::Class;
use serde_json::{json, Value};

/// Seconds of history the rate rings keep. Also the longest averaging
/// window a caller can ask for.
const RATE_BUCKETS: u64 = 30;
/// Seconds the reported rates average over. Long enough that one 1 MiB
/// batch landing does not read as a spike, short enough to track a stall.
const RATE_WINDOW: u64 = 10;
/// Files tracked at once. Streaming touches one or two; the cap only
/// bounds a long session that has played through a library.
const MAX_FILES: usize = 24;
/// A peer with no activity for this long is dropped from the readout - it
/// left the session and its stale row is just noise.
const PEER_IDLE_DROP: u64 = 300;

/// Per-second byte buckets in a ring, for a rate readout without keeping a
/// sample log. Stale buckets are cleared as the clock moves over them, so a
/// transfer that stops reads as zero rather than freezing at its last value.
struct Rate {
    buckets: [u64; RATE_BUCKETS as usize],
    /// The second `buckets` is current as of.
    last: u64,
}

impl Default for Rate {
    fn default() -> Self {
        Self { buckets: [0; RATE_BUCKETS as usize], last: 0 }
    }
}

impl Rate {
    /// Zero every bucket the clock has passed since the last touch, so a
    /// full lap of silence leaves the ring empty instead of replaying the
    /// previous lap's bytes.
    fn roll(&mut self, now: u64) {
        if now <= self.last {
            return;
        }
        let gap = (now - self.last).min(RATE_BUCKETS);
        for i in 1..=gap {
            self.buckets[((self.last + i) % RATE_BUCKETS) as usize] = 0;
        }
        self.last = now;
    }

    fn add(&mut self, now: u64, bytes: u64) {
        self.roll(now);
        self.buckets[(now % RATE_BUCKETS) as usize] += bytes;
    }

    /// Bytes per second averaged over the last [`RATE_WINDOW`] seconds.
    fn per_sec(&mut self, now: u64) -> u64 {
        self.roll(now);
        let sum: u64 = (0..RATE_WINDOW)
            .map(|i| self.buckets[(now.saturating_sub(i) % RATE_BUCKETS) as usize])
            .sum();
        sum / RATE_WINDOW
    }
}

/// One peer's contribution to a file, as the scheduler saw it.
#[derive(Default)]
struct PeerXfer {
    class: Option<Class>,
    /// Verified bytes this peer delivered.
    bytes: u64,
    /// Batches booked onto it.
    requests: u64,
    /// Batches it delivered (including ones it won off another peer).
    delivered: u64,
    /// Batches booked onto it that nobody could complete, or that it
    /// stalled badly enough to be raced off.
    failed: u64,
    /// Requests booked and not yet resolved.
    inflight: u32,
    /// Bytes booked onto it right now (what it owes us).
    inflight_bytes: u64,
    /// Last completed batch's wall time - the round trip a torrent client
    /// would show, dominated by transfer time, not by RTT.
    last_ms: Option<u64>,
    /// Unix second of its last delivered byte.
    last_at: u64,
    rate: Rate,
}

/// Everything known about one object's transfer.
struct FileXfer {
    address: String,
    inner_path: String,
    size: u64,
    /// Unix second the first byte of interest was recorded.
    started: u64,
    /// Unix second of the last activity of any kind (for eviction).
    touched: u64,
    peers: HashMap<String, PeerXfer>,
    /// Verified bytes in from the network.
    rate_in: Rate,
    /// Bytes handed to the browser (from the store, fetched or not).
    rate_out: Rate,
    fetched: u64,
    served: u64,
    /// Bytes served that were already in the store when asked for - the
    /// share of playback the network was not on the critical path for.
    served_cached: u64,
    requests: u64,
    duplicates: u64,
    batch_failures: u64,
    /// Peers the last session dialed, and how many answered with a usable
    /// bitfield.
    dialed: u64,
    connected: u64,
    session_at: u64,
    /// The read-ahead window currently being pulled, if any.
    readahead: Option<(u64, u64)>,
    /// Read-aheads running for this file. The moov warm-up runs two windows
    /// back to back and a streaming file re-arms continuously, so the flag
    /// is refcounted - otherwise the first one to finish reports the file as
    /// idle while the next is still pulling.
    readahead_depth: u32,
    /// The last byte range the browser asked for.
    last_range: Option<(u64, u64)>,
    /// One past the last byte actually served - where the player is reading
    /// from. The exact frontier, which is what the node's lead is measured
    /// against: guessing it from the play head's TIME needs a constant
    /// bitrate the film does not have, and on a variable-bitrate encode that
    /// guess lands in a gap and reports a healthy transfer as zero.
    last_served_end: u64,
    /// Last fetch failure, with the second it happened.
    last_error: Option<(u64, String)>,
    /// Requests in flight across all peers (a cheap top-line number).
    inflight: u32,
}

impl FileXfer {
    fn new(address: &str, inner_path: &str, size: u64, now: u64) -> Self {
        Self {
            address: address.to_string(),
            inner_path: inner_path.to_string(),
            size,
            started: now,
            touched: now,
            peers: HashMap::new(),
            rate_in: Rate::default(),
            rate_out: Rate::default(),
            fetched: 0,
            served: 0,
            served_cached: 0,
            requests: 0,
            duplicates: 0,
            batch_failures: 0,
            dialed: 0,
            connected: 0,
            session_at: 0,
            readahead: None,
            readahead_depth: 0,
            last_range: None,
            last_served_end: 0,
            last_error: None,
            inflight: 0,
        }
    }

    /// Drop peers that have been silent long enough to be gone. Keeps the
    /// readout to the peers actually in the session.
    fn prune(&mut self, now: u64) {
        self.peers.retain(|_, p| {
            p.inflight > 0 || now.saturating_sub(p.last_at) < PEER_IDLE_DROP
        });
    }

    fn snapshot(&mut self, now: u64, have: Option<u64>) -> Value {
        self.prune(now);
        let mut peers: Vec<Value> = self
            .peers
            .iter_mut()
            .map(|(label, p)| {
                json!({
                    "peer": label,
                    "transport": class_name(p.class),
                    "rate": p.rate.per_sec(now),
                    "bytes": p.bytes,
                    "requests": p.requests,
                    "delivered": p.delivered,
                    "failed": p.failed,
                    "inflight": p.inflight,
                    "inflight_bytes": p.inflight_bytes,
                    "last_ms": p.last_ms,
                    "idle": now.saturating_sub(p.last_at),
                })
            })
            .collect();
        // Fastest first, like a torrent client's default sort.
        peers.sort_by_key(|p| std::cmp::Reverse(p["rate"].as_u64().unwrap_or(0)));
        json!({
            "address": self.address,
            "inner_path": self.inner_path,
            "size": self.size,
            "have": have,
            "elapsed": now.saturating_sub(self.started),
            "rate_in": self.rate_in.per_sec(now),
            "rate_out": self.rate_out.per_sec(now),
            "fetched": self.fetched,
            "served": self.served,
            "served_cached": self.served_cached,
            "requests": self.requests,
            "duplicates": self.duplicates,
            "batch_failures": self.batch_failures,
            "inflight": self.inflight,
            "peers": peers,
            "session": {
                "dialed": self.dialed,
                "connected": self.connected,
                "age": if self.session_at == 0 { Value::Null } else { json!(now.saturating_sub(self.session_at)) },
            },
            "readahead": self.readahead.map(|(a, b)| json!({"start": a, "end": b})),
            "last_range": self.last_range.map(|(a, b)| json!({"start": a, "end": b})),
            "last_error": self.last_error.as_ref().map(|(at, e)| json!({"at": now.saturating_sub(*at), "error": e})),
        })
    }
}

fn class_name(class: Option<Class>) -> &'static str {
    match class {
        Some(Class::Clearnet) => "clearnet",
        Some(Class::I2p) => "i2p",
        Some(Class::Tor) => "tor",
        None => "unknown",
    }
}

/// The node's live transfer telemetry, keyed by object.
///
/// Keyed by [`ObjId`] rather than (address, path) because that is the one
/// identifier every layer of the fetch path carries - the read-ahead and
/// the scheduler know the object, not the file it came from - and because
/// two paths with identical bytes are genuinely one transfer.
#[derive(Default)]
pub struct Xfer {
    files: Mutex<HashMap<ObjId, FileXfer>>,
}

impl Xfer {
    /// Run `f` against `id`'s record, creating it if needed and evicting the
    /// stalest file when the table is full.
    fn with<R>(
        &self,
        id: ObjId,
        address: &str,
        inner_path: &str,
        size: u64,
        now: u64,
        f: impl FnOnce(&mut FileXfer) -> R,
    ) -> R {
        let mut files = self.files.lock().expect("xfer");
        if !files.contains_key(&id) && files.len() >= MAX_FILES {
            if let Some(stalest) =
                files.iter().min_by_key(|(_, f)| f.touched).map(|(id, _)| *id)
            {
                files.remove(&stalest);
            }
        }
        let entry = files
            .entry(id)
            .or_insert_with(|| FileXfer::new(address, inner_path, size, now));
        // A record created by the scheduler (which knows only the object)
        // learns its file identity from the first serve that names it.
        if entry.inner_path.is_empty() && !inner_path.is_empty() {
            entry.address = address.to_string();
            entry.inner_path = inner_path.to_string();
        }
        if entry.size == 0 {
            entry.size = size;
        }
        entry.touched = now;
        f(entry)
    }

    /// A browser Range request was answered: `bytes` served, `cached` when
    /// the store already held the whole window so nothing was fetched for it.
    pub fn note_serve(
        &self,
        id: ObjId,
        address: &str,
        inner_path: &str,
        size: u64,
        now: u64,
        range: (u64, u64),
        bytes: u64,
        cached: bool,
    ) {
        self.with(id, address, inner_path, size, now, |f| {
            f.last_range = Some(range);
            // A window that ends exactly at EOF is the player probing for the
            // moov/cues at the tail, not the position it is playing from.
            // Letting that move the read head parks it at the end of the file,
            // where nothing is ever "ahead" - which reported a film held whole
            // on disk as a zero lead. Windows during real playback are capped
            // well short of EOF, and the ones that do reach it are the last
            // few seconds of the film, when the lead no longer matters.
            if range.1 < size || size == 0 {
                f.last_served_end = range.0.saturating_add(bytes);
            }
            f.served += bytes;
            if cached {
                f.served_cached += bytes;
            }
            f.rate_out.add(now, bytes);
        });
    }

    /// Where the player is reading from: one past the last byte served.
    /// `None` when nothing has been served yet.
    pub fn read_head(&self, id: ObjId) -> Option<u64> {
        let files = self.files.lock().expect("xfer");
        files.get(&id).map(|f| f.last_served_end).filter(|end| *end > 0)
    }

    /// A peer session was opened for this object: `dialed` peers tried,
    /// `connected` of them usable.
    pub fn note_session(&self, id: ObjId, address: &str, now: u64, dialed: u64, connected: u64) {
        self.with(id, address, "", 0, now, |f| {
            f.dialed = dialed;
            f.connected = connected;
            f.session_at = now;
        });
    }

    /// A read-ahead started on `window`, or (with `None`) one finished.
    pub fn note_readahead(&self, id: ObjId, address: &str, now: u64, window: Option<(u64, u64)>) {
        self.with(id, address, "", 0, now, |f| match window {
            Some(w) => {
                f.readahead_depth += 1;
                f.readahead = Some(w);
            }
            None => {
                f.readahead_depth = f.readahead_depth.saturating_sub(1);
                if f.readahead_depth == 0 {
                    f.readahead = None;
                }
            }
        });
    }

    /// A fetch failed with `error`.
    pub fn note_error(&self, id: ObjId, address: &str, now: u64, error: &str) {
        self.with(id, address, "", 0, now, |f| {
            f.last_error = Some((now, error.to_string()));
        });
    }

    /// A scheduler hook for one [`epix_edx::sched::Swarm::fetch`] of `id`.
    /// Held for the fetch's lifetime; dropping it releases whatever it still
    /// had booked, so an abandoned batch cannot leak an in-flight count.
    pub fn scope(self: &std::sync::Arc<Self>, id: ObjId, address: &str) -> std::sync::Arc<Scope> {
        std::sync::Arc::new(Scope {
            xfer: self.clone(),
            id,
            address: address.to_string(),
            booked: Mutex::new(HashMap::new()),
        })
    }

    /// One file's telemetry as JSON, or `Null` when nothing is tracked for
    /// it. `have` is the bytes of the object present locally, which the
    /// caller reads from the store.
    pub fn snapshot(&self, id: ObjId, now: u64, have: Option<u64>) -> Value {
        let mut files = self.files.lock().expect("xfer");
        match files.get_mut(&id) {
            Some(f) => f.snapshot(now, have),
            None => Value::Null,
        }
    }
}

/// The [`epix_edx::sched::FetchObserver`] for one fetch: forwards the
/// scheduler's per-batch events into the file's record and cleans up after
/// itself.
pub struct Scope {
    xfer: std::sync::Arc<Xfer>,
    id: ObjId,
    address: String,
    /// Requests booked and not yet resolved, per peer. The scheduler
    /// abandons in-flight duplicates when a fetch completes early, so the
    /// counts are released on drop rather than trusted to balance.
    booked: Mutex<HashMap<String, (u32, u64)>>,
}

impl Scope {
    fn touch<R>(&self, now: u64, f: impl FnOnce(&mut FileXfer) -> R) -> R {
        self.xfer.with(self.id, &self.address, "", 0, now, f)
    }
}

impl epix_edx::sched::FetchObserver for Scope {
    fn on_request(&self, peer: &str, class: Class, bytes: u64) {
        let now = now_secs();
        {
            let mut booked = self.booked.lock().expect("booked");
            let slot = booked.entry(peer.to_string()).or_insert((0, 0));
            slot.0 += 1;
            slot.1 += bytes;
        }
        self.touch(now, |f| {
            f.requests += 1;
            f.inflight += 1;
            let p = f.peers.entry(peer.to_string()).or_default();
            p.class = Some(class);
            p.requests += 1;
            p.inflight += 1;
            p.inflight_bytes += bytes;
            if p.last_at == 0 {
                p.last_at = now;
            }
        });
    }

    fn on_batch(
        &self,
        booked_peer: &str,
        winner: Option<&str>,
        class: Option<Class>,
        bytes: u64,
        elapsed: Option<std::time::Duration>,
        duplicates: u64,
    ) {
        let now = now_secs();
        let released = {
            let mut booked = self.booked.lock().expect("booked");
            match booked.get_mut(booked_peer) {
                Some(slot) if slot.0 > 0 => {
                    slot.0 -= 1;
                    // The booking's byte reservation is only approximate
                    // once a batch has been split or raced; release what is
                    // left rather than tracking each batch's own size.
                    let per = slot.1 / (slot.0 + 1).max(1) as u64;
                    slot.1 = slot.1.saturating_sub(per);
                    Some(per)
                }
                _ => None,
            }
        };
        self.touch(now, |f| {
            f.duplicates += duplicates;
            f.inflight = f.inflight.saturating_sub(1);
            if bytes > 0 {
                f.fetched += bytes;
                f.rate_in.add(now, bytes);
            }
            if winner.is_none() {
                f.batch_failures += 1;
            }
            if let Some(p) = f.peers.get_mut(booked_peer) {
                p.inflight = p.inflight.saturating_sub(1);
                if let Some(per) = released {
                    p.inflight_bytes = p.inflight_bytes.saturating_sub(per);
                }
                if winner != Some(booked_peer) {
                    p.failed += 1;
                }
            }
            // Credit whoever actually delivered - on a rescue that is not
            // the peer the batch was booked onto.
            if let Some(w) = winner {
                let p = f.peers.entry(w.to_string()).or_default();
                if class.is_some() {
                    p.class = class;
                }
                p.delivered += 1;
                p.bytes += bytes;
                p.last_at = now;
                p.last_ms = elapsed.map(|d| d.as_millis() as u64);
                p.rate.add(now, bytes);
            }
        });
    }
}

impl Drop for Scope {
    /// Release every booking the fetch never resolved (an abandoned
    /// duplicate, or a fetch that returned with batches still racing).
    fn drop(&mut self) {
        let outstanding: Vec<(String, (u32, u64))> = self
            .booked
            .lock()
            .expect("booked")
            .drain()
            .filter(|(_, (n, _))| *n > 0)
            .collect();
        if outstanding.is_empty() {
            return;
        }
        let now = now_secs();
        self.touch(now, |f| {
            for (peer, (n, bytes)) in outstanding {
                f.inflight = f.inflight.saturating_sub(n);
                if let Some(p) = f.peers.get_mut(&peer) {
                    p.inflight = p.inflight.saturating_sub(n);
                    p.inflight_bytes = p.inflight_bytes.saturating_sub(bytes);
                }
            }
        });
    }
}

/// Bytes of an object present locally, from its group bitfield.
pub fn have_bytes(bits: &epix_blob::bitfield::GroupBits, size: u64) -> u64 {
    bits.ranges()
        .iter()
        .filter(|r| r.end > r.start)
        .map(|r| {
            // Whole runs at once: only the object's last group is short, so
            // spanning start..end-1 is exact and costs one step per run
            // rather than one per group (a 567 MB film is ~34k groups).
            bytes_of_group(r.end - 1, size).end - bytes_of_group(r.start, size).start
        })
        .sum()
}

/// Contiguous bytes present from `offset` onward - the node's lead over a
/// play head sitting there.
///
/// This is the number that separates "the network cannot keep up" from
/// "the browser is pacing itself": a player can be a couple of seconds from
/// the end of its OWN buffer while the node holds a minute of film past it,
/// and only one of those is a problem worth chasing.
pub fn contiguous_from(bits: &epix_blob::bitfield::GroupBits, size: u64, offset: u64) -> u64 {
    if offset >= size {
        return 0;
    }
    let g = epix_blob::bitfield::groups_for_bytes(&(offset..offset + 1)).start;
    for r in bits.ranges() {
        if r.start <= g && g < r.end {
            return bytes_of_group(r.end - 1, size).end.saturating_sub(offset);
        }
    }
    0
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_averages_over_the_window_and_decays_to_zero() {
        let mut r = Rate::default();
        // 10 seconds of 1000 bytes each reads as 1000 B/s.
        for t in 1_000..1_010 {
            r.add(t, 1000);
        }
        assert_eq!(r.per_sec(1_009), 1000);
        // Silence for a full window reads as zero, not as the last value.
        assert_eq!(r.per_sec(1_020), 0);
    }

    #[test]
    fn rate_clears_stale_buckets_after_a_full_lap() {
        let mut r = Rate::default();
        r.add(1_000, 100_000);
        // A lap later the old bucket must not be counted again.
        assert_eq!(r.per_sec(1_000 + RATE_BUCKETS), 0);
    }

    #[test]
    fn scope_releases_abandoned_bookings_on_drop() {
        use epix_edx::sched::FetchObserver;
        let xfer = std::sync::Arc::new(Xfer::default());
        let id = ObjId([7u8; 32]);
        let scope = xfer.scope(id, "epix1test");
        scope.on_request("peer-a", Class::Tor, 1_048_576);
        scope.on_request("peer-a", Class::Tor, 1_048_576);
        // One resolves, one is abandoned when the fetch ends.
        scope.on_batch("peer-a", Some("peer-a"), Some(Class::Tor), 1_048_576, None, 0);
        let now = now_secs();
        assert_eq!(xfer.snapshot(id, now, None)["inflight"], json!(1));
        drop(scope);
        let snap = xfer.snapshot(id, now, None);
        assert_eq!(snap["inflight"], json!(0));
        assert_eq!(snap["peers"][0]["inflight"], json!(0));
        assert_eq!(snap["fetched"], json!(1_048_576));
    }

    #[test]
    fn a_rescued_batch_credits_the_deliverer_and_faults_the_primary() {
        use epix_edx::sched::FetchObserver;
        let xfer = std::sync::Arc::new(Xfer::default());
        let id = ObjId([9u8; 32]);
        let scope = xfer.scope(id, "epix1test");
        scope.on_request("slow", Class::Tor, 1_000);
        scope.on_batch("slow", Some("fast"), Some(Class::Clearnet), 1_000, None, 1);
        let snap = xfer.snapshot(id, now_secs(), None);
        let peers = snap["peers"].as_array().unwrap();
        let slow = peers.iter().find(|p| p["peer"] == "slow").unwrap();
        let fast = peers.iter().find(|p| p["peer"] == "fast").unwrap();
        assert_eq!(slow["failed"], json!(1));
        assert_eq!(slow["bytes"], json!(0));
        assert_eq!(fast["bytes"], json!(1_000));
        assert_eq!(fast["transport"], json!("clearnet"));
        assert_eq!(snap["duplicates"], json!(1));
    }

    #[test]
    fn contiguous_from_measures_the_lead_over_a_play_head() {
        use epix_blob::bitfield::{GroupBits, GROUP_BYTES};
        let size = GROUP_BYTES * 100;
        let mut bits = GroupBits::new();
        bits.add(0..10);
        bits.add(20..30);
        // Inside the first run: the lead ends where that run does.
        assert_eq!(contiguous_from(&bits, size, 0), GROUP_BYTES * 10);
        assert_eq!(contiguous_from(&bits, size, GROUP_BYTES * 9), GROUP_BYTES);
        // In the gap: nothing is held at the play head at all.
        assert_eq!(contiguous_from(&bits, size, GROUP_BYTES * 12), 0);
        // A later island counts from the head, not from the file start.
        assert_eq!(contiguous_from(&bits, size, GROUP_BYTES * 25), GROUP_BYTES * 5);
        assert_eq!(contiguous_from(&bits, size, size), 0);
    }

    #[test]
    fn readahead_stays_reported_until_the_last_window_finishes() {
        let xfer = Xfer::default();
        let id = ObjId([3u8; 32]);
        // The moov warm-up: tail and head run back to back.
        xfer.note_readahead(id, "epix1test", 1_000, Some((0, 4_000)));
        xfer.note_readahead(id, "epix1test", 1_000, Some((8_000, 12_000)));
        xfer.note_readahead(id, "epix1test", 1_001, None);
        assert_ne!(
            xfer.snapshot(id, 1_001, None)["readahead"],
            Value::Null,
            "one window finishing must not report the file as idle"
        );
        xfer.note_readahead(id, "epix1test", 1_002, None);
        assert_eq!(xfer.snapshot(id, 1_002, None)["readahead"], Value::Null);
    }

    #[test]
    fn a_tail_probe_does_not_move_the_read_head() {
        let xfer = Xfer::default();
        let id = ObjId([5u8; 32]);
        let size = 100_000_000;
        // Playback window well short of EOF: this is the read position.
        xfer.note_serve(id, "epix1test", "video/x.webm", size, 1_000, (0, 4_000_000),
                        4_000_000, false);
        assert_eq!(xfer.read_head(id), Some(4_000_000));
        // The player's metadata probe at the tail must not become the head.
        xfer.note_serve(id, "epix1test", "video/x.webm", size, 1_001,
                        (size - 65_536, size), 65_536, true);
        assert_eq!(xfer.read_head(id), Some(4_000_000));
    }

    #[test]
    fn the_file_table_is_bounded() {
        let xfer = Xfer::default();
        for i in 0..(MAX_FILES + 8) {
            let mut raw = [0u8; 32];
            raw[0] = i as u8;
            xfer.note_serve(ObjId(raw), "epix1test", "video/x.webm", 10, 1_000 + i as u64,
                            (0, 10), 10, true);
        }
        assert_eq!(xfer.files.lock().unwrap().len(), MAX_FILES);
    }
}
