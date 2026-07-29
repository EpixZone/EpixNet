//! `epix-propagation` - offline-first store-and-forward for xite updates.
//!
//! When a xite is updated, its owner announces a small notification (`xite`
//! address + `modified` version) to propagation nodes. A propagation node holds
//! recent notifications so a peer that was **offline** at publish time can pull
//! what it missed the next time it connects. The receiver then runs a normal
//! `epix-worker` sync, which verifies content.json signatures - so a
//! propagation relay is untrusted and cannot forge an update; it can only hint
//! that one exists.
//!
//! It's transport-agnostic: the service is a [`RequestHandler`] and the client
//! calls go over a [`Connection`], so this runs unchanged over TCP and over the
//! Reticulum mesh (an offline peer on a mesh backhaul pulls the same way).
//!
//! Sync uses a monotonic **sequence cursor** rather than wall-clock time: each
//! stored notification gets a seq, a peer remembers the `head` it last saw, and
//! asks for everything `after` it. No clocks, no ambiguity, idempotent.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use epix_core::{PeerAddr, Result};
use epix_protocol::{vget, vmap, Connection, RequestHandler};
use rmpv::Value;
use tokio::sync::Mutex;

/// Wire command: announce that a xite was updated.
pub const CMD_ANNOUNCE: &str = "meshAnnounceUpdate";
/// Wire command: pull notifications after a cursor.
pub const CMD_GET: &str = "meshGetUpdates";

/// Default number of recent notifications a node retains.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// A xite-update notification: which xite, and the version it advanced to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notification {
    pub xite: String,
    pub modified: i64,
}

#[derive(Clone, Debug)]
struct Stored {
    seq: u64,
    xite: String,
    modified: i64,
}

/// A bounded, in-memory log of recent update notifications, addressed by a
/// monotonic sequence number. Oldest entries are evicted past the cap (a peer
/// offline longer than the retention window falls back to normal discovery).
pub struct PropagationStore {
    items: VecDeque<Stored>,
    next_seq: u64,
    cap: usize,
}

impl Default for PropagationStore {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

impl PropagationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self { items: VecDeque::new(), next_seq: 1, cap: cap.max(1) }
    }

    /// Record an update, idempotent per `(xite, modified)`. Returns the seq the
    /// notification is stored under (the existing seq if already present).
    pub fn record(&mut self, xite: &str, modified: i64) -> u64 {
        if let Some(existing) = self.items.iter().find(|s| s.xite == xite && s.modified == modified)
        {
            return existing.seq;
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.items.push_back(Stored { seq, xite: xite.to_string(), modified });
        while self.items.len() > self.cap {
            self.items.pop_front();
        }
        seq
    }

    /// Notifications stored after the `after` cursor (exclusive), plus the
    /// current `head` seq so the caller can advance even if older entries were
    /// evicted.
    pub fn since(&self, after: u64) -> (Vec<Notification>, u64) {
        let head = self.next_seq.saturating_sub(1);
        let updates = self
            .items
            .iter()
            .filter(|s| s.seq > after)
            .map(|s| Notification { xite: s.xite.clone(), modified: s.modified })
            .collect();
        (updates, head)
    }

    /// Current head sequence (0 if nothing recorded).
    pub fn head(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }
}

/// A [`PropagationStore`] shared between the msgpack service, the EDX control
/// plane and the node's update-apply path. One book, many readers.
pub type SharedStore = Arc<Mutex<PropagationStore>>;

/// The propagation-node role: answers `meshAnnounceUpdate` / `meshGetUpdates`
/// against a shared [`PropagationStore`]. Plug it into a `PeerServer`
/// (TCP) or `ReticulumServer` (mesh) like any other handler.
///
/// The read/write pair is also exposed codec-free
/// ([`updates_since`](Self::updates_since), [`record`](Self::record)) so a
/// non-msgpack wire (EDX) serves the same book without building `rmpv` values.
/// The msgpack handler below is a thin encode/decode shell over those two, so
/// both wires can never drift apart.
pub struct PropagationService {
    store: SharedStore,
}

impl PropagationService {
    pub fn new(store: SharedStore) -> Self {
        Self { store }
    }

    /// The shared store, for a caller that needs the handle itself (e.g. to
    /// hand the same book to another wire).
    pub fn store(&self) -> &SharedStore {
        &self.store
    }

    /// Notifications after the `after` cursor (exclusive) plus the current
    /// `head`, exactly what `meshGetUpdates` answers - no codec involved.
    pub async fn updates_since(&self, after: u64) -> (Vec<Notification>, u64) {
        self.store.lock().await.since(after)
    }

    /// Record an update hint, exactly what `meshAnnounceUpdate` does - no codec
    /// involved. Returns the seq it is stored under, or `None` when `xite` is
    /// empty (there is nothing to key the hint on).
    pub async fn record(&self, xite: &str, modified: i64) -> Option<u64> {
        if xite.is_empty() {
            return None;
        }
        Some(self.store.lock().await.record(xite, modified))
    }
}

/// Encode a `meshGetUpdates` reply, the msgpack half of the handler.
fn encode_updates(updates: Vec<Notification>, head: u64) -> Value {
    let arr = updates
        .into_iter()
        .map(|n| vmap(vec![("xite", Value::from(n.xite)), ("modified", Value::from(n.modified))]))
        .collect();
    vmap(vec![("updates", Value::Array(arr)), ("head", Value::from(head))])
}

/// Decode a `meshGetUpdates` reply. `after` is the cursor we asked from, used
/// as the head fallback so a malformed reply never rewinds our cursor.
fn decode_updates(resp: &Value, after: u64) -> (Vec<Notification>, u64) {
    let head = vget(resp, "head").and_then(|v| v.as_u64()).unwrap_or(after);
    let updates = vget(resp, "updates")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|u| {
                    Some(Notification {
                        xite: vget(u, "xite")?.as_str()?.to_string(),
                        modified: vget(u, "modified").and_then(|v| v.as_i64()).unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    (updates, head)
}

#[async_trait]
impl RequestHandler for PropagationService {
    async fn handle(&self, _peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        match cmd {
            CMD_ANNOUNCE => {
                let xite = vget(params, "xite").and_then(|v| v.as_str()).unwrap_or("");
                let modified = vget(params, "modified").and_then(|v| v.as_i64()).unwrap_or(0);
                match self.record(xite, modified).await {
                    Some(seq) => vmap(vec![("ok", Value::from(true)), ("seq", Value::from(seq))]),
                    None => vmap(vec![("error", Value::from("missing xite"))]),
                }
            }
            CMD_GET => {
                let after = vget(params, "after").and_then(|v| v.as_u64()).unwrap_or(0);
                let (updates, head) = self.updates_since(after).await;
                encode_updates(updates, head)
            }
            _ => vmap(vec![("error", Value::from("unknown command"))]),
        }
    }
}

/// Announce a xite update to a propagation node over `conn`. Returns the seq the
/// node stored it under.
pub async fn announce_update(conn: &mut Connection, xite: &str, modified: i64) -> Result<u64> {
    let resp = conn
        .request(
            CMD_ANNOUNCE,
            vmap(vec![
                ("xite", Value::from(xite)),
                ("modified", Value::from(modified)),
            ]),
        )
        .await?;
    Ok(vget(&resp, "seq").and_then(|v| v.as_u64()).unwrap_or(0))
}

/// Pull notifications after the `after` cursor from a propagation node. Returns
/// the new notifications and the node's current `head` (persist it as the next
/// `after`).
pub async fn fetch_updates(
    conn: &mut Connection,
    after: u64,
) -> Result<(Vec<Notification>, u64)> {
    let resp = conn
        .request(CMD_GET, vmap(vec![("after", Value::from(after))]))
        .await?;
    Ok(decode_updates(&resp, after))
}

/// Client-side propagation: remembers the pull cursor for one propagation node
/// so each [`poll`](PropagationClient::poll) returns only what's new since last
/// time. The node runtime holds one of these per propagation peer and drives it
/// on connect / on a timer.
#[derive(Debug, Default)]
pub struct PropagationClient {
    cursor: u64,
}

impl PropagationClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cursor to resume from (persist across restarts to avoid re-pulling).
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Resume from a previously persisted cursor.
    pub fn with_cursor(cursor: u64) -> Self {
        Self { cursor }
    }

    /// Pull notifications newer than the cursor and advance it.
    pub async fn poll(&mut self, conn: &mut Connection) -> Result<Vec<Notification>> {
        let (updates, head) = fetch_updates(conn, self.cursor).await?;
        self.cursor = head;
        Ok(updates)
    }
}

/// Of `notifications`, the xites we already host (present in `local` as
/// `address -> modified`) that advanced to a newer version - i.e. what the
/// worker should re-sync. Notifications for xites we don't host are ignored; a
/// node keeps *its* xites fresh, and the resync still verifies signatures.
pub fn needs_sync(
    notifications: &[Notification],
    local: &HashMap<String, i64>,
) -> Vec<Notification> {
    notifications
        .iter()
        .filter(|n| local.get(&n.xite).is_some_and(|&have| n.modified > have))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_sync_picks_hosted_and_newer_only() {
        let local = HashMap::from([("a.epix".to_string(), 1), ("c.epix".to_string(), 5)]);
        let notifications = vec![
            Notification { xite: "a.epix".into(), modified: 2 }, // hosted, newer -> sync
            Notification { xite: "b.epix".into(), modified: 9 }, // not hosted -> ignore
            Notification { xite: "c.epix".into(), modified: 5 }, // hosted, not newer -> ignore
        ];
        let out = needs_sync(&notifications, &local);
        assert_eq!(out, vec![Notification { xite: "a.epix".into(), modified: 2 }]);
    }

    #[test]
    fn store_is_idempotent_and_cursored() {
        let mut s = PropagationStore::new();
        assert_eq!(s.record("a.epix", 1), 1);
        assert_eq!(s.record("a.epix", 1), 1); // dup -> same seq
        assert_eq!(s.record("a.epix", 2), 2); // new version -> new seq
        assert_eq!(s.record("b.epix", 1), 3);

        let (ups, head) = s.since(0);
        assert_eq!(head, 3);
        assert_eq!(ups.len(), 3);

        let (ups, head) = s.since(2);
        assert_eq!(head, 3);
        assert_eq!(ups, vec![Notification { xite: "b.epix".into(), modified: 1 }]);

        let (ups, _) = s.since(3);
        assert!(ups.is_empty());
    }

    /// The codec-free read the EDX control plane uses must answer exactly what
    /// a msgpack `meshGetUpdates` client would decode off the same store - same
    /// notifications, same order, same head - or the two wires drift.
    #[tokio::test]
    async fn codec_free_reads_match_the_msgpack_path() {
        let svc = PropagationService::new(Arc::new(Mutex::new(PropagationStore::new())));
        let peer = PeerAddr::parse("1.2.3.4:1").unwrap();
        let get = |after: u64| vmap(vec![("after", Value::from(after))]);

        // Empty store: no updates, head 0, both paths agree.
        assert_eq!(svc.updates_since(0).await, (vec![], 0));
        assert_eq!(decode_updates(&svc.handle(&peer, CMD_GET, &get(0)).await, 0), (vec![], 0));

        // Announce over msgpack, read back codec-free (and vice versa): the two
        // sides share one book.
        let announce = vmap(vec![("xite", Value::from("a.epix")), ("modified", Value::from(1i64))]);
        let r = svc.handle(&peer, CMD_ANNOUNCE, &announce).await;
        assert_eq!(vget(&r, "seq").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(svc.record("a.epix", 2).await, Some(2));
        assert_eq!(svc.record("b.epix", 1).await, Some(3));

        for after in 0..=4 {
            let codec_free = svc.updates_since(after).await;
            let msgpack = decode_updates(&svc.handle(&peer, CMD_GET, &get(after)).await, after);
            assert_eq!(codec_free, msgpack, "after={after}");
        }

        // Head advances with every record; nothing newer past it.
        let (ups, head) = svc.updates_since(0).await;
        assert_eq!(head, 3);
        assert_eq!(ups.len(), 3);
        let (ups, head) = svc.updates_since(2).await;
        assert_eq!((ups, head), (vec![Notification { xite: "b.epix".into(), modified: 1 }], 3));
        assert_eq!(svc.updates_since(3).await, (vec![], 3), "nothing newer, head unchanged");

        // An empty xite is rejected the same way on both paths.
        assert_eq!(svc.record("", 1).await, None);
        let bad = vmap(vec![("xite", Value::from("")), ("modified", Value::from(1i64))]);
        assert!(vget(&svc.handle(&peer, CMD_ANNOUNCE, &bad).await, "error").is_some());
        assert_eq!(svc.updates_since(0).await.1, 3, "a rejected announce burns no seq");
    }

    #[test]
    fn store_evicts_past_capacity() {
        let mut s = PropagationStore::with_capacity(2);
        s.record("a.epix", 1);
        s.record("b.epix", 1);
        s.record("c.epix", 1); // evicts a.epix
        let (ups, head) = s.since(0);
        assert_eq!(head, 3, "head still advances past evicted entries");
        assert_eq!(ups.len(), 2);
        assert!(ups.iter().all(|n| n.xite != "a.epix"));
    }
}
