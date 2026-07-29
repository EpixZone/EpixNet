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
//! It's transport-agnostic: the store is codec-free and the EDX control plane
//! (`UpdatesSince`) carries it, so this runs unchanged over TCP, Tor, I2P and
//! the Reticulum mesh (an offline peer on a mesh backhaul pulls the same way).
//!
//! Sync uses a monotonic **sequence cursor** rather than wall-clock time: each
//! stored notification gets a seq, a peer remembers the `head` it last saw, and
//! asks for everything `after` it. No clocks, no ambiguity, idempotent.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use tokio::sync::Mutex;

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

/// A [`PropagationStore`] shared between the EDX control plane and the node's
/// update-apply path. One book, many readers.
pub type SharedStore = Arc<Mutex<PropagationStore>>;

/// The propagation-node role: the read/write pair over a shared
/// [`PropagationStore`], codec-free, so the EDX control plane
/// (`Req::UpdatesSince`) and the node's own update-apply path serve the same
/// book without either owning an encoding.
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
    /// `head` - what `Req::UpdatesSince` answers.
    pub async fn updates_since(&self, after: u64) -> (Vec<Notification>, u64) {
        self.store.lock().await.since(after)
    }

    /// Record an update hint. Returns the seq it is stored under, or `None`
    /// when `xite` is empty (there is nothing to key the hint on).
    pub async fn record(&self, xite: &str, modified: i64) -> Option<u64> {
        if xite.is_empty() {
            return None;
        }
        Some(self.store.lock().await.record(xite, modified))
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

    /// The service is a thin async shell over the store: what it reads back
    /// must be exactly what the store holds, at every cursor, and a rejected
    /// announce must not burn a seq.
    #[tokio::test]
    async fn the_service_reads_and_writes_the_same_book() {
        let svc = PropagationService::new(Arc::new(Mutex::new(PropagationStore::new())));

        // Empty store: no updates, head 0.
        assert_eq!(svc.updates_since(0).await, (vec![], 0));

        assert_eq!(svc.record("a.epix", 1).await, Some(1));
        assert_eq!(svc.record("a.epix", 1).await, Some(1), "idempotent per (xite, modified)");
        assert_eq!(svc.record("a.epix", 2).await, Some(2));
        assert_eq!(svc.record("b.epix", 1).await, Some(3));

        for after in 0..=4 {
            let via_service = svc.updates_since(after).await;
            let via_store = svc.store().lock().await.since(after);
            assert_eq!(via_service, via_store, "after={after}");
        }

        // Head advances with every record; nothing newer past it.
        let (ups, head) = svc.updates_since(0).await;
        assert_eq!(head, 3);
        assert_eq!(ups.len(), 3);
        let (ups, head) = svc.updates_since(2).await;
        assert_eq!((ups, head), (vec![Notification { xite: "b.epix".into(), modified: 1 }], 3));
        assert_eq!(svc.updates_since(3).await, (vec![], 3), "nothing newer, head unchanged");

        // An empty xite has nothing to key the hint on.
        assert_eq!(svc.record("", 1).await, None);
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
