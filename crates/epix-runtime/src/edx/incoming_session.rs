//! Reuse an authenticated incoming channel without inventing a dial-back address.

use super::{LinkActivity, LinkActivityState, RuntimeEdxFetcher};
use epix_core::PeerAddr;
use epix_edx::{choke::Reach, conn::Conn, server::UpdateSource};
use epix_protocol::registry::ConnHandle;
use epix_ui::AppState;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[cfg(test)]
#[path = "incoming_session_tests.rs"]
mod tests;

pub(super) struct IncomingSession {
    state: Arc<AppState>,
    fetcher: std::sync::Weak<RuntimeEdxFetcher>,
    peer: PeerAddr,
    conn: Conn,
    reg: Arc<ConnHandle>,
    activity: LinkActivity,
    binding: tokio::sync::Mutex<Binding>,
    closed: AtomicBool,
}

#[derive(Default)]
struct Binding {
    identity: Option<Vec<u8>>,
    generations: HashMap<String, u64>,
}

pub(super) fn routing_allows(peer: &PeerAddr, tor_always: bool) -> bool {
    !tor_always || peer.is_overlay()
}

impl IncomingSession {
    pub(super) fn new(
        state: Arc<AppState>,
        fetcher: &Arc<RuntimeEdxFetcher>,
        source: &PeerAddr,
        conn: Conn,
        reg: Arc<ConnHandle>,
    ) -> Arc<Self> {
        let id = hex::decode(epix_crypt::new_seed())
            .unwrap()
            .try_into()
            .unwrap();
        Arc::new(Self {
            state,
            fetcher: Arc::downgrade(fetcher),
            peer: PeerAddr::Session {
                id,
                network: source.ip_type(),
            },
            conn,
            reg,
            activity: LinkActivityState::new(),
            binding: tokio::sync::Mutex::new(Binding::default()),
            closed: AtomicBool::new(false),
        })
    }

    pub(super) async fn note_interest(&self, address: &str, source: UpdateSource) {
        if !self.conn.same_connection(&source.conn)
            || self.conn.is_closed()
            || self.peer.is_overlay() != matches!(source.reach, Reach::Overlay)
            || !routing_allows(&self.peer, epix_core::route_all_via_overlay())
        {
            return;
        }
        let mut binding = self.binding.lock().await;
        if self.closed.load(Ordering::Acquire)
            || binding
                .identity
                .as_ref()
                .is_some_and(|key| *key != source.identity.node_pk)
        {
            return;
        }
        let key = self.state.canonical_key(address).await;
        let Some(generation) = self.state.xite_membership_generation(&key).await else {
            return;
        };
        if !self.state.is_serving(&key).await {
            return;
        }
        match binding.generations.get(&key) {
            Some(old) if *old != generation => return,
            None if binding.generations.len() >= 128 => return,
            _ => {}
        }
        let Some(fetcher) = self.fetcher.upgrade() else {
            return;
        };
        if self.conn.is_closed() {
            return;
        }
        binding
            .identity
            .get_or_insert_with(|| source.identity.node_pk.clone());
        if fetcher.link_pool.live(&self.peer, 0).is_none() {
            // A transient request error may evict an otherwise live channel.
            // Restore only this exact still-open connection, preserving its
            // activity state. close() holds the same binding lock.
            fetcher.link_pool.store(
                self.peer.clone(),
                0,
                (
                    self.conn.clone(),
                    source.identity,
                    self.reg.clone(),
                    None,
                    self.activity.clone(),
                ),
            );
        }
        if binding
            .generations
            .insert(key.clone(), generation)
            .is_some()
        {
            return;
        }
        self.state
            .record_session_peer(&key, generation, self.peer.clone())
            .await;
    }

    pub(super) async fn close(&self) {
        let _binding = self.binding.lock().await;
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(fetcher) = self.fetcher.upgrade() {
            fetcher.link_pool.evict(&self.peer);
        }
        self.state.remove_session_peer(&self.peer).await;
    }
}

impl Drop for IncomingSession {
    fn drop(&mut self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(fetcher) = self.fetcher.upgrade() {
            fetcher.link_pool.evict(&self.peer);
        }
        // Cancellation of the accept loop must remove its transient registry
        // entries too. Each connection has its own random key, so old cleanup
        // cannot remove a replacement channel from the same remote identity.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let state = self.state.clone();
            let peer = self.peer.clone();
            runtime.spawn(async move {
                state.remove_session_peer(&peer).await;
            });
        }
    }
}
