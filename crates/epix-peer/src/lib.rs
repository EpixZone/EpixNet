//! `epix-peer` - the per-xite peer registry.
//!
//! A xite knows a set of peers, discovered from trackers / PEX / the DHT /
//! Reticulum announces. Each [`Peer`] carries its address, a live connection
//! flag, a reputation, and byte counters. [`Peers`] aggregates them into the
//! counts the UI reports (connected / connectable / onion / local / total) and
//! hands the worker a list of addresses to pull from.
//!
//! "Connectable" mirrors EpixNet: a peer we learned about only because it dialed
//! us (its listen port is unknown, encoded as `:0`) is *not* connectable; onion
//! and Reticulum peers always are.

use epix_core::PeerAddr;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Which peer networks this node can currently DIAL. Computed by the host
/// (which knows the transport/Tor/I2P state) and passed into
/// [`Peers::connectable_dialable`], so this crate needs no transport
/// dependency. Distinct from inbound reachability: a node with no published
/// onion service can still dial onion peers if its Tor client is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialableNets {
    /// Direct TCP (the base transport) - true on every real node.
    pub clearnet: bool,
    /// Tor onion dialing (the Tor client is up).
    pub onion: bool,
    /// I2P dialing (transport composed in and the session is Ready).
    pub i2p: bool,
    /// Reticulum mesh dialing (transport up).
    pub rns: bool,
}

impl DialableNets {
    /// Every network dialable - the permissive default for tests/tools.
    pub fn all() -> Self {
        Self { clearnet: true, onion: true, i2p: true, rns: true }
    }

    /// Can this node currently dial `addr`?
    pub fn can_dial(&self, addr: &PeerAddr) -> bool {
        match addr {
            PeerAddr::Ip(_) => self.clearnet,
            PeerAddr::Onion { .. } => self.onion,
            PeerAddr::I2p { .. } => self.i2p,
            PeerAddr::Rns(_) => self.rns,
        }
    }
}

/// One known peer of a xite.
#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: PeerAddr,
    /// Reputation; higher = preferred. Adjusted by success/failure.
    pub reputation: i32,
    /// Unix time the peer was first seen.
    pub time_found: i64,
    /// Unix time of the last successful response (0 = never).
    pub time_response: i64,
    /// Consecutive connection failures.
    pub connection_errors: u32,
    /// Unix time before which selection skips the peer (exponential backoff
    /// after failures). In-memory only - never serialized or sent to peers,
    /// so it is wire-safe.
    pub retry_after: i64,
    /// Whether we currently hold a live connection to the peer.
    pub connected: bool,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
}

impl Peer {
    pub fn new(addr: PeerAddr, now: i64) -> Self {
        Self {
            addr,
            reputation: 0,
            time_found: now,
            time_response: 0,
            connection_errors: 0,
            retry_after: 0,
            connected: false,
            bytes_recv: 0,
            bytes_sent: 0,
        }
    }

    /// Stable registry key (the address string).
    pub fn key(&self) -> String {
        self.addr.to_string()
    }

    /// A dial + handshake succeeded: clear the failure state and backoff,
    /// stamp the response time, and reward the peer.
    pub fn note_connect_ok(&mut self, now: i64) {
        self.connected = true;
        self.time_response = now;
        self.connection_errors = 0;
        self.retry_after = 0;
        self.reputation += 1;
    }

    /// A dial or handshake failed/timed out: back the peer off exponentially
    /// (EpixNet-style `min(3600, 15 << errors)` seconds) so selection stops
    /// burning time on it every pass, and dock its reputation.
    pub fn note_connect_fail(&mut self, now: i64) {
        self.connected = false;
        self.connection_errors += 1;
        self.reputation -= 1;
        let shift = self.connection_errors.min(8);
        self.retry_after = now + (15i64 << shift).min(3600);
    }

    /// A file downloaded from the peer and verified: the strongest positive
    /// signal a peer can give.
    pub fn note_file_ok(&mut self, now: i64) {
        self.time_response = now;
        self.reputation += 1;
    }

    /// A file fetch failed (refused, timed out, or hash mismatch). Reputation
    /// only - the dial itself worked, and the peer may serve other files, so
    /// it is deprioritized rather than backed off.
    pub fn note_file_fail(&mut self) {
        self.reputation -= 1;
    }

    /// A Tor onion peer.
    pub fn is_onion(&self) -> bool {
        matches!(self.addr, PeerAddr::Onion { .. })
    }

    /// Can we dial it? IP peers with a real listen port, plus all onion/RNS
    /// peers. An IP peer with port 0 only ever dialed us - not connectable.
    pub fn is_connectable(&self) -> bool {
        match &self.addr {
            PeerAddr::Ip(sa) => sa.port() != 0,
            PeerAddr::Onion { port, .. } => *port != 0,
            // I2P is addressed by destination, not port - always dialable.
            PeerAddr::I2p { .. } | PeerAddr::Rns(_) => true,
        }
    }

    /// A private/loopback LAN peer.
    pub fn is_local(&self) -> bool {
        match &self.addr {
            PeerAddr::Ip(SocketAddr::V4(v4)) => {
                v4.ip().is_private() || v4.ip().is_loopback() || v4.ip().is_link_local()
            }
            PeerAddr::Ip(SocketAddr::V6(v6)) => {
                let ip = IpAddr::V6(*v6.ip());
                ip.is_loopback()
            }
            _ => false,
        }
    }
}

/// Aggregate peer counts, as the sidebar's peer graph renders them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerCounts {
    pub total: usize,
    pub connected: usize,
    pub connectable: usize,
    pub onion: usize,
    pub local: usize,
}

/// A xite's peer set.
#[derive(Debug, Default)]
pub struct Peers {
    map: HashMap<String, Peer>,
}

impl Peers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert a peer if unknown (returns whether it was newly added).
    pub fn add(&mut self, addr: PeerAddr, now: i64) -> bool {
        self.restore(Peer::new(addr, now))
    }

    /// Add many peers, returning how many were new.
    pub fn add_many(&mut self, addrs: impl IntoIterator<Item = PeerAddr>, now: i64) -> usize {
        addrs.into_iter().filter(|a| self.add(a.clone(), now)).count()
    }

    pub fn restore(&mut self, peer: Peer) -> bool {
        let key = peer.key();
        if self.map.contains_key(&key) {
            return false;
        }
        self.map.insert(key, peer);
        true
    }

    pub fn get(&self, addr: &PeerAddr) -> Option<&Peer> {
        self.map.get(&addr.to_string())
    }

    pub fn get_mut(&mut self, addr: &PeerAddr) -> Option<&mut Peer> {
        self.map.get_mut(&addr.to_string())
    }

    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.map.values()
    }

    /// Mark a peer connected/disconnected, updating `time_response` on connect.
    pub fn set_connected(&mut self, addr: &PeerAddr, connected: bool, now: i64) {
        if let Some(peer) = self.map.get_mut(&addr.to_string()) {
            peer.connected = connected;
            if connected {
                peer.time_response = now;
                peer.connection_errors = 0;
            }
        }
    }

    /// Drop peers that keep failing and haven't answered recently (or ever).
    /// Without eviction a dead address - a node's old port after a config
    /// change, or an adopted ephemeral port - stays in the table forever,
    /// gets persisted to peers.json, and keeps spreading to other nodes via
    /// PEX. Six consecutive failures is past the backoff ceiling, so the
    /// peer got a fair retry window before it is dropped; a currently
    /// connected peer is never evicted. Returns how many were removed.
    pub fn evict_dead(&mut self, now: i64) -> usize {
        const MAX_ERRORS: u32 = 6;
        const RESPONSE_GRACE_SECS: i64 = 4 * 3600;
        self.retain(|p| {
            if p.connected || p.connection_errors < MAX_ERRORS {
                return true;
            }
            p.time_response != 0 && now - p.time_response < RESPONSE_GRACE_SECS
        })
    }

    /// Drop every peer failing the predicate, returning how many were
    /// removed. The persist janitor uses this to purge entries that never
    /// belonged (malformed placeholder shapes, the node's own addresses).
    pub fn retain(&mut self, keep: impl Fn(&Peer) -> bool) -> usize {
        let before = self.map.len();
        self.map.retain(|_, p| keep(p));
        before - self.map.len()
    }

    /// Record transferred bytes against a peer.
    pub fn record_transfer(&mut self, addr: &PeerAddr, recv: u64, sent: u64) {
        if let Some(peer) = self.map.get_mut(&addr.to_string()) {
            peer.bytes_recv += recv;
            peer.bytes_sent += sent;
        }
    }

    /// The connectable peer addresses (for the worker), best reputation first.
    /// Network-blind and backoff-blind; prefer [`Self::connectable_dialable`]
    /// when the caller knows which networks it can dial.
    pub fn connectable(&self, limit: usize) -> Vec<PeerAddr> {
        let mut peers: Vec<&Peer> = self.map.values().filter(|p| p.is_connectable()).collect();
        peers.sort_by(|a, b| b.reputation.cmp(&a.reputation));
        peers.into_iter().take(limit).map(|p| p.addr.clone()).collect()
    }

    /// The peers a sync pass should actually try: connectable, on a network
    /// this node can dial right now, and not in failure backoff - so a
    /// clearnet-only node stops handing the worker onion/i2p peers it can
    /// never reach (which crowded reachable peers out of the `limit`), and
    /// dead peers stop being redialed every pass.
    ///
    /// Ordering: REPUTATION first, then dialable clearnet before overlay (a
    /// direct socket is faster than a circuit) as the tiebreak, then fewer
    /// connection errors, then most recent response. Reputation must outrank
    /// the network preference: on a xite with more clearnet peers than the
    /// limit, a network-first sort returns an all-clearnet list forever, and
    /// an overlay-only publisher (the one peer that HAS a pending update's
    /// files) is never dialed no matter how often the clearnet peers fail.
    /// Reputation-first converges: one failed pass sinks the useless peers
    /// below the untried ones.
    ///
    /// Fallback: if the filters leave nothing but connectable peers exist,
    /// degrade gracefully - first drop the backoff filter (all candidates
    /// backed off: retrying early beats idling), then the network filter (an
    /// overlay-only xite on a node whose overlay is still warming up must
    /// still get candidates rather than starve). A node with any reachable
    /// peer can therefore never regress to an empty list.
    pub fn connectable_dialable(&self, limit: usize, nets: DialableNets, now: i64) -> Vec<PeerAddr> {
        let connectable: Vec<&Peer> =
            self.map.values().filter(|p| p.is_connectable()).collect();
        let mut peers: Vec<&Peer> = connectable
            .iter()
            .copied()
            .filter(|p| nets.can_dial(&p.addr) && p.retry_after <= now)
            .collect();
        if peers.is_empty() {
            peers = connectable.iter().copied().filter(|p| nets.can_dial(&p.addr)).collect();
        }
        if peers.is_empty() {
            peers = connectable;
        }
        let net_rank = |p: &Peer| if p.addr.is_overlay() { 1 } else { 0 };
        peers.sort_by(|a, b| {
            b.reputation
                .cmp(&a.reputation)
                .then(net_rank(a).cmp(&net_rank(b)))
                .then(a.connection_errors.cmp(&b.connection_errors))
                .then(b.time_response.cmp(&a.time_response))
        });
        peers.into_iter().take(limit).map(|p| p.addr.clone()).collect()
    }

    pub fn counts(&self) -> PeerCounts {
        let mut c = PeerCounts { total: self.map.len(), ..Default::default() };
        for peer in self.map.values() {
            if peer.connected {
                c.connected += 1;
            }
            if peer.is_connectable() {
                c.connectable += 1;
            }
            if peer.is_onion() {
                c.onion += 1;
            }
            if peer.is_local() {
                c.local += 1;
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> PeerAddr {
        PeerAddr::parse(s).unwrap()
    }

    #[test]
    fn classifies_peers() {
        let clearnet = Peer::new(ip("8.8.8.8:15441"), 0);
        assert!(clearnet.is_connectable() && !clearnet.is_onion() && !clearnet.is_local());

        let inbound_only = Peer::new(ip("8.8.8.8:0"), 0);
        assert!(!inbound_only.is_connectable(), "port 0 = dialed us, not connectable");

        let lan = Peer::new(ip("192.168.1.5:15441"), 0);
        assert!(lan.is_local() && lan.is_connectable());

        let onion = Peer::new(ip("expyuzz4wqqyqhjn.onion:15441"), 0);
        assert!(onion.is_onion() && onion.is_connectable() && !onion.is_local());
    }

    #[test]
    fn registry_counts_and_dedupes() {
        let mut peers = Peers::new();
        assert_eq!(peers.add_many([ip("8.8.8.8:15441"), ip("192.168.0.2:15441"), ip("expyuzz4wqqyqhjn.onion:15441")], 100), 3);
        assert_eq!(peers.add(ip("8.8.8.8:15441"), 100), false, "dedupe");
        assert!(peers.add(ip("8.8.8.8:0"), 100), "different port = different peer");

        peers.set_connected(&ip("8.8.8.8:15441"), true, 200);
        peers.record_transfer(&ip("8.8.8.8:15441"), 1000, 40);

        let c = peers.counts();
        assert_eq!(c.total, 4);
        assert_eq!(c.connected, 1);
        assert_eq!(c.onion, 1);
        assert_eq!(c.local, 1);
        assert_eq!(c.connectable, 3, "the :0 peer is not connectable");

        assert_eq!(peers.get(&ip("8.8.8.8:15441")).unwrap().bytes_recv, 1000);
        assert_eq!(peers.connectable(10).len(), 3);
    }

    /// Networks: clearnet only (the common cold-start node).
    fn clearnet_only() -> DialableNets {
        DialableNets { clearnet: true, onion: false, i2p: false, rns: false }
    }

    #[test]
    fn dialable_filter_excludes_unreachable_networks() {
        let mut peers = Peers::new();
        peers.add(ip("8.8.8.8:15441"), 0);
        peers.add(ip("expyuzz4wqqyqhjn.onion:15441"), 0);

        // A clearnet-only node gets only the clearnet peer...
        let got = peers.connectable_dialable(10, clearnet_only(), 100);
        assert_eq!(got, vec![ip("8.8.8.8:15441")]);

        // ...but an onion-only xite still gets its onion peer (fallback)
        // instead of an empty list.
        let mut onion_only = Peers::new();
        onion_only.add(ip("expyuzz4wqqyqhjn.onion:15441"), 0);
        let got = onion_only.connectable_dialable(10, clearnet_only(), 100);
        assert_eq!(got, vec![ip("expyuzz4wqqyqhjn.onion:15441")]);

        // With Tor dialable, both come back, clearnet preferred.
        let got = peers.connectable_dialable(10, DialableNets::all(), 100);
        assert_eq!(got[0], ip("8.8.8.8:15441"));
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn backoff_excludes_then_readmits_failed_peers() {
        let mut peers = Peers::new();
        peers.add(ip("1.1.1.1:15441"), 0);
        peers.add(ip("2.2.2.2:15441"), 0);

        // 1.1.1.1 failed a dial at t=100: backed off 30s (15 << 1).
        peers.get_mut(&ip("1.1.1.1:15441")).unwrap().note_connect_fail(100);
        let got = peers.connectable_dialable(10, DialableNets::all(), 101);
        assert_eq!(got, vec![ip("2.2.2.2:15441")], "backed-off peer skipped");

        // After the window it comes back (ranked last: reputation dropped).
        let got = peers.connectable_dialable(10, DialableNets::all(), 200);
        assert_eq!(got, vec![ip("2.2.2.2:15441"), ip("1.1.1.1:15441")]);

        // Repeated failures grow the window exponentially, capped at 3600.
        let p = peers.get_mut(&ip("1.1.1.1:15441")).unwrap();
        for _ in 0..10 {
            p.note_connect_fail(1000);
        }
        assert_eq!(p.retry_after, 1000 + 3600, "cap");
        assert_eq!(p.connection_errors, 11);

        // A success clears everything.
        p.note_connect_ok(2000);
        assert_eq!(p.connection_errors, 0);
        assert_eq!(p.retry_after, 0);
        assert!(p.connected);

        // If EVERY candidate is backed off, selection degrades to retrying
        // them rather than returning nothing.
        let mut all_down = Peers::new();
        all_down.add(ip("3.3.3.3:15441"), 0);
        all_down.get_mut(&ip("3.3.3.3:15441")).unwrap().note_connect_fail(100);
        let got = all_down.connectable_dialable(10, DialableNets::all(), 101);
        assert_eq!(got, vec![ip("3.3.3.3:15441")], "never starve the caller");
    }

    #[test]
    fn evict_dead_drops_never_working_peers_after_repeated_failures() {
        let mut peers = Peers::new();
        peers.add(ip("9.9.9.9:4833"), 0); // a stale port that never answers
        peers.add(ip("8.8.8.8:15441"), 0); // untouched, healthy candidate

        // Five failures: still kept (inside the retry window).
        for _ in 0..5 {
            peers.get_mut(&ip("9.9.9.9:4833")).unwrap().note_connect_fail(100);
        }
        assert_eq!(peers.evict_dead(200), 0);
        assert_eq!(peers.len(), 2);

        // The sixth failure crosses the threshold: evicted, so it stops being
        // persisted and PEX-shared. The untried peer stays.
        peers.get_mut(&ip("9.9.9.9:4833")).unwrap().note_connect_fail(100);
        assert_eq!(peers.evict_dead(200), 1);
        assert_eq!(peers.len(), 1);
        assert!(peers.get(&ip("8.8.8.8:15441")).is_some());
    }

    #[test]
    fn evict_dead_spares_recently_working_and_connected_peers() {
        let now = 10_000;
        let mut peers = Peers::new();

        // Worked an hour ago, now failing: kept (grace window).
        peers.add(ip("1.1.1.1:15441"), 0);
        let p = peers.get_mut(&ip("1.1.1.1:15441")).unwrap();
        p.time_response = now - 3600;
        for _ in 0..8 {
            p.note_connect_fail(now);
        }
        p.time_response = now - 3600; // note_connect_fail doesn't touch it, be explicit

        // Currently connected: never evicted regardless of error count.
        peers.add(ip("2.2.2.2:15441"), 0);
        let p = peers.get_mut(&ip("2.2.2.2:15441")).unwrap();
        p.connection_errors = 20;
        p.connected = true;

        // Last answered days ago and keeps failing: evicted.
        peers.add(ip("3.3.3.3:15441"), 0);
        let p = peers.get_mut(&ip("3.3.3.3:15441")).unwrap();
        p.time_response = now - 7 * 86_400;
        p.connection_errors = 20;

        assert_eq!(peers.evict_dead(now), 1);
        assert!(peers.get(&ip("1.1.1.1:15441")).is_some(), "recent responder kept");
        assert!(peers.get(&ip("2.2.2.2:15441")).is_some(), "connected peer kept");
        assert!(peers.get(&ip("3.3.3.3:15441")).is_none(), "long-dead peer dropped");
    }

    #[test]
    fn overlay_publisher_gets_selected_despite_a_clearnet_majority() {
        // The gateway stall: ~19 connectable clearnet peers serving the OLD
        // site version and one onion publisher holding a pending update's
        // files, selection limit 10. Every pass the clearnet peers connect
        // fine but fail the file hashes (reputation drops, no backoff). The
        // publisher must be selected after the first failed pass - with the
        // old network-first ordering it never was, and the update stalled
        // forever.
        let mut peers = Peers::new();
        for i in 1..=19 {
            peers.add(ip(&format!("10.0.0.{i}:26552")), 0);
        }
        let publisher = ip("6m4j2es4wom2xyhlvj4vjmsdsabqascped5d7t7knz3w2ku5hqlywwid.onion:26552");
        peers.add(publisher.clone(), 0);

        let mut committed = false;
        for pass in 0..3 {
            let selected = peers.connectable_dialable(10, DialableNets::all(), 100 + pass);
            assert_eq!(selected.len(), 10);
            if selected.contains(&publisher) {
                committed = true;
                break;
            }
            // Each selected clearnet peer connects but serves stale files:
            // ConnectOk then two FileFails, like the real retry pass.
            for addr in selected {
                let p = peers.get_mut(&addr).unwrap();
                p.note_connect_ok(100 + pass);
                p.note_file_fail();
                p.note_file_fail();
            }
        }
        assert!(committed, "the onion publisher was never selected");
    }

    #[test]
    fn selection_orders_by_reputation_then_errors_then_recency() {
        let mut peers = Peers::new();
        for (a, rep, errs, resp) in [
            ("1.1.1.1:1", 5, 0, 50),
            ("2.2.2.2:1", 5, 2, 90),
            ("3.3.3.3:1", 9, 0, 10),
            ("4.4.4.4:1", 5, 0, 90),
        ] {
            peers.add(ip(a), 0);
            let p = peers.get_mut(&ip(a)).unwrap();
            p.reputation = rep;
            p.connection_errors = errs;
            p.time_response = resp;
        }
        let got = peers.connectable_dialable(10, DialableNets::all(), 100);
        assert_eq!(
            got,
            vec![ip("3.3.3.3:1"), ip("4.4.4.4:1"), ip("1.1.1.1:1"), ip("2.2.2.2:1")],
            "reputation first, then fewer errors, then most recent response"
        );
    }
}
