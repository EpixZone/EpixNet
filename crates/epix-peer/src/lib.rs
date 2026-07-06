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
            connected: false,
            bytes_recv: 0,
            bytes_sent: 0,
        }
    }

    /// Stable registry key (the address string).
    pub fn key(&self) -> String {
        self.addr.to_string()
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
        let key = addr.to_string();
        if self.map.contains_key(&key) {
            return false;
        }
        self.map.insert(key, Peer::new(addr, now));
        true
    }

    /// Add many peers, returning how many were new.
    pub fn add_many(&mut self, addrs: impl IntoIterator<Item = PeerAddr>, now: i64) -> usize {
        addrs.into_iter().filter(|a| self.add(a.clone(), now)).count()
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

    /// Record transferred bytes against a peer.
    pub fn record_transfer(&mut self, addr: &PeerAddr, recv: u64, sent: u64) {
        if let Some(peer) = self.map.get_mut(&addr.to_string()) {
            peer.bytes_recv += recv;
            peer.bytes_sent += sent;
        }
    }

    /// The connectable peer addresses (for the worker), best reputation first.
    pub fn connectable(&self, limit: usize) -> Vec<PeerAddr> {
        let mut peers: Vec<&Peer> = self.map.values().filter(|p| p.is_connectable()).collect();
        peers.sort_by(|a, b| b.reputation.cmp(&a.reputation));
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
}
