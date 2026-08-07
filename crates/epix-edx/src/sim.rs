//! In-process swarm simulation harness.
//!
//! Phase B's scheduler and choker are developed AGAINST this harness,
//! not validated after the fact: it yields real `PeerStream`s (so the
//! whole EDX stack runs unmodified) whose links impose per-class latency
//! and bandwidth — clearnet, I2P and Tor differ by 10-30x, and every
//! algorithm that survives only on clearnet numbers is broken by design.
//!
//! Run tests under `#[tokio::test(start_paused = true)]`: virtual time
//! auto-advances through the shaping sleeps, so a simulated multi-second
//! Tor transfer completes in milliseconds of wall clock while elapsed
//! virtual time stays exact and deterministic.
//!
//! The model: each direction of a link has a pacing stage (serialization
//! at `bandwidth` bytes/s — models the sender's uplink) feeding a delay
//! stage (+`latency` — propagation). Throughput is set by bandwidth
//! alone; latency is additive and never throttles the pipe (a 500 ms /
//! 2 MB/s Tor link still moves 2 MB/s once flowing).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use epix_core::PeerAddr;
use epix_transport::{PeerStream, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Latency/bandwidth class of a simulated link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// ~30 ms, 12 MB/s.
    Clearnet,
    /// ~300 ms, 4 MB/s.
    I2p,
    /// ~500 ms, 2 MB/s.
    Tor,
}

impl Class {
    pub fn spec(self) -> LinkSpec {
        match self {
            Class::Clearnet => LinkSpec { latency: Duration::from_millis(30), bandwidth: 12_000_000 },
            Class::I2p => LinkSpec { latency: Duration::from_millis(300), bandwidth: 4_000_000 },
            Class::Tor => LinkSpec { latency: Duration::from_millis(500), bandwidth: 2_000_000 },
        }
    }

    /// Default class for an address scheme (overridable per address).
    ///
    /// In Tor-always mode ([`epix_core::route_all_via_overlay`]) a PUBLIC Ip
    /// peer is reached through an exit circuit, so it needs overlay batches
    /// and stall windows - clearnet sizing there (1 MiB batches, a 4s stall
    /// window) manufactured false stalls on what is really a Tor path. The
    /// dial-timeout and dial-permit paths already make this same check.
    /// Private/LAN addresses stay clearnet even then: an exit cannot reach
    /// RFC1918, so those dials bypass the exit path, and a LAN peer is the
    /// one genuinely fast class.
    pub fn of_addr(addr: &PeerAddr) -> Self {
        match addr {
            PeerAddr::Ip(_) if addr.is_private() => Class::Clearnet,
            PeerAddr::Ip(_) if epix_core::route_all_via_overlay() => Class::Tor,
            PeerAddr::Ip(_) => Class::Clearnet,
            PeerAddr::I2p { .. } => Class::I2p,
            PeerAddr::Onion { .. } | PeerAddr::Rns(_) => Class::Tor,
        }
    }
}

/// One-way link parameters.
#[derive(Clone, Copy, Debug)]
pub struct LinkSpec {
    pub latency: Duration,
    /// Bytes per second.
    pub bandwidth: u64,
}

/// Counters the gate tests assert against.
#[derive(Debug, Default)]
pub struct SimMetrics {
    pub bytes_delivered: AtomicU64,
    pub links_opened: AtomicU64,
    pub dials_failed: AtomicU64,
}

impl SimMetrics {
    pub fn delivered(&self) -> u64 {
        self.bytes_delivered.load(Ordering::Relaxed)
    }
}

type Inbox = mpsc::UnboundedSender<(PeerAddr, PeerStream)>;

/// The virtual network: listeners keyed by address, per-address class
/// overrides, shared metrics.
#[derive(Default)]
pub struct SimNet {
    listeners: Mutex<HashMap<PeerAddr, Inbox>>,
    classes: Mutex<HashMap<PeerAddr, Class>>,
    pub metrics: Arc<SimMetrics>,
}

impl SimNet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a node; incoming connections arrive on the receiver as
    /// (dialer address, stream).
    pub fn listen(&self, addr: PeerAddr) -> mpsc::UnboundedReceiver<(PeerAddr, PeerStream)> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.listeners.lock().expect("sim lock").insert(addr, tx);
        rx
    }

    /// Force a specific class for links dialed TO this address.
    pub fn set_class(&self, addr: PeerAddr, class: Class) {
        self.classes.lock().expect("sim lock").insert(addr, class);
    }

    fn class_for(&self, addr: &PeerAddr) -> Class {
        self.classes
            .lock()
            .expect("sim lock")
            .get(addr)
            .copied()
            .unwrap_or_else(|| Class::of_addr(addr))
    }

    /// Open a link from `from` to `to`, delivering the far end to the
    /// listener. Both directions get the target's class spec.
    pub fn connect(&self, from: PeerAddr, to: &PeerAddr) -> std::io::Result<PeerStream> {
        let spec = self.class_for(to).spec();
        let inbox = {
            let listeners = self.listeners.lock().expect("sim lock");
            listeners.get(to).cloned()
        };
        let Some(inbox) = inbox else {
            self.metrics.dials_failed.fetch_add(1, Ordering::Relaxed);
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("no sim listener at {to:?}"),
            ));
        };
        let (near, far) = shaped_pair(spec, self.metrics.clone());
        if inbox.send((from, far)).is_err() {
            self.metrics.dials_failed.fetch_add(1, Ordering::Relaxed);
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                format!("sim listener at {to:?} is gone"),
            ));
        }
        self.metrics.links_opened.fetch_add(1, Ordering::Relaxed);
        Ok(near)
    }
}

/// A `Transport` view of the sim for one node (its own address is the
/// dialer identity handed to listeners).
pub struct SimTransport {
    pub net: Arc<SimNet>,
    pub local: PeerAddr,
}

#[async_trait::async_trait]
impl Transport for SimTransport {
    fn scheme(&self) -> &'static str {
        "sim"
    }

    async fn dial(&self, addr: &PeerAddr) -> epix_core::Result<PeerStream> {
        self.net
            .connect(self.local.clone(), addr)
            .map_err(|e| epix_core::Error::Protocol(format!("sim dial {addr:?}: {e}")))
    }
}

/// Build a shaped bidirectional stream pair.
fn shaped_pair(spec: LinkSpec, metrics: Arc<SimMetrics>) -> (PeerStream, PeerStream) {
    let (a_user, a_net) = tokio::io::duplex(256 * 1024);
    let (b_user, b_net) = tokio::io::duplex(256 * 1024);
    let (a_read, a_write) = tokio::io::split(a_net);
    let (b_read, b_write) = tokio::io::split(b_net);
    spawn_shaper(a_read, b_write, spec, metrics.clone());
    spawn_shaper(b_read, a_write, spec, metrics);
    (Box::pin(a_user), Box::pin(b_user))
}

fn spawn_shaper(
    mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    spec: LinkSpec,
    metrics: Arc<SimMetrics>,
) {
    // Stage 1 paces reads at the link bandwidth (sender serialization);
    // stage 2 delivers each chunk `latency` later (propagation). The
    // bounded queue is the in-flight window.
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(64);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        let mut next_free = Instant::now();
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let now = Instant::now();
            let ser = Duration::from_secs_f64(n as f64 / spec.bandwidth as f64);
            next_free = next_free.max(now) + ser;
            tokio::time::sleep_until(next_free).await;
            if tx.send((next_free + spec.latency, buf[..n].to_vec())).await.is_err() {
                break;
            }
        }
        // tx drops here; the deliverer drains and closes the far side.
    });
    tokio::spawn(async move {
        while let Some((deliver_at, chunk)) = rx.recv().await {
            tokio::time::sleep_until(deliver_at).await;
            if to.write_all(&chunk).await.is_err() {
                break;
            }
            metrics.bytes_delivered.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
        let _ = to.shutdown().await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn ip(port: u16) -> PeerAddr {
        PeerAddr::Ip(SocketAddr::from(([10, 0, 0, 1], port)))
    }

    fn onion(name: &str) -> PeerAddr {
        PeerAddr::Onion { host: name.into(), port: 1 }
    }

    /// Echo RTT over clearnet ~= 2x latency (+epsilon for serialization).
    #[tokio::test(start_paused = true)]
    async fn clearnet_rtt_is_twice_latency() {
        let net = SimNet::new();
        let server = ip(1);
        let mut inbox = net.listen(server.clone());
        tokio::spawn(async move {
            let (_, mut stream) = inbox.recv().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
        });

        let t = SimTransport { net: net.clone(), local: ip(2) };
        let start = Instant::now();
        let mut s = t.dial(&server).await.unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        let rtt = start.elapsed();
        let expect = Class::Clearnet.spec().latency * 2;
        assert!(
            rtt >= expect && rtt < expect + Duration::from_millis(20),
            "rtt {rtt:?} vs expected ~{expect:?}"
        );
    }

    /// 1 MB over a Tor link arrives in ~latency + size/bandwidth virtual
    /// time — latency must NOT throttle throughput.
    #[tokio::test(start_paused = true)]
    async fn tor_bandwidth_is_not_latency_bound() {
        let net = SimNet::new();
        let server = onion("srv");
        let mut inbox = net.listen(server.clone());
        const MB: usize = 1_000_000;
        tokio::spawn(async move {
            let (_, mut stream) = inbox.recv().await.unwrap();
            let mut got = vec![0u8; MB];
            stream.read_exact(&mut got).await.unwrap();
            stream.write_all(b"k").await.unwrap();
        });

        let t = SimTransport { net: net.clone(), local: ip(2) };
        let start = Instant::now();
        let mut s = t.dial(&server).await.unwrap();
        s.write_all(&vec![7u8; MB]).await.unwrap();
        let mut ack = [0u8; 1];
        s.read_exact(&mut ack).await.unwrap();
        let took = start.elapsed();

        let spec = Class::Tor.spec();
        // serialization (0.5 s) + 2x latency (1.0 s) + ack serialization.
        let expect = Duration::from_secs_f64(MB as f64 / spec.bandwidth as f64) + spec.latency * 2;
        assert!(
            took >= expect && took < expect + Duration::from_millis(200),
            "took {took:?}, expected ~{expect:?} — if this is ~8x larger, \
             latency is throttling the pipe (chunk-per-RTT bug)"
        );
        assert!(net.metrics.delivered() >= MB as u64);
    }

    /// Tor and clearnet must actually differ by an order of magnitude —
    /// the whole point of per-class scheduling.
    #[tokio::test(start_paused = true)]
    async fn classes_differ_by_an_order_of_magnitude() {
        let c = Class::Clearnet.spec();
        let t = Class::Tor.spec();
        assert!(t.latency >= c.latency * 10);
        assert!(c.bandwidth >= t.bandwidth * 5);
    }

    /// In Tor-always mode a PUBLIC Ip peer rides an exit circuit and must be
    /// classed overlay so it gets overlay batches and stall windows; a
    /// private/LAN peer is dialed directly (an exit cannot reach RFC1918)
    /// and must stay clearnet - it is the one genuinely fast class. One test
    /// covers both flag states: the flag is process-global, so a separate
    /// test asserting the default would race the toggle.
    #[test]
    fn tor_always_classes_public_ip_as_overlay_but_never_lan() {
        use epix_core::set_route_all_via_overlay;
        let public = PeerAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 26552)));
        let lan = PeerAddr::Ip(SocketAddr::from(([192, 168, 1, 5], 26552)));
        let ten = PeerAddr::Ip(SocketAddr::from(([10, 0, 0, 1], 26552)));
        let lo = PeerAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 26552)));

        // Clearnet default: the address type alone decides.
        assert_eq!(Class::of_addr(&public), Class::Clearnet);
        assert_eq!(Class::of_addr(&lan), Class::Clearnet);

        set_route_all_via_overlay(true);
        let classed = (
            Class::of_addr(&public),
            Class::of_addr(&lan),
            Class::of_addr(&ten),
            Class::of_addr(&lo),
            Class::of_addr(&onion("x")),
        );
        // Restore before asserting so a failure cannot leave the global on.
        set_route_all_via_overlay(false);
        assert_eq!(classed.0, Class::Tor, "a public Ip peer rides an exit circuit");
        assert_eq!(classed.1, Class::Clearnet, "RFC1918 bypasses the exit; LAN stays fast");
        assert_eq!(classed.2, Class::Clearnet, "10/8 is private too");
        assert_eq!(classed.3, Class::Clearnet, "loopback is never an exit path");
        assert_eq!(classed.4, Class::Tor, "onions are overlay either way");
    }

    /// Dialing nowhere fails and is counted.
    #[tokio::test(start_paused = true)]
    async fn dial_without_listener_fails() {
        let net = SimNet::new();
        let t = SimTransport { net: net.clone(), local: ip(1) };
        assert!(t.dial(&ip(99)).await.is_err());
        assert_eq!(net.metrics.dials_failed.load(Ordering::Relaxed), 1);
    }
}
