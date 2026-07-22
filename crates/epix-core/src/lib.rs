//! `epix-core` - shared domain types and the UI-agnostic `Emitter` seam.
//!
//! This crate is intentionally free of any platform, UI, async-runtime, or
//! networking dependency. Everything above it (runtime, transports, UI shells)
//! builds on these types and the [`Emitter`] trait.

pub mod address;
pub mod emitter;
pub mod error;
pub mod peer;
pub mod time;

pub use address::{classify_label, Address, LabelClass};
pub use emitter::{CollectingEmitter, Emitter, NoopEmitter};
pub use error::{Error, Result};
pub use peer::{IpType, PeerAddr};
pub use time::{now_ms, now_secs};

/// The default bootstrap announcers: Epix-protocol trackers (`host:port`) and
/// public BitTorrent trackers (announce URLs - rendezvous by `sha1(address)`
/// infohash, the free public infrastructure the Python client also used). A
/// fresh node announces to all of these, so no single machine is a point of
/// failure. Every entry was verified live in July 2026; the Beacon plugin
/// seeds its book with them, health-checks them like any other announcer,
/// prunes the ones that die, and keeps discovering fresh ones from peers - so
/// this list only has to be good enough to reach the network once.
/// (Parse coverage is tested in epix-discovery, where the Tracker type lives.)
pub const DEFAULT_TRACKERS: &[&str] = &[
    // Epix announcers (community nodes speaking the wire protocol), with
    // the transport named explicitly - a node can front its announcer over
    // tcp, onion, or i2p.
    "tcp://51.38.34.170:15441",
    "tcp://74.208.249.9:48333",
    "tcp://111.237.115.101:15441",
    "tcp://145.223.69.23:26959",
    "tcp://161.97.147.133:15441",
    "tcp://194.5.98.39:15441",
    // Reachable over Tor / I2P only; skipped automatically while that
    // overlay is off.
    "onion://fzlzmxuz2bust72cuy5g4w6d62tx624xcjaupf2kp7ffuitbiniy2hqd.onion:15441",
    "onion://jszogollvhtyttpbcdhghuewsbojgdioixvoqphtyq5bqyvfkjx3k5qd.onion:48333",
    "i2p://ashvjmdch2622mesfch2qsuc6kkzl2xbtgfltr7nqjs5qtrsfbva.b32.i2p:48333",
    // Public BitTorrent trackers (hostname form - they survive IP churn).
    "udp://tracker.opentrackr.org:1337/announce",
    "udp://open.stealth.si:80/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://tracker.dler.org:6969/announce",
    "http://tracker.opentrackr.org:1337/announce",
];
