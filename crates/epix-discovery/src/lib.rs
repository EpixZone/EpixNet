//! `epix-discovery` - finding peers for a xite.
//!
//! The primary method on the live network is the **Epix tracker** (`epix://`):
//! an `announce` request over the ordinary EpixNet wire protocol (so it reuses
//! [`epix_protocol::Connection`]). BitTorrent trackers, the mainline DHT, PEX,
//! and local discovery will be added alongside it.

pub mod tracker;

use sha2::{Digest, Sha256};

/// A xite's tracker hash: `sha256(address)` (matches the reference address_hash).
pub fn address_hash(address: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(address.as_bytes());
    h.finalize().into()
}

pub use tracker::{announce, discover_via_epix_tracker, AnnounceParams};
