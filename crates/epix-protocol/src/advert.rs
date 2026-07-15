//! The node's handshake self-advertisement: which dial-back addresses an
//! outbound handshake offers the peer we are talking to.
//!
//! An inbound connection arrives from an ephemeral port (clearnet) or a blank
//! placeholder address (onion/i2p) - without an advertised self-address the
//! receiver can never dial the caller back, so an overlay-only publisher that
//! pushes an update stays unreachable until PEX or a tracker happens to name
//! it. The handshake fixes that at first contact, the same way the Python
//! client's `onion` handshake key does.
//!
//! Which address is offered follows the CONNECTION's transport class, so a
//! self-address is only ever claimed where it adds no linkage (the Python
//! client's policy):
//!   - dialing an onion peer: our onion (the wire already rides Tor);
//!   - dialing an i2p peer: our i2p destination;
//!   - dialing a mesh peer: our rns destination hash;
//!   - dialing clearnet directly: only the fileserver port (the peer sees our
//!     real IP anyway; never our onion - a clearnet handshake must not link
//!     IP and onion);
//!   - dialing clearnet through Tor (Always mode, `tor_always`): our onion -
//!     the source the peer sees is a Tor exit, so the onion is our only
//!     dialable identity and no real IP exists to link against.
//!
//! The advert is process-global (one node per process), like the chain-RPC
//! SOCKS setting in `epix-chain`: the runtime seeds it at startup and the
//! tor/i2p/mesh loops fill in each overlay address as it comes up, so every
//! `Connection::handshake()` call site picks the current addresses up without
//! threading node state through the protocol layer.

use std::sync::RwLock;

/// What this node can advertise about itself in an outbound handshake.
/// Overlay hosts use the registry-native shapes: onion host without `.onion`,
/// i2p destination without `.i2p` (the `<b32>.b32` short form), rns as the
/// destination-hash hex.
#[derive(Clone, Debug, Default)]
pub struct SelfAdvert {
    /// The node's release version (e.g. `0.3.9` from the git tag), reported in
    /// both the handshake request and reply so peers see the real build, not
    /// epix-protocol's own crate version. Empty falls back to that crate
    /// version (request) or the server's default banner (reply).
    pub version: String,
    /// Our fileserver port; 0 when not seeding. Doubles as the port a peer
    /// dials our onion/i2p address on (the onion service maps it 1:1).
    pub fileserver_port: u16,
    /// Whether the clearnet port is confirmed reachable (an inbound public
    /// peer completed a handshake). Python peers ignore an advertised port
    /// when this is false and no onion is offered.
    pub port_opened: bool,
    /// Tor-Always mode: every dial rides Tor, so clearnet peers see a Tor
    /// exit as our source - advertise the onion to them too.
    pub tor_always: bool,
    /// Our onion host (no `.onion` suffix), once the service is up.
    pub onion: Option<String>,
    /// Our i2p destination (no `.i2p` suffix), once the inbound session is up.
    pub i2p: Option<String>,
    /// Our Reticulum destination hash (hex), once the mesh is up.
    pub rns: Option<String>,
}

static SELF_ADVERT: RwLock<Option<SelfAdvert>> = RwLock::new(None);

/// Replace the node's self-advertisement (the runtime seeds it at startup).
pub fn set_self_advert(advert: SelfAdvert) {
    if let Ok(mut w) = SELF_ADVERT.write() {
        *w = Some(advert);
    }
}

/// Update one or more fields of the current advert in place - the overlay
/// loops use this as each address comes up (onion ~10-40s after start, i2p
/// minutes, mesh immediately).
pub fn update_self_advert(f: impl FnOnce(&mut SelfAdvert)) {
    if let Ok(mut w) = SELF_ADVERT.write() {
        f(w.get_or_insert_with(SelfAdvert::default));
    }
}

/// Run `f` against the current advert under the read lock, without cloning it.
/// A handshake only serializes the version plus one address, so borrowing and
/// cloning just those (inside `f`) avoids a full-struct clone per handshake -
/// on a phone that dials many peers, per-connection allocation adds up. When
/// the advert was never set (or the lock is poisoned) `f` sees the default
/// (empty) advert - the pre-Phase-6 wire shape.
pub(crate) fn with_self_advert<R>(f: impl FnOnce(&SelfAdvert) -> R) -> R {
    match SELF_ADVERT.read() {
        Ok(guard) => match guard.as_ref() {
            Some(advert) => f(advert),
            None => f(&SelfAdvert::default()),
        },
        Err(_) => f(&SelfAdvert::default()),
    }
}
