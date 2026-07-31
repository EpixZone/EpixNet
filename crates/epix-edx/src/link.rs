//! Assembled EDX link establishment: the glue that turns a freshly
//! connected transport stream into a live multiplexed [`Conn`].
//!
//! The pieces existed separately (the [`frame`] magic, the [`noise`]
//! handshake, [`Conn::start`]) but nothing joined them, so every caller
//! had to reproduce the exact order. This module is that order, once:
//!
//! - dialer: `write magic -> read magic -> Noise-XX initiator -> Conn`
//! - acceptor: `read magic -> write magic -> Noise-XX responder -> Conn`
//!
//! The magic travels in the clear, so a clearnet accept loop can drop a
//! connection that is not an EDX peer on its first byte before spending a
//! Noise handshake on it (see `epix_protocol::PeerServer`).

use std::io;

use epix_transport::PeerStream;
use tokio::sync::mpsc;

use crate::conn::{Conn, Incoming};
use crate::frame;
use crate::noise;

/// A live EDX link: the multiplexed connection, its inbound-request
/// receiver (drop it for a pure client), and the Noise handshake hash the
/// Hello channel binding signs (see [`crate::server::client_hello`]).
pub struct Link {
    pub conn: Conn,
    pub incoming: mpsc::Receiver<Incoming>,
    pub handshake_hash: [u8; 32],
}

/// Establish an EDX link as the DIALER over an already-connected clearnet
/// stream. Sends the magic first so the peer can route us, exchanges the
/// Noise-XX handshake, and starts the multiplexed connection.
pub async fn dial(stream: PeerStream) -> io::Result<Link> {
    let mut stream = stream;
    frame::write_magic(&mut stream).await?;
    frame::read_magic(&mut stream).await?;
    let sec = noise::secure_initiator(stream).await?;
    let (conn, incoming) = Conn::start(sec.stream, true);
    Ok(Link { conn, incoming, handshake_hash: sec.handshake_hash })
}

/// Establish an EDX link as the ACCEPTOR. The 4-byte magic has NOT been
/// consumed yet (this reads and checks it), so an accepted stream goes in
/// untouched. Answers with our own magic, runs the Noise-XX responder, and
/// starts the connection.
pub async fn accept(stream: PeerStream) -> io::Result<Link> {
    let mut stream = stream;
    frame::read_magic(&mut stream).await?;
    frame::write_magic(&mut stream).await?;
    let sec = noise::secure_responder(stream).await?;
    let (conn, incoming) = Conn::start(sec.stream, false);
    Ok(Link { conn, incoming, handshake_hash: sec.handshake_hash })
}

/// Establish an EDX link over an ALREADY-ENCRYPTED overlay stream
/// (Tor/I2P/Reticulum) as the acceptor: exchange the magic, then SKIP Noise
/// (the transport already encrypts and authenticates the endpoint) and start
/// the mux. There is no Noise channel binding, so serve/client_hello take
/// `None` as the handshake hash; identity rests on the overlay endpoint plus
/// the Hello node key, exactly as the plan describes for overlays.
///
/// Skipping Noise also skips its record deadlines, so the only I/O deadline
/// an overlay link has is the one [`Conn`] applies to each frame write. A
/// peer that stops reading its circuit is unwound by that and nothing else.
pub async fn accept_overlay(stream: PeerStream) -> io::Result<(Conn, mpsc::Receiver<Incoming>)> {
    let mut stream = stream;
    frame::read_magic(&mut stream).await?;
    frame::write_magic(&mut stream).await?;
    Ok(Conn::start(stream, false))
}

/// Dialer counterpart to [`accept_overlay`]: send the magic, skip Noise,
/// start the mux.
pub async fn dial_overlay(stream: PeerStream) -> io::Result<(Conn, mpsc::Receiver<Incoming>)> {
    let mut stream = stream;
    frame::write_magic(&mut stream).await?;
    frame::read_magic(&mut stream).await?;
    Ok(Conn::start(stream, true))
}
