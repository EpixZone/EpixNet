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
//! The magic travels in the clear so a coexisting msgpack node can be told
//! apart at accept time by its first byte ([`frame::sniff`]). Because an
//! overlay stream (Tor/I2P/Reticulum) cannot be `peek`ed like a raw TCP
//! socket, [`read_sniff`] reads the one routing byte and returns a stream
//! that still yields it, so the chosen handler sees the full data either
//! way.

use std::io;

use epix_transport::PeerStream;
use tokio::sync::mpsc;

use crate::conn::{Conn, Incoming};
use crate::frame::{self, Sniff};
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
/// consumed yet (this reads and checks it), so a stream returned by
/// [`read_sniff`] with [`Sniff::Edx`] is the expected input. Answers with
/// our own magic, runs the Noise-XX responder, and starts the connection.
pub async fn accept(stream: PeerStream) -> io::Result<Link> {
    let mut stream = stream;
    frame::read_magic(&mut stream).await?;
    frame::write_magic(&mut stream).await?;
    let sec = noise::secure_responder(stream).await?;
    let (conn, incoming) = Conn::start(sec.stream, false);
    Ok(Link { conn, incoming, handshake_hash: sec.handshake_hash })
}

/// Read the first byte of an accepted stream to route msgpack vs EDX, and
/// return it alongside a stream that still yields that byte. Portable
/// across overlays (no `TcpStream::peek` needed): the byte is buffered and
/// re-emitted, so the chosen path ([`accept`] for [`Sniff::Edx`], the
/// legacy msgpack server otherwise) sees the untouched stream.
pub async fn read_sniff(stream: PeerStream) -> io::Result<(Sniff, PeerStream)> {
    let (first, rewound) = epix_transport::peek_first_byte(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::UnexpectedEof, e.to_string()))?;
    Ok((frame::sniff(first), rewound))
}
