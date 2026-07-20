//! One BitTorrent peer connection: handshake, BEP10 extension protocol, BEP9
//! metadata (`ut_metadata`), and BEP3 piece download.
//!
//! A bare magnet gives only the info-hash. To stream it the node must (1) learn
//! the metainfo from a peer - BEP9 sends the info dict in 16 KiB chunks over the
//! BEP10 extension protocol - and (2) pull the actual file pieces over the BEP3
//! peer wire. This module is one peer end of that: [`Peer::connect`] does the
//! TCP dial + handshake, [`Peer::fetch_metadata`] returns the verified info
//! dict, and [`Peer::fetch_piece`] returns one hash-checkable piece.
//!
//! The TCP dial is either direct (Tor disabled) or through the node's Tor SOCKS5
//! proxy (Tor enabled but not "always"): the swarm discovers peers on the
//! clearnet DHT - Tor has no UDP so discovery can't be tunneled - but the actual
//! peer connection and data transfer can still ride Tor, hiding the node's IP
//! from the seeders. In "always" mode the swarm never runs at all (no UDP), so
//! this module is only ever reached on a transport that can carry a real dial.

use std::net::{SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::bencode::{self, Value};

/// The 19-byte protocol string that opens a BitTorrent handshake.
const PSTR: &[u8; 19] = b"BitTorrent protocol";
/// BEP9 transfers the info dict in 16 KiB pieces; BEP3 blocks are the same size.
const BLOCK: usize = 16 * 1024;
/// Our `ut_metadata` extension id, advertised in the extended handshake. Peers
/// address their metadata replies to this id; its value is our choice.
const UT_METADATA_ID: u8 = 1;
/// Reject any framed message longer than this - a hostile peer must not be able
/// to make us allocate unbounded memory. A piece block or metadata piece is
/// 16 KiB; a bitfield is `piece_count/8`; nothing legitimate is this big.
const MAX_MESSAGE: usize = 2 * 1024 * 1024;
/// A metainfo (BEP9) larger than this is refused before we start fetching: even
/// a multi-hour torrent's info dict is a few hundred KiB.
const MAX_METADATA: usize = 8 * 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// A whole piece must arrive within this or we give up on the peer and let the
/// swarm try another - keeps a slow seed from stalling playback forever.
const PIECE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peer io: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect timed out")]
    ConnectTimeout,
    #[error("timed out waiting for a peer message")]
    MessageTimeout,
    #[error("handshake rejected: {0}")]
    Handshake(&'static str),
    #[error("peer does not support {0}")]
    Unsupported(&'static str),
    #[error("peer sent a malformed {0}")]
    Malformed(&'static str),
    #[error("message length {0} exceeds the cap")]
    TooLong(usize),
    #[error("metadata size {0} exceeds the cap")]
    MetadataTooLarge(usize),
    #[error("peer choked the whole time / never served the piece")]
    NoData,
    #[error("socks5: {0}")]
    Socks(&'static str),
}

/// BEP3 message ids we send or recognize. `Extended` (20) carries BEP10.
mod id {
    pub const CHOKE: u8 = 0;
    pub const UNCHOKE: u8 = 1;
    pub const INTERESTED: u8 = 2;
    pub const HAVE: u8 = 4;
    pub const BITFIELD: u8 = 5;
    pub const REQUEST: u8 = 6;
    pub const PIECE: u8 = 7;
    pub const EXTENDED: u8 = 20;
}

/// A parsed peer-wire message. Anything we don't act on is dropped by the reader.
enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Have,
    Bitfield,
    Piece { index: u32, begin: u32, block: Vec<u8> },
    /// BEP10: `ext_id` selects the sub-protocol (0 = the extended handshake).
    Extended { ext_id: u8, payload: Vec<u8> },
    Other,
}

/// What we've learned about a peer from its handshake and announcements. Split
/// out from the socket so the pure protocol logic is unit-testable without one.
#[derive(Default)]
struct PeerState {
    /// The id the peer wants `ut_metadata` messages addressed to (from its
    /// extended handshake). `None` until the extended handshake completes.
    peer_ut_metadata: Option<u8>,
    /// The peer-advertised size of the info dict, in bytes (BEP9).
    metadata_size: Option<usize>,
    /// Raw BEP3 bitfield (bit `i`, MSB-first, set = peer has piece `i`).
    bitfield: Vec<u8>,
    /// Pieces the peer announced via a `have` beyond the bitfield's range.
    extra_have: Vec<u32>,
    choked: bool,
}

impl PeerState {
    fn new() -> PeerState {
        PeerState { choked: true, ..Default::default() }
    }

    /// Whether the peer has piece `index` (per its bitfield + `have`s). A peer
    /// that sent no bitfield yet reports `false`; the swarm treats "has" as a
    /// hint and still verifies every downloaded piece.
    fn has_piece(&self, index: u32) -> bool {
        let byte = (index / 8) as usize;
        let bit = 7 - (index % 8) as u8;
        if self.bitfield.get(byte).is_some_and(|b| b >> bit & 1 == 1) {
            return true;
        }
        self.extra_have.contains(&index)
    }

    fn note_have(&mut self, index: u32) {
        let byte = (index / 8) as usize;
        if byte < self.bitfield.len() {
            let bit = 7 - (index % 8) as u8;
            self.bitfield[byte] |= 1 << bit;
        } else if !self.extra_have.contains(&index) {
            self.extra_have.push(index);
        }
    }

    fn parse_extended_handshake(&mut self, payload: &[u8]) -> Result<(), PeerError> {
        let dict = bencode::decode(payload).map_err(|_| PeerError::Malformed("ext handshake"))?;
        if let Some(id) = dict
            .get("m")
            .and_then(|m| m.get("ut_metadata"))
            .and_then(Value::as_int)
            .filter(|&n| (1..=255).contains(&n))
        {
            self.peer_ut_metadata = Some(id as u8);
        }
        if let Some(sz) = dict.get("metadata_size").and_then(Value::as_int).filter(|&n| n > 0) {
            self.metadata_size = Some(sz as usize);
        }
        Ok(())
    }
}

/// A live connection to one peer.
pub struct Peer {
    stream: TcpStream,
    addr: SocketAddrV4,
    state: PeerState,
    interested_sent: bool,
}

impl Peer {
    /// Dial `addr` (directly, or through the SOCKS5 proxy at `socks` when set),
    /// complete the BitTorrent + extended handshakes for `info_hash`, and return
    /// the ready peer. `peer_id` is our 20-byte id.
    pub async fn connect(
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        peer_id: [u8; 20],
        socks: Option<SocketAddr>,
    ) -> Result<Peer, PeerError> {
        let stream = match socks {
            Some(proxy) => timeout(CONNECT_TIMEOUT, socks5_connect(proxy, addr))
                .await
                .map_err(|_| PeerError::ConnectTimeout)??,
            None => timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::V4(addr)))
                .await
                .map_err(|_| PeerError::ConnectTimeout)??,
        };
        let _ = stream.set_nodelay(true);

        let mut peer = Peer { stream, addr, state: PeerState::new(), interested_sent: false };
        timeout(HANDSHAKE_TIMEOUT, peer.handshake(info_hash, peer_id))
            .await
            .map_err(|_| PeerError::ConnectTimeout)??;
        peer.extended_handshake().await?;
        Ok(peer)
    }

    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }

    /// The peer-reported info-dict size, if it sent one.
    pub fn metadata_size(&self) -> Option<usize> {
        self.state.metadata_size
    }

    /// Whether the peer supports BEP9 metadata exchange.
    pub fn supports_metadata(&self) -> bool {
        self.state.peer_ut_metadata.is_some()
    }

    /// Whether the peer claims piece `index`.
    pub fn has_piece(&self, index: u32) -> bool {
        self.state.has_piece(index)
    }

    // ---- handshake ------------------------------------------------------

    async fn handshake(&mut self, info_hash: [u8; 20], peer_id: [u8; 20]) -> Result<(), PeerError> {
        self.stream.write_all(&handshake_bytes(info_hash, peer_id)).await?;

        let mut resp = [0u8; 68];
        self.stream.read_exact(&mut resp).await?;
        if resp[0] != 19 || &resp[1..20] != PSTR {
            return Err(PeerError::Handshake("not a BitTorrent peer"));
        }
        // The peer must be talking about the same torrent.
        if resp[28..48] != info_hash {
            return Err(PeerError::Handshake("info-hash mismatch"));
        }
        // Peers that don't set the extension bit can't do BEP9; the swarm still
        // keeps them for piece download, so that isn't fatal here.
        Ok(())
    }

    /// Send our BEP10 extended handshake advertising `ut_metadata`, then read
    /// messages until the peer's extended handshake arrives (recording its
    /// `ut_metadata` id and `metadata_size`).
    async fn extended_handshake(&mut self) -> Result<(), PeerError> {
        let dict = Value::Dict(
            [(
                b"m".to_vec(),
                Value::Dict(
                    [(b"ut_metadata".to_vec(), Value::Int(UT_METADATA_ID as i64))]
                        .into_iter()
                        .collect(),
                ),
            )]
            .into_iter()
            .collect(),
        );
        let mut payload = vec![0u8]; // extended-handshake sub-id is 0
        payload.extend_from_slice(&bencode::encode(&dict));
        self.send(id::EXTENDED, &payload).await?;

        // The peer's extended handshake is the first Extended(0) we see.
        loop {
            if let Message::Extended { ext_id: 0, payload } = self.read_message().await? {
                self.state.parse_extended_handshake(&payload)?;
                return Ok(());
            }
        }
    }

    // ---- BEP9 metadata --------------------------------------------------

    /// Fetch the full info dict via BEP9 and verify it hashes to `info_hash`.
    /// The returned bytes are exactly the info dict a `.torrent` would carry.
    pub async fn fetch_metadata(&mut self, info_hash: [u8; 20]) -> Result<Vec<u8>, PeerError> {
        let ut = self.state.peer_ut_metadata.ok_or(PeerError::Unsupported("ut_metadata (BEP9)"))?;
        let size = self.state.metadata_size.ok_or(PeerError::Unsupported("metadata_size"))?;
        if size > MAX_METADATA {
            return Err(PeerError::MetadataTooLarge(size));
        }
        let piece_count = size.div_ceil(BLOCK);
        let mut buf = vec![0u8; size];

        for piece in 0..piece_count {
            // request: {"msg_type":0, "piece":piece}
            let req = Value::Dict(
                [
                    (b"msg_type".to_vec(), Value::Int(0)),
                    (b"piece".to_vec(), Value::Int(piece as i64)),
                ]
                .into_iter()
                .collect(),
            );
            let mut payload = vec![ut];
            payload.extend_from_slice(&bencode::encode(&req));
            self.send(id::EXTENDED, &payload).await?;

            let data = self.await_metadata_piece(piece).await?;
            let start = piece * BLOCK;
            let want = (size - start).min(BLOCK);
            if data.len() != want {
                return Err(PeerError::Malformed("metadata piece length"));
            }
            buf[start..start + want].copy_from_slice(&data);
        }

        // Reject a peer whose info dict doesn't match the magnet's xt.
        use sha1::{Digest, Sha1};
        let h: [u8; 20] = Sha1::digest(&buf).into();
        if h != info_hash {
            return Err(PeerError::Malformed("metadata info-hash mismatch"));
        }
        Ok(buf)
    }

    /// Read messages until the peer delivers metadata piece `piece` (a `data`
    /// reply, `msg_type` 1), returning its raw bytes. A `reject` (2) is fatal.
    async fn await_metadata_piece(&mut self, piece: usize) -> Result<Vec<u8>, PeerError> {
        loop {
            let Message::Extended { ext_id, payload } = self.read_message().await? else {
                continue;
            };
            // Replies to our metadata requests come addressed to the id WE
            // advertised (UT_METADATA_ID), not the peer's.
            if ext_id != UT_METADATA_ID {
                continue;
            }
            let (val, used) =
                bencode::decode_prefix(&payload).map_err(|_| PeerError::Malformed("metadata msg"))?;
            let msg_type = val.get("msg_type").and_then(Value::as_int).unwrap_or(-1);
            let which = val.get("piece").and_then(Value::as_int).unwrap_or(-1);
            match msg_type {
                1 => {
                    if which != piece as i64 {
                        continue; // a data reply for a different piece; ignore
                    }
                    return Ok(payload[used..].to_vec());
                }
                2 => return Err(PeerError::NoData), // reject
                _ => continue,
            }
        }
    }

    // ---- BEP3 piece download -------------------------------------------

    /// Download a whole piece from this peer. Convenience wrapper over
    /// [`Peer::fetch_range`]; the caller verifies the SHA-1 against the metainfo.
    pub async fn fetch_piece(&mut self, index: u32, piece_len: u32) -> Result<Vec<u8>, PeerError> {
        self.fetch_range(index, 0, piece_len).await
    }

    /// Download the byte range `[begin, begin+length)` of piece `index`, block
    /// by block. The swarm splits one piece across several peers by giving each
    /// a different range, so a large piece downloads in parallel instead of
    /// serially from one peer. `begin`/`length` must be block-aligned (a
    /// multiple of 16 KiB), except a `length` that runs to the short final piece.
    /// Sends `interested` and waits for `unchoke` the first time.
    pub async fn fetch_range(
        &mut self,
        index: u32,
        begin: u32,
        length: u32,
    ) -> Result<Vec<u8>, PeerError> {
        if !self.interested_sent {
            self.send(id::INTERESTED, &[]).await?;
            self.interested_sent = true;
        }
        let deadline = tokio::time::Instant::now() + PIECE_TIMEOUT;
        let end = begin + length;

        let mut buf = vec![0u8; length as usize];
        let mut have = vec![false; length.div_ceil(BLOCK as u32) as usize];
        let mut requested = false;

        loop {
            if !self.state.choked && !requested {
                // Pipeline every block of the range at once.
                let mut off = begin;
                while off < end {
                    let len = (end - off).min(BLOCK as u32);
                    self.send_request(index, off, len).await?;
                    off += len;
                }
                requested = true;
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(PeerError::MessageTimeout);
            }
            match timeout(remaining.min(MESSAGE_TIMEOUT), self.read_message())
                .await
                .map_err(|_| PeerError::MessageTimeout)??
            {
                Message::Unchoke => {}         // state.choked already cleared
                Message::Choke => requested = false, // re-request after unchoke
                // Only accept blocks for our piece that fall inside our range.
                Message::Piece { index: pi, begin: b, block }
                    if pi == index && b >= begin && b < end =>
                {
                    let rel = (b - begin) as usize;
                    if rel + block.len() <= buf.len() {
                        buf[rel..rel + block.len()].copy_from_slice(&block);
                        if let Some(slot) = have.get_mut(rel / BLOCK) {
                            *slot = true;
                        }
                    }
                    if have.iter().all(|&h| h) {
                        return Ok(buf);
                    }
                }
                _ => {}
            }
        }
    }

    async fn send_request(&mut self, index: u32, begin: u32, len: u32) -> Result<(), PeerError> {
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(&index.to_be_bytes());
        p.extend_from_slice(&begin.to_be_bytes());
        p.extend_from_slice(&len.to_be_bytes());
        self.send(id::REQUEST, &p).await
    }

    // ---- framing --------------------------------------------------------

    /// Write one length-prefixed message: `<u32 len><id><payload>`.
    async fn send(&mut self, msg_id: u8, payload: &[u8]) -> Result<(), PeerError> {
        let len = 1 + payload.len();
        let mut frame = Vec::with_capacity(4 + len);
        frame.extend_from_slice(&(len as u32).to_be_bytes());
        frame.push(msg_id);
        frame.extend_from_slice(payload);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    /// Read one message, updating peer state for bitfield/have/choke and
    /// returning the parsed message (keep-alives surface as `KeepAlive`).
    async fn read_message(&mut self) -> Result<Message, PeerError> {
        let mut len_buf = [0u8; 4];
        timeout(MESSAGE_TIMEOUT, self.stream.read_exact(&mut len_buf))
            .await
            .map_err(|_| PeerError::MessageTimeout)??;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(Message::KeepAlive);
        }
        if len > MAX_MESSAGE {
            return Err(PeerError::TooLong(len));
        }
        let mut body = vec![0u8; len];
        timeout(MESSAGE_TIMEOUT, self.stream.read_exact(&mut body))
            .await
            .map_err(|_| PeerError::MessageTimeout)??;

        let msg_id = body[0];
        let payload = &body[1..];
        Ok(match msg_id {
            id::CHOKE => {
                self.state.choked = true;
                Message::Choke
            }
            id::UNCHOKE => {
                self.state.choked = false;
                Message::Unchoke
            }
            id::HAVE if payload.len() == 4 => {
                let i = u32::from_be_bytes(payload.try_into().unwrap());
                self.state.note_have(i);
                Message::Have
            }
            id::BITFIELD => {
                self.state.bitfield = payload.to_vec();
                Message::Bitfield
            }
            id::PIECE if payload.len() >= 8 => {
                let index = u32::from_be_bytes(payload[0..4].try_into().unwrap());
                let begin = u32::from_be_bytes(payload[4..8].try_into().unwrap());
                Message::Piece { index, begin, block: payload[8..].to_vec() }
            }
            id::EXTENDED if !payload.is_empty() => {
                Message::Extended { ext_id: payload[0], payload: payload[1..].to_vec() }
            }
            _ => Message::Other,
        })
    }
}

/// The 68-byte opening handshake: `<19>"BitTorrent protocol"<8 reserved><info
/// hash><peer id>`. Reserved byte 5 bit `0x10` advertises BEP10.
fn handshake_bytes(info_hash: [u8; 20], peer_id: [u8; 20]) -> [u8; 68] {
    let mut out = [0u8; 68];
    out[0] = 19;
    out[1..20].copy_from_slice(PSTR);
    out[25] |= 0x10; // reserved[5]
    out[28..48].copy_from_slice(&info_hash);
    out[48..68].copy_from_slice(&peer_id);
    out
}

/// Minimal SOCKS5 CONNECT (no auth) to reach `target` through `proxy` - the
/// node's Tor SOCKS listener. Tor carries TCP, so a CONNECT to a clearnet peer
/// IP tunnels the whole peer-wire session through Tor. Only IPv4 targets (what
/// the mainline DHT returns) are handled.
async fn socks5_connect(proxy: SocketAddr, target: SocketAddrV4) -> Result<TcpStream, PeerError> {
    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true).ok();
    // Greeting: version 5, one method, "no authentication".
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != 0x05 || sel[1] != 0x00 {
        return Err(PeerError::Socks("proxy refused no-auth"));
    }
    // CONNECT to an IPv4 host:port.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&target.ip().octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await?;
    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT. Consume the bound address.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(PeerError::Socks("CONNECT failed"));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(PeerError::Socks("bad reply ATYP")),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bencode::encode;

    #[test]
    fn handshake_bytes_are_well_formed() {
        let ih = [7u8; 20];
        let pid = [9u8; 20];
        let hs = handshake_bytes(ih, pid);
        assert_eq!(hs[0], 19);
        assert_eq!(&hs[1..20], PSTR);
        assert_eq!(hs[25] & 0x10, 0x10); // BEP10 extension bit
        assert_eq!(&hs[28..48], &ih);
        assert_eq!(&hs[48..68], &pid);
    }

    #[test]
    fn has_piece_reads_bitfield_msb_first() {
        let mut st = PeerState::new();
        // Byte 0b1010_0001 => peer has pieces 0, 2, 7.
        st.bitfield = vec![0b1010_0001];
        assert!(st.has_piece(0));
        assert!(!st.has_piece(1));
        assert!(st.has_piece(2));
        assert!(st.has_piece(7));
        assert!(!st.has_piece(8)); // out of range
    }

    #[test]
    fn note_have_extends_beyond_bitfield() {
        let mut st = PeerState::new();
        st.bitfield = vec![0x00]; // pieces 0..=7, none set
        st.note_have(2); // inside the bitfield -> sets the bit
        st.note_have(100); // beyond it -> tracked separately
        assert!(st.has_piece(2));
        assert!(st.has_piece(100));
        assert!(!st.has_piece(3));
    }

    #[test]
    fn parse_extended_handshake_reads_id_and_size() {
        let mut st = PeerState::new();
        let dict = Value::Dict(
            [
                (
                    b"m".to_vec(),
                    Value::Dict([(b"ut_metadata".to_vec(), Value::Int(3))].into_iter().collect()),
                ),
                (b"metadata_size".to_vec(), Value::Int(1234)),
            ]
            .into_iter()
            .collect(),
        );
        st.parse_extended_handshake(&encode(&dict)).unwrap();
        assert_eq!(st.peer_ut_metadata, Some(3));
        assert_eq!(st.metadata_size, Some(1234));
    }
}
