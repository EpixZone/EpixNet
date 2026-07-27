//! EDX wire protocol (replaces the msgpack xite command set).
//!
//! One protocol over every overlay: frames are postcard-encoded with a
//! small header and ≤64 KiB continuation frames, multiplexed yamux-style
//! over the single ordered `PeerStream` a `Transport` yields, so the same
//! code path serves clearnet TCP (Noise-XX mandatory, node-key channel
//! binding), Tor, I2P, and Reticulum. Object bytes travel as bao verified
//! streams decoded incrementally into the sparse store — a whole range is
//! never buffered in RAM.
//!
//! Phase B of the EDX plan fills this crate in, in this order: the swarm
//! simulation harness first, then framing, the connection pool, Noise,
//! the message set, the deadline/rarest-first scheduler, and the
//! reciprocity choker.

#![forbid(unsafe_code)]

pub mod frame;
pub mod msg;
pub mod sim;

/// First-byte magic for EDX framing. During the migration window the
/// accept path sniffs this against a legacy msgpack map header (legacy
/// first bytes are 0x80–0x8f, 0xde, or 0xdf — never ASCII 'E') to route a
/// connection to the right protocol server.
pub const MAGIC: [u8; 4] = *b"EDX1";

/// Maximum payload bytes in one frame. Large verified ranges are split
/// into continuation frames of at most this size so a slow stream cannot
/// hold a connection's memory hostage and priority frames can preempt
/// bulk between chunks.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// The magic must never collide with a legacy msgpack first byte, or
    /// the migration-window sniffing misroutes connections.
    #[test]
    fn magic_disjoint_from_msgpack() {
        let first = MAGIC[0];
        assert!(first != 0xde && first != 0xdf, "map16/map32 collision");
        assert!(!(0x80..=0x8f).contains(&first), "fixmap collision");
        assert_eq!(first, b'E');
    }
}
