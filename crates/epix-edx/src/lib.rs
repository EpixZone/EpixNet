//! EDX wire protocol — the one peer protocol.
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

pub mod choke;
pub mod conn;
pub mod fetch;
pub mod frame;
pub mod link;
pub mod msg;
pub mod noise;
pub mod sched;
pub mod server;
pub mod sim;

/// First-byte magic for EDX framing. The clearnet accept loop drops a
/// connection whose first byte is not `MAGIC[0]` before spending anything
/// on it — BT crawlers hit the announced fileserver port constantly.
pub const MAGIC: [u8; 4] = *b"EDX1";

/// Maximum payload bytes in one frame. Large verified ranges are split
/// into continuation frames of at most this size so a slow stream cannot
/// hold a connection's memory hostage and priority frames can preempt
/// bulk between chunks.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    /// `epix_protocol`'s accept loop hardcodes this first byte rather than
    /// depending on epix-edx for it; pin the two together.
    #[test]
    fn magic_starts_with_e() {
        assert_eq!(MAGIC[0], b'E');
    }
}
