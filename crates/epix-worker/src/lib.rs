//! `epix-worker` - peer-outcome reputation types.
//!
//! The parallel msgpack download worker this crate used to hold was retired
//! when content sync moved to EDX (verified BLAKE3 streaming). All that remains
//! is [`PeerOutcome`], the vocabulary every fetch path still reports so the peer
//! registry can reward good seeders and back off dead ones.

/// What happened with one peer during a fetch, so the host can adjust its
/// reputation and backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOutcome {
    /// Dial + handshake succeeded.
    ConnectOk,
    /// Dial or handshake failed or timed out.
    ConnectFail,
    /// A file downloaded from the peer and verified.
    FileOk,
    /// A file fetch failed: refused, timed out, or hash mismatch.
    FileFail,
}
