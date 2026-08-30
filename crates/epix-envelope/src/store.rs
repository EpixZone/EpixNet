//! The private-index abstraction the trial-decrypt indexer writes through.
//!
//! The indexer ([`crate::indexer`]) is app-agnostic: it opens sealed pool
//! records and records the results, but it does not know or care what schema
//! they land in. A consuming app implements [`EnvelopeStore`] over its own
//! private database — `epix_channel::ChannelDb` for mail; an encrypted forum or DM app
//! would implement it over its own — and the value types below are all that
//! cross the boundary.
//!
//! A "session" here is the local crypto state for one **channel** the node
//! belongs to (its ratchet + tag chain). A channel is 2-member for a DM/mail
//! thread or N-member for a forum category; the store treats them uniformly.

use epix_core::Result;
use serde_json::Value;

/// Number of expected-tag lookahead slots kept per session per direction — a
/// received record consumes its tag and the window is topped back up to K, so
/// out-of-order / lost pool records within a window of K still match in O(1).
pub const TAG_LOOKAHEAD: u32 = 8;

/// A session matched by an inbound detection tag: enough to open the record and
/// advance the ratchet.
#[derive(Debug, Clone)]
pub struct SessionMatch {
    pub session_id: i64,
    pub identity_id: i64,
    pub conv_id: String,
    pub peer_xid: Option<String>,
    /// Peer device identity key, hex-encoded. This lets the caller reject a
    /// specifically revoked device while leaving sibling-device sessions live.
    pub peer_ik: String,
    /// Linked-identity address that published this device key, when present in
    /// the authenticated bundle. Needed to recognize device revocation after
    /// that bundle file has been deleted.
    pub peer_auth: Option<String>,
    pub ratchet: Vec<u8>,
    pub n: u32,
}

/// A decrypted inbound record to commit, with the session/tag updates that MUST
/// land atomically with it (advance the ratchet, consume the matched tag,
/// register the next lookahead tags) so a crash can never split them. `subject`
/// / `body` are opaque payload strings — the app decides what they mean.
#[derive(Debug, Clone)]
pub struct InboundCommit {
    pub identity_id: i64,
    /// Existing matched session. `None` means this is a first-contact opener and
    /// `new_session` must be inserted in the same transaction as the message.
    pub session_id: Option<i64>,
    pub new_session: Option<OutboundSession>,
    pub conv_id: String,
    pub peer_xid: Option<String>,
    pub sender_xid: Option<String>,
    /// Full participant list of the thread (JSON-stored; enables reply-all).
    pub members: Vec<String>,
    pub subject: String,
    pub body: String,
    pub sent_ms: i64,
    pub received_ms: i64,
    pub epoch: i64,
    pub sign_h: Vec<u8>,
    /// New ratchet state to persist for `session_id`.
    pub ratchet_after: Vec<u8>,
    /// Tag consumed by this record (removed from the expected-tag set).
    pub consumed_tag: Vec<u8>,
    /// Newly expected `(n, tag)` receive slots to register (deduped).
    pub new_tags: Vec<(u32, Vec<u8>)>,
}

/// Parameters for [`EnvelopeStore::create_session`], grouped so the call stays
/// under the argument-count limit.
pub struct NewSession<'a> {
    pub identity_id: i64,
    pub conv_id: &'a str,
    /// Human identity of the peer, for display (may be shared across devices).
    pub peer_xid: Option<&'a str>,
    /// The peer DEVICE's identity key (leg key). Distinguishes a peer's multiple
    /// devices so each gets its own ratchet; must be stable per device and
    /// non-empty (use the device's `ik`, hex/base64-encoded).
    pub peer_ik: &'a str,
    pub peer_auth: Option<&'a str>,
    pub role: &'a str,
    pub ratchet: &'a [u8],
    pub established_ms: i64,
    pub recv_tags: &'a [(u32, Vec<u8>)],
}

/// One session mutation produced while sealing an outbound pool record.
///
/// The seal path stages these in memory. A consuming store must commit every
/// mutation together with the exact signed record in [`OutboundCommit`]. This
/// prevents a crash or failed pool append from advancing a ratchet without
/// leaving a durable record that can be retried.
#[derive(Debug, Clone)]
pub struct OutboundSession {
    /// Existing session to advance. `None` means this is a new initiator leg.
    pub session_id: Option<i64>,
    pub identity_id: i64,
    pub conv_id: String,
    pub peer_xid: Option<String>,
    pub peer_ik: String,
    pub peer_auth: Option<String>,
    pub role: String,
    /// Plaintext session state used to produce `ratchet_after`. Existing legs
    /// must provide it so the store can compare-and-swap and reject a stale
    /// concurrent seal. New legs leave it `None`.
    pub ratchet_before: Option<Vec<u8>>,
    pub ratchet_after: Vec<u8>,
    pub established_ms: i64,
    /// Initial receive tags. Present only for a newly-created initiator leg.
    pub recv_tags: Vec<(u32, Vec<u8>)>,
}

/// The sender's private-index copy that must land with its first outbound
/// record. It is never put in the anonymous pool.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub identity_id: i64,
    pub conv_id: String,
    pub peer_xid: Option<String>,
    pub members: Vec<String>,
    pub sender_xid: String,
    pub subject: String,
    pub body: String,
    pub sent_ms: i64,
}

/// Durable RLN allowance allocation for one sealed ciphertext. A retry against
/// a refreshed membership root reuses this exact unit range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RlnReservation {
    pub first_unit: u32,
    pub weight: u32,
    pub root: Option<[u8; 32]>,
}

/// Anonymous record material retained only in the private transactional outbox.
/// It permits route migration, stronger PoW, and current-root RLN re-proving
/// without advancing the pairwise ratchet or changing the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRecovery {
    pub author_private_key: String,
    pub rln: Option<RlnReservation>,
}

/// One atomically-staged outbound record and all private state it advances.
#[derive(Debug, Clone)]
pub struct OutboundCommit {
    pub sessions: Vec<OutboundSession>,
    pub record: Value,
    pub shard_path: String,
    pub created_ms: i64,
    /// Earliest transport attempt. Persisting this with the record preserves
    /// configured origin and burst jitter across a restart.
    pub next_attempt_ms: i64,
    pub recovery: OutboundRecovery,
    pub sent: Option<OutboundMessage>,
}

/// A signed record retained in the durable outbox until pool append succeeds.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingOutbound {
    pub outbox_id: i64,
    pub record: Value,
    pub shard_path: String,
    pub created_ms: i64,
    pub next_attempt_ms: i64,
    pub recovery: OutboundRecovery,
    pub last_error: Option<String>,
}

/// A consuming app's private index. Every method is the exact surface the
/// indexer and send path need — nothing app-specific (threads, search, folders)
/// belongs here; those stay on the concrete store.
pub trait EnvelopeStore {
    /// Whether a pool signature (16-byte prefix) has already been indexed FOR
    /// `identity_id`. Per-identity because one count-hiding record carries slots
    /// for several recipients, so it can deliver once per local identity.
    fn is_processed(&self, sign_h: &[u8], identity_id: i64) -> Result<bool>;
    /// Record a signature as processed for one identity.
    fn mark_processed(&self, sign_h: &[u8], identity_id: i64) -> Result<()>;
    /// Find the session an inbound tag is expected by (Tier-1 O(1) lookup).
    fn session_for_tag(&self, tag: &[u8]) -> Result<Option<SessionMatch>>;
    /// The raw ratchet blob of a session.
    fn session_ratchet(&self, session_id: i64) -> Result<Vec<u8>>;
    /// An existing session id for one leg `(identity, conv, peer_ik)`, if any. A
    /// conversation has one pairwise session PER peer DEVICE, so the device's
    /// identity key (not the shared human name) is the leg key.
    fn session_id_for_leg(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_ik: &str,
    ) -> Result<Option<i64>>;
    /// Create a session and register its initial expected receive tags atomically.
    fn create_session(&self, session: NewSession<'_>) -> Result<i64>;
    /// Persist an advanced ratchet for an existing session (own send path).
    fn update_session_ratchet(&self, session_id: i64, ratchet: &[u8]) -> Result<()>;
    /// Atomically advance outbound sessions, insert the optional own-message
    /// copy, and retain the exact signed record in a durable outbox. Returns
    /// `(outbox_id, msg_id)`, where `msg_id` is zero when `sent` is `None`.
    fn commit_outbound(&self, commit: &OutboundCommit) -> Result<(i64, i64)>;
    /// Commit a multi-record send as one SQLite transaction. This is required
    /// when a fixed-slot message spans several records: either every ratchet
    /// advance and exact record becomes durable, or none of them does.
    fn commit_outbound_batch(&self, commits: &[OutboundCommit]) -> Result<Vec<(i64, i64)>>;
    /// Commit a decrypted inbound record + its session/tag updates in one tx.
    /// Returns the new row id, or `None` on an idempotent replay.
    fn commit_inbound(&self, c: &InboundCommit) -> Result<Option<i64>>;
    /// Record an OWN sent item (no pool signature; never posted encrypted-to-self).
    #[allow(clippy::too_many_arguments)]
    fn insert_sent(
        &self,
        identity_id: i64,
        conv_id: &str,
        peer_xid: Option<&str>,
        members: &[String],
        sender_xid: &str,
        subject: &str,
        body: &str,
        sent_ms: i64,
    ) -> Result<i64>;
    /// Total unread count for an identity (drives new-item events).
    fn unread_count(&self, identity_id: i64) -> Result<i64>;
}
