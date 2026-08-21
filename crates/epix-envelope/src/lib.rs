//! `epix-envelope` — generic sealed-envelope messaging over the anonymous pool.
//!
//! This is the app-neutral middle layer between the generic pool
//! ([`epix_content::pool`] / `epix_ui::pool`) and a concrete encrypted app:
//!
//! - [`engine`] — the crypto [`Engine`](engine::Engine) trait (seal / detect /
//!   open sealed envelopes with detection tags and ratchet sessions), plus a
//!   deterministic, **insecure** [`FakeEngine`](engine::FakeEngine) for tests.
//!   The real X3DH + Double Ratchet impl is the separate `epix-pairwise-engine` crate.
//! - [`store`] — the [`EnvelopeStore`](store::EnvelopeStore) trait a consuming
//!   app implements over its own private index, and the value types that cross
//!   the boundary.
//! - [`indexer`] — the app-agnostic trial-decrypt receive path and the
//!   seal-and-post send path, generic over `EnvelopeStore`.
//!
//! ## Vocabulary
//! An **envelope** (the sealed record) travels through the **pool** (transport)
//! addressed to a **channel** — its encrypted audience and permission context —
//! and carries **messages** (decrypted units). A channel is the unifier: a 1:1
//! mail thread is a 2-member channel; a forum category is an N-member channel
//! with post/read permissions. So "mail" and "forum" are channel *types* / UI
//! surfaces, not separate architectures.
//!
//! Mail (`epix-channel` + `epix-plugins::channel`) is the first channel surface; an
//! encrypted forum or DM app is another — each brings its own store schema and
//! WS commands, and (for group vs pairwise channels) its own `Engine` impl,
//! while reusing this layer and the pool unchanged. See
//! `docs/channels.md` for the full envelope/pool/channel/message model.

pub mod engine;
pub mod indexer;
pub mod multislot;
pub mod store;

pub use engine::{Begun, Engine, EngineError, FakeEngine, IdentitySecret, Opened, Sealed};
pub use indexer::{
    new_conv_id, process_record, process_record_one, process_record_with_peer_status, send_message,
    ProcessOutcome, SendResult,
};
pub use multislot::{
    prepare_multi_scheduled, prepare_multi_with_rln_reserved_scheduled,
    prepare_multi_with_rln_scheduled, send_multi, send_multi_scheduled, send_multi_with_rln,
    send_multi_with_rln_scheduled, Dest, PreparedSend, RlnProofMaterial, SLOTS,
};
pub use store::{
    EnvelopeStore, InboundCommit, NewSession, OutboundCommit, OutboundMessage, OutboundRecovery,
    OutboundSession, PendingOutbound, RlnReservation, SessionMatch, TAG_LOOKAHEAD,
};
