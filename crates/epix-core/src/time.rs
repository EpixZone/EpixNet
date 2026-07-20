//! Wall-clock helpers. The signed-CRDT record `clock` lives in the millisecond
//! domain (per-record Lamport clock seeded by wall-ms), distinct from the
//! seconds-domain `modified` clock that content.json uses.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch. Returns 0 if the clock is before the epoch
/// (never happens in practice) rather than panicking.
pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Milliseconds since the Unix epoch. Used for record `clock` values; do NOT
/// compare a millisecond `clock` against a seconds-domain guard (the record
/// far-future bound uses this, not the content.json `now_secs` guard).
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
