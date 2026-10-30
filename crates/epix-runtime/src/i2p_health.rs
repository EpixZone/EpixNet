//! One health signal for the embedded I2P router that emissary does not expose
//! through its event stream: whether our destination currently has inbound
//! tunnels. Without them the lease set cannot be published and no peer can
//! reach this node over I2P, however many routers are connected.
//!
//! Emissary reports the condition only as a `tracing` WARN from its lease-set
//! publisher, re-emitted on a one-second timer for as long as it lasts
//! (`cannot publish lease set, no inbound tunnels`). The node's tracing filter
//! feeds every one of those events through [`note_lease_set_blocked`], which
//! turns the stream into a streak (started when, still going, how many
//! repeats swallowed) and decides which repeats are worth printing. The I2P
//! status loop reads the streak back with [`inbound_tunnels_missing`] and
//! raises ONE operator-facing warning once it has lasted longer than any
//! healthy tunnel build, plus one line when the tunnels come back.
//!
//! The dominant real cause is the local clock: I2P routers drop a session with
//! more than 60 s of skew, so a machine whose clock is a minute off connects
//! to nobody and builds nothing, while every other transport still works.
//! The warning says so, because the symptom ("no inbound tunnels") points
//! nowhere near it.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// The `tracing` target emissary's lease-set publisher logs under.
pub const LEASE_SET_BLOCKED_TARGET: &str = "emissary::destination::lease-set";
/// The message it repeats every second while the destination has no inbound
/// tunnels.
pub const LEASE_SET_BLOCKED_MESSAGE: &str = "cannot publish lease set, no inbound tunnels";

/// The publisher retries every second while blocked, so this long without a
/// repeat means the tunnels are back and the streak is over.
const STREAK_GAP_SECS: i64 = 30;
/// How often a suppressed repeat is let through to the tracing output as a
/// heartbeat, so a long outage stays visible there without a line per second.
const REPEAT_EVERY_SECS: i64 = 300;
/// How long the destination may be without inbound tunnels before the node
/// warns. A healthy build, even on a cold netDb, completes well inside this;
/// tunnels also expire and are rebuilt every 10 minutes, so a short gap at a
/// rollover is normal and must not warn.
pub const WARN_AFTER_SECS: i64 = 300;

static LAST_BLOCKED_UNIX: AtomicI64 = AtomicI64::new(0);
static BLOCKED_SINCE_UNIX: AtomicI64 = AtomicI64::new(0);
static LAST_PRINTED_UNIX: AtomicI64 = AtomicI64::new(0);
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Whether a `tracing` event is emissary's "no inbound tunnels" repeat.
pub fn is_lease_set_blocked_event(target: &str, message: &str) -> bool {
    target == LEASE_SET_BLOCKED_TARGET && message.contains(LEASE_SET_BLOCKED_MESSAGE)
}

/// Record one occurrence of the repeat. Returns whether this occurrence should
/// reach the tracing output: the first of a streak always does, then one every
/// [`REPEAT_EVERY_SECS`]; the rest are counted and dropped.
pub fn note_lease_set_blocked() -> bool {
    note_lease_set_blocked_at(unix_now())
}

fn note_lease_set_blocked_at(now: i64) -> bool {
    let last = LAST_BLOCKED_UNIX.swap(now, Ordering::AcqRel);
    let new_streak = last == 0 || now.saturating_sub(last) > STREAK_GAP_SECS;
    if new_streak {
        BLOCKED_SINCE_UNIX.store(now, Ordering::Release);
        SUPPRESSED.store(0, Ordering::Release);
        LAST_PRINTED_UNIX.store(now, Ordering::Release);
        return true;
    }
    let printed = LAST_PRINTED_UNIX.load(Ordering::Acquire);
    if now.saturating_sub(printed) >= REPEAT_EVERY_SECS {
        LAST_PRINTED_UNIX.store(now, Ordering::Release);
        return true;
    }
    SUPPRESSED.fetch_add(1, Ordering::AcqRel);
    false
}

/// A streak of "no inbound tunnels" that is still going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboundTunnelsMissing {
    /// Unix time the current streak started.
    pub since_unix: i64,
    /// How long it has lasted so far.
    pub for_secs: i64,
    /// Repeats of emissary's warning dropped from the tracing output so far.
    pub suppressed_warnings: u64,
}

/// The current streak, if the publisher is still reporting no inbound tunnels
/// (a repeat within the last [`STREAK_GAP_SECS`]); `None` once it has gone
/// quiet, which is how recovery is observed.
pub fn inbound_tunnels_missing() -> Option<InboundTunnelsMissing> {
    inbound_tunnels_missing_at(unix_now())
}

fn inbound_tunnels_missing_at(now: i64) -> Option<InboundTunnelsMissing> {
    let last = LAST_BLOCKED_UNIX.load(Ordering::Acquire);
    if last == 0 || now.saturating_sub(last) > STREAK_GAP_SECS {
        return None;
    }
    let since_unix = BLOCKED_SINCE_UNIX.load(Ordering::Acquire);
    Some(InboundTunnelsMissing {
        since_unix,
        for_secs: now.saturating_sub(since_unix).max(0),
        suppressed_warnings: SUPPRESSED.load(Ordering::Acquire),
    })
}

/// The operator-facing warning for a streak that has outlasted
/// [`WARN_AFTER_SECS`]. Names the consequence, the live router counts that
/// tell a dead router from a shunned one, and the usual cause with its fix.
pub fn missing_tunnels_warning(
    missing: &InboundTunnelsMissing,
    connected_routers: usize,
    tunnels_built: usize,
    tunnel_failures: usize,
) -> String {
    format!(
        "I2P: no inbound tunnels for {} min ({connected_routers} routers connected, \
         {tunnels_built} tunnels built, {tunnel_failures} build failures); peers cannot reach \
         this node over I2P until they return. I2P routers drop any session with more than \
         60 s of clock skew, so first check that the system clock is synchronized (NTP); \
         the router keeps retrying on its own",
        missing.for_secs / 60
    )
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The trackers are process-global; one test owns the whole scenario so
    // the steps cannot interleave with another test's.
    #[test]
    fn streak_is_tracked_throttled_and_ends_when_the_publisher_goes_quiet() {
        let t0 = 1_792_880_000;
        assert_eq!(inbound_tunnels_missing_at(t0), None, "nothing seen yet");

        // First repeat of a streak prints and starts the clock.
        assert!(note_lease_set_blocked_at(t0));
        // The per-second repeats are swallowed...
        for second in 1..REPEAT_EVERY_SECS {
            assert!(!note_lease_set_blocked_at(t0 + second), "second {second}");
        }
        // ...until the heartbeat interval, when one gets through again.
        assert!(note_lease_set_blocked_at(t0 + REPEAT_EVERY_SECS));
        assert!(!note_lease_set_blocked_at(t0 + REPEAT_EVERY_SECS + 1));

        let missing =
            inbound_tunnels_missing_at(t0 + REPEAT_EVERY_SECS + 2).expect("streak is still going");
        assert_eq!(missing.since_unix, t0);
        assert_eq!(missing.for_secs, REPEAT_EVERY_SECS + 2);
        // Everything between the two printed lines was swallowed.
        assert_eq!(missing.suppressed_warnings as i64, REPEAT_EVERY_SECS);
        assert!(missing.for_secs >= WARN_AFTER_SECS, "long enough to warn");

        // Silence past the gap means the tunnels are back.
        let quiet = t0 + REPEAT_EVERY_SECS + 1 + STREAK_GAP_SECS + 1;
        assert_eq!(inbound_tunnels_missing_at(quiet), None);

        // The next report after silence is a NEW streak: prints, counters reset.
        assert!(note_lease_set_blocked_at(quiet));
        let fresh = inbound_tunnels_missing_at(quiet + 1).unwrap();
        assert_eq!(fresh.since_unix, quiet);
        assert_eq!(fresh.for_secs, 1);
        assert_eq!(fresh.suppressed_warnings, 0);
    }

    #[test]
    fn only_emissarys_lease_set_repeat_is_recognised() {
        assert!(is_lease_set_blocked_event(
            LEASE_SET_BLOCKED_TARGET,
            "cannot publish lease set, no inbound tunnels local=oLt8E42s"
        ));
        assert!(!is_lease_set_blocked_event(
            LEASE_SET_BLOCKED_TARGET,
            "non-existent inbound tunnel about to expire"
        ));
        assert!(!is_lease_set_blocked_event(
            "emissary::tunnel::pool",
            "cannot publish lease set, no inbound tunnels"
        ));
    }

    #[test]
    fn warning_names_duration_counts_and_the_clock() {
        let missing = InboundTunnelsMissing {
            since_unix: 0,
            for_secs: 7 * 60 + 15,
            suppressed_warnings: 430,
        };
        let text = missing_tunnels_warning(&missing, 23, 4, 61);
        assert!(text.contains("no inbound tunnels for 7 min"), "{text}");
        assert!(text.contains("23 routers connected"), "{text}");
        assert!(text.contains("61 build failures"), "{text}");
        assert!(text.contains("clock"), "{text}");
        assert!(text.contains("NTP"), "{text}");
    }
}
