//! Process-wide pacing of the BULK send lane.
//!
//! The upload governor used to enforce its global cap with a per-second
//! token bucket that refused WHOLE requests: over multi-hundred-KiB bulk
//! batches, every saturated second became a BUSY storm, and each BUSY
//! costs the leecher a client-side cooldown — a saturated seeder served
//! in sawtooth. The cap is enforced here instead, as pacing: admitted
//! bulk frames wait for wire budget in the connection's ASYNC writer
//! task, so every stream keeps moving at the shared rate.
//!
//! Placement is load-bearing: pacing must never sleep on the
//! spawn_blocking encode threads (`server::MAX_ENCODE_THREADS` exists
//! precisely because that pool is shared with store and database IO —
//! 32 encode threads sleeping for rate would starve it). The writer task
//! is async and already the last hop before the socket, so the wait
//! costs a timer, not a thread. The PRIORITY lane (control frames,
//! first-paint data) is never paced — admission stays governed by the
//! choker's per-second bucket — but its served payload still charges the
//! debt here, so bulk yields to first-paint and the two lanes together
//! hold the one configured cap instead of a cap each.
//!
//! Debt model rather than a token bank: a frame is sent whenever no debt
//! is outstanding and its bytes become debt paid down at the configured
//! rate, so an idle period banks nothing (strictly smooth) and a frame
//! larger than one interval's budget can never deadlock the lane.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Yield fraction (in 1/256ths) applied while the user's own foreground
/// traffic is active — the same LEDBAT-style back-off the choker applies
/// to first-paint admission.
const FOREGROUND_YIELD_NUM: u64 = 64;

/// Upper bound on one pacing sleep, so a rate/foreground change is picked
/// up promptly even when the outstanding debt is large.
const MAX_PACE_SLICE: Duration = Duration::from_millis(250);

/// A byte-rate pacer. The process-global instance ([`bulk`]) shapes every
/// connection's bulk lane; tests build their own.
pub struct Pacer {
    /// Bytes/sec; 0 = pacing off (the default — ungoverned nodes and
    /// tests never wait).
    rate_bps: AtomicU64,
    foreground: AtomicBool,
    state: Mutex<Option<Debt>>,
}

struct Debt {
    /// Bytes sent ahead of the paced rate; [`Pacer::ready`] waits until
    /// refill pays this down to zero.
    debt: f64,
    last: tokio::time::Instant,
}

impl Pacer {
    pub const fn new() -> Self {
        Self {
            rate_bps: AtomicU64::new(0),
            foreground: AtomicBool::new(false),
            state: Mutex::new(None),
        }
    }

    /// Set the paced rate in bytes/sec (0 disables pacing). A governed
    /// node sets this to the same cap its choker was built with.
    pub fn set_rate(&self, bps: u64) {
        self.rate_bps.store(bps, Ordering::Relaxed);
    }

    /// Signal that the user's own foreground traffic is (in)active: while
    /// set, the effective rate drops to the yield fraction.
    pub fn set_foreground(&self, on: bool) {
        self.foreground.store(on, Ordering::Relaxed);
    }

    fn effective_rate(&self) -> u64 {
        let base = self.rate_bps.load(Ordering::Relaxed);
        if self.foreground.load(Ordering::Relaxed) {
            base.saturating_mul(FOREGROUND_YIELD_NUM) / 256
        } else {
            base
        }
    }

    /// Pay down debt for the time elapsed and return how much longer the
    /// remaining debt needs at the current rate (`None` = none, send now).
    fn wait_needed(&self) -> Option<Duration> {
        let rate = self.effective_rate();
        if rate == 0 {
            return None;
        }
        let mut state = self.state.lock().expect("pacer");
        let now = tokio::time::Instant::now();
        let s = state.get_or_insert(Debt { debt: 0.0, last: now });
        s.debt -= now.saturating_duration_since(s.last).as_secs_f64() * rate as f64;
        s.last = now;
        if s.debt <= 0.0 {
            s.debt = 0.0;
            return None;
        }
        Some(Duration::from_secs_f64(s.debt / rate as f64))
    }

    /// Wait until the lane has wire budget (no outstanding debt). Consumes
    /// nothing, so it is safe to cancel and retry (`select!` in the writer).
    pub async fn ready(&self) {
        loop {
            let Some(wait) = self.wait_needed() else { return };
            tokio::time::sleep(wait.min(MAX_PACE_SLICE)).await;
        }
    }

    /// Charge `bytes` just sent (they become debt paid down at the rate).
    /// Synchronous and never waits — the wait lives in [`Self::ready`].
    pub fn charge(&self, bytes: u64) {
        if self.effective_rate() == 0 {
            return;
        }
        // Settle elapsed time first so debt never double-counts it.
        let _ = self.wait_needed();
        let mut state = self.state.lock().expect("pacer");
        if let Some(s) = state.as_mut() {
            s.debt += bytes as f64;
        }
    }
}

impl Default for Pacer {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-global bulk-lane pacer every connection writer consults.
pub fn bulk() -> &'static Pacer {
    static BULK: Pacer = Pacer::new();
    &BULK
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unconfigured (rate 0), the pacer must cost nothing: no debt is
    /// tracked and ready() returns at once. This is every test fixture
    /// and every ungoverned node.
    #[tokio::test(start_paused = true)]
    async fn an_unconfigured_pacer_never_waits() {
        let p = Pacer::new();
        p.charge(10 << 20);
        let start = tokio::time::Instant::now();
        p.ready().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// Debt model: charged bytes delay the NEXT send by bytes/rate, and
    /// the wait is exact at the paced rate (paused tokio clock).
    #[tokio::test(start_paused = true)]
    async fn charged_bytes_pace_the_next_send() {
        let p = Pacer::new();
        p.set_rate(1_000_000); // 1 MB/s
        p.ready().await; // no debt yet: immediate
        p.charge(500_000);
        let start = tokio::time::Instant::now();
        p.ready().await;
        let waited = start.elapsed();
        assert!(
            (Duration::from_millis(450)..=Duration::from_millis(550)).contains(&waited),
            "500 KB at 1 MB/s should wait ~500ms, waited {waited:?}"
        );
        // Paid down: the lane is immediately ready again.
        let start = tokio::time::Instant::now();
        p.ready().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// The foreground yield lowers the effective rate to ~25%, so the
    /// same debt takes ~4x as long — seeding yields to the user's own
    /// traffic at the pacer now that bulk admission no longer refuses.
    #[tokio::test(start_paused = true)]
    async fn foreground_yield_slows_the_pace() {
        let p = Pacer::new();
        p.set_rate(1_000_000);
        p.ready().await;
        p.charge(250_000); // 250ms at full rate
        p.set_foreground(true);
        let start = tokio::time::Instant::now();
        p.ready().await;
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_millis(900),
            "250 KB at a yielded 250 KB/s should wait ~1s, waited {waited:?}"
        );
    }

    /// An idle period banks nothing: debt floors at zero, so a long quiet
    /// stretch does not buy a burst beyond the frame in flight.
    #[tokio::test(start_paused = true)]
    async fn idle_time_banks_no_burst() {
        let p = Pacer::new();
        p.set_rate(1_000_000);
        p.ready().await;
        tokio::time::sleep(Duration::from_secs(60)).await;
        // After a minute idle, a large charge still paces the next send
        // by its full size (nothing was banked).
        p.charge(1_000_000);
        let start = tokio::time::Instant::now();
        p.ready().await;
        assert!(
            start.elapsed() >= Duration::from_millis(900),
            "a full second of debt must wait ~1s, waited {:?}",
            start.elapsed()
        );
    }
}
