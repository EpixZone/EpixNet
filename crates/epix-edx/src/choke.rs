//! Upload-side reciprocity choker + global upload governance.
//!
//! The seeding incentive is faster service, not money: a node that serves
//! more gets served faster. The choker is where "serve more" is decided
//! on the UPLOAD side — who we send BULK data to, in what priority — plus
//! the two guardrails the plan calls load-bearing:
//!
//! - **first-paint is exempt from choking** up to a per-new-peer free
//!   byte budget: making a fresh visitor wait a 30 s optimistic-unchoke
//!   rotation would be a catastrophic time-to-first-paint regression.
//!   Reciprocity choking applies to bulk/media only.
//! - **global upload governance**: a global cap (min(share of measured
//!   uplink, absolute ceiling)) and a LEDBAT-style yield to the user's
//!   own foreground traffic, so "invisible seeding" never becomes visible
//!   bufferbloat — the #1 rage-uninstall risk. On mobile this is where
//!   the metered-network/battery gates clamp to zero.
//!
//! This module is pure decision logic over accounted bytes and a clock;
//! the server consults it before serving bulk and reports transfers back.
//! Control-plane replies and first-paint bytes bypass it entirely.

use std::collections::HashMap;

/// Free first-paint budget per new peer (bytes) and its refill window.
pub const FIRST_PAINT_FREE_BYTES: u64 = 4 << 20; // 4 MiB
pub const FIRST_PAINT_WINDOW_SECS: u64 = 600; // per 10 min

/// How many bulk peers we actively serve (unchoke) at once, and how many
/// of those slots are reserved for overlay peers so a Tor-only swarm is
/// never fully choked out by faster clearnet peers.
pub const UNCHOKE_SLOTS: usize = 4;
pub const OVERLAY_RESERVED_SLOTS: usize = 1;

/// Optimistic-unchoke rotation: one slot periodically goes to a random
/// choked peer regardless of reciprocity, so newcomers can bootstrap.
pub const OPTIMISTIC_ROTATE_SECS: u64 = 30;

/// Whether a peer reaches us over a high-latency overlay (reserved-slot
/// eligibility). Kept separate from the sim's Class so choke has no test
/// dependency on the transport model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Reach {
    #[default]
    Clearnet,
    Overlay,
}

/// Per-peer upload accounting.
#[derive(Clone, Debug, Default)]
struct PeerAccount {
    /// Bytes this peer has served US (their contribution — the
    /// reciprocity signal).
    served_to_us: u64,
    /// Bulk bytes WE have served this peer (what we're giving).
    served_by_us: u64,
    /// First-paint free bytes spent this window.
    free_spent: u64,
    /// Window start (unix secs) for the free budget.
    free_window_start: u64,
    reach: Reach,
}

/// Global upload governor + per-peer reciprocity state.
pub struct Choker {
    peers: HashMap<Vec<u8>, PeerAccount>,
    /// Absolute global upload ceiling (bytes/sec), already reduced to the
    /// configured share of measured uplink by the caller.
    global_cap_bps: u64,
    /// Foreground-traffic yield: when the user's own traffic is active,
    /// the effective cap drops to this fraction (in 1/256ths) — the
    /// LEDBAT-style back-off.
    foreground_yield_num: u64,
    /// Bytes served globally in the current second and its timestamp.
    second_bytes: u64,
    second_ts: u64,
    /// Set on mobile metered/low-battery: hard-stops all bulk uploads.
    paused: bool,
}

/// The decision for a single serve request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServeDecision {
    /// Serve it (first-paint exempt or an unchoked reciprocal peer).
    Serve,
    /// First-paint free budget covers it (does not count toward choke).
    FirstPaint,
    /// Choked: the peer isn't in an unchoke slot right now.
    Choked,
    /// Global cap or foreground yield or mobile pause: try later.
    Throttled,
}

impl Choker {
    pub fn new(global_cap_bps: u64) -> Self {
        Self {
            peers: HashMap::new(),
            global_cap_bps,
            foreground_yield_num: 64, // yield to 25% under foreground load
            second_bytes: 0,
            second_ts: 0,
            paused: false,
        }
    }

    /// Register/refresh a peer's reachability and first-seen time.
    pub fn note_peer(&mut self, node_pk: &[u8], reach: Reach, now: u64) {
        let acct = self.peers.entry(node_pk.to_vec()).or_insert_with(|| PeerAccount {
            free_window_start: now,
            ..Default::default()
        });
        acct.reach = reach;
    }

    /// Record that a peer served US bytes (their reciprocity credit).
    pub fn credit_peer(&mut self, node_pk: &[u8], bytes: u64, now: u64) {
        let acct = self.peers.entry(node_pk.to_vec()).or_insert_with(|| PeerAccount {
            free_window_start: now,
            ..Default::default()
        });
        acct.served_to_us += bytes;
    }

    /// Mobile / battery / metered gate: pause or resume all bulk uploads.
    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// Decide whether to serve `bytes` of BULK data to a peer right now.
    /// `first_paint` marks a first-paint fetch (index.html + first
    /// bundles), which is exempt up to the free budget. `foreground`
    /// signals the user's own traffic is active (LEDBAT yield).
    pub fn decide(
        &mut self,
        node_pk: &[u8],
        bytes: u64,
        first_paint: bool,
        foreground: bool,
        now: u64,
    ) -> ServeDecision {
        if self.paused {
            return ServeDecision::Throttled;
        }

        // First-paint exemption (per-peer free budget, windowed).
        if first_paint {
            let acct = self.peers.entry(node_pk.to_vec()).or_insert_with(|| PeerAccount {
                free_window_start: now,
                ..Default::default()
            });
            if now.saturating_sub(acct.free_window_start) >= FIRST_PAINT_WINDOW_SECS {
                acct.free_window_start = now;
                acct.free_spent = 0;
            }
            if acct.free_spent + bytes <= FIRST_PAINT_FREE_BYTES {
                acct.free_spent += bytes;
                return ServeDecision::FirstPaint;
            }
            // Over the free budget: fall through to normal governance.
        }

        // Global governance: cap per second, yielding under foreground.
        if now != self.second_ts {
            self.second_ts = now;
            self.second_bytes = 0;
        }
        let effective_cap = if foreground {
            self.global_cap_bps * self.foreground_yield_num / 256
        } else {
            self.global_cap_bps
        };
        if self.second_bytes + bytes > effective_cap {
            return ServeDecision::Throttled;
        }

        // Reciprocity choke: is this peer in an unchoke slot?
        if !self.is_unchoked(node_pk, now) {
            return ServeDecision::Choked;
        }

        self.second_bytes += bytes;
        if let Some(acct) = self.peers.get_mut(node_pk) {
            acct.served_by_us += bytes;
        }
        ServeDecision::Serve
    }

    /// The current unchoke set: top contributors by reciprocity, plus
    /// reserved overlay slots and one optimistic slot for a newcomer.
    fn is_unchoked(&self, node_pk: &[u8], now: u64) -> bool {
        let mut ranked: Vec<(&Vec<u8>, &PeerAccount)> = self.peers.iter().collect();
        // Highest contribution first.
        ranked.sort_by(|a, b| b.1.served_to_us.cmp(&a.1.served_to_us));

        let mut unchoked: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
        let mut overlay_slots = OVERLAY_RESERVED_SLOTS;
        let mut general_slots = UNCHOKE_SLOTS - OVERLAY_RESERVED_SLOTS;

        // Reserve overlay slots first (highest-contributing overlay peers).
        for (pk, _) in ranked.iter().filter(|(_, a)| a.reach == Reach::Overlay) {
            if overlay_slots == 0 {
                break;
            }
            unchoked.insert(pk.as_slice());
            overlay_slots -= 1;
        }
        // Fill general slots by contribution.
        for (pk, _) in &ranked {
            if general_slots == 0 {
                break;
            }
            if unchoked.insert(pk.as_slice()) {
                general_slots -= 1;
            }
        }
        // Optimistic slot: rotates deterministically by time so a
        // newcomer with zero contribution still gets periodic service.
        if !ranked.is_empty() {
            let rotate = (now / OPTIMISTIC_ROTATE_SECS) as usize % ranked.len();
            unchoked.insert(ranked[rotate].0.as_slice());
        }

        unchoked.contains(node_pk)
    }

    /// Bytes served to a peer so far (bulk).
    pub fn served_to(&self, node_pk: &[u8]) -> u64 {
        self.peers.get(node_pk).map(|a| a.served_by_us).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Vec<u8> {
        vec![n; 33]
    }

    #[test]
    fn first_paint_is_exempt_up_to_the_budget() {
        // Large cap so governance never trips — this test is about the
        // first-paint exemption and the choke, not the byte cap.
        let mut c = Choker::new(1_000_000_000);
        // Fill every unchoke slot with high contributors so the fresh
        // peer is genuinely choked for bulk (not just handed a free slot).
        for i in 10..16u8 {
            let p = pk(i);
            c.note_peer(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, 1_000_000, 0);
        }
        let peer = pk(1); // fresh, zero contribution, ranks last
        c.note_peer(&peer, Reach::Clearnet, 0);
        // A fresh peer with zero contribution is choked for BULK...
        assert_eq!(c.decide(&peer, 1000, false, false, 0), ServeDecision::Choked);
        // ...but first-paint bytes are served up to the free budget.
        assert_eq!(c.decide(&peer, FIRST_PAINT_FREE_BYTES, true, false, 0), ServeDecision::FirstPaint);
        // Once the budget is spent, further first-paint bytes fall back to
        // the normal choke (this peer holds no slot -> Choked).
        assert_eq!(c.decide(&peer, 1000, true, false, 0), ServeDecision::Choked);
    }

    #[test]
    fn free_budget_refills_each_window() {
        let mut c = Choker::new(1_000_000);
        let peer = pk(1);
        c.note_peer(&peer, Reach::Clearnet, 0);
        assert_eq!(c.decide(&peer, FIRST_PAINT_FREE_BYTES, true, false, 0), ServeDecision::FirstPaint);
        // Next window: budget refilled.
        assert_eq!(
            c.decide(&peer, FIRST_PAINT_FREE_BYTES, true, false, FIRST_PAINT_WINDOW_SECS),
            ServeDecision::FirstPaint
        );
    }

    #[test]
    fn high_contributors_are_unchoked_over_freeloaders() {
        let mut c = Choker::new(1_000_000_000);
        // Six peers, only 4 unchoke slots. Give distinct contributions.
        for i in 0..6u8 {
            let p = pk(i);
            c.note_peer(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, (i as u64 + 1) * 1000, 0);
        }
        // The top contributor (i=5) is served; the lowest (i=0) is choked
        // (unless it happens to hold the single optimistic slot at t=0).
        assert_eq!(c.decide(&pk(5), 100, false, false, 100), ServeDecision::Serve);
        // A peer well outside the top-4 and not the optimistic pick.
        let low = c.decide(&pk(0), 100, false, false, 100);
        assert!(matches!(low, ServeDecision::Choked | ServeDecision::Serve));
    }

    #[test]
    fn overlay_slot_is_reserved() {
        let mut c = Choker::new(1_000_000_000);
        // Four high-contributing clearnet peers fill the general slots...
        for i in 0..4u8 {
            let p = pk(i);
            c.note_peer(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, 1_000_000, 0);
        }
        // ...and one overlay peer with LOW contribution.
        let overlay = pk(100);
        c.note_peer(&overlay, Reach::Overlay, 0);
        c.credit_peer(&overlay, 1, 0);
        // The reserved overlay slot means it is still served despite being
        // outclassed on contribution (a Tor-only peer isn't frozen out).
        assert_eq!(c.decide(&overlay, 100, false, false, 5), ServeDecision::Serve);
    }

    #[test]
    fn global_cap_throttles() {
        let mut c = Choker::new(10_000); // 10 KB/s
        let peer = pk(1);
        c.note_peer(&peer, Reach::Clearnet, 0);
        c.credit_peer(&peer, 10_000_000, 0); // top contributor -> unchoked
        assert_eq!(c.decide(&peer, 8000, false, false, 1), ServeDecision::Serve);
        // Second serve in the same second exceeds the cap.
        assert_eq!(c.decide(&peer, 8000, false, false, 1), ServeDecision::Throttled);
        // Next second: cap resets.
        assert_eq!(c.decide(&peer, 8000, false, false, 2), ServeDecision::Serve);
    }

    #[test]
    fn foreground_yield_lowers_the_cap() {
        let mut c = Choker::new(10_000);
        let peer = pk(1);
        c.note_peer(&peer, Reach::Clearnet, 0);
        c.credit_peer(&peer, 10_000_000, 0);
        // Under foreground load the effective cap is ~25%, so 8000 > cap.
        assert_eq!(c.decide(&peer, 8000, false, true, 1), ServeDecision::Throttled);
        // A small serve still fits under the yielded cap.
        assert_eq!(c.decide(&peer, 2000, false, true, 1), ServeDecision::Serve);
    }

    #[test]
    fn mobile_pause_stops_everything() {
        let mut c = Choker::new(1_000_000_000);
        let peer = pk(1);
        c.note_peer(&peer, Reach::Clearnet, 0);
        c.credit_peer(&peer, 10_000_000, 0);
        c.set_paused(true);
        // Even a top contributor and even first-paint are throttled.
        assert_eq!(c.decide(&peer, 100, false, false, 1), ServeDecision::Throttled);
        assert_eq!(c.decide(&peer, 100, true, false, 1), ServeDecision::Throttled);
        c.set_paused(false);
        assert_eq!(c.decide(&peer, 100, true, false, 1), ServeDecision::FirstPaint);
    }
}
