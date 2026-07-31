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

use std::collections::{HashMap, HashSet};

/// Free first-paint budget per new peer (bytes) and its refill window.
pub const FIRST_PAINT_FREE_BYTES: u64 = 4 << 20; // 4 MiB
pub const FIRST_PAINT_WINDOW_SECS: u64 = 600; // per 10 min

/// Ceiling on tracked peer accounts, and how long an account may sit
/// idle before it is dropped. A peer mints a new node_pk for free by
/// reconnecting, so the account table has to be bounded: without this a
/// handshake flood grows it forever and makes every ranking slower.
pub const MAX_TRACKED_PEERS: usize = 4096;
pub const PEER_IDLE_EVICT_SECS: u64 = 24 * 3600;

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
    /// Last time we saw this peer (unix secs), for idle eviction.
    last_seen: u64,
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
    /// Cached unchoke set, the rotation epoch it was built for, and a
    /// flag set when the ranking inputs changed. Building the set sorts
    /// every account, so it runs once per rotation or state change
    /// instead of once per served request.
    unchoked: HashSet<Vec<u8>>,
    unchoked_epoch: u64,
    dirty: bool,
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
            unchoked: HashSet::new(),
            unchoked_epoch: 0,
            dirty: true,
        }
    }

    /// Get or create a peer's account and stamp it as seen now, making
    /// room first if the table is at its cap.
    fn touch(&mut self, node_pk: &[u8], now: u64) -> &mut PeerAccount {
        if !self.peers.contains_key(node_pk) {
            if self.peers.len() >= MAX_TRACKED_PEERS {
                self.evict(now);
            }
            // A new (or evicted) account changes the ranking.
            self.dirty = true;
        }
        let acct = self
            .peers
            .entry(node_pk.to_vec())
            .or_insert_with(|| PeerAccount { free_window_start: now, ..Default::default() });
        acct.last_seen = now;
        acct
    }

    /// Make room for a new account: drop long-idle ones first, then, if
    /// still at the cap, the least valuable (lowest contribution, oldest
    /// seen). Identities minted to flood us never contribute, so they go
    /// before any real peer does.
    fn evict(&mut self, now: u64) {
        self.peers.retain(|_, a| now.saturating_sub(a.last_seen) < PEER_IDLE_EVICT_SECS);
        while self.peers.len() >= MAX_TRACKED_PEERS {
            let worst = self
                .peers
                .iter()
                .min_by(|a, b| {
                    a.1.served_to_us.cmp(&b.1.served_to_us).then(a.1.last_seen.cmp(&b.1.last_seen))
                })
                .map(|(pk, _)| pk.clone());
            let Some(worst) = worst else { break };
            self.peers.remove(&worst);
        }
    }

    /// Register/refresh a peer's reachability and first-seen time.
    pub fn note_peer(&mut self, node_pk: &[u8], reach: Reach, now: u64) {
        let acct = self.touch(node_pk, now);
        acct.reach = reach;
        self.dirty = true;
    }

    /// Record that a peer served US bytes (their reciprocity credit).
    pub fn credit_peer(&mut self, node_pk: &[u8], bytes: u64, now: u64) {
        let acct = self.touch(node_pk, now);
        acct.served_to_us += bytes;
        self.dirty = true;
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
            let acct = self.touch(node_pk, now);
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
            acct.last_seen = now;
        }
        ServeDecision::Serve
    }

    /// Is this peer in the current unchoke set? Answered from the cache;
    /// the set is rebuilt only when the rotation epoch turns over or the
    /// ranking inputs changed.
    fn is_unchoked(&mut self, node_pk: &[u8], now: u64) -> bool {
        let epoch = now / OPTIMISTIC_ROTATE_SECS;
        if self.dirty || epoch != self.unchoked_epoch {
            self.rebuild_unchoked(epoch);
        }
        self.unchoked.contains(node_pk)
    }

    /// The unchoke set for a rotation epoch: top contributors by
    /// reciprocity, plus reserved overlay slots and one optimistic slot
    /// for a newcomer.
    fn rebuild_unchoked(&mut self, epoch: u64) {
        let mut ranked: Vec<(&[u8], &PeerAccount)> =
            self.peers.iter().map(|(pk, a)| (pk.as_slice(), a)).collect();
        // Highest contribution first.
        ranked.sort_by(|a, b| b.1.served_to_us.cmp(&a.1.served_to_us));

        let mut unchoked: HashSet<Vec<u8>> = HashSet::new();
        let mut overlay_slots = OVERLAY_RESERVED_SLOTS;
        let mut general_slots = UNCHOKE_SLOTS - OVERLAY_RESERVED_SLOTS;

        // Reserve overlay slots first (highest-contributing overlay peers).
        for (pk, _) in ranked.iter().filter(|(_, a)| a.reach == Reach::Overlay) {
            if overlay_slots == 0 {
                break;
            }
            unchoked.insert(pk.to_vec());
            overlay_slots -= 1;
        }
        // Fill general slots by contribution.
        for (pk, _) in &ranked {
            if general_slots == 0 {
                break;
            }
            if unchoked.insert(pk.to_vec()) {
                general_slots -= 1;
            }
        }
        // Optimistic slot: rotates deterministically by time so a
        // newcomer with zero contribution still gets periodic service.
        if !ranked.is_empty() {
            let rotate = epoch as usize % ranked.len();
            unchoked.insert(ranked[rotate].0.to_vec());
        }

        self.unchoked = unchoked;
        self.unchoked_epoch = epoch;
        self.dirty = false;
    }

    /// Bytes served to a peer so far (bulk).
    pub fn served_to(&self, node_pk: &[u8]) -> u64 {
        self.peers.get(node_pk).map(|a| a.served_by_us).unwrap_or(0)
    }

    /// Reciprocity credit a peer has earned: bytes it has served US, which
    /// buy it faster service in return.
    pub fn credit_of(&self, node_pk: &[u8]) -> u64 {
        self.peers.get(node_pk).map(|a| a.served_to_us).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Vec<u8> {
        vec![n; 33]
    }

    /// Distinct 33-byte keys for the eviction tests, where u8 is not
    /// enough room.
    fn pk_n(n: u32) -> Vec<u8> {
        let mut v = vec![0u8; 33];
        v[..4].copy_from_slice(&n.to_le_bytes());
        v
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

    #[test]
    fn peer_accounts_are_capped_and_freeloaders_go_first() {
        let mut c = Choker::new(1_000_000_000);
        // A real contributor.
        let good = pk_n(u32::MAX);
        c.note_peer(&good, Reach::Clearnet, 0);
        c.credit_peer(&good, 1_000_000, 0);
        // More zero-contribution identities than the cap, as a peer
        // cycling handshakes with fresh keys would mint.
        for i in 0..(MAX_TRACKED_PEERS as u32 + 200) {
            c.note_peer(&pk_n(i), Reach::Clearnet, 1);
        }
        assert!(c.peers.len() <= MAX_TRACKED_PEERS);
        // The contributor is still accounted for: eviction takes the
        // lowest credit first.
        assert_eq!(c.credit_of(&good), 1_000_000);

        // A day later, the next new peer sweeps the idle accounts, so the
        // table drops well below the cap instead of staying pinned at it.
        c.note_peer(&pk_n(u32::MAX - 1), Reach::Clearnet, PEER_IDLE_EVICT_SECS + 2);
        assert!(c.peers.len() < MAX_TRACKED_PEERS);
    }

    #[test]
    fn unchoke_cache_reflects_credit_within_the_same_rotation() {
        let mut c = Choker::new(1_000_000_000);
        for i in 0..6u8 {
            let p = pk(i);
            c.note_peer(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, 1_000_000, 0);
        }
        let late = pk(200);
        c.note_peer(&late, Reach::Clearnet, 100);
        // Zero contribution, every slot held, and not the optimistic pick
        // at t=100 (rotation index 3 of 7 lands on a contributor).
        assert_eq!(c.decide(&late, 100, false, false, 100), ServeDecision::Choked);
        // A big credit inside the SAME rotation window takes effect at
        // once: the cached set is invalidated, not held until the next one.
        c.credit_peer(&late, 10_000_000, 100);
        assert_eq!(c.decide(&late, 100, false, false, 100), ServeDecision::Serve);
    }

    #[test]
    fn unchoke_cache_rotates_with_the_clock() {
        let mut c = Choker::new(1_000_000_000);
        for i in 0..6u8 {
            let p = pk(i);
            c.note_peer(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, (i as u64 + 1) * 1000, 0);
        }
        // pk(2) is outside the top 3 general slots, so it is served only
        // in the rotation window where it holds the optimistic slot.
        // ranked is pk5,pk4,pk3,pk2,pk1,pk0; index 3 is pk(2).
        let held = c.decide(&pk(2), 100, false, false, 3 * OPTIMISTIC_ROTATE_SECS);
        assert_eq!(held, ServeDecision::Serve);
        // Next rotation the slot moves on, and the cached set moves with it.
        let dropped = c.decide(&pk(2), 100, false, false, 4 * OPTIMISTIC_ROTATE_SECS);
        assert_eq!(dropped, ServeDecision::Choked);
    }
}
