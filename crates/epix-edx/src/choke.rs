//! Upload-side reciprocity choker + global upload governance.
//!
//! The seeding incentive is faster service, not money: a node that serves
//! more gets served faster. The choker is where "serve more" is decided
//! on the UPLOAD side — who we send BULK data to, in what priority — plus
//! the two guardrails the plan calls load-bearing:
//!
//! - **generous by default, choking only under real contention**: home
//!   uplinks are ~1 Gbps now, so every peer gets a large free serving
//!   budget (~10 MB/s sustained) and the unchoke set is wide. A fresh
//!   visitor's first paint AND an ordinary site sync ride the free budget;
//!   reciprocity only decides who keeps getting served when more peers
//!   compete than there are slots.
//! - **global upload governance**: a global cap (min(share of measured
//!   uplink, absolute ceiling)) and a LEDBAT-style yield to the user's
//!   own foreground traffic, so "invisible seeding" never becomes visible
//!   bufferbloat — the #1 rage-uninstall risk. On mobile this is where
//!   the metered-network/battery gates clamp to zero.
//!
//! This module is pure decision logic over accounted bytes and a clock;
//! the server consults it before serving bulk and reports transfers back.
//! Control-plane replies bypass it entirely; first-paint bytes bypass only
//! the reciprocity choke, never the global cap or the foreground yield.
//! The RATE of admitted bulk is not enforced here by refusal any more: the
//! bulk-lane pacer ([`crate::pace`], same cap and yield) smooths those
//! bytes at the connection writer, so this module decides WHO is served
//! and the pacer decides how fast the wire moves.

use std::collections::{HashMap, HashSet};

/// Free serving budget per peer (bytes) and its refill window: ~10 MB/s
/// sustained, so an uncontended peer is simply served. Only past this does
/// bulk service depend on reciprocity.
pub const FIRST_PAINT_FREE_BYTES: u64 = 6 << 30; // 6 GiB
pub const FIRST_PAINT_WINDOW_SECS: u64 = 600; // per 10 min

/// Ceiling on tracked peer accounts, and how long an account may sit
/// idle before it is dropped. A peer mints a new node_pk for free by
/// reconnecting, so the account table has to be bounded: without this a
/// handshake flood grows it forever and makes every ranking slower.
pub const MAX_TRACKED_PEERS: usize = 4096;
pub const PEER_IDLE_EVICT_SECS: u64 = 24 * 3600;

/// How many bulk peers we actively serve (unchoke) at once, and how many
/// of those slots are reserved for overlay peers so a Tor-only swarm is
/// never fully choked out by faster clearnet peers. Wide on purpose: with
/// fewer competing peers than slots, nobody is ever choked.
pub const UNCHOKE_SLOTS: usize = 16;
pub const OVERLAY_RESERVED_SLOTS: usize = 4;

/// Optimistic-unchoke rotation: one slot periodically goes to a random
/// choked peer regardless of reciprocity, so newcomers can bootstrap.
pub const OPTIMISTIC_ROTATE_SECS: u64 = 30;

/// How recently a peer must have transferred (asked us for data, or served
/// us some) to compete for a RANKED unchoke slot. Ranking runs over
/// currently-connected peers — an unreachable overlay leecher has permanent
/// zero credit, and ranking every account it ever competed with froze it
/// out for good — but node_pk is free (see [`MAX_TRACKED_PEERS`]), so
/// merely being connected cannot hold a slot either: idle conns minted to
/// squat the slots go inactive after this window and stop counting.
pub const ACTIVE_WINDOW_SECS: u64 = 60;

/// Retry hint for a request refused because bulk uploads are paused
/// (mobile metered/battery gate) — pauses last minutes, not seconds.
pub const PAUSED_RETRY_SECS: u64 = 60;

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
    /// Live connections from this peer (a peer may hold several lanes).
    /// Only connected peers compete for unchoke slots: a slot's point is
    /// serving someone who is here to be served.
    conns: u32,
    /// Last transfer activity (a serve request from it, or bytes it served
    /// us). `None` = never. Gates RANKED slots — see [`ACTIVE_WINDOW_SECS`].
    last_activity: Option<u64>,
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
    /// before any real peer does. A CONNECTED account is never evicted —
    /// its refcount would dangle — and live connections are bounded far
    /// below the table cap by the accept side, so this cannot pin the
    /// table full.
    fn evict(&mut self, now: u64) {
        self.peers
            .retain(|_, a| a.conns > 0 || now.saturating_sub(a.last_seen) < PEER_IDLE_EVICT_SECS);
        while self.peers.len() >= MAX_TRACKED_PEERS {
            let worst = self
                .peers
                .iter()
                .filter(|(_, a)| a.conns == 0)
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

    /// A connection from this peer came up (the serve loop's Hello). Slot
    /// ranking runs over connected peers, so this is what admits a peer to
    /// the competition; [`Self::note_disconnected`] must pair with it.
    pub fn note_connected(&mut self, node_pk: &[u8], reach: Reach, now: u64) {
        let acct = self.touch(node_pk, now);
        acct.reach = reach;
        acct.conns = acct.conns.saturating_add(1);
        self.dirty = true;
    }

    /// A connection from this peer went away; at zero it stops competing
    /// for slots (its account and credit stay for when it returns).
    pub fn note_disconnected(&mut self, node_pk: &[u8], now: u64) {
        let acct = self.touch(node_pk, now);
        acct.conns = acct.conns.saturating_sub(1);
        self.dirty = true;
    }

    /// Record that a peer served US bytes (their reciprocity credit).
    pub fn credit_peer(&mut self, node_pk: &[u8], bytes: u64, now: u64) {
        let acct = self.touch(node_pk, now);
        acct.served_to_us += bytes;
        // Serving us is transfer activity too (ranked-slot eligibility).
        acct.last_activity = Some(now);
        self.dirty = true;
    }

    /// Mobile / battery / metered gate: pause or resume all bulk uploads.
    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    /// Decide whether to serve `bytes` of BULK data to a peer right now.
    /// `first_paint` marks a fetch of a small object (page assets: index,
    /// bundles, thumbnails — classified by the OBJECT's total size, not the
    /// request's), which is exempt from the reciprocity CHOKE up to the
    /// free budget; large-object (media) requests are bulk and never draw
    /// on it. First-paint bytes ride the priority lane, so the per-second
    /// bucket here (cap + foreground yield) is what governs them — with a
    /// multi-GB budget per peer, an exemption would let a handful of
    /// syncing peers saturate the uplink the moment the user's own traffic
    /// needs it. BULK admission no longer draws on the bucket: an admitted
    /// bulk request's bytes are smoothed onto the wire by the bulk-lane
    /// pacer ([`crate::pace`], same cap and yield) instead of being
    /// refused whole — a per-second bucket over multi-hundred-KiB batches
    /// turned every saturated second into a BUSY storm, and each BUSY
    /// costs the leecher a cooldown. First-paint payload charges the
    /// pacer's debt at the writer too (never waiting there), so the two
    /// lanes share the one cap rather than spending a cap each.
    /// `foreground` signals the user's own traffic is active (LEDBAT
    /// yield).
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

        // Every serve request is transfer activity: the request itself is
        // what tells a leecher actually pulling apart from an idle conn
        // squatting a slot. The cached set is rebuilt only when this flips
        // the peer's eligibility, not on every request.
        {
            let acct = self.touch(node_pk, now);
            let was_active =
                acct.last_activity.is_some_and(|t| now.saturating_sub(t) <= ACTIVE_WINDOW_SECS);
            acct.last_activity = Some(now);
            if !was_active {
                self.dirty = true;
            }
        }

        // Roll the per-second bucket, yielding under foreground.
        if now != self.second_ts {
            self.second_ts = now;
            self.second_bytes = 0;
        }
        let effective_cap = if foreground {
            self.global_cap_bps.saturating_mul(self.foreground_yield_num) / 256
        } else {
            self.global_cap_bps
        };

        // First-paint exemption from the choke (per-peer free budget,
        // windowed), refused past the bucket: the priority lane it rides
        // is the one lane the pacer never shapes.
        if first_paint {
            if self.second_bytes + bytes > effective_cap {
                return ServeDecision::Throttled;
            }
            let acct = self.touch(node_pk, now);
            if now.saturating_sub(acct.free_window_start) >= FIRST_PAINT_WINDOW_SECS {
                acct.free_window_start = now;
                acct.free_spent = 0;
            }
            if acct.free_spent + bytes <= FIRST_PAINT_FREE_BYTES {
                acct.free_spent += bytes;
                self.second_bytes += bytes;
                return ServeDecision::FirstPaint;
            }
            // Over the free budget: fall through to the choke.
        }

        // Reciprocity choke: is this peer in an unchoke slot?
        if !self.is_unchoked(node_pk, now) {
            return ServeDecision::Choked;
        }

        if first_paint {
            // Past the free budget but still on the priority lane: the
            // bucket stays its governor.
            self.second_bytes += bytes;
        }
        if let Some(acct) = self.peers.get_mut(node_pk) {
            acct.served_by_us += bytes;
            acct.last_seen = now;
        }
        ServeDecision::Serve
    }

    /// When a refused peer should come back: a Choked one at the next
    /// unchoke rotation (the set changes then), a Throttled one next
    /// second (the bucket rolls per second) — unless bulk is paused, which
    /// lasts minutes. Feeds the typed `Resp::Busy` retry hint.
    pub fn retry_after_secs(&self, decision: ServeDecision, now: u64) -> u64 {
        match decision {
            ServeDecision::Choked => OPTIMISTIC_ROTATE_SECS - (now % OPTIMISTIC_ROTATE_SECS),
            ServeDecision::Throttled if self.paused => PAUSED_RETRY_SECS,
            ServeDecision::Throttled => 1,
            ServeDecision::Serve | ServeDecision::FirstPaint => 0,
        }
    }

    /// Is this peer in the current unchoke set? Answered from the cache;
    /// the set is rebuilt only when the rotation epoch turns over or the
    /// ranking inputs changed.
    fn is_unchoked(&mut self, node_pk: &[u8], now: u64) -> bool {
        let epoch = now / OPTIMISTIC_ROTATE_SECS;
        if self.dirty || epoch != self.unchoked_epoch {
            self.rebuild_unchoked(epoch, now);
        }
        self.unchoked.contains(node_pk)
    }

    /// The unchoke set for a rotation epoch. Ranked slots are competed for
    /// by peers that are CONNECTED and recently ACTIVE (see
    /// [`ACTIVE_WINDOW_SECS`]): a slot's point is serving someone actually
    /// pulling, and an unreachable overlay leecher — permanent zero credit,
    /// since we can never dial it back — must not be frozen out by credited
    /// accounts that are not even here. Reciprocity stays the PRIORITY
    /// (top contributors first), never the admission: among equals the
    /// least-served-by-us peer wins, which rotates contested slots across
    /// zero-credit leechers instead of starving all but one.
    fn rebuild_unchoked(&mut self, epoch: u64, now: u64) {
        let active = |a: &PeerAccount| {
            a.conns > 0
                && a.last_activity.is_some_and(|t| now.saturating_sub(t) <= ACTIVE_WINDOW_SECS)
        };
        let mut ranked: Vec<(&[u8], &PeerAccount)> = self
            .peers
            .iter()
            .filter(|(_, a)| active(a))
            .map(|(pk, a)| (pk.as_slice(), a))
            .collect();
        // Highest contribution first; ties go to whoever we have served
        // least (fair-share among zero-credit leechers), then by key so
        // the order is deterministic.
        ranked.sort_by(|a, b| {
            b.1.served_to_us
                .cmp(&a.1.served_to_us)
                .then(a.1.served_by_us.cmp(&b.1.served_by_us))
                .then(a.0.cmp(b.0))
        });

        let mut unchoked: HashSet<Vec<u8>> = HashSet::new();
        let mut overlay_slots = OVERLAY_RESERVED_SLOTS;
        let mut general_slots = UNCHOKE_SLOTS - OVERLAY_RESERVED_SLOTS;

        // Reserve overlay slots first (best-ranked overlay peers).
        for (pk, _) in ranked.iter().filter(|(_, a)| a.reach == Reach::Overlay) {
            if overlay_slots == 0 {
                break;
            }
            unchoked.insert(pk.to_vec());
            overlay_slots -= 1;
        }
        // Fill general slots by rank.
        for (pk, _) in &ranked {
            if general_slots == 0 {
                break;
            }
            if unchoked.insert(pk.to_vec()) {
                general_slots -= 1;
            }
        }
        // Optimistic slot: rotates deterministically by time over every
        // CONNECTED peer (active or not), so a newcomer that has not made
        // its first request still gets periodic service to bootstrap on.
        let mut connected: Vec<&[u8]> = self
            .peers
            .iter()
            .filter(|(_, a)| a.conns > 0)
            .map(|(pk, _)| pk.as_slice())
            .collect();
        if !connected.is_empty() {
            connected.sort_unstable();
            let rotate = epoch as usize % connected.len();
            unchoked.insert(connected[rotate].to_vec());
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
        // first-paint exemption and the choke, not the byte cap. (The
        // whole multi-GB budget is drawn in one call, so the cap must
        // exceed it.)
        let mut c = Choker::new(1 << 40);
        // More high contributors than unchoke slots — connected and
        // active, so the fresh peer is genuinely choked for bulk (not
        // just handed a free slot).
        for i in 10..(10 + UNCHOKE_SLOTS as u8 + 4) {
            let p = pk(i);
            c.note_connected(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, 1_000_000, 0);
        }
        // Fresh, zero contribution, ranks last; sorts after every
        // contributor so the epoch-0 optimistic slot is not its.
        let peer = pk(200);
        c.note_connected(&peer, Reach::Clearnet, 0);
        // A fresh peer with zero contribution is choked for BULK...
        assert_eq!(c.decide(&peer, 1000, false, false, 0), ServeDecision::Choked);
        // ...but first-paint bytes are served up to the free budget.
        assert_eq!(c.decide(&peer, FIRST_PAINT_FREE_BYTES, true, false, 0), ServeDecision::FirstPaint);
        // Once the budget is spent, further first-paint bytes fall back to
        // the normal choke (this peer holds no slot -> Choked).
        assert_eq!(c.decide(&peer, 1000, true, false, 0), ServeDecision::Choked);
    }

    /// The generous defaults: with no contention (fewer peers than slots),
    /// nobody is ever choked, even with zero contribution — reciprocity
    /// only decides who keeps service when peers COMPETE for slots. The
    /// first request itself is the activity that admits a peer to ranking,
    /// so no warm-up round is needed.
    #[test]
    fn a_small_swarm_is_never_choked() {
        let mut c = Choker::new(1_000_000_000);
        for i in 0..10u8 {
            c.note_connected(&pk(i), Reach::Clearnet, 0);
        }
        for i in 0..10u8 {
            assert_eq!(c.decide(&pk(i), 100_000, false, false, 5), ServeDecision::Serve);
        }
    }

    /// The free budget sustains ~10 MB/s for a whole window: a fresh peer
    /// syncing a site at home-connection speed never hits the choke.
    #[test]
    fn a_fresh_peer_draws_ten_megabytes_per_second_free() {
        let mut c = Choker::new(1_000_000_000);
        let peer = pk(1);
        c.note_peer(&peer, Reach::Clearnet, 0);
        for t in 0..FIRST_PAINT_WINDOW_SECS {
            assert_eq!(c.decide(&peer, 10_000_000, true, false, t), ServeDecision::FirstPaint);
        }
    }

    #[test]
    fn free_budget_refills_each_window() {
        let mut c = Choker::new(1 << 40);
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
        // Twenty peers, more than the unchoke slots. Distinct
        // contributions, all connected and recently active at probe time.
        for i in 0..20u8 {
            let p = pk(i);
            c.note_connected(&p, Reach::Clearnet, 90);
            c.credit_peer(&p, (i as u64 + 1) * 1000, 90);
        }
        // The top contributor (i=19) is served; the lowest (i=0) ranks
        // outside every general slot and is not the optimistic pick at
        // t=100 (epoch 3 of 20 lands on pk(3)).
        assert_eq!(c.decide(&pk(19), 100, false, false, 100), ServeDecision::Serve);
        assert_eq!(c.decide(&pk(0), 100, false, false, 100), ServeDecision::Choked);
    }

    #[test]
    fn overlay_slot_is_reserved() {
        let mut c = Choker::new(1_000_000_000);
        // Enough high-contributing clearnet peers to fill every general
        // slot...
        for i in 0..UNCHOKE_SLOTS as u8 {
            let p = pk(i);
            c.note_connected(&p, Reach::Clearnet, 0);
            c.credit_peer(&p, 1_000_000, 0);
        }
        // ...and one overlay peer with ZERO contribution (an unreachable
        // leecher can never earn any: we cannot dial it back).
        let overlay = pk(100);
        c.note_connected(&overlay, Reach::Overlay, 0);
        // The reserved overlay slot means it is still served despite being
        // outclassed on contribution (a Tor-only peer isn't frozen out).
        assert_eq!(c.decide(&overlay, 100, false, false, 5), ServeDecision::Serve);
    }

    /// First-paint bypasses only the CHOKE, never the governor: with a
    /// multi-GB free budget per peer, a cap exemption would let a few
    /// syncing peers saturate the uplink. Free-budget bytes must respect
    /// the cap, the foreground yield, and count into the global tally.
    #[test]
    fn first_paint_respects_the_global_cap_and_foreground_yield() {
        let mut c = Choker::new(10_000); // 10 KB/s
        let a = pk(1);
        let b = pk(2);
        c.note_peer(&a, Reach::Clearnet, 0);
        c.note_peer(&b, Reach::Clearnet, 0);
        // Within the cap: served off the free budget.
        assert_eq!(c.decide(&a, 8000, true, false, 1), ServeDecision::FirstPaint);
        // A SECOND peer's first-paint in the same second exceeds the cap:
        // free-budget bytes count into the global tally, so the exemption
        // has a cross-peer bound.
        assert_eq!(c.decide(&b, 8000, true, false, 1), ServeDecision::Throttled);
        // Under foreground load the effective cap is ~25%: too-large
        // first-paint yields to the user's own traffic.
        assert_eq!(c.decide(&a, 8000, true, true, 2), ServeDecision::Throttled);
        assert_eq!(c.decide(&a, 2000, true, true, 2), ServeDecision::FirstPaint);
    }

    /// The per-second bucket refuses only FIRST-PAINT (priority-lane)
    /// bytes now: admitted bulk is smoothed by the bulk-lane pacer at the
    /// connection writer instead, so a saturated second must not turn into
    /// a BUSY storm (every refusal costs the leecher a client-side
    /// cooldown, which is what made saturated seeders serve in sawtooth).
    #[test]
    fn the_bucket_refuses_first_paint_but_never_bulk() {
        let mut c = Choker::new(10_000); // 10 KB/s
        let peer = pk(1);
        c.note_connected(&peer, Reach::Clearnet, 1);
        c.credit_peer(&peer, 10_000_000, 1); // top contributor -> unchoked
        assert_eq!(c.decide(&peer, 8000, false, false, 1), ServeDecision::Serve);
        // Way past the old per-second refusal point, same second, even
        // under foreground: still admitted (the pacer owns the rate).
        assert_eq!(c.decide(&peer, 8000, false, false, 1), ServeDecision::Serve);
        assert_eq!(c.decide(&peer, 80_000, false, true, 1), ServeDecision::Serve);
    }

    #[test]
    fn mobile_pause_stops_everything() {
        let mut c = Choker::new(1_000_000_000);
        let peer = pk(1);
        c.note_connected(&peer, Reach::Clearnet, 0);
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

    /// A CONNECTED account must survive eviction even as the worst-ranked
    /// one — its connection refcount would dangle otherwise. Live conns
    /// are bounded far below the table cap by the accept side.
    #[test]
    fn a_connected_account_survives_the_eviction_sweep() {
        let mut c = Choker::new(1_000_000_000);
        let live = pk_n(u32::MAX);
        c.note_connected(&live, Reach::Overlay, 0); // zero credit: worst rank
        for i in 0..(MAX_TRACKED_PEERS as u32 + 200) {
            c.note_peer(&pk_n(i), Reach::Clearnet, 1);
        }
        assert!(c.peers.get(&live).is_some_and(|a| a.conns == 1), "the live conn is kept");
    }

    /// RC6 regression: an unreachable overlay leecher has permanent zero
    /// credit (we can never dial it back to earn any), and ranking every
    /// account it ever competed with froze it out of every slot for good.
    /// Ranked slots now run over connected+active peers, so credited
    /// accounts that are not even connected cannot freeze out the
    /// leechers actually here.
    #[test]
    fn zero_credit_overlay_leechers_hold_the_reserved_slots() {
        let mut c = Choker::new(1_000_000_000);
        // Credited history: accounts from past sessions, NOT connected.
        for i in 100..140u8 {
            let p = pk(i);
            c.note_peer(&p, Reach::Overlay, 0);
            c.credit_peer(&p, 1_000_000, 0);
        }
        // Four overlay leechers, connected, zero credit, actively pulling.
        for i in 0..4u8 {
            c.note_connected(&pk(i), Reach::Overlay, 5);
        }
        for i in 0..4u8 {
            assert_eq!(
                c.decide(&pk(i), 100_000, false, false, 5),
                ServeDecision::Serve,
                "leecher {i} must be served despite 40 credited absent accounts"
            );
        }
    }

    /// Slot-squatting: node_pk is free, so idle conns minted to hold
    /// slots must lose them. A conn that stops transferring goes inactive
    /// after ACTIVE_WINDOW_SECS and stops occupying a ranked slot; asking
    /// again readmits it like any other leecher.
    #[test]
    fn idle_conns_lose_ranked_slots_to_active_leechers() {
        let mut c = Choker::new(1_000_000_000);
        // More sybil conns than there are slots, each active once at t=0.
        for i in 100..(100 + UNCHOKE_SLOTS as u8 + 8) {
            c.note_connected(&pk(i), Reach::Overlay, 0);
            c.decide(&pk(i), 1, false, false, 0);
        }
        // A real leecher arriving past the window: the sybils' idle conns
        // no longer count, so it is served, not frozen out by 24
        // squatting identities.
        let late = ACTIVE_WINDOW_SECS + 30;
        let leecher = pk(1);
        c.note_connected(&leecher, Reach::Overlay, late);
        assert_eq!(c.decide(&leecher, 100_000, false, false, late), ServeDecision::Serve);
        // A squatter that actually asks again is just a leecher:
        // readmitted by its own request.
        assert_eq!(c.decide(&pk(100), 100_000, false, false, late), ServeDecision::Serve);
    }

    /// Reciprocity is prioritization, not admission: under genuine
    /// contention (more active conns than slots) a contributor is served
    /// ahead of zero-credit peers.
    #[test]
    fn contributors_outrank_active_squatters_under_contention() {
        let mut c = Choker::new(1_000_000_000);
        for i in 100..(100 + UNCHOKE_SLOTS as u8 + 8) {
            c.note_connected(&pk(i), Reach::Overlay, 0);
            c.decide(&pk(i), 1, false, false, 0);
        }
        let seeder = pk(1);
        c.note_connected(&seeder, Reach::Overlay, 0);
        c.credit_peer(&seeder, 1_000_000, 0);
        assert_eq!(c.decide(&seeder, 100_000, false, false, 0), ServeDecision::Serve);
    }

    /// A disconnect frees the slot: ranking is over live connections, so
    /// a contributor that left stops occupying a slot it cannot use.
    #[test]
    fn disconnect_releases_the_slot() {
        let mut c = Choker::new(1_000_000_000);
        for i in 10..(10 + UNCHOKE_SLOTS as u8 + 4) {
            c.note_connected(&pk(i), Reach::Clearnet, 0);
            c.credit_peer(&pk(i), 1_000_000, 0);
        }
        let peer = pk(1);
        c.note_connected(&peer, Reach::Clearnet, 0);
        c.credit_peer(&peer, 2_000_000, 0); // top contributor: unchoked
        assert_eq!(c.decide(&peer, 100, false, false, 0), ServeDecision::Serve);
        c.note_disconnected(&peer, 1);
        assert_eq!(c.decide(&peer, 100, false, false, 1), ServeDecision::Choked);
    }

    /// The typed-BUSY retry hints point at the next decision point: the
    /// unchoke rotation for a choked peer, the next bucket second for a
    /// throttled one, a pause-scale breather when bulk is paused.
    #[test]
    fn retry_hints_point_at_the_next_decision_point() {
        let mut c = Choker::new(10_000);
        assert_eq!(c.retry_after_secs(ServeDecision::Choked, 65), OPTIMISTIC_ROTATE_SECS - 5);
        assert_eq!(c.retry_after_secs(ServeDecision::Throttled, 65), 1);
        c.set_paused(true);
        assert_eq!(c.retry_after_secs(ServeDecision::Throttled, 65), PAUSED_RETRY_SECS);
        assert_eq!(c.retry_after_secs(ServeDecision::Serve, 65), 0);
    }

    #[test]
    fn unchoke_cache_reflects_credit_within_the_same_rotation() {
        let mut c = Choker::new(1_000_000_000);
        for i in 0..20u8 {
            let p = pk(i);
            c.note_connected(&p, Reach::Clearnet, 90);
            c.credit_peer(&p, 1_000_000, 90);
        }
        let late = pk(200);
        c.note_connected(&late, Reach::Clearnet, 100);
        // Zero contribution, every slot held, and not the optimistic pick
        // at t=100 (rotation index 3 of 21 lands on pk(3)).
        assert_eq!(c.decide(&late, 100, false, false, 100), ServeDecision::Choked);
        // A big credit inside the SAME rotation window takes effect at
        // once: the cached set is invalidated, not held until the next one.
        c.credit_peer(&late, 10_000_000, 100);
        assert_eq!(c.decide(&late, 100, false, false, 100), ServeDecision::Serve);
    }

    #[test]
    fn unchoke_cache_rotates_with_the_clock() {
        let mut c = Choker::new(1_000_000_000);
        // Fifteen contributors and one freeloader, pk(13): more
        // contributors than the 12 general slots, so the freeloader holds
        // no ranked slot and rides only the optimistic rotation.
        let t13 = 13 * OPTIMISTIC_ROTATE_SECS;
        let t14 = 14 * OPTIMISTIC_ROTATE_SECS;
        for i in 0..16u8 {
            c.note_connected(&pk(i), Reach::Clearnet, t13);
            if i != 13 {
                c.credit_peer(&pk(i), 1_000_000, t13);
            }
        }
        // The optimistic slot rotates over the connected set in key order,
        // so epoch 13 of 16 lands exactly on pk(13): served.
        let held = c.decide(&pk(13), 100, false, false, t13);
        assert_eq!(held, ServeDecision::Serve);
        // Next rotation the slot moves on, and the cached set moves with
        // it (the contributors stay active: re-credited inside the window).
        for i in 0..16u8 {
            if i != 13 {
                c.credit_peer(&pk(i), 1_000, t14);
            }
        }
        let dropped = c.decide(&pk(13), 100, false, false, t14);
        assert_eq!(dropped, ServeDecision::Choked);
    }
}
