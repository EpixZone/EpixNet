//! Multi-peer fetch scheduler: a sliding window of rarest-first batches
//! with progress-based (stall-only) failure and duplication.
//!
//! The driver ([`Swarm`]) fetches an object's missing chunk groups from
//! many peers at once — torrent-style striping — so a hot object comes
//! down as fast as the fastest peers allow, verified per chunk against
//! the signed root the whole way (`fetch::fetch_ranges`). The policy
//! pieces the plan calls out:
//!
//! - **rarest-first**: groups held by the fewest peers are scheduled
//!   first, so the swarm keeps every piece alive instead of everyone
//!   grabbing the common prefix.
//! - **sliding window**: up to [`PIPELINE_DEPTH`] batches stay in flight
//!   per healthy peer, each slot refilled the moment its batch completes.
//!   There is no round barrier for one slow batch to hold up.
//! - **stall-only failure/duplication**: a batch fails (or is raced onto
//!   another peer) only when NO new bytes arrive for a transport-aware
//!   stall window — an onion circuit moving 1 MiB at 100 KB/s is slow,
//!   not dead, and must never be cut down by an elapsed-time deadline.
//!   Duplicates go to equal-or-lower-latency classes only and are capped,
//!   so a stall can't fan out unboundedly.
//! - **durable progress**: a failed batch keeps the groups its streamed
//!   prefix already verified into the store (`Store::write_slice_partial`)
//!   and only the remainder is rescheduled.
//! - **deadline tiers**: tight for streaming/first-paint, loose for
//!   background; the tier bounds a batch's absolute wait.
//!
//! This module owns the DECISION logic (what to ask which peer, when to
//! duplicate) and drives it via the fetch client; the choker
//! (`choke.rs`) governs the upload side.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use epix_blob::bitfield::{group_count, GroupBits};
use epix_blob::store::Store;
use epix_blob::ObjId;

use crate::conn::Conn;
use crate::fetch;
use crate::sim::Class;

/// Max concurrent duplicate fetches of the same group set (endgame cap).
pub const MAX_DUPLICATES: usize = 2;
/// Share of a batch's budget the primary's stall window may cover (1/N of
/// the cap). A stall detected only near the cap would leave the duplicated
/// race no time to answer.
pub const PRIMARY_BUDGET_DIVISOR: u32 = 2;
/// Groups per striped request (16 KiB * 64 = 1 MiB chunks of work).
pub const GROUPS_PER_REQUEST: u64 = 64;
/// Groups per request on an overlay link (16 KiB * 32 = 512 KiB).
///
/// A Tor/I2P circuit carries a few hundred KB/s, so a 1 MiB batch occupies it
/// for seconds - measured here, 4 s at 250 KB/s and 32 s on a bad circuit.
/// That coarseness costs three ways while streaming: a failed batch throws
/// away a megabyte of circuit time (batch failures ran ~20% on a live overlay
/// swarm), the stall detector cannot react inside a batch, and the served
/// contiguous prefix only advances a megabyte at a time, which is what a
/// player feels as a stall. Halving the batch halves all three, and together
/// with [`PIPELINE_DEPTH_OVERLAY`] sets the bytes a circuit keeps in flight -
/// the per-link throughput ceiling (window / RTT). 512 KiB is comfortably
/// inside the server's per-request caps (64 ranges / 64 MiB), so old seeders
/// serve it unchanged.
pub const GROUPS_PER_REQUEST_OVERLAY: u64 = 32;
/// A clearnet transfer with no new bytes for this long is stalled.
pub const STALL_CLEARNET: Duration = Duration::from_secs(4);
/// Overlay stall window: an onion/I2P circuit legitimately pauses for
/// seconds where the same clearnet silence means trouble.
pub const STALL_OVERLAY: Duration = Duration::from_secs(12);
/// Absolute per-batch cap, progress or not: the backstop against a peer
/// that trickles a byte a second forever. This is the budget for ONE
/// request's worth of link queue; `race_batch` scales it by the link's
/// queue depth ([`link_queue_depth`]), because a batch behind N requests'
/// worth of bytes on the circuit legitimately needs N shares of it just
/// to drain - a fixed cap here let a deeper pipeline manufacture batch
/// failures on a slow-but-healthy circuit.
pub const MAX_BATCH_WAIT: Duration = Duration::from_secs(90);
/// Batches kept in flight per healthy peer by the sliding window.
pub const PIPELINE_DEPTH: u32 = 2;
/// Sliding-window depth on an overlay link.
///
/// A link's throughput is capped at bytes-in-flight over round trip. The old
/// 3 x 256 KiB = 768 KiB window was itself the per-circuit ceiling on live
/// onion links: at the 1-2 s RTTs measured there it capped every transfer at
/// ~300-400 KB/s regardless of what the circuit could carry. 6 x 512 KiB =
/// 3 MiB in flight lifts that ceiling to ~1.5-3 MB/s. The cost of queueing
/// deeper - a healthy request waiting behind its siblings looks silent - is
/// paid for by scaling the stall window and the absolute batch cap with the
/// bytes actually queued on the link ([`link_queue_depth`]), not just this
/// swarm's own load.
pub const PIPELINE_DEPTH_OVERLAY: u32 = 6;
/// Consecutive failed batches before a peer is exhausted (dropped from
/// scheduling for the rest of the fetch); a delivered batch resets it.
pub const PEER_FAIL_LIMIT: u32 = 3;

/// How much work one request to `class` carries. Overlay links get smaller
/// batches (see [`GROUPS_PER_REQUEST_OVERLAY`]).
pub fn groups_per_request(class: Class) -> u64 {
    match class {
        Class::Clearnet => GROUPS_PER_REQUEST,
        Class::I2p | Class::Tor => GROUPS_PER_REQUEST_OVERLAY,
    }
}

/// How many batches to `class` stay in flight at once. Overlay links run
/// more, smaller batches: the window has to cover a much larger
/// bandwidth-delay product (see [`PIPELINE_DEPTH_OVERLAY`]).
pub fn pipeline_depth(class: Class) -> u32 {
    match class {
        Class::Clearnet => PIPELINE_DEPTH,
        Class::I2p | Class::Tor => PIPELINE_DEPTH_OVERLAY,
    }
}

/// The batch size for a fetch over `peers`: the smallest any of them wants,
/// so a session with even one overlay link uses the fine-grained batching
/// that link needs. Batches are cut before a peer is picked (the pick needs
/// the batch's groups), so one size has to serve the whole peer set; taking
/// the minimum keeps a slow circuit from being handed a megabyte, and costs
/// a fast peer only some request overhead it has the bandwidth to absorb.
pub fn batch_groups_for(peers: &[PeerHandle]) -> u64 {
    peers.iter().map(|p| groups_per_request(p.class)).min().unwrap_or(GROUPS_PER_REQUEST)
}

/// The no-new-bytes window for one request, given how many requests are
/// already queued on that link.
///
/// Stall detection is per-request, but a pipelined link serves its requests
/// roughly in turn: with `inflight` of them outstanding, a request can wait
/// its whole share of the link before its first byte arrives, while the link
/// is working perfectly. Judging it against the bare [`stall_timeout`] made a
/// healthy overlay link look stalled, and every such "stall" was duplicated
/// onto another peer - which spent the swarm's scarce bandwidth re-fetching
/// bytes already on the way, slowing the real transfers and producing more
/// apparent stalls. Observed live: 242 duplicates against 291 real requests,
/// with per-peer failure rates of 23-56%.
///
/// Scaling the window by the queue depth keeps the detector meaningful (a
/// link that has genuinely gone silent still trips it, just proportionally
/// later) while a request merely waiting its turn does not.
///
/// `inflight` is the LINK's queue depth, not this swarm's: several swarms
/// can share one circuit (the link pool hands out clones of one conn per
/// lane), and a batch waiting behind another swarm's traffic is exactly as
/// not-stalled as one waiting behind its own siblings. The scheduler takes
/// the larger of its own load and [`link_queue_depth`].
pub fn stall_window(class: Class, inflight: u32) -> Duration {
    stall_timeout(class) * inflight.max(1)
}

/// The link's queue depth in requests: `queued_bytes` outstanding on the
/// connection across every swarm sharing it (see
/// [`Conn::queued_fetch_bytes`]), in units of the class's request size,
/// rounded up. Feeds [`stall_window`] and the batch cap in the same unit
/// the swarm's own load is counted in.
pub fn link_queue_depth(class: Class, queued_bytes: u64) -> u32 {
    let request_bytes = groups_per_request(class) * epix_blob::bitfield::GROUP_BYTES;
    queued_bytes.div_ceil(request_bytes).min(u32::MAX as u64) as u32
}

/// The no-new-bytes window after which a transfer to `class` counts as
/// stalled (the trigger for duplication and, with nowhere to duplicate,
/// for failing the batch).
pub fn stall_timeout(class: Class) -> Duration {
    match class {
        Class::Clearnet => STALL_CLEARNET,
        Class::I2p | Class::Tor => STALL_OVERLAY,
    }
}

/// Smoothed per-class round-trip prior. Starts at the class's nominal
/// RTT and converges toward observed request latencies (EWMA, alpha 1/4).
/// Feeds duplicate-target ordering (`faster_or_equal`) and peer picking.
#[derive(Clone, Debug)]
pub struct ClassStats {
    rtt: HashMap<Class, Duration>,
}

impl Default for ClassStats {
    fn default() -> Self {
        let mut rtt = HashMap::new();
        for c in [Class::Clearnet, Class::I2p, Class::Tor] {
            // Nominal RTT prior = 2x one-way latency.
            rtt.insert(c, c.spec().latency * 2);
        }
        Self { rtt }
    }
}

impl ClassStats {
    pub fn rtt(&self, class: Class) -> Duration {
        self.rtt.get(&class).copied().unwrap_or_else(|| Duration::from_secs(1))
    }

    /// Fold an observed request latency into the class prior.
    pub fn observe(&mut self, class: Class, sample: Duration) {
        let prior = self.rtt(class);
        // EWMA: new = 3/4 prior + 1/4 sample.
        let next = (prior * 3 + sample) / 4;
        self.rtt.insert(class, next);
    }

    /// Classes at equal-or-lower latency than `class` (valid duplication
    /// targets — never duplicate onto something slower).
    pub fn faster_or_equal(&self, class: Class) -> Vec<Class> {
        let bound = self.rtt(class);
        let mut out: Vec<Class> = [Class::Clearnet, Class::I2p, Class::Tor]
            .into_iter()
            .filter(|c| self.rtt(*c) <= bound)
            .collect();
        out.sort_by_key(|c| self.rtt(*c));
        out
    }
}

/// Smoothed per-PEER service time, measured per group so batches of
/// different sizes compare directly.
///
/// [`ClassStats`] answers "how fast is Tor today", which is the right
/// question for choosing a duplication target but not for choosing between
/// two peers of the SAME class: measured live, one onion peer served a group
/// in ~250 ms while another on the same circuit type took ~2 s, and the class
/// prior rated them identically. For a streaming deadline that difference is
/// the whole game - a batch just past the play head handed to the slow one
/// arrives after the player needed it, however healthy the swarm's aggregate
/// throughput looks.
///
/// A peer with no sample yet has no entry, and picking falls back to its class
/// prior, so an unmeasured peer is still tried rather than starved by peers
/// that happen to have gone first.
#[derive(Clone, Debug, Default)]
pub struct PeerStats {
    per_group: HashMap<String, Duration>,
}

impl PeerStats {
    /// Fold one delivered batch into the peer's prior. `groups` is the batch's
    /// group count; a zero-group batch carries no rate information.
    pub fn observe(&mut self, label: &str, elapsed: Duration, groups: u64) {
        if groups == 0 {
            return;
        }
        let sample = elapsed / groups as u32;
        let next = match self.per_group.get(label) {
            // EWMA: new = 3/4 prior + 1/4 sample, matching ClassStats.
            Some(prior) => (*prior * 3 + sample) / 4,
            None => sample,
        };
        self.per_group.insert(label.to_string(), next);
    }

    /// The peer's smoothed per-group service time, if it has delivered.
    pub fn per_group(&self, label: &str) -> Option<Duration> {
        self.per_group.get(label).copied()
    }
}

/// Live reporting hook for one [`Swarm::fetch`].
///
/// The scheduler already knows everything a torrent client's transfer pane
/// shows - which peer a request went to, how many bytes it delivered, how
/// long it took, whether it stalled - but that all died with the
/// [`FetchReport`] when the fetch returned. An observer publishes it as it
/// happens, so the UI can show a live per-peer picture instead of a summary
/// nobody ever sees. Reporting must be cheap and must never block: these
/// fire on the fetch's own task, between batches.
pub trait FetchObserver: Send + Sync {
    /// A batch was booked onto `peer` (its request is now in flight).
    fn on_request(&self, peer: &str, class: Class, bytes: u64);
    /// A batch completed. `bytes` is what verified into the store from it
    /// (0 on a total failure), `peer` the label of whoever delivered - which
    /// is not necessarily the peer the batch was booked onto, since a
    /// stalled batch is raced onto others. `booked` is that original peer,
    /// so an in-flight count can be released against the same peer it was
    /// taken from.
    fn on_batch(&self, booked: &str, peer: Option<&str>, class: Option<Class>, bytes: u64,
                elapsed: Option<Duration>, duplicates: u64);
}

/// A peer available to fetch from: its connection, transport class, and
/// last-known availability bitfield for the object in question.
pub struct PeerHandle {
    pub conn: Conn,
    pub class: Class,
    pub bits: GroupBits,
    /// Stable label for tests/metrics.
    pub label: String,
}

/// Order missing groups rarest-first: for each needed group, count how
/// many peers hold it; schedule the least-held groups first. Returns
/// group indices in scheduling order (only groups at least one peer has).
pub fn rarest_first_order(needed: &GroupBits, peers: &[PeerHandle]) -> Vec<u64> {
    let mut counts: Vec<(u64, u64)> = Vec::new(); // (holders, group)
    for run in needed.ranges() {
        for g in run.clone() {
            let holders = peers.iter().filter(|p| p.bits.contains(g)).count() as u64;
            if holders > 0 {
                counts.push((holders, g));
            }
        }
    }
    counts.sort();
    counts.into_iter().map(|(_, g)| g).collect()
}

/// Order missing groups in play order: lowest index first, skipping any no
/// peer holds. What a player needs, and NOT what [`rarest_first_order`] gives.
///
/// A serve can only hand the player the CONTIGUOUS prefix of its window that
/// has landed (`present_prefix_len`), so one hole truncates everything behind
/// it however much of the window arrived: a node holding most of a film still
/// shows "buffering" if the group at the play head is the one outstanding.
/// Rarest-first maximises swarm health by spreading which pieces exist, which
/// is right for a bulk transfer and precisely wrong here - it scatters arrivals
/// across the window, so the prefix crawls while total throughput looks fine.
///
/// Bulk fetches keep rarest-first, so the swarm still gets that property from
/// every non-streaming transfer; only a fetch feeding a player trades it for
/// contiguity.
pub fn sequential_order(needed: &GroupBits, peers: &[PeerHandle]) -> Vec<u64> {
    let mut out = Vec::new();
    for run in needed.ranges() {
        for g in run.clone() {
            if peers.iter().any(|p| p.bits.contains(g)) {
                out.push(g);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Group a sorted list of group indices into contiguous request-sized
/// byte ranges for an object of `size` bytes.
pub fn batch_into_ranges(groups: &[u64], size: u64, max_groups: u64) -> Vec<std::ops::Range<u64>> {
    use epix_blob::bitfield::bytes_of_group;
    let mut out = Vec::new();
    let mut i = 0;
    while i < groups.len() {
        let start_group = groups[i];
        let mut end_group = start_group;
        let mut j = i + 1;
        while j < groups.len()
            && groups[j] == end_group + 1
            && (end_group + 1 - start_group) < max_groups
        {
            end_group = groups[j];
            j += 1;
        }
        let start = bytes_of_group(start_group, size).start;
        let end = bytes_of_group(end_group, size).end;
        out.push(start..end);
        i = j;
    }
    out
}

/// Partition `groups` (ascending) into maximal contiguous byte-range
/// batches, each fully held by at least one peer. Used when a
/// rarest-first batch straddles disjoint holder sets: the run is only
/// extended while the intersection of holding peers stays non-empty, so
/// every emitted range has a common holder (worst case one group per
/// range). Groups NO peer holds are dropped.
fn split_by_holder(
    groups: &[u64],
    peers: &[PeerHandle],
    size: u64,
    max_groups: u64,
) -> Vec<std::ops::Range<u64>> {
    use epix_blob::bitfield::bytes_of_group;
    let mut out = Vec::new();
    let mut i = 0;
    while i < groups.len() {
        // Peers holding this run's first group; skip groups no peer has.
        let mut holders: Vec<usize> = peers
            .iter()
            .enumerate()
            .filter(|(_, p)| p.bits.contains(groups[i]))
            .map(|(k, _)| k)
            .collect();
        if holders.is_empty() {
            i += 1;
            continue;
        }
        let start_group = groups[i];
        let mut end_group = start_group;
        let mut j = i + 1;
        while j < groups.len()
            && groups[j] == end_group + 1
            && (end_group + 1 - start_group) < max_groups
        {
            // Narrow to holders that also hold the next group; stop when
            // no single peer spans the extended run.
            let next: Vec<usize> =
                holders.iter().copied().filter(|&k| peers[k].bits.contains(groups[j])).collect();
            if next.is_empty() {
                break;
            }
            holders = next;
            end_group = groups[j];
            j += 1;
        }
        let start = bytes_of_group(start_group, size).start;
        let end = bytes_of_group(end_group, size).end;
        out.push(start..end);
        i = j;
    }
    out
}

/// The next `window` unassigned groups of the precomputed rarest-first
/// order: advance `cursor` past the already-fetched prefix, then collect
/// still-remaining groups not already assigned to an in-flight batch. A
/// group whose batch failed is still in `remaining` and no longer in
/// `inflight`, so it holds the cursor and is rescheduled, exactly as a
/// full recompute would.
fn next_unassigned(
    full_order: &[u64],
    cursor: &mut usize,
    remaining: &GroupBits,
    inflight: &GroupBits,
    window: usize,
) -> Vec<u64> {
    while *cursor < full_order.len() && !remaining.contains(full_order[*cursor]) {
        *cursor += 1;
    }
    let mut order = Vec::new();
    for &g in &full_order[*cursor..] {
        if order.len() >= window {
            break;
        }
        if remaining.contains(g) && !inflight.contains(g) {
            order.push(g);
        }
    }
    order
}

/// The fetch driver for one object across a peer set.
pub struct Swarm {
    store: Arc<Store>,
    obj: ObjId,
    size: u64,
    /// Interior-mutable: the in-flight batch futures borrow the swarm
    /// shared while completed outcomes fold their latencies back in.
    stats: Mutex<ClassStats>,
    /// Per-peer speed, the signal streaming peer-picking orders on.
    peer_stats: Mutex<PeerStats>,
    /// Live reporting sink, when the caller wants one.
    observer: Option<Arc<dyn FetchObserver>>,
}

/// What a completed fetch produced (for metrics/tests).
#[derive(Debug, Default, Clone)]
pub struct FetchReport {
    pub groups_fetched: u64,
    pub requests_issued: u64,
    pub duplicates_issued: u64,
    /// per-peer-label groups delivered.
    pub by_peer: HashMap<String, u64>,
}

/// An in-flight batch: boxed so the sliding window can hold a heterogenous
/// set and drop completed slots one at a time.
type BatchFut<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = BatchOutcome> + Send + 'a>>;

/// The sliding window's bookkeeping for one [`Swarm::fetch`]: the per-peer
/// pipeline load and failure counts, the groups an in-flight batch already
/// covers, and the batch futures themselves. There is no round barrier —
/// each completed batch frees its slot and [`Window::refill`] tops the
/// window back up.
struct Window<'a> {
    /// Batches in flight per peer.
    load: Vec<u32>,
    /// Consecutive per-peer failures: a failing peer is picked last and,
    /// past PEER_FAIL_LIMIT, exhausted (never picked again), so the swarm
    /// routes around it instead of retrying it forever. This is also what
    /// terminates the fetch when nothing is obtainable.
    fails: Vec<u32>,
    /// Per-peer sliding-window depth, from each peer's class: an overlay
    /// link runs more, smaller batches than a clearnet one.
    depth: Vec<u32>,
    /// Groups an in-flight batch is already covering.
    inflight: GroupBits,
    /// Boxed so the window can hold a heterogenous set and drop completed
    /// slots one at a time.
    futs: Vec<BatchFut<'a>>,
}

impl<'a> Window<'a> {
    fn new(peers: &[PeerHandle]) -> Self {
        Self {
            load: vec![0u32; peers.len()],
            fails: vec![0u32; peers.len()],
            depth: peers.iter().map(|p| pipeline_depth(p.class)).collect(),
            inflight: GroupBits::new(),
            futs: Vec::new(),
        }
    }

    /// Free pipeline slots across the peers still worth scheduling.
    fn free_slots(&self) -> usize {
        self.load
            .iter()
            .zip(self.fails.iter())
            .zip(self.depth.iter())
            .filter(|((_, f), _)| **f < PEER_FAIL_LIMIT)
            .map(|((l, _), d)| d.saturating_sub(*l) as usize)
            .sum()
    }

    /// Book one batch onto peer `idx`: take its pipeline slot, reserve its
    /// groups and push the racing future.
    #[allow(clippy::too_many_arguments)]
    fn schedule(
        &mut self,
        swarm: &'a Swarm,
        batch: std::ops::Range<u64>,
        groups: Vec<u64>,
        idx: usize,
        peers: &'a [PeerHandle],
        deadline: Deadline,
        now: u64,
        report: &mut FetchReport,
    ) {
        self.load[idx] += 1;
        for &g in &groups {
            self.inflight.add(g..g + 1);
        }
        report.requests_issued += 1;
        let bytes = swarm.bytes_of(&groups);
        if let Some(obs) = &swarm.observer {
            obs.on_request(&peers[idx].label, peers[idx].class, bytes);
        }
        // Charge this batch's bytes to the LINK before reading its depth,
        // so the counter includes us. The charge lives inside the batch
        // future and refunds on its drop (completed, failed or cancelled).
        let charge = peers[idx].conn.charge_fetch(bytes);
        // The stall window and cap scale on the link's whole queue: our own
        // load (`load[idx]` already counts this batch) or, when other swarms
        // share the circuit, the bytes they have queued on it - whichever
        // says the queue is deeper. Cross-swarm queueing on a shared circuit
        // is depth, not silence.
        let queued = self.load[idx]
            .max(link_queue_depth(peers[idx].class, peers[idx].conn.queued_fetch_bytes()));
        self.futs.push(Box::pin(
            swarm.race_batch(batch, groups, idx, peers, deadline, now, queued, charge),
        ));
    }

    /// Assign one batch to a peer that holds all of it, else split it by
    /// holder. Returns whether anything was scheduled.
    #[allow(clippy::too_many_arguments)]
    fn assign(
        &mut self,
        swarm: &'a Swarm,
        batch: std::ops::Range<u64>,
        peers: &'a [PeerHandle],
        deadline: Deadline,
        now: u64,
        batch_groups: u64,
        report: &mut FetchReport,
    ) -> bool {
        let bgroups = swarm.groups_of(&batch);
        match swarm.pick_peer(&bgroups, peers, &self.load, &self.fails, deadline) {
            Some(idx) => {
                self.schedule(swarm, batch, bgroups, idx, peers, deadline, now, report);
                true
            }
            None => {
                self.assign_split(swarm, &bgroups, peers, deadline, now, batch_groups, report)
            }
        }
    }

    /// A merged batch can straddle groups held by DISJOINT peers (equal
    /// holder COUNTS don't mean the same holder SET), so no single peer
    /// holds all of it. Split into maximal sub-batches each fully held by
    /// some peer instead of skipping it — skipping would strand groups that
    /// ARE available and leave the object stuck.
    #[allow(clippy::too_many_arguments)]
    fn assign_split(
        &mut self,
        swarm: &'a Swarm,
        bgroups: &[u64],
        peers: &'a [PeerHandle],
        deadline: Deadline,
        now: u64,
        batch_groups: u64,
        report: &mut FetchReport,
    ) -> bool {
        let mut assigned = false;
        for sub in split_by_holder(bgroups, peers, swarm.size, batch_groups) {
            let sgroups = swarm.groups_of(&sub);
            let Some(idx) = swarm.pick_peer(&sgroups, peers, &self.load, &self.fails, deadline)
            else {
                continue;
            };
            self.schedule(swarm, sub, sgroups, idx, peers, deadline, now, report);
            assigned = true;
        }
        assigned
    }

    /// Fill every free slot with the next unassigned batches, until the
    /// window is full or nothing in this slice is schedulable.
    #[allow(clippy::too_many_arguments)]
    fn refill(
        &mut self,
        swarm: &'a Swarm,
        full_order: &[u64],
        cursor: &mut usize,
        remaining: &GroupBits,
        peers: &'a [PeerHandle],
        deadline: Deadline,
        now: u64,
        batch_groups: u64,
        report: &mut FetchReport,
    ) {
        loop {
            let free = self.free_slots();
            if free == 0 {
                break;
            }
            let order = next_unassigned(
                full_order,
                cursor,
                remaining,
                &self.inflight,
                free * batch_groups as usize,
            );
            if order.is_empty() {
                break;
            }
            let mut assigned = false;
            for batch in batch_into_ranges(&order, swarm.size, batch_groups) {
                assigned |= self.assign(swarm, batch, peers, deadline, now, batch_groups, report);
            }
            if !assigned {
                break; // nothing schedulable in this window slice
            }
        }
    }

    /// Give a completed batch's pipeline slot and group reservations back.
    fn release(&mut self, outcome: &BatchOutcome) {
        self.load[outcome.primary] = self.load[outcome.primary].saturating_sub(1);
        for &g in &outcome.groups {
            self.inflight.remove(g..g + 1);
        }
    }
}

impl Swarm {
    pub fn new(store: Arc<Store>, obj: ObjId, size: u64) -> Self {
        Self {
            store,
            obj,
            size,
            stats: Mutex::new(ClassStats::default()),
            peer_stats: Mutex::new(PeerStats::default()),
            observer: None,
        }
    }

    /// Report this fetch's per-peer progress to `observer` as it runs.
    pub fn with_observer(mut self, observer: Arc<dyn FetchObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn stats(&self) -> ClassStats {
        self.stats.lock().expect("stats").clone()
    }

    /// Bytes the groups of `batch` cover, for the observer's accounting.
    fn bytes_of(&self, groups: &[u64]) -> u64 {
        use epix_blob::bitfield::bytes_of_group;
        groups.iter().map(|g| bytes_of_group(*g, self.size)).map(|r| r.end - r.start).sum()
    }

    /// Fetch every group in `needed` from the peer set, striping
    /// rarest-first through a sliding window and duplicating stalled
    /// batches onto faster-or-equal peers. Returns when all needed groups
    /// are present locally or no schedulable peer can supply a remaining
    /// group.
    ///
    /// `deadline` bounds a batch's absolute wait: a tight (streaming)
    /// deadline caps how long one batch may hold its groups.
    pub async fn fetch(
        &mut self,
        needed: &GroupBits,
        peers: &[PeerHandle],
        deadline: Deadline,
        now: u64,
    ) -> std::io::Result<FetchReport> {
        let mut report = FetchReport::default();
        let mut remaining = needed.clone();

        // Ensure the sparse object exists before writing slices.
        self.store.ensure_sparse(self.obj, epix_blob::Ns::Plain, self.size, now)?;

        // The peer set and their bitfields are fixed for this call, so the
        // rarest-first order never changes: build it once and walk it with a
        // cursor. Re-counting holders and re-sorting every remaining group
        // on each refill made a whole-object fetch quadratic in object size
        // (a 10 GB object is ~600k groups).
        // A player needs contiguity (see `sequential_order`); a bulk transfer
        // needs swarm health (see `rarest_first_order`).
        let full_order = if deadline.is_streaming() {
            sequential_order(needed, peers)
        } else {
            rarest_first_order(needed, peers)
        };
        // One size for the whole call: batches are cut before a peer is
        // picked, so the slowest class present sets it.
        let batch_groups = batch_groups_for(peers);
        let mut cursor = 0usize;
        let this = &*self;
        let mut window = Window::new(peers);
        loop {
            window.refill(
                this,
                &full_order,
                &mut cursor,
                &remaining,
                peers,
                deadline,
                now,
                batch_groups,
                &mut report,
            );
            let Some(outcome) = next_ready(&mut window.futs).await else {
                break; // nothing in flight and nothing left to assign
            };
            window.release(&outcome);
            this.apply_outcome(outcome, peers, &mut remaining, &mut window.fails, &mut report);
            if remaining.is_empty() {
                break; // done; dropping `flight` cancels leftover duplicates
            }
        }

        Ok(report)
    }

    /// Fold one batch outcome into the running state: the class RTT
    /// priors, the per-peer failure counts, the remaining bitfield and the
    /// report. Landed groups count whether the batch won or failed partway.
    fn apply_outcome(
        &self,
        outcome: BatchOutcome,
        peers: &[PeerHandle],
        remaining: &mut GroupBits,
        fails: &mut [u32],
        report: &mut FetchReport,
    ) {
        if let Some(obs) = &self.observer {
            obs.on_batch(
                &peers[outcome.primary].label,
                outcome.winner_label.as_deref(),
                outcome.winner_class,
                self.bytes_of(&outcome.landed),
                outcome.elapsed,
                outcome.duplicates,
            );
        }
        report.duplicates_issued += outcome.duplicates;
        // Fold the winner's measured latency into the class prior, so
        // duplicate-target ordering uses real RTT.
        if let (Some(cls), Some(el)) = (outcome.winner_class, outcome.elapsed) {
            self.stats.lock().expect("stats").observe(cls, el);
            // Same measurement, attributed to the peer rather than its class,
            // so picking can tell two peers of one class apart.
            if let Some(label) = outcome.winner_label.as_deref() {
                self.peer_stats
                    .lock()
                    .expect("peer stats")
                    .observe(label, el, outcome.landed.len() as u64);
            }
        }
        // Count a failed batch against its peer; a peer that delivered is
        // healthy again, so one bad batch cannot bury it forever.
        if let Some(p) = outcome.failed_peer {
            if let Some(f) = fails.get_mut(p) {
                *f = f.saturating_add(1);
            }
        }
        if let Some(w) = outcome.winner {
            if let Some(f) = fails.get_mut(w) {
                *f = 0;
            }
        }
        for g in &outcome.landed {
            remaining.remove(*g..*g + 1);
            report.groups_fetched += 1;
        }
        if let Some(label) = outcome.winner_label {
            *report.by_peer.entry(label).or_default() += outcome.landed.len() as u64;
        }
    }

    fn groups_of(&self, batch: &std::ops::Range<u64>) -> Vec<u64> {
        use epix_blob::bitfield::groups_for_bytes;
        let gr = groups_for_bytes(batch);
        gr.collect()
    }

    /// Least-loaded peer with a free pipeline slot that holds every group
    /// in `groups`, ties broken by prior failures then class RTT (fast
    /// peers preferred). A peer past PEER_FAIL_LIMIT consecutive failures
    /// is exhausted and never picked.
    /// Choose a peer for `groups`, from those that hold all of it, are not
    /// exhausted, and have a free pipeline slot.
    ///
    /// The ordering depends on what the fetch is for. Background bulk keeps
    /// spreading work by load, which uses the whole swarm and is what a
    /// patient transfer wants. A streaming deadline instead orders by measured
    /// per-peer speed first, because there load-balancing actively hurts: an
    /// idle slow peer sorts ahead of a busy fast one on load, so the batch just
    /// past the play head goes to the peer least able to deliver it in time,
    /// and the contiguous prefix the player consumes stalls while aggregate
    /// throughput still looks healthy. Ordering by speed lets the fast peers
    /// fill their pipelines first and leaves a slow peer only the work they
    /// have no slot for - it still contributes, but never holds up playback.
    ///
    /// A peer with no measurement yet falls back to its class prior, so it is
    /// tried rather than starved by whoever happened to be measured first.
    fn pick_peer(
        &self,
        groups: &[u64],
        peers: &[PeerHandle],
        load: &[u32],
        fails: &[u32],
        deadline: Deadline,
    ) -> Option<usize> {
        let stats = self.stats.lock().expect("stats");
        let peer_stats = self.peer_stats.lock().expect("peer stats");
        let eligible = peers.iter().enumerate().filter(|(i, p)| {
            fails[*i] < PEER_FAIL_LIMIT
                && load[*i] < pipeline_depth(p.class)
                && groups.iter().all(|g| p.bits.contains(*g))
        });
        if deadline.is_streaming() {
            eligible
                .min_by_key(|(i, p)| {
                    let cost = peer_stats.per_group(&p.label).unwrap_or_else(|| stats.rtt(p.class));
                    (fails[*i], cost, load[*i])
                })
                .map(|(i, _)| i)
        } else {
            eligible.min_by_key(|(i, p)| (fails[*i], load[*i], stats.rtt(p.class))).map(|(i, _)| i)
        }
    }

    /// A failed batch's outcome. The groups whose streamed prefix already
    /// verified into the store (`Store::write_slice_partial`) are reported
    /// as landed so they are not refetched; a commit still finishing on the
    /// decode thread is missed here and simply refetched — wasteful once,
    /// never wrong (verified writes are idempotent).
    fn batch_failed(&self, groups: Vec<u64>, primary: usize, duplicates: u64) -> BatchOutcome {
        let present = self.store.present_bits(self.obj).unwrap_or_default();
        let landed = groups.iter().copied().filter(|g| present.contains(*g)).collect();
        BatchOutcome {
            groups,
            landed,
            primary,
            winner: None,
            winner_label: None,
            duplicates,
            winner_class: None,
            elapsed: None,
            failed_peer: Some(primary),
        }
    }

    /// Fetch `batch` from peer `primary`, progress-based: the primary is
    /// duplicated onto up to MAX_DUPLICATES faster-or-equal peers only when
    /// it STALLS (no new bytes for its class's stall window), never merely
    /// for being slow; the batch fails only when nobody moves bytes for a
    /// stall window or the absolute cap runs out. First success wins; the
    /// object store's idempotent verified writes make a late duplicate
    /// harmless, and a failed batch keeps the groups its streamed prefix
    /// landed.
    #[allow(clippy::too_many_arguments)]
    async fn race_batch(
        &self,
        batch: std::ops::Range<u64>,
        groups: Vec<u64>,
        primary: usize,
        peers: &[PeerHandle],
        deadline: Deadline,
        now: u64,
        queued: u32,
        // Held for this future's whole life: its Drop refunds the link's
        // queued-bytes counter on completion and cancellation alike.
        _charge: crate::conn::FetchCharge,
    ) -> BatchOutcome {
        // The cap is a per-request budget scaled by the link's queue depth:
        // a batch behind `queued` requests' worth of bytes on the circuit
        // needs that many shares of it just to drain. A fixed cap turned a
        // deep pipeline on a slow-but-healthy circuit into a strike factory
        // (every batch on a shared 4 MiB queue blew 90s below ~46 KB/s).
        let cap = deadline.max_wait.min(MAX_BATCH_WAIT) * queued.max(1);
        // The stall window is capped to a share of the batch budget: a
        // stall detected only near the cap would leave the duplicated race
        // below no time to answer.
        let stall = stall_window(peers[primary].class, queued).min(cap / PRIMARY_BUDGET_DIVISOR);
        // Arc: the fetches' incremental disk commits bump it from the
        // blocking pool, so committing counts as liveness too.
        let progress = Arc::new(AtomicU64::new(0));
        let ranges = [batch.clone()];
        let fetch_from = |i: usize| {
            fetch::fetch_ranges_observed(
                &peers[i].conn,
                &self.store,
                self.obj,
                self.size,
                &ranges,
                deadline.ms,
                now,
                &progress,
            )
        };

        let start = std::time::Instant::now();
        let mut primary_fut = Box::pin(fetch_from(primary));

        // Run the primary until it finishes, stalls, or eats the whole cap.
        // Record whether it already COMPLETED with an error: a completed
        // async fn must never be polled again (that panics "async fn
        // resumed after completion"), so a fast primary error must not fall
        // through to a re-await.
        let primary_errored = tokio::select! {
            res = &mut primary_fut => match res {
                Ok(_) => {
                    let cls = peers[primary].class;
                    return BatchOutcome::won(
                        groups, primary, primary, peers[primary].label.clone(), 0, cls, start.elapsed(),
                    );
                }
                Err(_) => true,
            },
            _ = stalled(&progress, stall) => false,
            _ = tokio::time::sleep(cap) => {
                // Absolute cap with the primary mid-flight: abandon it (the
                // cancel-on-abandon guard stops the peer; the streamed
                // prefix stays committed) and fail the batch.
                drop(primary_fut);
                return self.batch_failed(groups, primary, 0);
            }
        };

        // Duplicate onto faster-or-equal peers holding the groups.
        let ok_classes =
            self.stats.lock().expect("stats").faster_or_equal(peers[primary].class);
        let targets: Vec<usize> = peers
            .iter()
            .enumerate()
            .filter(|(i, p)| {
                *i != primary
                    && p.label != peers[primary].label
                    && ok_classes.contains(&p.class)
                    && groups.iter().all(|g| p.bits.contains(*g))
            })
            .map(|(i, _)| i)
            .take(MAX_DUPLICATES)
            .collect();

        // What is left of the batch's hard cap; the race below is bounded
        // by it, so a peer that accepts the GetRange and then sends nothing
        // cannot park the batch forever.
        let left = cap.saturating_sub(start.elapsed());

        if targets.is_empty() || left.is_zero() {
            // Nowhere to duplicate onto, or no budget left for a racer to
            // answer in. The primary is stalled (or already errored): the
            // stall window IS the failure criterion, so give up now instead
            // of holding the batch — and the groups it strands — to the
            // cap. Dropping the primary cancels its stream; whatever its
            // prefix landed stays and the remainder is rescheduled.
            drop(primary_fut);
            return self.batch_failed(groups, primary, 0);
        }

        type BoxFut<'a> =
            std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>;
        let mut racers: Vec<BoxFut<'_>> = Vec::new();
        for &t in &targets {
            racers.push(Box::pin(async move { fetch_from(t).await.map(|_| t) }));
        }
        // Only re-race the primary if it is still pending; a completed
        // (errored) primary must not be polled again.
        if !primary_errored {
            racers.push(Box::pin(async move { primary_fut.await.map(|_| primary) }));
        }

        let dups = targets.len() as u64;
        // Every racer bumps the same progress counter, so the race fails
        // early only when NONE of them moves bytes for the widest stall
        // window among the classes racing.
        let race_stall = targets
            .iter()
            .map(|&t| stall_timeout(peers[t].class))
            .chain((!primary_errored).then(|| stall_timeout(peers[primary].class)))
            .max()
            .unwrap_or(stall);
        let winner = tokio::select! {
            w = select_first_ok(racers) => w,
            _ = stalled(&progress, race_stall) => None,
            _ = tokio::time::sleep(left) => None,
        };
        match winner {
            Some(w) => {
                let cls = peers[w].class;
                let mut out = BatchOutcome::won(
                    groups, primary, w, peers[w].label.clone(), dups, cls, start.elapsed(),
                );
                // A rescue is a strike against the primary: it stalled (or
                // errored) its way into this race and somebody else had to
                // deliver its batch. Without the strike its fail count
                // never moves, pick_peer keeps assigning it, and every one
                // of its batches eats a stall window plus a duplicate —
                // PEER_FAIL_LIMIT exhaustion would never engage against a
                // peer that accepts requests but sends nothing.
                if w != primary {
                    out.failed_peer = Some(primary);
                }
                out
            }
            None => self.batch_failed(groups, primary, dups),
        }
    }
}

/// The result of racing one batch: which groups were assigned and which
/// actually landed in the store, the winning peer, how many duplicates
/// fired, and the winner's class + measured request latency (fed back into
/// the per-class EWMA).
struct BatchOutcome {
    /// The groups the batch was assigned (in-flight bookkeeping).
    groups: Vec<u64>,
    /// The groups whose verified bytes reached the store: all of `groups`
    /// on a win, the committed prefix on a partial failure.
    landed: Vec<u64>,
    /// The peer the batch was assigned to (whose window slot it held).
    primary: usize,
    /// The peer that delivered, for the fail-count reset.
    winner: Option<usize>,
    winner_label: Option<String>,
    duplicates: u64,
    winner_class: Option<Class>,
    elapsed: Option<Duration>,
    /// The peer index that failed this batch (a stall, a network error or,
    /// worse, bytes that failed verification), so scheduling deprioritizes
    /// and eventually exhausts it.
    failed_peer: Option<usize>,
}

impl BatchOutcome {
    #[allow(clippy::too_many_arguments)]
    fn won(
        groups: Vec<u64>,
        primary: usize,
        winner: usize,
        label: String,
        duplicates: u64,
        class: Class,
        elapsed: Duration,
    ) -> Self {
        Self {
            landed: groups.clone(),
            groups,
            primary,
            winner: Some(winner),
            winner_label: Some(label),
            duplicates,
            winner_class: Some(class),
            elapsed: Some(elapsed),
            failed_peer: None,
        }
    }
}

/// A fetch deadline tier.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    /// Advisory ms sent to the peer for its own ordering.
    pub ms: u32,
    /// Hard local wait cap before giving up on a batch.
    pub max_wait: Duration,
}

impl Deadline {
    /// First-paint / streaming. Failure is stall-based, so the cap only
    /// backstops a batch that keeps trickling: generous enough that a
    /// 1 MiB batch over a 100-250 KB/s onion circuit finishes instead of
    /// dying on an elapsed-time cliff (the HTTP path serves whatever
    /// contiguous prefix landed rather than blocking on the whole window).
    pub fn tight() -> Self {
        Self { ms: 250, max_wait: Duration::from_secs(60) }
    }
    /// Background bulk: patient.
    pub fn background() -> Self {
        Self { ms: 0, max_wait: Duration::from_secs(120) }
    }

    /// Read-ahead for a player: the fetch that keeps the buffer ahead of the
    /// play head.
    ///
    /// This is streaming work - it decides whether playback stalls a minute
    /// from now - so it wants play-order scheduling and the fastest peers, like
    /// [`Self::tight`]. Running it as background bulk (which is what it used to
    /// be) meant the buffer was built by whichever peer happened to be idle,
    /// including one too slow to deliver before the play head arrived.
    ///
    /// The absolute cap stays patient like background's: nothing is waiting on
    /// any single one of these batches right now, so a slow-but-moving one
    /// should finish rather than be cut off and refetched.
    pub fn prefetch() -> Self {
        Self { ms: 500, max_wait: Duration::from_secs(120) }
    }

    /// Whether this tier is serving a player, where a late batch is a visible
    /// stall rather than a slower transfer. Keyed off the advisory `ms` the
    /// tier already carries: only the streaming tiers set one.
    pub fn is_streaming(&self) -> bool {
        self.ms > 0
    }
}

// --- tiny future combinators (avoid pulling futures-util) ---

/// Resolves when `progress` stops advancing for `stall` (checked at that
/// granularity, so detection lags at most one extra window). A zero stall
/// resolves immediately.
async fn stalled(progress: &AtomicU64, stall: Duration) {
    let mut last = progress.load(Ordering::Relaxed);
    loop {
        tokio::time::sleep(stall).await;
        let cur = progress.load(Ordering::Relaxed);
        if cur == last {
            return;
        }
        last = cur;
    }
}

/// Wait for the FIRST of the in-flight futures to complete, remove it and
/// return its output; `None` if the set is empty. Every future is polled
/// concurrently — `race_batch` only sends its request when first polled,
/// so awaiting them one after another would serialize the window.
async fn next_ready<'a, T>(
    futs: &mut Vec<std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>>,
) -> Option<T> {
    use std::task::Poll;
    if futs.is_empty() {
        return None;
    }
    std::future::poll_fn(|cx| {
        for i in 0..futs.len() {
            if let Poll::Ready(v) = futs[i].as_mut().poll(cx) {
                drop(futs.remove(i));
                return Poll::Ready(Some(v));
            }
        }
        Poll::Pending
    })
    .await
}

/// Return the first `Ok(T)` among the futures, or None if all error.
async fn select_first_ok<T>(
    futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<T>> + Send + '_>>>,
) -> Option<T> {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct FirstOk<'a, T> {
        futs: Vec<Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>>,
    }
    impl<T> Future for FirstOk<'_, T> {
        type Output = Option<T>;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let mut i = 0;
            while i < self.futs.len() {
                match self.futs[i].as_mut().poll(cx) {
                    Poll::Ready(Ok(v)) => return Poll::Ready(Some(v)),
                    Poll::Ready(Err(_)) => {
                        drop(self.futs.remove(i));
                    }
                    Poll::Pending => i += 1,
                }
            }
            if self.futs.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Pending
            }
        }
    }
    FirstOk { futs }.await
}

/// Groups an object of `size` still needs, given what the store holds.
pub fn needed_groups(store: &Store, obj: ObjId, size: u64) -> std::io::Result<GroupBits> {
    let have = store.present_bits(obj)?;
    let mut all = GroupBits::new();
    let n = group_count(size);
    if n > 0 {
        all.add(0..n);
    }
    // added_in(x) = x \ self, so have.added_in(all) = all \ have.
    Ok(have.added_in(&all))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_converges_toward_samples() {
        let mut s = ClassStats::default();
        let start = s.rtt(Class::Tor);
        for _ in 0..20 {
            s.observe(Class::Tor, Duration::from_millis(100));
        }
        let end = s.rtt(Class::Tor);
        assert!(end < start, "Tor prior should fall toward the 100ms samples");
        assert!(end >= Duration::from_millis(100));
    }

    #[test]
    fn faster_or_equal_never_includes_slower() {
        let s = ClassStats::default();
        // Duplicating a Tor request may target clearnet/i2p/tor.
        let from_tor = s.faster_or_equal(Class::Tor);
        assert!(from_tor.contains(&Class::Clearnet));
        // Duplicating a clearnet request may only target clearnet.
        let from_clear = s.faster_or_equal(Class::Clearnet);
        assert_eq!(from_clear, vec![Class::Clearnet]);
    }

    /// Streaming picks the peer that actually delivers fastest, even when a
    /// slower one is idle; background keeps spreading by load. The slow peer is
    /// the same class as the fast one, so only the per-PEER measurement can
    /// tell them apart.
    #[tokio::test]
    async fn streaming_picks_the_fastest_peer_while_background_spreads_load() {
        let mut bits = GroupBits::new();
        bits.add(0..4);
        let peers = vec![
            PeerHandle {
                conn: dummy_conn(),
                class: Class::Tor,
                bits: bits.clone(),
                label: "fast".into(),
            },
            PeerHandle { conn: dummy_conn(), class: Class::Tor, bits, label: "slow".into() },
        ];
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let swarm = Swarm::new(store, epix_blob::ObjId([0u8; 32]), 4 * 16 * 1024);
        {
            let mut ps = swarm.peer_stats.lock().expect("peer stats");
            ps.observe("fast", Duration::from_millis(250), 1);
            ps.observe("slow", Duration::from_secs(4), 1);
        }

        // "fast" is busy, "slow" is idle. Load-ordering would take the idle
        // slow peer; a streaming deadline must still take the fast one.
        let load = [1u32, 0];
        let fails = [0u32, 0];
        let groups = [0u64];
        assert_eq!(
            swarm.pick_peer(&groups, &peers, &load, &fails, Deadline::tight()),
            Some(0),
            "streaming must prefer the measured-fast peer over an idle slow one"
        );
        assert_eq!(
            swarm.pick_peer(&groups, &peers, &load, &fails, Deadline::background()),
            Some(1),
            "background still spreads by load"
        );

        // Once the fast peer's pipeline is full, the slow peer still gets work
        // rather than the fetch stalling - it contributes, it just never holds
        // up the play head.
        let saturated = [pipeline_depth(Class::Tor), 0];
        assert_eq!(
            swarm.pick_peer(&groups, &peers, &saturated, &fails, Deadline::tight()),
            Some(1),
            "a saturated fast peer must not starve the swarm"
        );
    }

    /// A player is served the contiguous prefix of its window, so streaming
    /// must fetch in play order even when that is the opposite of rarest-first.
    /// Bulk keeps rarest-first, so the swarm still gets that property.
    #[tokio::test]
    async fn streaming_fetches_in_play_order_while_bulk_stays_rarest_first() {
        // group 0 held by both peers (common), groups 1 and 2 by one each (rare).
        let mut a = GroupBits::new();
        a.add(0..2); // 0,1
        let mut b = GroupBits::new();
        b.add(0..1); // 0
        b.add(2..3); // 2
        let peers = vec![
            PeerHandle { conn: dummy_conn(), class: Class::Tor, bits: a, label: "a".into() },
            PeerHandle { conn: dummy_conn(), class: Class::Tor, bits: b, label: "b".into() },
        ];
        let mut needed = GroupBits::new();
        needed.add(0..3);

        // Play order: 0 first, because the player cannot use 1 or 2 until 0 has
        // landed - exactly the case rarest-first gets wrong.
        assert_eq!(sequential_order(&needed, &peers), vec![0, 1, 2]);
        // Rarest-first puts the common group last.
        assert_eq!(*rarest_first_order(&needed, &peers).last().unwrap(), 0);

        // A group no peer holds is not schedulable in either order.
        let mut unheld = GroupBits::new();
        unheld.add(0..1);
        unheld.add(9..10);
        assert_eq!(sequential_order(&unheld, &peers), vec![0]);
    }

    /// The read-ahead tier is streaming (so it gets play-order scheduling and
    /// speed-ordered peers) while staying patient on the absolute cap.
    #[test]
    fn prefetch_is_streaming_but_patient() {
        assert!(Deadline::prefetch().is_streaming());
        assert!(Deadline::tight().is_streaming());
        assert!(!Deadline::background().is_streaming());
        assert_eq!(Deadline::prefetch().max_wait, Deadline::background().max_wait);
    }

    #[tokio::test]
    async fn rarest_first_orders_by_holder_count() {
        // group 0 held by both peers, group 1 by one, group 2 by one.
        let mut a = GroupBits::new();
        a.add(0..2); // holds 0,1
        let mut b = GroupBits::new();
        b.add(0..1); // holds 0
        b.add(2..3); // holds 2
        let peers = vec![
            PeerHandle { conn: dummy_conn(), class: Class::Clearnet, bits: a, label: "a".into() },
            PeerHandle { conn: dummy_conn(), class: Class::Clearnet, bits: b, label: "b".into() },
        ];
        let mut needed = GroupBits::new();
        needed.add(0..3);
        let order = rarest_first_order(&needed, &peers);
        // group 0 (2 holders) must come last; 1 and 2 (1 holder) first.
        assert_eq!(*order.last().unwrap(), 0);
        assert!(order[..2].contains(&1) && order[..2].contains(&2));
    }

    #[test]
    fn batching_coalesces_contiguous_groups() {
        let groups: Vec<u64> = (0..5).chain(10..12).collect();
        let ranges = batch_into_ranges(&groups, 1_000_000, GROUPS_PER_REQUEST);
        // Two contiguous runs -> two ranges.
        assert_eq!(ranges.len(), 2);
    }

    /// An overlay link gets smaller requests so a failure or a stall costs a
    /// fraction of the circuit time, and a deep window so the circuit's
    /// bandwidth-delay product stays covered: throughput is bounded by
    /// bytes-in-flight over RTT, and the old 768 KiB window was itself the
    /// ~300-400 KB/s per-circuit ceiling observed live.
    #[test]
    fn overlay_links_get_small_requests_and_a_deep_window() {
        use epix_blob::bitfield::GROUP_BYTES;
        for overlay in [Class::Tor, Class::I2p] {
            assert_eq!(groups_per_request(overlay), GROUPS_PER_REQUEST_OVERLAY);
            assert!(
                groups_per_request(overlay) < GROUPS_PER_REQUEST,
                "{overlay:?} must ask for less per request than clearnet"
            );
            // Wire compat: one request stays inside the server's caps
            // (64 ranges / 64 MiB), so old seeders serve it unchanged.
            assert!(groups_per_request(overlay) * GROUP_BYTES <= 64 * 1024 * 1024);
            let window =
                pipeline_depth(overlay) as u64 * groups_per_request(overlay) * GROUP_BYTES;
            assert_eq!(
                window,
                3 * 1024 * 1024,
                "{overlay:?} window: at a 2s circuit RTT this is a ~1.5 MB/s ceiling"
            );
        }
        assert_eq!(groups_per_request(Class::Clearnet), GROUPS_PER_REQUEST);
        assert_eq!(pipeline_depth(Class::Clearnet), PIPELINE_DEPTH);
    }

    /// A request waiting its turn behind siblings on the same link is not
    /// stalled: the window grows with the queue, so a healthy pipelined link
    /// is never duplicated onto another peer (which would spend the swarm's
    /// scarce bandwidth re-fetching bytes already on the way).
    #[test]
    fn the_stall_window_grows_with_the_links_queue() {
        let base = stall_timeout(Class::Tor);
        assert_eq!(stall_window(Class::Tor, 0), base, "an empty queue still gets one window");
        assert_eq!(stall_window(Class::Tor, 1), base);
        assert_eq!(stall_window(Class::Tor, 3), base * 3);
        assert!(
            stall_window(Class::Tor, PIPELINE_DEPTH_OVERLAY) >= base * PIPELINE_DEPTH_OVERLAY,
            "a full queue must never be judged against a single request's window"
        );
    }

    /// The link's queue is counted in the class's own request units, rounded
    /// up, so it composes directly with the swarm's per-request load.
    #[test]
    fn link_queue_depth_counts_in_request_units() {
        use epix_blob::bitfield::GROUP_BYTES;
        let request = GROUPS_PER_REQUEST_OVERLAY * GROUP_BYTES;
        assert_eq!(link_queue_depth(Class::Tor, 0), 0);
        assert_eq!(link_queue_depth(Class::Tor, 1), 1, "a partial request still counts");
        assert_eq!(link_queue_depth(Class::Tor, request), 1);
        assert_eq!(link_queue_depth(Class::Tor, request + 1), 2);
        assert_eq!(link_queue_depth(Class::Tor, 6 * request), 6);
        assert_eq!(
            link_queue_depth(Class::Clearnet, GROUPS_PER_REQUEST * GROUP_BYTES),
            1,
            "clearnet counts in its larger request unit"
        );
    }

    /// Eight 512 KiB requests queued on one circuit (two swarms sharing a
    /// depth-6 link, or one link run past its own depth) used to face a
    /// fixed 90s cap: any circuit under ~46 KB/s failed every batch and
    /// struck out its only peer. The ceilings now scale with the link's
    /// queue, while a truly dead peer still fails within a bounded few
    /// windows.
    #[test]
    fn a_deep_link_queue_scales_the_ceilings_instead_of_failing_slow_circuits() {
        use epix_blob::bitfield::GROUP_BYTES;
        let request = GROUPS_PER_REQUEST_OVERLAY * GROUP_BYTES; // 512 KiB
        let queued_bytes = 8 * request; // 4 MiB on the wire
        let q = link_queue_depth(Class::Tor, queued_bytes);
        assert_eq!(q, 8);

        // What race_batch derives for a background batch at this depth.
        let cap = Deadline::background().max_wait.min(MAX_BATCH_WAIT) * q;
        let stall = stall_window(Class::Tor, q).min(cap / PRIMARY_BUDGET_DIVISOR);

        // A 46 KB/s circuit fair-sharing the queue completes a request only
        // once the whole 4 MiB drains (~91s). It must beat the cap with
        // room to spare - and so must a circuit three times slower.
        let drain = Duration::from_secs(queued_bytes / (46 * 1000));
        assert!(cap > drain, "46 KB/s must survive the cap: cap={cap:?} drain={drain:?}");
        assert!(cap > drain * 3, "a slower-still circuit must not insta-fail");
        // The scaled stall window is no longer truncated to the old fixed
        // cap share (45s): waiting a full turn of the queue for a first
        // byte is not a stall.
        assert_eq!(stall, stall_timeout(Class::Tor) * q);

        // A dead peer is still bounded: one silent stall window fails the
        // batch, PEER_FAIL_LIMIT of them exhausts the peer.
        assert!(stall <= Duration::from_secs(120));
        assert!(stall * PEER_FAIL_LIMIT <= Duration::from_secs(360));
    }

    /// Batches are cut before a peer is picked, so one size serves the whole
    /// set: the slowest class present wins, and a set with no peers falls back
    /// to the clearnet size rather than zero.
    #[tokio::test]
    async fn batch_size_follows_the_slowest_class_in_the_session() {
        let bits = |n: u64| {
            let mut b = GroupBits::new();
            b.add(0..n);
            b
        };
        let peer = |class| PeerHandle {
            conn: dummy_conn(),
            class,
            bits: bits(64),
            label: format!("{class:?}"),
        };
        assert_eq!(batch_groups_for(&[peer(Class::Clearnet)]), GROUPS_PER_REQUEST);
        assert_eq!(
            batch_groups_for(&[peer(Class::Clearnet), peer(Class::Tor)]),
            GROUPS_PER_REQUEST_OVERLAY,
            "one overlay link sets the size for the session"
        );
        assert_eq!(batch_groups_for(&[]), GROUPS_PER_REQUEST);
    }

    #[test]
    fn batching_splits_at_request_size() {
        let groups: Vec<u64> = (0..(GROUPS_PER_REQUEST * 2 + 5)).collect();
        let ranges = batch_into_ranges(&groups, 1 << 40, GROUPS_PER_REQUEST);
        assert!(ranges.len() >= 3, "a run longer than a request must split");
    }

    #[test]
    fn next_unassigned_skips_inflight_but_reschedules_failed() {
        let full_order: Vec<u64> = (0..6).collect();
        let mut remaining = GroupBits::new();
        remaining.add(1..6); // group 0 already fetched
        let mut inflight = GroupBits::new();
        inflight.add(2..4); // groups 2,3 assigned to an in-flight batch
        let mut cursor = 0usize;
        let order = next_unassigned(&full_order, &mut cursor, &remaining, &inflight, 10);
        assert_eq!(order, vec![1, 4, 5], "in-flight groups are not double-assigned");
        // The failed batch returns its groups to the pool (still remaining,
        // no longer inflight): the cursor did not skip past them.
        inflight.remove(2..4);
        let mut cursor2 = cursor;
        let order2 = next_unassigned(&full_order, &mut cursor2, &remaining, &inflight, 10);
        assert!(order2.contains(&2) && order2.contains(&3), "failed groups reschedule");
    }

    fn dummy_conn() -> Conn {
        let (a, _b) = tokio::io::duplex(64);
        std::mem::forget(_b);
        let (c, _in) = Conn::start(a, true);
        c
    }

    /// A connection whose peer end is gone: any fetch errors almost
    /// immediately (BrokenPipe), well before any stall window.
    fn dead_conn() -> Conn {
        let (a, b) = tokio::io::duplex(64);
        let (c, _in) = Conn::start(a, true);
        drop(b); // peer end dropped -> writes fail, stream reports closed
        c
    }

    #[tokio::test]
    async fn race_batch_survives_a_fast_primary_error() {
        // A primary peer that errors BEFORE any stall (here a dead
        // connection) hits race_batch's Err arm. The completed fetch
        // future must never be polled again — doing so panics ("async fn
        // resumed after completion"). With no other peer the batch must
        // fail cleanly instead of panicking.
        use epix_blob::ObjId;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 40_000]; // spans a few groups
        let id = ObjId::of(&data);
        let size = data.len() as u64;

        let peers = vec![PeerHandle {
            conn: dead_conn(),
            class: Class::Clearnet,
            bits: GroupBits::complete(size),
            label: "dead".into(),
        }];

        let mut swarm = Swarm::new(store.clone(), id, size);
        let needed = needed_groups(&store, id, size).unwrap();
        // Must return cleanly rather than panic.
        let report = swarm.fetch(&needed, &peers, Deadline::background(), 2).await.unwrap();
        assert_eq!(report.groups_fetched, 0, "dead-only swarm fetches nothing but must not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_fails_at_the_stall_window_not_the_cap() {
        // A peer that takes the GetRange and then answers nothing, on a
        // connection that stays open, leaves fetch_ranges pending for as
        // long as the link lives. The batch must fail once the stall
        // window passes with no bytes — long before the absolute cap — and
        // the peer must be exhausted after PEER_FAIL_LIMIT retries instead
        // of parking the fetch forever.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 40_000];
        let id = ObjId::of(&data);
        let size = data.len() as u64;

        let peers = vec![PeerHandle {
            conn: dummy_conn(),
            class: Class::Clearnet,
            bits: GroupBits::complete(size),
            label: "silent".into(),
        }];

        let mut swarm = Swarm::new(store.clone(), id, size);
        let needed = needed_groups(&store, id, size).unwrap();
        let deadline = Deadline::tight();
        let start = tokio::time::Instant::now();
        let report =
            tokio::time::timeout(deadline.max_wait * 3, swarm.fetch(&needed, &peers, deadline, 2))
                .await
                .expect("a silent peer must not hang the fetch")
                .unwrap();
        assert_eq!(report.groups_fetched, 0, "the silent peer served nothing");
        // PEER_FAIL_LIMIT retries, each one stall window: well under the cap.
        assert!(
            start.elapsed() < deadline.max_wait,
            "stall-based failure must not wait out the absolute cap"
        );
    }

    /// A peer that answers every GetRange with the canonical whole-object
    /// bao slice, so a duplicate racer can actually win its race.
    fn serving_conn(data: &[u8]) -> Conn {
        use crate::msg::{Frame, FrameBody, Req};
        use epix_blob::verified::{encode_slice, OutboardBytes};

        let ob = OutboardBytes::from_slice(data);
        let ranges = vec![0..data.len() as u64];
        let mut slice = Vec::new();
        encode_slice(data, &ob, &ranges, &mut slice).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);
        tokio::spawn(async move {
            while let Some(inc) = server_in.recv().await {
                if !matches!(inc.req, Req::GetRange { .. }) {
                    continue;
                }
                let mut off = 0usize;
                while off < slice.len() {
                    let end = (off + 60_000).min(slice.len());
                    let last = end == slice.len();
                    let body = FrameBody::Data { last, bytes: slice[off..end].to_vec() };
                    if server.send(Frame { stream: inc.stream, body }).await.is_err() {
                        return;
                    }
                    off = end;
                }
            }
        });
        client
    }

    /// Like [`serving_conn`], but the slice trickles: small frames with
    /// `gap` between them. Slow, but never stalled.
    fn trickle_conn(data: &[u8], gap: Duration) -> Conn {
        use crate::msg::{Frame, FrameBody, Req};
        use epix_blob::verified::{encode_slice, OutboardBytes};

        let ob = OutboardBytes::from_slice(data);
        let ranges = vec![0..data.len() as u64];
        let mut slice = Vec::new();
        encode_slice(data, &ob, &ranges, &mut slice).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);
        tokio::spawn(async move {
            while let Some(inc) = server_in.recv().await {
                if !matches!(inc.req, Req::GetRange { .. }) {
                    continue;
                }
                let mut off = 0usize;
                while off < slice.len() {
                    let end = (off + 20_000).min(slice.len());
                    let last = end == slice.len();
                    let body = FrameBody::Data { last, bytes: slice[off..end].to_vec() };
                    if server.send(Frame { stream: inc.stream, body }).await.is_err() {
                        return;
                    }
                    off = end;
                    if !last {
                        tokio::time::sleep(gap).await;
                    }
                }
            }
        });
        client
    }

    // Real time: the trickle gaps are small and the decode runs on a real
    // blocking thread, which tokio's paused clock does not wait for.
    #[tokio::test]
    async fn a_slow_but_moving_primary_is_not_duplicated() {
        // The primary trickles the slice with 100ms gaps: bytes keep
        // arriving inside every stall window, so it is slow, not stalled.
        // Elapsed-time duplication would have raced it onto the fast peer;
        // stall-only duplication must let it finish alone.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 300_000];
        let id = ObjId::of(&data);
        let size = data.len() as u64;
        store.ensure_sparse(id, epix_blob::Ns::Plain, size, 1).unwrap();

        let peers = vec![
            PeerHandle {
                conn: trickle_conn(&data, Duration::from_millis(100)),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "trickle".into(),
            },
            PeerHandle {
                conn: serving_conn(&data),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "fast".into(),
            },
        ];

        let swarm = Swarm::new(store.clone(), id, size);
        let groups = swarm.groups_of(&(0..size));
        let charge = peers[0].conn.charge_fetch(size);
        let outcome =
            swarm.race_batch(0..size, groups, 0, &peers, Deadline::background(), 2, 1, charge).await;
        assert_eq!(outcome.duplicates, 0, "a moving transfer is never raced");
        assert_eq!(outcome.winner_label.as_deref(), Some("trickle"));
    }

    // Real (not paused) time: race_batch measures its budget with
    // std::time::Instant, which tokio's virtual clock does not advance.
    #[tokio::test]
    async fn a_stalled_primary_is_raced_and_the_duplicate_can_win() {
        // The primary goes silent after taking the request: once its stall
        // window (capped to a share of the batch budget) passes with no
        // bytes, the batch is duplicated onto the serving peer, which must
        // still have budget left to answer in.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 40_000];
        let id = ObjId::of(&data);
        let size = data.len() as u64;
        store.ensure_sparse(id, epix_blob::Ns::Plain, size, 1).unwrap();

        let peers = vec![
            PeerHandle {
                conn: dummy_conn(),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "silent".into(),
            },
            PeerHandle {
                conn: serving_conn(&data),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "fast".into(),
            },
        ];

        let swarm = Swarm::new(store.clone(), id, size);
        let deadline = Deadline { ms: 0, max_wait: Duration::from_millis(600) };
        let groups = swarm.groups_of(&(0..size));
        let charge = peers[0].conn.charge_fetch(size);
        let outcome = swarm.race_batch(0..size, groups, 0, &peers, deadline, 2, 1, charge).await;
        assert_eq!(outcome.duplicates, 1, "the stalled primary is duplicated onto the other peer");
        assert_eq!(
            outcome.winner_label.as_deref(),
            Some("fast"),
            "the duplicate must be issued with enough budget left to answer"
        );
        assert_eq!(
            outcome.failed_peer,
            Some(0),
            "a rescued batch still counts against the stalled primary, or a dead-but-accepting \
             peer is never exhausted"
        );
    }

    /// A stalled batch must not be raced onto another LANE of the same peer.
    /// Lanes are separate paths to ONE node, so a duplicate there asks the
    /// peer that has already gone quiet to serve the same bytes twice - which
    /// is how a striped swarm spends the capacity its extra circuits bought.
    /// The sibling here is a perfectly good server, and the batch must still
    /// fail rather than lean on it.
    #[tokio::test]
    async fn a_duplicate_never_goes_to_a_sibling_lane() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 40_000];
        let id = ObjId::of(&data);
        let size = data.len() as u64;
        store.ensure_sparse(id, epix_blob::Ns::Plain, size, 1).unwrap();

        // Two lanes of ONE peer: the primary goes silent, its sibling would
        // happily serve. Same label = same node.
        let peers = vec![
            PeerHandle {
                conn: dummy_conn(),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "peer-a".into(),
            },
            PeerHandle {
                conn: serving_conn(&data),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "peer-a".into(),
            },
        ];

        let swarm = Swarm::new(store.clone(), id, size);
        let deadline = Deadline { ms: 0, max_wait: Duration::from_millis(600) };
        let groups = swarm.groups_of(&(0..size));
        let charge = peers[0].conn.charge_fetch(size);
        let outcome = swarm.race_batch(0..size, groups, 0, &peers, deadline, 2, 1, charge).await;
        assert_eq!(outcome.duplicates, 0, "a sibling lane is not a duplication target");
        assert_eq!(
            outcome.winner_label, None,
            "the batch fails and is rescheduled, rather than doubling the load on the one \
             peer that is already not delivering"
        );
    }

    #[tokio::test]
    async fn a_batch_with_no_budget_left_issues_no_duplicates() {
        // With nothing left of the hard cap a duplicate could only be issued
        // and dropped in the same poll - a GetRange followed straight by a
        // Cancel, for a request that could never win. It must not be sent.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 40_000];
        let id = ObjId::of(&data);
        let size = data.len() as u64;
        store.ensure_sparse(id, epix_blob::Ns::Plain, size, 1).unwrap();

        let peers = vec![
            PeerHandle {
                conn: dummy_conn(),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "silent".into(),
            },
            PeerHandle {
                conn: dummy_conn(),
                class: Class::Clearnet,
                bits: GroupBits::complete(size),
                label: "other".into(),
            },
        ];

        let swarm = Swarm::new(store.clone(), id, size);
        let deadline = Deadline { ms: 0, max_wait: Duration::ZERO };
        let groups = swarm.groups_of(&(0..size));
        let charge = peers[0].conn.charge_fetch(size);
        let outcome = swarm.race_batch(0..size, groups, 0, &peers, deadline, 2, 1, charge).await;
        assert_eq!(outcome.duplicates, 0, "no budget left means no duplicate is issued");
        assert!(outcome.winner_label.is_none(), "nobody can win a zero-length race");
    }

    #[tokio::test(start_paused = true)]
    async fn in_flight_batches_poll_together_and_complete_one_at_a_time() {
        // Each future waits on the other's start signal, so both finish
        // only if the window polls them together (awaiting them in sequence
        // deadlocks here) — and next_ready hands them back one by one as
        // they land, which is what lets the refill scheduler top the window
        // up without a round barrier.
        let (tx_a, rx_a) = tokio::sync::oneshot::channel::<()>();
        let (tx_b, rx_b) = tokio::sync::oneshot::channel::<()>();
        let a = async move {
            let _ = tx_a.send(());
            rx_b.await.unwrap();
            1u32
        };
        let b = async move {
            let _ = tx_b.send(());
            rx_a.await.unwrap();
            2u32
        };
        let mut flight: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = u32> + Send>>> =
            vec![Box::pin(a), Box::pin(b)];
        let first = tokio::time::timeout(Duration::from_secs(5), next_ready(&mut flight))
            .await
            .expect("in-flight batches must make progress together")
            .expect("one batch completed");
        assert_eq!(flight.len(), 1, "the other batch is still in flight");
        let second = next_ready(&mut flight).await.expect("the second batch completes");
        assert!(flight.is_empty());
        assert_ne!(first, second);
        assert!(next_ready(&mut flight).await.is_none(), "an empty window yields None");
    }

    /// A peer that serves each GetRange for ITS requested ranges, one
    /// request at a time with `delay` before each serve, logging request
    /// arrival ("start") and serve completion ("end") instants. Arrivals
    /// are logged the moment the request comes off the wire, so the log
    /// shows when the CLIENT issued it, not when the worker got to it.
    fn sequential_serving_conn(
        data: Vec<u8>,
        delay: Duration,
        log: Arc<std::sync::Mutex<Vec<(&'static str, std::time::Instant)>>>,
    ) -> Conn {
        use crate::msg::{Frame, FrameBody, Req};
        use epix_blob::verified::{encode_slice, OutboardBytes};

        let ob = OutboardBytes::from_slice(&data);
        let (a, b) = tokio::io::duplex(1 << 22);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);
        let (work_tx, mut work_rx) = tokio::sync::mpsc::unbounded_channel();
        let arrival_log = log.clone();
        tokio::spawn(async move {
            while let Some(inc) = server_in.recv().await {
                if !matches!(inc.req, Req::GetRange { .. }) {
                    continue;
                }
                arrival_log.lock().unwrap().push(("start", std::time::Instant::now()));
                if work_tx.send(inc).is_err() {
                    return;
                }
            }
        });
        tokio::spawn(async move {
            while let Some(inc) = work_rx.recv().await {
                let Req::GetRange { ranges, .. } = inc.req else { continue };
                tokio::time::sleep(delay).await;
                let byte_ranges: Vec<std::ops::Range<u64>> =
                    ranges.iter().map(|&(s, e)| s..e).collect();
                let mut slice = Vec::new();
                encode_slice(&data[..], &ob, &byte_ranges, &mut slice).unwrap();
                let mut off = 0usize;
                while off < slice.len() {
                    let end = (off + 60_000).min(slice.len());
                    let last = end == slice.len();
                    let body = FrameBody::Data { last, bytes: slice[off..end].to_vec() };
                    if server.send(Frame { stream: inc.stream, body }).await.is_err() {
                        return;
                    }
                    off = end;
                }
                log.lock().unwrap().push(("end", std::time::Instant::now()));
            }
        });
        client
    }

    // Real time: the interleaving is measured with wall-clock instants
    // across a real blocking decode.
    #[tokio::test]
    async fn the_window_refills_before_the_round_drains() {
        // One peer, PIPELINE_DEPTH slots, a 3-batch object served one
        // request at a time: the THIRD batch must be issued as soon as the
        // first completes, while the second is still being served. A round
        // barrier would only issue it after the whole round drained.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let batch_bytes = GROUPS_PER_REQUEST * epix_blob::bitfield::GROUP_BYTES;
        let data = vec![7u8; (batch_bytes * 3) as usize];
        let id = ObjId::of(&data);
        let size = data.len() as u64;

        // A wide serve delay: the assertion below compares wall-clock
        // instants across real decode work, and the suite runs many tests
        // in parallel, so the refill gap must dwarf scheduling noise.
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let peers = vec![PeerHandle {
            conn: sequential_serving_conn(data, Duration::from_secs(1), log.clone()),
            class: Class::Clearnet,
            bits: GroupBits::complete(size),
            label: "seq".into(),
        }];

        let mut swarm = Swarm::new(store.clone(), id, size);
        store.ensure_sparse(id, epix_blob::Ns::Plain, size, 1).unwrap();
        let needed = needed_groups(&store, id, size).unwrap();
        let report = swarm.fetch(&needed, &peers, Deadline::background(), 2).await.unwrap();
        assert!(store.is_complete(id).unwrap(), "object completed");
        assert_eq!(report.requests_issued, 3, "three batches were issued");

        let log = log.lock().unwrap();
        let starts: Vec<_> = log.iter().filter(|(k, _)| *k == "start").map(|(_, t)| *t).collect();
        let ends: Vec<_> = log.iter().filter(|(k, _)| *k == "end").map(|(_, t)| *t).collect();
        assert_eq!(starts.len(), 3);
        assert!(
            starts[2] < ends[1],
            "the third batch must be issued while the second is still being served"
        );
    }

    /// Every scheduled batch charges its bytes to its link and the charge
    /// is refunded when the batch future ends - won, failed, or cancelled -
    /// so one fetch's leftovers cannot inflate the stall windows of the
    /// next swarm to share the connection.
    #[tokio::test]
    async fn the_link_queue_counter_is_refunded_when_the_fetch_ends() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let data = vec![7u8; 300_000];
        let id = ObjId::of(&data);
        let size = data.len() as u64;

        let peers = vec![PeerHandle {
            conn: serving_conn(&data),
            class: Class::Clearnet,
            bits: GroupBits::complete(size),
            label: "srv".into(),
        }];
        let mut swarm = Swarm::new(store.clone(), id, size);
        let needed = needed_groups(&store, id, size).unwrap();
        swarm.fetch(&needed, &peers, Deadline::background(), 2).await.unwrap();
        assert!(store.is_complete(id).unwrap());
        assert_eq!(peers[0].conn.queued_fetch_bytes(), 0, "a completed fetch refunds its charges");

        // A fetch whose batches all FAIL (dead link) refunds too.
        let data2 = vec![9u8; 40_000];
        let id2 = ObjId::of(&data2);
        let size2 = data2.len() as u64;
        let peers = vec![PeerHandle {
            conn: dead_conn(),
            class: Class::Clearnet,
            bits: GroupBits::complete(size2),
            label: "dead".into(),
        }];
        let mut swarm = Swarm::new(store.clone(), id2, size2);
        let needed = needed_groups(&store, id2, size2).unwrap();
        let _ = swarm.fetch(&needed, &peers, Deadline::background(), 2).await;
        assert_eq!(peers[0].conn.queued_fetch_bytes(), 0, "a failed fetch refunds its charges");
    }
}
