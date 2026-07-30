//! Multi-peer fetch scheduler: deadline + rarest-first striping with
//! per-transport-class latency priors and duplicate-on-timeout.
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
//! - **per-transport-class EWMA**: clearnet, I2P and Tor differ 10-30x,
//!   so a global timeout is wrong. Each class carries its own smoothed
//!   RTT; a request that overruns `k * class_rtt` is DUPLICATED to an
//!   equal-or-lower-latency class (never a slower one — that just adds
//!   load), duplicates capped so a stall can't fan out unboundedly.
//! - **deadline tiers**: tight for streaming/first-paint, loose for
//!   background; tighter deadlines are scheduled first.
//!
//! This module owns the DECISION logic (what to ask which peer, when to
//! duplicate) and drives it via the fetch client; the choker
//! (`choke.rs`) governs the upload side.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use epix_blob::bitfield::{group_count, GroupBits};
use epix_blob::store::Store;
use epix_blob::ObjId;

use crate::conn::Conn;
use crate::fetch;
use crate::sim::Class;

/// Timeout multiplier: a request slower than `K_TIMEOUT * class_rtt` is
/// eligible for duplication.
pub const K_TIMEOUT: u32 = 4;
/// Max concurrent duplicate fetches of the same group set (endgame cap).
pub const MAX_DUPLICATES: usize = 2;
/// Share of a batch's hard budget the primary may hold before the
/// duplicated race starts (1/N of `Deadline::max_wait`). A class prior
/// that has grown past the whole budget would otherwise let the primary
/// eat all of it, leaving the duplicates no time to answer.
pub const PRIMARY_BUDGET_DIVISOR: u32 = 2;
/// Groups per striped request (16 KiB * 64 = 1 MiB chunks of work).
pub const GROUPS_PER_REQUEST: u64 = 64;

/// Smoothed per-class round-trip prior. Starts at the class's nominal
/// RTT and converges toward observed request latencies (EWMA, alpha 1/4).
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

    /// The timeout after which a request to `class` may be duplicated.
    pub fn timeout(&self, class: Class) -> Duration {
        self.rtt(class) * K_TIMEOUT
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

/// Group a sorted list of group indices into contiguous request-sized
/// byte ranges for an object of `size` bytes.
pub fn batch_into_ranges(groups: &[u64], size: u64) -> Vec<std::ops::Range<u64>> {
    use epix_blob::bitfield::bytes_of_group;
    let mut out = Vec::new();
    let mut i = 0;
    while i < groups.len() {
        let start_group = groups[i];
        let mut end_group = start_group;
        let mut j = i + 1;
        while j < groups.len()
            && groups[j] == end_group + 1
            && (end_group + 1 - start_group) < GROUPS_PER_REQUEST
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
fn split_by_holder(groups: &[u64], peers: &[PeerHandle], size: u64) -> Vec<std::ops::Range<u64>> {
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
            && (end_group + 1 - start_group) < GROUPS_PER_REQUEST
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

/// The fetch driver for one object across a peer set.
pub struct Swarm {
    store: Arc<Store>,
    obj: ObjId,
    size: u64,
    stats: ClassStats,
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

impl Swarm {
    pub fn new(store: Arc<Store>, obj: ObjId, size: u64) -> Self {
        Self { store, obj, size, stats: ClassStats::default() }
    }

    pub fn stats(&self) -> &ClassStats {
        &self.stats
    }

    /// Fetch every group in `needed` from the peer set, striping
    /// rarest-first and duplicating stalled requests onto faster-or-equal
    /// peers. Returns when all needed groups are present locally or no
    /// peer can supply a remaining group.
    ///
    /// `deadline` scales the timeout: a tight (streaming) deadline shrinks
    /// the duplicate trigger so a slow peer is raced sooner.
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

        // Per-peer failure counts across rounds: a peer that errors or serves
        // bytes that fail verification is deprioritized (picked last) so the
        // swarm routes around it instead of retrying it every round.
        let mut fails = vec![0u32; peers.len()];
        // The peer set and their bitfields are fixed for this call, so the
        // rarest-first order never changes: build it once and walk it with a
        // cursor. Re-counting holders and re-sorting every remaining group
        // each round made a whole-object fetch quadratic in object size (a
        // 10 GB object is ~600k groups over ~1600 rounds).
        let full_order = rarest_first_order(needed, peers);
        let mut cursor = 0usize;
        // Groups needed to fill one round's batches (see the take() below).
        let window = peers.len().max(1) * 2 * GROUPS_PER_REQUEST as usize;
        while !remaining.is_empty() {
            // Skip the fetched prefix. A group whose batch failed is still in
            // `remaining`, so it holds the cursor and is retried this round,
            // exactly as a full recompute would.
            while cursor < full_order.len() && !remaining.contains(full_order[cursor]) {
                cursor += 1;
            }
            let mut order = Vec::new();
            for &g in &full_order[cursor..] {
                if order.len() >= window {
                    break;
                }
                if remaining.contains(g) {
                    order.push(g);
                }
            }
            if order.is_empty() {
                break; // no peer holds any remaining group
            }
            let batches = batch_into_ranges(&order, self.size);

            // Assign concurrent batches across peers so work STRIPES
            // instead of piling onto the single fastest peer: each batch
            // goes to the least-loaded eligible peer this round, ties
            // broken by class RTT (so fast peers still get more, but slow
            // peers are used in parallel rather than idled).
            let mut load = vec![0u32; peers.len()];
            let mut tasks = Vec::new();
            for batch in batches.into_iter().take(peers.len().max(1) * 2) {
                let bgroups = self.groups_of(&batch);
                match self.pick_peer(&bgroups, peers, &load, &fails) {
                    Some(idx) => {
                        load[idx] += 1;
                        report.requests_issued += 1;
                        tasks.push(self.race_batch(batch, bgroups, idx, peers, deadline, now));
                    }
                    None => {
                        // A merged batch can straddle groups held by DISJOINT
                        // peers (equal holder COUNTS don't mean the same
                        // holder SET), so no single peer holds all of it.
                        // Split into maximal sub-batches each fully held by
                        // some peer instead of skipping it — skipping would
                        // strand groups that ARE available and leave the
                        // object stuck incomplete.
                        for sub in split_by_holder(&bgroups, peers, self.size) {
                            let sgroups = self.groups_of(&sub);
                            let Some(idx) = self.pick_peer(&sgroups, peers, &load, &fails) else {
                                continue;
                            };
                            load[idx] += 1;
                            report.requests_issued += 1;
                            tasks.push(self.race_batch(sub, sgroups, idx, peers, deadline, now));
                        }
                    }
                }
            }
            if tasks.is_empty() {
                break;
            }
            let results = futures_join_all(tasks).await;
            let mut progressed = false;
            for outcome in results {
                report.duplicates_issued += outcome.duplicates;
                // Fold the winner's measured latency into the class prior, so
                // the next round's timeout/duplication uses real RTT.
                if let (Some(cls), Some(el)) = (outcome.winner_class, outcome.elapsed) {
                    self.stats.observe(cls, el);
                }
                // Deprioritize a peer that failed this batch next round.
                if let Some(p) = outcome.failed_peer {
                    if let Some(f) = fails.get_mut(p) {
                        *f = f.saturating_add(1);
                    }
                }
                let Some(label) = outcome.winner_label else { continue };
                for g in &outcome.groups {
                    remaining.remove(*g..*g + 1);
                    report.groups_fetched += 1;
                    progressed = true;
                }
                *report.by_peer.entry(label).or_default() += outcome.groups.len() as u64;
            }
            if !progressed {
                break; // a full round made no progress; give up
            }
        }

        Ok(report)
    }

    fn groups_of(&self, batch: &std::ops::Range<u64>) -> Vec<u64> {
        use epix_blob::bitfield::groups_for_bytes;
        let gr = groups_for_bytes(batch);
        gr.collect()
    }

    /// Least-loaded peer this round that holds every group in `groups`,
    /// ties broken by class RTT (fast peers preferred). Spreads
    /// concurrent batches so a multi-peer swarm actually stripes.
    fn pick_peer(&self, groups: &[u64], peers: &[PeerHandle], load: &[u32], fails: &[u32]) -> Option<usize> {
        peers
            .iter()
            .enumerate()
            .filter(|(_, p)| groups.iter().all(|g| p.bits.contains(*g)))
            // Fewest prior failures first, then least-loaded, then fastest
            // class: a peer that failed verification or errored is used only
            // when no healthier peer holds the groups.
            .min_by_key(|(i, p)| (fails[*i], load[*i], self.stats.rtt(p.class)))
            .map(|(i, _)| i)
    }

    /// Fetch `batch` from peer `primary`; if it overruns the class
    /// timeout, duplicate to up to MAX_DUPLICATES faster-or-equal peers
    /// that also hold the groups. First success wins; the object store's
    /// idempotent verified writes make a late duplicate harmless.
    async fn race_batch(
        &self,
        batch: std::ops::Range<u64>,
        groups: Vec<u64>,
        primary: usize,
        peers: &[PeerHandle],
        deadline: Deadline,
        now: u64,
    ) -> BatchOutcome {
        // The primary gets its class timeout, but never more than a share of
        // the batch's hard budget: whatever it leaves is all the duplicated
        // race below can have, and a race with no time left is just wasted
        // peer traffic.
        let timeout = self
            .stats
            .timeout(peers[primary].class)
            .min(deadline.max_wait / PRIMARY_BUDGET_DIVISOR);
        let ranges = [batch.clone()];
        let fetch_from = |i: usize| {
            fetch::fetch_ranges(
                &peers[i].conn,
                &self.store,
                self.obj,
                self.size,
                &ranges,
                deadline.ms,
                now,
            )
        };

        let start = std::time::Instant::now();
        let primary_fut = fetch_from(primary);
        tokio::pin!(primary_fut);

        // Race the primary against its timeout. Record whether it already
        // COMPLETED with an error: a completed async fn must never be
        // polled again (that panics "async fn resumed after completion"),
        // so a fast primary error must not fall through to a re-await.
        let primary_errored = match tokio::time::timeout(timeout, &mut primary_fut).await {
            Ok(Ok(_)) => {
                let cls = peers[primary].class;
                return BatchOutcome::won(groups, peers[primary].label.clone(), 0, cls, start.elapsed());
            }
            Ok(Err(_)) => true,  // primary finished with an error
            Err(_) => false,     // primary still running, just slow
        };

        // Duplicate onto faster-or-equal peers holding the groups.
        let ok_classes = self.stats.faster_or_equal(peers[primary].class);
        let targets: Vec<usize> = peers
            .iter()
            .enumerate()
            .filter(|(i, p)| {
                *i != primary
                    && ok_classes.contains(&p.class)
                    && groups.iter().all(|g| p.bits.contains(*g))
            })
            .map(|(i, _)| i)
            .take(MAX_DUPLICATES)
            .collect();

        // What is left of the batch's hard cap. Everything below is bounded
        // by it: a peer that accepts the GetRange and then sends nothing
        // keeps `fetch_ranges` pending for as long as the connection lives,
        // so an unbounded wait here would never return.
        let left = deadline.max_wait.saturating_sub(start.elapsed());

        if targets.is_empty() || left.is_zero() {
            // Nothing to duplicate onto, or no budget for a duplicate to
            // answer in. Issuing a fetch we would drop in the same tick only
            // makes those peers start encoding and take a Cancel for nothing,
            // so do not issue it. If the primary already errored there is
            // nothing left to try; otherwise wait it out under what remains.
            if primary_errored {
                return BatchOutcome::failed(0, Some(primary));
            }
            return match tokio::time::timeout(left, &mut primary_fut).await {
                Ok(Ok(_)) => {
                    let cls = peers[primary].class;
                    BatchOutcome::won(groups, peers[primary].label.clone(), 0, cls, start.elapsed())
                }
                Ok(Err(_)) | Err(_) => BatchOutcome::failed(0, Some(primary)),
            };
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
        // The race runs on what the primary left of the budget: silent-but-
        // alive peers stay Pending forever, so without this the whole fetch
        // parks. Dropping the racers on expiry fires their cancel-on-abandon
        // guards, telling those peers to stop encoding.
        match tokio::time::timeout(left, select_first_ok(racers)).await {
            Ok(Some(winner)) => {
                let cls = peers[winner].class;
                BatchOutcome::won(groups, peers[winner].label.clone(), dups, cls, start.elapsed())
            }
            Ok(None) | Err(_) => BatchOutcome::failed(dups, Some(primary)),
        }
    }
}

/// The result of racing one batch: which groups landed (empty on
/// failure), the winning peer's label, how many duplicates fired, and the
/// winner's class + measured request latency (fed back into the per-class
/// EWMA so duplicate-on-timeout uses real RTT, not just the static prior).
struct BatchOutcome {
    groups: Vec<u64>,
    winner_label: Option<String>,
    duplicates: u64,
    winner_class: Option<Class>,
    elapsed: Option<Duration>,
    /// The peer index that failed this batch (a network error or, worse,
    /// bytes that failed verification), so later rounds deprioritize it.
    failed_peer: Option<usize>,
}

impl BatchOutcome {
    fn won(groups: Vec<u64>, label: String, duplicates: u64, class: Class, elapsed: Duration) -> Self {
        Self {
            groups,
            winner_label: Some(label),
            duplicates,
            winner_class: Some(class),
            elapsed: Some(elapsed),
            failed_peer: None,
        }
    }
    fn failed(duplicates: u64, failed_peer: Option<usize>) -> Self {
        Self {
            groups: Vec::new(),
            winner_label: None,
            duplicates,
            winner_class: None,
            elapsed: None,
            failed_peer,
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
    /// First-paint / streaming: race slow peers quickly.
    pub fn tight() -> Self {
        Self { ms: 250, max_wait: Duration::from_secs(10) }
    }
    /// Background bulk: patient.
    pub fn background() -> Self {
        Self { ms: 0, max_wait: Duration::from_secs(120) }
    }
}

// --- tiny future combinators (avoid pulling futures-util) ---

/// Poll every future concurrently, returning the outputs in input order.
///
/// A round's batches must be in flight AT THE SAME TIME: `race_batch` only
/// sends its request when first polled, so awaiting the futures one after
/// another would issue batch N+1 to its peer only once batch N finished,
/// and the whole per-round striping across peers would run serially.
async fn futures_join_all<F, T>(futs: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T>,
{
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct JoinAll<F: Future> {
        /// Each slot is cleared once its future resolves.
        futs: Vec<Option<Pin<Box<F>>>>,
        out: Vec<Option<F::Output>>,
    }
    // The futures are boxed, so nothing is pin-projected through Self.
    impl<F: Future> Unpin for JoinAll<F> {}
    impl<F: Future> Future for JoinAll<F> {
        type Output = Vec<F::Output>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let me = self.get_mut();
            let mut pending = false;
            for i in 0..me.futs.len() {
                let ready = match me.futs[i].as_mut() {
                    Some(f) => match f.as_mut().poll(cx) {
                        Poll::Ready(v) => Some(v),
                        Poll::Pending => {
                            pending = true;
                            None
                        }
                    },
                    None => None,
                };
                if let Some(v) = ready {
                    me.out[i] = Some(v);
                    me.futs[i] = None;
                }
            }
            if pending {
                return Poll::Pending;
            }
            Poll::Ready(me.out.iter_mut().filter_map(Option::take).collect())
        }
    }

    let mut out: Vec<Option<T>> = Vec::new();
    out.resize_with(futs.len(), || None);
    JoinAll { futs: futs.into_iter().map(|f| Some(Box::pin(f))).collect(), out }.await
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
        let ranges = batch_into_ranges(&groups, 1_000_000);
        // Two contiguous runs -> two ranges.
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn batching_splits_at_request_size() {
        let groups: Vec<u64> = (0..(GROUPS_PER_REQUEST * 2 + 5)).collect();
        let ranges = batch_into_ranges(&groups, 1 << 40);
        assert!(ranges.len() >= 3, "a run longer than a request must split");
    }

    fn dummy_conn() -> Conn {
        let (a, _b) = tokio::io::duplex(64);
        std::mem::forget(_b);
        let (c, _in) = Conn::start(a, true);
        c
    }

    /// A connection whose peer end is gone: any fetch errors almost
    /// immediately (BrokenPipe), well before the class timeout.
    fn dead_conn() -> Conn {
        let (a, b) = tokio::io::duplex(64);
        let (c, _in) = Conn::start(a, true);
        drop(b); // peer end dropped -> writes fail, stream reports closed
        c
    }

    #[tokio::test]
    async fn race_batch_survives_a_fast_primary_error() {
        // A primary peer that errors BEFORE the class timeout (here a dead
        // connection) hits race_batch's Ok(Err(_)) arm. The completed fetch
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
    async fn a_silent_peer_gives_up_at_the_deadline() {
        // A peer that takes the GetRange and then answers nothing, on a
        // connection that stays open, leaves fetch_ranges pending for as
        // long as the link lives. The batch must still give up at
        // Deadline::max_wait rather than parking the fetch (and the task
        // that awaits it) forever.
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
        let report =
            tokio::time::timeout(deadline.max_wait * 3, swarm.fetch(&needed, &peers, deadline, 2))
                .await
                .expect("a silent peer must not hang the fetch")
                .unwrap();
        assert_eq!(report.groups_fetched, 0, "the silent peer served nothing");
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

    // Real (not paused) time: race_batch measures its budget with
    // std::time::Instant, which tokio's virtual clock does not advance.
    #[tokio::test]
    async fn a_slow_primary_leaves_the_duplicate_time_to_win() {
        // Once the class prior grows past the batch's hard cap, the primary's
        // first wait used to swallow the WHOLE cap. The duplicated race was
        // then issued with nothing left: both targets got a GetRange followed
        // immediately by a Cancel, and the batch always failed. A share of
        // the cap is reserved, so the duplicate still has time to answer.
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

        let mut swarm = Swarm::new(store.clone(), id, size);
        // Grow the clearnet prior until its timeout exceeds the cap below:
        // that is the case the reserved share is for.
        for _ in 0..20 {
            swarm.stats.observe(Class::Clearnet, Duration::from_millis(300));
        }
        let deadline = Deadline { ms: 0, max_wait: Duration::from_millis(600) };
        assert!(swarm.stats.timeout(Class::Clearnet) > deadline.max_wait);

        let groups = swarm.groups_of(&(0..size));
        let outcome = swarm.race_batch(0..size, groups, 0, &peers, deadline, 2).await;
        assert_eq!(outcome.duplicates, 1, "the stalled primary is duplicated onto the other peer");
        assert_eq!(
            outcome.winner_label.as_deref(),
            Some("fast"),
            "the duplicate must be issued with enough budget left to answer"
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
        let outcome = swarm.race_batch(0..size, groups, 0, &peers, deadline, 2).await;
        assert_eq!(outcome.duplicates, 0, "no budget left means no duplicate is issued");
        assert!(outcome.winner_label.is_none(), "nobody can win a zero-length race");
    }

    #[tokio::test(start_paused = true)]
    async fn join_all_polls_every_batch_concurrently() {
        // Each future waits on the other's start signal, so both finish only
        // if the join polls them together. Awaiting them in sequence (one
        // batch fully done before the next is even issued) deadlocks here.
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
        let futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = u32>>>> =
            vec![Box::pin(a), Box::pin(b)];
        let out = tokio::time::timeout(Duration::from_secs(5), futures_join_all(futs))
            .await
            .expect("a round's batches must make progress together");
        assert_eq!(out, vec![1, 2], "outputs stay in input order");
    }
}
