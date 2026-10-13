//! The durable scheduler (`docs/evx-milestone-3.md` section 2): one tokio
//! task that sleeps until the earliest persisted `next_due`, wakes for the
//! events that change what is due, and on every tick re-derives admission
//! from the durable state, the grant and the plugin switch before reserving
//! an occurrence and running it through [`EvxService::execute`].
//!
//! Nothing here is state that matters: the schedule, the claims, the
//! budget and the failure counts all live in `evx-state`, so the task can
//! die with the process and the next start continues from the rows. What
//! the task holds is a wake handle, a count of runs in flight and the time
//! it means to wake at, for status. The selection itself ([`plan`]) is a
//! pure function of what the tick gathered, so it is tested on a fake time
//! line without a database or a worker. The tick reads the clock again
//! after every step that can take a while, so no decision is made at a
//! time a slot has since left behind.
//!
//! The lifecycle, from the spec: wait, wake, admit, run, commit, release.
//! Admission checks run in the spec's order (plugin, grant, declaration
//! coverage, daily budget, host-wide workers, the xite's run lock), then
//! `claim_occurrence` reserves the slot; a reservation that is not fresh is
//! someone else's (a manual run of the same slot) and the job steps past it.
//! A clock before the last claimed slot claims nothing and sleeps until that
//! slot has passed. Missed slots are never backfilled: `Skip` and `Coalesce`
//! both run the current slot once after a gap, which is what the state's
//! claim rule already enforces, so the policies need no code here.
//!
//! Recovery runs once, at the first tick with the plugin enabled: a
//! reservation left open before guest admission is run under the same
//! identity when its slot is still the current one (`DurableState::recover`
//! rotates its fencing token so the dead worker could not commit even if it
//! were alive), and finished as `abandoned` when the slot has passed, so
//! the schedule moves on and the history says what happened. A recovered
//! run is never awaited inside the tick: it waits for a worker like any
//! admitted occurrence, counted against the host-wide cap, and is closed as
//! abandoned instead if its slot passes while it waits. A reservation this
//! process holds (a claim made before the task got to run) is not an
//! earlier process's and is left to its owner, which is why every claim is
//! registered with [`Scheduler::hold`] before it is made. A reservation is
//! never dropped silently; one whose grant was fenced since (a run revoked
//! in flight), or whose job is paused, is closed as abandoned without the
//! fence (`DurableState::abandon`) rather than left open for every later
//! start to trip over.
//! A reservation whose guest was admitted may already have changed its
//! workspace. Recovery closes it as `effect_unknown` and atomically pauses
//! the job for reconciliation, even if its slot has passed.

use std::collections::{HashMap, HashSet};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use epix_ui::AppState;
use evx_state::{DurableState, Invocation, JobRow, RunRecord, SECONDS_PER_DAY};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::Notify;

use crate::limits::{BACKGROUND_RUNS_PER_DAY, BACKGROUND_WORKERS};
use crate::service::{
    bounded_message, now_unix, occurrence_request, status_name, EvxService, Integrity, Occurrence,
    PauseReason, Run, Trigger, WaitReason,
};
use crate::PLUGIN_NAME;

/// Backup policy polling while disabled. Configuration changes also wake
/// the dedicated watch, including when there are no registered jobs.
pub const DISABLED_POLL: u64 = 2;

/// A content change for a xite with jobs wakes the scheduler this long
/// after the first event, so a burst of events (a download of many files,
/// a re-sign followed by a sync) causes one tick, not one per event.
pub const CONTENT_WAKE_COALESCE: Duration = Duration::from_secs(2);

/// How long the task waits before looking again at a job it could not act
/// on for a reason no wake will clear by itself but that passes quickly: a
/// xite whose run lock is held by a run-once, a database error. A bound on
/// retries, never a cadence.
pub const RETRY_INTERVAL: u64 = 2;

/// How long the jobs of a xite the scheduler could not inspect (a
/// declaration gone, unsigned or unreadable, files still missing) wait
/// before the scheduler inspects it again by itself. A content change for
/// the xite inspects it at once, so this is only the safety net for a
/// change no event announced.
pub const INSPECTION_RECHECK: u64 = 300;

/// Smallest and largest jitter added to a wake, in seconds. The jitter is
/// up to a tenth of the job's period within these bounds, so a thousand
/// nodes with the same hourly job do not all wake on the hour, while a job
/// every second is not delayed by a minute.
pub const JITTER_BOUNDS: (u64, u64) = (1, 60);

/// Base of the failure backoff: the first failure waits at least a minute.
pub const BACKOFF_BASE: u64 = 30;

/// Longest the failure backoff grows to: six hours.
pub const BACKOFF_CEILING: u64 = 6 * 3600;

/// The status word an abandoned reservation is finished and recorded with.
pub const ABANDONED: &str = evx_state::ABANDONED;

/// The wake handle and the counters the task shares with the service.
#[derive(Default)]
pub struct Scheduler {
    notify: Notify,
    /// Background occurrences admitted and not yet finished.
    busy: AtomicUsize,
    /// The same occurrences by xite: a xite here is busy from the moment
    /// its occurrence is spawned, before the run has taken the xite's run
    /// lock, so a tick in between cannot admit a second run of the xite.
    active: Mutex<HashMap<String, usize>>,
    /// When the task means to wake next, for status; `None` while it waits
    /// for a wake only.
    next_wake: Mutex<Option<u64>>,
    /// Occurrences reserved (or about to be) by this process and not yet
    /// finished, as `<xite>/<occurrence>`, each with how many holders it
    /// has: what recovery must not mistake for a crash's leftovers. Counted,
    /// so a claim that turns out not to be its holder's own (the slot was
    /// already taken) releases only its own hold, never the owner's.
    held: Mutex<HashMap<String, usize>>,
    /// Whether recovery has run; it runs once, at the first enabled tick.
    recovered: AtomicBool,
    stopped: AtomicBool,
    /// Ticks completed since start, for tests and status views.
    ticks: AtomicU64,
}

impl Scheduler {
    /// Note that this process reserved `occurrence` of `xite`; released by
    /// [`EvxService::execute`] once the reservation is finished.
    /// [`EvxService::execute`] once the reservation is finished. Called
    /// before the claim is made, so there is no moment at which this
    /// process's fresh reservation is in the database but not held.
    pub(crate) fn hold(&self, xite: &str, occurrence: &str) {
        if let Ok(mut held) = self.held.lock() {
            *held.entry(format!("{xite}/{occurrence}")).or_default() += 1;
        }
    }

    /// Drop one hold of `occurrence` of `xite`; the occurrence stays held
    /// while any other holder remains.
    pub(crate) fn release(&self, xite: &str, occurrence: &str) {
        if let Ok(mut held) = self.held.lock() {
            let key = format!("{xite}/{occurrence}");
            if let Some(count) = held.get_mut(&key) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(&key);
                }
            }
        }
    }

    pub(crate) fn holds(&self, xite: &str, occurrence: &str) -> bool {
        self.held
            .lock()
            .is_ok_and(|held| held.contains_key(&format!("{xite}/{occurrence}")))
    }

    /// Wake the task: something that decides what is due changed. A wake
    /// with no waiter is kept for the next wait, so a wake during a tick is
    /// never lost.
    pub fn wake(&self) {
        self.notify.notify_one();
    }

    /// Stop the task at its next wake.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Whether [`Scheduler::stop`] was called.
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Background occurrences in flight right now.
    pub fn busy(&self) -> usize {
        self.busy.load(Ordering::SeqCst)
    }

    /// Count a background occurrence of `xite` as in flight.
    fn enter(&self, xite: &str) {
        self.busy.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut active) = self.active.lock() {
            *active.entry(xite.to_string()).or_default() += 1;
        }
    }

    /// The occurrence [`Scheduler::enter`] counted has finished.
    fn leave(&self, xite: &str) {
        self.busy.fetch_sub(1, Ordering::SeqCst);
        if let Ok(mut active) = self.active.lock() {
            if let Some(count) = active.get_mut(xite) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    active.remove(xite);
                }
            }
        }
    }

    /// Whether a background occurrence of `xite` is in flight, whether or
    /// not it has reached the xite's run lock yet.
    pub(crate) fn active(&self, xite: &str) -> bool {
        self.active.lock().is_ok_and(|active| active.contains_key(xite))
    }

    /// Ticks the task completed since start: what a wake led to.
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::SeqCst)
    }

    /// When the task means to wake next, for status.
    pub fn next_wake(&self) -> Option<u64> {
        self.next_wake.lock().ok().and_then(|wake| *wake)
    }

    fn set_next_wake(&self, wake: Option<u64>) {
        if let Ok(mut next) = self.next_wake.lock() {
            *next = wake;
        }
    }
}

/// Seconds to wait after the `failures`th consecutive failure:
/// `min(2^failures * BACKOFF_BASE, BACKOFF_CEILING)`, with the shift
/// saturating so a long failure streak cannot wrap into a short wait.
pub(crate) fn backoff(failures: u32) -> u64 {
    let factor = 1u64.checked_shl(failures).unwrap_or(u64::MAX);
    factor.saturating_mul(BACKOFF_BASE).min(BACKOFF_CEILING)
}

/// The most jitter a wake for a job of `period` seconds gets.
pub(crate) fn jitter_bound(period: u64) -> u64 {
    (period / 10).clamp(JITTER_BOUNDS.0, JITTER_BOUNDS.1)
}

/// `due` plus a jitter of `seed % (bound + 1)` seconds for a job of
/// `period`: the caller supplies the randomness so the arithmetic is
/// testable, and the result never precedes the due time.
pub(crate) fn jittered(due: u64, period: u64, seed: u64) -> u64 {
    due.saturating_add(seed % (jitter_bound(period) + 1))
}

/// A per-process random seed for the jitter. The standard hasher's random
/// keys are all the randomness this needs: jitter spreads wakes across
/// nodes, it secures nothing.
fn jitter_seed(now: u64) -> u64 {
    RandomState::new().hash_one(now)
}

/// One due job as the tick gathered it, with the facts admission decides on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub xite: String,
    pub job: String,
    /// The live grant covers the current declaration.
    pub covers: bool,
    /// Background runs the xite started this UTC day.
    pub daily_runs: u32,
    /// The xite's run lock is held.
    pub xite_busy: bool,
}

/// What [`plan`] decided for one candidate, in decision order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    Admit { xite: String, job: String },
    Wait { xite: String, job: String, reason: WaitReason },
}

/// Decide which due jobs to admit this tick, fairly across xites: the
/// candidates come in `due_jobs` order (oldest `next_due` first) and are
/// taken round robin over the xites in the order each first appears, one
/// job per xite per round, so a xite with many due jobs cannot starve one
/// with a single job. Each pick runs the spec's remaining checks in order:
/// the grant covers the declaration; the xite's daily runs, counting those
/// admitted earlier this tick, are under `daily_limit`; the host-wide
/// workers, counting `busy` and those admitted this tick, are under
/// `workers`; the xite's run lock is free and no job of it was admitted
/// this tick (the lock admits one run per xite). The first check that
/// fails is the reason the job waits with. Pure.
pub(crate) fn plan(candidates: &[Candidate], busy: usize, workers: usize, daily_limit: u32) -> Vec<Decision> {
    let mut order: Vec<&str> = Vec::new();
    let mut groups: HashMap<&str, Vec<&Candidate>> = HashMap::new();
    for candidate in candidates {
        let group = groups.entry(candidate.xite.as_str()).or_default();
        if group.is_empty() {
            order.push(candidate.xite.as_str());
        }
        group.push(candidate);
    }
    let mut cursors: Vec<usize> = vec![0; order.len()];
    let mut in_flight = busy;
    let mut admitted_xites: HashSet<&str> = HashSet::new();
    let mut admitted_runs: HashMap<&str, u32> = HashMap::new();
    let mut decisions = Vec::with_capacity(candidates.len());
    loop {
        let mut any = false;
        for (position, xite) in order.iter().enumerate() {
            let group = &groups[xite];
            let Some(candidate) = group.get(cursors[position]) else { continue };
            cursors[position] += 1;
            any = true;
            let admitted_today = candidate.daily_runs.saturating_add(*admitted_runs.get(xite).unwrap_or(&0));
            let reason = if !candidate.covers {
                Some(WaitReason::DeclarationNotCovered)
            } else if admitted_today >= daily_limit {
                Some(WaitReason::DailyBudget)
            } else if in_flight >= workers {
                Some(WaitReason::WorkersBusy)
            } else if candidate.xite_busy || admitted_xites.contains(xite) {
                Some(WaitReason::XiteBusy)
            } else {
                None
            };
            match reason {
                Some(reason) => decisions.push(Decision::Wait {
                    xite: candidate.xite.clone(),
                    job: candidate.job.clone(),
                    reason,
                }),
                None => {
                    in_flight += 1;
                    admitted_xites.insert(xite);
                    *admitted_runs.entry(xite).or_default() += 1;
                    decisions.push(Decision::Admit { xite: candidate.xite.clone(), job: candidate.job.clone() });
                }
            }
        }
        if !any {
            break;
        }
    }
    decisions
}

/// The period of a registered job's schedule, from its stored JSON form.
fn period(row: &JobRow) -> Result<u64, String> {
    // One second past the slot start is still that slot, so its end is the
    // start of the next one and the period is their difference.
    let slot = DurableState::slot_at(&row.schedule, 0).map_err(|error| format!("EVX state: {error}"))?;
    Ok(slot.end_unix - slot.start_unix)
}

/// What the task carries from one tick to the next. None of it is state
/// that matters across a restart: the reservations in `recovered` are open
/// rows a later start recovers again, and the rest only paces re-checks.
#[derive(Default)]
pub(crate) struct TaskState {
    /// Reservations recovery re-fenced and holds, waiting for a worker:
    /// they run on their own tasks like admitted occurrences, counted
    /// against [`BACKGROUND_WORKERS`], never inline in a tick.
    recovered: Vec<Occurrence>,
    /// Xites with jobs whose content changed since the last tick: each is
    /// inspected again at the next tick, so a re-signed declaration is
    /// registered (or paused) without waiting for its next due time.
    changed: HashSet<String>,
    /// When the task last inspected each xite whose jobs it paused because
    /// it could not inspect them, for the slow re-check.
    rechecked: HashMap<String, u64>,
}

/// The scheduler task: the wait/wake loop until [`Scheduler::stop`], with
/// recovery folded into the first tick that finds the plugin enabled.
pub(crate) async fn run(service: Arc<EvxService>, app: Arc<AppState>) {
    let scheduler = &service.scheduler;
    let mut events = app.subscribe_events();
    let mut plugin_changes = app.subscribe_plugin_changes();
    let mut events_open = true;
    let mut job_xites: Vec<String> = Vec::new();
    let mut coalesce: Option<Instant> = None;
    let mut tick_due = true;
    let mut task = TaskState::default();
    loop {
        if scheduler.stopped() {
            scheduler.set_next_wake(None);
            break;
        }
        if tick_due {
            tick_due = false;
            let wake = match now_unix() {
                Ok(now) => tick(&service, &app, now, &mut task).await,
                Err(error) => {
                    app.log("ERROR", format!("EVX scheduler: {error}")).await;
                    None
                }
            };
            scheduler.set_next_wake(wake);
            scheduler.ticks.fetch_add(1, Ordering::SeqCst);
            job_xites = service.state.job_xites().unwrap_or_default();
        }
        let timer = scheduler
            .next_wake()
            .and_then(|at| now_unix().ok().map(|now| Instant::now() + Duration::from_secs(at.saturating_sub(now))));
        let deadline = match (timer, coalesce) {
            (Some(timer), Some(coalesce)) => Some(timer.min(coalesce)),
            (timer, coalesce) => timer.or(coalesce),
        };
        tokio::select! {
            _ = plugin_changes.changed() => {
                tick_due = true;
            }
            _ = scheduler.notify.notified() => {
                tick_due = true;
            }
            _ = sleep_until(deadline) => {
                coalesce = None;
                tick_due = true;
            }
            event = events.recv(), if events_open => {
                let relevant = match event {
                    Ok(event) => match event.target {
                        Some(target) if job_xites.contains(&target) => {
                            task.changed.insert(target);
                            true
                        }
                        _ => false,
                    },
                    // Events were dropped: any of them may have been for a
                    // xite with jobs, so every such xite is looked at again.
                    Err(RecvError::Lagged(_)) => {
                        task.changed.extend(job_xites.iter().cloned());
                        !job_xites.is_empty()
                    }
                    Err(RecvError::Closed) => {
                        events_open = false;
                        false
                    }
                };
                if relevant && coalesce.is_none() {
                    coalesce = Some(Instant::now() + CONTENT_WAKE_COALESCE);
                }
            }
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

/// The facts of one xite a tick gathers once for all of its due jobs.
struct XiteFacts {
    covers: bool,
    daily_runs: u32,
    busy: bool,
    rows: Vec<JobRow>,
}

/// One pass: admit what is due and say when to wake next (`None`: only a
/// wake will do). Every pass starts with the plugin switch, so disabling
/// the plugin stops admission at the next pass and revokes the brokers of
/// running work; a host that cannot execute admits nothing and says so in
/// status. Nothing in a pass waits for a run: recovered and admitted
/// occurrences run on their own tasks, so the switch is read again within
/// [`DISABLED_POLL`] whatever is running. The clock is read again after
/// every step that can take a while (recovery, the inspections), so each
/// decision is made at the time it is made, never at a time a slot has
/// since left behind.
async fn tick(service: &Arc<EvxService>, app: &Arc<AppState>, now: u64, task: &mut TaskState) -> Option<u64> {
    let scheduler = &service.scheduler;
    if !app.plugin_enabled(PLUGIN_NAME).await {
        let brokers: Vec<_> = service
            .running
            .lock()
            .map(|running| running.values().cloned().collect())
            .unwrap_or_default();
        for broker in &brokers {
            broker.revoke();
        }
        if !brokers.is_empty() {
            app.log("INFO", format!("EVX scheduler: plugin disabled, {} run(s) stopped", brokers.len())).await;
        }
        return Some(now + DISABLED_POLL);
    }
    if !scheduler.recovered.swap(true, Ordering::SeqCst) {
        let found = recover(service, app, now_unix).await;
        task.recovered.extend(found);
    }
    let mut hints: Vec<u64> = Vec::new();
    let now = now_unix().unwrap_or(now);
    // Recovered occurrences go first: their slot is current and already
    // reserved, so they take the free workers before new admissions do.
    let mut held_xites = launch_recovered(service, app, &mut task.recovered, now, &mut hints).await;
    held_xites.extend(task.recovered.iter().map(|occurrence| occurrence.row.xite.clone()));
    reinspect(service, app, now, task, &mut hints).await;
    if service.execution_ready().is_err() {
        return hints.into_iter().min();
    }
    let now = now_unix().unwrap_or(now);
    let due_cutoff = now;
    let due = match service.state.due_jobs(due_cutoff) {
        Ok(due) => due,
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: due jobs: {error}")).await;
            return Some(now + RETRY_INTERVAL);
        }
    };
    let mut facts: HashMap<String, XiteFacts> = HashMap::new();
    let mut skipped: HashSet<String> = HashSet::new();
    for row in &due {
        if facts.contains_key(&row.xite) || skipped.contains(&row.xite) {
            continue;
        }
        match xite_facts(service, app, &row.xite, now, held_xites.contains(&row.xite), task, &mut hints).await {
            Some(xite) => {
                facts.insert(row.xite.clone(), xite);
            }
            None => {
                skipped.insert(row.xite.clone());
            }
        }
    }
    // The inspections read files; decide at the time the decision is made.
    let now = now_unix().unwrap_or(now);
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut rows: HashMap<(String, String), JobRow> = HashMap::new();
    for due_row in &due {
        let Some(xite) = facts.get(&due_row.xite) else { continue };
        let Some(row) = xite.rows.iter().find(|row| row.job == due_row.job) else { continue };
        if !row.enabled || row.paused_reason.is_some() || row.next_due_unix.is_none_or(|at| at > now) {
            continue;
        }
        candidates.push(Candidate {
            xite: row.xite.clone(),
            job: row.job.clone(),
            covers: xite.covers,
            daily_runs: xite.daily_runs,
            xite_busy: xite.busy,
        });
        rows.insert((row.xite.clone(), row.job.clone()), row.clone());
    }
    for decision in plan(&candidates, scheduler.busy(), BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY) {
        match decision {
            Decision::Admit { xite, job } => {
                if let Some(row) = rows.remove(&(xite, job)) {
                    admit(service, app, row, now, &mut hints).await;
                }
            }
            Decision::Wait { reason: WaitReason::DailyBudget, .. } => {
                hints.push((now / SECONDS_PER_DAY + 1) * SECONDS_PER_DAY);
            }
            Decision::Wait { reason: WaitReason::XiteBusy, .. } => {
                hints.push(now + RETRY_INTERVAL);
            }
            // A worker finishing or a grant changing wakes the task.
            Decision::Wait { .. } => {}
        }
    }
    // A job that became due during this tick was absent from `due`. Search
    // from that original cutoff so it produces an immediate wake instead of
    // disappearing between the due and future queries at a second boundary.
    match next_job_wake(&service.state, due_cutoff, now) {
        Ok(Some(wake)) => hints.push(wake),
        Ok(None) => {}
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: next due: {error}")).await;
            hints.push(now + RETRY_INTERVAL);
        }
    }
    hints.into_iter().min()
}

fn next_job_wake(state: &DurableState, due_cutoff: u64, now: u64) -> evx_state::Result<Option<u64>> {
    Ok(state.next_due_job(due_cutoff)?.and_then(|row| {
        let due = row.next_due_unix?;
        let period = period(&row).ok()?;
        Some(jittered(due, period, jitter_seed(now)))
    }))
}

/// Gather what admission decides on for one xite with due jobs, or `None`
/// when its jobs cannot be considered this tick. The inspection re-registers
/// the jobs from what is on disk now and pauses what the grant no longer
/// covers, so the rows are read after it and a job it paused is not a
/// candidate. A xite that cannot be inspected has its jobs paused with the
/// reason, which status shows, and is looked at again on a content change
/// or after [`INSPECTION_RECHECK`], never on every tick.
async fn xite_facts(
    service: &Arc<EvxService>,
    app: &Arc<AppState>,
    xite: &str,
    now: u64,
    held: bool,
    task: &mut TaskState,
    hints: &mut Vec<u64>,
) -> Option<XiteFacts> {
    let (reason, detail) = match service.inspect(app, xite).await {
        Ok(inspection) if inspection.integrity == Integrity::Verified => {
            return match (service.state.daily_runs(xite, now), service.state.jobs(xite)) {
                (Ok(daily_runs), Ok(rows)) => Some(XiteFacts {
                    covers: inspection.covers_declaration(now),
                    daily_runs,
                    busy: held || service.scheduler.active(xite) || !service.run_lock_free(xite).await,
                    rows,
                }),
                (Err(error), _) | (_, Err(error)) => {
                    app.log("ERROR", format!("EVX scheduler: {xite}: {error}")).await;
                    hints.push(now + RETRY_INTERVAL);
                    None
                }
            };
        }
        Ok(inspection) => (inspection_pause(inspection.integrity), format!("declaration is {}", inspection.integrity.name())),
        Err(error) => (PauseReason::DeclarationUnavailable, error),
    };
    pause_unreadable(service, app, xite, reason, &detail).await;
    task.rechecked.insert(xite.to_string(), now);
    hints.push(now.saturating_add(INSPECTION_RECHECK));
    None
}

/// The pause a xite gets for an inspection that did not verify.
fn inspection_pause(integrity: Integrity) -> PauseReason {
    match integrity {
        Integrity::Incomplete => PauseReason::ContentIncomplete,
        _ => PauseReason::DeclarationUnavailable,
    }
}

/// Pause the jobs of a xite the scheduler could not inspect, logging the
/// pause once, when it is set, rather than on every look.
async fn pause_unreadable(service: &EvxService, app: &AppState, xite: &str, reason: PauseReason, detail: &str) {
    match service.pause_for_inspection(xite, reason) {
        Ok(true) => {
            app.log("WARN", format!("EVX scheduler: jobs of {xite} paused ({}): {detail}", reason.name())).await;
        }
        Ok(false) => {}
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: jobs of {xite} not paused: {error}")).await;
        }
    }
}

/// Inspect again every xite whose content changed since the last tick and
/// every xite whose jobs the task paused for an inspection that failed,
/// the latter at most every [`INSPECTION_RECHECK`] unless its content
/// changed. A verified inspection registers the jobs, which re-derives
/// every pause registration owns (clearing an inspection pause); one that
/// fails pauses the jobs with the reason instead.
async fn reinspect(service: &Arc<EvxService>, app: &Arc<AppState>, now: u64, task: &mut TaskState, hints: &mut Vec<u64>) {
    let changed = std::mem::take(&mut task.changed);
    let paused: HashSet<String> = match service.state.paused_jobs(now) {
        Ok(rows) => rows
            .into_iter()
            .filter(|row| {
                row.paused_reason
                    .as_deref()
                    .and_then(PauseReason::parse)
                    .is_some_and(PauseReason::from_inspection)
            })
            .map(|row| row.xite)
            .collect(),
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: paused jobs: {error}")).await;
            HashSet::new()
        }
    };
    task.rechecked.retain(|xite, _| paused.contains(xite));
    let mut look: Vec<String> = changed.iter().cloned().collect();
    for xite in &paused {
        if changed.contains(xite) {
            continue;
        }
        match task.rechecked.get(xite).map(|at| at.saturating_add(INSPECTION_RECHECK)) {
            Some(at) if at > now => hints.push(at),
            _ => look.push(xite.clone()),
        }
    }
    look.sort();
    for xite in look {
        let unreadable = match service.inspect(app, &xite).await {
            Ok(inspection) if inspection.integrity == Integrity::Verified => None,
            Ok(inspection) => Some((inspection_pause(inspection.integrity), format!("declaration is {}", inspection.integrity.name()))),
            Err(error) => Some((PauseReason::DeclarationUnavailable, error)),
        };
        match unreadable {
            None => {
                if task.rechecked.remove(&xite).is_some() {
                    app.log("INFO", format!("EVX scheduler: {xite} inspected again; its jobs are registered from the current declaration")).await;
                }
            }
            Some((reason, detail)) => {
                pause_unreadable(service, app, &xite, reason, &detail).await;
                task.rechecked.insert(xite, now);
                hints.push(now.saturating_add(INSPECTION_RECHECK));
            }
        }
    }
}

/// Run recovered occurrences on their own tasks while workers are free,
/// one per xite at a time and only where the xite's run lock is free, and
/// close the ones whose slot passed while they waited (a passed slot is
/// never run). Returns the xites launched for, which the rest of the tick
/// treats as busy: their runs have not taken the lock yet.
async fn launch_recovered(
    service: &Arc<EvxService>,
    app: &Arc<AppState>,
    pending: &mut Vec<Occurrence>,
    now: u64,
    hints: &mut Vec<u64>,
) -> HashSet<String> {
    let mut launched: HashSet<String> = HashSet::new();
    let mut waiting: Vec<Occurrence> = Vec::new();
    for occurrence in std::mem::take(pending) {
        let xite = occurrence.row.xite.clone();
        if occurrence.slot.end_unix <= now {
            let closed = close_abandoned(
                service,
                app,
                &occurrence.invocation,
                Some(&occurrence.row),
                Close::Finish(Some(occurrence.slot.end_unix)),
                RECOVERED_SLOT_PASSED,
                now,
            )
            .await;
            if closed {
                service.scheduler.release(&xite, &occurrence.invocation.occurrence);
            }
            continue;
        }
        if service.scheduler.busy() >= BACKGROUND_WORKERS
            || service.scheduler.active(&xite)
            || !service.run_lock_free(&xite).await
        {
            waiting.push(occurrence);
            continue;
        }
        app.log("INFO", format!("EVX recovery: running {} of {xite} again under the same identity", occurrence.invocation.occurrence)).await;
        launched.insert(xite);
        spawn_occurrence(service, app, occurrence);
    }
    if !waiting.is_empty() {
        hints.push(now + RETRY_INTERVAL);
    }
    *pending = waiting;
    launched
}

/// Run a reserved, held occurrence on its own task, counted in `busy` and
/// as its xite's from now until it is finished, and wake the task when it
/// is.
fn spawn_occurrence(service: &Arc<EvxService>, app: &Arc<AppState>, occurrence: Occurrence) {
    let xite = occurrence.row.xite.clone();
    let job = occurrence.row.job.clone();
    let program = occurrence.row.program.clone();
    service.scheduler.enter(&xite);
    let service = Arc::clone(service);
    let app = Arc::clone(app);
    tokio::spawn(async move {
        let result = service
            .execute(&app, &xite, &program, Run::Job { occurrence: Box::new(occurrence), trigger: Trigger::Job })
            .await;
        if let Err(error) = result {
            app.log("WARN", format!("EVX scheduler: job {job} of {xite} refused: {error}")).await;
        }
        service.scheduler.leave(&xite);
        service.scheduler.wake();
    });
}

/// Reserve the current slot of `row` and run it on its own task, so two
/// xites admitted in one tick run at once. A slot already claimed (by a
/// manual run) is stepped past; a clock before the last claimed slot
/// claims nothing and the job sleeps until that slot has passed. The
/// reservation is held before it is made, so recovery can never take a
/// fresh claim of this process for a crash's leftover.
async fn admit(service: &Arc<EvxService>, app: &Arc<AppState>, row: JobRow, now: u64, hints: &mut Vec<u64>) {
    let xite = row.xite.clone();
    let job = row.job.clone();
    let slot = match DurableState::slot_at(&row.schedule, now) {
        Ok(slot) => slot,
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: job {job} of {xite}: {error}")).await;
            hints.push(now + RETRY_INTERVAL);
            return;
        }
    };
    if let Some(last) = row.last_slot.filter(|last| slot.index < *last) {
        let period = slot.end_unix - slot.start_unix;
        let passed = (last + 1).saturating_mul(period);
        app.log("WARN", format!("EVX scheduler: clock rollback for job {job} of {xite}: slot {} before {last}; waiting until {passed}", slot.index)).await;
        if let Err(error) = service.state.set_job_next_due(&xite, &job, Some(passed)) {
            app.log("ERROR", format!("EVX scheduler: job {job} of {xite}: {error}")).await;
        }
        hints.push(passed);
        return;
    }
    let occurrence_id = DurableState::occurrence_id(&row.job, &slot);
    service.scheduler.hold(&xite, &occurrence_id);
    let invocation = match service
        .state
        .claim_occurrence(&xite, &row, &slot, &occurrence_request(&row, &slot), now)
    {
        Ok(invocation) => invocation,
        Err(error) => {
            service.scheduler.release(&xite, &occurrence_id);
            match error {
                // A bound the state keeps (the retained occurrences, the
                // grant's persistent budget) will not move by itself within
                // this slot: the job steps to the next slot, which status
                // shows, instead of trying again every few seconds.
                evx_state::Error::BudgetExceeded(_) => {
                    app.log("WARN", format!("EVX scheduler: job {job} of {xite} not claimed: {error}; next slot")).await;
                    if let Err(error) = service.state.set_job_next_due(&xite, &job, Some(slot.end_unix)) {
                        app.log("ERROR", format!("EVX scheduler: job {job} of {xite}: {error}")).await;
                    }
                }
                // The grant changed under the plan; the change wakes the task.
                evx_state::Error::Denied(_) => {
                    app.log("WARN", format!("EVX scheduler: job {job} of {xite} not claimed: {error}")).await;
                }
                _ => {
                    app.log("WARN", format!("EVX scheduler: job {job} of {xite} not claimed: {error}")).await;
                    hints.push(now + RETRY_INTERVAL);
                }
            }
            return;
        }
    };
    if !invocation.fresh {
        service.scheduler.release(&xite, &occurrence_id);
        app.log(
            "INFO",
            format!(
                "EVX scheduler: occurrence {} of {xite} already {}; next slot",
                invocation.occurrence,
                if invocation.completed { "completed" } else { "running" }
            ),
        )
        .await;
        if let Err(error) = service.state.set_job_next_due(&xite, &job, Some(slot.end_unix)) {
            app.log("ERROR", format!("EVX scheduler: job {job} of {xite}: {error}")).await;
        }
        return;
    }
    if let Err(error) = service.state.reserve_daily_run(&xite, now, BACKGROUND_RUNS_PER_DAY) {
        // The budget was spent between the plan and the claim (a manual run
        // does not spend it, but a tick on another day could); the
        // reservation is finished as refused so it is not left open.
        let summary = json!({
            "status": status_name(evx_api::Status::Denied),
            "value": null,
            "error": error.to_string(),
            "elapsed_ms": 0,
            "occurrence": invocation.occurrence,
        });
        if let Err(error) = service.state.finish_occurrence(&invocation, &summary, Some(slot.end_unix), false) {
            app.log("ERROR", format!("EVX scheduler: occurrence {} of {xite} not finished: {error}", invocation.occurrence)).await;
        }
        service.scheduler.release(&xite, &occurrence_id);
        hints.push((now / SECONDS_PER_DAY + 1) * SECONDS_PER_DAY);
        return;
    }
    spawn_occurrence(service, app, Occurrence { invocation, row, slot });
}

/// Why a reservation from an earlier process is closed without running.
const RECOVERED_SLOT_PASSED: &str = "reservation from before a restart; its slot has passed";
const RECOVERED_JOB_PAUSED: &str = "reservation from before a restart; the job is paused or disabled";
const RECOVERED_GRANT_CHANGED: &str = "reservation from before a restart; the grant changed since it was made";

/// Examine every reservation left open by an earlier process, once, reading
/// `clock` afresh for each so that whatever time the examination takes,
/// "still current" means current when it is decided. Nothing runs here:
/// an occurrence whose slot is current and whose job may run is re-fenced
/// (`DurableState::recover` rotates its token), held, and returned for the
/// tick to run on a worker like an admitted one. One whose slot has passed
/// is finished as abandoned so the schedule moves on; one whose job is
/// paused or disabled, or whose grant changed since it was made (a run
/// revoked mid-flight), is closed as abandoned without the grant fence and
/// without moving the schedule. Each closure is recorded in the history.
async fn recover(
    service: &Arc<EvxService>,
    app: &Arc<AppState>,
    clock: impl Fn() -> Result<u64, String>,
) -> Vec<Occurrence> {
    let mut recovered = Vec::new();
    let incomplete = match service.state.incomplete_occurrences(None) {
        Ok(incomplete) => incomplete,
        Err(error) => {
            app.log("ERROR", format!("EVX recovery: {error}")).await;
            return recovered;
        }
    };
    for open in incomplete {
        if service.scheduler.holds(&open.xite, &open.occurrence) {
            // Reserved by this process and still running: its owner will
            // finish it.
            continue;
        }
        let (job, index) = match evx_state::occurrence_parts(&open.occurrence) {
            Ok(parts) => parts,
            Err(_) => {
                // Not a job occurrence (a Milestone 1 fixture's, say): no
                // schedule to move on, nothing to run again. Left as it is.
                app.log("WARN", format!("EVX recovery: {} of {} is not a job occurrence; left open", open.occurrence, open.xite)).await;
                continue;
            }
        };
        let invocation = Invocation {
            xite: open.xite.clone(),
            occurrence: open.occurrence.clone(),
            token: open.token.clone(),
            generation: open.generation,
            schema_generation: open.schema_generation,
            fresh: false,
            completed: false,
            response: None,
        };
        let row = match service.state.jobs(&open.xite) {
            Ok(rows) => rows.into_iter().find(|row| row.job == job),
            Err(error) => {
                app.log("ERROR", format!("EVX recovery: {}: {error}", open.xite)).await;
                continue;
            }
        };
        let now = match clock() {
            Ok(now) => now,
            Err(error) => {
                app.log("ERROR", format!("EVX recovery: {error}")).await;
                break;
            }
        };
        if open.execution_started {
            let message = "execution was interrupted after admission; reconcile workspace effects before resuming";
            match service.state.abandon_uncertain(&invocation, message) {
                Ok(()) => {
                    app.log("WARN", format!("EVX recovery: {} of {} requires reconciliation", open.occurrence, open.xite)).await;
                    if let Some(row) = &row {
                        record_closed(service, app, row, &open.occurrence, "effect_unknown", message, now).await;
                    }
                }
                Err(error) => {
                    app.log("ERROR", format!("EVX recovery: {} of {} could not be paused: {error}", open.occurrence, open.xite)).await;
                }
            }
            continue;
        }
        let current = row
            .as_ref()
            .and_then(|row| DurableState::slot_at(&row.schedule, now).ok())
            .filter(|slot| slot.index == index);
        match (row, current) {
            (Some(row), Some(_)) if !row.enabled || row.paused_reason.is_some() => {
                close_abandoned(service, app, &invocation, Some(&row), Close::Abandon, RECOVERED_JOB_PAUSED, now).await;
            }
            (Some(row), Some(slot)) => match service.state.recover(&invocation) {
                Ok(fresh) => {
                    service.scheduler.hold(&open.xite, &open.occurrence);
                    recovered.push(Occurrence { invocation: fresh, row, slot });
                }
                Err(evx_state::Error::Denied(_)) => {
                    close_abandoned(service, app, &invocation, Some(&row), Close::Abandon, RECOVERED_GRANT_CHANGED, now).await;
                }
                Err(error) => {
                    app.log("ERROR", format!("EVX recovery: {} of {} cannot be recovered: {error}", open.occurrence, open.xite)).await;
                }
            },
            // No current slot: the slot has passed, or the job vanished (a
            // slot is only ever computed from a row, so a row-less slot
            // cannot occur).
            (row, _) => {
                let next_due = row
                    .as_ref()
                    .and_then(|row| period(row).ok())
                    .map(|period| (index + 1).saturating_mul(period));
                close_abandoned(service, app, &invocation, row.as_ref(), Close::Finish(next_due), RECOVERED_SLOT_PASSED, now).await;
            }
        }
    }
    recovered
}

/// How [`close_abandoned`] closes a reservation.
#[derive(Debug, Clone, Copy)]
enum Close {
    /// Finish it through the grant fence and move the job to this
    /// `next_due`; a fenced grant falls back to [`Close::Abandon`].
    Finish(Option<u64>),
    /// Close it without the fence, leaving the job row as it is.
    Abandon,
}

/// Close a reservation without a run, as `abandoned` with `message`, and
/// record it in the run history. Returns whether it is closed.
async fn close_abandoned(
    service: &EvxService,
    app: &AppState,
    invocation: &Invocation,
    row: Option<&JobRow>,
    close: Close,
    message: &str,
    now: u64,
) -> bool {
    let id = invocation.occurrence.as_str();
    let xite = invocation.xite.as_str();
    let summary = json!({
        "status": ABANDONED,
        "value": null,
        "error": message,
        "elapsed_ms": 0,
        "occurrence": id,
    });
    let closed = match close {
        Close::Finish(next_due) => match service.state.finish_occurrence(invocation, &summary, next_due, false) {
            // Fenced: the grant was revoked or given again since the
            // reservation was made, which would refuse every later finish
            // too. The host closes its own reservation without the fence.
            Err(evx_state::Error::Denied(_)) => service.state.abandon(invocation, &bounded_message(message)),
            other => other,
        },
        Close::Abandon => service.state.abandon(invocation, &bounded_message(message)),
    };
    match closed {
        Ok(()) => {
            app.log("WARN", format!("EVX recovery: {id} of {xite} abandoned: {message}")).await;
            if let Some(row) = row {
                record_abandoned(service, app, row, id, message, now).await;
            }
            true
        }
        Err(error) => {
            app.log("ERROR", format!("EVX recovery: {id} of {xite} not closed: {error}")).await;
            false
        }
    }
}

/// Put an abandoned occurrence in the run history, so status shows what
/// became of it next to the runs that happened. Nothing ran, so the
/// artifact is the digest of nothing and the input the canonical `null`.
async fn record_abandoned(service: &EvxService, app: &AppState, row: &JobRow, occurrence: &str, message: &str, now: u64) {
    record_closed(service, app, row, occurrence, ABANDONED, message, now).await;
}

// No artifact or telemetry survives an interrupted process. The empty digest
// denotes unavailable provenance, not evidence that the guest did no work.
async fn record_closed(service: &EvxService, app: &AppState, row: &JobRow, occurrence: &str, status: &str, message: &str, now: u64) {
    let input = evx_state::canonical(&Value::Null)
        .map(|canonical| evx_state::digest(&canonical))
        .unwrap_or_default();
    let record = RunRecord {
        started_unix: now,
        finished_unix: now,
        program: row.program.clone(),
        declaration_digest: row.declaration_digest.clone(),
        artifact_sha256: hex::encode(Sha256::digest(b"")),
        input_digest: input,
        status: status.to_string(),
        message: Some(bounded_message(message)),
        cpu_seconds: 0.0,
        peak_rss: 0,
        occurrence: Some(occurrence.to_string()),
        trigger: Trigger::Job.name().to_string(),
    };
    if let Err(error) = service.state.record_run(&row.xite, &record) {
        app.log("ERROR", format!("EVX recovery: {occurrence} of {} not recorded: {error}", row.xite)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::collections::BTreeSet;

    use evx_api::Limits;
    use evx_declaration::{Anchor, Missed, Schedule};
    use evx_state::{JobSpec, XiteGrant};

    use crate::service::RUNTIME_PROFILE;

    /// The period of every job in the recovery tests.
    const PERIOD: u64 = 60;
    /// A slot start (a multiple of [`PERIOD`]) after the grants' consent.
    const T: u64 = 1_700_000_040;

    /// A service over a throwaway root with no xite served: an inspection
    /// fails, and nothing a test does here reaches a worker.
    fn service() -> (Arc<EvxService>, Arc<AppState>) {
        let app = AppState::new("test");
        let service = Arc::new(EvxService::for_node(&app, None).unwrap());
        (service, app)
    }

    #[tokio::test]
    async fn disabling_the_plugin_wakes_an_idle_scheduler_and_revokes_a_manual_run() {
        let (service, app) = service();
        let workspace = service.workspace_dir("1ManualRun");
        std::fs::create_dir_all(&workspace).unwrap();
        let grant = evx_api::Grant::new("1ManualRun", true).unwrap();
        let broker = Arc::new(evx_supervisor::Broker::new(&workspace, grant, Limits::default()).unwrap());
        service.running.lock().unwrap().insert("1ManualRun".into(), broker.clone());
        let task = tokio::spawn(run(service.clone(), app.clone()));
        while service.scheduler_ticks() == 0 {
            tokio::task::yield_now().await;
        }
        app.set_plugin_enabled(PLUGIN_NAME, false).await;
        let stopped = tokio::time::timeout(Duration::from_secs(3), async {
            while broker.grant().enabled {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await;
        service.shutdown();
        task.await.unwrap();
        assert!(stopped.is_ok(), "plugin disable never woke a scheduler with no jobs");
    }

    fn grant(service: &EvxService, xite: &str) {
        let grant = XiteGrant {
            xite: xite.into(),
            publisher: xite.into(),
            enabled: true,
            capabilities: BTreeSet::new(),
            runtime_profiles: [RUNTIME_PROFILE.to_string()].into_iter().collect(),
            limits: Limits::default(),
            allow_run_once: true,
            allow_background: true,
            created_unix: 1_700_000_000,
            expires_unix: None,
            label: "test".into(),
        };
        service.state.set_xite_grant(&grant).unwrap();
    }

    /// Grant `xite` and register its one job `sync` every [`PERIOD`].
    fn granted_job(service: &EvxService, xite: &str) -> JobRow {
        grant(service, xite);
        let spec = JobSpec {
            job: "sync".into(),
            program: "calc".into(),
            schedule: Schedule::Interval { seconds: PERIOD, anchor: Anchor::UnixEpoch, missed: Missed::Skip },
            max_concurrency: 1,
        };
        service.state.set_jobs(xite, &"a".repeat(64), &[spec], T).unwrap();
        service.state.jobs(xite).unwrap().remove(0)
    }

    #[test]
    fn a_job_becoming_due_during_a_tick_still_supplies_a_wake() {
        let (service, _app) = service();
        granted_job(&service, "1Boundary");
        service.state.set_job_next_due("1Boundary", "sync", Some(T + PERIOD)).unwrap();
        let cutoff = T + PERIOD - 1;
        assert!(service.state.due_jobs(cutoff).unwrap().is_empty());
        let finished = T + PERIOD + 30;
        assert!(service.state.next_due_job(finished).unwrap().is_none());
        let wake = next_job_wake(&service.state, cutoff, finished).unwrap().expect("newly due job must wake the scheduler");
        assert!(wake <= finished, "a passed deadline must schedule an immediate tick");
    }

    /// Reserve the slot `at` falls in, as a process that then crashed did.
    fn reserve(service: &EvxService, row: &JobRow, at: u64) -> Invocation {
        let slot = DurableState::slot_at(&row.schedule, at).unwrap();
        let invocation = service
            .state
            .claim_occurrence(&row.xite, row, &slot, &occurrence_request(row, &slot), at)
            .unwrap();
        assert!(invocation.fresh);
        invocation
    }

    /// The committed response of `occurrence`, if it was closed.
    fn response(service: &EvxService, xite: &str, occurrence: &str) -> Option<Value> {
        service
            .state
            .snapshot(xite)
            .unwrap()
            .invocations
            .into_iter()
            .find(|row| row.occurrence == occurrence)
            .and_then(|row| row.response)
    }

    fn job_row(service: &EvxService, xite: &str) -> JobRow {
        service.state.jobs(xite).unwrap().remove(0)
    }

    #[tokio::test]
    async fn recovery_never_replays_an_occurrence_that_may_have_written_before_crashing() {
        for offset in [10, PERIOD + 10] {
            let (service, app) = service();
            let row = granted_job(&service, "1InterruptedWrite");
            let open = reserve(&service, &row, T + 5);
            service.state.mark_execution_started(&open).unwrap();
            let workspace = service.workspace_dir(&row.xite);
            std::fs::create_dir_all(&workspace).unwrap();
            std::fs::write(workspace.join("score.txt"), "1").unwrap();
            // The previous process died after a write, before its result was
            // committed. Neither a current nor an expired slot proves that
            // repeating that invocation would be safe.
            let recovered = recover(&service, &app, || Ok(T + offset)).await;
            assert!(recovered.is_empty(), "an admitted guest was scheduled again");
            assert_eq!(job_row(&service, &row.xite).paused_reason.as_deref(), Some("reconcile_required"));
            assert_eq!(response(&service, &row.xite, &open.occurrence).unwrap()["status"], "effect_unknown");
            assert_eq!(std::fs::read_to_string(workspace.join("score.txt")).unwrap(), "1");
        }
    }

    #[tokio::test]
    async fn recovery_decides_each_reservation_when_it_reaches_it_so_a_slot_that_passed_meanwhile_is_abandoned_not_run() {
        let (service, app) = service();
        let a = granted_job(&service, "1RecoverA");
        let b = granted_job(&service, "1RecoverB");
        let open_a = reserve(&service, &a, T + 10);
        let open_b = reserve(&service, &b, T + 10);
        // The clock moves on while recovery works through the list: the
        // first reservation is examined inside its slot, the second after
        // the slot ended (as if the first had taken ninety seconds).
        let reads = Cell::new(0u32);
        let clock = || {
            reads.set(reads.get() + 1);
            Ok(if reads.get() == 1 { T + 10 } else { T + PERIOD + 30 })
        };
        let recovered = recover(&service, &app, clock).await;
        assert_eq!(reads.get(), 2, "one clock read per reservation");
        // The current one is handed back to run on a worker, re-fenced and
        // held; nothing ran inside recovery.
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].row.xite, "1RecoverA");
        assert_eq!(recovered[0].invocation.occurrence, open_a.occurrence);
        assert_ne!(recovered[0].invocation.token, open_a.token, "recover rotates the token");
        assert!(service.scheduler.holds("1RecoverA", &open_a.occurrence));
        assert!(service.state.runs("1RecoverA").unwrap().is_empty(), "nothing ran inline");
        assert!(response(&service, "1RecoverA", &open_a.occurrence).is_none());
        // The passed one is finished as abandoned and its job moves to the
        // end of that slot, never re-run as if it were current.
        let closed = response(&service, "1RecoverB", &open_b.occurrence).unwrap();
        assert_eq!(closed["status"], ABANDONED);
        assert_eq!(job_row(&service, "1RecoverB").next_due_unix, Some(T + PERIOD));
        assert!(!service.scheduler.holds("1RecoverB", &open_b.occurrence));
        let runs = service.state.runs("1RecoverB").unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, ABANDONED);
        assert_eq!(runs[0].occurrence.as_deref(), Some(open_b.occurrence.as_str()));
    }

    #[tokio::test]
    async fn recovered_runs_wait_for_a_free_worker_and_are_abandoned_if_their_slot_passes_while_they_wait() {
        let (service, app) = service();
        let xites = ["1RecoverA", "1RecoverB", "1RecoverC"];
        let mut open = Vec::new();
        for xite in xites {
            let row = granted_job(&service, xite);
            open.push(reserve(&service, &row, T + 10));
        }
        let mut pending = recover(&service, &app, || Ok(T + 10)).await;
        assert_eq!(pending.len(), 3);
        // Every worker is busy with admitted runs: none of the recovered
        // runs starts, and the task looks again shortly.
        service.scheduler.busy.store(BACKGROUND_WORKERS, Ordering::SeqCst);
        let mut hints = Vec::new();
        let launched = launch_recovered(&service, &app, &mut pending, T + 10, &mut hints).await;
        assert!(launched.is_empty());
        assert_eq!(pending.len(), 3);
        assert_eq!(hints, [T + 10 + RETRY_INTERVAL]);
        // One worker frees up: exactly one recovered run takes it, counted
        // in `busy` before it has even started.
        service.scheduler.busy.store(BACKGROUND_WORKERS - 1, Ordering::SeqCst);
        let mut hints = Vec::new();
        let launched = launch_recovered(&service, &app, &mut pending, T + 11, &mut hints).await;
        assert_eq!(launched.into_iter().collect::<Vec<_>>(), ["1RecoverA"]);
        assert_eq!(service.scheduler.busy(), BACKGROUND_WORKERS);
        assert_eq!(pending.len(), 2);
        // The slot ends before another worker is free: the two still
        // waiting are closed as abandoned rather than run late, and their
        // jobs move to the end of the slot.
        let mut hints = Vec::new();
        let launched = launch_recovered(&service, &app, &mut pending, T + PERIOD, &mut hints).await;
        assert!(launched.is_empty());
        assert!(pending.is_empty());
        assert!(hints.is_empty());
        for (xite, invocation) in xites.iter().zip(&open).skip(1) {
            assert_eq!(response(&service, xite, &invocation.occurrence).unwrap()["status"], ABANDONED, "{xite}");
            assert!(!service.scheduler.holds(xite, &invocation.occurrence), "{xite}");
            assert_eq!(job_row(&service, xite).next_due_unix, Some(T + PERIOD), "{xite}");
        }
    }

    #[tokio::test]
    async fn a_xite_with_a_spawned_run_is_busy_before_the_run_takes_its_lock() {
        let (service, app) = service();
        grant(&service, "1RecoverA");
        let spec = |job: &str| JobSpec {
            job: job.into(),
            program: "calc".into(),
            schedule: Schedule::Interval { seconds: PERIOD, anchor: Anchor::UnixEpoch, missed: Missed::Skip },
            max_concurrency: 1,
        };
        service.state.set_jobs("1RecoverA", &"a".repeat(64), &[spec("first"), spec("second")], T).unwrap();
        for row in service.state.jobs("1RecoverA").unwrap() {
            reserve(&service, &row, T + 10);
        }
        let mut pending = recover(&service, &app, || Ok(T + 10)).await;
        assert_eq!(pending.len(), 2);
        // The first is spawned and has not run at all yet (this runtime
        // has one thread and the test has not yielded): its xite's run lock
        // is still free, and the xite is busy all the same.
        let mut hints = Vec::new();
        let launched = launch_recovered(&service, &app, &mut pending, T + 10, &mut hints).await;
        assert_eq!(launched.len(), 1);
        assert!(service.run_lock_free("1RecoverA").await);
        assert!(service.scheduler.active("1RecoverA"));
        assert_eq!(pending.len(), 1, "one run per xite at a time");
        // A later pass, before the first run has started, still waits.
        let launched = launch_recovered(&service, &app, &mut pending, T + 11, &mut hints).await;
        assert!(launched.is_empty());
        assert_eq!(pending.len(), 1);
        // Once the first run is over the xite is free again.
        wait_until(|| !service.scheduler.active("1RecoverA")).await;
        assert_eq!(service.scheduler.busy(), 0);
        let launched = launch_recovered(&service, &app, &mut pending, T + 12, &mut hints).await;
        assert_eq!(launched.len(), 1);
        assert!(pending.is_empty());
        wait_until(|| service.scheduler.busy() == 0).await;
    }

    /// Yield until `done` holds, for at most ten seconds.
    async fn wait_until(done: impl Fn() -> bool) {
        let started = Instant::now();
        while !done() {
            assert!(started.elapsed() < Duration::from_secs(10), "timed out");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn recovery_closes_a_paused_jobs_reservation_as_abandoned_without_running_it_or_moving_its_schedule() {
        let (service, app) = service();
        let row = granted_job(&service, "1RecoverA");
        let open = reserve(&service, &row, T + 10);
        service.state.set_job_paused("1RecoverA", "sync", Some("user")).unwrap();
        let before = job_row(&service, "1RecoverA");
        let recovered = recover(&service, &app, || Ok(T + 10)).await;
        assert!(recovered.is_empty(), "a paused job is not run behind its pause");
        assert_eq!(response(&service, "1RecoverA", &open.occurrence).unwrap()["status"], ABANDONED);
        assert!(service.state.incomplete_occurrences(None).unwrap().is_empty());
        let after = job_row(&service, "1RecoverA");
        assert_eq!(after.paused_reason.as_deref(), Some("user"));
        assert_eq!(after.next_due_unix, before.next_due_unix);
        assert_eq!(after.failures, before.failures);
        // The same for a pause a run set.
        let row = granted_job(&service, "1RecoverB");
        let open = reserve(&service, &row, T + 10);
        service.state.set_job_paused("1RecoverB", "sync", Some("reconcile_required")).unwrap();
        assert!(recover(&service, &app, || Ok(T + 10)).await.is_empty());
        assert_eq!(response(&service, "1RecoverB", &open.occurrence).unwrap()["status"], ABANDONED);
    }

    #[tokio::test]
    async fn a_reservation_whose_grant_was_revoked_and_given_again_is_closed_at_recovery_instead_of_leaking() {
        let (service, app) = service();
        let a = granted_job(&service, "1RecoverA");
        let b = granted_job(&service, "1RecoverB");
        let open_a = reserve(&service, &a, T + 10);
        let open_b = reserve(&service, &b, T + 10);
        // Revoked mid-run and granted again: the generation the
        // reservations were made under is gone, which fences `recover` and
        // `finish_occurrence` for good.
        for xite in ["1RecoverA", "1RecoverB"] {
            service.state.revoke_xite(xite).unwrap();
            grant(&service, xite);
        }
        assert!(service.state.recover(&open_a).is_err(), "the fence holds");
        // A's slot is current, B's has passed.
        let reads = Cell::new(0u32);
        let clock = || {
            reads.set(reads.get() + 1);
            Ok(if reads.get() == 1 { T + 10 } else { T + PERIOD + 5 })
        };
        let recovered = recover(&service, &app, clock).await;
        assert!(recovered.is_empty(), "a fenced reservation is not run");
        for (xite, open) in [("1RecoverA", &open_a), ("1RecoverB", &open_b)] {
            let closed = response(&service, xite, &open.occurrence).unwrap();
            assert_eq!(closed["status"], ABANDONED, "{xite}");
            assert_eq!(service.state.runs(xite).unwrap()[0].status, ABANDONED, "{xite}");
        }
        assert!(service.state.incomplete_occurrences(None).unwrap().is_empty(), "nothing left for the next start");
        // The next start finds nothing to trip over.
        assert!(recover(&service, &app, || Ok(T + 10)).await.is_empty());
    }

    #[tokio::test]
    async fn a_claim_refused_by_a_retention_bound_moves_the_job_to_its_next_slot_instead_of_retrying_every_tick() {
        let (service, app) = service();
        let row = granted_job(&service, "1RecoverA");
        // Fill the xite's retained rows with reservations of its own.
        for index in 0..evx_state::MAX_ROWS {
            service.state.begin("1RecoverA", &format!("once-{index:016x}"), None, 1).unwrap();
        }
        let now = T + 10;
        let mut hints = Vec::new();
        admit(&service, &app, row.clone(), now, &mut hints).await;
        let after = job_row(&service, "1RecoverA");
        assert_eq!(after.next_due_unix, Some(T + PERIOD), "the job steps to the next slot");
        assert!(!hints.contains(&(now + RETRY_INTERVAL)), "no retry every few seconds: {hints:?}");
        assert_eq!(service.scheduler.busy(), 0, "nothing started");
        let slot = DurableState::slot_at(&row.schedule, now).unwrap();
        assert!(!service.scheduler.holds("1RecoverA", &DurableState::occurrence_id("sync", &slot)), "the hold is released");
        // Status says why the job is not running.
        let status = service.status(&app, "1RecoverA").await.unwrap();
        assert_eq!(status["jobs"][0]["waiting_reason"], "occurrence_limit", "{status}");
    }

    #[tokio::test]
    async fn a_hold_is_counted_so_a_claim_that_was_not_its_own_never_drops_the_owners_hold() {
        let (service, app) = service();
        let row = granted_job(&service, "1RecoverA");
        // A manual run holds and claims the current slot first.
        let slot = DurableState::slot_at(&row.schedule, T + 10).unwrap();
        let id = DurableState::occurrence_id("sync", &slot);
        service.scheduler.hold("1RecoverA", &id);
        reserve(&service, &row, T + 10);
        // The scheduler then admits the same slot: its claim is not fresh,
        // it releases its own hold and steps past the slot.
        let mut hints = Vec::new();
        admit(&service, &app, row, T + 10, &mut hints).await;
        assert!(service.scheduler.holds("1RecoverA", &id), "the manual run still holds its occurrence");
        assert_eq!(job_row(&service, "1RecoverA").next_due_unix, Some(T + PERIOD));
        assert_eq!(service.scheduler.busy(), 0);
        // Recovery leaves a held reservation to its owner.
        assert!(recover(&service, &app, || Ok(T + 10)).await.is_empty());
        assert!(response(&service, "1RecoverA", &id).is_none(), "the owner's reservation is untouched");
        service.scheduler.release("1RecoverA", &id);
        assert!(!service.scheduler.holds("1RecoverA", &id));
        service.scheduler.release("1RecoverA", &id);
        assert!(!service.scheduler.holds("1RecoverA", &id), "a release past zero stays at zero");
    }

    #[tokio::test]
    async fn a_xite_that_cannot_be_inspected_has_its_jobs_paused_with_the_reason_and_is_looked_at_again_only_on_a_change_or_the_slow_recheck() {
        let (service, app) = service();
        granted_job(&service, "1RecoverA");
        let now = now_unix().unwrap();
        assert_eq!(service.state.due_jobs(now).unwrap().len(), 1);
        let mut task = TaskState::default();
        let mut hints = Vec::new();
        // No such xite on this node: the declaration cannot be read.
        let facts = xite_facts(&service, &app, "1RecoverA", now, false, &mut task, &mut hints).await;
        assert!(facts.is_none());
        assert_eq!(hints, [now + INSPECTION_RECHECK], "no retry every tick");
        let row = job_row(&service, "1RecoverA");
        assert_eq!(row.paused_reason.as_deref(), Some(PauseReason::DeclarationUnavailable.name()));
        assert!(service.state.due_jobs(now).unwrap().is_empty(), "a paused job is not due");
        let status = service.status(&app, "1RecoverA").await.unwrap();
        assert_eq!(status["jobs"][0]["paused_reason"], "declaration_unavailable", "{status}");
        assert_eq!(status["jobs"][0]["waiting_reason"], "paused");
        // The next ticks leave it alone until the slow re-check is due...
        let mut hints = Vec::new();
        reinspect(&service, &app, now + 1, &mut task, &mut hints).await;
        assert_eq!(hints, [now + INSPECTION_RECHECK]);
        assert_eq!(task.rechecked.get("1RecoverA"), Some(&now));
        // ...unless its content changed, which looks at once.
        task.changed.insert("1RecoverA".into());
        let mut hints = Vec::new();
        reinspect(&service, &app, now + 2, &mut task, &mut hints).await;
        assert_eq!(task.rechecked.get("1RecoverA"), Some(&(now + 2)));
        assert_eq!(hints, [now + 2 + INSPECTION_RECHECK]);
        assert!(task.changed.is_empty());
        // A pause a person set is not the scheduler's to touch.
        service.state.set_job_paused("1RecoverA", "sync", Some("user")).unwrap();
        assert!(!service.pause_for_inspection("1RecoverA", PauseReason::ContentIncomplete).unwrap());
        assert_eq!(job_row(&service, "1RecoverA").paused_reason.as_deref(), Some("user"));
        // And with no pause of its own left, the slow re-check forgets it.
        let mut hints = Vec::new();
        reinspect(&service, &app, now + 3, &mut task, &mut hints).await;
        assert!(task.rechecked.is_empty());
        assert!(hints.is_empty());
    }

    fn candidate(xite: &str, job: &str) -> Candidate {
        Candidate { xite: xite.into(), job: job.into(), covers: true, daily_runs: 0, xite_busy: false }
    }

    fn admitted(decisions: &[Decision]) -> Vec<(&str, &str)> {
        decisions
            .iter()
            .filter_map(|decision| match decision {
                Decision::Admit { xite, job } => Some((xite.as_str(), job.as_str())),
                Decision::Wait { .. } => None,
            })
            .collect()
    }

    fn waiting(decisions: &[Decision]) -> Vec<(&str, &str, WaitReason)> {
        decisions
            .iter()
            .filter_map(|decision| match decision {
                Decision::Wait { xite, job, reason } => Some((xite.as_str(), job.as_str(), *reason)),
                Decision::Admit { .. } => None,
            })
            .collect()
    }

    #[test]
    fn two_xites_are_admitted_in_one_tick_and_a_third_waits_for_a_worker() {
        let candidates = [candidate("a", "sync"), candidate("b", "sync"), candidate("c", "sync")];
        let decisions = plan(&candidates, 0, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(admitted(&decisions), [("a", "sync"), ("b", "sync")]);
        assert_eq!(waiting(&decisions), [("c", "sync", WaitReason::WorkersBusy)]);
        // A worker already busy counts against the cap.
        let decisions = plan(&candidates, 1, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(admitted(&decisions), [("a", "sync")]);
        let decisions = plan(&candidates, 2, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert!(admitted(&decisions).is_empty());
        assert_eq!(waiting(&decisions).len(), 3);
    }

    #[test]
    fn round_robin_takes_one_job_per_xite_before_a_second_of_the_same_xite() {
        // `due_jobs` order: a's two jobs are older than b's one.
        let candidates = [candidate("a", "first"), candidate("a", "second"), candidate("b", "only")];
        let decisions = plan(&candidates, 0, 3, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(admitted(&decisions), [("a", "first"), ("b", "only")]);
        // a's second job waits on a's own lock, not on a worker: a xite runs
        // one occurrence at a time whatever the host-wide cap.
        assert_eq!(waiting(&decisions), [("a", "second", WaitReason::XiteBusy)]);
        // Decisions are in round-robin order: a, b, then a again.
        assert!(matches!(&decisions[1], Decision::Admit { xite, .. } if xite == "b"));
    }

    #[test]
    fn a_held_run_lock_and_a_spent_daily_budget_each_wait_with_their_reason() {
        let mut busy = candidate("a", "sync");
        busy.xite_busy = true;
        let mut spent = candidate("b", "sync");
        spent.daily_runs = BACKGROUND_RUNS_PER_DAY;
        let mut last_one = candidate("c", "sync");
        last_one.daily_runs = BACKGROUND_RUNS_PER_DAY - 1;
        let decisions = plan(&[busy, spent, last_one], 0, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(admitted(&decisions), [("c", "sync")]);
        assert_eq!(
            waiting(&decisions),
            [("a", "sync", WaitReason::XiteBusy), ("b", "sync", WaitReason::DailyBudget)]
        );
        // The budget counts what this tick admitted: with one run left and
        // two due jobs of the same xite, the second waits on the budget only
        // if the lock did not stop it first, which it does.
        let mut one_left_a = candidate("d", "first");
        one_left_a.daily_runs = BACKGROUND_RUNS_PER_DAY - 1;
        let mut one_left_b = candidate("d", "second");
        one_left_b.daily_runs = BACKGROUND_RUNS_PER_DAY - 1;
        let decisions = plan(&[one_left_a, one_left_b], 0, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(admitted(&decisions), [("d", "first")]);
        assert_eq!(waiting(&decisions), [("d", "second", WaitReason::DailyBudget)]);
    }

    #[test]
    fn the_checks_run_in_the_specs_order_and_the_first_failure_is_the_reason() {
        let mut uncovered = candidate("a", "sync");
        uncovered.covers = false;
        uncovered.daily_runs = BACKGROUND_RUNS_PER_DAY;
        uncovered.xite_busy = true;
        let decisions = plan(&[uncovered.clone()], BACKGROUND_WORKERS, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(waiting(&decisions), [("a", "sync", WaitReason::DeclarationNotCovered)]);
        uncovered.covers = true;
        let decisions = plan(&[uncovered.clone()], BACKGROUND_WORKERS, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(waiting(&decisions), [("a", "sync", WaitReason::DailyBudget)]);
        uncovered.daily_runs = 0;
        let decisions = plan(&[uncovered.clone()], BACKGROUND_WORKERS, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(waiting(&decisions), [("a", "sync", WaitReason::WorkersBusy)]);
        let decisions = plan(&[uncovered], 0, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY);
        assert_eq!(waiting(&decisions), [("a", "sync", WaitReason::XiteBusy)]);
        assert!(plan(&[], 0, BACKGROUND_WORKERS, BACKGROUND_RUNS_PER_DAY).is_empty());
    }

    #[test]
    fn the_failure_backoff_doubles_from_a_minute_and_stops_at_six_hours() {
        assert_eq!(backoff(1), 60);
        assert_eq!(backoff(2), 120);
        assert_eq!(backoff(3), 240);
        assert_eq!(backoff(9), 15_360);
        assert_eq!(backoff(10), BACKOFF_CEILING);
        assert_eq!(backoff(63), BACKOFF_CEILING);
        assert_eq!(backoff(64), BACKOFF_CEILING, "a shift past the width saturates");
        assert_eq!(backoff(u32::MAX), BACKOFF_CEILING);
    }

    #[test]
    fn jitter_is_a_tenth_of_the_period_within_one_second_and_a_minute() {
        assert_eq!(jitter_bound(1), 1);
        assert_eq!(jitter_bound(9), 1);
        assert_eq!(jitter_bound(50), 5);
        assert_eq!(jitter_bound(600), 60);
        assert_eq!(jitter_bound(86_400), 60);
        for seed in [0, 1, 7, u64::MAX] {
            let wake = jittered(1_000, 50, seed);
            assert!((1_000..=1_005).contains(&wake), "{wake}");
        }
        assert_eq!(jittered(1_000, 50, 0), 1_000, "never before the due time");
        assert_eq!(jittered(1_000, 50, 5), 1_005, "the bound itself is reachable");
        assert_eq!(jittered(u64::MAX, 50, 5), u64::MAX, "saturates");
        let seed = jitter_seed(1_700_000_000);
        assert!(jittered(1_000, 50, seed) <= 1_005);
    }

    #[test]
    fn the_period_of_a_registered_job_comes_from_its_stored_schedule() {
        let row = JobRow {
            xite: "a".into(),
            job: "sync".into(),
            program: "main".into(),
            schedule: json!({ "type": "interval", "seconds": 1800, "anchor": "unix_epoch", "missed": "skip" }),
            max_concurrency: 1,
            declaration_digest: "0".repeat(64),
            enabled: true,
            paused_reason: None,
            next_due_unix: Some(0),
            last_slot: None,
            last_occurrence: None,
            failures: 0,
            updated_unix: 0,
        };
        assert_eq!(period(&row).unwrap(), 1800);
        let mut bad = row;
        bad.schedule = json!({ "type": "cron" });
        assert!(period(&bad).is_err());
    }
}
