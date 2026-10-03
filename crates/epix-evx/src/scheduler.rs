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
//! line without a database or a worker, and the tick is the only clock
//! read per pass: every decision of a pass is made at one `now`.
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
//! reservation left open by an earlier process is run again under the same
//! identity when its slot is still the current one (`DurableState::recover`
//! rotates its fencing token so the dead worker could not commit even if it
//! were alive), and finished as `abandoned` when the slot has passed, so
//! the schedule moves on and the history says what happened. A reservation
//! this process holds (a manual run that claimed its slot before the task
//! got to run) is not an earlier process's and is left to its owner, which
//! is why every claim is registered with [`Scheduler::hold`] in the same
//! breath. A reservation is never dropped silently; one the state refuses
//! to touch (a grant fenced since, which also fences the commit of a run
//! revoked in flight) is logged and left for the next start.

use std::collections::{HashMap, HashSet};
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    now_unix, occurrence_request, status_name, EvxService, Integrity, Occurrence, Run, Trigger,
    WaitReason,
};
use crate::PLUGIN_NAME;

/// How often the task re-reads the plugin switch while the plugin is
/// disabled. `AppState::set_plugin_enabled` has no hook a plugin can
/// subscribe to, so the "plugin enabled" wake of the spec is a poll at this
/// interval: two seconds is prompt for a person flipping a switch and costs
/// one config read.
pub const DISABLED_POLL: u64 = 2;

/// A content change for a xite with jobs wakes the scheduler this long
/// after the first event, so a burst of events (a download of many files,
/// a re-sign followed by a sync) causes one tick, not one per event.
pub const CONTENT_WAKE_COALESCE: Duration = Duration::from_secs(2);

/// How long the task waits before looking again at a job it could not act
/// on for a reason no wake will clear by itself: a xite whose run lock is
/// held by a run-once, an inspection that failed, a claim the state
/// refused. A bound on retries, never a cadence.
pub const RETRY_INTERVAL: u64 = 2;

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
pub const ABANDONED: &str = "abandoned";

/// The wake handle and the counters the task shares with the service.
#[derive(Default)]
pub struct Scheduler {
    notify: Notify,
    /// Background occurrences admitted and not yet finished.
    busy: AtomicUsize,
    /// When the task means to wake next, for status; `None` while it waits
    /// for a wake only.
    next_wake: Mutex<Option<u64>>,
    /// Occurrences reserved by this process and not yet finished, as
    /// `<xite>/<occurrence>`: what recovery must not mistake for a crash's
    /// leftovers.
    held: Mutex<HashSet<String>>,
    /// Whether recovery has run; it runs once, at the first enabled tick.
    recovered: AtomicBool,
    stopped: AtomicBool,
}

impl Scheduler {
    /// Note that this process reserved `occurrence` of `xite`; released by
    /// [`EvxService::execute`] once the reservation is finished.
    pub(crate) fn hold(&self, xite: &str, occurrence: &str) {
        if let Ok(mut held) = self.held.lock() {
            held.insert(format!("{xite}/{occurrence}"));
        }
    }

    pub(crate) fn release(&self, xite: &str, occurrence: &str) {
        if let Ok(mut held) = self.held.lock() {
            held.remove(&format!("{xite}/{occurrence}"));
        }
    }

    fn holds(&self, xite: &str, occurrence: &str) -> bool {
        self.held
            .lock()
            .is_ok_and(|held| held.contains(&format!("{xite}/{occurrence}")))
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

/// The scheduler task: the wait/wake loop until [`Scheduler::stop`], with
/// recovery folded into the first tick that finds the plugin enabled.
pub(crate) async fn run(service: Arc<EvxService>, app: Arc<AppState>) {
    let scheduler = &service.scheduler;
    let mut events = app.subscribe_events();
    let mut events_open = true;
    let mut job_xites: Vec<String> = Vec::new();
    let mut coalesce: Option<Instant> = None;
    let mut tick_due = true;
    loop {
        if scheduler.stopped() {
            scheduler.set_next_wake(None);
            break;
        }
        if tick_due {
            tick_due = false;
            let wake = match now_unix() {
                Ok(now) => tick(&service, &app, now).await,
                Err(error) => {
                    app.log("ERROR", format!("EVX scheduler: {error}")).await;
                    None
                }
            };
            scheduler.set_next_wake(wake);
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
            _ = scheduler.notify.notified() => {
                tick_due = true;
            }
            _ = sleep_until(deadline) => {
                coalesce = None;
                tick_due = true;
            }
            event = events.recv(), if events_open => {
                let relevant = match event {
                    Ok(event) => event.target.as_deref().is_some_and(|target| job_xites.iter().any(|xite| xite == target)),
                    // Events were dropped: one of them may have been a
                    // xite with jobs, so wake as if it was.
                    Err(RecvError::Lagged(_)) => !job_xites.is_empty(),
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

/// One pass: admit what is due at `now` and say when to wake next
/// (`None`: only a wake will do). Every pass starts with the plugin switch,
/// so disabling the plugin stops admission at the next pass and revokes the
/// brokers of running work; a host that cannot execute admits nothing and
/// says so in status.
async fn tick(service: &Arc<EvxService>, app: &Arc<AppState>, now: u64) -> Option<u64> {
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
        recover(service, app, now).await;
    }
    if service.execution().is_err() {
        return None;
    }
    let due = match service.state.due_jobs(now) {
        Ok(due) => due,
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: due jobs: {error}")).await;
            return Some(now + RETRY_INTERVAL);
        }
    };
    let mut hints: Vec<u64> = Vec::new();
    let mut order: Vec<String> = Vec::new();
    let mut facts: HashMap<String, XiteFacts> = HashMap::new();
    for row in &due {
        if facts.contains_key(&row.xite) {
            continue;
        }
        // The inspection re-registers the jobs from what is on disk now and
        // pauses what the grant no longer covers, so the rows are re-read
        // after it and a job it paused is not a candidate.
        let inspection = match service.inspect(app, &row.xite).await {
            Ok(inspection) => inspection,
            Err(error) => {
                app.log("WARN", format!("EVX scheduler: {} not inspected: {error}", row.xite)).await;
                hints.push(now + RETRY_INTERVAL);
                continue;
            }
        };
        if inspection.integrity != Integrity::Verified {
            app.log("WARN", format!("EVX scheduler: {} is {}, jobs wait", row.xite, inspection.integrity.name())).await;
            hints.push(now + RETRY_INTERVAL);
            continue;
        }
        let (daily_runs, rows) = match (service.state.daily_runs(&row.xite, now), service.state.jobs(&row.xite)) {
            (Ok(daily_runs), Ok(rows)) => (daily_runs, rows),
            (Err(error), _) | (_, Err(error)) => {
                app.log("ERROR", format!("EVX scheduler: {}: {error}", row.xite)).await;
                hints.push(now + RETRY_INTERVAL);
                continue;
            }
        };
        order.push(row.xite.clone());
        facts.insert(
            row.xite.clone(),
            XiteFacts {
                covers: inspection.covers_declaration(now),
                daily_runs,
                busy: !service.run_lock_free(&row.xite).await,
                rows,
            },
        );
    }
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut rows: HashMap<(String, String), JobRow> = HashMap::new();
    for due_row in &due {
        let Some(xite) = facts.get(&due_row.xite) else { continue };
        let Some(row) = xite.rows.iter().find(|row| row.job == due_row.job) else { continue };
        if !row.enabled || row.paused_reason.is_some() || !row.next_due_unix.is_some_and(|at| at <= now) {
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
    match service.state.next_due_job(now) {
        Ok(Some(row)) => {
            if let (Some(due), Ok(period)) = (row.next_due_unix, period(&row)) {
                hints.push(jittered(due, period, jitter_seed(now)));
            }
        }
        Ok(None) => {}
        Err(error) => {
            app.log("ERROR", format!("EVX scheduler: next due: {error}")).await;
            hints.push(now + RETRY_INTERVAL);
        }
    }
    hints.into_iter().min()
}

/// Reserve the current slot of `row` and run it on its own task, so two
/// xites admitted in one tick run at once. A slot already claimed (by a
/// manual run) is stepped past; a clock before the last claimed slot
/// claims nothing and the job sleeps until that slot has passed.
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
    let invocation = match service
        .state
        .claim_occurrence(&xite, &row, &slot, &occurrence_request(&row, &slot), now)
    {
        Ok(invocation) => invocation,
        Err(error) => {
            app.log("WARN", format!("EVX scheduler: job {job} of {xite} not claimed: {error}")).await;
            hints.push(now + RETRY_INTERVAL);
            return;
        }
    };
    if !invocation.fresh {
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
        hints.push((now / SECONDS_PER_DAY + 1) * SECONDS_PER_DAY);
        return;
    }
    service.scheduler.hold(&xite, &invocation.occurrence);
    let program = row.program.clone();
    let occurrence = Box::new(Occurrence { invocation, row, slot });
    service.scheduler.busy.fetch_add(1, Ordering::SeqCst);
    let service = Arc::clone(service);
    let app = Arc::clone(app);
    tokio::spawn(async move {
        let result = service
            .execute(&app, &xite, &program, Run::Job { occurrence, trigger: Trigger::Job })
            .await;
        if let Err(error) = result {
            app.log("WARN", format!("EVX scheduler: job {job} of {xite} refused: {error}")).await;
        }
        service.scheduler.busy.fetch_sub(1, Ordering::SeqCst);
        service.scheduler.wake();
    });
}

/// Examine every reservation left open by an earlier process, once.
async fn recover(service: &Arc<EvxService>, app: &Arc<AppState>, now: u64) {
    let incomplete = match service.state.incomplete_occurrences(None) {
        Ok(incomplete) => incomplete,
        Err(error) => {
            app.log("ERROR", format!("EVX recovery: {error}")).await;
            return;
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
        let current = row
            .as_ref()
            .and_then(|row| DurableState::slot_at(&row.schedule, now).ok())
            .filter(|slot| slot.index == index);
        match (row, current) {
            (Some(row), Some(slot)) => match service.state.recover(&invocation) {
                Ok(fresh) => {
                    app.log("INFO", format!("EVX recovery: running {} of {} again under the same identity", open.occurrence, open.xite)).await;
                    service.scheduler.hold(&open.xite, &open.occurrence);
                    let program = row.program.clone();
                    let occurrence = Box::new(Occurrence { invocation: fresh, row, slot });
                    service.scheduler.busy.fetch_add(1, Ordering::SeqCst);
                    let result = service
                        .execute(app, &open.xite, &program, Run::Job { occurrence, trigger: Trigger::Job })
                        .await;
                    service.scheduler.busy.fetch_sub(1, Ordering::SeqCst);
                    if let Err(error) = result {
                        app.log("WARN", format!("EVX recovery: {} of {} refused: {error}", open.occurrence, open.xite)).await;
                    }
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
                let summary = json!({
                    "status": ABANDONED,
                    "value": null,
                    "error": "reservation from before a restart; its slot has passed",
                    "elapsed_ms": 0,
                    "occurrence": open.occurrence,
                });
                match service.state.finish_occurrence(&invocation, &summary, next_due, false) {
                    Ok(()) => {
                        app.log("WARN", format!("EVX recovery: {} of {} abandoned; its slot has passed", open.occurrence, open.xite)).await;
                        if let Some(row) = &row {
                            record_abandoned(service, app, row, &open.occurrence, now).await;
                        }
                    }
                    Err(error) => {
                        app.log("ERROR", format!("EVX recovery: {} of {} not finished: {error}", open.occurrence, open.xite)).await;
                    }
                }
            }
        }
    }
}

/// Put an abandoned occurrence in the run history, so status shows what
/// became of it next to the runs that happened. Nothing ran, so the
/// artifact is the digest of nothing and the input the canonical `null`.
async fn record_abandoned(service: &Arc<EvxService>, app: &Arc<AppState>, row: &JobRow, occurrence: &str, now: u64) {
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
        status: ABANDONED.to_string(),
        message: Some("reservation from before a restart; its slot has passed".to_string()),
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
