# EVX Milestone 3: durable scheduler and background lifecycle

Milestone 2 (`docs/evx-milestone-2.md`) runs a declared program when the
user or the operator says so. Milestone 3 makes a declared job run on its
schedule inside the node, with no xite page open and across node restarts,
without ever running the same logical occurrence twice. It implements the
plan's sections "Local execution and durable schedules", "Background task
lifecycle", "Scheduling, budgets and native work" and "Required idempotency
and recovery" for the desktop node. OS wake on mobile (WorkManager,
BGTaskScheduler), publication, streams and chain operations stay out.

Rules, one line each: a schedule is persisted, not a thread; an occurrence
identity is reserved before a worker starts and completed atomically with
its result; a restart, a reconnecting page and a manual run never create a
second execution of the same occurrence; a missed interval is skipped or
coalesced into one catch-up, never backfilled; grants, budgets and the
plugin switch are rechecked at admission and a revocation stops queued
work; a budget wait, a paused job and an unsupported host are visible
states, never silently dropped runs.

## Lifecycle

```text
wait  -> the scheduler sleeps until the earliest persisted next_due (with jitter) or a wake
wake  -> grant changed, job registered, revoke, plugin toggled, manual run, content update, timer
admit -> recheck plugin enabled, grant enabled + allow_background, declaration digest, daily budget,
         host-wide and per-xite concurrency; reserve the occurrence (evx-state begin) - not fresh => skip
run   -> the Milestone 2 run path (inspect from bytes, bind, read files, verify_content, worker)
commit-> evx-state commit of the occurrence with its result; run record; next_due; backoff on failure
release-> worker gone, broker dropped, nothing resident; back to wait
```

## Components

### 1. `crates/evx-state`: schedule model (additive schema, version 3)

```rust
pub struct JobSpec { pub job: String, pub program: String, pub schedule: evx_declaration::Schedule /* serialised as JSON text */, pub max_concurrency: u32 }
pub struct JobRow { pub xite: String, pub job: String, pub program: String, pub schedule: Value, pub max_concurrency: u32, pub declaration_digest: String,
                    pub enabled: bool, pub paused_reason: Option<String>, pub next_due_unix: Option<u64>, pub last_slot: Option<u64>, pub last_occurrence: Option<String>,
                    pub failures: u32, pub updated_unix: u64 }
pub struct Slot { pub index: u64, pub start_unix: u64, pub end_unix: u64 }

impl DurableState {
    /// Replace a xite's registered jobs from its current verified declaration (keyed by digest). Jobs that vanished are removed; existing rows keep last_slot/failures.
    pub fn set_jobs(&self, xite: &str, declaration_digest: &str, jobs: &[JobSpec], now: u64) -> Result<()>;
    pub fn jobs(&self, xite: &str) -> Result<Vec<JobRow>>;
    pub fn set_job_paused(&self, xite: &str, job: &str, reason: Option<&str>) -> Result<()>;       // None resumes
    /// Every job due at `now`: enabled, not paused, next_due <= now, grant enabled + allow_background + not expired, plugin not required here.
    pub fn due_jobs(&self, now: u64) -> Result<Vec<JobRow>>;
    /// The slot an interval schedule puts `now` in, honouring anchor and period; pure.
    pub fn slot_at(schedule: &Value, now: u64) -> Result<Slot>;
    /// The occurrence id for a job slot: "<job>@<slot index>" (identifier-safe).
    pub fn occurrence_id(job: &str, slot: &Slot) -> String;
    /// Reserve the occurrence and record it on the job row in one transaction: begin(xite, occurrence, request = {"job","slot","program","declaration_digest"}, cost 1),
    /// and if fresh set last_slot/last_occurrence. A slot <= last_slot (clock rollback, duplicate wake) is Error::Conflict. Returns the Invocation.
    pub fn claim_occurrence(&self, xite: &str, job: &JobRow, slot: &Slot, request: &Value) -> Result<Invocation>;
    /// After a run: commit the occurrence (DurableState::commit with the result as the response), bump or reset failures, set next_due (caller computed) in one transaction.
    pub fn finish_occurrence(&self, invocation: &Invocation, result: &Value, next_due_unix: Option<u64>, failed: bool) -> Result<()>;
    /// Incomplete occurrences (reserved, never committed) for recovery after a restart.
    pub fn incomplete_occurrences(&self, xite: Option<&str>) -> Result<Vec<InvocationRow>>;
    /// Daily background budget: runs started in the current UTC day for the xite; `reserve_daily_run` fails with BudgetExceeded past `limit`. Never reset by restart.
    pub fn daily_runs(&self, xite: &str, now: u64) -> Result<u32>;
    pub fn reserve_daily_run(&self, xite: &str, now: u64, limit: u32) -> Result<()>;
}
```

Slot rules (`Schedule::Interval { seconds, anchor: UnixEpoch, missed }`):
`index = now / seconds`, `start = index * seconds`, `end = start + seconds`.
`next_due` after a completed slot `k` is `(k + 1) * seconds` for both
policies; the difference is at admission: with `Skip`, a wake at a slot `>
last_slot + 1` runs only the current slot; with `Coalesce`, the same wake
runs the current slot once (one catch-up, never one per missed slot). A
`now` earlier than `last_slot`'s end is a clock rollback: nothing is
claimed and the job reports `clock_rollback` until time passes the slot.

### 2. `crates/epix-evx`: the scheduler

- `Scheduler` owned by `EvxService`, started in `Plugin::start` as one tokio
  task. It holds a `tokio::sync::Notify` for wakes and sleeps until the
  earliest `next_due` across jobs plus a jitter of up to 10% of the period
  (bounded 1..=60 s), or a wake.
- Wake sources: `evxGrant`, `evxRevoke`, `evxSetLimits`, `evxJobPause`,
  `evxJobResume`, `evxRunJob`, the plugin being enabled, and a xite's content
  change (subscribe to `AppState::subscribe_events` and wake on any event
  for a xite that has jobs; coalesce within 2 s).
- Registration: whenever a xite's inspection is produced for a xite with an
  enabled grant (`allow_background`), `set_jobs` is called with the usable
  jobs of the current declaration. A job whose program became unsupported
  is paused with the reason; a declaration digest change re-registers under
  the new digest (grant covers it only if `covers_declaration`, else the
  jobs are paused with `declaration_outgrew_grant`).
- Admission (per tick, fair across xites in round-robin order of oldest
  `next_due`): plugin enabled; grant enabled, unexpired, `allow_background`;
  `covers_declaration`; `daily_runs < HOST_CEILING.background_runs_per_day`
  (new ceiling constant, 288); host-wide running workers `<
  HOST_CEILING.background_workers` (2); the xite's run lock free. Then
  `claim_occurrence`; a non-fresh or completed invocation is skipped and the
  job's `next_due` moves on.
- Run: the Milestone 2 path refactored so `run_once` and the scheduler share
  `execute(xite, program, authority, occurrence: Option<Invocation>)`.
  `Authority::Scheduled` carries the generation like `Grant`. Revocation,
  plugin disable and the queued-run recheck behave exactly as for run once.
- Commit: `finish_occurrence` with the `RunResult` as the response; the
  `RunRecord` gains `occurrence: Option<String>` and `trigger: "once" |
  "job" | "manual_job"`. On failure (`error`, `denied`, `timeout`,
  `resource_limit`, `effect_unknown`) `failures += 1` and `next_due = max(next
  slot, now + min(2^failures * 30 s, 6 h))`; `effect_unknown` also pauses the
  job with `reconcile_required` (a user resumes it from status). Success
  resets failures.
- Recovery at start: `incomplete_occurrences` are examined once: an
  occurrence whose slot is still current is run again under the same
  identity (`DurableState::recover` rotates the fencing token); an older one
  is finished as `{"status":"abandoned"}` so the schedule moves on and the
  record says so. Reservations are never silently dropped.
- Manual job run: `evxRunJob {xite, job}` (wrapper/operator only) claims the
  job's *current* slot occurrence, so a manual run and the scheduled run of
  that slot cannot both execute; a second request returns the stored result.
  `evxRunOnce {program}` keeps its own identity `once-<16 hex>` and does not
  touch the job's slot.
- Pause reasons owned by registration: `declaration_outgrew_grant`,
  `declaration_unavailable`, `content_incomplete`; cleared by the next
  verified inspection. A xite that fails inspection is rechecked on a content
  change or every 300 s, never every tick. Completed occurrences are trimmed
  to the newest 64 per job; a claim refused by that bound waits for the next
  slot with `waiting_reason: occurrence_limit`. A reservation fenced by a
  revocation is closed with `DurableState::abandon`.
- Status: `evxStatus` gains `jobs: [{job, program, schedule, enabled,
  paused_reason, next_due_unix, last_slot, last_occurrence, failures,
  runs_today, daily_limit}]` and `scheduler: {enabled, busy_workers,
  next_wake_unix, host: "macos"|"unsupported"}`; `evxInspect` lists the
  declared jobs as before. Run records expose `occurrence` and `trigger`.
- Commands (wrapper/operator only, gated like the other EVX mutators in
  `EVX_WRAPPER_COMMANDS`): `evxJobPause {xite, job}`, `evxJobResume {xite,
  job}`, `evxRunJob {xite, job}`. The page may read status only.
- Plugin disable (`set_plugin_enabled("Evx", false)`): the scheduler stops
  admitting at its next check (every tick starts with it), revokes the
  brokers of running work, and the next enable wakes it.

### 3. Wrapper (`ui/media/all.js`) and grant semantics

- `evxGrant mode "enable"` sets `allow_background = true` when the
  declaration has at least one usable job. The wrapper sends `shown`
  (programs, jobs, `allow_run_once`, `allow_background`) from the payload it
  drew the dialog from, and the node refuses the grant when the current
  inspection disagrees ("declaration changed since it was shown"). the consent dialog then says,
  in its own paragraph: "This xite also declares N scheduled job(s): <job>
  runs <program> every <period>. Enabling lets them run in the background on
  this node, even when no page of this xite is open." A declaration with no
  jobs grants no background authority (unchanged).
- Nothing else in the dialog changes. `ui/tests/wrapper-evx.test.cjs` gains
  the background paragraph test and a no-jobs test.

### 4. Tests (acceptance)

- Slots: anchor and period math, `Skip` runs only the current slot after a
  gap, `Coalesce` runs exactly one catch-up, a clock rollback claims nothing
  and reports it, a slot never repeats across a reopen of the database.
- Idempotency: the same occurrence claimed twice yields one run; a manual
  job run and a scheduled run of the same slot execute once; a page
  reconnect or restart does not create a second execution; a completed
  occurrence survives a reopen as completed.
- Recovery: an incomplete occurrence of the current slot is retried once
  under the same identity; an older incomplete one is finished as
  abandoned; the daily budget is not reset by a reopen.
- Authority: no grant, grant without `allow_background`, expired grant,
  revoked grant, paused job, disabled plugin, and a declaration that
  outgrew its grant each admit nothing and show the reason in status; the
  next tick after re-enable resumes on the right slot.
- Budgets and fairness: two xites with due jobs both run within one tick
  (host-wide cap 2); a third waits with a visible reason; the per-xite lock
  holds; a xite past its daily limit waits with `daily_budget`.
- Failures: a failing program backs off exponentially with the persisted
  `next_due`; `effect_unknown` pauses with `reconcile_required`; success
  resets failures.
- macOS, through the real worker: a 1-second interval job declared in a
  signed fixture xite runs at least twice with no page open and no manual
  command, each run recorded with its occurrence id and `trigger: "job"`,
  and stops within one period after `evxRevoke`.
- Wrapper: dialog text with and without jobs; `evxRunJob`/`evxJobPause`
  from a page id refused through the dispatcher gate.

## Non-goals

Mobile OS wake, event-driven triggers from shared data, publication of
results, retained streams, chain operations, the resource dashboard beyond
the status payload, and a graceful node-shutdown hook (the design is
crash-safe instead).
