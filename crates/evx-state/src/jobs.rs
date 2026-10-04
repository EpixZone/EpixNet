//! Persisted job schedules, slot bookkeeping and the daily background budget
//! (Milestone 3, `docs/evx-milestone-3.md` section 1).
//!
//! A schedule is a row, not a thread. [`DurableState::set_jobs`] records a
//! xite's declared jobs under the declaration digest the host verified;
//! [`DurableState::due_jobs`] is the only question the scheduler asks on a
//! wake, and it joins the xite grant so a revoked, expired or
//! background-less grant makes nothing due without any in-memory state.
//!
//! An occurrence is a job plus a slot. The slot is pure arithmetic on the
//! schedule ([`DurableState::slot_at`]): for an interval of `seconds`
//! anchored at the Unix epoch, slot `index` is `now / seconds`, so every
//! node, restart and wake computes the same identity for the same moment and
//! the occurrence id ([`DurableState::occurrence_id`]) is the same string
//! everywhere. [`DurableState::claim_occurrence`] reserves that id with the
//! Milestone 1 `begin` and records the slot on the job row in the same
//! transaction, which is what makes "never run the same occurrence twice"
//! durable: a second claim of the same slot finds the reservation and is
//! not fresh, and a claim of an earlier slot than the one recorded is a
//! clock rollback and changes nothing. Missed slots are never backfilled:
//! after a gap only the current slot is claimable, whichever `missed`
//! policy the schedule names (the two policies differ only in what the
//! scheduler computes as the next due time, which is the caller's input to
//! [`DurableState::finish_occurrence`]).
//!
//! The daily budget counts background runs per xite per UTC day. It lives in
//! its own table rather than in memory so a restart cannot reset it; a new
//! UTC day starts a new count by key, not by deletion, so a reopen on the
//! same day keeps yesterday's number out of today's.
//!
//! No scheduling decision here reads the clock: every operation takes
//! `now` from the host, so the scheduler's tests run on a fixed time line
//! and the host's single clock read per tick is the only one in the
//! system. That includes the grant expiry a claim checks:
//! [`DurableState::claim_occurrence`] checks it at the `now` it is given,
//! so what [`DurableState::due_jobs`] called due at that moment is
//! claimable at that moment, never a wall-clock second later. The one
//! clock read left is inside [`DurableState::finish_occurrence`], whose
//! commit is the Milestone 1 `commit` and checks the grant the way every
//! commit does; it decides nothing about the schedule.

use evx_declaration::{Anchor, Schedule};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::{identifier, sha256_hex};
use crate::xite::MAX_MESSAGE;
use crate::xite::{load_xite_grant, text, timestamp};
use crate::{
    begin_in_at, canonical, commit_in, count, digest, invocation_row, load_invocation,
    prepare_commit, transaction, DurableState, Error, Invocation, InvocationRow, InvocationStatus,
    Result, INVOCATION_COLUMNS, MAX_LIMIT,
};

/// Seconds in one UTC day; the daily budget's window.
pub const SECONDS_PER_DAY: u64 = 86_400;
/// How many UTC days of a xite's daily run counts are kept behind the day
/// being reserved. A count is dropped only once it is older than this, so
/// a clock that rolls back into a recent day finds that day's spent budget
/// rather than a fresh one; a rollback further than a week is a clock
/// nobody should trust and is not defended against here.
pub const DAILY_RUN_RETENTION_DAYS: u64 = 7;
/// Most jobs one `set_jobs` call may register for a xite.
pub const MAX_JOBS: usize = 64;
/// Largest `max_concurrency` a job may declare (the declaration's `1..=16`).
pub const MAX_JOB_CONCURRENCY: u32 = 16;
/// The character between the job id and the slot index in an occurrence id.
///
/// `.` rather than the spec's `@`: an occurrence id is stored through
/// `begin`, which only accepts [`evx_api::validate_identifier`] characters
/// (alphanumerics, `_`, `.`, `-`), and `.` can never collide with the
/// run-once identity `once-<16 hex>`, which a `-` could for a job named
/// `once`. The index is always the text after the last separator, so a job
/// id that itself contains `.` stays recoverable.
pub const OCCURRENCE_SEPARATOR: char = '.';
/// Longest identifier `begin` accepts, as [`evx_api::validate_identifier`]
/// defines it; pinned by a test so a change there cannot silently make
/// registered jobs unclaimable.
const MAX_IDENTIFIER: usize = 128;
/// Digits in the largest slot index: `now` is at most [`MAX_SAFE_INTEGER`]
/// (16 digits) and `index = now / seconds` can be no larger.
const MAX_INDEX_DIGITS: usize = 16;
/// Completed occurrence rows each job keeps, newest first by insertion.
///
/// Every occurrence is an `invocations` row and the reservation refuses a
/// new one once a xite holds [`crate::MAX_ROWS`] of them, so without a
/// bound a job running every five minutes would stop being claimable
/// after about two weeks. The newest rows are the ones idempotency needs:
/// the slot a manual run and the scheduler might both claim is the
/// current one, and older slots are already behind the job row's
/// `last_slot`. A claim trims the job's completed rows to one fewer than
/// this before it reserves, so a job never holds more than this many rows
/// in all and [`MAX_JOBS`] jobs together stay under the row limit; a
/// finish trims them to this.
pub const RETAINED_OCCURRENCES_PER_JOB: usize = 64;
/// The status word of an occurrence the host closed without a result
/// ([`DurableState::abandon`]), and of the scheduler's own abandonment of
/// a reservation whose slot passed.
pub const ABANDONED: &str = "abandoned";
/// Longest job id `set_jobs` accepts: a job id plus the separator and the
/// widest slot index must still be an identifier, or the job could be
/// registered but never claimed.
pub const MAX_JOB_ID: usize = MAX_IDENTIFIER - 1 - MAX_INDEX_DIGITS;

/// Additive Milestone 3 tables. Every statement is `IF NOT EXISTS` so a
/// version 1 or 2 database migrates by simply being opened.
pub(crate) const SCHEMA_V3: &str = "
CREATE TABLE IF NOT EXISTS jobs (
 xite TEXT NOT NULL, job TEXT NOT NULL, program TEXT NOT NULL, schedule TEXT NOT NULL,
 max_concurrency INTEGER NOT NULL, declaration_digest TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, paused_reason TEXT, next_due_unix INTEGER,
 last_slot INTEGER, last_occurrence TEXT, failures INTEGER NOT NULL DEFAULT 0,
 updated_unix INTEGER NOT NULL, PRIMARY KEY (xite, job));
CREATE INDEX IF NOT EXISTS jobs_by_due ON jobs (next_due_unix);
CREATE TABLE IF NOT EXISTS daily_runs (
 xite TEXT NOT NULL, day INTEGER NOT NULL, runs INTEGER NOT NULL,
 PRIMARY KEY (xite, day));
";

/// Replay guards survive removal of a declared job and pruning of its results.
/// Each cadence keeps its own floor so changing an interval does not erase
/// the guard for the old cadence or prevent the new cadence from starting.
pub(crate) const SCHEMA_V5: &str = "
CREATE TABLE IF NOT EXISTS job_guards (
 xite TEXT NOT NULL, job TEXT NOT NULL, period INTEGER NOT NULL,
 latest_start_unix INTEGER NOT NULL, PRIMARY KEY (xite, job, period));
";

pub(crate) const SCHEMA_V7: &str = "
CREATE TABLE IF NOT EXISTS job_reconciliation (
 xite TEXT NOT NULL, job TEXT NOT NULL, PRIMARY KEY (xite, job));
";

pub(crate) const SCHEMA_V8: &str = "
CREATE TABLE IF NOT EXISTS job_controls (
 xite TEXT NOT NULL, job TEXT NOT NULL, enabled INTEGER NOT NULL,
 paused_reason TEXT, PRIMARY KEY (xite, job));
";

pub(crate) const SCHEMA_V9: &str = "
CREATE TABLE IF NOT EXISTS job_management_revisions (
 xite TEXT PRIMARY KEY, revision INTEGER NOT NULL);
";

fn management_revision(conn: &Connection, xite: &str) -> Result<u64> {
    let revision = conn.query_row(
        "SELECT revision FROM job_management_revisions WHERE xite=?1",
        params![xite], |row| row.get::<_, u64>(0),
    ).optional()?.unwrap_or(0);
    if revision > MAX_LIMIT {
        return Err(Error::conflict("invalid job management revision"));
    }
    Ok(revision)
}

fn advance_management_revision(conn: &Connection, xite: &str) -> Result<()> {
    let current = management_revision(conn, xite)?;
    if current >= MAX_LIMIT {
        return Err(Error::budget("job management revision limit"));
    }
    conn.execute(
        "INSERT INTO job_management_revisions VALUES (?1,?2) ON CONFLICT(xite) \
         DO UPDATE SET revision=excluded.revision",
        params![xite, current + 1],
    )?;
    Ok(())
}

fn save_job_controls(conn: &Connection, xite: &str, job: &str) -> Result<()> {
    let row = load_job(conn, xite, job)?.ok_or_else(|| Error::conflict("unknown job"))?;
    if row.enabled && row.paused_reason.is_none() {
        conn.execute(
            "DELETE FROM job_controls WHERE xite=?1 AND job=?2",
            params![xite, job],
        )?;
        return Ok(());
    }
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM job_controls WHERE xite=?1 AND job=?2)",
        params![xite, job],
        |row| row.get(0),
    )?;
    if !exists
        && count(
            conn,
            "SELECT COUNT(*) FROM job_controls WHERE xite=?1",
            params![xite],
        )? >= crate::MAX_ROWS
    {
        return Err(Error::budget("retained job control limit"));
    }
    conn.execute(
        "INSERT INTO job_controls VALUES (?1,?2,?3,?4) ON CONFLICT(xite,job) \
         DO UPDATE SET enabled=excluded.enabled, paused_reason=excluded.paused_reason",
        params![xite, job, row.enabled, row.paused_reason],
    )?;
    Ok(())
}

pub(crate) fn seed_job_controls(conn: &Connection) -> Result<()> {
    let mut statement =
        conn.prepare("SELECT xite,job FROM jobs WHERE enabled=0 OR paused_reason IS NOT NULL")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (xite, job) in rows {
        save_job_controls(conn, &xite, &job)?;
    }
    Ok(())
}

fn requires_reconciliation(conn: &Connection, xite: &str, job: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM job_reconciliation WHERE xite=?1 AND job=?2)",
        params![xite, job],
        |row| row.get(0),
    )?)
}

fn record_reconciliation(conn: &Connection, xite: &str, job: &str) -> Result<()> {
    if !requires_reconciliation(conn, xite, job)? {
        if count(
            conn,
            "SELECT COUNT(*) FROM job_reconciliation WHERE xite=?1",
            params![xite],
        )? >= crate::MAX_ROWS
        {
            return Err(Error::budget("retained reconciliation limit"));
        }
        conn.execute(
            "INSERT INTO job_reconciliation VALUES (?1,?2)",
            params![xite, job],
        )?;
    }
    conn.execute(
        "UPDATE jobs SET paused_reason='reconcile_required' WHERE xite=?1 AND job=?2",
        params![xite, job],
    )?;
    Ok(())
}

/// Host summaries carry the effect flag independently of status because a
/// quarantine can take precedence over the effect-unknown display status.
fn result_requires_reconciliation(result: &Value) -> bool {
    matches!(
        result.get("status").and_then(Value::as_str),
        Some("effect_unknown" | "quarantined")
    ) || result
        .get("effect_outcome_unknown")
        .and_then(Value::as_bool)
        == Some(true)
}

pub(crate) fn seed_reconciliation(conn: &Connection) -> Result<()> {
    let mut statement =
        conn.prepare("SELECT xite,job FROM jobs WHERE paused_reason='reconcile_required'")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (xite, job) in rows {
        record_reconciliation(conn, &xite, &job)?;
    }
    let mut statement =
        conn.prepare("SELECT xite,occurrence,response FROM invocations WHERE status='completed'")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (xite, occurrence, response) in rows {
        let Some(response) = crate::parse_json(response)? else {
            continue;
        };
        if result_requires_reconciliation(&response) {
            if let Ok((job, _)) = occurrence_parts(&occurrence) {
                record_reconciliation(conn, &xite, job)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn seed_job_guards(conn: &Connection) -> Result<()> {
    let mut statement = conn.prepare("SELECT DISTINCT xite FROM jobs")?;
    let xites = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for xite in xites {
        for job in load_jobs(conn, &xite)? {
            if let Some(index) = job.last_slot {
                let seconds = period(&parse_schedule(&job.schedule)?)?;
                let start = index
                    .checked_mul(seconds)
                    .ok_or_else(|| Error::conflict("stored job slot overflows"))?;
                timestamp(start, "stored slot start")?;
                conn.execute(
                    "INSERT INTO job_guards VALUES (?1,?2,?3,?4) ON CONFLICT(xite,job,period) \
                     DO UPDATE SET latest_start_unix=MAX(latest_start_unix,excluded.latest_start_unix)",
                    params![xite, job.job, seconds, start],
                )?;
            }
        }
    }
    Ok(())
}

const JOB_COLUMNS: &str = "xite, job, program, schedule, max_concurrency, declaration_digest, \
                           enabled, paused_reason, next_due_unix, last_slot, last_occurrence, \
                           failures, updated_unix";
/// [`JOB_COLUMNS`] qualified for the grant join in `due_jobs`.
const JOINED_JOB_COLUMNS: &str = "j.xite, j.job, j.program, j.schedule, j.max_concurrency, \
                                  j.declaration_digest, j.enabled, j.paused_reason, \
                                  j.next_due_unix, j.last_slot, j.last_occurrence, j.failures, \
                                  j.updated_unix";

/// One job as the host registers it from a verified declaration.
///
/// The schedule is the declaration's typed form; it is stored as its JSON
/// text and read back as a [`Value`] on [`JobRow`] so a status payload can
/// show it verbatim and so a later schedule kind needs no column change.
/// Decoding refuses unknown fields like every other wire type here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSpec {
    /// Job identifier from the declaration (at most [`MAX_JOB_ID`] bytes).
    pub job: String,
    /// Program identifier the job runs.
    pub program: String,
    /// When the job runs.
    pub schedule: Schedule,
    /// Most occurrences the publisher wants running at once, `1..=16`.
    pub max_concurrency: u32,
}

/// A registered job with its durable scheduling state.
///
/// `enabled` is the host's switch ([`DurableState::set_job_enabled`]) and
/// `paused_reason` the scheduler's or the user's; both must be clear for the
/// job to be due, and the reason is kept so status can say why a job is not
/// running instead of silently dropping it. `last_slot` and
/// `last_occurrence` are the idempotency record: no slot at or before
/// `last_slot` can be claimed again as fresh. `failures` is the consecutive
/// failure count the scheduler backs off on; `next_due_unix` is the
/// scheduler's own computation, stored so a restart sleeps until the right
/// moment. `updated_unix` is the time of the `set_jobs` that last wrote the
/// registration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRow {
    /// Xite namespace.
    pub xite: String,
    /// Job identifier.
    pub job: String,
    /// Program identifier.
    pub program: String,
    /// The schedule as registered, in its JSON form.
    pub schedule: Value,
    /// Most occurrences the publisher wants running at once.
    pub max_concurrency: u32,
    /// Digest of the declaration the job was registered from.
    pub declaration_digest: String,
    /// Host switch; a disabled job is never due.
    pub enabled: bool,
    /// Why the job is paused, or `None` when it is not.
    pub paused_reason: Option<String>,
    /// Unix seconds the job is next due at, or `None` when it never is.
    pub next_due_unix: Option<u64>,
    /// Index of the last slot claimed, or `None` before the first claim.
    pub last_slot: Option<u64>,
    /// Occurrence id of the last slot claimed.
    pub last_occurrence: Option<String>,
    /// Consecutive failed occurrences; reset by a success.
    pub failures: u32,
    /// Unix seconds of the registration that last wrote this row.
    pub updated_unix: u64,
}

/// The slot an interval schedule puts a moment in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    /// Slot number since the anchor: `start_unix / seconds`.
    pub index: u64,
    /// First second of the slot (inclusive).
    pub start_unix: u64,
    /// First second after the slot (exclusive).
    pub end_unix: u64,
}

/// The period of a schedule, after checking it is one this host can slot.
/// The declaration parser already requires `seconds >= 1`, but a schedule
/// reaches this crate as a value that may have been stored by an older
/// build or handed over by a caller, so the bound is checked again here
/// rather than trusted; a zero period would divide by zero.
fn period(schedule: &Schedule) -> Result<u64> {
    match schedule {
        Schedule::Interval {
            seconds,
            anchor: Anchor::UnixEpoch,
            missed: _,
        } => {
            if *seconds == 0 || *seconds > MAX_LIMIT {
                return Err(Error::invalid("invalid schedule period"));
            }
            Ok(*seconds)
        }
    }
}

/// Strict decode of a stored or supplied schedule value.
fn parse_schedule(value: &Value) -> Result<Schedule> {
    serde_json::from_value(value.clone()).map_err(|_| Error::invalid("invalid schedule"))
}

fn encode_schedule(schedule: &Schedule) -> Result<String> {
    serde_json::to_string(schedule).map_err(|_| Error::invalid("unsupported schedule"))
}

fn validate_spec(spec: &JobSpec) -> Result<u64> {
    identifier(&spec.job).map_err(|_| Error::invalid("invalid job"))?;
    if spec.job.len() > MAX_JOB_ID {
        return Err(Error::invalid("job id too long for an occurrence id"));
    }
    identifier(&spec.program).map_err(|_| Error::invalid("invalid program"))?;
    if spec.max_concurrency == 0 || spec.max_concurrency > MAX_JOB_CONCURRENCY {
        return Err(Error::invalid("invalid max_concurrency"));
    }
    period(&spec.schedule)
}

fn validate_digest(declaration_digest: &str) -> Result<()> {
    sha256_hex(declaration_digest)
        .map(|_| ())
        .map_err(|_| Error::invalid("invalid declaration digest"))
}

/// Split an occurrence id back into its job and slot index. Strict: the
/// index is the text after the last separator, all digits, with no leading
/// zero, and the job part is itself an identifier, so a run-once identity
/// or a hand-made string is refused rather than attributed to a job. Public
/// so the host's recovery can tell which job an incomplete reservation
/// belongs to without a second spelling of the id format.
pub fn occurrence_parts(occurrence: &str) -> Result<(&str, u64)> {
    let (job, index_text) = occurrence
        .rsplit_once(OCCURRENCE_SEPARATOR)
        .ok_or_else(|| Error::invalid("occurrence id is not a job occurrence"))?;
    let index = match index_text.parse::<u64>() {
        Ok(index) if index_text.len() <= MAX_INDEX_DIGITS && index.to_string() == index_text => {
            index
        }
        _ => return Err(Error::invalid("occurrence id is not a job occurrence")),
    };
    identifier(job).map_err(|_| Error::invalid("occurrence id is not a job occurrence"))?;
    Ok((job, index))
}

fn job_row(row: &rusqlite::Row<'_>) -> Result<JobRow> {
    let schedule: String = row.get(3)?;
    Ok(JobRow {
        xite: row.get(0)?,
        job: row.get(1)?,
        program: row.get(2)?,
        schedule: serde_json::from_str(&schedule)
            .map_err(|_| Error::conflict("stored JSON is unreadable"))?,
        max_concurrency: row.get(4)?,
        declaration_digest: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        paused_reason: row.get(7)?,
        next_due_unix: row.get(8)?,
        last_slot: row.get(9)?,
        last_occurrence: row.get(10)?,
        failures: row.get(11)?,
        updated_unix: row.get(12)?,
    })
}

fn load_job(conn: &Connection, xite: &str, job: &str) -> Result<Option<JobRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {JOB_COLUMNS} FROM jobs WHERE xite=?1 AND job=?2"
    ))?;
    let mut rows = statement.query(params![xite, job])?;
    match rows.next()? {
        Some(row) => job_row(row).map(Some),
        None => Ok(None),
    }
}

fn load_jobs(conn: &Connection, xite: &str) -> Result<Vec<JobRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {JOB_COLUMNS} FROM jobs WHERE xite=?1 ORDER BY job"
    ))?;
    let mut rows = statement.query(params![xite])?;
    let mut jobs = Vec::new();
    while let Some(row) = rows.next()? {
        jobs.push(job_row(row)?);
    }
    Ok(jobs)
}

/// Update one column of a job row; an unknown job is an [`Error::Conflict`]
/// because the caller is acting on a registration that is not there.
fn update_job(conn: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<()> {
    if conn.execute(sql, args)? != 1 {
        return Err(Error::conflict("unknown job"));
    }
    Ok(())
}

/// Delete all but the newest `keep` completed occurrences of `job` in
/// `xite`. "Newest" is insertion order (the table's rowid), not the slot
/// index: a re-registration with a new period renumbers the slots, and the
/// row just completed under the new numbering must never be the one
/// dropped. Running rows are never touched, and an occurrence id whose job
/// part is not exactly `job` (a job `a.b` next to a job `a`) is not this
/// job's. Runs inside the caller's transaction.
fn prune_job_occurrences(conn: &Connection, xite: &str, job: &str, keep: usize) -> Result<()> {
    let prefix = format!("{job}{OCCURRENCE_SEPARATOR}");
    let mut statement = conn.prepare(
        "SELECT rowid, occurrence FROM invocations \
         WHERE xite=?1 AND status=?2 AND substr(occurrence, 1, length(?3))=?3 \
         ORDER BY rowid DESC",
    )?;
    let mut rows = statement.query(params![xite, InvocationStatus::Completed.as_str(), prefix])?;
    let mut kept = 0usize;
    let mut doomed: Vec<i64> = Vec::new();
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let occurrence: String = row.get(1)?;
        if !occurrence_parts(&occurrence).is_ok_and(|(owner, _)| owner == job) {
            continue;
        }
        if kept < keep {
            kept += 1;
        } else {
            doomed.push(rowid);
        }
    }
    for rowid in doomed {
        conn.execute("DELETE FROM invocations WHERE rowid=?1", params![rowid])?;
    }
    Ok(())
}

impl DurableState {
    /// Replace the xite's registered jobs with `jobs`, the usable jobs of the
    /// declaration whose digest is `declaration_digest`, as of `now`.
    ///
    /// Jobs that vanished are deleted (their past occurrences stay in
    /// `invocations`, so a job that returns under the same name cannot rerun
    /// a slot it already ran). A kept job keeps `enabled`, `paused_reason`,
    /// `next_due_unix`, `last_slot`, `last_occurrence` and `failures`, unless
    /// its period changed: slot indexes are a function of the period, so the
    /// old `last_slot` would compare against the new numbering as either a
    /// permanent clock rollback or no protection at all, and `next_due_unix`
    /// belongs to the old cadence; both are restarted from the current slot
    /// while `failures` and the pause survive. A new job is due in the slot
    /// `now` falls in (its start), never in a past one.
    pub fn set_jobs(
        &self,
        xite: &str,
        declaration_digest: &str,
        jobs: &[JobSpec],
        now: u64,
    ) -> Result<()> {
        identifier(xite)?;
        validate_digest(declaration_digest)?;
        timestamp(now, "now")?;
        if jobs.len() > MAX_JOBS {
            return Err(Error::invalid("too many jobs"));
        }
        let mut encoded = Vec::with_capacity(jobs.len());
        for spec in jobs {
            let seconds = validate_spec(spec)?;
            encoded.push((spec, seconds, encode_schedule(&spec.schedule)?));
        }
        let mut names: Vec<&str> = jobs.iter().map(|spec| spec.job.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::invalid("duplicate job"));
        }
        transaction(&self.path, |conn| {
            for old in load_jobs(conn, xite)? {
                if names.binary_search(&old.job.as_str()).is_err() {
                    save_job_controls(conn, xite, &old.job)?;
                    conn.execute(
                        "DELETE FROM jobs WHERE xite=?1 AND job=?2",
                        params![xite, old.job],
                    )?;
                }
            }
            for (spec, seconds, schedule) in &encoded {
                let slot_start = (now / seconds) * seconds;
                match load_job(conn, xite, &spec.job)? {
                    None => {
                        conn.execute(
                            &format!(
                                "INSERT INTO jobs ({JOB_COLUMNS}) \
                                 VALUES (?1,?2,?3,?4,?5,?6,1,NULL,?7,NULL,NULL,0,?8)"
                            ),
                            params![
                                xite,
                                spec.job,
                                spec.program,
                                schedule,
                                spec.max_concurrency,
                                declaration_digest,
                                slot_start,
                                now,
                            ],
                        )?;
                        conn.execute(
                            "UPDATE jobs SET (enabled,paused_reason)=(SELECT enabled,paused_reason \
                             FROM job_controls WHERE xite=?1 AND job=?2) WHERE xite=?1 AND job=?2 \
                             AND EXISTS(SELECT 1 FROM job_controls WHERE xite=?1 AND job=?2)",
                            params![xite,spec.job],
                        )?;
                    }
                    Some(old) => {
                        let same_period = period(&parse_schedule(&old.schedule)?)? == *seconds;
                        if same_period {
                            update_job(
                                conn,
                                "UPDATE jobs SET program=?1, schedule=?2, max_concurrency=?3, \
                                 declaration_digest=?4, updated_unix=?5 \
                                 WHERE xite=?6 AND job=?7",
                                params![
                                    spec.program,
                                    schedule,
                                    spec.max_concurrency,
                                    declaration_digest,
                                    now,
                                    xite,
                                    spec.job,
                                ],
                            )?;
                        } else {
                            update_job(
                                conn,
                                "UPDATE jobs SET program=?1, schedule=?2, max_concurrency=?3, \
                                 declaration_digest=?4, updated_unix=?5, next_due_unix=?6, \
                                 last_slot=NULL, last_occurrence=NULL \
                                 WHERE xite=?7 AND job=?8",
                                params![
                                    spec.program,
                                    schedule,
                                    spec.max_concurrency,
                                    declaration_digest,
                                    now,
                                    slot_start,
                                    xite,
                                    spec.job,
                                ],
                            )?;
                        }
                    }
                }
                if requires_reconciliation(conn, xite, &spec.job)? {
                    record_reconciliation(conn, xite, &spec.job)?;
                }
            }
            Ok(())
        })
    }

    /// The xite's registered jobs, ordered by job id.
    pub fn jobs(&self, xite: &str) -> Result<Vec<JobRow>> {
        let conn = crate::connect(&self.path)?;
        load_jobs(&conn, xite)
    }

    /// Pause the job with `reason`, or clear an ordinary pause with `None`. The reason is
    /// shown in status and must be non-empty printable text, so a pause can
    /// never be a silent drop. Reconciliation and `user` pauses survive
    /// automatic updates; only [`DurableState::resume_job`] clears them.
    /// An unknown job is an [`Error::Conflict`].
    pub fn set_job_paused(&self, xite: &str, job: &str, reason: Option<&str>) -> Result<()> {
        identifier(xite)?;
        identifier(job).map_err(|_| Error::invalid("invalid job"))?;
        if let Some(reason) = reason {
            text(reason, "paused_reason")?;
            if reason.is_empty() {
                return Err(Error::invalid("invalid paused_reason"));
            }
        }
        transaction(&self.path, |conn| {
            let row = load_job(conn, xite, job)?.ok_or_else(|| Error::conflict("unknown job"))?;
            if reason == Some("reconcile_required") {
                record_reconciliation(conn, xite, job)?;
            }
            let reason = if requires_reconciliation(conn, xite, job)? {
                Some("reconcile_required")
            } else if row.paused_reason.as_deref() == Some("user") {
                Some("user")
            } else {
                reason
            };
            update_job(
                conn,
                "UPDATE jobs SET paused_reason=?1 WHERE xite=?2 AND job=?3",
                params![reason, xite, job],
            )?;
            advance_management_revision(conn, xite)?;
            save_job_controls(conn, xite, job)
        })
    }

    /// Explicit host management resume after reviewing an uncertain outcome.
    /// Clears the durable reconciliation guard and pause atomically. Never
    /// call this from automatic retry, content registration or recovery.
    /// The job must currently exist; unknown jobs fail without any mutation.
    pub fn resume_job(&self, xite: &str, job: &str) -> Result<()> {
        self.resume_job_guarded(xite, job, None)
    }

    /// A durable fence for host management while workspace recovery is in
    /// progress. It advances even when a repeated pause/disable has the same
    /// value, and is retained when a declaration withdraws its jobs.
    pub fn job_management_revision(&self, xite: &str) -> Result<u64> {
        identifier(xite)?;
        transaction(&self.path, |conn| management_revision(conn, xite))
    }

    /// Resume only if no later pause, enable/disable or resume changed this
    /// xite's job controls. Comparison and clearing share one write transaction.
    pub fn resume_job_at_revision(&self, xite: &str, job: &str, revision: u64) -> Result<()> {
        if revision > MAX_LIMIT {
            return Err(Error::invalid("invalid job management revision"));
        }
        self.resume_job_guarded(xite, job, Some(revision))
    }

    fn resume_job_guarded(&self, xite: &str, job: &str, revision: Option<u64>) -> Result<()> {
        identifier(xite)?;
        identifier(job).map_err(|_| Error::invalid("invalid job"))?;
        transaction(&self.path, |conn| {
            if let Some(expected) = revision {
                if management_revision(conn, xite)? != expected {
                    return Err(Error::conflict("job controls changed during workspace recovery"));
                }
            }
            update_job(
                conn,
                "UPDATE jobs SET paused_reason=NULL WHERE xite=?1 AND job=?2",
                params![xite, job],
            )?;
            conn.execute(
                "DELETE FROM job_reconciliation WHERE xite=?1 AND job=?2",
                params![xite, job],
            )?;
            advance_management_revision(conn, xite)?;
            save_job_controls(conn, xite, job)
        })
    }

    /// The host's own switch for a job, independent of the pause and its
    /// reason: a disabled job is never due and cannot be claimed. An unknown
    /// job is an [`Error::Conflict`].
    pub fn set_job_enabled(&self, xite: &str, job: &str, enabled: bool) -> Result<()> {
        identifier(xite)?;
        identifier(job).map_err(|_| Error::invalid("invalid job"))?;
        transaction(&self.path, |conn| {
            update_job(
                conn,
                "UPDATE jobs SET enabled=?1 WHERE xite=?2 AND job=?3",
                params![i64::from(enabled), xite, job],
            )?;
            advance_management_revision(conn, xite)?;
            save_job_controls(conn, xite, job)
        })
    }

    /// Move a job's next due time without an occurrence, for the scheduler
    /// to step past a slot it found already completed (a manual run of that
    /// slot, or a job that returned to a declaration after running it). An
    /// unknown job is an [`Error::Conflict`].
    pub fn set_job_next_due(
        &self,
        xite: &str,
        job: &str,
        next_due_unix: Option<u64>,
    ) -> Result<()> {
        identifier(xite)?;
        identifier(job).map_err(|_| Error::invalid("invalid job"))?;
        if let Some(next_due) = next_due_unix {
            timestamp(next_due, "next_due_unix")?;
        }
        transaction(&self.path, |conn| {
            update_job(
                conn,
                "UPDATE jobs SET next_due_unix=?1 WHERE xite=?2 AND job=?3",
                params![next_due_unix, xite, job],
            )
        })
    }

    /// Every job due at `now`: enabled, not paused, with a `next_due_unix`
    /// at or before `now`, whose xite holds a xite grant that is enabled,
    /// allows background work and has not expired. Ordered by due time, so
    /// the scheduler's round-robin starts from the longest waiting. The
    /// plugin switch is the host's and is not consulted here.
    pub fn due_jobs(&self, now: u64) -> Result<Vec<JobRow>> {
        timestamp(now, "now")?;
        let conn = crate::connect(&self.path)?;
        let mut statement = conn.prepare(&format!(
            "SELECT {JOINED_JOB_COLUMNS} FROM jobs AS j JOIN xite_grants AS g ON g.xite=j.xite \
             WHERE j.enabled=1 AND j.paused_reason IS NULL \
             AND j.next_due_unix IS NOT NULL AND j.next_due_unix<=?1 \
             AND g.enabled=1 AND g.allow_background=1 \
             AND (g.expires_unix IS NULL OR g.expires_unix>?1) \
             ORDER BY j.next_due_unix, j.xite, j.job"
        ))?;
        let mut rows = statement.query(params![now])?;
        let mut jobs = Vec::new();
        while let Some(row) = rows.next()? {
            jobs.push(job_row(row)?);
        }
        Ok(jobs)
    }

    /// The job that is due soonest after `now` under the same conditions
    /// [`DurableState::due_jobs`] applies at that moment, or `None` when no
    /// job will come due by itself: what the scheduler sleeps until. A job
    /// whose grant expires before its due time is left out, since it will
    /// not be due then either; a wake for a grant change comes from the
    /// host, not the timer. Ties are broken like `due_jobs` orders.
    pub fn next_due_job(&self, now: u64) -> Result<Option<JobRow>> {
        timestamp(now, "now")?;
        let conn = crate::connect(&self.path)?;
        let mut statement = conn.prepare(&format!(
            "SELECT {JOINED_JOB_COLUMNS} FROM jobs AS j JOIN xite_grants AS g ON g.xite=j.xite \
             WHERE j.enabled=1 AND j.paused_reason IS NULL \
             AND j.next_due_unix IS NOT NULL AND j.next_due_unix>?1 \
             AND g.enabled=1 AND g.allow_background=1 \
             AND (g.expires_unix IS NULL OR g.expires_unix>j.next_due_unix) \
             ORDER BY j.next_due_unix, j.xite, j.job LIMIT 1"
        ))?;
        let mut rows = statement.query(params![now])?;
        match rows.next()? {
            Some(row) => job_row(row).map(Some),
            None => Ok(None),
        }
    }

    /// Every xite with at least one registered job, ordered by address, for
    /// the host to tell a content change that matters to the scheduler from
    /// one that does not. Paused, disabled and ungranted jobs count: a wake
    /// for them is harmless, a missed one for a job just resumed is not.
    pub fn job_xites(&self) -> Result<Vec<String>> {
        let conn = crate::connect(&self.path)?;
        let mut statement = conn.prepare("SELECT DISTINCT xite FROM jobs ORDER BY xite")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut xites = Vec::new();
        for row in rows {
            xites.push(row?);
        }
        Ok(xites)
    }

    /// The slot an interval schedule puts `now` in: `index = now / seconds`,
    /// `start = index * seconds`, `end = start + seconds`, anchored at the
    /// Unix epoch. A boundary second belongs to the slot it starts. Pure:
    /// touches no database.
    pub fn slot_at(schedule: &Value, now: u64) -> Result<Slot> {
        timestamp(now, "now")?;
        let seconds = period(&parse_schedule(schedule)?)?;
        let index = now / seconds;
        let start_unix = index * seconds;
        Ok(Slot {
            index,
            start_unix,
            end_unix: start_unix + seconds,
        })
    }

    /// The occurrence id for a job slot: the job id, [`OCCURRENCE_SEPARATOR`]
    /// and the slot index in decimal. Identifier-safe for every job
    /// `set_jobs` accepts. Pure.
    pub fn occurrence_id(job: &str, slot: &Slot) -> String {
        format!("{job}{OCCURRENCE_SEPARATOR}{}", slot.index)
    }

    /// Reserve the occurrence of `job` at `slot` and record it on the job row
    /// in one transaction.
    ///
    /// `request` must be exactly `{"job", "slot", "program",
    /// "declaration_digest"}` for this job and slot: the request digest is
    /// what makes a second claim of the same occurrence match the first, so
    /// a caller-chosen extra field (a timestamp, say) would silently defeat
    /// the idempotency and is refused. `slot` must be the one this job's own
    /// schedule produces for its start.
    ///
    /// The job row is re-read inside the transaction, so the caller's copy
    /// may be stale: a job that was re-registered under another declaration
    /// is an [`Error::Conflict`], one that was disabled or paused, or whose
    /// grant no longer allows background work, is [`Error::Denied`] (the
    /// grant's own `enabled` and expiry are checked by the reservation as
    /// for every invocation, the expiry against `now`, the same tick the
    /// scheduler passed to [`DurableState::due_jobs`], so the two can never
    /// disagree about an expiring grant). A slot earlier than `last_slot`
    /// is a clock rollback or an out-of-order wake and is an
    /// [`Error::Conflict`] with nothing changed; the slot equal to
    /// `last_slot` is the same occurrence again and comes back with
    /// `fresh == false`, completed or not, so a manual run and the scheduled
    /// run of one slot can never both start. Only a fresh reservation moves
    /// `last_slot` and `last_occurrence`.
    ///
    /// `now` is one parameter more than the spec's signature: the spec has
    /// the reservation read the clock, which would make the claim's expiry
    /// check untestable on a fixed time line and able to deny what
    /// `due_jobs(now)` just admitted.
    pub fn claim_occurrence(
        &self,
        xite: &str,
        job: &JobRow,
        slot: &Slot,
        request: &Value,
        now: u64,
    ) -> Result<Invocation> {
        identifier(xite)?;
        timestamp(now, "now")?;
        if job.xite != xite {
            return Err(Error::invalid("job belongs to another xite"));
        }
        identifier(&job.job).map_err(|_| Error::invalid("invalid job"))?;
        if Self::slot_at(&job.schedule, slot.start_unix)? != *slot {
            return Err(Error::invalid("slot does not belong to the job's schedule"));
        }
        let occurrence = Self::occurrence_id(&job.job, slot);
        identifier(&occurrence)
            .map_err(|_| Error::invalid("job id too long for an occurrence id"))?;
        let expected = json!({
            "job": job.job,
            "slot": slot.index,
            "program": job.program,
            "declaration_digest": job.declaration_digest,
        });
        if *request != expected {
            return Err(Error::invalid("request is not the occurrence request"));
        }
        let request_digest = digest(&canonical(&expected)?);
        transaction(&self.path, |conn| {
            let row =
                load_job(conn, xite, &job.job)?.ok_or_else(|| Error::conflict("unknown job"))?;
            if row.declaration_digest != job.declaration_digest {
                return Err(Error::conflict(
                    "job re-registered under another declaration",
                ));
            }
            if !row.enabled {
                return Err(Error::denied("job disabled"));
            }
            if requires_reconciliation(conn, xite, &job.job)? {
                return Err(Error::denied("job requires reconciliation"));
            }
            if let Some(reason) = &row.paused_reason {
                return Err(Error::Denied(evx_api::Denied::new(format!(
                    "job paused: {reason}"
                ))));
            }
            match load_xite_grant(conn, xite)? {
                Some(grant) if grant.allow_background => {}
                _ => return Err(Error::denied("background runs not granted")),
            }
            if row.last_slot.is_some_and(|last| slot.index < last) {
                return Err(Error::conflict(
                    "clock rollback: slot before the last claimed slot",
                ));
            }
            let latest: Option<u64> = conn.query_row(
                "SELECT latest_start_unix FROM job_guards WHERE xite=?1 AND job=?2 AND period=?3",
                params![xite, job.job, slot.end_unix - slot.start_unix], |row| row.get(0),
            ).optional()?;
            if load_invocation(conn, xite, &occurrence)?.is_none() {
                if latest.is_some_and(|last| slot.start_unix <= last) {
                    return Err(Error::conflict("clock rollback: slot already passed"));
                }
                if latest.is_none()
                    && count(
                        conn,
                        "SELECT COUNT(*) FROM job_guards WHERE xite=?1",
                        params![xite],
                    )? >= crate::MAX_ROWS
                {
                    return Err(Error::budget("retained job identity limit"));
                }
                // Make room only for a new identity. Pruning a retained
                // retry first could delete that very row and reserve it
                // again when a removed job has lost its last_slot value.
                prune_job_occurrences(conn, xite, &job.job, RETAINED_OCCURRENCES_PER_JOB - 1)?;
            }
            let invocation = begin_in_at(conn, xite, &occurrence, &request_digest, 1, now)?;
            if invocation.fresh {
                conn.execute(
                    "INSERT INTO job_guards VALUES (?1,?2,?3,?4) ON CONFLICT(xite,job,period) \
                     DO UPDATE SET latest_start_unix=MAX(latest_start_unix,excluded.latest_start_unix)",
                    params![xite, job.job, slot.end_unix - slot.start_unix, slot.start_unix],
                )?;
                update_job(
                    conn,
                    "UPDATE jobs SET last_slot=?1, last_occurrence=?2 WHERE xite=?3 AND job=?4",
                    params![slot.index, occurrence, xite, job.job],
                )?;
            }
            Ok(invocation)
        })
    }

    /// Complete a job occurrence after its run: commit `result` as the
    /// occurrence's response (no effects, no checkpoint), then on the job
    /// row count the failure or reset the count and store the caller's
    /// `next_due_unix`, all in one transaction.
    ///
    /// `result` must be canonical JSON (integers only, no floats), as every
    /// committed response is; a raw host result with a float field is
    /// refused before any lock is taken. Finishing an occurrence that is
    /// already completed with the identical result is a no-op that
    /// succeeds, exactly as `commit` replays, so a retry after a crash
    /// between the commit and the host's own bookkeeping neither counts a
    /// failure twice nor moves the schedule again; a different result is an
    /// [`Error::Conflict`]. A job that vanished while its occurrence ran
    /// still gets the occurrence completed, since the reservation must never
    /// be left open; there is then no row to update.
    ///
    /// `next_due_unix` was computed from the cadence the occurrence was
    /// claimed under, so it is stored only while the row still names this
    /// occurrence as its last one. A `set_jobs` with a new period between
    /// the claim and the finish restarted the row's slot bookkeeping and
    /// put its own `next_due_unix` there; writing the old cadence's value
    /// over it would make the job early or late by an arbitrary amount.
    /// The failure count is kept or reset either way, since it survives a
    /// re-registration too. A host result with status `effect_unknown` or
    /// `quarantined`, or boolean `effect_outcome_unknown: true`, also records
    /// the reconciliation guard in this same transaction, even if the job
    /// was removed or its registration changed during the execution.
    pub fn finish_occurrence(
        &self,
        invocation: &Invocation,
        result: &Value,
        next_due_unix: Option<u64>,
        failed: bool,
    ) -> Result<()> {
        identifier(&invocation.xite)?;
        identifier(&invocation.occurrence)?;
        let (job, _) = occurrence_parts(&invocation.occurrence)?;
        if let Some(next_due) = next_due_unix {
            timestamp(next_due, "next_due_unix")?;
        }
        let prepared = prepare_commit(result, &[], None)?;
        transaction(&self.path, |conn| {
            if commit_in(conn, invocation, &prepared, None)?.is_some() {
                return Ok(());
            }
            if result_requires_reconciliation(result) {
                record_reconciliation(conn, &invocation.xite, job)?;
            }
            prune_job_occurrences(conn, &invocation.xite, job, RETAINED_OCCURRENCES_PER_JOB)?;
            let Some(row) = load_job(conn, &invocation.xite, job)? else {
                return Ok(());
            };
            let failures = if failed {
                row.failures.saturating_add(1)
            } else {
                0
            };
            if row.last_occurrence.as_deref() == Some(invocation.occurrence.as_str()) {
                update_job(
                    conn,
                    "UPDATE jobs SET failures=?1, next_due_unix=?2 WHERE xite=?3 AND job=?4",
                    params![failures, next_due_unix, invocation.xite, job],
                )
            } else {
                update_job(
                    conn,
                    "UPDATE jobs SET failures=?1 WHERE xite=?2 AND job=?3",
                    params![failures, invocation.xite, job],
                )
            }
        })
    }

    /// Close a reservation the host gave up on, without the grant fence.
    ///
    /// A reservation is fenced by the grant generation it was made under:
    /// [`DurableState::commit`], [`DurableState::finish_occurrence`] and
    /// [`DurableState::recover`] all refuse once the grant was revoked, which
    /// is what stops a revoked worker from committing. But the host must
    /// still be able to close its own reservation afterwards, or a run
    /// revoked mid-flight leaves a `running` row that no later call can
    /// touch (a re-grant advances the generation again) and that recovery
    /// meets at every start. This is that close: the row whose token
    /// matches `invocation` is marked completed with the response
    /// `{"status": "abandoned", "value": null, "error": message,
    /// "elapsed_ms": 0, "occurrence": ...}`, the shape the host commits for
    /// every job occurrence, and nothing else changes: no effect is queued,
    /// no checkpoint moves, and the job row (if any) keeps its schedule, so
    /// the scheduler claims the slot current when it next looks.
    ///
    /// Only the host calls this, never on a worker's behalf: the token
    /// check keeps a stale handle from closing a reservation that was
    /// recovered since. An unknown occurrence or another token is an
    /// [`Error::Conflict`]; a row already completed is left as it is and the
    /// call succeeds, so closing twice is harmless. `message` is at most
    /// [`MAX_MESSAGE`] bytes of printable text.
    pub fn abandon(&self, invocation: &Invocation, message: &str) -> Result<()> {
        self.abandon_with_status(invocation, message, false)
    }

    /// Close a stopped execution whose non-transactional effects are unknown.
    ///
    /// Like [`DurableState::abandon`], this host-only operation checks the
    /// token but not current grant authority, so revocation cannot strand a
    /// reservation. The `effect_unknown` response and the extant job's
    /// `reconcile_required` pause are committed atomically. No effect is
    /// retried, undone or queued. Completed reservations remain unchanged.
    pub fn abandon_uncertain(&self, invocation: &Invocation, message: &str) -> Result<()> {
        self.abandon_with_status(invocation, message, true)
    }

    fn abandon_with_status(
        &self,
        invocation: &Invocation,
        message: &str,
        uncertain: bool,
    ) -> Result<()> {
        identifier(&invocation.xite)?;
        identifier(&invocation.occurrence)?;
        if message.len() > MAX_MESSAGE || message.chars().any(char::is_control) {
            return Err(Error::invalid("invalid message"));
        }
        let response = json!({
            "status": if uncertain { "effect_unknown" } else { ABANDONED },
            "value": null,
            "error": message,
            "elapsed_ms": 0,
            "occurrence": invocation.occurrence,
        });
        let response_raw = canonical(&response)?;
        // The digest a commit of the same response with no effects and no
        // checkpoint records, so a later identical finish replays.
        let commit_digest = digest(&canonical(&json!({
            "response": response,
            "effects": [],
            "state_update": null,
        }))?);
        transaction(&self.path, |conn| {
            let row = match load_invocation(conn, &invocation.xite, &invocation.occurrence)? {
                Some(row) if row.token == invocation.token => row,
                _ => return Err(Error::conflict("stale invocation token")),
            };
            if row.status == InvocationStatus::Completed {
                return Ok(());
            }
            conn.execute(
                "UPDATE invocations SET status=?1, response=?2, commit_digest=?3 \
                 WHERE xite=?4 AND occurrence=?5",
                params![
                    InvocationStatus::Completed.as_str(),
                    response_raw,
                    commit_digest,
                    invocation.xite,
                    invocation.occurrence,
                ],
            )?;
            if let Ok((job, _)) = occurrence_parts(&invocation.occurrence) {
                if uncertain {
                    record_reconciliation(conn, &invocation.xite, job)?;
                }
                prune_job_occurrences(conn, &invocation.xite, job, RETAINED_OCCURRENCES_PER_JOB)?;
            }
            Ok(())
        })
    }

    /// Every enabled job that is paused, whose xite holds a grant that is
    /// enabled, allows background work and has not expired at `now`: the
    /// jobs that would be due but for their pause, ordered by xite and job.
    /// The host re-checks the ones whose pause it owns (a declaration it
    /// could not read, say) without waiting for a person.
    pub fn paused_jobs(&self, now: u64) -> Result<Vec<JobRow>> {
        timestamp(now, "now")?;
        let conn = crate::connect(&self.path)?;
        let mut statement = conn.prepare(&format!(
            "SELECT {JOINED_JOB_COLUMNS} FROM jobs AS j JOIN xite_grants AS g ON g.xite=j.xite \
             WHERE j.enabled=1 AND j.paused_reason IS NOT NULL \
             AND g.enabled=1 AND g.allow_background=1 \
             AND (g.expires_unix IS NULL OR g.expires_unix>?1) \
             ORDER BY j.xite, j.job"
        ))?;
        let mut rows = statement.query(params![now])?;
        let mut jobs = Vec::new();
        while let Some(row) = rows.next()? {
            jobs.push(job_row(row)?);
        }
        Ok(jobs)
    }

    /// How many invocation rows the xite holds, running and completed: the
    /// number the reservation compares with [`crate::MAX_ROWS`].
    pub fn retained_occurrences(&self, xite: &str) -> Result<u64> {
        identifier(xite)?;
        let conn = crate::connect(&self.path)?;
        count(
            &conn,
            "SELECT COUNT(*) FROM invocations WHERE xite=?1",
            params![xite],
        )
    }

    /// Invocations reserved and never committed, for one xite or all, ordered
    /// by xite and occurrence. Every running reservation is listed, including
    /// run-once ones, so recovery after a restart sees all of them.
    pub fn incomplete_occurrences(&self, xite: Option<&str>) -> Result<Vec<InvocationRow>> {
        if let Some(xite) = xite {
            identifier(xite)?;
        }
        let conn = crate::connect(&self.path)?;
        let mut statement = conn.prepare(&format!(
            "SELECT {INVOCATION_COLUMNS} FROM invocations \
             WHERE status=?1 AND (?2 IS NULL OR xite=?2) ORDER BY xite, occurrence"
        ))?;
        let mut rows = statement.query(params![InvocationStatus::Running.as_str(), xite])?;
        let mut incomplete = Vec::new();
        while let Some(row) = rows.next()? {
            incomplete.push(invocation_row(row)?);
        }
        Ok(incomplete)
    }

    /// Background runs the xite started in the UTC day `now` falls in.
    pub fn daily_runs(&self, xite: &str, now: u64) -> Result<u32> {
        identifier(xite)?;
        timestamp(now, "now")?;
        let conn = crate::connect(&self.path)?;
        Ok(conn
            .query_row(
                "SELECT runs FROM daily_runs WHERE xite=?1 AND day=?2",
                params![xite, now / SECONDS_PER_DAY],
                |row| row.get::<_, u32>(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    /// Count one more background run for the xite in the UTC day `now`
    /// falls in, or fail with [`Error::BudgetExceeded`] when `limit` runs
    /// are already counted (a limit of 0 admits nothing). The count is a
    /// row keyed on the xite and the day, so a restart keeps it and a new
    /// day starts at zero by key. The xite's rows for the last
    /// [`DAILY_RUN_RETENTION_DAYS`] days are kept, so a clock that rolls
    /// back into a day whose budget was spent finds that count and admits
    /// nothing more; only older rows are dropped here.
    pub fn reserve_daily_run(&self, xite: &str, now: u64, limit: u32) -> Result<()> {
        identifier(xite)?;
        timestamp(now, "now")?;
        let day = now / SECONDS_PER_DAY;
        transaction(&self.path, |conn| {
            let latest: Option<u64> = conn.query_row(
                "SELECT MAX(day) FROM daily_runs WHERE xite=?1",
                params![xite],
                |row| row.get(0),
            )?;
            if latest.is_some_and(|latest| day < latest.saturating_sub(DAILY_RUN_RETENTION_DAYS)) {
                return Err(Error::budget(
                    "clock rollback outside retained daily budget",
                ));
            }
            conn.execute(
                "DELETE FROM daily_runs WHERE xite=?1 AND day<?2",
                params![xite, day.saturating_sub(DAILY_RUN_RETENTION_DAYS)],
            )?;
            let runs: u32 = conn
                .query_row(
                    "SELECT runs FROM daily_runs WHERE xite=?1 AND day=?2",
                    params![xite, day],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            if runs >= limit {
                return Err(Error::budget("daily background run limit"));
            }
            conn.execute(
                "INSERT INTO daily_runs (xite, day, runs) VALUES (?1,?2,1) \
                 ON CONFLICT(xite, day) DO UPDATE SET runs=runs+1",
                params![xite, day],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod assumptions {
    use super::*;
    use crate::canonical::MAX_SAFE_INTEGER;

    #[test]
    fn the_identifier_length_the_job_id_bound_is_derived_from_still_holds() {
        assert!(identifier(&"x".repeat(MAX_IDENTIFIER)).is_ok());
        assert!(identifier(&"x".repeat(MAX_IDENTIFIER + 1)).is_err());
        assert_eq!(MAX_SAFE_INTEGER.to_string().len(), MAX_INDEX_DIGITS);
    }
}
