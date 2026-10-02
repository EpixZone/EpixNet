//! Host-owned SQLite durable state for EVX: grants, invocation reservations,
//! an effect outbox and per-xite checkpoints.
//!
//! This is never a guest filesystem or database API. Only the trusted
//! supervisor chooses database paths, xites, grants and occurrence IDs.
//! Budgets are cumulative reservations with no automatic reset or refund.
//! Recovery requires the supervisor to establish that the previous worker
//! stopped. The separate [`MockDestination`] models transactional
//! deduplication, not a chain or a publication protocol.
//!
//! # Generations
//!
//! Every grant carries three independent generation counters:
//!
//! * `generation`, the **authority** generation. It advances on
//!   [`DurableState::revoke`], when a grant row is first created, and when
//!   [`DurableState::set_grant`] changes `enabled` or `publication_prefix`.
//!   Invocations and queued effects record it and are denied once it moves.
//! * `limits_generation`, which advances only when `budget_limit` changes.
//!   Nothing is fenced on it: a pure budget change neither cancels queued
//!   effects nor fails running invocations. (The proof-of-concept bumped the
//!   authority generation on every `set_grant`, which this crate deliberately
//!   fixes.)
//! * `schema_generation`, supplied by the host and checked independently; it
//!   can never move backwards.
//!
//! # Xite grants (Milestone 2)
//!
//! Milestone 2 adds the persistent [`XiteGrant`] the wrapper records,
//! single-use allow-once tokens and a bounded [`RunRecord`] history. A xite
//! grant is derived into the policy row above, so the same generations fence
//! everything. The database carries its layout in `PRAGMA user_version`
//! ([`SCHEMA_VERSION`]); every migration is additive and runs on open, and a
//! database written by a newer build is refused rather than guessed at.
//!
//! # Job schedules (Milestone 3)
//!
//! Milestone 3 adds the persisted schedule: a [`JobRow`] per declared job,
//! its slot bookkeeping, and the per-day background budget. A scheduled run
//! is an ordinary invocation whose occurrence id names the job and the slot
//! ([`DurableState::occurrence_id`]), reserved with
//! [`DurableState::claim_occurrence`] and completed with
//! [`DurableState::finish_occurrence`], so every fence above applies to it
//! unchanged and the same occurrence can never execute twice.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod canonical;
mod destination;
mod jobs;
#[cfg(test)]
mod jobs_tests;
#[cfg(test)]
mod tests;
mod xite;
#[cfg(test)]
mod xite_tests;

use std::path::{Path, PathBuf};
use std::time::Duration;

use rand::RngCore as _;
use rusqlite::{params, Connection, OptionalExtension as _, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use canonical::{
    canonical, digest, identifier, positive, relative_path, sha256_hex, MAX_DEPTH, MAX_JSON,
    MAX_LIMIT, MAX_SAFE_INTEGER,
};
pub use destination::{Destination, MockDestination};
pub use jobs::{
    JobRow, JobSpec, Slot, DAILY_RUN_RETENTION_DAYS, MAX_JOBS, MAX_JOB_CONCURRENCY, MAX_JOB_ID,
    OCCURRENCE_SEPARATOR, SECONDS_PER_DAY,
};
pub use xite::{
    RunRecord, XiteGrant, ALLOW_ONCE_TTL, MAX_ALLOW_ONCE, MAX_MESSAGE, MAX_RUNS,
    MAX_RUNTIME_PROFILES, MAX_TEXT, XITE_BUDGET_LIMIT,
};

/// Layout version recorded in the database's `PRAGMA user_version`.
///
/// Version 1 is the Milestone 1 layout (`grants`, `invocations`, `outbox`,
/// `checkpoints`; databases written before the version was recorded read as
/// 0 and are treated as 1). Version 2 adds `xite_grants`, `allow_once` and
/// `runs`. Version 3 adds `jobs` and `daily_runs`. [`DurableState::open`]
/// applies every step up to this version with `IF NOT EXISTS` statements
/// only, so an older file keeps all of its rows.
pub const SCHEMA_VERSION: u32 = 3;

/// Most invocations or outbox rows retained per xite, and most receipts or
/// published entries retained by the mock destination.
pub const MAX_ROWS: u64 = 4096;
/// Most effects a single commit may carry.
pub const MAX_EFFECTS: usize = 16;
/// Most writes plus deletes a single publication delta may carry.
pub const MAX_PUBLICATION_ENTRIES: usize = 16;
/// Largest published text file, in bytes.
pub const MAX_PUBLICATION_CONTENT: usize = 2048;
/// Largest `limit` accepted by [`DurableState::dispatch`].
pub const MAX_DISPATCH: u64 = 64;

/// Errors raised by the durable state and the mock destination.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The grant, generation or capability required for the operation is
    /// missing, disabled or stale.
    #[error("{0}")]
    Denied(#[from] evx_api::Denied),
    /// The operation contradicts something already durably recorded.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A cumulative budget or retention limit would be exceeded.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(String),
    /// Malformed input (the proof-of-concept's `ValueError` class).
    #[error("invalid input: {0}")]
    Invalid(String),
    /// The underlying SQLite database reported a failure.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl Error {
    fn denied(reason: &str) -> Self {
        Error::Denied(evx_api::Denied::new(reason))
    }

    fn conflict(reason: &str) -> Self {
        Error::Conflict(reason.to_owned())
    }

    fn budget(reason: &str) -> Self {
        Error::BudgetExceeded(reason.to_owned())
    }

    fn invalid(reason: &str) -> Self {
        Error::Invalid(reason.to_owned())
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Test-only failure injection hook: called with a named point during an
/// operation so a test can crash or abort the process there.
pub type Failpoint<'a> = &'a dyn Fn(&str);

/// Trusted grant configuration supplied by the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantPolicy {
    /// Whether the xite may reserve, commit and have effects delivered.
    pub enabled: bool,
    /// Cumulative reservation ceiling; `used` is never reset by a policy change.
    pub budget_limit: u64,
    /// Host schema generation; may only stay equal or increase.
    pub schema_generation: u64,
    /// Host-selected publication prefix, or `None` to withhold publication.
    pub publication_prefix: Option<String>,
}

impl Default for GrantPolicy {
    /// Enabled, budget 100, schema generation 1, no publication capability.
    fn default() -> Self {
        GrantPolicy {
            enabled: true,
            budget_limit: 100,
            schema_generation: 1,
            publication_prefix: None,
        }
    }
}

/// Generation counters of a grant after [`DurableState::set_grant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generations {
    /// Authority generation recorded by invocations and queued effects.
    pub generation: u64,
    /// Budget generation; advances only when `budget_limit` changes.
    pub limits_generation: u64,
    /// Schema generation as supplied by the host.
    pub schema_generation: u64,
}

/// A reservation handle returned by [`DurableState::begin`] or
/// [`DurableState::recover`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invocation {
    /// Host-selected xite namespace.
    pub xite: String,
    /// Host-selected occurrence identifier, unique per xite.
    pub occurrence: String,
    /// Fencing token; a commit with a stale token is rejected.
    pub token: String,
    /// Authority generation of the grant when the reservation was made.
    pub generation: u64,
    /// Schema generation of the grant when the reservation was made.
    pub schema_generation: u64,
    /// `true` when this call created the reservation or rotated the token;
    /// `false` means another worker already holds it and none should start.
    pub fresh: bool,
    /// Whether a result has already been committed.
    pub completed: bool,
    /// The committed response, when `completed`.
    pub response: Option<Value>,
}

/// Kind of a mock effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectKind {
    /// An opaque record delivered to the destination as-is.
    Record,
    /// An exact publication delta (`writes` and `deletes`) under the grant's
    /// publication prefix.
    Publish,
}

/// An effect intent saved atomically with a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// Effect key, unique per xite; identical keys must carry identical payloads.
    pub key: String,
    /// Effect kind.
    pub kind: EffectKind,
    /// Effect payload (canonical JSON rules apply).
    pub payload: Value,
}

impl Effect {
    /// A record effect.
    pub fn record(key: impl Into<String>, payload: Value) -> Self {
        Effect {
            key: key.into(),
            kind: EffectKind::Record,
            payload,
        }
    }

    /// A publication effect with the given exact delta payload
    /// (`{"writes": {...}, "deletes": [...]}`).
    pub fn publish(key: impl Into<String>, payload: Value) -> Self {
        Effect {
            key: key.into(),
            kind: EffectKind::Publish,
            payload,
        }
    }
}

/// A compare-and-swap checkpoint update carried by a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateUpdate {
    /// The checkpoint version the caller last read; `0` when none exists.
    pub expected_version: u64,
    /// The new checkpoint value.
    pub value: Value,
}

/// A xite checkpoint as returned by [`DurableState::read_state`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Current version, `0` when no checkpoint has ever been written.
    pub version: u64,
    /// Current value, `Value::Null` when no checkpoint has ever been written.
    pub value: Value,
}

/// Status of an invocation row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvocationStatus {
    /// Reserved, no result yet.
    Running,
    /// Result committed.
    Completed,
}

impl InvocationStatus {
    fn as_str(self) -> &'static str {
        match self {
            InvocationStatus::Running => "running",
            InvocationStatus::Completed => "completed",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "running" => Ok(InvocationStatus::Running),
            "completed" => Ok(InvocationStatus::Completed),
            _ => Err(Error::conflict("unknown invocation status")),
        }
    }
}

/// Status of an outbox row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboxStatus {
    /// Waiting for dispatch.
    Queued,
    /// Delivered to the destination.
    Delivered,
    /// Cancelled because its authority expired before delivery.
    Cancelled,
}

impl OutboxStatus {
    fn as_str(self) -> &'static str {
        match self {
            OutboxStatus::Queued => "queued",
            OutboxStatus::Delivered => "delivered",
            OutboxStatus::Cancelled => "cancelled",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        match text {
            "queued" => Ok(OutboxStatus::Queued),
            "delivered" => Ok(OutboxStatus::Delivered),
            "cancelled" => Ok(OutboxStatus::Cancelled),
            _ => Err(Error::conflict("unknown outbox status")),
        }
    }
}

/// A grant row as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRow {
    /// Xite namespace.
    pub xite: String,
    /// Whether the grant is enabled.
    pub enabled: bool,
    /// Authority generation.
    pub generation: u64,
    /// Budget generation.
    pub limits_generation: u64,
    /// Schema generation.
    pub schema_generation: u64,
    /// Cumulative reservation ceiling.
    pub budget_limit: u64,
    /// Cumulative reservations made; never reset or refunded.
    pub used: u64,
    /// Publication prefix, if publication is granted.
    pub publication_prefix: Option<String>,
}

/// An invocation row as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRow {
    /// Xite namespace.
    pub xite: String,
    /// Occurrence identifier.
    pub occurrence: String,
    /// Current fencing token.
    pub token: String,
    /// Authority generation at reservation.
    pub generation: u64,
    /// Schema generation at reservation.
    pub schema_generation: u64,
    /// Digest of the canonical request.
    pub request_digest: String,
    /// Reserved cost.
    pub cost: u64,
    /// Row status.
    pub status: InvocationStatus,
    /// Committed response, if any.
    pub response: Option<Value>,
    /// Digest of the whole committed result, if any.
    pub commit_digest: Option<String>,
}

/// An outbox row as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxRow {
    /// Xite namespace.
    pub xite: String,
    /// Effect key.
    pub effect_key: String,
    /// Authority generation at commit.
    pub generation: u64,
    /// Schema generation at commit.
    pub schema_generation: u64,
    /// Canonical envelope handed to the destination.
    pub envelope: String,
    /// Digest of the envelope.
    pub payload_digest: String,
    /// Row status.
    pub status: OutboxStatus,
    /// Destination response once delivered.
    pub response: Option<Value>,
}

/// Trusted diagnostics for one xite; not a guest query surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The grant row, if any.
    pub grant: Option<GrantRow>,
    /// Invocations ordered by occurrence.
    pub invocations: Vec<InvocationRow>,
    /// Outbox rows ordered by effect key.
    pub outbox: Vec<OutboxRow>,
}

/// Result of dispatching one queued effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// The destination accepted the effect.
    Delivered,
    /// The effect's authority was stale, so it was cancelled without delivery.
    Cancelled,
}

/// One entry returned by [`DurableState::dispatch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// Xite namespace of the effect.
    pub xite: String,
    /// Effect key.
    pub key: String,
    /// What happened.
    pub status: DeliveryStatus,
    /// The destination response when delivered.
    pub response: Option<Value>,
}

/// The Milestone 1 tables; `xite::SCHEMA_V2` adds the rest. Kept separate so
/// the migration test can create a version 1 file the way the old code did.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS grants (
 xite TEXT PRIMARY KEY, enabled INTEGER NOT NULL, generation INTEGER NOT NULL,
 limits_generation INTEGER NOT NULL DEFAULT 1,
 schema_generation INTEGER NOT NULL, budget_limit INTEGER NOT NULL,
 used INTEGER NOT NULL DEFAULT 0, publication_prefix TEXT);
CREATE TABLE IF NOT EXISTS invocations (
 xite TEXT NOT NULL, occurrence TEXT NOT NULL, token TEXT NOT NULL,
 generation INTEGER NOT NULL, schema_generation INTEGER NOT NULL,
 request_digest TEXT NOT NULL, cost INTEGER NOT NULL, status TEXT NOT NULL,
 response TEXT, commit_digest TEXT, PRIMARY KEY (xite, occurrence));
CREATE TABLE IF NOT EXISTS outbox (
 xite TEXT NOT NULL, effect_key TEXT NOT NULL, generation INTEGER NOT NULL,
 schema_generation INTEGER NOT NULL, envelope TEXT NOT NULL,
 payload_digest TEXT NOT NULL, status TEXT NOT NULL, response TEXT,
 PRIMARY KEY (xite, effect_key));
CREATE TABLE IF NOT EXISTS checkpoints (
 xite TEXT PRIMARY KEY, version INTEGER NOT NULL, value TEXT NOT NULL);
";

const GRANT_COLUMNS: &str = "xite, enabled, generation, limits_generation, schema_generation, \
                             budget_limit, used, publication_prefix";
const INVOCATION_COLUMNS: &str = "xite, occurrence, token, generation, schema_generation, \
                                  request_digest, cost, status, response, commit_digest";
const OUTBOX_COLUMNS: &str = "xite, effect_key, generation, schema_generation, envelope, \
                              payload_digest, status, response";

/// Open a SQLite connection the way every operation in this crate does: a
/// ten-second busy timeout and `synchronous=FULL`.
pub(crate) fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    Ok(conn)
}

/// Run `body` inside a `BEGIN IMMEDIATE` transaction on a fresh connection.
/// The transaction is rolled back when `body` fails.
pub(crate) fn transaction<T>(
    path: &Path,
    body: impl FnOnce(&Connection) -> Result<T>,
) -> Result<T> {
    let mut conn = connect(path)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let out = body(&tx)?;
    tx.commit()?;
    Ok(out)
}

/// `bytes` random bytes from the process CSPRNG as lower-case hex.
pub(crate) fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buffer);
    hex::encode(buffer)
}

fn fresh_token() -> String {
    random_hex(16)
}

fn parse_json(text: Option<String>) -> Result<Option<Value>> {
    match text {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|_| Error::conflict("stored JSON is unreadable")),
    }
}

fn grant_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GrantRow> {
    Ok(GrantRow {
        xite: row.get(0)?,
        enabled: row.get::<_, i64>(1)? != 0,
        generation: row.get(2)?,
        limits_generation: row.get(3)?,
        schema_generation: row.get(4)?,
        budget_limit: row.get(5)?,
        used: row.get(6)?,
        publication_prefix: row.get(7)?,
    })
}

fn invocation_row(row: &rusqlite::Row<'_>) -> Result<InvocationRow> {
    Ok(InvocationRow {
        xite: row.get(0)?,
        occurrence: row.get(1)?,
        token: row.get(2)?,
        generation: row.get(3)?,
        schema_generation: row.get(4)?,
        request_digest: row.get(5)?,
        cost: row.get(6)?,
        status: InvocationStatus::parse(&row.get::<_, String>(7)?)?,
        response: parse_json(row.get(8)?)?,
        commit_digest: row.get(9)?,
    })
}

fn outbox_row(row: &rusqlite::Row<'_>) -> Result<OutboxRow> {
    Ok(OutboxRow {
        xite: row.get(0)?,
        effect_key: row.get(1)?,
        generation: row.get(2)?,
        schema_generation: row.get(3)?,
        envelope: row.get(4)?,
        payload_digest: row.get(5)?,
        status: OutboxStatus::parse(&row.get::<_, String>(6)?)?,
        response: parse_json(row.get(7)?)?,
    })
}

fn load_grant(conn: &Connection, xite: &str) -> Result<Option<GrantRow>> {
    Ok(conn
        .query_row(
            &format!("SELECT {GRANT_COLUMNS} FROM grants WHERE xite=?1"),
            params![xite],
            grant_row,
        )
        .optional()?)
}

fn load_invocation(
    conn: &Connection,
    xite: &str,
    occurrence: &str,
) -> Result<Option<InvocationRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {INVOCATION_COLUMNS} FROM invocations WHERE xite=?1 AND occurrence=?2"
    ))?;
    let mut rows = statement.query(params![xite, occurrence])?;
    match rows.next()? {
        Some(row) => invocation_row(row).map(Some),
        None => Ok(None),
    }
}

fn load_outbox(conn: &Connection, xite: &str, key: &str) -> Result<Option<OutboxRow>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {OUTBOX_COLUMNS} FROM outbox WHERE xite=?1 AND effect_key=?2"
    ))?;
    let mut rows = statement.query(params![xite, key])?;
    match rows.next()? {
        Some(row) => outbox_row(row).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn count(conn: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<u64> {
    Ok(conn.query_row(sql, args, |row| row.get::<_, u64>(0))?)
}

/// Check that `xite` holds an enabled grant, unexpired at `now`, whose
/// schema and authority generations match the ones supplied (when
/// supplied). When a xite grant exists it must be enabled too: the policy
/// row alone can never admit a xite whose consent record says no. `now` is
/// the caller's: the Milestone 2 operations read the clock, a job claim
/// passes the scheduler's tick so the claim and `due_jobs` agree.
fn allowed(
    conn: &Connection,
    xite: &str,
    generation: Option<u64>,
    schema_generation: Option<u64>,
    now: u64,
) -> Result<GrantRow> {
    let grant = match load_grant(conn, xite)? {
        Some(grant) if grant.enabled => grant,
        _ => return Err(Error::denied("grant disabled or missing")),
    };
    xite::check_xite_grant(conn, xite, now)?;
    if schema_generation.is_some_and(|expected| grant.schema_generation != expected) {
        return Err(Error::denied("stale schema generation"));
    }
    if generation.is_some_and(|expected| grant.generation != expected) {
        return Err(Error::denied("stale grant generation"));
    }
    Ok(grant)
}

fn invocation_from_row(row: InvocationRow, fresh: bool) -> Invocation {
    Invocation {
        xite: row.xite,
        occurrence: row.occurrence,
        token: row.token,
        generation: row.generation,
        schema_generation: row.schema_generation,
        fresh,
        completed: row.status == InvocationStatus::Completed,
        response: row.response,
    }
}

/// The body of [`DurableState::begin`] at the wall clock's `now`.
pub(crate) fn begin_in(
    conn: &Connection,
    xite: &str,
    occurrence: &str,
    request_digest: &str,
    cost: u64,
) -> Result<Invocation> {
    begin_in_at(
        conn,
        xite,
        occurrence,
        request_digest,
        cost,
        xite::now_unix()?,
    )
}

/// The body of [`DurableState::begin`], run inside a caller-owned
/// `BEGIN IMMEDIATE` transaction so a job claim can reserve the occurrence
/// and update its job row atomically, with the grant's expiry checked at
/// the caller's `now`. Inputs are already validated and `request_digest`
/// is the digest of the canonical request.
pub(crate) fn begin_in_at(
    conn: &Connection,
    xite: &str,
    occurrence: &str,
    request_digest: &str,
    cost: u64,
    now: u64,
) -> Result<Invocation> {
    let grant = allowed(conn, xite, None, None, now)?;
    if let Some(prior) = load_invocation(conn, xite, occurrence)? {
        if prior.request_digest != request_digest || prior.cost != cost {
            return Err(Error::conflict("occurrence payload or cost conflict"));
        }
        return Ok(invocation_from_row(prior, false));
    }
    if grant.used + cost > grant.budget_limit {
        return Err(Error::budget("persistent budget exhausted"));
    }
    if count(
        conn,
        "SELECT COUNT(*) FROM invocations WHERE xite=?1",
        params![xite],
    )? >= MAX_ROWS
    {
        return Err(Error::budget("retained occurrence limit"));
    }
    conn.execute(
        "UPDATE grants SET used=used+?1 WHERE xite=?2",
        params![cost, xite],
    )?;
    conn.execute(
        &format!(
            "INSERT INTO invocations ({INVOCATION_COLUMNS}) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,NULL,NULL)"
        ),
        params![
            xite,
            occurrence,
            fresh_token(),
            grant.generation,
            grant.schema_generation,
            request_digest,
            cost,
            InvocationStatus::Running.as_str(),
        ],
    )?;
    let row = load_invocation(conn, xite, occurrence)?
        .ok_or_else(|| Error::conflict("reservation vanished"))?;
    Ok(invocation_from_row(row, true))
}

/// A commit whose inputs passed validation and canonical encoding, ready to
/// be applied inside a transaction by [`commit_in`].
pub(crate) struct PreparedCommit<'a> {
    response: &'a Value,
    response_raw: String,
    effects: &'a [Effect],
    state: Option<(StateUpdate, String)>,
}

/// Validate and canonically encode a commit's inputs outside any
/// transaction, so a malformed result holds no database lock.
pub(crate) fn prepare_commit<'a>(
    response: &'a Value,
    effects: &'a [Effect],
    state: Option<StateUpdate>,
) -> Result<PreparedCommit<'a>> {
    let response_raw = canonical(response)?;
    let mut keys: Vec<&str> = effects.iter().map(|effect| effect.key.as_str()).collect();
    keys.sort_unstable();
    keys.dedup();
    if effects.len() > MAX_EFFECTS || keys.len() != effects.len() {
        return Err(Error::invalid("effect count or duplicate key"));
    }
    let state = match state {
        Some(update) => {
            positive(update.expected_version, true)?;
            let raw = canonical(&update.value)?;
            Some((update, raw))
        }
        None => None,
    };
    Ok(PreparedCommit {
        response,
        response_raw,
        effects,
        state,
    })
}

/// The body of [`DurableState::commit`], run inside a caller-owned
/// `BEGIN IMMEDIATE` transaction so a job's finish can complete the
/// occurrence and update its job row atomically. Returns the stored response
/// when the occurrence was already completed with an identical result
/// (nothing is written in that case) and `None` when this call completed it.
pub(crate) fn commit_in(
    conn: &Connection,
    invocation: &Invocation,
    prepared: &PreparedCommit<'_>,
    failpoint: Option<Failpoint<'_>>,
) -> Result<Option<Value>> {
    let row = match load_invocation(conn, &invocation.xite, &invocation.occurrence)? {
        Some(row) if row.token == invocation.token => row,
        _ => return Err(Error::conflict("stale invocation token")),
    };
    let grant = allowed(
        conn,
        &invocation.xite,
        Some(row.generation),
        Some(row.schema_generation),
        xite::now_unix()?,
    )?;
    let mut encoded = prepared
        .effects
        .iter()
        .map(|effect| {
            envelope(effect, grant.publication_prefix.as_deref())
                .map(|raw| (effect.key.as_str(), raw))
        })
        .collect::<Result<Vec<_>>>()?;
    encoded.sort();
    let state_update = prepared.state.as_ref().map(
        |(update, _)| json!({"expected_version": update.expected_version, "value": update.value}),
    );
    let commit_digest = digest(&canonical(&json!({
        "response": prepared.response,
        "effects": encoded.iter().map(|(key, raw)| json!([key, raw])).collect::<Vec<_>>(),
        "state_update": state_update,
    }))?);
    if row.status == InvocationStatus::Completed {
        if row.commit_digest.as_deref() != Some(commit_digest.as_str()) {
            return Err(Error::conflict("completed occurrence result conflict"));
        }
        return Ok(Some(row.response.unwrap_or(Value::Null)));
    }
    if let Some((update, state_raw)) = &prepared.state {
        let version: u64 = conn
            .query_row(
                "SELECT version FROM checkpoints WHERE xite=?1",
                params![invocation.xite],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if version != update.expected_version {
            return Err(Error::conflict("checkpoint version conflict"));
        }
        conn.execute(
            "INSERT INTO checkpoints (xite, version, value) VALUES (?1,?2,?3) \
             ON CONFLICT(xite) DO UPDATE SET version=excluded.version, \
             value=excluded.value",
            params![invocation.xite, version + 1, state_raw],
        )?;
    }
    for (key, raw) in &encoded {
        let payload_digest = digest(raw);
        if let Some(prior) = load_outbox(conn, &invocation.xite, key)? {
            if prior.payload_digest != payload_digest {
                return Err(Error::conflict("effect payload conflict"));
            }
            let expired = prior.status == OutboxStatus::Cancelled
                || (prior.status == OutboxStatus::Queued
                    && (prior.generation != row.generation
                        || prior.schema_generation != row.schema_generation));
            if expired {
                return Err(Error::denied("effect belongs to expired authority"));
            }
            continue;
        }
        if count(
            conn,
            "SELECT COUNT(*) FROM outbox WHERE xite=?1",
            params![invocation.xite],
        )? >= MAX_ROWS
        {
            return Err(Error::budget("retained effect limit"));
        }
        conn.execute(
            &format!("INSERT INTO outbox ({OUTBOX_COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL)"),
            params![
                invocation.xite,
                key,
                row.generation,
                row.schema_generation,
                raw,
                payload_digest,
                OutboxStatus::Queued.as_str(),
            ],
        )?;
    }
    conn.execute(
        "UPDATE invocations SET status=?1, response=?2, commit_digest=?3 \
         WHERE xite=?4 AND occurrence=?5",
        params![
            InvocationStatus::Completed.as_str(),
            prepared.response_raw,
            commit_digest,
            invocation.xite,
            invocation.occurrence,
        ],
    )?;
    if let Some(failpoint) = failpoint {
        failpoint("before_commit");
    }
    Ok(None)
}

/// Validate an effect and encode its canonical envelope. `prefix` is the
/// grant's publication prefix; publication without one is denied.
pub(crate) fn envelope(effect: &Effect, prefix: Option<&str>) -> Result<String> {
    identifier(&effect.key)?;
    let envelope = match effect.kind {
        EffectKind::Record => json!({"kind": "record", "payload": effect.payload}),
        EffectKind::Publish => {
            let prefix = prefix.ok_or_else(|| Error::denied("publication capability missing"))?;
            let delta = match effect.payload.as_object() {
                Some(delta)
                    if delta.len() == 2
                        && delta.contains_key("writes")
                        && delta.contains_key("deletes") =>
                {
                    delta
                }
                _ => return Err(Error::invalid("invalid exact publication delta")),
            };
            let (writes, deletes) = match (delta["writes"].as_object(), delta["deletes"].as_array())
            {
                (Some(writes), Some(deletes))
                    if writes.len() + deletes.len() <= MAX_PUBLICATION_ENTRIES =>
                {
                    (writes, deletes)
                }
                _ => return Err(Error::invalid("publication entry limit")),
            };
            for (path, content) in writes {
                relative_path(path)?;
                match content.as_str() {
                    Some(text) if text.len() <= MAX_PUBLICATION_CONTENT => {}
                    _ => return Err(Error::invalid("invalid text content")),
                }
            }
            let mut delete_paths = Vec::with_capacity(deletes.len());
            for path in deletes {
                let path = path
                    .as_str()
                    .ok_or_else(|| Error::invalid("invalid publication path"))?;
                relative_path(path)?;
                delete_paths.push(path);
            }
            let mut unique = delete_paths.clone();
            unique.sort_unstable();
            unique.dedup();
            if unique.len() != delete_paths.len()
                || delete_paths.iter().any(|path| writes.contains_key(*path))
            {
                return Err(Error::invalid("overlapping publication delta"));
            }
            json!({"kind": "publish", "prefix": prefix, "payload": effect.payload})
        }
    };
    canonical(&envelope)
}

/// Host-owned durable state backed by one SQLite database in WAL mode.
///
/// Every operation opens its own connection and runs in a `BEGIN IMMEDIATE`
/// transaction with `synchronous=FULL`, so the value is cheap to clone and
/// safe to share between threads; concurrent writers serialise on the
/// database lock with a ten-second busy timeout.
#[derive(Debug, Clone)]
pub struct DurableState {
    path: PathBuf,
}

impl DurableState {
    /// Open (creating if needed) the database at `path`, switch it to WAL and
    /// bring the schema up to [`SCHEMA_VERSION`].
    ///
    /// Migration is additive only (`CREATE ... IF NOT EXISTS`), runs inside
    /// one `BEGIN IMMEDIATE` transaction with the version bump, and never
    /// touches existing rows. A file whose `user_version` is newer than this
    /// build is an [`Error::Conflict`]: reading it with older assumptions
    /// could silently drop authority this build does not know about.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let state = DurableState {
            path: path.as_ref().to_path_buf(),
        };
        let conn = connect(&state.path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let version: u32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::conflict("database schema is newer than this build"));
        }
        conn.execute_batch(&format!(
            "BEGIN IMMEDIATE;{SCHEMA}{}{}PRAGMA user_version={SCHEMA_VERSION};COMMIT;",
            xite::SCHEMA_V2,
            jobs::SCHEMA_V3
        ))?;
        Ok(state)
    }

    /// The layout version the database at this path carries; equals
    /// [`SCHEMA_VERSION`] after a successful [`DurableState::open`].
    pub fn schema_version(&self) -> Result<u32> {
        let conn = connect(&self.path)?;
        Ok(conn.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    /// Trusted configuration operation. Existing usage is never reset.
    ///
    /// The authority `generation` advances only when the row is new or when
    /// `enabled` or `publication_prefix` change; `limits_generation` advances
    /// only when `budget_limit` changes. Lowering `schema_generation` is a
    /// [`Error::Conflict`].
    ///
    /// For a xite that also holds a [`XiteGrant`], `enabled` can only be
    /// lowered here: `enabled: false` disables the xite grant as well, so
    /// [`DurableState::xite_grant`] reads back what the fences enforce, and
    /// `enabled: true` while the xite grant is disabled is an
    /// [`Error::Conflict`], since re-enabling is consent and only
    /// [`DurableState::set_xite_grant`] records consent. Budget, schema
    /// generation and publication prefix changes are unaffected.
    pub fn set_grant(&self, xite: &str, policy: GrantPolicy) -> Result<Generations> {
        identifier(xite)?;
        positive(policy.budget_limit, true)?;
        positive(policy.schema_generation, false)?;
        if let Some(prefix) = policy.publication_prefix.as_deref() {
            relative_path(prefix)?;
        }
        transaction(&self.path, |conn| {
            let old = load_grant(conn, xite)?;
            if old
                .as_ref()
                .is_some_and(|old| policy.schema_generation < old.schema_generation)
            {
                return Err(Error::conflict("schema generation cannot move backwards"));
            }
            if let Some(xite_grant) = xite::load_xite_grant(conn, xite)? {
                if policy.enabled && !xite_grant.enabled {
                    return Err(Error::conflict(
                        "xite grant is disabled; re-enable it with set_xite_grant",
                    ));
                }
                if !policy.enabled {
                    xite::disable_xite_grant_row(conn, xite)?;
                }
            }
            let (generation, limits_generation, used) = match &old {
                None => (1, 1, 0),
                Some(old) => {
                    let authority_changed = old.enabled != policy.enabled
                        || old.publication_prefix != policy.publication_prefix;
                    let limits_changed = old.budget_limit != policy.budget_limit;
                    (
                        old.generation + u64::from(authority_changed),
                        old.limits_generation + u64::from(limits_changed),
                        old.used,
                    )
                }
            };
            conn.execute(
                "INSERT INTO grants (xite, enabled, generation, limits_generation, \
                 schema_generation, budget_limit, used, publication_prefix) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                 ON CONFLICT(xite) DO UPDATE SET enabled=excluded.enabled, \
                 generation=excluded.generation, limits_generation=excluded.limits_generation, \
                 schema_generation=excluded.schema_generation, \
                 budget_limit=excluded.budget_limit, \
                 publication_prefix=excluded.publication_prefix",
                params![
                    xite,
                    i64::from(policy.enabled),
                    generation,
                    limits_generation,
                    policy.schema_generation,
                    policy.budget_limit,
                    used,
                    policy.publication_prefix,
                ],
            )?;
            Ok(Generations {
                generation,
                limits_generation,
                schema_generation: policy.schema_generation,
            })
        })
    }

    /// Disable the grant and advance its authority generation, fencing every
    /// running invocation and queued effect. The xite grant, if one exists,
    /// reads back disabled and its outstanding allow-once tokens are
    /// discarded (see [`DurableState::revoke_xite`]). Unknown xites are a
    /// no-op.
    pub fn revoke(&self, xite: &str) -> Result<()> {
        transaction(&self.path, |conn| {
            conn.execute(
                "UPDATE grants SET enabled=0, generation=generation+1 WHERE xite=?1",
                params![xite],
            )?;
            xite::revoke_xite_rows(conn, xite)
        })
    }

    /// Reserve `cost` once for `(xite, occurrence)`.
    ///
    /// Repeated calls with the same request and cost return the existing
    /// reservation with `fresh == false`, meaning no new worker should start;
    /// a different request digest or cost is an [`Error::Conflict`]. `None`
    /// as the request is the canonical JSON `null`.
    pub fn begin(
        &self,
        xite: &str,
        occurrence: &str,
        request: Option<&Value>,
        cost: u64,
    ) -> Result<Invocation> {
        identifier(xite)?;
        identifier(occurrence)?;
        positive(cost, false)?;
        let request_digest = digest(&canonical(request.unwrap_or(&Value::Null))?);
        transaction(&self.path, |conn| {
            begin_in(conn, xite, occurrence, &request_digest, cost)
        })
    }

    /// Host-only fencing after establishing that the old worker has stopped:
    /// rotates the token so the old handle can no longer commit, without
    /// making a new reservation.
    pub fn recover(&self, invocation: &Invocation) -> Result<Invocation> {
        transaction(&self.path, |conn| {
            allowed(
                conn,
                &invocation.xite,
                Some(invocation.generation),
                Some(invocation.schema_generation),
                xite::now_unix()?,
            )?;
            let row = load_invocation(conn, &invocation.xite, &invocation.occurrence)?;
            match row {
                Some(row)
                    if row.status == InvocationStatus::Running && row.token == invocation.token => {
                }
                _ => return Err(Error::conflict("invocation cannot be recovered")),
            }
            conn.execute(
                "UPDATE invocations SET token=?1 WHERE xite=?2 AND occurrence=?3",
                params![fresh_token(), invocation.xite, invocation.occurrence],
            )?;
            let row = load_invocation(conn, &invocation.xite, &invocation.occurrence)?
                .ok_or_else(|| Error::conflict("invocation cannot be recovered"))?;
            Ok(invocation_from_row(row, true))
        })
    }

    /// Save the result, the exact effect intents and an optional checkpoint
    /// compare-and-swap atomically. See [`DurableState::commit_with_failpoint`].
    pub fn commit(
        &self,
        invocation: &Invocation,
        response: &Value,
        effects: &[Effect],
        state: Option<StateUpdate>,
    ) -> Result<Value> {
        self.commit_with_failpoint(invocation, response, effects, state, None)
    }

    /// [`DurableState::commit`] with a test-only failpoint that is called with
    /// `"before_commit"` inside the transaction and `"after_commit"` once it
    /// is durable.
    ///
    /// Committing an already completed occurrence succeeds only when the
    /// response, effects and checkpoint update are identical, in which case
    /// the stored response is returned. The committed response is returned
    /// re-parsed from its canonical form.
    pub fn commit_with_failpoint(
        &self,
        invocation: &Invocation,
        response: &Value,
        effects: &[Effect],
        state: Option<StateUpdate>,
        failpoint: Option<Failpoint<'_>>,
    ) -> Result<Value> {
        let prepared = prepare_commit(response, effects, state)?;
        let replayed = transaction(&self.path, |conn| {
            commit_in(conn, invocation, &prepared, failpoint)
        })?;
        if let Some(failpoint) = failpoint {
            failpoint("after_commit");
        }
        if let Some(stored) = replayed {
            return Ok(stored);
        }
        serde_json::from_str(&prepared.response_raw)
            .map_err(|_| Error::invalid("unsupported JSON value"))
    }

    /// Host-selected xite checkpoint with its compare-and-swap version.
    pub fn read_state(&self, xite: &str) -> Result<Checkpoint> {
        let conn = connect(&self.path)?;
        let row: Option<(u64, String)> = conn
            .query_row(
                "SELECT version, value FROM checkpoints WHERE xite=?1",
                params![xite],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match row {
            Some((version, raw)) => Ok(Checkpoint {
                version,
                value: parse_json(Some(raw))?.unwrap_or(Value::Null),
            }),
            None => Ok(Checkpoint {
                version: 0,
                value: Value::Null,
            }),
        }
    }

    /// Serial mock dispatch of up to `limit` queued effects (at most
    /// [`MAX_DISPATCH`]). See [`DurableState::dispatch_with_failpoint`].
    pub fn dispatch(&self, destination: &mut dyn Destination, limit: u64) -> Result<Vec<Outcome>> {
        self.dispatch_with_failpoint(destination, limit, None)
    }

    /// [`DurableState::dispatch`] with a test-only failpoint called with
    /// `"after_destination"` once the destination accepted an effect but
    /// before the outbox row is marked delivered.
    ///
    /// Each effect is handled in its own `BEGIN IMMEDIATE` transaction, so
    /// the database lock orders revocation against delivery: an effect whose
    /// authority or schema generation no longer matches the grant is
    /// cancelled instead of delivered. Real network calls must not hold this
    /// lock; they need bounded dispatch authorisation and destination-specific
    /// reconciliation instead.
    pub fn dispatch_with_failpoint(
        &self,
        destination: &mut dyn Destination,
        limit: u64,
        failpoint: Option<Failpoint<'_>>,
    ) -> Result<Vec<Outcome>> {
        positive(limit, false)?;
        if limit > MAX_DISPATCH {
            return Err(Error::invalid("dispatch limit"));
        }
        let mut outcomes = Vec::new();
        for _ in 0..limit {
            let outcome = transaction(&self.path, |conn| {
                let next = {
                    let mut statement = conn.prepare(&format!(
                        "SELECT {OUTBOX_COLUMNS} FROM outbox WHERE status='queued' \
                         ORDER BY xite, effect_key LIMIT 1"
                    ))?;
                    let mut rows = statement.query([])?;
                    match rows.next()? {
                        Some(row) => Some(outbox_row(row)?),
                        None => None,
                    }
                };
                let Some(row) = next else {
                    return Ok(None);
                };
                match allowed(
                    conn,
                    &row.xite,
                    Some(row.generation),
                    Some(row.schema_generation),
                    xite::now_unix()?,
                ) {
                    Ok(_) => {}
                    Err(Error::Denied(_)) => {
                        conn.execute(
                            "UPDATE outbox SET status=?1 WHERE xite=?2 AND effect_key=?3",
                            params![OutboxStatus::Cancelled.as_str(), row.xite, row.effect_key],
                        )?;
                        return Ok(Some(Outcome {
                            xite: row.xite,
                            key: row.effect_key,
                            status: DeliveryStatus::Cancelled,
                            response: None,
                        }));
                    }
                    Err(error) => return Err(error),
                }
                let response = destination.apply(
                    &row.xite,
                    &row.effect_key,
                    &row.envelope,
                    &row.payload_digest,
                )?;
                if let Some(failpoint) = failpoint {
                    failpoint("after_destination");
                }
                conn.execute(
                    "UPDATE outbox SET status=?1, response=?2 WHERE xite=?3 AND effect_key=?4",
                    params![
                        OutboxStatus::Delivered.as_str(),
                        canonical(&response)?,
                        row.xite,
                        row.effect_key
                    ],
                )?;
                Ok(Some(Outcome {
                    xite: row.xite,
                    key: row.effect_key,
                    status: DeliveryStatus::Delivered,
                    response: Some(response),
                }))
            })?;
            match outcome {
                Some(outcome) => outcomes.push(outcome),
                None => break,
            }
        }
        Ok(outcomes)
    }

    /// Trusted diagnostics for one xite; not a guest query surface.
    pub fn snapshot(&self, xite: &str) -> Result<Snapshot> {
        let conn = connect(&self.path)?;
        let grant = load_grant(&conn, xite)?;
        let mut statement = conn.prepare(&format!(
            "SELECT {INVOCATION_COLUMNS} FROM invocations WHERE xite=?1 ORDER BY occurrence"
        ))?;
        let mut rows = statement.query(params![xite])?;
        let mut invocations = Vec::new();
        while let Some(row) = rows.next()? {
            invocations.push(invocation_row(row)?);
        }
        let mut statement = conn.prepare(&format!(
            "SELECT {OUTBOX_COLUMNS} FROM outbox WHERE xite=?1 ORDER BY effect_key"
        ))?;
        let mut rows = statement.query(params![xite])?;
        let mut outbox = Vec::new();
        while let Some(row) = rows.next()? {
            outbox.push(outbox_row(row)?);
        }
        Ok(Snapshot {
            grant,
            invocations,
            outbox,
        })
    }
}
