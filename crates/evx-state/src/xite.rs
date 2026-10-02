//! Persistent xite grants, allow-once tokens and bounded run history
//! (Milestone 2, `docs/evx-milestone-2.md` section 3).
//!
//! A [`XiteGrant`] is the consent the wrapper recorded for one xite: which
//! publisher it trusts, which capabilities and runtime profiles the xite's
//! programs may use, and the host-clamped limits. It is stored next to the
//! Milestone 1 [`GrantPolicy`](crate::GrantPolicy) row rather than replacing
//! it: every `set_xite_grant` derives a policy and writes both rows in one
//! transaction, so `begin`, `commit`, `dispatch` and the checkpoint keep
//! fencing on the same `grants.generation` they always did. The generation
//! rules are the plan's: authority moves only when `enabled`, the
//! capabilities, the runtime profiles or the publisher change, and the limits
//! generation only when the limits change, so adjusting a quota never cancels
//! queued work and re-saving an identical grant never fences anything.
//!
//! The derivation is one-way. The Milestone 1
//! [`set_grant`](DurableState::set_grant) may still tighten a xite's budget
//! or disable it (a disable is mirrored into the xite grant so status views
//! stay truthful), but it can never re-enable a xite whose xite grant is
//! disabled: that is consent, and only a new `set_xite_grant` records it.
//! Independently, every fence (`begin`, `commit`, `dispatch`) consults the
//! xite grant's own `enabled` flag and expiry, so the two rows can never
//! disagree about whether the xite may run.
//!
//! Allow-once tokens are the "Allow once" button: a single-use secret bound
//! to the xite, the declaration digest the operator saw and the one program
//! they approved. They expire after [`ALLOW_ONCE_TTL`] seconds, and revoking
//! the xite discards the ones still outstanding, because "revoke" means no
//! further runs of any kind. Nothing here consults a xite's own files or
//! lets a page mint, widen or forge any of it; only the host calls these.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use evx_api::{Capability, Limits};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};

use crate::canonical::{identifier, sha256_hex, MAX_SAFE_INTEGER};
use crate::{
    load_grant, random_hex, transaction, DurableState, Error, Failpoint, Generations, Result,
    MAX_LIMIT,
};

/// Run records retained per xite; older ones are dropped as new ones arrive.
pub const MAX_RUNS: u64 = 50;
/// Seconds an unconsumed allow-once token stays valid.
pub const ALLOW_ONCE_TTL: u64 = 600;
/// Most unconsumed, unexpired allow-once tokens one xite may hold at once.
pub const MAX_ALLOW_ONCE: u64 = 64;
/// Longest `label`, `publisher` or `status` text accepted, in bytes.
pub const MAX_TEXT: usize = 256;
/// Longest run `message` accepted, in bytes.
pub const MAX_MESSAGE: usize = 4096;
/// Most runtime profiles one xite grant may list.
///
/// `capabilities` needs no such bound: it is a set over the closed
/// [`Capability`] enum, so it can never hold more members than the enum has.
pub const MAX_RUNTIME_PROFILES: usize = 16;
/// Reservation ceiling of the policy derived from a xite grant.
///
/// The cumulative reservation budget is the Milestone 1 fixture control; a
/// xite's real ceilings are its [`Limits`] and the host scheduler, so the
/// derived policy uses the largest budget the crate accepts. A host that
/// wants a tighter cumulative budget can still lower it with `set_grant`.
pub const XITE_BUDGET_LIMIT: u64 = MAX_LIMIT;

/// Additive Milestone 2 tables. Every statement is `IF NOT EXISTS` so a
/// Milestone 1 database migrates by simply being opened.
pub(crate) const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS xite_grants (
 xite TEXT PRIMARY KEY, publisher TEXT NOT NULL, enabled INTEGER NOT NULL,
 capabilities TEXT NOT NULL, runtime_profiles TEXT NOT NULL, limits TEXT NOT NULL,
 allow_run_once INTEGER NOT NULL DEFAULT 0, allow_background INTEGER NOT NULL DEFAULT 0,
 created_unix INTEGER NOT NULL, expires_unix INTEGER, label TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS allow_once (
 xite TEXT NOT NULL, token TEXT NOT NULL, declaration_digest TEXT NOT NULL,
 program TEXT NOT NULL, issued_unix INTEGER NOT NULL,
 consumed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (xite, token));
CREATE TABLE IF NOT EXISTS runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, xite TEXT NOT NULL,
 started_unix INTEGER NOT NULL, finished_unix INTEGER NOT NULL,
 program TEXT NOT NULL, declaration_digest TEXT NOT NULL,
 artifact_sha256 TEXT NOT NULL, input_digest TEXT NOT NULL, status TEXT NOT NULL,
 message TEXT, cpu_seconds REAL NOT NULL, peak_rss INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS runs_by_xite ON runs (xite, id);
";

const XITE_GRANT_COLUMNS: &str = "xite, publisher, enabled, capabilities, runtime_profiles, \
                                  limits, allow_run_once, allow_background, created_unix, \
                                  expires_unix, label";
const RUN_COLUMNS: &str = "started_unix, finished_unix, program, declaration_digest, \
                           artifact_sha256, input_digest, status, message, cpu_seconds, peak_rss";

/// The persistent consent recorded for one xite by the wrapper or operator.
///
/// `capabilities` and `runtime_profiles` are the ceiling an activation must
/// fit under; `limits` are already host-clamped. `allow_run_once` and
/// `allow_background` record what the operator consented to beyond
/// activation itself (background scheduling is Milestone 3 and is stored
/// only so the consent survives). `expires_unix`, when set, makes the grant
/// deny from that second on without a revocation.
///
/// Decoding is strict: an unknown or misspelled field is a deserialisation
/// error, never silently dropped, like every other wire type in `evx_api`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XiteGrant {
    /// Xite namespace (its address).
    pub xite: String,
    /// Root address of the publisher whose signature the grant trusts.
    pub publisher: String,
    /// Whether the xite may activate and run at all.
    pub enabled: bool,
    /// Capabilities the xite's programs may hold.
    pub capabilities: BTreeSet<Capability>,
    /// Runtime profiles the xite's programs may declare.
    pub runtime_profiles: BTreeSet<String>,
    /// Host-clamped per-invocation limits.
    pub limits: Limits,
    /// Whether the operator allowed one-off runs through `evxRunOnce`.
    pub allow_run_once: bool,
    /// Whether the operator allowed background jobs (unused until Milestone 3).
    pub allow_background: bool,
    /// Unix seconds when the consent was recorded.
    pub created_unix: u64,
    /// Unix seconds after which the grant denies, or `None` for no expiry.
    pub expires_unix: Option<u64>,
    /// Free-text user or device label shown in status views.
    pub label: String,
}

/// One completed or failed program run, as kept by
/// [`DurableState::record_run`].
///
/// `status` is the host's closed vocabulary (`ok`, `denied`, `crashed`,
/// ...) stored as text so the state crate does not have to change when the
/// host adds one; it is validated as an identifier, never interpreted here.
/// Decoding refuses unknown fields, as [`XiteGrant`] does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    /// Unix seconds when the run started.
    pub started_unix: u64,
    /// Unix seconds when the run finished; never before `started_unix`.
    pub finished_unix: u64,
    /// Program identifier from the declaration.
    pub program: String,
    /// Digest of the declaration the run was admitted under.
    pub declaration_digest: String,
    /// SHA-256 of the compiled artifact that ran.
    pub artifact_sha256: String,
    /// Digest of the canonical input the program received.
    pub input_digest: String,
    /// Host status word for the outcome.
    pub status: String,
    /// Optional human-readable detail (an error message, a trap reason).
    pub message: Option<String>,
    /// CPU seconds consumed across worker and helper processes.
    pub cpu_seconds: f64,
    /// Peak resident-set bytes observed.
    pub peak_rss: u64,
}

/// Current Unix time in whole seconds. A clock before the epoch is an
/// [`Error::Denied`]: no token can be minted or spent and no grant can be
/// admitted without a clock to check its expiry against, so the caller
/// fails closed instead of comparing against a sentinel.
pub(crate) fn now_unix() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| Error::denied("clock before the Unix epoch"))
}

fn text(value: &str, what: &str) -> Result<()> {
    if value.len() > MAX_TEXT || value.chars().any(char::is_control) {
        return Err(Error::Invalid(format!("invalid {what}")));
    }
    Ok(())
}

fn timestamp(value: u64, what: &str) -> Result<()> {
    if value > MAX_SAFE_INTEGER {
        return Err(Error::Invalid(format!("invalid {what}")));
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::invalid("unsupported JSON value"))
}

fn decode<T: for<'de> Deserialize<'de>>(raw: &str) -> Result<T> {
    serde_json::from_str(raw).map_err(|_| Error::conflict("stored JSON is unreadable"))
}

fn validate_grant(grant: &XiteGrant) -> Result<()> {
    identifier(&grant.xite)?;
    identifier(&grant.publisher).map_err(|_| Error::invalid("invalid publisher"))?;
    if grant.runtime_profiles.len() > MAX_RUNTIME_PROFILES {
        return Err(Error::invalid("too many runtime profiles"));
    }
    for profile in &grant.runtime_profiles {
        identifier(profile).map_err(|_| Error::invalid("invalid runtime profile"))?;
    }
    grant
        .limits
        .validate()
        .map_err(|denied| Error::Invalid(denied.to_string()))?;
    timestamp(grant.created_unix, "created_unix")?;
    if let Some(expires) = grant.expires_unix {
        timestamp(expires, "expires_unix")?;
        if expires <= grant.created_unix {
            return Err(Error::invalid("expires_unix must follow created_unix"));
        }
    }
    text(&grant.label, "label")
}

fn validate_run(run: &RunRecord) -> Result<()> {
    identifier(&run.program).map_err(|_| Error::invalid("invalid program"))?;
    sha256_hex(&run.declaration_digest)
        .map_err(|_| Error::invalid("invalid declaration digest"))?;
    sha256_hex(&run.artifact_sha256).map_err(|_| Error::invalid("invalid artifact digest"))?;
    sha256_hex(&run.input_digest).map_err(|_| Error::invalid("invalid input digest"))?;
    identifier(&run.status).map_err(|_| Error::invalid("invalid run status"))?;
    if run.status.len() > MAX_TEXT {
        return Err(Error::invalid("invalid run status"));
    }
    if let Some(message) = &run.message {
        if message.len() > MAX_MESSAGE {
            return Err(Error::invalid("run message too long"));
        }
    }
    timestamp(run.started_unix, "started_unix")?;
    timestamp(run.finished_unix, "finished_unix")?;
    if run.finished_unix < run.started_unix {
        return Err(Error::invalid("run finished before it started"));
    }
    if !run.cpu_seconds.is_finite() || run.cpu_seconds < 0.0 {
        return Err(Error::invalid("invalid cpu_seconds"));
    }
    timestamp(run.peak_rss, "peak_rss")
}

fn xite_grant_row(row: &rusqlite::Row<'_>) -> Result<XiteGrant> {
    Ok(XiteGrant {
        xite: row.get(0)?,
        publisher: row.get(1)?,
        enabled: row.get::<_, i64>(2)? != 0,
        capabilities: decode(&row.get::<_, String>(3)?)?,
        runtime_profiles: decode(&row.get::<_, String>(4)?)?,
        limits: decode(&row.get::<_, String>(5)?)?,
        allow_run_once: row.get::<_, i64>(6)? != 0,
        allow_background: row.get::<_, i64>(7)? != 0,
        created_unix: row.get(8)?,
        expires_unix: row.get(9)?,
        label: row.get(10)?,
    })
}

fn run_row(row: &rusqlite::Row<'_>) -> Result<RunRecord> {
    Ok(RunRecord {
        started_unix: row.get(0)?,
        finished_unix: row.get(1)?,
        program: row.get(2)?,
        declaration_digest: row.get(3)?,
        artifact_sha256: row.get(4)?,
        input_digest: row.get(5)?,
        status: row.get(6)?,
        message: row.get(7)?,
        cpu_seconds: row.get(8)?,
        peak_rss: row.get(9)?,
    })
}

pub(crate) fn load_xite_grant(conn: &Connection, xite: &str) -> Result<Option<XiteGrant>> {
    let mut statement = conn.prepare(&format!(
        "SELECT {XITE_GRANT_COLUMNS} FROM xite_grants WHERE xite=?1"
    ))?;
    let mut rows = statement.query(params![xite])?;
    match rows.next()? {
        Some(row) => xite_grant_row(row).map(Some),
        None => Ok(None),
    }
}

/// Deny unless the xite grant for `xite`, if any, is enabled and has not
/// passed its `expires_unix` at `now`. A xite without a xite grant passes
/// (its Milestone 1 policy row alone decides). `now == 0` is the reading of
/// a clock that could not be trusted, so a grant that expires at all is
/// treated as expired rather than compared against it.
pub(crate) fn check_xite_grant(conn: &Connection, xite: &str, now: u64) -> Result<()> {
    let row: Option<(i64, Option<u64>)> = conn
        .query_row(
            "SELECT enabled, expires_unix FROM xite_grants WHERE xite=?1",
            params![xite],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(()),
        Some((0, _)) => Err(Error::denied("xite grant disabled")),
        Some((_, Some(at))) if now == 0 || now >= at => Err(Error::denied("grant expired")),
        Some(_) => Ok(()),
    }
}

/// Mirror a policy-row disable into the xite grant row (if any) so
/// [`DurableState::xite_grant`] reports what the fences enforce. Called by
/// `set_grant`; `revoke` uses [`revoke_xite_rows`], which also drops tokens.
pub(crate) fn disable_xite_grant_row(conn: &Connection, xite: &str) -> Result<()> {
    conn.execute(
        "UPDATE xite_grants SET enabled=0 WHERE xite=?1",
        params![xite],
    )?;
    Ok(())
}

/// Disable the xite grant row (if any) and drop every outstanding allow-once
/// token, so a revoked xite cannot run under a token minted before the
/// revocation either. Called by `revoke`.
pub(crate) fn revoke_xite_rows(conn: &Connection, xite: &str) -> Result<()> {
    conn.execute(
        "UPDATE xite_grants SET enabled=0 WHERE xite=?1",
        params![xite],
    )?;
    conn.execute("DELETE FROM allow_once WHERE xite=?1", params![xite])?;
    Ok(())
}

impl DurableState {
    /// Store or replace the persistent grant for `grant.xite` and derive the
    /// Milestone 1 policy row from it in the same transaction.
    ///
    /// The authority generation advances when the row is new, when a policy
    /// row existed without a xite grant, or when `enabled`, `capabilities`,
    /// `runtime_profiles` or `publisher` change; the limits generation only
    /// when `limits` change. `allow_run_once`, `allow_background`,
    /// `expires_unix`, `created_unix` and `label` never move a generation:
    /// none of them widens what a running invocation may do. Existing usage,
    /// schema generation and any budget the host lowered with `set_grant`
    /// are kept; the derived policy never grants publication.
    pub fn set_xite_grant(&self, grant: &XiteGrant) -> Result<Generations> {
        validate_grant(grant)?;
        let capabilities = encode(&grant.capabilities)?;
        let profiles = encode(&grant.runtime_profiles)?;
        let limits = encode(&grant.limits)?;
        transaction(&self.path, |conn| {
            let old_policy = load_grant(conn, &grant.xite)?;
            let old_grant = load_xite_grant(conn, &grant.xite)?;
            let (generation, limits_generation, schema_generation, budget_limit, used) =
                match &old_policy {
                    None => (1, 1, 1, XITE_BUDGET_LIMIT, 0),
                    Some(old) => {
                        let (authority_changed, limits_changed) = match &old_grant {
                            None => (true, true),
                            Some(prev) => (
                                prev.enabled != grant.enabled
                                    || prev.capabilities != grant.capabilities
                                    || prev.runtime_profiles != grant.runtime_profiles
                                    || prev.publisher != grant.publisher,
                                prev.limits != grant.limits,
                            ),
                        };
                        // The policy row is the fence the invocations check, so
                        // a change to it by `set_grant` since the last xite
                        // grant counts as an authority change too.
                        let policy_changed =
                            old.enabled != grant.enabled || old.publication_prefix.is_some();
                        (
                            old.generation + u64::from(authority_changed || policy_changed),
                            old.limits_generation + u64::from(limits_changed),
                            old.schema_generation,
                            old.budget_limit,
                            old.used,
                        )
                    }
                };
            conn.execute(
                "INSERT INTO grants (xite, enabled, generation, limits_generation, \
                 schema_generation, budget_limit, used, publication_prefix) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,NULL) \
                 ON CONFLICT(xite) DO UPDATE SET enabled=excluded.enabled, \
                 generation=excluded.generation, limits_generation=excluded.limits_generation, \
                 schema_generation=excluded.schema_generation, \
                 budget_limit=excluded.budget_limit, publication_prefix=NULL",
                params![
                    grant.xite,
                    i64::from(grant.enabled),
                    generation,
                    limits_generation,
                    schema_generation,
                    budget_limit,
                    used,
                ],
            )?;
            conn.execute(
                &format!(
                    "INSERT INTO xite_grants ({XITE_GRANT_COLUMNS}) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) \
                     ON CONFLICT(xite) DO UPDATE SET publisher=excluded.publisher, \
                     enabled=excluded.enabled, capabilities=excluded.capabilities, \
                     runtime_profiles=excluded.runtime_profiles, limits=excluded.limits, \
                     allow_run_once=excluded.allow_run_once, \
                     allow_background=excluded.allow_background, \
                     created_unix=excluded.created_unix, expires_unix=excluded.expires_unix, \
                     label=excluded.label"
                ),
                params![
                    grant.xite,
                    grant.publisher,
                    i64::from(grant.enabled),
                    capabilities,
                    profiles,
                    limits,
                    i64::from(grant.allow_run_once),
                    i64::from(grant.allow_background),
                    grant.created_unix,
                    grant.expires_unix,
                    grant.label,
                ],
            )?;
            Ok(Generations {
                generation,
                limits_generation,
                schema_generation,
            })
        })
    }

    /// The stored xite grant and the generations of its derived policy, or
    /// `None` when the xite was never granted through
    /// [`DurableState::set_xite_grant`]. A revoked grant is returned with
    /// `enabled == false`; an expired one is returned as stored, with its
    /// `expires_unix` for the caller to show.
    ///
    /// Both rows are read in one snapshot, so the grant body and the
    /// generations always belong to the same `set_xite_grant` or revocation
    /// even while another thread is writing.
    pub fn xite_grant(&self, xite: &str) -> Result<Option<(XiteGrant, Generations)>> {
        self.xite_grant_with_failpoint(xite, None)
    }

    /// [`DurableState::xite_grant`] with a test-only failpoint called with
    /// `"between_reads"` after the xite grant row is read and before the
    /// policy row is.
    pub(crate) fn xite_grant_with_failpoint(
        &self,
        xite: &str,
        failpoint: Option<Failpoint<'_>>,
    ) -> Result<Option<(XiteGrant, Generations)>> {
        let mut conn = crate::connect(&self.path)?;
        // A deferred (read) transaction: in WAL mode it pins one snapshot for
        // both reads without blocking the writers it is racing.
        let tx = conn.transaction()?;
        let Some(grant) = load_xite_grant(&tx, xite)? else {
            return Ok(None);
        };
        if let Some(failpoint) = failpoint {
            failpoint("between_reads");
        }
        let policy = load_grant(&tx, xite)?
            .ok_or_else(|| Error::conflict("xite grant without a policy row"))?;
        Ok(Some((
            grant,
            Generations {
                generation: policy.generation,
                limits_generation: policy.limits_generation,
                schema_generation: policy.schema_generation,
            },
        )))
    }

    /// Disable the xite's grant with [`DurableState::revoke`] semantics: the
    /// authority generation advances, fencing every running invocation and
    /// queued effect, the xite grant reads back disabled and every
    /// outstanding allow-once token is discarded. Unknown xites are a no-op.
    pub fn revoke_xite(&self, xite: &str) -> Result<()> {
        self.revoke(xite)
    }

    /// Mint a single-use token that lets the host run `program` once under
    /// the declaration whose digest is `declaration_digest`, without a
    /// persistent grant. The token is 64 lower-case hex characters from the
    /// process CSPRNG and expires [`ALLOW_ONCE_TTL`] seconds after minting.
    pub fn allow_once(
        &self,
        xite: &str,
        declaration_digest: &str,
        program: &str,
    ) -> Result<String> {
        self.allow_once_at(xite, declaration_digest, program, now_unix()?)
    }

    /// [`DurableState::allow_once`] with an explicit issue time, for tests.
    pub(crate) fn allow_once_at(
        &self,
        xite: &str,
        declaration_digest: &str,
        program: &str,
        issued_unix: u64,
    ) -> Result<String> {
        identifier(xite)?;
        sha256_hex(declaration_digest).map_err(|_| Error::invalid("invalid declaration digest"))?;
        identifier(program).map_err(|_| Error::invalid("invalid program"))?;
        timestamp(issued_unix, "issued_unix")?;
        let token = random_hex(32);
        transaction(&self.path, |conn| {
            // Expired or spent tokens are garbage, so collect them here rather
            // than letting the table grow with every prompt the user answered.
            conn.execute(
                "DELETE FROM allow_once WHERE xite=?1 AND (consumed=1 OR issued_unix+?2<=?3)",
                params![xite, ALLOW_ONCE_TTL, issued_unix],
            )?;
            let outstanding = crate::count(
                conn,
                "SELECT COUNT(*) FROM allow_once WHERE xite=?1",
                params![xite],
            )?;
            if outstanding >= MAX_ALLOW_ONCE {
                return Err(Error::budget("outstanding allow-once token limit"));
            }
            conn.execute(
                "INSERT INTO allow_once (xite, token, declaration_digest, program, issued_unix, \
                 consumed) VALUES (?1,?2,?3,?4,?5,0)",
                params![xite, token, declaration_digest, program, issued_unix],
            )?;
            Ok(())
        })?;
        Ok(token)
    }

    /// Spend an allow-once token. Returns `true` exactly once per token, and
    /// only when the token was minted for this `xite`, `declaration_digest`
    /// and `program` and has not expired. Every other case is `false`: a
    /// token minted for a different declaration or program stays unspent,
    /// since it could still serve the run it was minted for, while an expired
    /// one is deleted. A malformed token or identifier is
    /// [`Error::Invalid`], not `false`, so a caller bug is visible.
    pub fn consume_allow_once(
        &self,
        xite: &str,
        token: &str,
        declaration_digest: &str,
        program: &str,
    ) -> Result<bool> {
        self.consume_allow_once_at(xite, token, declaration_digest, program, now_unix()?)
    }

    /// [`DurableState::consume_allow_once`] with an explicit clock, for tests.
    pub(crate) fn consume_allow_once_at(
        &self,
        xite: &str,
        token: &str,
        declaration_digest: &str,
        program: &str,
        now: u64,
    ) -> Result<bool> {
        identifier(xite)?;
        sha256_hex(token).map_err(|_| Error::invalid("invalid allow-once token"))?;
        sha256_hex(declaration_digest).map_err(|_| Error::invalid("invalid declaration digest"))?;
        identifier(program).map_err(|_| Error::invalid("invalid program"))?;
        transaction(&self.path, |conn| {
            let row: Option<(String, String, u64, i64)> = conn
                .query_row(
                    "SELECT declaration_digest, program, issued_unix, consumed FROM allow_once \
                     WHERE xite=?1 AND token=?2",
                    params![xite, token],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?;
            let Some((bound_digest, bound_program, issued_unix, consumed)) = row else {
                return Ok(false);
            };
            if consumed != 0 {
                return Ok(false);
            }
            if now < issued_unix || now >= issued_unix + ALLOW_ONCE_TTL {
                conn.execute(
                    "DELETE FROM allow_once WHERE xite=?1 AND token=?2",
                    params![xite, token],
                )?;
                return Ok(false);
            }
            if bound_digest != declaration_digest || bound_program != program {
                return Ok(false);
            }
            let changed = conn.execute(
                "UPDATE allow_once SET consumed=1 WHERE xite=?1 AND token=?2 AND consumed=0",
                params![xite, token],
            )?;
            Ok(changed == 1)
        })
    }

    /// Append one run to the xite's history and drop everything older than
    /// the newest [`MAX_RUNS`] records. No grant is required: a denied or
    /// crashed run is exactly what the operator wants to see in status.
    pub fn record_run(&self, xite: &str, run: &RunRecord) -> Result<()> {
        identifier(xite)?;
        validate_run(run)?;
        transaction(&self.path, |conn| {
            conn.execute(
                &format!(
                    "INSERT INTO runs (xite, {RUN_COLUMNS}) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
                ),
                params![
                    xite,
                    run.started_unix,
                    run.finished_unix,
                    run.program,
                    run.declaration_digest,
                    run.artifact_sha256,
                    run.input_digest,
                    run.status,
                    run.message,
                    run.cpu_seconds,
                    run.peak_rss,
                ],
            )?;
            conn.execute(
                "DELETE FROM runs WHERE xite=?1 AND id NOT IN \
                 (SELECT id FROM runs WHERE xite=?1 ORDER BY id DESC LIMIT ?2)",
                params![xite, MAX_RUNS],
            )?;
            Ok(())
        })
    }

    /// The xite's retained runs, newest first (by insertion order, which is
    /// the host's completion order; `started_unix` can tie or run backwards
    /// across a clock change and is not used for ordering).
    pub fn runs(&self, xite: &str) -> Result<Vec<RunRecord>> {
        let conn = crate::connect(&self.path)?;
        let mut statement = conn.prepare(&format!(
            "SELECT {RUN_COLUMNS} FROM runs WHERE xite=?1 ORDER BY id DESC"
        ))?;
        let mut rows = statement.query(params![xite])?;
        let mut runs = Vec::new();
        while let Some(row) = rows.next()? {
            runs.push(run_row(row)?);
        }
        Ok(runs)
    }
}
