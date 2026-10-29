//! Persistent, disposable projections of already verified merger inputs.
//!
//! The caller owns cryptographic verification, authority invalidation, and the
//! private cache path. Versions must bind both accepted bytes and their complete
//! authorization context. This layer atomically compares those versions and
//! updates source ownership and SQL rows. It never treats a disk cache as an
//! authorization decision.

use crate::{populate, Database, DbSchema};
use epix_core::{Error, Result};
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

const FORMAT: i64 = 1;
const INVALID_CACHE: &str = "invalid derived cache: ";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceVersion {
    pub digest: String,
    pub authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub hub: String,
    pub path: String,
    pub version: SourceVersion,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaMetrics {
    pub changed_sources: u64,
    pub skipped_sources: u64,
    pub replayed_sources: u64,
    pub replayed_bytes: u64,
    pub affected_targets: u64,
    pub sql_changes: u64,
}

#[derive(Clone)]
pub struct DerivedIndex {
    db: Database,
    schema: Arc<DbSchema>,
    routes: Arc<Vec<(Regex, Option<String>)>>,
    tables: Arc<BTreeSet<String>>,
}

fn db_err(error: rusqlite::Error) -> Error {
    Error::Db(error.to_string())
}

fn invalid(message: &str) -> Error {
    Error::Db(message.to_string())
}

fn invalid_cache(message: &str) -> Error {
    Error::Db(format!("{INVALID_CACHE}{message}"))
}

fn cache_sql_error(error: rusqlite::Error) -> Error {
    match &error {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            invalid_cache(&error.to_string())
        }
        _ => db_err(error),
    }
}

type Layout = Vec<(String, String, String, Option<String>)>;

fn layout(conn: &Connection) -> rusqlite::Result<Layout> {
    let mut stmt =
        conn.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get::<_, String>(1)?,
            row.get(2)?,
            row.get(3)?,
        ))
    })?;
    rows.filter_map(|row| match row {
        Ok(row) if row.1.to_ascii_lowercase().starts_with("sqlite_") => None,
        other => Some(other),
    })
    .collect()
}

fn initialize(
    conn: &Connection,
    schema: &DbSchema,
    tables: &BTreeSet<String>,
    serialized: &str,
    context: &str,
) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE __epix_derived_meta (
            id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL,
            schema_json TEXT NOT NULL, context TEXT NOT NULL);
         CREATE TABLE __epix_sources (
            hub TEXT NOT NULL, path TEXT NOT NULL, digest TEXT NOT NULL,
            authority TEXT NOT NULL, value TEXT NOT NULL,
            PRIMARY KEY(hub,path));
         CREATE TABLE __epix_source_targets (
            hub TEXT NOT NULL, source_path TEXT NOT NULL, target_path TEXT NOT NULL,
            PRIMARY KEY(hub,source_path,target_path),
            FOREIGN KEY(hub,source_path) REFERENCES __epix_sources(hub,path) ON DELETE CASCADE);
         CREATE INDEX __epix_targets_reverse ON __epix_source_targets(hub,target_path,source_path);",
    ).map_err(db_err)?;
    crate::schema::apply(conn, schema)?;
    for table in tables {
        conn.execute_batch(&format!(
            "CREATE INDEX \"__epix_source_rows_{table}\" ON \"{table}\"(json_id);"
        ))
        .map_err(db_err)?;
    }
    conn.execute(
        "INSERT INTO __epix_derived_meta VALUES(1,?1,?2,?3)",
        params![FORMAT, serialized, context],
    )
    .map_err(db_err)?;
    Ok(())
}

fn validate_metadata(conn: &Connection, serialized: &str, context: &str) -> Result<()> {
    let stored: Option<(i64, String, String)> = conn
        .query_row(
            "SELECT format,schema_json,context FROM __epix_derived_meta WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(cache_sql_error)?;
    if stored != Some((FORMAT, serialized.to_string(), context.to_string())) {
        return Err(invalid_cache("format, schema or context mismatch"));
    }
    Ok(())
}

fn validate_cache(
    conn: &Connection,
    serialized: &str,
    context: &str,
    expected: &Layout,
) -> Result<()> {
    let check: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(cache_sql_error)?;
    if check != "ok" {
        return Err(invalid_cache(&check));
    }
    if &layout(conn).map_err(cache_sql_error)? != expected {
        return Err(invalid_cache(
            "missing or altered internal/projection table or index",
        ));
    }
    validate_metadata(conn, serialized, context)
}

fn validate_source(hub: &str, path: &str) -> Result<()> {
    if hub.is_empty() || hub.contains(['/', '\\', '\0']) || hub == "." || hub == ".." {
        return Err(invalid("invalid derived source hub"));
    }
    if path.is_empty()
        || path.contains(['\\', '\0'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid("invalid derived source path"));
    }
    Ok(())
}

impl DerivedIndex {
    /// Open a node-private cache. An existing cache must match the exact schema
    /// and caller context, even when `schema.version` has not changed. A mismatch
    /// leaves the old cache untouched; open a new generation at another path.
    pub fn open(path: impl AsRef<Path>, schema: &DbSchema, context: &str) -> Result<Self> {
        if schema.version != 3 {
            return Err(invalid(
                "persistent derived indexes require a version-3 merger schema",
            ));
        }
        let mut routes = Vec::new();
        let mut tables = BTreeSet::new();
        for (pattern, map) in &schema.maps {
            let regex = Regex::new(&format!("^(?:{pattern})"))
                .map_err(|error| invalid(&error.to_string()))?;
            if let Some(file_name) = &map.file_name {
                validate_source("hub", file_name)?;
            }
            routes.push((regex, map.file_name.clone()));
            for entry in &map.to_table {
                let table = entry.table();
                if table == "json" || table == "keyvalue" || crate::internal_identifier(table) {
                    return Err(invalid("reserved derived projection table"));
                }
                if !schema.tables.get(table).is_some_and(|definition| {
                    definition.cols.iter().any(|(name, _)| name == "json_id")
                }) {
                    return Err(invalid("derived projection table requires json_id"));
                }
                tables.insert(table.to_string());
            }
        }
        let serialized = serde_json::to_string(schema)?;
        // Validate application DDL separately so an invalid schema never gets
        // classified as a disposable-cache failure.
        let reference = Connection::open_in_memory().map_err(db_err)?;
        initialize(&reference, schema, &tables, &serialized, context)?;
        let expected_layout = layout(&reference).map_err(db_err)?;
        // Acquire before inspecting SQLite: a retired generation's final reader
        // may be closing concurrently, and owns deletion until this lease joins.
        let lease = crate::cache::CacheLease::acquire(path.as_ref())?;
        let path = lease.path();
        if path
            .metadata()
            .map(|metadata| metadata.len() > 0)
            .unwrap_or(false)
        {
            let inspect =
                Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(cache_sql_error)?;
            validate_cache(&inspect, &serialized, context, &expected_layout)?;
        }
        let db = Database::open_derived(lease.clone())?;
        {
            let mut conn = db.conn()?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_err)?;
            let present: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='__epix_derived_meta')",
                [], |row| row.get(0),
            ).map_err(db_err)?;
            if present {
                validate_metadata(&tx, &serialized, context)?;
            } else {
                let occupied: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')",
                    [], |row| row.get(0),
                ).map_err(db_err)?;
                if occupied {
                    return Err(invalid_cache("unrecognized database layout"));
                }
                initialize(&tx, schema, &tables, &serialized, context)?;
            }
            tx.commit().map_err(db_err)?;
        }
        lease.revive()?;
        Ok(Self {
            db,
            schema: Arc::new(schema.clone()),
            routes: Arc::new(routes),
            tables: Arc::new(tables),
        })
    }

    pub fn database(&self) -> Database {
        self.db.clone()
    }

    /// Mark this private cache for deletion once all database, pooled reader,
    /// and worker handles close. Normal shutdown leaves unretired caches intact.
    /// A successful same-path open with matching schema/context can revive it.
    pub fn retire(&self) -> Result<()> {
        self.db.retire_derived()
    }

    /// Remove a disposable cache and sidecars only when no live leased handles
    /// use its path. The caller must restrict `path` to its node-private cache
    /// directory. `false` means cleanup must wait for active readers/workers.
    pub fn discard_cache(path: impl AsRef<Path>) -> Result<bool> {
        crate::cache::CacheLease::discard(path.as_ref())
    }

    /// Only errors carrying this marker permit a caller to discard its private
    /// derived cache and retry once. Invalid schemas and source conflicts do not.
    pub fn is_recoverable_cache_error(error: &Error) -> bool {
        matches!(error, Error::Db(message) if message.starts_with(INVALID_CACHE))
    }

    /// Explicit repair, not the ordinary update path. The caller must withdraw
    /// every query receipt and reverify sources before exposing this generation.
    /// Foreign-key checks are deferred until all projections are empty.
    pub fn reset(&self) -> Result<DeltaMetrics> {
        let mut conn = self.db.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_err)?;
        let changed_sources = tx
            .query_row("SELECT COUNT(*) FROM __epix_sources", [], |row| row.get(0))
            .map_err(db_err)?;
        let affected_targets = tx
            .query_row("SELECT COUNT(*) FROM json", [], |row| row.get(0))
            .map_err(db_err)?;
        let before = tx.total_changes();
        tx.execute_batch("PRAGMA defer_foreign_keys=ON; DELETE FROM __epix_source_targets; DELETE FROM __epix_sources;").map_err(db_err)?;
        for table in self
            .schema
            .tables
            .keys()
            .filter(|table| table.as_str() != "json" && table.as_str() != "keyvalue")
        {
            tx.execute(&format!("DELETE FROM \"{table}\""), [])
                .map_err(db_err)?;
        }
        tx.execute_batch("DELETE FROM json; DELETE FROM keyvalue WHERE json_id <> 0;")
            .map_err(db_err)?;
        let sql_changes = tx.total_changes() - before;
        tx.commit().map_err(db_err)?;
        Ok(DeltaMetrics {
            changed_sources,
            affected_targets,
            sql_changes,
            ..Default::default()
        })
    }

    /// Whether this physical source matches any mapping. Unmatched app JSON is
    /// not retained in the ledger. Matching uses the same hub-prefixed path as
    /// the existing merger population path.
    pub fn matches_source(&self, hub: &str, path: &str) -> Result<bool> {
        Ok(!self.targets(hub, path)?.is_empty())
    }

    pub fn source(&self, hub: &str, path: &str) -> Result<Option<SourceVersion>> {
        validate_source(hub, path)?;
        let conn = self.db.conn()?;
        source_version(&conn, hub, path)
    }

    /// Metadata only, suitable for reconciliation without reading source JSON.
    pub fn sources(&self, hub: &str) -> Result<Vec<SourceEntry>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT hub,path,digest,authority FROM __epix_sources WHERE hub=?1 ORDER BY path",
            )
            .map_err(db_err)?;
        source_entries(&mut stmt, [hub])
    }

    pub fn sources_all(&self) -> Result<Vec<SourceEntry>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare("SELECT hub,path,digest,authority FROM __epix_sources ORDER BY hub,path")
            .map_err(db_err)?;
        source_entries(&mut stmt, [])
    }

    /// Compare and replace one already verified physical input. `None` requires
    /// absence; an expected version must match exactly, including no-op writes.
    pub fn apply_source(
        &self,
        hub: &str,
        path: &str,
        version: &SourceVersion,
        value: &Value,
        expected: Option<&SourceVersion>,
    ) -> Result<DeltaMetrics> {
        let targets = self.targets(hub, path)?;
        if version.digest.is_empty() || version.authority.is_empty() {
            return Err(invalid(
                "derived source version must bind digest and authority",
            ));
        }
        if targets.is_empty() {
            if expected.is_some() {
                return Err(invalid("derived source compare-and-swap conflict"));
            }
            return Ok(DeltaMetrics {
                skipped_sources: 1,
                ..Default::default()
            });
        }
        let serialized = serde_json::to_string(value)?;
        self.mutate(hub, path, Some((version, &serialized, targets)), expected)
    }

    /// Remove only the version the caller verified as obsolete. A concurrent
    /// replacement cannot be deleted by an earlier reconciliation pass.
    pub fn remove_source(
        &self,
        hub: &str,
        path: &str,
        expected: &SourceVersion,
    ) -> Result<DeltaMetrics> {
        validate_source(hub, path)?;
        self.mutate(hub, path, None, Some(expected))
    }

    fn targets(&self, hub: &str, path: &str) -> Result<BTreeSet<String>> {
        validate_source(hub, path)?;
        let matched = format!("{hub}/{path}");
        let directory = path.rsplit_once('/').map(|(directory, _)| directory);
        let mut targets = BTreeSet::new();
        for (regex, file_name) in self.routes.iter() {
            if !regex.is_match(&matched) {
                continue;
            }
            targets.insert(path.to_string());
            if let Some(file_name) = file_name {
                targets.insert(match directory {
                    Some(directory) => format!("{directory}/{file_name}"),
                    None => file_name.clone(),
                });
            }
        }
        Ok(targets)
    }

    fn mutate(
        &self,
        hub: &str,
        path: &str,
        replacement: Option<(&SourceVersion, &str, BTreeSet<String>)>,
        expected: Option<&SourceVersion>,
    ) -> Result<DeltaMetrics> {
        let conn = self.db.conn()?;
        // TEMP triggers apply to this checked-out connection only. They prevent
        // INSERT OR REPLACE from deleting another logical source target through
        // a global UNIQUE index, while preserving same-target replacement.
        let guards = ReplacementGuards::install(&conn, &self.tables)?;
        let result = (|| {
            let tx = rusqlite::Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)
                .map_err(db_err)?;
            let current = source_version(&tx, hub, path)?;
            if current.as_ref() != expected {
                return Err(invalid("derived source compare-and-swap conflict"));
            }
            if let Some((version, serialized, _)) = &replacement {
                match reuse_projection(&tx, hub, path, current.as_ref(), version, serialized)? {
                    ProjectionReuse::Unchanged => {
                        return Ok(DeltaMetrics {
                            skipped_sources: 1,
                            ..Default::default()
                        });
                    }
                    ProjectionReuse::AuthorityUpdated => {
                        tx.commit().map_err(db_err)?;
                        return Ok(DeltaMetrics {
                            changed_sources: 1,
                            sql_changes: 1,
                            ..Default::default()
                        });
                    }
                    ProjectionReuse::Reproject => {}
                }
            }
            let before = tx.total_changes();
            let mut targets = source_targets(&tx, hub, path)?;
            tx.execute(
                "DELETE FROM __epix_sources WHERE hub=?1 AND path=?2",
                params![hub, path],
            )
            .map_err(db_err)?;
            if let Some((version, serialized, new_targets)) = &replacement {
                tx.execute(
                    "INSERT INTO __epix_sources(hub,path,digest,authority,value) VALUES(?1,?2,?3,?4,?5)",
                    params![hub, path, version.digest, version.authority, serialized],
                ).map_err(db_err)?;
                for target in new_targets {
                    tx.execute(
                        "INSERT INTO __epix_source_targets VALUES(?1,?2,?3)",
                        params![hub, path, target],
                    )
                    .map_err(db_err)?;
                }
                targets.extend(new_targets.iter().cloned());
            }
            let (targets, sources) = component(&tx, hub, targets)?;
            let mut metrics = DeltaMetrics {
                changed_sources: 1,
                affected_targets: targets.len() as u64,
                ..Default::default()
            };
            self.clear_targets(&tx, hub, &targets)?;
            for (source_path, serialized) in sources {
                let value: Value = serde_json::from_str(&serialized)?;
                populate::update_json_scoped(
                    &tx,
                    &self.schema,
                    &format!("{hub}/{source_path}"),
                    &value,
                    hub,
                )?;
                metrics.replayed_sources += 1;
                metrics.replayed_bytes += serialized.len() as u64;
            }
            prune_unreferenced_targets(&tx, hub, &targets)?;
            metrics.sql_changes = tx.total_changes() - before;
            tx.commit().map_err(db_err)?;
            Ok(metrics)
        })();
        // Restore connection-local behavior before returning it to the pool,
        // including after a rollback. Failure to clean up must fail the call.
        let cleanup = guards.finish();
        match (result, cleanup) {
            (Err(error), _) | (_, Err(error)) => Err(error),
            (Ok(metrics), Ok(())) => Ok(metrics),
        }
    }

    fn clear_targets(
        &self,
        conn: &Connection,
        hub: &str,
        targets: &BTreeSet<String>,
    ) -> Result<()> {
        for target in targets {
            let (directory, file_name) = target.rsplit_once('/').unwrap_or(("", target));
            let jid: Option<i64> = conn
                .query_row(
                    "SELECT json_id FROM json WHERE site=?1 AND directory=?2 AND file_name=?3",
                    params![hub, directory, file_name],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_err)?;
            let Some(jid) = jid else { continue };
            conn.execute("UPDATE temp.__epix_write_target SET json_id=?1", [jid])
                .map_err(db_err)?;
            for table in self.tables.iter() {
                conn.execute(&format!("DELETE FROM \"{table}\" WHERE json_id=?1"), [jid])
                    .map_err(db_err)?;
            }
            conn.execute("DELETE FROM keyvalue WHERE json_id=?1", [jid])
                .map_err(db_err)?;
            for column in self.schema.json_table_cols() {
                conn.execute(
                    &format!("UPDATE json SET \"{column}\"=NULL WHERE json_id=?1"),
                    [jid],
                )
                .map_err(db_err)?;
            }
        }
        Ok(())
    }
}

enum ProjectionReuse {
    Unchanged,
    AuthorityUpdated,
    Reproject,
}

/// Reuse rows only when both the input digest and accepted data are unchanged.
/// The caller retains transaction ownership, including the authority commit.
fn reuse_projection(
    conn: &Connection,
    hub: &str,
    path: &str,
    current: Option<&SourceVersion>,
    version: &SourceVersion,
    serialized: &str,
) -> Result<ProjectionReuse> {
    let Some(current) = current.filter(|current| current.digest == version.digest) else {
        return Ok(ProjectionReuse::Reproject);
    };
    let prior: String = conn
        .query_row(
            "SELECT value FROM __epix_sources WHERE hub=?1 AND path=?2",
            params![hub, path],
            |row| row.get(0),
        )
        .map_err(db_err)?;
    if current == version && prior != serialized {
        return Err(invalid(
            "derived source version reused for different accepted data",
        ));
    }
    if prior != serialized {
        return Ok(ProjectionReuse::Reproject);
    }
    if current == version {
        return Ok(ProjectionReuse::Unchanged);
    }
    conn.execute(
        "UPDATE __epix_sources SET authority=?3 WHERE hub=?1 AND path=?2",
        params![hub, path, version.authority],
    )
    .map_err(db_err)?;
    Ok(ProjectionReuse::AuthorityUpdated)
}

/// Keep stable json_ids for live aliases. Remove only targets no retained
/// source references after the component has been replayed.
fn prune_unreferenced_targets(
    conn: &Connection,
    hub: &str,
    targets: &BTreeSet<String>,
) -> Result<()> {
    for target in targets {
        let retained: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM __epix_source_targets WHERE hub=?1 AND target_path=?2)",
            params![hub, target], |row| row.get(0),
        ).map_err(db_err)?;
        if !retained {
            let (directory, file_name) = target.rsplit_once('/').unwrap_or(("", target));
            conn.execute(
                "DELETE FROM json WHERE site=?1 AND directory=?2 AND file_name=?3",
                params![hub, directory, file_name],
            )
            .map_err(db_err)?;
        }
    }
    Ok(())
}

fn source_version(conn: &Connection, hub: &str, path: &str) -> Result<Option<SourceVersion>> {
    conn.query_row(
        "SELECT digest,authority FROM __epix_sources WHERE hub=?1 AND path=?2",
        params![hub, path],
        |row| {
            Ok(SourceVersion {
                digest: row.get(0)?,
                authority: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(db_err)
}

fn source_entries<P: rusqlite::Params>(
    stmt: &mut rusqlite::Statement<'_>,
    params: P,
) -> Result<Vec<SourceEntry>> {
    stmt.query_map(params, |row| {
        Ok(SourceEntry {
            hub: row.get(0)?,
            path: row.get(1)?,
            version: SourceVersion {
                digest: row.get(2)?,
                authority: row.get(3)?,
            },
        })
    })
    .map_err(db_err)?
    .collect::<std::result::Result<_, _>>()
    .map_err(db_err)
}

fn source_targets(conn: &Connection, hub: &str, path: &str) -> Result<BTreeSet<String>> {
    let mut stmt = conn
        .prepare("SELECT target_path FROM __epix_source_targets WHERE hub=?1 AND source_path=?2")
        .map_err(db_err)?;
    let rows = stmt
        .query_map(params![hub, path], |row| row.get(0))
        .map_err(db_err)?;
    rows.collect::<std::result::Result<_, _>>().map_err(db_err)
}

/// Find only sources linked by logical json targets. A sibling alias can join
/// several paths; following both edge directions avoids erasing its other maps.
fn component(
    conn: &Connection,
    hub: &str,
    initial: BTreeSet<String>,
) -> Result<(BTreeSet<String>, BTreeMap<String, String>)> {
    let mut pending: VecDeque<_> = initial.iter().cloned().collect();
    let mut targets = initial;
    let mut sources = BTreeMap::new();
    while let Some(target) = pending.pop_front() {
        let mut stmt = conn.prepare(
            "SELECT s.path,s.value FROM __epix_source_targets t JOIN __epix_sources s ON s.hub=t.hub AND s.path=t.source_path WHERE t.hub=?1 AND t.target_path=?2 ORDER BY s.path",
        ).map_err(db_err)?;
        let rows = stmt
            .query_map(params![hub, target], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_err)?;
        for row in rows {
            let (path, value) = row.map_err(db_err)?;
            if sources.contains_key(&path) {
                continue;
            }
            for other in source_targets(conn, hub, &path)? {
                if targets.insert(other.clone()) {
                    pending.push_back(other);
                }
            }
            sources.insert(path, value);
        }
    }
    Ok((targets, sources))
}

struct ReplacementGuards<'a> {
    conn: &'a Connection,
    names: Vec<String>,
    previous_recursive: bool,
    cleaned: bool,
}

impl<'a> ReplacementGuards<'a> {
    fn install(conn: &'a Connection, tables: &BTreeSet<String>) -> Result<Self> {
        let previous_recursive = conn
            .query_row("PRAGMA recursive_triggers", [], |row| row.get(0))
            .map_err(db_err)?;
        let mut guard = Self {
            conn,
            names: Vec::new(),
            previous_recursive,
            cleaned: false,
        };
        conn.execute_batch("PRAGMA recursive_triggers=ON; CREATE TEMP TABLE __epix_write_target(json_id INTEGER); INSERT INTO temp.__epix_write_target VALUES(NULL);")
            .map_err(db_err)?;
        for table in tables {
            let name = format!("__epix_guard_{table}");
            conn.execute_batch(&format!(
                "CREATE TEMP TRIGGER \"{name}\" BEFORE DELETE ON main.\"{table}\" WHEN OLD.json_id IS NOT (SELECT json_id FROM __epix_write_target LIMIT 1) BEGIN SELECT RAISE(ABORT,'derived projection conflicts with another source target'); END;"
            )).map_err(db_err)?;
            guard.names.push(name);
        }
        Ok(guard)
    }

    fn cleanup(&mut self) -> Result<()> {
        for name in &self.names {
            self.conn
                .execute_batch(&format!("DROP TRIGGER IF EXISTS temp.\"{name}\";"))
                .map_err(db_err)?;
        }
        self.conn
            .execute_batch(&format!(
                "DROP TABLE IF EXISTS temp.__epix_write_target; PRAGMA recursive_triggers={};",
                u8::from(self.previous_recursive)
            ))
            .map_err(db_err)?;
        self.cleaned = true;
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        self.cleanup()
    }
}

impl Drop for ReplacementGuards<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}
