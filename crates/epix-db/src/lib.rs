//! `epix-db` - SQLite storage for EpixNet.
//!
//! A pooled [`Database`] (rusqlite + r2d2), per-xite schemas applied from a
//! xite's `dbschema.json` ([`schema`]), and the global [`ContentDb`].

pub mod content_db;
pub mod populate;
pub mod schema;

pub use content_db::ContentDb;
pub use schema::{DbSchema, MapSettings, TableSchema, ToTable};

use epix_core::{Error, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde_json::Value;

pub type PooledConn = r2d2::PooledConnection<SqliteConnectionManager>;

/// A connection pool over a single SQLite database.
#[derive(Clone)]
pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

impl Database {
    /// Open (creating if needed) a file-backed database.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let mgr = SqliteConnectionManager::file(path.as_ref());
        Self::from_manager(mgr, 8)
    }

    /// A private in-memory database (pool size 1 so the single connection - and
    /// thus the data - is shared across all `conn()` calls). For tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_manager(SqliteConnectionManager::memory(), 1)
    }

    fn from_manager(mgr: SqliteConnectionManager, max_size: u32) -> Result<Self> {
        // WAL + foreign keys on every checked-out connection.
        let mgr =
            mgr.with_init(|c| c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;"));
        let pool = Pool::builder()
            .max_size(max_size)
            .build(mgr)
            .map_err(|e| Error::Db(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Check out a pooled connection.
    pub fn conn(&self) -> Result<PooledConn> {
        self.pool.get().map_err(|e| Error::Db(e.to_string()))
    }

    /// Apply a per-xite `dbschema.json` (create tables + indexes + meta-tables).
    pub fn apply_schema(&self, schema: &DbSchema) -> Result<()> {
        let conn = self.conn()?;
        schema::apply(&conn, schema)
    }

    /// Populate the db from JSON data files under `db_dir`, per the schema's
    /// `maps`. Returns the number of files ingested.
    pub fn populate(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate(&conn, schema, db_dir.as_ref())
    }

    /// Populate, skipping data files whose path contains one of `exclude`
    /// (ContentFilter mute enforcement - muted authors' files are left out).
    pub fn populate_filtered(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
        exclude: &[String],
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate_xite_filtered(&conn, schema, db_dir.as_ref(), "", exclude, "")
    }

    /// Populate only the supplied normalized paths under `db_dir`, skipping
    /// paths matched by `exclude`. The directory is not walked.
    pub fn populate_paths_filtered(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
        rel_paths: &[String],
        exclude: &[String],
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate_xite_paths_filtered(
            &conn,
            schema,
            db_dir.as_ref(),
            "",
            rel_paths,
            exclude,
            "",
        )
    }

    /// Route ONE data file under `db_dir` into the db, per the schema's `maps`
    /// - EpixNet's `Db.updateJson` for a single file, so a file is queryable
    /// the moment it arrives instead of after a full-tree rescan. `rel_path`
    /// is the file's path relative to `db_dir`; `path_prefix` (a merged
    /// xite's address, or empty) is prepended for the regex match, and `xite`
    /// tags the rows for a version-3 merger db. Returns whether any map
    /// matched (false too when the file is missing or not JSON, mirroring the
    /// full scan, which skips such files).
    pub fn update_file(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
        rel_path: &str,
        xite: &str,
        path_prefix: &str,
    ) -> Result<bool> {
        let Ok(bytes) = std::fs::read(db_dir.as_ref().join(rel_path)) else {
            return Ok(false);
        };
        let Ok(data) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(false);
        };
        let matched_path = if path_prefix.is_empty() {
            rel_path.to_string()
        } else {
            format!("{path_prefix}/{rel_path}")
        };
        let conn = self.conn()?;
        populate::update_json(&conn, schema, &matched_path, &data, xite)
    }

    /// Populate a version-3 merger db from one merged xite's files, tagging the
    /// rows with `xite`. Every file's path is matched as `<xite>/<relpath>`, so
    /// the merger's address-scoped dbschema regexes match. Call once per
    /// merged xite.
    pub fn populate_xite(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
        xite: &str,
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate_xite_prefixed(&conn, schema, db_dir.as_ref(), xite, xite)
    }

    /// Populate a version-3 merger db from only the supplied normalized paths
    /// under one merged xite. Paths are matched as `<xite>/<relative path>`.
    pub fn populate_xite_paths(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
        xite: &str,
        rel_paths: &[String],
    ) -> Result<usize> {
        self.populate_xite_paths_filtered(schema, db_dir, xite, rel_paths, &[])
    }

    /// Populate a version-3 merger db from only the supplied normalized paths,
    /// excluding paths that contain one of the supplied author identifiers.
    pub fn populate_xite_paths_filtered(
        &self,
        schema: &DbSchema,
        db_dir: impl AsRef<std::path::Path>,
        xite: &str,
        rel_paths: &[String],
        exclude: &[String],
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate_xite_paths_filtered(
            &conn,
            schema,
            db_dir.as_ref(),
            xite,
            rel_paths,
            exclude,
            xite,
        )
    }

    /// Populate an ordinary xite database from already-verified JSON values.
    pub fn populate_values_filtered(
        &self,
        schema: &DbSchema,
        values: &[(String, Value)],
        exclude: &[String],
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate_values_filtered(&conn, schema, "", values, exclude, "")
    }

    /// Populate a version-3 merger database from already-verified JSON values
    /// belonging to one source xite.
    pub fn populate_xite_values_filtered(
        &self,
        schema: &DbSchema,
        xite: &str,
        values: &[(String, Value)],
        exclude: &[String],
    ) -> Result<usize> {
        let conn = self.conn()?;
        populate::populate_values_filtered(&conn, schema, xite, values, exclude, xite)
    }

    /// Run a read query, returning rows as JSON objects.
    pub fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Value>> {
        let conn = self.conn()?;
        populate::query(&conn, sql, params)
    }

    /// Run a write statement, returning `last_insert_rowid`.
    pub fn execute(&self, sql: &str, params: &[Value]) -> Result<i64> {
        let conn = self.conn()?;
        populate::execute(&conn, sql, params)
    }

    /// Run several statements with no params (DDL/schema setup).
    pub fn execute_batch(&self, sql: &str) -> Result<()> {
        self.conn()?
            .execute_batch(sql)
            .map_err(|e| Error::Db(e.to_string()))
    }

    /// Run a read query whose params are a JSON value (object = named binds,
    /// array = positional). The SQL here is trusted (built by the node, or an
    /// already SELECT-checked `chartDbQuery`); for page-supplied SQL use
    /// [`query_untrusted`](Self::query_untrusted).
    pub fn query_value(&self, sql: &str, params: &Value) -> Result<Vec<Value>> {
        let conn = self.conn()?;
        populate::query_value(&conn, sql, params)
    }

    /// Run a query whose SQL comes from an untrusted source - the `dbQuery` WS
    /// command, where a served xite's page sends the SQL verbatim. A read-only
    /// authorizer is installed for the call so the engine refuses anything but
    /// reads: no INSERT/UPDATE/DELETE, no DDL, no PRAGMA, and - the dangerous
    /// one - no `ATTACH`. Without this, `dbQuery` runs arbitrary SQL, and
    /// `ATTACH DATABASE '<path>'` lets a caller create or overwrite a SQLite
    /// file anywhere the node can write. On the public gateway, where `dbQuery`
    /// is neither admin- nor owner-gated, that is a pre-auth arbitrary file
    /// write reachable by any visitor bound to any served xite.
    ///
    /// Enforcement is at the SQLite engine (a statement blocklist is bypassable);
    /// the authorizer is cleared before the pooled connection goes back so the
    /// node's own writes (populate/update) are never affected.
    pub fn query_untrusted(&self, sql: &str, params: &Value) -> Result<Vec<Value>> {
        let conn = self.conn()?;
        conn.authorizer(Some(read_only_authorizer));
        // Cleared on every exit path (including `?`), before `conn` is returned
        // to the pool, so the next checkout starts unrestricted.
        let _restore = AuthorizerReset(&conn);
        populate::query_value(&conn, sql, params)
    }
}

/// Authorizer callback for [`Database::query_untrusted`]: allow only read
/// actions (reads, the SELECT itself, scalar/aggregate functions, and recursive
/// CTEs) and deny everything else. The catch-all covers writes, DDL, PRAGMA,
/// transaction control, and ATTACH/DETACH - `Deny` turns each into a query
/// error rather than silently ignoring it.
fn read_only_authorizer(ctx: rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization {
    use rusqlite::hooks::{AuthAction, Authorization};
    match ctx.action {
        AuthAction::Select
        | AuthAction::Read { .. }
        | AuthAction::Function { .. }
        | AuthAction::Recursive => Authorization::Allow,
        _ => Authorization::Deny,
    }
}

/// Clears the authorizer on drop, so a pooled connection never carries the
/// read-only restriction back into the pool (which would block the node's own
/// populate/update writes on the shared in-memory connection).
struct AuthorizerReset<'a>(&'a rusqlite::Connection);

impl Drop for AuthorizerReset<'_> {
    fn drop(&mut self) {
        self.0
            .authorizer::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>(
                None,
            );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_dbschema_json_and_queries() {
        let json = r#"{
            "db_name": "TestXite", "db_file": "db/db.db", "version": 1,
            "tables": {
                "post": {
                    "cols": [["post_id","INTEGER"],["title","TEXT"],["date_added","INTEGER"]],
                    "indexes": ["CREATE INDEX IF NOT EXISTS post_date ON post(date_added)"],
                    "schema_changed": 1
                }
            }
        }"#;
        let schema = DbSchema::from_json(json).unwrap();
        assert_eq!(schema.db_name, "TestXite");
        assert_eq!(schema.tables["post"].cols.len(), 3);

        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        // Idempotent.
        db.apply_schema(&schema).unwrap();

        let conn = db.conn().unwrap();
        conn.execute(
            "INSERT INTO post (post_id, title, date_added) VALUES (1, 'hi', 100)",
            [],
        )
        .unwrap();
        let title: String = conn
            .query_row("SELECT title FROM post WHERE post_id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(title, "hi");
    }

    #[test]
    fn query_untrusted_reads_but_blocks_writes_and_attach() {
        use serde_json::json;
        let db = Database::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE post (post_id INTEGER, title TEXT);
             INSERT INTO post VALUES (1, 'hi'), (2, 'yo');",
        )
        .unwrap();

        // Reads work, params bind, and functions/CTEs are allowed.
        let rows = db
            .query_untrusted("SELECT title FROM post WHERE post_id = ?", &json!([1]))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["title"], "hi");
        db.query_untrusted("SELECT COUNT(*) AS n FROM post", &Value::Null)
            .unwrap();

        // Writes and DDL are refused by the authorizer.
        assert!(db
            .query_untrusted("INSERT INTO post VALUES (3, 'no')", &Value::Null)
            .is_err());
        assert!(db
            .query_untrusted("UPDATE post SET title = 'x'", &Value::Null)
            .is_err());
        assert!(db
            .query_untrusted("DELETE FROM post", &Value::Null)
            .is_err());
        assert!(db
            .query_untrusted("CREATE TABLE pwned (x)", &Value::Null)
            .is_err());
        // The data is untouched by the rejected writes.
        let after = db
            .query_untrusted("SELECT COUNT(*) AS n FROM post", &Value::Null)
            .unwrap();
        assert_eq!(after[0]["n"].as_i64().unwrap(), 2);

        // The file-write primitive: ATTACH to an on-disk path must be refused,
        // and no file may be created for it.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("pwned.db");
        let attach = format!("ATTACH DATABASE '{}' AS x", target.display());
        assert!(db.query_untrusted(&attach, &Value::Null).is_err());
        assert!(!target.exists(), "ATTACH must not create a file on disk");

        // The authorizer was cleared: the node's own connection can still write.
        db.execute_batch("INSERT INTO post VALUES (4, 'ok')")
            .unwrap();
    }

    #[test]
    fn content_db_tracks_xite_files() {
        let cdb = ContentDb::open(Database::open_in_memory().unwrap()).unwrap();
        let xite = cdb
            .add_xite("epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g")
            .unwrap();
        // add_xite is idempotent.
        assert_eq!(
            xite,
            cdb.add_xite("epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g")
                .unwrap()
        );

        cdb.set_content(xite, "content.json", 1777, 9120).unwrap();
        cdb.set_content(xite, "data/users/content.json", 1700, 50)
            .unwrap();
        assert_eq!(
            cdb.get_content(xite, "content.json").unwrap(),
            Some((1777, 9120))
        );
        assert_eq!(cdb.get_content(xite, "missing.json").unwrap(), None);

        // Upsert updates in place.
        cdb.set_content(xite, "content.json", 1888, 9200).unwrap();
        assert_eq!(
            cdb.get_content(xite, "content.json").unwrap(),
            Some((1888, 9200))
        );

        let listed = cdb.list_content(xite).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].0, "content.json");
    }

    #[test]
    fn dict_key_col_survives_import_cols_filter() {
        // EpixMail's schema: conversations is a dict keyed by conv_id, with
        // key_col storing the dict key and import_cols listing only the VALUE
        // fields (EpixNet filters values first, then adds the key). The key
        // column must land even though import_cols doesn't mention it.
        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Mail", "db_file": "db/db.db", "version": 2,
              "maps": {
                ".+/data.json": {
                  "to_table": [{"node": "conversations", "table": "conversation",
                                "key_col": "conv_id",
                                "import_cols": ["peer_xid", "established"]}]
                }
              },
              "tables": {
                "conversation": { "cols": [["conv_id","TEXT"],["peer_xid","TEXT"],
                                            ["established","INTEGER"],["json_id","INTEGER"]] }
              }
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("data/users/facts.epix");
        std::fs::create_dir_all(&user).unwrap();
        std::fs::write(
            user.join("data.json"),
            r#"{ "conversations": {
                   "abc123": { "peer_xid": "mud.epix", "established": 100,
                               "messages": { "1": {"ct": "x"} } } } }"#,
        )
        .unwrap();
        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        db.populate(&schema, dir.path()).unwrap();
        let rows = db
            .query("SELECT conv_id, peer_xid FROM conversation", &[])
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["conv_id"], serde_json::json!("abc123"));
        assert_eq!(rows[0]["peer_xid"], serde_json::json!("mud.epix"));
    }

    #[test]
    fn query_ignores_unreferenced_named_params() {
        // Python's sqlite3 ignores dict keys the query never references;
        // EpixPost sends helper keys (`{"directories": "all"}`) alongside SQL
        // that has no such placeholder, and the page dies if this errors.
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn().unwrap();
        conn.execute("CREATE TABLE t (id INTEGER, name TEXT)", [])
            .unwrap();
        conn.execute("INSERT INTO t VALUES (1, 'a'), (2, 'b')", [])
            .unwrap();
        drop(conn);

        let rows = db
            .query_value(
                "SELECT * FROM t WHERE id = :id",
                &serde_json::json!({ "id": 1, "directories": "all", "unused_list": [1, 2] }),
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"], serde_json::json!("a"));

        // A dict with no referenced keys at all still runs the query.
        let rows = db
            .query_value(
                "SELECT * FROM t",
                &serde_json::json!({ "directories": "all" }),
            )
            .unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn populates_from_data_files_and_queries() {
        // A blog-style schema: data/<user>/data.json -> post table + keyvalue.
        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Blog", "db_file": "db/db.db", "version": 2,
              "maps": {
                "data/.*/data.json": {
                  "to_table": [{"node": "posts", "table": "post"}],
                  "to_keyvalue": ["next_post_id"]
                }
              },
              "tables": {
                "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["date_added","INTEGER"],["json_id","INTEGER"]],
                          "indexes": ["CREATE INDEX IF NOT EXISTS post_date ON post(date_added)"] }
              }
            }"#,
        )
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let user = dir.path().join("data/alice");
        std::fs::create_dir_all(&user).unwrap();
        std::fs::write(
            user.join("data.json"),
            r#"{ "next_post_id": 3,
                 "posts": [ {"post_id": 1, "title": "Hello", "date_added": 100},
                            {"post_id": 2, "title": "World", "date_added": 200, "extra": "ignored"} ] }"#,
        )
        .unwrap();
        // A non-matching file is skipped.
        std::fs::write(
            dir.path().join("content.json"),
            r#"{"posts":[{"post_id":99}]}"#,
        )
        .unwrap();

        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        let ingested = db.populate(&schema, dir.path()).unwrap();
        assert_eq!(ingested, 1, "only data/alice/data.json matched");

        // Rows landed, unknown col (`extra`) filtered, json_id linked.
        let rows = db
            .query(
                "SELECT post_id, title, date_added FROM post ORDER BY post_id",
                &[],
            )
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["title"], "Hello");
        assert_eq!(rows[1]["title"], "World");
        assert_eq!(rows[1]["date_added"], 200);

        // Parameterized query works.
        let one = db
            .query(
                "SELECT title FROM post WHERE post_id = ?1",
                &[Value::from(2)],
            )
            .unwrap();
        assert_eq!(one[0]["title"], "World");

        // keyvalue captured.
        let kv = db
            .query("SELECT value FROM keyvalue WHERE key = 'next_post_id'", &[])
            .unwrap();
        assert_eq!(kv[0]["value"], 3);

        // Re-populating is idempotent (INSERT OR REPLACE + DELETE by json_id).
        db.populate(&schema, dir.path()).unwrap();
        let again = db.query("SELECT COUNT(*) AS n FROM post", &[]).unwrap();
        assert_eq!(again[0]["n"], 2);
    }

    #[test]
    fn path_population_ingests_only_listed_json_and_applies_exclusion_first() {
        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Allowed", "db_file": "db/db.db", "version": 2,
              "maps": {
                "data/.*/data.json": {
                  "to_table": [{"node": "posts", "table": "post"}]
                }
              },
              "tables": {
                "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] }
              }
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        for author in ["allowed", "unlisted", "blocked"] {
            std::fs::create_dir_all(dir.path().join(format!("data/{author}"))).unwrap();
            std::fs::write(
                dir.path().join(format!("data/{author}/data.json")),
                format!(r#"{{"posts":[{{"post_id":1,"title":"{author}"}}]}}"#),
            )
            .unwrap();
        }

        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        let paths = vec![
            "data/allowed/data.json".to_string(),
            "data/blocked/data.json".to_string(),
        ];
        let excluded = vec!["data/blocked/".to_string()];
        let ingested = db
            .populate_paths_filtered(&schema, dir.path(), &paths, &excluded)
            .unwrap();
        assert_eq!(ingested, 1);
        let rows = db.query("SELECT title FROM post", &[]).unwrap();
        assert_eq!(rows, vec![serde_json::json!({"title": "allowed"})]);
    }

    #[test]
    fn xite_path_population_preserves_v3_prefix_and_json_shape() {
        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Merger", "db_file": "db/db.db", "version": 3,
              "maps": {
                ".+/data/users/.+/data.json": {
                  "to_table": [{"node": "posts", "table": "post"}]
                }
              },
              "tables": {
                "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] }
              }
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let user_dir = dir.path().join("data/users/alice");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(
            user_dir.join("data.json"),
            r#"{"posts":[{"post_id":7,"title":"prefixed"}]}"#,
        )
        .unwrap();

        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        let paths = vec!["data/users/alice/data.json".to_string()];
        let ingested = db
            .populate_xite_paths(&schema, dir.path(), "epix1child", &paths)
            .unwrap();
        assert_eq!(ingested, 1);
        let rows = db
            .query(
                "SELECT p.title, j.site, j.directory, j.file_name FROM post p JOIN json j USING(json_id)",
                &[],
            )
            .unwrap();
        assert_eq!(
            rows,
            vec![serde_json::json!({
                "title": "prefixed",
                "site": "epix1child",
                "directory": "data/users/alice",
                "file_name": "data.json"
            })]
        );
    }

    #[test]
    fn xite_path_population_treats_a_missing_db_dir_as_empty_after_validation() {
        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Merger", "db_file": "db/db.db", "version": 3,
              "maps": {
                ".+/data/users/.+/data.json": {
                  "to_table": [{"node": "posts", "table": "post"}]
                }
              },
              "tables": {
                "post": { "cols": [["post_id","INTEGER"],["json_id","INTEGER"]] }
              }
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let missing_db_dir = dir.path().join("not-downloaded");
        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();

        let valid = vec!["data/users/alice/data.json".to_string()];
        let ingested = db
            .populate_xite_paths_filtered(&schema, &missing_db_dir, "epix1child", &valid, &[])
            .unwrap();
        assert_eq!(ingested, 0);

        let invalid = vec!["../outside.json".to_string()];
        assert!(db
            .populate_xite_paths_filtered(&schema, &missing_db_dir, "epix1child", &invalid, &[],)
            .is_err());
    }

    #[test]
    fn path_population_rejects_non_normal_paths_before_ingesting() {
        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Safe", "db_file": "db/db.db", "version": 2,
              "maps": {"data/.*/data.json": {"to_table": [{"node": "posts", "table": "post"}]}},
              "tables": {"post": {"cols": [["post_id","INTEGER"],["json_id","INTEGER"]]}}
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("data/alice")).unwrap();
        std::fs::write(
            dir.path().join("data/alice/data.json"),
            r#"{"posts":[{"post_id":1}]}"#,
        )
        .unwrap();
        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        let paths = vec![
            "data/alice/data.json".to_string(),
            "../outside.json".to_string(),
        ];
        assert!(db
            .populate_paths_filtered(&schema, dir.path(), &paths, &[])
            .is_err());
        let rows = db.query("SELECT COUNT(*) AS n FROM post", &[]).unwrap();
        assert_eq!(rows[0]["n"], 0);
    }

    #[cfg(unix)]
    #[test]
    fn path_population_rejects_symlink_targets() {
        use std::os::unix::fs::symlink;

        let schema = DbSchema::from_json(
            r#"{
              "db_name": "Safe", "db_file": "db/db.db", "version": 2,
              "maps": {"data/.*/data.json": {"to_table": [{"node": "posts", "table": "post"}]}},
              "tables": {"post": {"cols": [["post_id","INTEGER"],["json_id","INTEGER"]]}}
            }"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("data.json"),
            r#"{"posts":[{"post_id":9}]}"#,
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("data/alice")).unwrap();
        symlink(
            outside.path().join("data.json"),
            dir.path().join("data/alice/data.json"),
        )
        .unwrap();
        let db = Database::open_in_memory().unwrap();
        db.apply_schema(&schema).unwrap();
        let paths = vec!["data/alice/data.json".to_string()];
        assert!(db
            .populate_paths_filtered(&schema, dir.path(), &paths, &[])
            .is_err());
    }
}
