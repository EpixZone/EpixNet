//! `epix-db` — SQLite storage for EpixNet.
//!
//! A pooled [`Database`] (rusqlite + r2d2), per-xite schemas applied from a
//! xite's `dbschema.json` ([`schema`]), and the global [`ContentDb`].

pub mod content_db;
pub mod schema;

pub use content_db::ContentDb;
pub use schema::{DbSchema, TableSchema};

use epix_core::{Error, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

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

    /// A private in-memory database (pool size 1 so the single connection — and
    /// thus the data — is shared across all `conn()` calls). For tests.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_manager(SqliteConnectionManager::memory(), 1)
    }

    fn from_manager(mgr: SqliteConnectionManager, max_size: u32) -> Result<Self> {
        // WAL + foreign keys on every checked-out connection.
        let mgr = mgr.with_init(|c| {
            c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        });
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

    /// Apply a per-xite `dbschema.json` (create tables + indexes).
    pub fn apply_schema(&self, schema: &DbSchema) -> Result<()> {
        let conn = self.conn()?;
        schema::apply(&conn, schema)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_dbschema_json_and_queries() {
        let json = r#"{
            "db_name": "TestZite", "db_file": "db/db.db", "version": 1,
            "tables": {
                "post": {
                    "cols": [["post_id","INTEGER"],["title","TEXT"],["date_added","INTEGER"]],
                    "indexes": ["CREATE INDEX IF NOT EXISTS post_date ON post(date_added)"],
                    "schema_changed": 1
                }
            }
        }"#;
        let schema = DbSchema::from_json(json).unwrap();
        assert_eq!(schema.db_name, "TestZite");
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
    fn content_db_tracks_xite_files() {
        let cdb = ContentDb::open(Database::open_in_memory().unwrap()).unwrap();
        let xite = cdb.add_xite("epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t").unwrap();
        // add_xite is idempotent.
        assert_eq!(xite, cdb.add_xite("epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t").unwrap());

        cdb.set_content(xite, "content.json", 1777, 9120).unwrap();
        cdb.set_content(xite, "data/users/content.json", 1700, 50).unwrap();
        assert_eq!(cdb.get_content(xite, "content.json").unwrap(), Some((1777, 9120)));
        assert_eq!(cdb.get_content(xite, "missing.json").unwrap(), None);

        // Upsert updates in place.
        cdb.set_content(xite, "content.json", 1888, 9200).unwrap();
        assert_eq!(cdb.get_content(xite, "content.json").unwrap(), Some((1888, 9200)));

        let listed = cdb.list_content(xite).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].0, "content.json");
    }
}
