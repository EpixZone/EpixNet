//! The global ContentDb: tracks every site's content.json file metadata
//! (modified time + size), the index the worker/announcer consult.

use crate::Database;
use epix_core::{Error, Result};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS site (
    site_id  INTEGER PRIMARY KEY,
    address  TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS content (
    content_id INTEGER PRIMARY KEY,
    site_id    INTEGER NOT NULL REFERENCES site(site_id),
    inner_path TEXT NOT NULL,
    modified   INTEGER NOT NULL DEFAULT 0,
    size       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(site_id, inner_path)
);
CREATE INDEX IF NOT EXISTS content_site ON content(site_id);
";

pub struct ContentDb {
    db: Database,
}

impl ContentDb {
    pub fn open(db: Database) -> Result<Self> {
        db.conn()?
            .execute_batch(SCHEMA)
            .map_err(|e| Error::Db(e.to_string()))?;
        Ok(Self { db })
    }

    /// Register a site (idempotent), returning its `site_id`.
    pub fn add_site(&self, address: &str) -> Result<i64> {
        let conn = self.db.conn()?;
        let dberr = |e: rusqlite::Error| Error::Db(e.to_string());
        conn.execute("INSERT OR IGNORE INTO site (address) VALUES (?1)", [address])
            .map_err(dberr)?;
        conn.query_row("SELECT site_id FROM site WHERE address = ?1", [address], |r| r.get(0))
            .map_err(dberr)
    }

    /// Upsert a content.json file's metadata.
    pub fn set_content(&self, site_id: i64, inner_path: &str, modified: i64, size: i64) -> Result<()> {
        self.db
            .conn()?
            .execute(
                "INSERT INTO content (site_id, inner_path, modified, size) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(site_id, inner_path) DO UPDATE SET modified = ?3, size = ?4",
                rusqlite::params![site_id, inner_path, modified, size],
            )
            .map(|_| ())
            .map_err(|e| Error::Db(e.to_string()))
    }

    /// `(modified, size)` for a file, if known.
    pub fn get_content(&self, site_id: i64, inner_path: &str) -> Result<Option<(i64, i64)>> {
        let conn = self.db.conn()?;
        conn.query_row(
            "SELECT modified, size FROM content WHERE site_id = ?1 AND inner_path = ?2",
            rusqlite::params![site_id, inner_path],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(Error::Db(other.to_string())),
        })
    }

    /// All `(inner_path, modified, size)` rows for a site, ordered by path.
    pub fn list_content(&self, site_id: i64) -> Result<Vec<(String, i64, i64)>> {
        let conn = self.db.conn()?;
        let mut stmt = conn
            .prepare("SELECT inner_path, modified, size FROM content WHERE site_id = ?1 ORDER BY inner_path")
            .map_err(|e| Error::Db(e.to_string()))?;
        let rows = stmt
            .query_map([site_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| Error::Db(e.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::Db(e.to_string()))
    }
}
