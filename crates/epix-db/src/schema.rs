//! Per-xite database schema, parsed from a xite's `dbschema.json`.
//!
//! Mirrors EpixNet's format so existing zites' schemas apply unchanged:
//! ```json
//! { "db_name": "...", "db_file": "db/db.db", "version": 1,
//!   "tables": { "posts": {
//!       "cols": [["post_id","INTEGER"],["body","TEXT"]],
//!       "indexes": ["CREATE INDEX IF NOT EXISTS post_id ON posts(post_id)"],
//!       "schema_changed": 1 } } }
//! ```

use epix_core::{Error, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DbSchema {
    #[serde(default)]
    pub db_name: String,
    #[serde(default)]
    pub db_file: String,
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub tables: BTreeMap<String, TableSchema>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TableSchema {
    /// `[[name, sql_type], ...]`.
    pub cols: Vec<(String, String)>,
    #[serde(default)]
    pub indexes: Vec<String>,
    #[serde(default)]
    pub schema_changed: i64,
}

impl DbSchema {
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(Error::from)
    }
}

/// Create every table + index in `schema` (idempotent via `IF NOT EXISTS`).
pub fn apply(conn: &Connection, schema: &DbSchema) -> Result<()> {
    let db = |e: rusqlite::Error| Error::Db(e.to_string());
    for (name, table) in &schema.tables {
        if table.cols.is_empty() {
            return Err(Error::Db(format!("table `{name}` has no columns")));
        }
        let cols = table
            .cols
            .iter()
            .map(|(n, t)| format!("{n} {t}"))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {name} ({cols});"))
            .map_err(db)?;
        for idx in &table.indexes {
            conn.execute_batch(&format!("{idx};")).map_err(db)?;
        }
    }
    Ok(())
}
