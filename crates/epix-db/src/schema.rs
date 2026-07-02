//! Per-xite database schema, parsed from a xite's `dbschema.json`.
//!
//! Mirrors EpixNet's format so existing xites' schemas apply unchanged: `tables`
//! define SQL tables, and `maps` say how JSON data files populate them —
//! matched by a regex on the file's path relative to the db dir, then routed via
//! `to_table` (rows), `to_keyvalue` (key/value pairs), and `to_json_table`
//! (columns on the per-file `json` row).
//!
//! ```json
//! { "db_name": "Blog", "db_file": "db/db.db", "version": 2,
//!   "maps": { "data.json": { "to_table": [{"node": "posts", "table": "post"}],
//!                            "to_keyvalue": ["next_post_id"] } },
//!   "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]],
//!                         "indexes": ["CREATE INDEX post_id ON post(post_id)"] } } }
//! ```

use epix_core::{Error, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DbSchema {
    #[serde(default)]
    pub db_name: String,
    #[serde(default)]
    pub db_file: String,
    #[serde(default = "default_version")]
    pub version: i64,
    #[serde(default)]
    pub tables: BTreeMap<String, TableSchema>,
    /// `path-regex -> how that file populates the db`.
    #[serde(default)]
    pub maps: BTreeMap<String, MapSettings>,
}

fn default_version() -> i64 {
    1
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MapSettings {
    #[serde(default)]
    pub to_table: Vec<ToTable>,
    #[serde(default)]
    pub to_keyvalue: Vec<String>,
    #[serde(default)]
    pub to_json_table: Vec<String>,
}

/// A `to_table` entry: either a bare table/node name, or a spec.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ToTable {
    Simple(String),
    Spec {
        table: String,
        #[serde(default)]
        node: Option<String>,
        #[serde(default)]
        key_col: Option<String>,
        #[serde(default)]
        val_col: Option<String>,
        #[serde(default)]
        import_cols: Option<Vec<String>>,
    },
}

impl ToTable {
    pub fn table(&self) -> &str {
        match self {
            ToTable::Simple(s) => s,
            ToTable::Spec { table, .. } => table,
        }
    }

    /// The JSON node the rows come from (defaults to the table name).
    pub fn node(&self) -> &str {
        match self {
            ToTable::Simple(s) => s,
            ToTable::Spec { table, node, .. } => node.as_deref().unwrap_or(table),
        }
    }
}

impl DbSchema {
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(Error::from)
    }

    /// Columns that land on the per-file `json` row (union of every map's
    /// `to_json_table`), so the `json` table can be created wide enough.
    pub fn json_table_cols(&self) -> BTreeSet<String> {
        self.maps.values().flat_map(|m| m.to_json_table.iter().cloned()).collect()
    }
}

/// Create every user table + index, plus the internal `json` and `keyvalue`
/// meta-tables the populate step needs. Idempotent (`IF NOT EXISTS`).
pub fn apply(conn: &Connection, schema: &DbSchema) -> Result<()> {
    let db = |e: rusqlite::Error| Error::Db(e.to_string());

    for (name, table) in &schema.tables {
        if name == "json" || name == "keyvalue" {
            continue; // reserved meta-tables, created below
        }
        if table.cols.is_empty() {
            return Err(Error::Db(format!("table `{name}` has no columns")));
        }
        let cols = table.cols.iter().map(|(n, t)| format!("{n} {t}")).collect::<Vec<_>>().join(", ");
        conn.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {name} ({cols});")).map_err(db)?;
        for idx in &table.indexes {
            conn.execute_batch(&format!("{idx};")).map_err(db)?;
        }
    }

    create_meta_tables(conn, schema)?;
    Ok(())
}

/// The `json` (one row per data file) and `keyvalue` meta-tables, shaped by the
/// schema version and its `to_json_table` columns.
fn create_meta_tables(conn: &Connection, schema: &DbSchema) -> Result<()> {
    let db = |e: rusqlite::Error| Error::Db(e.to_string());

    // Base identity columns for a data file, by schema version. Version 3 adds
    // a `site` column so a merger site's db can aggregate rows from many sites.
    let (id_cols, unique) = match schema.version {
        1 => ("path VARCHAR(255)", "CREATE UNIQUE INDEX IF NOT EXISTS path ON json(path)"),
        3 => (
            "site VARCHAR(255), directory VARCHAR(255), file_name VARCHAR(255)",
            "CREATE UNIQUE INDEX IF NOT EXISTS path ON json(site, directory, file_name)",
        ),
        _ => (
            "directory VARCHAR(255), file_name VARCHAR(255)",
            "CREATE UNIQUE INDEX IF NOT EXISTS path ON json(directory, file_name)",
        ),
    };
    let mut extra = String::new();
    for col in schema.json_table_cols() {
        extra.push_str(&format!(", {col} TEXT"));
    }
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS json (json_id INTEGER PRIMARY KEY AUTOINCREMENT, {id_cols}{extra});"
    ))
    .map_err(db)?;
    conn.execute_batch(&format!("{unique};")).map_err(db)?;

    // `value` has no type affinity so it round-trips numbers as numbers and
    // strings as strings (keyvalue holds mixed types).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS keyvalue (\
           keyvalue_id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value, json_id INTEGER);\
         CREATE UNIQUE INDEX IF NOT EXISTS key_id ON keyvalue(json_id, key);",
    )
    .map_err(db)?;
    Ok(())
}
