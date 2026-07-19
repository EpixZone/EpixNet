//! Per-xite database schema, parsed from a xite's `dbschema.json`.
//!
//! Mirrors EpixNet's format so existing xites' schemas apply unchanged: `tables`
//! define SQL tables, and `maps` say how JSON data files populate them -
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
    /// `to_json_table` writes onto the json row of THIS sibling file instead
    /// of the matched file's own row (EpixNet: a user's content.json carries
    /// cert_user_id, but queries join it from the data.json row). When set, a
    /// merge-file map's `to_table` rows ALSO attach to the sibling's json row,
    /// so a per-record posts.json joins the user's profile from data.json.
    #[serde(default)]
    pub file_name: Option<String>,
    /// A signed-CRDT merge file (posts.json): before `to_table` ingest, fold
    /// this node's versioned records to their live display winners (dropping
    /// tombstones and superseded versions), so a deleted post never leaves a
    /// live row and a concurrent edit resolves to one deterministic winner.
    #[serde(default)]
    pub fold_crdt: Option<String>,
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

/// Validate a table name is a plain SQL identifier (letters, digits,
/// underscore; not starting with a digit), since names come from a
/// site-controlled `dbschema.json`. Rejects anything that could break out of
/// the interpolated DDL. EpixNet's `safe_sql_identifier`.
fn safe_identifier(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.chars().next().unwrap().is_ascii_digit()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(Error::Db(format!("unsafe table name in dbschema.json: {name:?}")))
    }
}

/// Create every user table + index, plus the internal `json` and `keyvalue`
/// meta-tables the populate step needs.
///
/// Applies EpixNet's schema versioning: the schema's `version` is tracked in
/// `keyvalue` (`db.version`). When the site bumps it, every table is **dropped
/// and recreated** in the new shape (the data is repopulated from the site's
/// content data files afterward), so a node follows a site's schema change
/// instead of keeping a stale table layout. Otherwise this is idempotent
/// (`IF NOT EXISTS`).
pub fn apply(conn: &Connection, schema: &DbSchema) -> Result<()> {
    let db = |e: rusqlite::Error| Error::Db(e.to_string());

    // Validate every table name up front (used in interpolated DDL below).
    for name in schema.tables.keys() {
        safe_identifier(name)?;
    }

    // The keyvalue meta-table must exist before we can read the stored version.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS keyvalue (\
           keyvalue_id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value, json_id INTEGER);\
         CREATE UNIQUE INDEX IF NOT EXISTS key_id ON keyvalue(json_id, key);",
    )
    .map_err(db)?;
    let stored_version: i64 = conn
        .query_row(
            "SELECT value FROM keyvalue WHERE json_id = 0 AND key = 'db.version'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let outdated = stored_version < schema.version;
    if outdated {
        // Drop the user tables + json so they are recreated in the new shape
        // (the json table's own columns depend on the schema version too).
        for name in schema.tables.keys() {
            if name != "keyvalue" {
                conn.execute_batch(&format!("DROP TABLE IF EXISTS {name};")).map_err(db)?;
            }
        }
        conn.execute_batch("DROP TABLE IF EXISTS json;").map_err(db)?;
    }

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

    if outdated {
        conn.execute(
            "INSERT OR REPLACE INTO keyvalue (json_id, key, value) VALUES (0, 'db.version', ?)",
            [schema.version],
        )
        .map_err(db)?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn schema_with_col(version: i64, col: &str) -> DbSchema {
        let json = format!(
            r#"{{ "db_name": "T", "db_file": "db.db", "version": {version},
                  "maps": {{}},
                  "tables": {{ "post": {{ "cols": [["post_id","INTEGER"],["{col}","TEXT"]],
                                         "indexes": [], "schema_changed": 1 }} }} }}"#
        );
        DbSchema::from_json(&json).unwrap()
    }

    fn columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).unwrap();
        let rows = stmt.query_map([], |r| r.get::<_, String>(1)).unwrap();
        rows.filter_map(|r| r.ok()).collect()
    }

    #[test]
    fn version_bump_rebuilds_tables() {
        let conn = Connection::open_in_memory().unwrap();
        // v1 schema with a `title` column.
        apply(&conn, &schema_with_col(1, "title")).unwrap();
        assert!(columns(&conn, "post").contains(&"title".to_string()));
        conn.execute("INSERT INTO post (post_id, title) VALUES (1, 'hi')", []).unwrap();

        // Re-applying the same version keeps the table (and its row).
        apply(&conn, &schema_with_col(1, "title")).unwrap();
        let count: i64 =
            conn.query_row("SELECT count(*) FROM post", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "same version does not rebuild");

        // Bumping the version to 2 with a different column rebuilds the table.
        apply(&conn, &schema_with_col(2, "body")).unwrap();
        let cols = columns(&conn, "post");
        assert!(cols.contains(&"body".to_string()), "new column present");
        assert!(!cols.contains(&"title".to_string()), "old column gone (rebuilt)");
        let stored: i64 = conn
            .query_row("SELECT value FROM keyvalue WHERE json_id=0 AND key='db.version'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, 2, "stored version advanced");
    }

    #[test]
    fn rejects_unsafe_table_name() {
        let conn = Connection::open_in_memory().unwrap();
        let json = r#"{ "db_name": "T", "db_file": "db.db", "version": 1, "maps": {},
            "tables": { "post; DROP TABLE x": { "cols": [["a","TEXT"]], "indexes": [] } } }"#;
        let schema = DbSchema::from_json(json).unwrap();
        assert!(apply(&conn, &schema).is_err(), "unsafe table name rejected");
    }
}
