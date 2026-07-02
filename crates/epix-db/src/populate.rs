//! Populate a xite's database from its JSON data files, per its `dbschema.json`
//! `maps`. This is EpixNet's `Db.updateJson`: for each data file whose path
//! matches a map's regex, load the JSON and route it into tables
//! (`to_table`), key/value pairs (`to_keyvalue`), and per-file columns
//! (`to_json_table`), each tagged with the file's `json_id`.

use crate::schema::{DbSchema, ToTable};
use epix_core::{Error, Result};
use regex::Regex;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::Connection;
use serde_json::{Map, Value};
use std::path::Path;

fn db_err(e: rusqlite::Error) -> Error {
    Error::Db(e.to_string())
}

/// serde_json value -> a SQLite-bindable value (containers become JSON text).
fn to_sql(v: &Value) -> SqlValue {
    match v {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Integer(*b as i64),
        Value::Number(n) => n
            .as_i64()
            .map(SqlValue::Integer)
            .unwrap_or_else(|| SqlValue::Real(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => SqlValue::Text(s.clone()),
        other => SqlValue::Text(other.to_string()),
    }
}

/// SQLite value -> serde_json value (for query results).
pub fn from_sql(v: ValueRef) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => Value::from(f),
        ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::from(format!("<{} bytes>", b.len())),
    }
}

/// Get (or create) the `json_id` for a data file's relative path. `site` is the
/// merged-site address for version-3 (merger) schemas, ignored otherwise.
fn json_id(conn: &Connection, schema: &DbSchema, rel_path: &str, site: &str) -> Result<i64> {
    let rel_path = rel_path.replace('\\', "/");
    match schema.version {
        1 => {
            conn.execute("INSERT OR IGNORE INTO json (path) VALUES (?1)", [&rel_path])
                .map_err(db_err)?;
            conn.query_row("SELECT json_id FROM json WHERE path = ?1", [&rel_path], |r| r.get(0))
                .map_err(db_err)
        }
        3 => {
            let (dir, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path.as_str()));
            conn.execute(
                "INSERT OR IGNORE INTO json (site, directory, file_name) VALUES (?1, ?2, ?3)",
                [site, dir, name],
            )
            .map_err(db_err)?;
            conn.query_row(
                "SELECT json_id FROM json WHERE site = ?1 AND directory = ?2 AND file_name = ?3",
                [site, dir, name],
                |r| r.get(0),
            )
            .map_err(db_err)
        }
        _ => {
            let (dir, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path.as_str()));
            conn.execute(
                "INSERT OR IGNORE INTO json (directory, file_name) VALUES (?1, ?2)",
                [dir, name],
            )
            .map_err(db_err)?;
            conn.query_row(
                "SELECT json_id FROM json WHERE directory = ?1 AND file_name = ?2",
                [dir, name],
                |r| r.get(0),
            )
            .map_err(db_err)
        }
    }
}

/// Insert a row (a JSON object) into `table`, keeping only `allowed` columns
/// plus `json_id`. `INSERT OR REPLACE` so a re-run refreshes cleanly.
fn insert_row(
    conn: &Connection,
    table: &str,
    allowed: &[String],
    row: &Map<String, Value>,
    json_id: i64,
) -> Result<()> {
    let mut cols: Vec<&str> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();
    for (k, v) in row {
        if allowed.iter().any(|c| c == k) && k != "json_id" {
            cols.push(k);
            params.push(to_sql(v));
        }
    }
    cols.push("json_id");
    params.push(SqlValue::Integer(json_id));

    let placeholders = (1..=cols.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
    let sql = format!("INSERT OR REPLACE INTO {table} ({}) VALUES ({placeholders})", cols.join(", "));
    conn.execute(&sql, rusqlite::params_from_iter(params.iter())).map_err(db_err)?;
    Ok(())
}

/// Allowed columns for a `to_table` entry: its `import_cols`, else the table's
/// schema columns.
fn allowed_cols(schema: &DbSchema, entry: &ToTable) -> Vec<String> {
    if let ToTable::Spec { import_cols: Some(cols), .. } = entry {
        return cols.clone();
    }
    schema
        .tables
        .get(entry.table())
        .map(|t| t.cols.iter().map(|(n, _)| n.clone()).collect())
        .unwrap_or_default()
}

/// Route one already-loaded data file's JSON into the db per the matching maps.
/// `site` tags the rows for a version-3 merger db (empty for a normal site).
pub fn update_json(
    conn: &Connection,
    schema: &DbSchema,
    rel_path: &str,
    data: &Value,
    site: &str,
) -> Result<bool> {
    let mut matched = false;
    for (pattern, map) in &schema.maps {
        let re = Regex::new(&format!("^(?:{pattern})")).map_err(|e| Error::Db(e.to_string()))?;
        if !re.is_match(rel_path) {
            continue;
        }
        matched = true;
        let jid = json_id(conn, schema, rel_path, site)?;

        // to_keyvalue
        for key in &map.to_keyvalue {
            let val = to_sql(data.get(key).unwrap_or(&Value::Null));
            conn.execute(
                "INSERT OR REPLACE INTO keyvalue (json_id, key, value) VALUES (?1, ?2, ?3)",
                rusqlite::params![jid, key, val],
            )
            .map_err(db_err)?;
        }

        // to_json_table: set columns on the json row itself
        for key in &map.to_json_table {
            let val = to_sql(data.get(key).unwrap_or(&Value::Null));
            conn.execute(
                &format!("UPDATE json SET {key} = ?1 WHERE json_id = ?2"),
                rusqlite::params![val, jid],
            )
            .map_err(db_err)?;
        }

        // to_table
        for entry in &map.to_table {
            let table = entry.table();
            let node = entry.node();
            let allowed = allowed_cols(schema, entry);
            conn.execute(&format!("DELETE FROM {table} WHERE json_id = ?1"), [jid]).map_err(db_err)?;

            let Some(node_data) = data.get(node) else { continue };

            match entry {
                // Dict-mapped: `key_col` carries the map key.
                ToTable::Spec { key_col: Some(key_col), val_col, .. } => {
                    if let Some(obj) = node_data.as_object() {
                        for (k, v) in obj {
                            if let Some(val_col) = val_col {
                                let mut row = Map::new();
                                row.insert(key_col.clone(), Value::from(k.clone()));
                                row.insert(val_col.clone(), v.clone());
                                insert_row(conn, table, &allowed, &row, jid)?;
                            } else if let Some(row_obj) = v.as_object() {
                                let mut row = row_obj.clone();
                                row.insert(key_col.clone(), Value::from(k.clone()));
                                insert_row(conn, table, &allowed, &row, jid)?;
                            } else if let Some(rows) = v.as_array() {
                                for r in rows.iter().filter_map(|r| r.as_object()) {
                                    let mut row = r.clone();
                                    row.insert(key_col.clone(), Value::from(k.clone()));
                                    insert_row(conn, table, &allowed, &row, jid)?;
                                }
                            }
                        }
                    }
                }
                // List of rows.
                _ => {
                    if let Some(rows) = node_data.as_array() {
                        for r in rows.iter().filter_map(|r| r.as_object()) {
                            insert_row(conn, table, &allowed, r, jid)?;
                        }
                    }
                }
            }
        }
    }
    Ok(matched)
}

/// Populate the db by scanning every file under `db_dir` and routing the ones
/// that match a map. `db_dir` is the xite's content root; paths are matched
/// relative to it (forward slashes), like EpixNet.
pub fn populate(conn: &Connection, schema: &DbSchema, db_dir: &Path) -> Result<usize> {
    populate_site(conn, schema, db_dir, "")
}

/// Like [`populate`], but tags every row with `site` - for a version-3 merger
/// db aggregating data from several merged sites (call once per merged site).
pub fn populate_site(conn: &Connection, schema: &DbSchema, db_dir: &Path, site: &str) -> Result<usize> {
    let mut count = 0;
    let mut stack = vec![db_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(rel) = path.strip_prefix(db_dir) else { continue };
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let Ok(bytes) = std::fs::read(&path) else { continue };
            let Ok(data) = serde_json::from_slice::<Value>(&bytes) else { continue };
            if update_json(conn, schema, &rel_str, &data, site)? {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Collect a prepared statement's rows as JSON objects (column -> value).
fn collect(stmt: &mut rusqlite::Statement, params: impl rusqlite::Params) -> Result<Vec<Value>> {
    let col_names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();
    let mut rows = stmt.query(params).map_err(db_err)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(db_err)? {
        let mut obj = Map::new();
        for (i, name) in col_names.iter().enumerate() {
            obj.insert(name.clone(), from_sql(row.get_ref(i).map_err(db_err)?));
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

/// Run a read query with positional params, returning rows as JSON objects.
pub fn query(conn: &Connection, sql: &str, params: &[Value]) -> Result<Vec<Value>> {
    let sql_params: Vec<SqlValue> = params.iter().map(to_sql).collect();
    let mut stmt = conn.prepare(sql).map_err(db_err)?;
    collect(&mut stmt, rusqlite::params_from_iter(sql_params.iter()))
}

/// Run a write statement with positional params, returning the row id inserted
/// by the statement (`last_insert_rowid`).
pub fn execute(conn: &Connection, sql: &str, params: &[Value]) -> Result<i64> {
    let sql_params: Vec<SqlValue> = params.iter().map(to_sql).collect();
    conn.execute(sql, rusqlite::params_from_iter(sql_params.iter())).map_err(db_err)?;
    Ok(conn.last_insert_rowid())
}

/// Run a read query whose params are a JSON value: an object binds by name
/// (`{"post_id": 1}` -> `:post_id`), an array binds positionally, null/absent
/// means no params. This is the shape the `dbQuery` WS command receives.
pub fn query_value(conn: &Connection, sql: &str, params: &Value) -> Result<Vec<Value>> {
    match params {
        Value::Object(map) => {
            // A list-valued param expands `IN :key` into `IN (:key__0, :key__1,
            // …)`, binding each element (matching EpixNet's DbCursor). This is
            // what the Stats page's chartDbQuery relies on for `type_id IN
            // :type_ids`.
            let mut sql = sql.to_string();
            let mut named: Vec<(String, SqlValue)> = Vec::new();
            for (k, v) in map {
                let base = k.strip_prefix(':').unwrap_or(k);
                match v {
                    Value::Array(items) => {
                        let placeholders: Vec<String> =
                            (0..items.len()).map(|i| format!(":{base}__{i}")).collect();
                        // Replace `:key` when followed by `)`, whitespace, or end.
                        let re = Regex::new(&format!(r":{}([)\s]|$)", regex::escape(base)))
                            .map_err(|e| Error::Db(e.to_string()))?;
                        sql = re
                            .replace_all(&sql, format!("({})$1", placeholders.join(", ")))
                            .into_owned();
                        for (i, item) in items.iter().enumerate() {
                            named.push((format!(":{base}__{i}"), to_sql(item)));
                        }
                    }
                    _ => named.push((format!(":{base}"), to_sql(v))),
                }
            }
            let refs: Vec<(&str, &dyn rusqlite::ToSql)> =
                named.iter().map(|(k, v)| (k.as_str(), v as &dyn rusqlite::ToSql)).collect();
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            collect(&mut stmt, refs.as_slice())
        }
        Value::Array(arr) => query(conn, sql, arr),
        _ => query(conn, sql, &[]),
    }
}
