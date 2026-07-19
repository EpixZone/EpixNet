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
            // Merger paths are keyed `<site>/<inner path>` so the schema
            // regexes match, but the json row's `directory` is stored WITHOUT
            // the site segment (EpixNet's v3 getJsonRow splits the path into
            // site / directory / file_name). Queries rely on that shape, e.g.
            // REPLACE(json.directory, 'data/users/', '') for the user name.
            let inner = rel_path.strip_prefix(&format!("{site}/")).unwrap_or(rel_path.as_str());
            let (dir, name) = inner.rsplit_once('/').unwrap_or(("", inner));
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
/// schema columns. The `key_col`/`val_col` names always pass: EpixNet applies
/// `import_cols` to a dict entry's VALUE fields before adding the dict key, so
/// a schema like EpixMail's (`key_col: conv_id`, `import_cols` without it)
/// still stores the key - filtering it out left every conv_id NULL and the
/// inbox unable to look conversations up.
fn allowed_cols(schema: &DbSchema, entry: &ToTable) -> Vec<String> {
    if let ToTable::Spec { import_cols: Some(cols), key_col, val_col, .. } = entry {
        let mut cols = cols.clone();
        for extra in [key_col, val_col].into_iter().flatten() {
            if !cols.contains(extra) {
                cols.push(extra.clone());
            }
        }
        return cols;
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

        // to_json_table: set columns on a json row - the matched file's own,
        // or (with the map's `file_name`) its sibling's. EpixNet stores a
        // user's cert_user_id from content.json onto the data.json row, where
        // the post/topic queries join it from.
        if !map.to_json_table.is_empty() {
            let target_jid = match &map.file_name {
                Some(file_name) => {
                    let dir = rel_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                    let sibling = if dir.is_empty() {
                        file_name.clone()
                    } else {
                        format!("{dir}/{file_name}")
                    };
                    json_id(conn, schema, &sibling, site)?
                }
                None => jid,
            };
            for key in &map.to_json_table {
                let val = to_sql(data.get(key).unwrap_or(&Value::Null));
                conn.execute(
                    &format!("UPDATE json SET {key} = ?1 WHERE json_id = ?2"),
                    rusqlite::params![val, target_jid],
                )
                .map_err(db_err)?;
            }
        }

        // Merge-file rows (posts.json) attach to the SIBLING data.json json row
        // (via `file_name`) so post -> profile joins resolve, and the versioned
        // node is folded to its live CRDT winners first (tombstones and
        // superseded/concurrent-losing versions dropped).
        let table_jid = match &map.file_name {
            Some(fname) => {
                let dir = rel_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                let sibling =
                    if dir.is_empty() { fname.clone() } else { format!("{dir}/{fname}") };
                json_id(conn, schema, &sibling, site)?
            }
            None => jid,
        };
        let folded_owned;
        let table_data: &Value = match &map.fold_crdt {
            Some(fold_node) => {
                let live = epix_content::live_records(data);
                let mut d = data.clone();
                if let Value::Object(m) = &mut d {
                    m.insert(fold_node.clone(), Value::Array(live));
                }
                folded_owned = d;
                &folded_owned
            }
            None => data,
        };

        // to_table
        for entry in &map.to_table {
            let table = entry.table();
            let node = entry.node();
            let allowed = allowed_cols(schema, entry);
            conn.execute(&format!("DELETE FROM {table} WHERE json_id = ?1"), [table_jid])
                .map_err(db_err)?;

            let Some(node_data) = table_data.get(node) else { continue };

            match entry {
                // Dict-mapped: `key_col` carries the map key.
                ToTable::Spec { key_col: Some(key_col), val_col, .. } => {
                    if let Some(obj) = node_data.as_object() {
                        for (k, v) in obj {
                            if let Some(val_col) = val_col {
                                let mut row = Map::new();
                                row.insert(key_col.clone(), Value::from(k.clone()));
                                row.insert(val_col.clone(), v.clone());
                                insert_row(conn, table, &allowed, &row, table_jid)?;
                            } else if let Some(row_obj) = v.as_object() {
                                let mut row = row_obj.clone();
                                row.insert(key_col.clone(), Value::from(k.clone()));
                                insert_row(conn, table, &allowed, &row, table_jid)?;
                            } else if let Some(rows) = v.as_array() {
                                for r in rows.iter().filter_map(|r| r.as_object()) {
                                    let mut row = r.clone();
                                    row.insert(key_col.clone(), Value::from(k.clone()));
                                    insert_row(conn, table, &allowed, &row, table_jid)?;
                                }
                            }
                        }
                    }
                }
                // List of rows.
                _ => {
                    if let Some(rows) = node_data.as_array() {
                        for r in rows.iter().filter_map(|r| r.as_object()) {
                            insert_row(conn, table, &allowed, r, table_jid)?;
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
    populate_site_filtered(conn, schema, db_dir, "", &[], "")
}

/// Like [`populate`], but tags every row with `site` - for a version-3 merger
/// db aggregating data from several merged sites (call once per merged site).
pub fn populate_site(conn: &Connection, schema: &DbSchema, db_dir: &Path, site: &str) -> Result<usize> {
    populate_site_filtered(conn, schema, db_dir, site, &[], "")
}

/// Like [`populate_site`], but every scanned file's path is matched against the
/// schema as `<path_prefix>/<relative path>`. Merger databases use this: a
/// merged site's files are keyed under its address (e.g.
/// `epix1…/data/users/x/data.json`), which is what the merger's dbschema
/// regexes match on (a plain `data/users/x/data.json` matches nothing, since
/// the patterns require an address segment before `data/`).
pub fn populate_site_prefixed(
    conn: &Connection,
    schema: &DbSchema,
    db_dir: &Path,
    site: &str,
    path_prefix: &str,
) -> Result<usize> {
    populate_site_filtered(conn, schema, db_dir, site, &[], path_prefix)
}

/// Like [`populate_site`], but skips any data file whose path contains one of
/// `exclude` - the ContentFilter mute enforcement point (muted authors'
/// `data/<auth_address>/…` files are left out of the database).
pub fn populate_site_filtered(
    conn: &Connection,
    schema: &DbSchema,
    db_dir: &Path,
    site: &str,
    exclude: &[String],
    path_prefix: &str,
) -> Result<usize> {
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
            let rel_body = rel.to_string_lossy().replace('\\', "/");
            let rel_str = if path_prefix.is_empty() {
                rel_body
            } else {
                format!("{path_prefix}/{rel_body}")
            };
            if !exclude.is_empty() && exclude.iter().any(|e| rel_str.contains(e.as_str())) {
                continue;
            }
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
/// Keep only characters that can appear in a column reference - the dict keys
/// become SQL identifiers (EpixNet's safe_sql_identifier).
fn safe_sql_identifier(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.').collect()
}

/// Quote a JSON value for embedding directly in SQL (only used for the
/// >100-element IN lists, like EpixNet's sqlquote).
fn sql_quote(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        other => {
            let s = match other {
                Value::String(s) => s.clone(),
                v => v.to_string(),
            };
            format!("'{}'", s.replace('\'', "''"))
        }
    }
}

/// EpixNet's `WHERE ?` + dict convention (DbCursor.parseQuery): the LAST `?`
/// in a SELECT/DELETE/UPDATE expands to conditions built from the dict -
/// a list value becomes `key IN (...)`, scalars `key = ?`, with `not__`,
/// `__like`, and trailing `>`/`<` key modifiers. Sites query this way
/// (Epix Post: `... FROM comment ... WHERE ? AND date_added < n` with
/// `{post_uri: [...]}`).
fn expand_where_dict(sql: &str, map: &Map<String, Value>) -> Option<(String, Vec<SqlValue>)> {
    let pos = sql.rfind('?')?;
    let head = sql.trim_start().split_whitespace().next().unwrap_or("").to_uppercase();
    if !matches!(head.as_str(), "SELECT" | "DELETE" | "UPDATE") {
        return None;
    }
    let mut wheres: Vec<String> = Vec::new();
    let mut values: Vec<SqlValue> = Vec::new();
    for (key, value) in map {
        match value {
            Value::Array(items) => {
                let (field, op) = match key.strip_prefix("not__") {
                    Some(k) => (safe_sql_identifier(k.trim()), "NOT IN"),
                    None => (safe_sql_identifier(key.trim()), "IN"),
                };
                if items.len() > 100 {
                    // Embed values to avoid "too many SQL variables".
                    let embedded: Vec<String> = items.iter().map(sql_quote).collect();
                    wheres.push(format!("{field} {op} ({})", embedded.join(",")));
                } else {
                    let marks = vec!["?"; items.len()].join(",");
                    wheres.push(format!("{field} {op} ({marks})"));
                    values.extend(items.iter().map(to_sql));
                }
            }
            v => {
                let cond = if let Some(k) = key.strip_prefix("not__") {
                    format!("{} != ?", safe_sql_identifier(k.trim()))
                } else if let Some(k) = key.strip_suffix("__like") {
                    format!("{} LIKE ?", safe_sql_identifier(k.trim()))
                } else if let Some(k) = key.strip_suffix('>') {
                    format!("{} > ?", safe_sql_identifier(k.trim()))
                } else if let Some(k) = key.strip_suffix('<') {
                    format!("{} < ?", safe_sql_identifier(k.trim()))
                } else {
                    format!("{} = ?", safe_sql_identifier(key.trim()))
                };
                wheres.push(cond);
                values.push(to_sql(v));
            }
        }
    }
    let clause = if wheres.is_empty() { "1".to_string() } else { wheres.join(" AND ") };
    let out = format!("{}{}{}", &sql[..pos], clause, &sql[pos + 1..]);
    Some((out, values))
}

pub fn query_value(conn: &Connection, sql: &str, params: &Value) -> Result<Vec<Value>> {
    match params {
        Value::Object(map) if sql.contains('?') => {
            let Some((sql, values)) = expand_where_dict(sql, map) else {
                return query(conn, sql, &[]);
            };
            let mut stmt = conn.prepare(&sql).map_err(db_err)?;
            collect(&mut stmt, rusqlite::params_from_iter(values.iter()))
        }
        Value::Object(map) => {
            // A list-valued param expands `IN :key` into `IN (:key__0, :key__1,
            // …)`, binding each element (matching EpixNet's DbCursor). This is
            // what the Stats page's chartDbQuery relies on for `type_id IN
            // :type_ids`.
            let mut sql = sql.to_string();
            let mut named: Vec<(String, SqlValue)> = Vec::new();
            for (k, v) in map {
                let base = k.strip_prefix(':').unwrap_or(k);
                // Python's sqlite3 ignores dict keys the query never references
                // (EpixPost passes helper keys like `directories` alongside its
                // feed SQL); binding an unreferenced name errors in rusqlite,
                // so skip them.
                let referenced =
                    Regex::new(&format!(r":{}([^0-9A-Za-z_]|$)", regex::escape(base)))
                        .map_err(|e| Error::Db(e.to_string()))?
                        .is_match(&sql);
                if !referenced {
                    continue;
                }
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

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::schema::{apply, DbSchema};
    use rusqlite::Connection;
    use serde_json::json;

    fn epixpost_schema() -> DbSchema {
        DbSchema::from_json(
            r#"{ "db_name":"T","db_file":"db.db","version":3,
              "maps":{
                ".+/data/users/.+/posts.json":{"to_table":[{"node":"post","table":"post"}],"file_name":"data.json","fold_crdt":"post"},
                ".+/data/users/.+/data.json":{"to_json_table":["user_name"]}
              },
              "tables":{"post":{"cols":[["post_id","INTEGER"],["body","TEXT"],["json_id","INTEGER"]],
                                "indexes":["CREATE UNIQUE INDEX post_key ON post(json_id,post_id)"],"schema_changed":1}} }"#,
        )
        .unwrap()
    }

    #[test]
    fn crdt_fold_ingests_live_winners_under_the_sibling_json_row() {
        let conn = Connection::open_in_memory().unwrap();
        let schema = epixpost_schema();
        apply(&conn, &schema).unwrap();
        let site = "epix1hub";
        // The user's data.json (profile) creates its json row.
        update_json(&conn, &schema, "epix1hub/data/users/u/data.json", &json!({"user_name":"alice"}), site).unwrap();
        // posts.json: post 1 live, post 2 edited (v2 supersedes v1), post 3 tombstoned.
        let posts = json!({ "record_format":"epix-orset-1", "post":[
            {"post_id":1,"body":"one","clock":1,"supersedes":0,"deleted":false},
            {"post_id":2,"body":"two-v1","clock":1,"supersedes":0,"deleted":false},
            {"post_id":2,"body":"two-v2","clock":5,"supersedes":1,"deleted":false},
            {"post_id":3,"body":"gone","clock":1,"supersedes":0,"deleted":false},
            {"post_id":3,"body":"","clock":5,"supersedes":1,"deleted":true}
        ]});
        update_json(&conn, &schema, "epix1hub/data/users/u/posts.json", &posts, site).unwrap();

        // Live winners only, joined to the data.json profile row.
        let mut stmt = conn
            .prepare("SELECT p.post_id, p.body, j.user_name FROM post p JOIN json j USING(json_id) ORDER BY p.post_id")
            .unwrap();
        let rows: Vec<(i64, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(
            rows,
            vec![(1, "one".into(), "alice".into()), (2, "two-v2".into(), "alice".into())],
            "post 3 tombstoned (absent), post 2 folded to the edit, both joined to alice"
        );
    }
}
