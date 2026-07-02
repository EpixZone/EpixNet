//! The network-stats chart database, mirroring EpixNet's Chart plugin.
//!
//! A background collector snapshots node metrics into a small SQLite database
//! with three tables - `type` (metric id -> name), `site` (site id -> address),
//! and `data` (timestamped values) - and the dashboard's Stats page reads it
//! through the `chartDbQuery` command. `date_added` is stored as unix seconds
//! (the page divides and buckets by it), matching the Python collector.

use epix_db::Database;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS type (type_id INTEGER PRIMARY KEY NOT NULL UNIQUE, name TEXT);
CREATE TABLE IF NOT EXISTS site (site_id INTEGER PRIMARY KEY NOT NULL UNIQUE, address TEXT);
CREATE TABLE IF NOT EXISTS data (
    data_id INTEGER PRIMARY KEY ASC AUTOINCREMENT NOT NULL UNIQUE,
    type_id INTEGER NOT NULL,
    site_id INTEGER,
    value INTEGER,
    date_added INTEGER DEFAULT (strftime('%s','now')));
CREATE INDEX IF NOT EXISTS data_site_id ON data (site_id);
CREATE INDEX IF NOT EXISTS data_date_added ON data (date_added);";

/// One metric to record. `is_change` stores the delta from the previous
/// snapshot (for running totals like bytes transferred), mirroring the
/// collector's `|change` suffix.
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub is_change: bool,
}

impl Metric {
    pub fn now(name: &str, value: f64) -> Self {
        Self { name: name.to_string(), value, is_change: false }
    }
    pub fn change(name: &str, value: f64) -> Self {
        Self { name: name.to_string(), value, is_change: true }
    }
}

/// The chart database plus in-memory id caches (like the Python loadTypes /
/// loadSites) and the last raw value of each `|change` metric.
pub struct ChartDb {
    db: Database,
    types: Mutex<HashMap<String, i64>>,
    sites: Mutex<HashMap<String, i64>>,
    last_values: Mutex<HashMap<String, f64>>,
}

impl ChartDb {
    /// Open (creating if needed) a file-backed chart db.
    pub fn file(path: impl AsRef<std::path::Path>) -> Option<Self> {
        Database::open(path).ok().and_then(Self::init)
    }

    /// An in-memory chart db (nodes with no data dir, and tests).
    pub fn memory() -> Option<Self> {
        Database::open_in_memory().ok().and_then(Self::init)
    }

    fn init(db: Database) -> Option<Self> {
        db.execute_batch(SCHEMA).ok()?;
        let types = load_ids(&db, "SELECT name, type_id AS id FROM type");
        let sites = load_ids(&db, "SELECT address AS name, site_id AS id FROM site");
        Some(Self {
            db,
            types: Mutex::new(types),
            sites: Mutex::new(sites),
            last_values: Mutex::new(HashMap::new()),
        })
    }

    /// The id of a metric name, inserting it on first use.
    fn type_id(&self, name: &str) -> Option<i64> {
        if let Some(id) = self.types.lock().unwrap().get(name) {
            return Some(*id);
        }
        let id = self.db.execute("INSERT INTO type (name) VALUES (?)", &[Value::from(name)]).ok()?;
        self.types.lock().unwrap().insert(name.to_string(), id);
        Some(id)
    }

    /// The id of a site address, inserting it on first use.
    pub fn site_id(&self, address: &str) -> Option<i64> {
        if let Some(id) = self.sites.lock().unwrap().get(address) {
            return Some(*id);
        }
        let id = self
            .db
            .execute("INSERT INTO site (address) VALUES (?)", &[Value::from(address)])
            .ok()?;
        self.sites.lock().unwrap().insert(address.to_string(), id);
        Some(id)
    }

    /// Record one snapshot of metrics at `now` (unix seconds), optionally tagged
    /// with a site. `|change` metrics are stored as the delta from last time.
    pub fn record(&self, now: i64, site_id: Option<i64>, metrics: &[Metric]) {
        for m in metrics {
            let mut value = m.value;
            if m.is_change {
                let key = match site_id {
                    Some(id) => format!("{id}:{}", m.name),
                    None => m.name.clone(),
                };
                let mut last = self.last_values.lock().unwrap();
                let prev = last.get(&key).copied().unwrap_or(0.0);
                last.insert(key, value);
                value -= prev;
            }
            let Some(type_id) = self.type_id(&m.name) else { continue };
            let _ = self.db.execute(
                "INSERT INTO data (type_id, site_id, value, date_added) VALUES (?, ?, ?, ?)",
                &[Value::from(type_id), site_id.map(Value::from).unwrap_or(Value::Null), Value::from(value.round() as i64), Value::from(now)],
            );
        }
    }

    /// Enforce retention so the chart db does not grow without bound: drop
    /// per-site datapoints older than one month and global datapoints older than
    /// six months, then reclaim the space. Mirrors EpixNet's `ChartDb.archive`
    /// retention (without its downsampling of old rows).
    pub fn archive(&self, now: i64) {
        const MONTH: i64 = 60 * 60 * 24 * 30;
        let _ = self.db.execute(
            "DELETE FROM data WHERE site_id IS NOT NULL AND date_added < ?",
            &[Value::from(now - MONTH)],
        );
        let _ = self.db.execute(
            "DELETE FROM data WHERE site_id IS NULL AND date_added < ?",
            &[Value::from(now - 6 * MONTH)],
        );
        let _ = self.db.execute_batch("VACUUM");
    }

    /// Run a read-only chart query (the `chartDbQuery` command). Only SELECT is
    /// allowed, matching the Python action. `params` is bound by name (a
    /// list-valued param expands `IN :key` into a placeholder list), so the
    /// Stats page's `type_id IN :type_ids` query works.
    pub fn query(&self, sql: &str, params: &Value) -> Result<Vec<Value>, String> {
        if !sql.trim_start().to_uppercase().starts_with("SELECT") {
            return Err("Only SELECT query supported".to_string());
        }
        self.db.query_value(sql, params).map_err(|e| e.to_string())
    }
}

fn load_ids(db: &Database, sql: &str) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    if let Ok(rows) = db.query(sql, &[]) {
        for row in rows {
            if let (Some(name), Some(id)) =
                (row.get("name").and_then(Value::as_str), row.get("id").and_then(Value::as_i64))
            {
                out.insert(name.to_string(), id);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn archive_enforces_retention_windows() {
        let db = ChartDb::memory().unwrap();
        let now: i64 = 2_000_000_000;
        let day = 60 * 60 * 24;
        let site = db.site_id("1Site");
        // Old global (7 months) + old per-site (2 months) should be dropped;
        // recent points of each kind should stay.
        db.record(now - day * 210, None, &[Metric::now("a", 1.0)]);
        db.record(now - day * 60, site, &[Metric::now("a", 2.0)]);
        db.record(now - day * 2, None, &[Metric::now("a", 3.0)]);
        db.record(now - day * 2, site, &[Metric::now("a", 4.0)]);
        assert_eq!(count(&db), 4);

        db.archive(now);
        assert_eq!(count(&db), 2);
    }

    fn count(db: &ChartDb) -> i64 {
        db.query("SELECT COUNT(*) AS n FROM data", &json!({})).unwrap()[0]["n"].as_i64().unwrap()
    }
}
