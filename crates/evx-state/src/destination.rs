//! The destination side of dispatch: the trait the host hands to
//! [`DurableState::dispatch`](crate::DurableState::dispatch) and a bounded,
//! sacrificial SQLite implementation used by tests and the conformance suite.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::{params, OptionalExtension as _};
use serde_json::{json, Value};

use crate::canonical::{canonical, digest, identifier, relative_path};
use crate::{connect, envelope, transaction, Effect, EffectKind, Error, Result, MAX_ROWS};

/// Something queued effects are delivered to.
///
/// `apply` is called while the host database lock is held, so an
/// implementation must be local and bounded: it must either accept the
/// envelope idempotently (returning the same response for a repeated key with
/// the same digest) or fail with an [`Error`], in which case the effect stays
/// queued and is retried on the next dispatch.
pub trait Destination {
    /// Deliver `envelope_raw` (canonical JSON whose SHA-256 is
    /// `payload_digest`) for `(xite, key)` and return the receipt.
    fn apply(
        &mut self,
        xite: &str,
        key: &str,
        envelope_raw: &str,
        payload_digest: &str,
    ) -> Result<Value>;
}

/// Bounded sacrificial destination with atomic receipt and effect storage.
///
/// This assumes destination-side idempotency and does not establish it for
/// actual contracts, publication protocols, signing or any network service.
/// Receipts are keyed by `(xite, effect_key)` and immutable; a repeated key
/// with a different digest is a conflict. Publication deltas are applied
/// exactly, under the prefix the host embedded in the envelope.
#[derive(Debug, Clone)]
pub struct MockDestination {
    path: PathBuf,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS receipts (xite TEXT, effect_key TEXT,
    payload_digest TEXT NOT NULL, response TEXT NOT NULL,
    PRIMARY KEY(xite,effect_key));
CREATE TABLE IF NOT EXISTS published (xite TEXT, path TEXT,
    content TEXT NOT NULL, PRIMARY KEY(xite,path));
";

impl MockDestination {
    /// Open (creating if needed) the destination database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let destination = MockDestination {
            path: path.as_ref().to_path_buf(),
        };
        let conn = connect(&destination.path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(destination)
    }

    /// Number of receipts stored across all xites.
    pub fn receipt_count(&self) -> Result<u64> {
        let conn = connect(&self.path)?;
        Ok(conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?)
    }

    /// Every published path and its content for `xite`.
    pub fn published(&self, xite: &str) -> Result<BTreeMap<String, String>> {
        let conn = connect(&self.path)?;
        let mut statement =
            conn.prepare("SELECT path, content FROM published WHERE xite=?1 ORDER BY path")?;
        let rows = statement.query_map(params![xite], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut published = BTreeMap::new();
        for row in rows {
            let (path, content): (String, String) = row?;
            published.insert(path, content);
        }
        Ok(published)
    }
}

impl Destination for MockDestination {
    fn apply(
        &mut self,
        xite: &str,
        key: &str,
        envelope_raw: &str,
        payload_digest: &str,
    ) -> Result<Value> {
        identifier(xite)?;
        identifier(key)?;
        let parsed: Value = serde_json::from_str(envelope_raw)
            .map_err(|_| Error::invalid("unreadable destination envelope"))?;
        if canonical(&parsed)? != envelope_raw || digest(envelope_raw) != payload_digest {
            return Err(Error::conflict("destination payload digest mismatch"));
        }
        transaction(&self.path, |conn| {
            let prior: Option<(String, String)> = conn
                .query_row(
                    "SELECT payload_digest, response FROM receipts WHERE xite=?1 AND effect_key=?2",
                    params![xite, key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if let Some((prior_digest, response)) = prior {
                if prior_digest != payload_digest {
                    return Err(Error::conflict("destination immutable key conflict"));
                }
                return serde_json::from_str(&response)
                    .map_err(|_| Error::conflict("stored receipt is unreadable"));
            }
            let receipts: u64 =
                conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
            if receipts >= MAX_ROWS {
                return Err(Error::budget("mock destination receipt limit"));
            }
            match parsed.get("kind").and_then(Value::as_str) {
                Some("publish") => {
                    let prefix = parsed
                        .get("prefix")
                        .and_then(Value::as_str)
                        .ok_or_else(|| Error::invalid("invalid publication path"))?;
                    relative_path(prefix)?;
                    let payload = parsed
                        .get("payload")
                        .cloned()
                        .ok_or_else(|| Error::invalid("invalid exact publication delta"))?;
                    let effect = Effect {
                        key: key.to_owned(),
                        kind: EffectKind::Publish,
                        payload: payload.clone(),
                    };
                    if envelope(&effect, Some(prefix))? != envelope_raw {
                        return Err(Error::conflict("invalid publication envelope"));
                    }
                    let writes = payload["writes"]
                        .as_object()
                        .ok_or_else(|| Error::invalid("invalid exact publication delta"))?;
                    let deletes = payload["deletes"]
                        .as_array()
                        .ok_or_else(|| Error::invalid("invalid exact publication delta"))?;
                    for (path, content) in writes {
                        let content = content
                            .as_str()
                            .ok_or_else(|| Error::invalid("invalid text content"))?;
                        conn.execute(
                            "INSERT INTO published (xite, path, content) VALUES (?1,?2,?3) \
                             ON CONFLICT(xite,path) DO UPDATE SET content=excluded.content",
                            params![xite, format!("{prefix}/{path}"), content],
                        )?;
                    }
                    for path in deletes {
                        let path = path
                            .as_str()
                            .ok_or_else(|| Error::invalid("invalid publication path"))?;
                        conn.execute(
                            "DELETE FROM published WHERE xite=?1 AND path=?2",
                            params![xite, format!("{prefix}/{path}")],
                        )?;
                    }
                    let entries: u64 =
                        conn.query_row("SELECT COUNT(*) FROM published", [], |row| row.get(0))?;
                    if entries > MAX_ROWS {
                        return Err(Error::budget("mock publication entry limit"));
                    }
                }
                Some("record") => {}
                _ => return Err(Error::denied("unknown destination effect")),
            }
            let response = json!({"accepted": true, "key": key, "digest": payload_digest});
            conn.execute(
                "INSERT INTO receipts (xite, effect_key, payload_digest, response) \
                 VALUES (?1,?2,?3,?4)",
                params![xite, key, payload_digest, canonical(&response)?],
            )?;
            Ok(response)
        })
    }
}
