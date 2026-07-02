//! Per-xite runtime state (`XiteSettings`) and the stats derived from
//! content.json. This is the EpixNet `Site.settings` model: the persisted facts
//! about a xite (is it served, do we own it, when added, size, peer count, …)
//! plus the sizes/counts computed from its content.json.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Transient per-xite cache persisted with settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cache {
    /// inner_path -> retry count for files that failed to download/verify.
    #[serde(default)]
    pub bad_files: HashMap<String, i64>,
}

/// The persisted per-xite state, mirroring EpixNet's `Site.settings`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct XiteSettings {
    pub serving: bool,
    pub own: bool,
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Unix time the xite was added.
    pub added: i64,
    /// Unix time the last file finished downloading (None until first sync).
    #[serde(default)]
    pub downloaded: Option<i64>,
    /// content.json `modified` (the site's version clock).
    #[serde(default)]
    pub modified: f64,
    /// Total size of required files, bytes.
    #[serde(default)]
    pub size: i64,
    /// Total size of optional files, bytes.
    #[serde(default)]
    pub size_optional: i64,
    /// Bytes of optional files actually downloaded.
    #[serde(default)]
    pub optional_downloaded: i64,
    #[serde(default)]
    pub size_files_optional: i64,
    /// Last known peer count for the xite.
    #[serde(default)]
    pub peers: i64,
    /// Per-xite size limit override (bytes); falls back to the global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_limit: Option<i64>,
    #[serde(default)]
    pub autodownloadoptional: bool,
    /// Whether the user favourited this xite (sidebar star).
    #[serde(default)]
    pub favorite: bool,
    /// Random key authorizing this xite's WebSocket (part of the wrapper URL).
    pub wrapper_key: String,
    /// Random key authorizing AJAX/media requests.
    pub ajax_key: String,
    #[serde(default)]
    pub cache: Cache,
}

impl XiteSettings {
    /// Fresh settings for a newly added xite (`added` = now, as unix time).
    pub fn new(added: i64) -> Self {
        Self {
            serving: true,
            own: false,
            permissions: Vec::new(),
            added,
            downloaded: None,
            modified: 0.0,
            size: 0,
            size_optional: 0,
            optional_downloaded: 0,
            size_files_optional: 0,
            peers: 0,
            size_limit: None,
            autodownloadoptional: false,
            favorite: false,
            wrapper_key: epix_crypt::new_seed(),
            ajax_key: epix_crypt::new_seed(),
            cache: Cache::default(),
        }
    }

    /// Fold in sizes/modified computed from content.json.
    pub fn apply_content_stats(&mut self, stats: &ContentStats) {
        self.size = stats.size;
        self.size_optional = stats.size_optional;
        self.modified = stats.modified;
    }

    /// The effective size limit in bytes: the per-xite override or `default`.
    pub fn size_limit(&self, default: i64) -> i64 {
        self.size_limit.unwrap_or(default)
    }
}

/// Sizes and counts derived from a content.json (root only; includes are their
/// own content.json and contribute when merged).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ContentStats {
    pub size: i64,
    pub size_optional: i64,
    pub files: usize,
    pub files_optional: usize,
    pub includes: usize,
    pub modified: f64,
}

/// Sum the `size` fields of a content.json file map, ignoring negatives.
fn sum_sizes(map: Option<&serde_json::Map<String, Value>>) -> i64 {
    map.map(|m| {
        m.values()
            .filter_map(|v| v.get("size").and_then(|s| s.as_i64()))
            .filter(|&s| s >= 0)
            .sum()
    })
    .unwrap_or(0)
}

/// Compute sizes and counts from a content.json.
pub fn content_stats(content: &Value) -> ContentStats {
    let files = content.get("files").and_then(|f| f.as_object());
    let files_optional = content.get("files_optional").and_then(|f| f.as_object());
    ContentStats {
        size: sum_sizes(files),
        size_optional: sum_sizes(files_optional),
        files: files.map(|f| f.len()).unwrap_or(0),
        files_optional: files_optional.map(|f| f.len()).unwrap_or(0),
        includes: content.get("includes").and_then(|i| i.as_object()).map(|i| i.len()).unwrap_or(0),
        modified: content.get("modified").and_then(|m| m.as_f64()).unwrap_or(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stats_sum_sizes_and_count() {
        let content = json!({
            "modified": 1777992697.0,
            "files": {
                "index.html": {"size": 100, "sha512": "a"},
                "js/app.js": {"size": 250, "sha512": "b"},
            },
            "files_optional": {
                "big.mp4": {"size": 9000, "sha512": "c"},
            },
            "includes": {"data/content.json": {}},
        });
        let s = content_stats(&content);
        assert_eq!(s.size, 350);
        assert_eq!(s.size_optional, 9000);
        assert_eq!(s.files, 2);
        assert_eq!(s.files_optional, 1);
        assert_eq!(s.includes, 1);
        assert_eq!(s.modified, 1777992697.0);
    }

    #[test]
    fn settings_apply_and_limit() {
        let mut set = XiteSettings::new(1000);
        assert!(set.serving && !set.own);
        assert_eq!(set.wrapper_key.len(), 64);
        assert_ne!(set.wrapper_key, set.ajax_key);

        let content = json!({"modified": 42.0, "files": {"a": {"size": 5, "sha512": "x"}}});
        set.apply_content_stats(&content_stats(&content));
        assert_eq!(set.size, 5);
        assert_eq!(set.modified, 42.0);

        assert_eq!(set.size_limit(10_000_000), 10_000_000);
        set.size_limit = Some(20);
        assert_eq!(set.size_limit(10_000_000), 20);
    }
}
