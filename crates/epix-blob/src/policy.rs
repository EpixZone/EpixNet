//! Owner-declared load/stream order + distribution units (issue #340).
//!
//! Two creator-declared, owner-signed manifest features, both plain JSON
//! fields folded into the signed content.json (unknown fields already
//! ride inside the signature, so "add fields + re-sign" is the whole
//! mechanism), consumed fetcher-side.
//!
//! - **Order policy** ([`OrderPolicy`]): a first-paint set + a feed
//!   ordering directive (newest/oldest/pinned/custom) + prefetch hints,
//!   feeding the EDX deadline scheduler. Replaces the hardcoded
//!   download-priority ladder with an owner-declared one; the ladder
//!   stays the safe default when nothing is declared. EpixTalk =
//!   newest-first.
//! - **Distribution units** ([`DistributionUnit`], [`Retention`]):
//!   per-path `distribution_unit` (package | file-refs | feed) +
//!   `retention` (complete | partial). Content-addressing already gives
//!   #340's cross-site file-by-reference; this declares the completion
//!   policy. `retention:complete` is consent-gated (reuses the existing
//!   size-limit prompt) so it never ambushes first paint or a data cap.

use serde_json::Value;

/// How a feed's records stream in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedOrder {
    /// Newest segment + tail first, then page backward (forum default).
    NewestFirst,
    OldestFirst,
    /// Owner-pinned items first, then newest.
    PinnedFirst,
    /// A custom order the app resolves (falls back to newest-first for
    /// scheduling if the app declares nothing more specific).
    Custom,
}

impl FeedOrder {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "newest-first" => Some(Self::NewestFirst),
            "oldest-first" => Some(Self::OldestFirst),
            "pinned-first" => Some(Self::PinnedFirst),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// The owner's order policy for a xite (from `content.json.order_policy`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderPolicy {
    /// Paths to fetch first at tight deadlines (the visible shell).
    pub first_paint: Vec<String>,
    /// Feed ordering directive; None → scheduler default ladder.
    pub feed_order: Option<FeedOrder>,
    /// Extra paths to prefetch after first paint.
    pub prefetch: Vec<String>,
}

impl OrderPolicy {
    /// Read the policy from a parsed content.json. Absent/malformed →
    /// empty policy (the safe default ladder still applies).
    pub fn from_content(content: &Value) -> Self {
        let Some(p) = content.get("order_policy") else { return Self::default() };
        let str_list = |key: &str| -> Vec<String> {
            p.get(key)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        Self {
            first_paint: str_list("first_paint"),
            feed_order: p.get("feed_order").and_then(Value::as_str).and_then(FeedOrder::parse),
            prefetch: str_list("prefetch"),
        }
    }

    /// Whether `inner_path` is in the first-paint set (fetched at the
    /// tightest deadline, exempt from choking up to the free budget).
    pub fn is_first_paint(&self, inner_path: &str) -> bool {
        self.first_paint.iter().any(|p| p == inner_path)
    }
}

/// How a path is distributed (issue #340's creator-chosen unit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DistributionUnit {
    /// Whole-xite indivisible unit (blog/app): download-to-completion,
    /// reseed-whole.
    Package,
    /// Big media by reference: open → complete → seed that file;
    /// stream-to-play meanwhile.
    FileRefs,
    /// A feed: partial by nature (you can't complete 100M posts).
    Feed,
}

impl DistributionUnit {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "package" => Some(Self::Package),
            "file-refs" => Some(Self::FileRefs),
            "feed" => Some(Self::Feed),
            _ => None,
        }
    }
}

/// Retention commitment for a unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Finish downloading + reseed whole (consent-gated on size).
    Complete,
    /// Only fetch/seed what you viewed (the default everywhere).
    Partial,
}

impl Retention {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "complete" => Some(Self::Complete),
            "partial" => Some(Self::Partial),
            _ => None,
        }
    }
}

/// The distribution policy for one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathPolicy {
    pub unit: DistributionUnit,
    pub retention: Retention,
}

/// Per-path distribution rules (from `content.json.distribution`), matched
/// by longest declared path prefix. A xite MIXES units — a forum is a
/// package shell (complete) plus a feed (partial).
#[derive(Clone, Debug, Default)]
pub struct DistributionPolicy {
    /// (path_prefix, policy), longest-prefix wins.
    rules: Vec<(String, PathPolicy)>,
    default: Option<PathPolicy>,
}

impl DistributionPolicy {
    /// Parse from content.json. Shape:
    /// ```jsonc
    /// "distribution": {
    ///   "default": {"unit": "package", "retention": "complete"},
    ///   "paths": {
    ///     "data/feed/": {"unit": "feed", "retention": "partial"},
    ///     "media/":     {"unit": "file-refs", "retention": "complete"}
    ///   }
    /// }
    /// ```
    pub fn from_content(content: &Value) -> Self {
        let Some(d) = content.get("distribution") else { return Self::default() };
        let parse_policy = |v: &Value| -> Option<PathPolicy> {
            Some(PathPolicy {
                unit: DistributionUnit::parse(v.get("unit")?.as_str()?)?,
                retention: Retention::parse(v.get("retention")?.as_str()?)?,
            })
        };
        let default = d.get("default").and_then(parse_policy);
        let mut rules = Vec::new();
        if let Some(Value::Object(paths)) = d.get("paths") {
            for (prefix, v) in paths {
                if let Some(p) = parse_policy(v) {
                    rules.push((prefix.clone(), p));
                }
            }
        }
        // Longest prefix first so `resolve` can take the first match.
        rules.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self { rules, default }
    }

    /// The policy governing `inner_path` (longest declared prefix wins;
    /// else the default; else package/partial — stream-first, seed what
    /// you viewed, the universal safe behavior).
    pub fn resolve(&self, inner_path: &str) -> PathPolicy {
        for (prefix, policy) in &self.rules {
            if inner_path.starts_with(prefix.as_str()) {
                return *policy;
            }
        }
        self.default.unwrap_or(PathPolicy {
            unit: DistributionUnit::Package,
            retention: Retention::Partial,
        })
    }

    /// Whether fetching `inner_path` to completion needs the size-limit
    /// consent prompt: only `retention:complete` units, and only above the
    /// caller's size threshold (checked by the caller against the object
    /// size). Returns whether the path is complete-retention at all.
    pub fn wants_complete(&self, inner_path: &str) -> bool {
        self.resolve(inner_path).retention == Retention::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn order_policy_parses_and_defaults() {
        let content = json!({
            "order_policy": {
                "first_paint": ["index.html", "css/all.css"],
                "feed_order": "newest-first",
                "prefetch": ["js/app.js"]
            }
        });
        let p = OrderPolicy::from_content(&content);
        assert!(p.is_first_paint("index.html"));
        assert!(!p.is_first_paint("big.mp4"));
        assert_eq!(p.feed_order, Some(FeedOrder::NewestFirst));
        assert_eq!(p.prefetch, vec!["js/app.js"]);

        // Absent policy -> empty (safe default ladder applies elsewhere).
        assert_eq!(OrderPolicy::from_content(&json!({})), OrderPolicy::default());
    }

    #[test]
    fn epixtalk_defaults_newest_first() {
        let content = json!({ "order_policy": { "feed_order": "newest-first" } });
        assert_eq!(OrderPolicy::from_content(&content).feed_order, Some(FeedOrder::NewestFirst));
    }

    #[test]
    fn distribution_longest_prefix_wins_and_mixes_units() {
        // The EpixTalk case: a package shell + a feed + file-refs media.
        let content = json!({
            "distribution": {
                "default": {"unit": "package", "retention": "complete"},
                "paths": {
                    "data/feed/": {"unit": "feed", "retention": "partial"},
                    "media/": {"unit": "file-refs", "retention": "complete"}
                }
            }
        });
        let d = DistributionPolicy::from_content(&content);
        // The app shell falls to the package default (complete).
        assert_eq!(d.resolve("index.html").unit, DistributionUnit::Package);
        assert_eq!(d.resolve("index.html").retention, Retention::Complete);
        // The feed is partial.
        assert_eq!(d.resolve("data/feed/seg1").unit, DistributionUnit::Feed);
        assert_eq!(d.resolve("data/feed/seg1").retention, Retention::Partial);
        // Media is file-refs.
        assert_eq!(d.resolve("media/movie.mp4").unit, DistributionUnit::FileRefs);
    }

    #[test]
    fn absent_distribution_is_stream_first_partial() {
        let d = DistributionPolicy::from_content(&json!({}));
        let p = d.resolve("anything");
        assert_eq!(p.unit, DistributionUnit::Package);
        assert_eq!(p.retention, Retention::Partial, "default never ambushes a data cap");
        assert!(!d.wants_complete("anything"));
    }

    #[test]
    fn wants_complete_gates_only_complete_paths() {
        let content = json!({
            "distribution": {
                "default": {"unit": "package", "retention": "partial"},
                "paths": { "app/": {"unit": "package", "retention": "complete"} }
            }
        });
        let d = DistributionPolicy::from_content(&content);
        assert!(d.wants_complete("app/index.html"));
        assert!(!d.wants_complete("other/file"));
    }
}
