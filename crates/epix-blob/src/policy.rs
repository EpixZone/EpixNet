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

    /// Whether a scheduler should pull the newest feed unit (segment, or the
    /// newest-modified record file) first and page backward. Pinned-first and
    /// custom have no scheduling signal of their own - the pinned/custom set is
    /// resolved by the app after the records arrive - so they schedule
    /// newest-first, which is what a reader sees first either way.
    pub fn newest_first(self) -> bool {
        !matches!(self, Self::OldestFirst)
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

    /// Whether `inner_path` is a declared prefetch hint (fetched after first
    /// paint, at the background deadline).
    pub fn is_prefetch(&self, inner_path: &str) -> bool {
        self.prefetch.iter().any(|p| p == inner_path)
    }

    /// Which fetch tier `inner_path` belongs to. First paint wins if a path is
    /// (nonsensically) in both lists. An undeclared path lands in
    /// [`FetchTier::Default`], so a xite with no `order_policy` puts every path
    /// in one tier and the scheduler's existing ladder is unchanged.
    ///
    /// This orders OUR OWN fetching only. The policy is owner-signed, so it is
    /// authentic, but "authentic" is not "trusted with someone else's
    /// bandwidth": it must never be echoed into a serving priority we grant a
    /// remote peer, or an owner could declare their whole xite first-paint and
    /// take service from everyone else's.
    pub fn tier(&self, inner_path: &str) -> FetchTier {
        if self.is_first_paint(inner_path) {
            FetchTier::FirstPaint
        } else if self.is_prefetch(inner_path) {
            FetchTier::Prefetch
        } else {
            FetchTier::Default
        }
    }

    /// Whether the owner declared anything at all. Nothing declared → the
    /// caller keeps its default ladder untouched.
    pub fn is_empty(&self) -> bool {
        self.first_paint.is_empty() && self.prefetch.is_empty() && self.feed_order.is_none()
    }
}

/// The fetch order tiers an [`OrderPolicy`] sorts paths into. `Ord` is the
/// scheduling order: first paint, then everything undeclared, then prefetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FetchTier {
    /// The visible shell: fetched first, at the tightest deadline.
    FirstPaint,
    /// Undeclared - the existing default ladder.
    Default,
    /// Declared prefetch hints: after first paint, background deadline.
    Prefetch,
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

    /// Plan the background completion pass for a xite: of `missing`
    /// (inner_path, size) pairs, keep only the paths whose unit committed to
    /// `retention:complete`, and report whether finishing them needs the
    /// user's consent.
    ///
    /// This is what makes the retention COMMITMENT real, and it is deliberately
    /// a plan rather than a fetch: completion happens in the BACKGROUND after
    /// first paint, so a package unit can never block the first render on a
    /// full download. `limit_bytes` is the xite's existing per-site size limit;
    /// over it the caller taps the same optional-download prompt a big optional
    /// file already raises, so there is no new consent UX.
    pub fn completion_plan(&self, missing: &[(String, u64)], limit_bytes: u64) -> CompletionPlan {
        let mut paths = Vec::new();
        let mut bytes = 0u64;
        for (path, size) in missing {
            if self.wants_complete(path) {
                paths.push(path.clone());
                bytes = bytes.saturating_add(*size);
            }
        }
        // Deterministic order so two nodes (and two test runs) plan alike.
        paths.sort();
        CompletionPlan { needs_consent: bytes > limit_bytes, paths, bytes }
    }
}

/// What a background completion pass would fetch, and whether it needs consent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompletionPlan {
    /// The still-missing paths belonging to `retention:complete` units.
    pub paths: Vec<String>,
    /// Their declared total size.
    pub bytes: u64,
    /// The total exceeds the xite's size limit, so the caller must have (or
    /// ask for) the user's optional-download consent before finishing.
    pub needs_consent: bool,
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
    fn tiers_reorder_declared_paths_and_default_when_absent() {
        let content = json!({
            "order_policy": {
                "first_paint": ["index.html", "css/all.css"],
                "prefetch": ["js/later.js"]
            }
        });
        let p = OrderPolicy::from_content(&content);
        // A scheduler sorts by tier; the declared shell goes first, the
        // prefetch hint last, everything undeclared keeps its place between.
        let mut paths = vec!["big.mp4", "js/later.js", "index.html", "data/x.json", "css/all.css"];
        paths.sort_by_key(|p2| p.tier(p2));
        assert_eq!(
            paths,
            vec!["index.html", "css/all.css", "big.mp4", "data/x.json", "js/later.js"],
            "first paint first, prefetch last, undeclared order preserved"
        );

        // Nothing declared -> one tier, so a stable sort is a no-op and the
        // caller's existing ladder survives untouched.
        let none = OrderPolicy::from_content(&json!({}));
        assert!(none.is_empty());
        let mut same = vec!["b", "a", "c"];
        same.sort_by_key(|p2| none.tier(p2));
        assert_eq!(same, vec!["b", "a", "c"], "no policy -> no reorder");
    }

    #[test]
    fn feed_order_schedules_newest_first_unless_oldest_declared() {
        assert!(FeedOrder::NewestFirst.newest_first());
        assert!(FeedOrder::PinnedFirst.newest_first(), "pinned resolves app-side; schedule newest");
        assert!(FeedOrder::Custom.newest_first());
        assert!(!FeedOrder::OldestFirst.newest_first());
    }

    #[test]
    fn completion_plan_gates_on_the_size_limit() {
        // A package shell committed to `complete`, a feed that stays partial.
        let content = json!({
            "distribution": {
                "default": {"unit": "package", "retention": "complete"},
                "paths": { "data/feed/": {"unit": "feed", "retention": "partial"} }
            }
        });
        let d = DistributionPolicy::from_content(&content);
        let missing = vec![
            ("js/app.js".to_string(), 3_000_000u64),
            ("img/hero.png".to_string(), 2_000_000),
            ("data/feed/seg7".to_string(), 90_000_000), // partial: never completed
        ];

        // Under the limit: completes quietly, no prompt.
        let quiet = d.completion_plan(&missing, 10_000_000);
        assert_eq!(quiet.paths, vec!["img/hero.png", "js/app.js"], "only complete-retention paths");
        assert_eq!(quiet.bytes, 5_000_000, "the partial feed is not counted");
        assert!(!quiet.needs_consent);

        // Over the limit: the familiar optional-download prompt gates it.
        let gated = d.completion_plan(&missing, 1_000_000);
        assert!(gated.needs_consent, "over the size limit -> consent required");

        // No declared distribution -> nothing to complete at all.
        let bare = DistributionPolicy::from_content(&json!({}));
        assert!(bare.completion_plan(&missing, 0).paths.is_empty());
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
