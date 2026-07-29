//! Node-side feed engine glue: derive the deterministic `epix-feed` artifacts
//! from a xite's existing signed OR-set records, cache them, and answer
//! per-target / gallery queries.
//!
//! This module holds the PURE parts (derivation + query shaping) that need no
//! `AppState`; the `AppState` methods that gather records off disk, cache the
//! blobs in the EDX store, and register the WS query commands live in
//! `state.rs`/`command.rs`. Everything here is read-only and recomputable: it
//! never mutates stored records, never re-signs, and never touches the
//! merge-file or db flow. The artifacts are a derived, content-addressed cache.
//!
//! STATUS: foundation. Nothing consumes it yet (the apps still read merge-files
//! directly), so it is safe to land. The finality model below is DECIDED (user,
//! 2026-07-29) but NOT YET IMPLEMENTED here; the current derivation still uses
//! cumulative sealing + a wall-clock boundary and must be reworked to match:
//!
//! DECIDED MODEL (implement before feeds go live):
//! 1. SEGMENTATION IS f(records), NEVER wall-clock. Segment k = records whose
//!    authored clock is in [k*I, (k+1)*I), folded canonically. Root depends
//!    only on those records + the fixed interval, so two honest nodes with the
//!    same records get byte-identical roots. Remove every `now`/skew from the
//!    boundary. (Fixes the old Finding 4 determinism bug.)
//! 2. ANTI-ROLLBACK IS RECORD-SET MONOTONE, not byte-frozen segments. The OR-set
//!    only grows, so a late-arriving old record legitimately GROWS its interval
//!    segment (addition, not rollback) and re-derives that ONE segment
//!    deterministically. A peer's checkpoint is valid iff its record set is a
//!    superset of what we hold AND every tombstone we hold stays present
//!    (tombstones sticky). Reject only a checkpoint that DROPS a signed record
//!    or un-sticks a tombstone. No frozen-blob / corrections machinery.
//!    (Dissolves the old Finding 1: a backfill grows the set, so it passes.)
//! 3. LIVE TAIL + INCREMENTAL. Interval size I = 1 day (86_400_000 ms). Seal an
//!    interval into the spine only once it is older than a 2-DAY grace window;
//!    the current + previous day stay the live gossiping OR-set (served as
//!    records, not a sealed root). A new record re-derives ONLY its own
//!    interval's segment + its target's index entries + its item's rollup,
//!    never the whole site. (Fixes the old Finding 2 O(n^2) recompute.)
//!    Interval/grace are per-feed-overridable defaults.

use std::collections::HashSet;

use epix_blob::ObjId;
use epix_feed::checkpoint::Checkpoint;
use epix_feed::index::TargetIndex;
use epix_feed::rollup::Rollup;
use epix_feed::segment::{seal, Segment, Spine};
use epix_feed::{canonical_order, Record};
use serde_json::{json, Value};

/// The segment interval grid (milliseconds). A sealed segment closes on the
/// boundary `(k+1)*I - 1`; the grid is a NETWORK-WIDE CONSTANT so every node
/// picks identical boundaries from identical records and derives byte-identical
/// segment roots. One day keeps the sealed-segment count small while still
/// freezing history promptly.
pub const SEGMENT_INTERVAL_MS: u64 = 86_400_000;

/// The derived feed artifacts for one (xite, feed), all pure functions of the
/// record set. Held per-(xite,feed) as a recomputable cache; the sealed
/// segments are also inserted into the EDX object store so they serve over the
/// wire like any content-addressed blob.
#[derive(Clone)]
pub struct FeedArtifacts {
    /// The deduped, canonically ordered record set the artifacts derive from.
    pub records: Vec<Record>,
    /// The open snapshot covering every record (the live tail included); its
    /// bytes back the per-target range fetch and the index.
    pub segment: Segment,
    /// target -> record locations inside `segment` (the O(window) fetch).
    pub index: TargetIndex,
    /// Live winners + reaction counts + sticky tombstones at the open boundary.
    pub checkpoint: Checkpoint,
    /// The monotone spine of sealed (frozen) cumulative segments.
    pub spine: Spine,
    /// The sealed segments backing `spine`, in boundary order. These are the
    /// immutable blobs cached in the EDX store.
    pub sealed: Vec<Segment>,
}

/// Derive every artifact from a record set as of `now_ms`. Pure and
/// deterministic: the same records at the same `now_ms` yield identical roots,
/// and the sealed spine is grid-aligned so its roots match on any node
/// regardless of `now_ms`.
pub fn derive_feed(mut records: Vec<Record>, now_ms: i64) -> FeedArtifacts {
    // Dedup by content address (an OR-set gossips the same record more than
    // once), then canonically order - the basis of every deterministic root.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    records.retain(|r| seen.insert(r.addr().0));
    canonical_order(&mut records);

    let now = now_ms.max(0) as u64;
    let skew = epix_content::CLOCK_SKEW_BOUND_MS.max(0) as u64;

    // The open snapshot includes every verified record (a valid clock is at
    // most now+skew), so the index and checkpoint see the whole set.
    let open_boundary = now.saturating_add(skew);
    let segment = seal(&records, open_boundary);
    let mut index = TargetIndex::new();
    index.add_segment(&segment);
    let checkpoint = Checkpoint::compute(&records, open_boundary, ObjId([0; 32]));

    // Sealed spine: one cumulative segment per CLOSED interval boundary that
    // contains a record. An interval k is closed only once now has passed its
    // end plus the skew bound, so no in-bounds record still lands inside a
    // sealed interval; a later recompute (more records in newer intervals, or
    // a newly-closed interval) only appends, so the spine grows monotonically.
    let mut spine = Spine::new();
    let mut sealed = Vec::new();
    let max_clock = records.iter().map(|r| r.clock).max().unwrap_or(0);
    // SEGMENT_INTERVAL_MS is a nonzero constant, so these divisions are exact.
    let max_k = max_clock / SEGMENT_INTERVAL_MS;
    // Start at the FIRST record's interval, not k=0. Record clocks are
    // ms-since-epoch (~20k days), so scanning from 1970 would walk ~20k empty
    // pre-history intervals on every call. Every interval below min_k holds no
    // record and would be `continue`d anyway, so this only drops dead
    // iterations - the sealed spine is byte-for-byte the same.
    let min_k = records.iter().map(|r| r.clock).min().unwrap_or(0) / SEGMENT_INTERVAL_MS;
    for k in min_k..=max_k {
        let interval_start = k * SEGMENT_INTERVAL_MS;
        let interval_end = (k + 1) * SEGMENT_INTERVAL_MS; // exclusive
        // Once an interval is still open, every later one is too.
        if now < interval_end.saturating_add(skew) {
            break;
        }
        // Skip an interval with no records in it (no new content to seal), so
        // the spine has one link per interval that actually closed data.
        let has_record =
            records.iter().any(|r| r.clock >= interval_start && r.clock < interval_end);
        if !has_record {
            continue;
        }
        let seg = seal(&records, interval_end - 1);
        if spine.append(&seg).is_ok() {
            sealed.push(seg);
        }
    }

    FeedArtifacts { records, segment, index, checkpoint, spine, sealed }
}

/// Shape a `feedItemQuery` response: the live records attached to `target`
/// (comments on a post, or the post itself), newest first, plus the target's
/// reaction counts and the roots a caller can re-derive to verify.
///
/// Uses the checkpoint's live set (edits folded, tombstoned dropped), so the
/// result is exactly the target's live winners; the index/segment back the
/// separate byte-range fetch a cold client uses.
pub fn item_query(
    art: &FeedArtifacts,
    target: &str,
    limit: Option<usize>,
    before_clock: Option<u64>,
) -> Value {
    let mut winners: Vec<&Record> = art
        .checkpoint
        .live
        .iter()
        // A comment attaches to `target`; a top-level post IS the target
        // (its own id, with an empty attach target).
        .filter(|r| r.target == target || (r.target.is_empty() && r.id == target))
        .filter(|r| before_clock.map(|bc| r.clock < bc).unwrap_or(true))
        .collect();
    // Newest first, ties broken deterministically by id.
    winners.sort_by(|a, b| b.clock.cmp(&a.clock).then_with(|| b.id.cmp(&a.id)));
    if let Some(l) = limit {
        winners.truncate(l);
    }
    let records: Vec<Value> = winners
        .iter()
        .filter_map(|r| serde_json::from_slice::<Value>(&r.canonical).ok())
        .collect();

    let reactions = art
        .checkpoint
        .reaction_counts
        .get(target)
        .map(|kinds| {
            Value::Object(kinds.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
        })
        .unwrap_or_else(|| json!({}));

    let mut segment_roots: Vec<String> = art.sealed.iter().map(|s| s.root.to_string()).collect();
    segment_roots.push(art.segment.root.to_string());

    json!({
        "target": target,
        "records": records,
        "reactions": reactions,
        "checkpoint_root": art.checkpoint.root.to_string(),
        "segment_roots": segment_roots,
    })
}

/// Shape a `feedGalleryRollup` response: per-item comment counts, reaction
/// counts, and newest-activity clock - one blob that paints a gallery landing
/// page without pulling every author's files.
pub fn gallery_rollup(art: &FeedArtifacts, items: &[String]) -> Value {
    let roll = Rollup::compute(items, &art.records);
    let mut map = serde_json::Map::new();
    for item in items {
        let summary = roll.get(item).cloned().unwrap_or_default();
        let reactions: serde_json::Map<String, Value> = summary
            .reactions
            .by_kind
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        map.insert(
            item.clone(),
            json!({
                "comment_count": summary.comment_count,
                "reactions": Value::Object(reactions),
                "newest_clock": summary.newest_clock,
            }),
        );
    }
    json!({ "items": Value::Object(map), "rollup_root": roll.root().to_string() })
}

/// Match a merge-file `inner_path` against a descriptor `files` glob. `*`
/// matches any run of characters within one path segment (no `/`); `**`
/// matches across segments. Enough for globs like `data/users/*/posts.json`.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    glob_inner(pattern.as_bytes(), path.as_bytes())
}

fn glob_inner(pat: &[u8], path: &[u8]) -> bool {
    // Iterative backtracking matcher (no regex dependency).
    let (mut p, mut s) = (0usize, 0usize);
    let (mut star_p, mut star_s): (Option<usize>, usize) = (None, 0);
    let mut star_crosses = false;
    while s < path.len() {
        if p < pat.len() && pat[p] == b'*' {
            let crosses = p + 1 < pat.len() && pat[p + 1] == b'*';
            let skip = if crosses { 2 } else { 1 };
            star_p = Some(p);
            star_crosses = crosses;
            star_s = s;
            p += skip;
        } else if p < pat.len() && (pat[p] == path[s]) {
            p += 1;
            s += 1;
        } else if let Some(sp) = star_p {
            // Backtrack: let the last `*` swallow one more char, unless a
            // single-segment `*` would have to cross a '/'.
            if !star_crosses && path[star_s] == b'/' {
                return false;
            }
            star_s += 1;
            s = star_s;
            p = if star_crosses { sp + 2 } else { sp + 1 };
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += if p + 1 < pat.len() && pat[p + 1] == b'*' { 2 } else { 1 };
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_content::record::record_signed_data;
    use epix_feed::adapter::{record_from_value, FeedDescriptor};
    use serde_json::json;

    // A runtime-generated signing key shared across this module's tests (no
    // hard-coded literal, per the record-module convention).
    fn key() -> &'static (String, String) {
        static K: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        K.get_or_init(|| {
            let pk = epix_crypt::new_seed();
            let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
            (pk, addr)
        })
    }

    fn author() -> String {
        key().1.clone()
    }

    fn comments_descriptor() -> FeedDescriptor {
        FeedDescriptor::parse(
            "comments",
            &json!({
                "files": "data/users/*/comments.json",
                "record_key": "comment",
                "map": { "id": "comment_id", "author": "author", "clock": "clock", "target": "post_id" },
                "kind": { "default": "comment" }
            }),
            None,
        )
        .unwrap()
    }

    /// A signed comment record + its adapter-converted `Record`. `deleted`
    /// makes it a tombstone. Mirrors how the node builds a Record: verify would
    /// pass (self-signed by an authorized author), canonical == dumps_sorted.
    fn comment(comment_id: &str, post_id: &str, clock: i64, deleted: bool) -> Record {
        let a = author();
        let mut rec = json!({
            "comment_id": comment_id, "post_id": post_id, "author": a,
            "clock": clock, "deleted": deleted, "body": if deleted { "" } else { "hi" },
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), &key().0).unwrap());
        let canonical = epix_content::dumps_sorted(&rec).into_bytes();
        record_from_value(&comments_descriptor(), &rec, canonical).unwrap()
    }

    #[test]
    fn same_records_different_order_same_roots() {
        // Determinism through the adapter: identical signed records delivered
        // in different orders (with a duplicate) derive identical roots.
        let base = vec![
            comment("c1", "p1", 1000, false),
            comment("c2", "p1", 2000, false),
            comment("c3", "p2", 3000, false),
        ];
        let now = 10_000_000;
        let a = derive_feed(base.clone(), now);

        let mut shuffled = base.clone();
        shuffled.reverse();
        shuffled.push(base[0].clone()); // duplicate delivery
        let b = derive_feed(shuffled, now);

        assert_eq!(a.segment.root, b.segment.root, "segment roots diverge");
        assert_eq!(a.index.root(), b.index.root(), "index roots diverge");
        assert_eq!(a.checkpoint.root, b.checkpoint.root, "checkpoint roots diverge");
        assert_eq!(a.spine.head(), b.spine.head(), "spine heads diverge");
    }

    #[test]
    fn per_target_query_returns_only_that_targets_live_records() {
        // p1 has c1, c2 (live) and c3 which is edited then the edit wins; p2
        // has c4 but it is tombstoned. Query p1 -> exactly its live winners.
        let records = vec![
            comment("c1", "p1", 1000, false),
            comment("c2", "p1", 2000, false),
            comment("c3", "p1", 1500, false),
            comment("c3", "p1", 5000, false), // edit of c3 (same id) wins
            comment("c4", "p2", 2500, false),
            comment("c4", "p2", 6000, true), // tombstone c4
        ];
        let art = derive_feed(records, 10_000_000);
        let resp = item_query(&art, "p1", None, None);
        let ids: Vec<String> = resp["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["comment_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids.len(), 3, "p1 has three live comment ids");
        assert!(ids.contains(&"c1".to_string()));
        assert!(ids.contains(&"c2".to_string()));
        assert!(ids.contains(&"c3".to_string()));
        // The edit folded to one winner (clock 5000), not two.
        let c3_clocks: Vec<i64> = resp["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["comment_id"] == json!("c3"))
            .map(|r| r["clock"].as_i64().unwrap())
            .collect();
        assert_eq!(c3_clocks, vec![5000], "the edit is the single live c3");

        // p2's only comment was tombstoned -> no live records.
        let p2 = item_query(&art, "p2", None, None);
        assert!(p2["records"].as_array().unwrap().is_empty(), "tombstoned comment is gone");

        // The index still locates p1's records for a range fetch.
        assert!(!art.index.locations("p1").is_empty());
    }

    #[test]
    fn recompute_after_new_record_extends_the_spine_monotonically() {
        // Day 0 has a record; recompute once day 0 is closed -> one sealed link.
        let day = SEGMENT_INTERVAL_MS;
        let now1 = (day + 10_000_000) as i64; // day 0 closed, day 1 open
        let first = vec![comment("c1", "p1", (day / 2) as i64, false)];
        let a = derive_feed(first.clone(), now1);
        assert_eq!(a.spine.links.len(), 1, "day 0 sealed into one link");

        // A new record lands in day 1; recompute once day 1 has also closed.
        let now2 = (2 * day + 10_000_000) as i64;
        let mut more = first;
        more.push(comment("c2", "p1", (day + day / 2) as i64, false));
        let b = derive_feed(more, now2);
        assert_eq!(b.spine.links.len(), 2, "day 1 added a second link");
        assert!(b.spine.is_extension_of(&a.spine), "the spine only grew (no rollback)");
    }

    #[test]
    fn glob_matches_user_merge_files() {
        assert!(glob_match("data/users/*/posts.json", "data/users/epix1abc/posts.json"));
        assert!(!glob_match("data/users/*/posts.json", "data/users/epix1abc/comments.json"));
        // A single `*` does not cross a path separator.
        assert!(!glob_match("data/users/*/posts.json", "data/users/a/b/posts.json"));
        assert!(glob_match("data/**/posts.json", "data/users/a/b/posts.json"));
    }
}
