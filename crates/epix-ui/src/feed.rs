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
//! 2026-07-29) and IMPLEMENTED here:
//!
//! DECIDED MODEL:
//! 1. SEGMENTATION IS f(records), NEVER wall-clock. Segment k = records whose
//!    authored clock is in [k*I, (k+1)*I), sealed at the fixed edge
//!    (k+1)*I - 1. The root depends only on those records + the fixed interval,
//!    so two honest nodes with the same records get byte-identical roots.
//!    `derive_feed` takes NO `now`: no wall clock enters any root.
//! 2. ANTI-ROLLBACK IS RECORD-SET MONOTONE, not byte-frozen segments. The OR-set
//!    only grows, so a late-arriving old record legitimately GROWS its interval
//!    segment (addition, not rollback) and re-derives that ONE segment
//!    deterministically. A peer's checkpoint is valid iff its record set is a
//!    superset of what we hold AND every tombstone we hold stays present
//!    (tombstones sticky). Reject only a checkpoint that DROPS a signed record
//!    or un-sticks a tombstone. Do NOT assert an old segment root is byte-frozen
//!    across recomputes - a late old record re-derives its one interval segment.
//! 3. LIVE TAIL / GRACE IS A CACHING POLICY, not part of derivation. Interval
//!    size I = 1 day (86_400_000 ms). `derive_feed` is pure and seals EVERY
//!    non-empty interval; whether the caller pins the churny recent segments is
//!    a serving choice that touches no root (see `recompute_feeds`).
//! 4. INCREMENTAL is a perf follow-up. `derive_feed` is O(n log n) per call: it
//!    groups records into their populated intervals only (never a dense scan
//!    over the clock range, which an author-controlled clock could blow up), so
//!    a single crafted clock cannot make it loop. A future change may re-derive
//!    only the changed interval; for now the whole set is refolded on each call.

use std::collections::{BTreeMap, HashSet};

use epix_blob::ObjId;
use epix_feed::checkpoint::Checkpoint;
use epix_feed::index::TargetIndex;
use epix_feed::rollup::Rollup;
use epix_feed::segment::{record_extents, seal, Segment, Spine};
use epix_feed::{canonical_order, Record};
use epix_search::xor8::Xor8;
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
    /// target -> record locations across the sealed segments (the O(window)
    /// fetch). Built from every per-interval segment, so it covers all records.
    pub index: TargetIndex,
    /// Live winners + reaction counts + sticky tombstones at the max-clock
    /// boundary (deterministic, covers all records).
    pub checkpoint: Checkpoint,
    /// The monotone spine of sealed per-interval segments.
    pub spine: Spine,
    /// The sealed per-interval segments backing `spine`, in boundary order.
    /// These are the immutable blobs cached in the EDX store.
    pub sealed: Vec<Segment>,
    /// One XOR8 skip-filter per entry of `sealed`, same order. Derived, so
    /// losing them is harmless - they rebuild byte-identically from the
    /// records. See [`segment_filter`].
    pub filters: Vec<Xor8>,
}

/// Domain separator for the skip-filter sibling object key. Part of the frozen
/// format: changing it re-keys every filter on the network.
const SKIP_FILTER_DOMAIN: &[u8] = b"epix-feed-skipfilter-v1";

/// The EDX object id a segment's skip-filter is stored under: a SIBLING object
/// keyed by the segment root, not a field folded into the segment itself.
///
/// Folding the filter into the segment root would be a stronger commitment (the
/// owner's signature would then cover the filter), but it changes `Segment`'s
/// byte format and therefore every segment root already derived, and it would
/// make a filter-format revision a consensus break for the whole feed. A
/// sibling object costs nothing in trust: the filter is only ever used to SKIP
/// work, and every surviving candidate is fetched and verified against the
/// segment root anyway, so a wrong or hostile filter can waste a fetch or hide
/// a result but can never forge one. Any node re-derives the true filter from
/// the segment bytes it already verified.
pub fn skip_filter_id(segment_root: ObjId) -> ObjId {
    let mut buf = Vec::with_capacity(SKIP_FILTER_DOMAIN.len() + 32);
    buf.extend_from_slice(SKIP_FILTER_DOMAIN);
    buf.extend_from_slice(&segment_root.0);
    ObjId::of(&buf)
}

/// Build the deterministic XOR8 skip-filter over one sealed segment's terms.
///
/// DETERMINISM: the input is the segment's canonical record bytes (already
/// frozen by `seal`), the tokenizer is `epix_search::tokenize` (frozen v1:
/// ASCII lowercase fold, non-alphanumeric splits, 2..=40 byte tokens), the key
/// is `epix_search::term_hash` (BLAKE3 truncated), and `Xor8::build` uses a
/// fixed seed schedule with keys sorted+deduped first. So any node holding the
/// same segment rebuilds byte-identical filter bytes.
///
/// UNICODE: the v1 tokenizer treats every non-ASCII byte as a separator, so
/// non-Latin text contributes no terms and its segments are never skipped for
/// those queries (they fall through to the candidate path). That is a
/// correctness-preserving limitation, not a silent one: adding normalization is
/// a tokenizer format bump that re-keys every filter.
pub fn segment_filter(seg: &Segment) -> Xor8 {
    let mut keys: Vec<u64> = Vec::new();
    for r in &seg.records {
        for term in record_terms(r) {
            keys.push(epix_search::term_hash(&term));
        }
    }
    keys.sort_unstable();
    keys.dedup();
    Xor8::build(&keys)
}

/// The searchable terms of one record: every string leaf of its canonical JSON
/// (post bodies, titles, tags), tokenized. Only string VALUES, so JSON field
/// names do not end up in every segment's filter and drown the skip signal. A
/// record whose canonical bytes are not JSON falls back to tokenizing them as
/// text, which is still deterministic.
fn record_terms(r: &Record) -> Vec<String> {
    match serde_json::from_slice::<Value>(&r.canonical) {
        Ok(v) => {
            let mut out = Vec::new();
            collect_strings(&v, &mut out);
            out
        }
        Err(_) => epix_search::tokenize(&String::from_utf8_lossy(&r.canonical)),
    }
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.extend(epix_search::tokenize(s)),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        // BTreeMap-backed, so this walks keys in a fixed order.
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// Derive every artifact from a record set. Pure and deterministic with NO
/// wall clock: any two nodes holding the same records derive byte-identical
/// roots. Segmentation is a pure function of record clocks - each non-empty
/// interval `k` (clocks in `[k*I, (k+1)*I)`) seals at the fixed edge
/// `(k+1)*I - 1`, the checkpoint closes at the max record clock.
pub fn derive_feed(mut records: Vec<Record>) -> FeedArtifacts {
    // Dedup by content address (an OR-set gossips the same record more than
    // once), then canonically order - the basis of every deterministic root.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    records.retain(|r| seen.insert(r.addr().0));
    canonical_order(&mut records);

    // One sealed segment per NON-EMPTY interval. `seal` filters `clock <=
    // boundary` internally, so passing only interval k's records with boundary
    // `end - 1` keeps exactly those; the segment root depends only on that
    // interval's records and the fixed grid, never on wall time or on records
    // from other intervals. Grouping into a BTreeMap keyed by interval index
    // yields intervals in ascending order, so boundaries strictly increase and
    // the spine appends monotonically. Iterating only the POPULATED intervals
    // (not the dense [min_k, max_k] range) keeps this O(n log n): `clock` is
    // author-controlled up to i64::MAX, so a single crafted record with a huge
    // clock would make a dense scan run ~10^11 times. The index is built from
    // these segments, so it covers every record (each falls in exactly one
    // non-empty interval).
    let mut index = TargetIndex::new();
    let mut spine = Spine::new();
    let mut sealed = Vec::new();
    let mut by_k: BTreeMap<u64, Vec<Record>> = BTreeMap::new();
    for r in &records {
        // SEGMENT_INTERVAL_MS is a nonzero constant, so this division is exact.
        by_k.entry(r.clock / SEGMENT_INTERVAL_MS).or_default().push(r.clone());
    }
    let mut filters = Vec::new();
    for (k, in_k) in by_k {
        let end = (k + 1) * SEGMENT_INTERVAL_MS; // exclusive
        let seg = seal(&in_k, end - 1);
        index.add_segment(&seg);
        if spine.append(&seg).is_ok() {
            // Sealing a segment commits its skip-filter with it: both are pure
            // functions of the same frozen record bytes.
            filters.push(segment_filter(&seg));
            sealed.push(seg);
        }
    }

    // The checkpoint boundary is the max record clock: deterministic and
    // covers every record (never now+skew).
    let boundary = records.iter().map(|r| r.clock).max().unwrap_or(0);
    let checkpoint = Checkpoint::compute(&records, boundary, ObjId([0; 32]));

    FeedArtifacts { records, index, checkpoint, spine, sealed, filters }
}

/// Shape a `feedSegmentSearch` response: walk the segment spine, SKIP every
/// segment whose XOR8 filter rejects all query terms, and return the matching
/// records of the surviving candidates as verifiable POINTERS.
///
/// The skip is sound because XOR8 has no false negatives: a filter that says
/// "absent" is proof the term is not in that segment, so nothing real is
/// dropped. A false positive only costs a candidate scan.
///
/// TRUST: every hit is returned as `(segment_root, offset, len)` plus the
/// record's own content address, exactly what `record_extents` locates, so a
/// caller range-fetches the bytes and checks them against the segment root
/// before believing anything. SOUNDNESS is therefore trustless - a lying
/// answerer cannot inject a match. COMPLETENESS is only relative to the
/// owner-signed committed record set: a xite owner who never publishes a record
/// (or whose committed set omits it) makes it unfindable, the same owner-trust
/// content.json already carries. We do not claim more.
///
/// A record matches when it contains EVERY query term (AND semantics), matching
/// what the filter pre-check tests for.
pub fn segment_search(art: &FeedArtifacts, terms: &[String], limit: usize) -> Value {
    // Tokenize the query with the same frozen tokenizer that built the filters,
    // so "Hello!" and "hello" hit the same keys.
    let query: Vec<String> = {
        let mut t: Vec<String> =
            terms.iter().flat_map(|t| epix_search::tokenize(t)).collect();
        t.sort();
        t.dedup();
        t
    };
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    let mut skipped = 0usize;
    // A query with no usable terms (empty, all sub-2-byte, or all non-ASCII -
    // the v1 tokenizer indexes ASCII alphanumeric runs only) matches NOTHING.
    // Returning early matters: the per-record check below is `all()`, which is
    // vacuously true for an empty query, so falling through would hand back the
    // first `limit` records of the feed as if they were hits - and scan every
    // segment to do it. `unindexable_query` tells the caller its terms were
    // not searchable rather than that the feed is empty.
    if query.is_empty() {
        return json!({
            "terms": query,
            "pointers": [],
            "unindexable_query": true,
            "segments_total": art.sealed.len(),
            "segments_skipped": 0,
            "segments_scanned": 0,
            "spine_head": art.spine.head().to_string(),
        });
    }
    for (i, seg) in art.sealed.iter().enumerate() {
        // Skip only when a query term is provably absent from the whole
        // segment. Xor8 has no false negatives, so a term the segment holds
        // always reports present; AND-semantics means one absent term rules
        // out every record here. A missing filter scans (never skips).
        let candidate = match art.filters.get(i) {
            Some(f) => query.iter().all(|t| f.contains(epix_search::term_hash(t))),
            None => true,
        };
        if !candidate {
            skipped += 1;
            continue;
        }
        scanned += 1;
        let extents = record_extents(seg);
        for (r, (addr, offset, len)) in seg.records.iter().zip(extents) {
            if hits.len() >= limit {
                break;
            }
            let terms_of = record_terms(r);
            if !query.iter().all(|t| terms_of.contains(t)) {
                continue;
            }
            hits.push(json!({
                "record": addr.to_string(),
                "segment_root": seg.root.to_string(),
                "offset": offset,
                "len": len,
                "id": r.id,
                "target": r.target,
                "clock": r.clock,
            }));
        }
        if hits.len() >= limit {
            break;
        }
    }
    json!({
        "terms": query,
        "pointers": hits,
        "segments_total": art.sealed.len(),
        "segments_skipped": skipped,
        "segments_scanned": scanned,
        "spine_head": art.spine.head().to_string(),
    })
}

/// Shape a `feedItemQuery` response: the live records attached to `target`
/// (comments on a post, or the post itself), newest first, plus the target's
/// reaction counts and the roots a caller can re-derive to verify.
///
/// Uses the checkpoint's live set (edits folded, tombstoned dropped), so the
/// result is exactly the target's live winners; the index and sealed segments
/// back the separate byte-range fetch a cold client uses.
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

    // The sealed per-interval roots a caller re-derives to verify (the open
    // snapshot is gone: every record lives in some sealed segment).
    let segment_roots: Vec<String> = art.sealed.iter().map(|s| s.root.to_string()).collect();

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
        comment_saying(comment_id, post_id, clock, deleted, "hi")
    }

    /// [`comment`] with a chosen body (what the search filter indexes).
    fn comment_saying(
        comment_id: &str,
        post_id: &str,
        clock: i64,
        deleted: bool,
        body: &str,
    ) -> Record {
        let a = author();
        let mut rec = json!({
            "comment_id": comment_id, "post_id": post_id, "author": a,
            "clock": clock, "deleted": deleted, "body": if deleted { "" } else { body },
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), &key().0).unwrap());
        let canonical = epix_content::dumps_sorted(&rec).into_bytes();
        record_from_value(&comments_descriptor(), &rec, canonical).unwrap()
    }

    #[test]
    fn same_records_same_roots_regardless_of_order() {
        // Determinism with NO wall clock: identical signed records delivered in
        // different orders (with a duplicate) derive identical roots. Any two
        // derivations of the same set now agree - there is no `now` to differ.
        let base = vec![
            comment("c1", "p1", 1000, false),
            comment("c2", "p1", 2000, false),
            comment("c3", "p2", 3000, false),
        ];
        let a = derive_feed(base.clone());

        let mut shuffled = base.clone();
        shuffled.reverse();
        shuffled.push(base[0].clone()); // duplicate delivery
        let b = derive_feed(shuffled);

        assert_eq!(a.index.root(), b.index.root(), "index roots diverge");
        assert_eq!(a.checkpoint.root, b.checkpoint.root, "checkpoint roots diverge");
        assert_eq!(a.spine.head(), b.spine.head(), "spine heads diverge");
        let a_roots: Vec<_> = a.sealed.iter().map(|s| s.root).collect();
        let b_roots: Vec<_> = b.sealed.iter().map(|s| s.root).collect();
        assert_eq!(a_roots, b_roots, "sealed segment roots diverge");
    }

    #[test]
    fn each_interval_seals_over_only_its_own_records() {
        // Two days of records -> two segments, each sealed over ONLY its day's
        // records (no cumulative carry-over from earlier days).
        let day = SEGMENT_INTERVAL_MS as i64;
        let records = vec![
            comment("c1", "p1", 1000, false),             // day 0
            comment("c2", "p1", 2000, false),             // day 0
            comment("c3", "p2", day + 1000, false),       // day 1
        ];
        let art = derive_feed(records);
        assert_eq!(art.sealed.len(), 2, "one segment per non-empty day");

        // Day 0 segment holds exactly c1, c2; day 1 segment holds exactly c3.
        let day0 = &art.sealed[0];
        let day1 = &art.sealed[1];
        assert_eq!(day0.boundary, SEGMENT_INTERVAL_MS - 1);
        assert_eq!(day1.boundary, 2 * SEGMENT_INTERVAL_MS - 1);
        let ids0: Vec<&str> = day0.records.iter().map(|r| r.id.as_str()).collect();
        let ids1: Vec<&str> = day1.records.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids0.len(), 2, "day 0 seals only its two records");
        assert!(ids0.contains(&"c1") && ids0.contains(&"c2"));
        assert_eq!(ids1, vec!["c3"], "day 1 seals only its one record");

        // Sealing that day's records alone reproduces the exact segment root.
        let day1_alone = seal(&[comment("c3", "p2", day + 1000, false)], 2 * SEGMENT_INTERVAL_MS - 1);
        assert_eq!(day1.root, day1_alone.root, "day 1 root is a pure f(day 1 records)");
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
        let art = derive_feed(records);
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
    fn adding_a_record_grows_the_set_and_spine_nothing_dropped() {
        // Record-set monotone: day 0 seals into one link; adding a day-1 record
        // grows the record set and appends a second link. Day 0's segment root
        // is unchanged (same day-0 records), so here the spine also cleanly
        // extends - but the acceptance rule is that the record set is a superset
        // and no signed record was dropped, not that segments are byte-frozen.
        let day = SEGMENT_INTERVAL_MS as i64;
        let first = vec![comment("c1", "p1", day / 2, false)];
        let a = derive_feed(first.clone());
        assert_eq!(a.spine.links.len(), 1, "day 0 sealed into one link");

        let mut more = first.clone();
        more.push(comment("c2", "p1", day + day / 2, false));
        let b = derive_feed(more);
        assert_eq!(b.spine.links.len(), 2, "day 1 added a second link");
        assert!(b.spine.is_extension_of(&a.spine), "same-interval segments unchanged, spine grew");

        // The record set is a strict superset and drops nothing.
        let a_ids: HashSet<&str> = a.records.iter().map(|r| r.id.as_str()).collect();
        let b_ids: HashSet<&str> = b.records.iter().map(|r| r.id.as_str()).collect();
        assert!(a_ids.is_subset(&b_ids), "no signed record dropped");
        assert!(b_ids.len() > a_ids.len(), "the set grew");
    }

    #[test]
    fn late_old_record_re_derives_its_interval_and_grows_the_set() {
        // Records arrive newest-first: a day-2 record is derived, THEN an old
        // day-0 record shows up. Derivation is order-free, so the full set
        // re-derives deterministically, seals the old record's interval, and
        // the checkpoint live set is a superset - nothing rolls back.
        let day = SEGMENT_INTERVAL_MS as i64;
        let newer = vec![comment("c2", "p1", 2 * day + 1000, false)]; // day 2
        let a = derive_feed(newer.clone());
        assert_eq!(a.sealed.len(), 1, "only day 2 sealed so far");

        // The old record lands in day 0 (an already-passed interval).
        let mut full = newer.clone();
        full.push(comment("c1", "p1", 1000, false)); // day 0
        let b = derive_feed(full.clone());
        // A shuffled delivery of the same set derives byte-identical roots.
        let mut shuffled = full.clone();
        shuffled.reverse();
        let b2 = derive_feed(shuffled);

        assert_eq!(b.spine.head(), b2.spine.head(), "late old record re-derives deterministically");
        assert_eq!(b.checkpoint.root, b2.checkpoint.root, "checkpoint deterministic");
        // Day 0 now seals its own segment; day 2 is still present.
        assert_eq!(b.sealed.len(), 2, "day 0's interval now has a sealed segment");
        assert_eq!(b.sealed[0].boundary, SEGMENT_INTERVAL_MS - 1, "day 0 sealed at its own edge");

        // The checkpoint live set is a superset of the newer-only derivation.
        let a_live: HashSet<&str> = a.checkpoint.live.iter().map(|r| r.id.as_str()).collect();
        let b_live: HashSet<&str> = b.checkpoint.live.iter().map(|r| r.id.as_str()).collect();
        assert!(a_live.is_subset(&b_live), "no live record dropped by the late arrival");
        assert!(b_live.contains("c1") && b_live.contains("c2"), "both records live");
    }

    #[test]
    fn skip_filter_rejects_unrelated_segments_and_never_misses_a_real_match() {
        // Three days, three vocabularies. A query for one day's word must skip
        // the other two segments outright and still find every real match.
        let day = SEGMENT_INTERVAL_MS as i64;
        let records = vec![
            comment_saying("c1", "p1", 1000, false, "banana smoothie recipe"),
            comment_saying("c2", "p1", 2000, false, "another banana note"),
            comment_saying("c3", "p2", day + 1000, false, "quantum tunneling notes"),
            comment_saying("c4", "p3", 2 * day + 1000, false, "sourdough starter"),
        ];
        let art = derive_feed(records.clone());
        assert_eq!(art.sealed.len(), 3);
        assert_eq!(art.filters.len(), art.sealed.len(), "one filter per sealed segment");

        let resp = segment_search(&art, &["banana".into()], 50);
        assert_eq!(resp["segments_total"], json!(3));
        assert_eq!(resp["segments_scanned"], json!(1), "only day 0 survives the filter");
        assert_eq!(resp["segments_skipped"], json!(2), "unrelated segments are skipped");
        let ptrs = resp["pointers"].as_array().unwrap();
        assert_eq!(ptrs.len(), 2, "both banana comments found");

        // The pointers are verifiable: the byte extent inside the named
        // segment is exactly the record's canonical bytes.
        for p in ptrs {
            let root = p["segment_root"].as_str().unwrap();
            let seg = art.sealed.iter().find(|s| s.root.to_string() == root).unwrap();
            let off = p["offset"].as_u64().unwrap() as usize;
            let len = p["len"].as_u64().unwrap() as usize;
            let slice = &seg.bytes[off..off + len];
            assert_eq!(
                epix_blob::ObjId::of(slice).to_string(),
                p["record"].as_str().unwrap(),
                "the extent hashes to the advertised record address"
            );
        }

        // NO FALSE NEGATIVES: every term of every record finds its own record.
        for r in &records {
            for term in record_terms(r) {
                let resp = segment_search(&art, &[term.clone()], 50);
                let found = resp["pointers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["record"].as_str().unwrap() == r.addr().to_string());
                assert!(found, "term '{term}' must never miss its own record");
            }
        }

        // A term nobody wrote skips everything (the whole point of the track).
        let none = segment_search(&art, &["xylophone".into()], 50);
        assert!(none["pointers"].as_array().unwrap().is_empty());
        assert_eq!(none["segments_scanned"], json!(0), "no candidate segments at all");
    }

    /// A query the v1 tokenizer cannot index must return NOTHING, not the
    /// whole feed. Regression: the per-record match is `all()`, which is
    /// vacuously true for an empty term list, so an unindexable query used to
    /// fall through the filter and hand back the first `limit` records as if
    /// every one of them matched (while scanning every segment to do it).
    #[test]
    fn an_unindexable_query_matches_nothing_rather_than_everything() {
        let records = vec![
            comment_saying("c1", "p1", 1000, false, "banana smoothie recipe"),
            comment_saying("c2", "p1", 2000, false, "another banana note"),
        ];
        let art = derive_feed(records);
        assert!(!art.sealed.is_empty(), "there is content to accidentally return");

        // Non-ASCII (tokenizer indexes ASCII alphanumeric runs only), a
        // sub-2-byte term, and pure punctuation all tokenize to nothing.
        for q in ["\u{65e5}\u{672c}\u{8a9e}", "a", "!!"] {
            let resp = segment_search(&art, &[q.to_string()], 50);
            assert!(
                resp["pointers"].as_array().unwrap().is_empty(),
                "query {q:?} must match nothing, got {:?}",
                resp["pointers"]
            );
            assert_eq!(resp["unindexable_query"], json!(true), "flagged for {q:?}");
            assert_eq!(resp["segments_scanned"], json!(0), "and scans nothing for {q:?}");
        }
    }

    #[test]
    fn skip_filters_are_deterministic_and_keyed_by_segment_root() {
        // Any node rebuilds byte-identical filters from the same records, in
        // any delivery order - the Phase-G determinism requirement.
        let base = vec![
            comment_saying("c1", "p1", 1000, false, "alpha beta"),
            comment_saying("c2", "p1", 2000, false, "gamma delta"),
        ];
        let a = derive_feed(base.clone());
        let mut shuffled = base.clone();
        shuffled.reverse();
        let b = derive_feed(shuffled);
        let a_bytes: Vec<Vec<u8>> = a.filters.iter().map(|f| f.to_bytes()).collect();
        let b_bytes: Vec<Vec<u8>> = b.filters.iter().map(|f| f.to_bytes()).collect();
        assert_eq!(a_bytes, b_bytes, "filter bytes must be reproducible");
        assert!(!a_bytes[0].is_empty());

        // Round-trips through the stored sibling object form.
        let back = epix_search::xor8::Xor8::from_bytes(&a_bytes[0]).unwrap();
        assert!(back.contains(epix_search::term_hash("alpha")));

        // The sibling key is a pure function of the segment root, and distinct
        // from it (so it cannot collide with the segment object itself).
        let root = a.sealed[0].root;
        assert_eq!(skip_filter_id(root), skip_filter_id(root));
        assert_ne!(skip_filter_id(root), root);
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
