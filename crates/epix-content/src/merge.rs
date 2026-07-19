//! The signed grow-only OR-Set merge for the `posts.json` merge-file class
//! (Option A, `docs/signed-crdt-posts-plan.md` §3).
//!
//! A container is `{ "record_format": "epix-orset-1", "post": [ <record>, … ] }`.
//! [`merge_orset`] unions the verified records of two containers (dedup by
//! signature); it NEVER removes a version, so a blank or partial container
//! merges to a no-op - that is the invariant that kills the blank-publish wipe.
//! The live view for feeds/DB is computed at read time by [`live_records`],
//! which folds each `post_id`'s versions to a single deterministic display
//! winner (tombstones hide the post; concurrent edits are retained on disk but
//! only the winner is shown).
//!
//! `watermark` compaction is deferred (see the plan §0): all versions are
//! retained, so a losing concurrent version simply stays on disk (recoverable).

use crate::record::verify_record;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The container `record_format` marker (untrusted; unknown values still parse).
pub const RECORD_FORMAT: &str = "epix-orset-1";

/// The records array of a container (empty if absent/malformed).
pub fn records_of(container: &Value) -> Vec<Value> {
    container.get("post").and_then(|v| v.as_array()).cloned().unwrap_or_default()
}

/// Wrap a set of records into a canonical container.
pub fn make_container(records: Vec<Value>) -> Value {
    json!({ "record_format": RECORD_FORMAT, "post": records })
}

fn sign_of(r: &Value) -> &str {
    r.get("sign").and_then(|v| v.as_str()).unwrap_or("")
}
fn post_id_of(r: &Value) -> Option<i64> {
    r.get("post_id").and_then(|v| v.as_i64())
}
fn clock_of(r: &Value) -> i64 {
    r.get("clock").and_then(|v| v.as_i64()).unwrap_or(0)
}
fn supersedes_of(r: &Value) -> i64 {
    r.get("supersedes").and_then(|v| v.as_i64()).unwrap_or(0)
}
fn is_deleted(r: &Value) -> bool {
    r.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Deterministic on-disk order: `(post_id, clock, sign)`. Makes merge output
/// byte-stable across nodes (a convenience, not required for correctness).
fn sort_records(records: &mut [Value]) {
    records.sort_by(|a, b| {
        post_id_of(a)
            .cmp(&post_id_of(b))
            .then(clock_of(a).cmp(&clock_of(b)))
            .then(sign_of(a).cmp(sign_of(b)))
    });
}

/// Merge two containers into the union of their VERIFIED records, deduped by
/// signature. Grow-only and commutative + idempotent: no version is ever
/// dropped for being absent on one side. Every record (local and inbound) is
/// re-verified against `valid_signers`, so a poisoned on-disk file cannot
/// smuggle a forged record through a merge. `now_ms` bounds record clocks.
pub fn merge_orset(local: &Value, inbound: &Value, valid_signers: &[String], now_ms: i64) -> Value {
    let mut by_sign: BTreeMap<String, Value> = BTreeMap::new();
    for r in records_of(local).into_iter().chain(records_of(inbound)) {
        if verify_record(&r, valid_signers, now_ms).is_err() {
            continue;
        }
        let sig = sign_of(&r).to_string();
        if sig.is_empty() {
            continue;
        }
        by_sign.entry(sig).or_insert(r);
    }
    let mut records: Vec<Value> = by_sign.into_values().collect();
    sort_records(&mut records);
    make_container(records)
}

/// Whether version `b` causally dominates version `a`: `b` was written by an
/// author who had already observed `a` (`b.supersedes >= a.clock`). A dominated
/// version is superseded and drops out of the live frontier.
fn dominates(b: &Value, a: &Value) -> bool {
    sign_of(b) != sign_of(a) && supersedes_of(b) >= clock_of(a)
}

/// The causal frontier of a `post_id`'s versions: those not dominated by any
/// other version. Normally size 1; >1 means a genuine concurrent conflict.
fn frontier<'a>(versions: &[&'a Value]) -> Vec<&'a Value> {
    versions
        .iter()
        .copied()
        .filter(|a| !versions.iter().any(|b| dominates(b, a)))
        .collect()
}

/// The single deterministic display winner among a `post_id`'s versions.
/// Delete-wins (a tombstone in the frontier beats a concurrent live edit, for
/// privacy - no zombie post), then highest clock, then lexicographically
/// greater signature. Returns `None` only for an empty input.
pub fn display_winner<'a>(versions: &[&'a Value]) -> Option<&'a Value> {
    frontier(versions).into_iter().max_by(|a, b| {
        is_deleted(a)
            .cmp(&is_deleted(b))
            .then(clock_of(a).cmp(&clock_of(b)))
            .then(sign_of(a).cmp(sign_of(b)))
    })
}

/// The live records of a container: for each `post_id`, its display winner,
/// excluding tombstones. This is what the merger DB ingests and the feed shows.
/// Order is by `post_id` ascending (callers re-sort for display as needed).
pub fn live_records(container: &Value) -> Vec<Value> {
    let records = records_of(container);
    let mut groups: BTreeMap<i64, Vec<&Value>> = BTreeMap::new();
    for r in &records {
        if let Some(pid) = post_id_of(r) {
            groups.entry(pid).or_default().push(r);
        }
    }
    let mut live = Vec::new();
    for (_pid, versions) in groups {
        if let Some(w) = display_winner(&versions) {
            if !is_deleted(w) {
                live.push(w.clone());
            }
        }
    }
    live
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{derive_post_id, record_signed_data};

    const PRIV: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

    fn author() -> String {
        epix_crypt::privatekey_to_address(PRIV).unwrap()
    }

    /// A signed version of a post. `nonce`/`date_added` fix the post_id lineage;
    /// vary `clock`/`supersedes`/`deleted`/`body` for edits & tombstones.
    fn ver(nonce: &str, clock: i64, supersedes: i64, deleted: bool, body: &str) -> Value {
        let a = author();
        let date_added = 1737331200_i64;
        let post_id = derive_post_id(&a, nonce, date_added);
        let mut rec = json!({
            "post_id": post_id, "nonce": nonce, "author": a,
            "clock": clock, "supersedes": supersedes, "deleted": deleted,
            "body": body, "date_added": date_added,
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), PRIV).unwrap());
        rec
    }

    fn signers() -> Vec<String> {
        vec![author()]
    }

    fn bodies(container: &Value) -> Vec<String> {
        let mut b: Vec<String> = live_records(container)
            .iter()
            .map(|r| r["body"].as_str().unwrap_or("").to_string())
            .collect();
        b.sort();
        b
    }

    #[test]
    fn merge_is_commutative_and_idempotent() {
        let a = make_container(vec![ver("p1", 1, 0, false, "one")]);
        let b = make_container(vec![ver("p2", 1, 0, false, "two")]);
        let ab = merge_orset(&a, &b, &signers(), 10_000_000);
        let ba = merge_orset(&b, &a, &signers(), 10_000_000);
        assert_eq!(ab, ba, "commutative");
        assert_eq!(merge_orset(&ab, &b, &signers(), 10_000_000), ab, "idempotent");
        assert_eq!(bodies(&ab), vec!["one", "two"]);
    }

    #[test]
    fn absence_is_not_deletion() {
        // Local has a post; an inbound blank container must not remove it.
        let local = make_container(vec![ver("p1", 1, 0, false, "keep me")]);
        let blank = make_container(vec![]);
        let merged = merge_orset(&local, &blank, &signers(), 10_000_000);
        assert_eq!(bodies(&merged), vec!["keep me"]);
    }

    #[test]
    fn edit_supersedes_the_original() {
        let orig = ver("p1", 1, 0, false, "v1");
        let edit = ver("p1", 5, 1, false, "v2"); // observed v1 (supersedes>=1)
        let merged = merge_orset(
            &make_container(vec![orig]),
            &make_container(vec![edit]),
            &signers(),
            10_000_000,
        );
        assert_eq!(bodies(&merged), vec!["v2"], "edit wins, single live row");
    }

    #[test]
    fn tombstone_hides_the_post() {
        let orig = ver("p1", 1, 0, false, "v1");
        let tomb = ver("p1", 5, 1, true, "");
        let merged = merge_orset(
            &make_container(vec![orig]),
            &make_container(vec![tomb]),
            &signers(),
            10_000_000,
        );
        assert!(bodies(&merged).is_empty(), "tombstoned post is not live");
    }

    #[test]
    fn edit_after_delete_resurrects() {
        let orig = ver("p1", 1, 0, false, "v1");
        let tomb = ver("p1", 5, 1, true, "");
        let edit = ver("p1", 9, 5, false, "v3"); // observed the tombstone
        let mut c = make_container(vec![orig]);
        for r in [tomb, edit] {
            c = merge_orset(&c, &make_container(vec![r]), &signers(), 10_000_000);
        }
        assert_eq!(bodies(&c), vec!["v3"], "edit after delete resurrects");
    }

    #[test]
    fn concurrent_delete_and_edit_delete_wins_but_edit_retained() {
        // Both branch off the origin (supersedes=1), neither observed the other.
        let orig = ver("p1", 1, 0, false, "v1");
        let edit = ver("p1", 6, 1, false, "concurrent edit");
        let tomb = ver("p1", 5, 1, true, "");
        let merged = merge_orset(
            &make_container(vec![orig.clone(), edit.clone()]),
            &make_container(vec![tomb]),
            &signers(),
            10_000_000,
        );
        // Delete wins for display (no zombie) even though the edit has a higher clock.
        assert!(bodies(&merged).is_empty(), "delete wins the concurrent conflict");
        // ...but the edit's body is retained on disk (recoverable), not destroyed.
        let raw = records_of(&merged);
        assert!(
            raw.iter().any(|r| r["body"] == "concurrent edit"),
            "losing concurrent edit is retained on disk"
        );
    }

    #[test]
    fn merge_drops_forged_records() {
        // A record whose author is not an authorized signer is dropped.
        let mut forged = ver("p1", 1, 0, false, "forged");
        forged["author"] = json!("epix1attacker");
        let merged = merge_orset(
            &make_container(vec![]),
            &make_container(vec![forged]),
            &signers(),
            10_000_000,
        );
        assert!(bodies(&merged).is_empty(), "forged record never enters the set");
    }

    #[test]
    fn merge_order_independent_over_a_chain() {
        // Deliver origin, edit, tombstone, re-edit in several orders; all converge.
        let recs =
            [ver("p1", 1, 0, false, "v1"), ver("p1", 5, 1, false, "v2"), ver("p1", 9, 5, true, ""), ver("p1", 12, 9, false, "v4")];
        let orders: [[usize; 4]; 3] = [[0, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]];
        let mut outcomes = Vec::new();
        for order in orders {
            let mut c = make_container(vec![]);
            for i in order {
                c = merge_orset(&c, &make_container(vec![recs[i].clone()]), &signers(), 10_000_000);
            }
            outcomes.push(bodies(&c));
        }
        assert_eq!(outcomes[0], vec!["v4"]);
        assert!(outcomes.iter().all(|o| *o == outcomes[0]), "all delivery orders converge");
    }
}
