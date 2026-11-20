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
//! only the winner is shown). Only the author who created a `post_id` can
//! publish its content: another authorized signer's version of that id is
//! retained but ignored unless it is a tombstone (see [`content_author`]).
//!
//! `watermark` compaction is deferred (see the plan §0): all versions are
//! retained, so a losing concurrent version simply stays on disk (recoverable).

use crate::record::{derive_post_id, derive_post_id_keyed, verify_record};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The container `record_format` marker (untrusted; unknown values still parse).
pub const RECORD_FORMAT: &str = "epix-orset-1";

/// The records array of a container (empty if absent/malformed).
pub fn records_of(container: &Value) -> Vec<Value> {
    container.get("post").and_then(|v| v.as_array()).cloned().unwrap_or_default()
}

/// The inner-path keys a content.json declares as merge files (`files_merged`),
/// relative to that content.json's directory. A merge file is verified
/// per-record and bypasses whole-file hash sync.
pub fn declared_merge_files(content: &Value) -> Vec<String> {
    content
        .get("files_merged")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
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
fn author_of(r: &Value) -> &str {
    r.get("author").and_then(|v| v.as_str()).unwrap_or("")
}

/// Whether `r`'s `post_id` is derived from its own `author` (the `key` form or
/// the `nonce` + `date_added` form `recordSign` mints at creation), which binds
/// the id to the author who created it: another author cannot produce a
/// version whose own fields derive the same id.
fn post_id_bound_to_author(r: &Value) -> bool {
    let (Some(pid), Some(author)) = (post_id_of(r), r.get("author").and_then(|v| v.as_str()))
    else {
        return false;
    };
    if let Some(key) = r.get("key").and_then(|v| v.as_str()) {
        if derive_post_id_keyed(author, key) == pid {
            return true;
        }
    }
    match (
        r.get("nonce").and_then(|v| v.as_str()),
        r.get("date_added").and_then(|v| v.as_i64()),
    ) {
        (Some(nonce), Some(date_added)) => derive_post_id(author, nonce, date_added) == pid,
        _ => false,
    }
}

/// The one author allowed to publish content (non-tombstone versions) for a
/// `post_id`: its creator. Computed from the SET of versions, never from their
/// order, so the fold stays a CRDT.
///
/// The creator is the author the id is derived from ([`post_id_bound_to_author`]).
/// A legacy migrated id is not derived from anything, and record clocks are
/// author-chosen (a lower clock proves nothing), so for such an id the creator
/// is known only when exactly one author has content versions. Any ambiguity
/// (two derivation-bound authors, or two content authors of a legacy id)
/// yields `None`: no content version is shown, so a conflict can hide a post
/// but never swap in another author's content.
fn content_author<'a>(versions: &[&'a Value]) -> Option<&'a str> {
    let bound: BTreeSet<&str> = versions
        .iter()
        .filter(|r| post_id_bound_to_author(r))
        .map(|r| author_of(r))
        .collect();
    let candidates: BTreeSet<&str> = if bound.is_empty() {
        versions.iter().filter(|r| !is_deleted(r)).map(|r| author_of(r)).collect()
    } else {
        bound
    };
    if candidates.len() == 1 {
        candidates.into_iter().next()
    } else {
        None
    }
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

/// Merge for the AUTHORING device's own `fileWrite`: union two containers by
/// signature with NO re-verification - the local client just produced these
/// records, and the point here is only to stop a blank/partial page-view write
/// from wiping the on-disk set. Inbound peer merges use [`merge_orset`], which
/// verifies every record.
pub fn merge_local(local: &Value, incoming: &Value) -> Value {
    let mut by_sign: BTreeMap<String, Value> = BTreeMap::new();
    for r in records_of(local).into_iter().chain(records_of(incoming)) {
        let sig = sign_of(&r).to_string();
        if !sig.is_empty() {
            by_sign.entry(sig).or_insert(r);
        }
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
/// Only tombstones (from any authorized signer, e.g. a moderator) and the
/// creator's own content versions ([`content_author`]) take part, so another
/// signer cannot replace an author's post by reusing its id. Among those:
/// delete-wins (a tombstone in the frontier beats a concurrent live edit, for
/// privacy - no zombie post), then highest clock, then lexicographically
/// greater signature. Returns `None` when no version takes part.
pub fn display_winner<'a>(versions: &[&'a Value]) -> Option<&'a Value> {
    let owner = content_author(versions);
    let accepted: Vec<&Value> = versions
        .iter()
        .copied()
        .filter(|r| is_deleted(r) || Some(author_of(r)) == owner)
        .collect();
    frontier(&accepted).into_iter().max_by(|a, b| {
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

    // A test signing key generated at runtime (not a hard-coded literal), shared
    // across this module's tests so every record has one consistent author.
    fn test_key() -> &'static (String, String) {
        static K: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        K.get_or_init(|| {
            let pk = epix_crypt::new_seed();
            let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
            (pk, addr)
        })
    }

    fn author() -> String {
        test_key().1.clone()
    }

    // A stable nonce for a logical post label ("p1", "p2", ...): reusing a label
    // must yield the same post_id lineage, so the mapping is stable within a run
    // - but the value is generated at runtime, not a hard-coded literal (CodeQL's
    // hard-coded-cryptographic-value rule flags literal nonces even in tests).
    fn post_nonce(label: &str) -> String {
        use std::collections::HashMap;
        use std::sync::{Mutex, OnceLock};
        static MAP: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
        MAP.get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap()
            .entry(label.to_string())
            .or_insert_with(epix_crypt::new_seed)
            .clone()
    }

    /// A signed version of a post. `label`/`date_added` fix the post_id lineage
    /// (a label maps to a stable per-run nonce); vary `clock`/`supersedes`/
    /// `deleted`/`body` for edits & tombstones.
    fn ver(label: &str, clock: i64, supersedes: i64, deleted: bool, body: &str) -> Value {
        let a = author();
        let nonce = post_nonce(label);
        let date_added = 1737331200_i64;
        let post_id = derive_post_id(&a, &nonce, date_added);
        let mut rec = json!({
            "post_id": post_id, "nonce": nonce, "author": a,
            "clock": clock, "supersedes": supersedes, "deleted": deleted,
            "body": body, "date_added": date_added,
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), &test_key().0).unwrap());
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

    // A second authorized signer of the directory (a moderator or the hub
    // owner), generated at runtime like the author key.
    fn mod_key() -> &'static (String, String) {
        static K: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        K.get_or_init(|| {
            let pk = epix_crypt::new_seed();
            let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
            (pk, addr)
        })
    }

    fn signers_with_mod() -> Vec<String> {
        vec![author(), mod_key().1.clone()]
    }

    /// A version of `orig`'s post (same post_id, nonce and date_added) signed
    /// by `key` with its own address as `author`, the way `recordSign` signs
    /// any record for whoever holds the key.
    fn foreign_ver(
        orig: &Value,
        key: &(String, String),
        clock: i64,
        supersedes: i64,
        deleted: bool,
        moderated: bool,
        body: &str,
    ) -> Value {
        let mut rec = json!({
            "post_id": orig["post_id"], "nonce": orig["nonce"], "author": key.1,
            "clock": clock, "supersedes": supersedes, "deleted": deleted,
            "body": body, "date_added": orig["date_added"],
        });
        if moderated {
            rec["moderated"] = json!(true);
        }
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), &key.0).unwrap());
        rec
    }

    /// An author-signed version with an explicit (legacy, non-derived) post_id,
    /// like the records a legacy data.json migration signs.
    fn legacy_ver(key: &(String, String), post_id: i64, clock: i64, supersedes: i64, body: &str) -> Value {
        let mut rec = json!({
            "post_id": post_id, "nonce": epix_crypt::new_seed(), "author": key.1,
            "clock": clock, "supersedes": supersedes, "deleted": false,
            "body": body, "date_added": 1737331200_i64,
        });
        rec["sign"] = json!(epix_crypt::sign(&record_signed_data(&rec), &key.0).unwrap());
        rec
    }

    fn merge_all(records: &[Value], signers: &[String]) -> Value {
        merge_orset(&make_container(vec![]), &make_container(records.to_vec()), signers, 10_000_000)
    }

    #[test]
    fn another_signer_cannot_replace_an_authors_post() {
        let orig = ver("victim", 1, 0, false, "original");
        // Valid record (authorized author, signature recovers to it) that
        // reuses the victim's post_id with a higher clock and a supersedes
        // that dominates the original.
        let replacement = foreign_ver(&orig, mod_key(), 5, 1, false, false, "replaced");
        let merged = merge_all(&[orig, replacement], &signers_with_mod());
        assert_eq!(records_of(&merged).len(), 2, "both versions verify and are retained");
        assert_eq!(bodies(&merged), vec!["original"], "the foreign version is not shown");
        // The `moderated` flag gives an edit no extra power either.
        let orig = ver("victim-m", 1, 0, false, "original");
        let flagged = foreign_ver(&orig, mod_key(), 5, 1, false, true, "replaced");
        let merged = merge_all(&[orig, flagged], &signers_with_mod());
        assert_eq!(bodies(&merged), vec!["original"]);
    }

    #[test]
    fn a_moderator_tombstone_still_hides_the_post() {
        let orig = ver("modded", 1, 0, false, "spam");
        let tomb = foreign_ver(&orig, mod_key(), 5, 1, true, true, "");
        let merged = merge_all(&[orig, tomb], &signers_with_mod());
        assert!(bodies(&merged).is_empty(), "moderation tombstone hides the post");
    }

    #[test]
    fn the_author_can_still_edit_their_own_post() {
        let orig = ver("own", 1, 0, false, "v1");
        let edit = ver("own", 5, 1, false, "v2");
        // A foreign replacement attempt in the same set does not block the edit.
        let replacement = foreign_ver(&orig, mod_key(), 3, 1, false, false, "replaced");
        let merged = merge_all(&[orig, edit, replacement], &signers_with_mod());
        assert_eq!(bodies(&merged), vec!["v2"]);
    }

    #[test]
    fn a_legacy_id_with_a_foreign_version_is_never_replaced() {
        // A legacy migrated id is not derived from the author, so the creator
        // cannot be proven; a lower clock must not let another signer claim it.
        let owner = test_key();
        let orig = legacy_ver(owner, 7, 1, 0, "original");
        let undercut = legacy_ver(mod_key(), 7, 0, 0, "replaced-low");
        let over = legacy_ver(mod_key(), 7, 9, 1, "replaced-high");
        let merged = merge_all(&[orig.clone(), undercut, over], &signers_with_mod());
        // The creator is ambiguous, so the post is hidden (fail closed), which
        // a moderation tombstone could do anyway; foreign content never shows.
        assert!(bodies(&merged).is_empty(), "no content is shown: {:?}", bodies(&merged));
        // Without a foreign version the legacy post and its edits show as before.
        let edit = legacy_ver(owner, 7, 5, 1, "edited");
        assert_eq!(bodies(&merge_all(&[orig, edit], &signers())), vec!["edited"]);
    }

    #[test]
    fn author_binding_is_order_independent() {
        let orig = ver("shuffle", 1, 0, false, "v1");
        let recs = vec![
            orig.clone(),
            ver("shuffle", 5, 1, false, "v2"),
            foreign_ver(&orig, mod_key(), 6, 5, false, false, "replaced"),
            foreign_ver(&orig, mod_key(), 2, 1, false, false, "replaced-early"),
            ver("other", 1, 0, false, "other"),
            foreign_ver(&ver("other", 1, 0, false, "other"), mod_key(), 4, 1, true, true, ""),
        ];
        let orders: [[usize; 6]; 5] = [
            [0, 1, 2, 3, 4, 5],
            [5, 4, 3, 2, 1, 0],
            [2, 0, 5, 1, 3, 4],
            [3, 2, 1, 4, 0, 5],
            [4, 5, 2, 3, 0, 1],
        ];
        let mut outcomes = Vec::new();
        for order in orders {
            // Raw container order (no merge sort) and incremental merges.
            let raw: Vec<Value> = order.iter().map(|&i| recs[i].clone()).collect();
            outcomes.push(live_records(&make_container(raw)));
            let mut c = make_container(vec![]);
            for i in order {
                c = merge_orset(&c, &make_container(vec![recs[i].clone()]), &signers_with_mod(), 10_000_000);
            }
            outcomes.push(live_records(&c));
        }
        assert_eq!(outcomes[0].len(), 1);
        assert_eq!(outcomes[0][0]["body"], "v2");
        assert!(outcomes.iter().all(|o| *o == outcomes[0]), "every order converges");
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
