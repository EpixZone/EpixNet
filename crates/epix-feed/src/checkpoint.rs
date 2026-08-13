//! Checkpoints: the monotone feed state (the "pruned blockchain" pattern)
//! with NO attester.
//!
//! A checkpoint is EpixChain's state-vs-history split applied to a feed:
//! current live records (each still carrying its author signature — no
//! forgery post-prune), aggregate reaction counts, the sticky-tombstone
//! set, and the Merkle root of summarized history. It is DETERMINISTIC —
//! any node computes the identical checkpoint from the records, content-
//! addressed by its BLAKE3 root — so there is no attester to trust.
//!
//! Ordinary nodes keep checkpoint + recent hot segments and prune old raw
//! segments; counts still display correctly because the checkpoint
//! carries them ("balances"). Tombstones persist in the checkpoint so
//! moderated content cannot resurrect from a re-introduced ancient
//! segment. A checkpoint must extend its predecessor's history root
//! (no rollback).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use epix_blob::ObjId;

use crate::{canonical_order, Kind, Record};

/// A deterministic feed state checkpoint at a boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub boundary: u64,
    /// The live record set (winners after supersede/retract/tombstone),
    /// canonically ordered. Each keeps its signed bytes.
    pub live: Vec<Record>,
    /// target → reaction kind → count (the "balances").
    pub reaction_counts: BTreeMap<String, BTreeMap<String, u64>>,
    /// Sticky tombstones: the `(author, id)` items that are deleted and
    /// cannot resurrect.
    pub tombstones: BTreeSet<(String, String)>,
    /// Merkle root summarizing all history up to `boundary` (prev-linked).
    pub history_root: ObjId,
    /// This checkpoint's own content root.
    pub root: ObjId,
}

/// Which `(author, id)` items are tombstoned. A tombstone is sticky: once
/// present its target can never come back, even via a higher-clock
/// supersede.
///
/// Keyed on the tombstone's author as well as its target, the same keying
/// `Record::identity()` uses: verification authorizes a signer for a
/// DIRECTORY, not over another author's item, so any authorized user could
/// otherwise self-sign a tombstone carrying someone else's id and delete
/// it everywhere. A legitimate cross-author moderation tombstone still
/// matches its victim: `verify_record` requires such a record's `author`
/// field to be the ORIGINAL author (only the signature comes from the
/// moderator).
pub(crate) fn tombstoned_ids(records: &[Record]) -> BTreeSet<(String, String)> {
    records
        .iter()
        .filter(|r| matches!(r.kind, Kind::Tombstone))
        .map(|r| (r.author.clone(), r.target.clone()))
        .collect()
}

/// The live winner of each non-reaction identity: highest order_key wins,
/// excluding anything tombstoned. Keyed on `identity()` so two distinct
/// posts/comments by the same author survive and only a real edit (same
/// id) supersedes. Reactions are represented by their counts, not
/// individual live records.
pub(crate) fn live_records(
    records: &[Record],
    tombstones: &BTreeSet<(String, String)>,
) -> Vec<Record> {
    let mut winners: BTreeMap<String, Record> = BTreeMap::new();
    for r in records {
        if matches!(r.kind, Kind::Reaction { .. } | Kind::Tombstone) {
            continue;
        }
        // A tombstoned item (by its author AND id) is dropped entirely.
        if tombstones.contains(&(r.author.clone(), r.id.clone())) {
            continue;
        }
        winners
            .entry(r.identity())
            .and_modify(|cur| {
                if r.order_key() > cur.order_key() {
                    *cur = r.clone();
                }
            })
            .or_insert_with(|| r.clone());
    }
    let mut live: Vec<Record> = winners.into_values().collect();
    canonical_order(&mut live);
    live
}

impl Checkpoint {
    /// Compute the checkpoint for every record with `clock <= boundary`,
    /// chained to `prev` (pass `ObjId([0;32])` for the genesis history
    /// root). Deterministic: same records + boundary + prev → same root.
    pub fn compute(records: &[Record], boundary: u64, prev_history: ObjId) -> Self {
        // Borrow when every record is already in scope (the common case:
        // the feed boundary is the max record clock), so a recompute does
        // not deep clone the whole corpus and its canonical bytes.
        let in_scope: Cow<'_, [Record]> = if records.iter().all(|r| r.clock <= boundary) {
            Cow::Borrowed(records)
        } else {
            Cow::Owned(records.iter().filter(|r| r.clock <= boundary).cloned().collect())
        };

        let tombstones = tombstoned_ids(&in_scope);
        let live = live_records(&in_scope, &tombstones);

        // Reaction counts, folded in ONE pass: keep the highest-order_key
        // record of each (author, target, kind) lineage, then tally the
        // active winners per target. This is the same fold `reactions::count`
        // does, so the counts and every root over them are unchanged;
        // calling it once per target rescanned all records per target.
        let mut winners: BTreeMap<String, &Record> = BTreeMap::new();
        for r in in_scope.iter() {
            if !matches!(r.kind, Kind::Reaction { .. }) {
                continue;
            }
            winners
                .entry(r.lineage())
                .and_modify(|cur| {
                    if r.order_key() > cur.order_key() {
                        *cur = r;
                    }
                })
                .or_insert(r);
        }
        let mut reaction_counts: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for r in winners.values() {
            if let Kind::Reaction { kind, active } = &r.kind {
                if *active {
                    *reaction_counts
                        .entry(r.target.clone())
                        .or_default()
                        .entry(kind.clone())
                        .or_insert(0) += 1;
                }
            }
        }

        // History root: prev-linked hash over the summarized state, so a
        // checkpoint that does not extend its predecessor is detectable.
        let history_root = Self::compute_history_root(
            prev_history,
            boundary,
            &live,
            &reaction_counts,
            &tombstones,
        );
        let root = Self::compute_root(boundary, &history_root, &live, &reaction_counts, &tombstones);

        Self { boundary, live, reaction_counts, tombstones, history_root, root }
    }

    fn compute_history_root(
        prev: ObjId,
        boundary: u64,
        live: &[Record],
        reactions: &BTreeMap<String, BTreeMap<String, u64>>,
        tombstones: &BTreeSet<(String, String)>,
    ) -> ObjId {
        let mut m = Vec::new();
        m.extend_from_slice(b"EDXHIST1");
        m.extend_from_slice(&prev.0);
        m.extend_from_slice(&boundary.to_le_bytes());
        m.extend_from_slice(&Self::state_digest(live, reactions, tombstones).0);
        ObjId::of(&m)
    }

    fn compute_root(
        boundary: u64,
        history_root: &ObjId,
        live: &[Record],
        reactions: &BTreeMap<String, BTreeMap<String, u64>>,
        tombstones: &BTreeSet<(String, String)>,
    ) -> ObjId {
        let mut m = Vec::new();
        m.extend_from_slice(b"EDXCKPT1");
        m.extend_from_slice(&boundary.to_le_bytes());
        m.extend_from_slice(&history_root.0);
        m.extend_from_slice(&Self::state_digest(live, reactions, tombstones).0);
        ObjId::of(&m)
    }

    /// Deterministic digest of the state triple (live set, reaction
    /// counts, tombstones).
    fn state_digest(
        live: &[Record],
        reactions: &BTreeMap<String, BTreeMap<String, u64>>,
        tombstones: &BTreeSet<(String, String)>,
    ) -> ObjId {
        let mut m = Vec::new();
        m.extend_from_slice(&(live.len() as u32).to_le_bytes());
        for r in live {
            m.extend_from_slice(&r.addr().0);
        }
        m.extend_from_slice(&(reactions.len() as u32).to_le_bytes());
        for (target, kinds) in reactions {
            m.extend_from_slice(&(target.len() as u32).to_le_bytes());
            m.extend_from_slice(target.as_bytes());
            m.extend_from_slice(&(kinds.len() as u32).to_le_bytes());
            for (k, v) in kinds {
                m.extend_from_slice(&(k.len() as u32).to_le_bytes());
                m.extend_from_slice(k.as_bytes());
                m.extend_from_slice(&v.to_le_bytes());
            }
        }
        // Both halves length-prefixed, so two distinct (author, target)
        // pairs cannot concatenate to the same bytes.
        m.extend_from_slice(&(tombstones.len() as u32).to_le_bytes());
        for (author, target) in tombstones {
            m.extend_from_slice(&(author.len() as u32).to_le_bytes());
            m.extend_from_slice(author.as_bytes());
            m.extend_from_slice(&(target.len() as u32).to_le_bytes());
            m.extend_from_slice(target.as_bytes());
        }
        ObjId::of(&m)
    }

    /// Whether `self` validly extends `prev`: the boundary advanced and
    /// `self.history_root` was computed FROM `prev.history_root`.
    ///
    /// NOT THE ACCEPTANCE RULE for feeds - it requires the boundary to
    /// ADVANCE, and the feed boundary is the max record clock, so a
    /// legitimately late-arriving OLD record leaves the boundary unchanged
    /// and this returns false even though the record set only grew. Feed
    /// anti-rollback is RECORD-SET MONOTONE: accept iff the record set is a
    /// superset of ours and every tombstone we hold is still present.
    /// Use this only for a strictly forward-advancing checkpoint chain.
    pub fn extends(&self, prev: &Checkpoint) -> bool {
        if self.boundary <= prev.boundary {
            return false;
        }
        // Recompute what our history root must be given prev's; if a peer
        // hands us a checkpoint whose history_root doesn't derive from
        // prev's, it is rejected.
        let expected = Self::compute_history_root(
            prev.history_root,
            self.boundary,
            &self.live,
            &self.reaction_counts,
            &self.tombstones,
        );
        expected == self.history_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_record;

    fn records() -> Vec<Record> {
        vec![
            test_record("p1", "u1", "", 1, Kind::Post),
            test_record("c1", "u2", "p1", 2, Kind::Comment),
            test_record("c1", "u2", "p1", 5, Kind::Comment), // edit (same lineage)
            test_record("l1", "u3", "p1", 3, Kind::Reaction { kind: "like".into(), active: true }),
            test_record("l1", "u3", "p1", 9, Kind::Reaction { kind: "like".into(), active: false }),
            test_record("l2", "u4", "p1", 4, Kind::Reaction { kind: "like".into(), active: true }),
        ]
    }

    #[test]
    fn checkpoint_is_deterministic_no_sealer() {
        // The keystone: two independent nodes with the same records
        // produce byte-identical checkpoint roots — no attester needed.
        let recs = records();
        let mut shuffled = recs.clone();
        shuffled.reverse();
        let a = Checkpoint::compute(&recs, 100, ObjId([0; 32]));
        let b = Checkpoint::compute(&shuffled, 100, ObjId([0; 32]));
        assert_eq!(a.root, b.root, "same records -> identical checkpoint root");
        assert_eq!(a.history_root, b.history_root);
        assert_eq!(a.live, b.live);
    }

    #[test]
    fn counts_survive_in_the_checkpoint_after_prune() {
        // The "balances display correctly after pruning" property: the
        // checkpoint carries the reaction count so raw records can be
        // dropped. One like remains active (l2); l1 was un-liked.
        let ck = Checkpoint::compute(&records(), 100, ObjId([0; 32]));
        assert_eq!(ck.reaction_counts.get("p1").unwrap().get("like"), Some(&1));
    }

    #[test]
    fn reaction_counts_match_the_per_target_fold() {
        // The one-pass fold must agree with `reactions::count` target by
        // target, or the checkpoint roots would shift.
        let mut recs = records();
        recs.push(test_record("l3", "u5", "p2", 6, Kind::Reaction { kind: "love".into(), active: true }));
        recs.push(test_record("l3", "u5", "p2", 7, Kind::Reaction { kind: "love".into(), active: false }));
        recs.push(test_record("l4", "u6", "p2", 8, Kind::Reaction { kind: "like".into(), active: true }));
        let ck = Checkpoint::compute(&recs, 100, ObjId([0; 32]));
        for t in ["p1", "p2"] {
            let expected: BTreeMap<String, u64> = crate::reactions::count(&recs, t)
                .by_kind
                .into_iter()
                .filter(|(_, v)| *v > 0)
                .collect();
            let got = ck.reaction_counts.get(t).cloned().unwrap_or_default();
            assert_eq!(got, expected, "target {t}");
        }
        // p2 keeps only the like: the love was retracted, so no zero entry.
        let p2 = ck.reaction_counts.get("p2").unwrap();
        assert_eq!(p2.get("like"), Some(&1));
        assert!(p2.get("love").is_none());
    }

    #[test]
    fn edit_supersedes_in_live_set() {
        let ck = Checkpoint::compute(&records(), 100, ObjId([0; 32]));
        // c1 appears once (the higher-clock edit won), plus the post = 2 live.
        assert_eq!(ck.live.len(), 2);
        let comment = ck.live.iter().find(|r| r.id == "c1").unwrap();
        assert_eq!(comment.clock, 5, "the edit (clock 5) is the live winner");
    }

    #[test]
    fn tombstone_is_sticky_and_removes_the_item() {
        let mut recs = records();
        // A tombstone as the adapter emits one: target = its own id, author
        // = the item's author. A moderation tombstone has this same shape,
        // since verify_record makes a moderator sign a record whose `author`
        // is still the original author.
        recs.push(test_record("c1", "u2", "c1", 20, Kind::Tombstone));
        // ...and the author tries to resurrect it with a higher clock.
        recs.push(test_record("c1", "u2", "p1", 30, Kind::Comment));
        let ck = Checkpoint::compute(&recs, 100, ObjId([0; 32]));
        assert!(ck.tombstones.contains(&("u2".to_string(), "c1".to_string())));
        assert!(!ck.live.iter().any(|r| r.id == "c1"), "tombstoned item cannot resurrect");
    }

    #[test]
    fn a_tombstone_cannot_delete_another_authors_item() {
        // Any authorized xite user can self-sign a record in her OWN
        // directory carrying someone else's id, so a tombstone must only
        // remove its own author's item.
        let mut recs = records();
        recs.push(test_record("p1", "mallory", "p1", 40, Kind::Tombstone));
        let ck = Checkpoint::compute(&recs, 100, ObjId([0; 32]));
        assert!(
            ck.live.iter().any(|r| r.id == "p1" && r.author == "u1"),
            "u1's post must survive another author's tombstone",
        );
        // Mallory's tombstone is still recorded, scoped to her own items.
        assert!(ck.tombstones.contains(&("mallory".to_string(), "p1".to_string())));
        assert!(!ck.tombstones.contains(&("u1".to_string(), "p1".to_string())));
    }

    #[test]
    fn distinct_items_by_one_author_all_survive() {
        // Identity keys on (author, id), not (author, target, kind), so two
        // distinct posts by one author and two distinct comments by one
        // author on the same post all survive instead of collapsing to one.
        let recs = vec![
            test_record("p1", "u1", "", 1, Kind::Post),
            test_record("p2", "u1", "", 2, Kind::Post), // same author, distinct post
            test_record("a", "u2", "p1", 3, Kind::Comment),
            test_record("b", "u2", "p1", 4, Kind::Comment), // same author, distinct comment
        ];
        let ck = Checkpoint::compute(&recs, 100, ObjId([0; 32]));
        for id in ["p1", "p2", "a", "b"] {
            assert!(ck.live.iter().any(|r| r.id == id), "{id} missing from live set");
        }
        assert_eq!(ck.live.len(), 4);
    }

    #[test]
    fn state_digest_inner_kinds_map_is_length_prefixed() {
        // Two DIFFERENT reaction states that concatenate to identical bytes
        // if the inner kinds map is not length-prefixed. The digest must
        // tell them apart, else two distinct states share a checkpoint root.
        let a: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::from([
            ("T".to_string(), BTreeMap::from([("a".to_string(), 0u64)])),
            ("b".to_string(), BTreeMap::from([("c".to_string(), 7205759403809570816u64)])),
        ]);
        let b: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::from([
            (
                "T".to_string(),
                BTreeMap::from([("a".to_string(), 0u64), ("b".to_string(), 425201762305u64)]),
            ),
            ("d".to_string(), BTreeMap::new()),
        ]);
        assert_ne!(a, b);
        let tomb = BTreeSet::new();
        let da = Checkpoint::state_digest(&[], &a, &tomb);
        let db = Checkpoint::state_digest(&[], &b, &tomb);
        assert_ne!(da, db, "distinct states must not share a state digest");
    }

    #[test]
    fn checkpoint_chain_detects_rollback() {
        let recs = records();
        let c1 = Checkpoint::compute(&recs, 5, ObjId([0; 32]));
        let mut recs2 = recs.clone();
        recs2.push(test_record("c9", "u5", "p1", 8, Kind::Comment));
        let c2 = Checkpoint::compute(&recs2, 10, c1.history_root);
        assert!(c2.extends(&c1), "a properly chained checkpoint extends its predecessor");

        // A checkpoint built from the WRONG prev history is rejected.
        let forged = Checkpoint::compute(&recs2, 10, ObjId([9; 32]));
        assert!(!forged.extends(&c1), "a checkpoint not chained to prev is a rollback");

        // A non-increasing boundary is not an extension.
        let same = Checkpoint::compute(&recs, 5, c1.history_root);
        assert!(!same.extends(&c1));
    }
}
