//! OR-set reaction counts: exact, retractable, no HyperLogLog.
//!
//! Reactions fold into one CRDT lineage per (author, target, kind), so a
//! re-like SUPERSEDES the prior like (no self-inflation) and an un-like
//! RETRACTS it. The exact count is the number of lineages whose latest
//! record is `active`. HyperLogLog was rejected in design: it cannot
//! subtract an un-like, so counts would inflate forever.

use std::collections::HashMap;

use crate::{Kind, Record};

/// Per-target reaction tallies: kind → count.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReactionCounts {
    pub by_kind: HashMap<String, u64>,
}

impl ReactionCounts {
    pub fn total(&self) -> u64 {
        self.by_kind.values().sum()
    }
    pub fn of(&self, kind: &str) -> u64 {
        self.by_kind.get(kind).copied().unwrap_or(0)
    }
}

/// The winning record of each reaction lineage on `target`: for each
/// (author, kind) keep the highest-clock reaction (ties broken by the
/// canonical order, so it's deterministic).
fn fold_lineages<'a>(records: &'a [Record], target: &str) -> HashMap<String, &'a Record> {
    let mut winners: HashMap<String, &Record> = HashMap::new();
    for r in records {
        if r.target != target {
            continue;
        }
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
    winners
}

/// Exact reaction counts for one target, folded from signed records.
pub fn count(records: &[Record], target: &str) -> ReactionCounts {
    let mut counts = ReactionCounts::default();
    for r in fold_lineages(records, target).values() {
        if let Kind::Reaction { kind, active } = &r.kind {
            if *active {
                *counts.by_kind.entry(kind.clone()).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Whether `author` currently reacts with `kind` to `target` (local "did
/// I like this" — you authored your own reactions, so it's a local read).
pub fn is_active(records: &[Record], author: &str, target: &str, kind: &str) -> bool {
    let lineage = format!("{author}\u{1f}{target}\u{1f}{kind}");
    fold_lineages(records, target)
        .get(&lineage)
        .map(|r| matches!(&r.kind, Kind::Reaction { active: true, .. }))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_record;

    fn like(id: &str, author: &str, target: &str, clock: u64, active: bool) -> Record {
        test_record(id, author, target, clock, Kind::Reaction { kind: "like".into(), active })
    }

    #[test]
    fn relike_supersedes_never_double_counts() {
        let records = vec![
            like("a", "u1", "p", 1, true),
            like("b", "u1", "p", 2, true), // same lineage, re-like
            like("c", "u2", "p", 1, true),
        ];
        // Two distinct authors -> count 2, not 3.
        assert_eq!(count(&records, "p").of("like"), 2);
    }

    #[test]
    fn unlike_retracts() {
        let records = vec![
            like("a", "u1", "p", 1, true),
            like("b", "u1", "p", 5, false), // un-like wins (higher clock)
            like("c", "u2", "p", 1, true),
        ];
        assert_eq!(count(&records, "p").of("like"), 1);
        assert!(!is_active(&records, "u1", "p", "like"));
        assert!(is_active(&records, "u2", "p", "like"));
    }

    #[test]
    fn relike_after_unlike_counts_again() {
        let records = vec![
            like("a", "u1", "p", 1, true),
            like("b", "u1", "p", 2, false),
            like("c", "u1", "p", 3, true), // re-like after un-like
        ];
        assert_eq!(count(&records, "p").of("like"), 1);
        assert!(is_active(&records, "u1", "p", "like"));
    }

    #[test]
    fn count_is_order_independent() {
        let mut records = vec![
            like("a", "u1", "p", 1, true),
            like("b", "u1", "p", 5, false),
            like("c", "u2", "p", 3, true),
            like("d", "u3", "p", 2, true),
        ];
        let c1 = count(&records, "p").of("like");
        records.reverse();
        let c2 = count(&records, "p").of("like");
        assert_eq!(c1, c2, "fold is deterministic regardless of input order");
        assert_eq!(c1, 2);
    }

    #[test]
    fn multiple_kinds_tallied_separately() {
        let records = vec![
            test_record("a", "u1", "p", 1, Kind::Reaction { kind: "like".into(), active: true }),
            test_record("b", "u1", "p", 1, Kind::Reaction { kind: "love".into(), active: true }),
            test_record("c", "u2", "p", 1, Kind::Reaction { kind: "love".into(), active: true }),
        ];
        let counts = count(&records, "p");
        assert_eq!(counts.of("like"), 1);
        assert_eq!(counts.of("love"), 2);
        assert_eq!(counts.total(), 3);
    }
}
