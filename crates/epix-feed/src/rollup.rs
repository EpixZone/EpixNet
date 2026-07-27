//! Gallery rollup: one deterministic blob of per-item counts.
//!
//! The reported symptom that motivated feeds: a gallery landing page
//! showing per-item counts pulled every user's social files. Instead one
//! rollup blob `{item → (comment_count, reaction_counts, newest_clock)}`
//! paints the whole gallery; per-item detail is fetched only on open.
//! Like every derived artifact it is recomputable from the records and
//! verified by re-derivation, not by trusting an authority.

use std::collections::BTreeMap;

use epix_blob::ObjId;

use crate::reactions::{count, ReactionCounts};
use crate::{Kind, Record};

/// Per-item gallery summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ItemSummary {
    pub comment_count: u64,
    pub reactions: ReactionCounts,
    pub newest_clock: u64,
}

/// item → summary, sorted for determinism.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rollup {
    map: BTreeMap<String, ItemSummary>,
}

impl Rollup {
    /// Compute the rollup for a set of item ids from the full record set.
    /// Only live (non-tombstoned) comments are counted.
    pub fn compute(items: &[String], records: &[Record]) -> Self {
        // Which (target) items are tombstoned by a moderator/self tombstone.
        let mut map = BTreeMap::new();
        for item in items {
            let tombstoned: std::collections::HashSet<&str> = records
                .iter()
                .filter(|r| matches!(r.kind, Kind::Tombstone) && r.target == *item)
                .map(|r| r.id.as_str())
                .collect();

            let mut comment_count = 0u64;
            let mut newest = 0u64;
            for r in records.iter().filter(|r| r.target == *item) {
                newest = newest.max(r.clock);
                if matches!(r.kind, Kind::Comment) && !tombstoned.contains(r.id.as_str()) {
                    comment_count += 1;
                }
            }
            map.insert(
                item.clone(),
                ItemSummary { comment_count, reactions: count(records, item), newest_clock: newest },
            );
        }
        Self { map }
    }

    pub fn get(&self, item: &str) -> Option<&ItemSummary> {
        self.map.get(item)
    }

    /// Content-address the rollup blob (verifiable by re-derivation).
    pub fn root(&self) -> ObjId {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EDXROLL1");
        bytes.extend_from_slice(&(self.map.len() as u32).to_le_bytes());
        for (item, s) in &self.map {
            bytes.extend_from_slice(&(item.len() as u32).to_le_bytes());
            bytes.extend_from_slice(item.as_bytes());
            bytes.extend_from_slice(&s.comment_count.to_le_bytes());
            bytes.extend_from_slice(&s.newest_clock.to_le_bytes());
            // Reaction kinds sorted for determinism.
            let mut kinds: Vec<(&String, &u64)> = s.reactions.by_kind.iter().collect();
            kinds.sort();
            bytes.extend_from_slice(&(kinds.len() as u32).to_le_bytes());
            for (k, v) in kinds {
                bytes.extend_from_slice(&(k.len() as u32).to_le_bytes());
                bytes.extend_from_slice(k.as_bytes());
                bytes.extend_from_slice(&v.to_le_bytes());
            }
        }
        ObjId::of(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_record;

    fn gallery() -> (Vec<String>, Vec<Record>) {
        let items = vec!["gif1".to_string(), "gif2".to_string()];
        let records = vec![
            test_record("c1", "u1", "gif1", 5, Kind::Comment),
            test_record("c2", "u2", "gif1", 8, Kind::Comment),
            test_record("l1", "u1", "gif1", 6, Kind::Reaction { kind: "like".into(), active: true }),
            test_record("c3", "u3", "gif2", 2, Kind::Comment),
        ];
        (items, records)
    }

    #[test]
    fn summarizes_each_item() {
        let (items, records) = gallery();
        let roll = Rollup::compute(&items, &records);
        let g1 = roll.get("gif1").unwrap();
        assert_eq!(g1.comment_count, 2);
        assert_eq!(g1.reactions.of("like"), 1);
        assert_eq!(g1.newest_clock, 8);
        assert_eq!(roll.get("gif2").unwrap().comment_count, 1);
    }

    #[test]
    fn tombstoned_comment_is_not_counted() {
        let (items, mut records) = gallery();
        // Moderate comment c1 on gif1.
        records.push(test_record("c1", "mod", "gif1", 20, Kind::Tombstone));
        let roll = Rollup::compute(&items, &records);
        assert_eq!(roll.get("gif1").unwrap().comment_count, 1, "tombstoned comment excluded");
    }

    #[test]
    fn rollup_root_is_deterministic() {
        let (items, records) = gallery();
        let a = Rollup::compute(&items, &records);
        let mut shuffled = records.clone();
        shuffled.reverse();
        let b = Rollup::compute(&items, &shuffled);
        assert_eq!(a.root(), b.root(), "rollup root is order-independent");
    }
}
