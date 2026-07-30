//! Index by target: `target → record locations`, so "post X's comments"
//! fetches only X's records instead of every participant's whole file.
//!
//! The index is itself a deterministic derived blob (any node rebuilds
//! the identical bytes/root), mapping each target to a LIST of locations
//! (a list, not one entry, to catch edits/tombstones landing in later
//! segments). A location is `(segment_root, offset, len)` — enough for a
//! verified byte-range fetch of exactly that record.

use std::collections::BTreeMap;

use epix_blob::ObjId;

use crate::segment::{record_extents, Segment};

/// One record's location within a sealed segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Loc {
    pub segment_root: ObjId,
    pub offset: u64,
    pub len: u32,
}

/// target → sorted locations. `BTreeMap`/sorted vecs keep it deterministic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TargetIndex {
    map: BTreeMap<String, Vec<Loc>>,
}

impl TargetIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one sealed segment's records into the index.
    pub fn add_segment(&mut self, seg: &Segment) {
        let extents = record_extents(seg);
        let mut touched: Vec<String> = Vec::with_capacity(seg.records.len());
        for (r, (_addr, off, len)) in seg.records.iter().zip(extents) {
            // A comment/reaction indexes under its target; a top-level
            // post indexes under its own id so its detail page finds it.
            let key = if r.target.is_empty() { r.id.clone() } else { r.target.clone() };
            self.map.entry(key.clone()).or_default().push(Loc {
                segment_root: seg.root,
                offset: off,
                len,
            });
            touched.push(key);
        }
        // Keep each target's locations in a canonical order. Only the
        // targets this segment touched can be out of order; every other
        // one was left canonical by the call that last touched it, so
        // re-sorting the whole map would cost O(segments x targets).
        touched.sort();
        touched.dedup();
        for key in &touched {
            if let Some(locs) = self.map.get_mut(key) {
                locs.sort();
                locs.dedup();
            }
        }
    }

    /// Locations of every record attached to `target` (across segments).
    pub fn locations(&self, target: &str) -> &[Loc] {
        self.map.get(target).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Targets present, sorted (deterministic iteration).
    pub fn targets(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }

    /// Serialize to deterministic bytes, so the index blob itself can be
    /// content-addressed and served as an EDX object (verified by re-derivation).
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"EDXIDX1");
        bytes.extend_from_slice(&(self.map.len() as u32).to_le_bytes());
        for (target, locs) in &self.map {
            bytes.extend_from_slice(&(target.len() as u32).to_le_bytes());
            bytes.extend_from_slice(target.as_bytes());
            bytes.extend_from_slice(&(locs.len() as u32).to_le_bytes());
            for l in locs {
                bytes.extend_from_slice(&l.segment_root.0);
                bytes.extend_from_slice(&l.offset.to_le_bytes());
                bytes.extend_from_slice(&l.len.to_le_bytes());
            }
        }
        bytes
    }

    /// The index blob's content address (BLAKE3 of [`Self::serialize`]).
    pub fn root(&self) -> ObjId {
        ObjId::of(&self.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::seal;
    use crate::{test_record, Kind};

    fn records() -> Vec<crate::Record> {
        vec![
            test_record("p1", "u1", "", 1, Kind::Post), // post, target = its id
            test_record("c1", "u2", "p1", 2, Kind::Comment),
            test_record("c2", "u3", "p1", 3, Kind::Comment),
            test_record("c3", "u2", "p2", 4, Kind::Comment), // comment on another post
        ]
    }

    #[test]
    fn indexes_comments_under_their_target() {
        let seg = seal(&records(), 100);
        let mut idx = TargetIndex::new();
        idx.add_segment(&seg);
        // p1 has: the post itself + two comments = 3 locations.
        assert_eq!(idx.locations("p1").len(), 3);
        assert_eq!(idx.locations("p2").len(), 1);
        assert_eq!(idx.locations("nonexistent").len(), 0);
    }

    #[test]
    fn locations_point_at_verifiable_bytes() {
        let seg = seal(&records(), 100);
        let mut idx = TargetIndex::new();
        idx.add_segment(&seg);
        for loc in idx.locations("p1") {
            assert_eq!(loc.segment_root, seg.root);
            let slice = &seg.bytes[loc.offset as usize..loc.offset as usize + loc.len as usize];
            // The located bytes are a real record's canonical bytes.
            assert!(ObjId::of(slice).0 != [0u8; 32]);
        }
    }

    #[test]
    fn adding_a_second_segment_keeps_every_target_canonical() {
        // add_segment re-sorts only the targets it touched, so a target
        // carried over from an earlier segment must still come out sorted
        // and deduped, whatever order the segments arrive in.
        let early = seal(&records(), 3);
        let late = seal(&records(), 100);
        let mut a = TargetIndex::new();
        a.add_segment(&early);
        a.add_segment(&late);
        let mut b = TargetIndex::new();
        b.add_segment(&late);
        b.add_segment(&early);
        assert_eq!(a.root(), b.root(), "segment order must not change the index root");
        for target in ["p1", "p2"] {
            let locs = a.locations(target);
            let mut canonical = locs.to_vec();
            canonical.sort();
            canonical.dedup();
            assert_eq!(locs, canonical.as_slice(), "{target} locations must stay canonical");
        }
    }

    #[test]
    fn index_root_is_deterministic() {
        let seg = seal(&records(), 100);
        let mut a = TargetIndex::new();
        a.add_segment(&seg);
        let mut b = TargetIndex::new();
        b.add_segment(&seg);
        assert_eq!(a.root(), b.root(), "any node rebuilds the identical index root");
    }
}
