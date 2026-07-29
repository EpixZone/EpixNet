//! Sealed segments: a closed, content-addressed set of records.
//!
//! A segment is the closed set `{records : clock ≤ boundary}` for a
//! quantized boundary (interval-aligned or chain-block-anchored). Because
//! it is a pure function of content, ANY node produces byte-identical
//! segment bytes → the identical BLAKE3 root. That reproducibility is
//! what removes the "sealer" role: sealing is arithmetic anyone runs.
//!
//! Wire format (frozen): `"EDXSEG1" ‖ le64(boundary) ‖ le32(count) ‖
//! [le32(len) ‖ canonical_bytes]*`, records in [`crate::canonical_order`].
//! The root is BLAKE3 of these bytes, and it doubles as the segment's
//! content address (`docs/edx-feed.md`).

use epix_blob::ObjId;

use crate::{canonical_order, Record};

const MAGIC: &[u8; 7] = b"EDXSEG1";

/// A sealed segment: its boundary, ordered records, serialized bytes, and
/// content root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub boundary: u64,
    pub records: Vec<Record>,
    pub bytes: Vec<u8>,
    pub root: ObjId,
}

/// Seal every record with `clock <= boundary` into a segment. Records with
/// a later clock belong to a future segment (or the live tail) and are
/// excluded. Deterministic: same records + boundary → identical root.
pub fn seal(records: &[Record], boundary: u64) -> Segment {
    let mut selected: Vec<Record> =
        records.iter().filter(|r| r.clock <= boundary).cloned().collect();
    canonical_order(&mut selected);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&boundary.to_le_bytes());
    bytes.extend_from_slice(&(selected.len() as u32).to_le_bytes());
    for r in &selected {
        bytes.extend_from_slice(&(r.canonical.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&r.canonical);
    }
    let root = ObjId::of(&bytes);
    Segment { boundary, records: selected, bytes, root }
}

/// Byte offset + length of each record inside a sealed segment's bytes,
/// in segment order (what the index points at for a verified range fetch).
pub fn record_extents(seg: &Segment) -> Vec<(ObjId, u64, u32)> {
    let mut out = Vec::with_capacity(seg.records.len());
    let mut off = (MAGIC.len() + 8 + 4) as u64; // magic + boundary + count
    for r in &seg.records {
        off += 4; // the per-record length prefix
        out.push((r.addr(), off, r.canonical.len() as u32));
        off += r.canonical.len() as u64;
    }
    out
}

/// The monotone segment spine: prev-root-linked sealed segments. A shorter
/// or rolled-back spine is rejected because it does not extend the one you
/// hold.
#[derive(Clone, Debug, Default)]
pub struct Spine {
    /// Sealed segments in boundary order; each commits to its predecessor.
    pub links: Vec<SpineLink>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpineLink {
    pub boundary: u64,
    pub segment_root: ObjId,
    /// BLAKE3(prev_link_root ‖ segment_root ‖ le64(boundary)); the head of
    /// this value is the spine head a cold client checks against a signed
    /// commitment in content.json.
    pub link_root: ObjId,
}

impl Spine {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current spine head (zero if empty).
    pub fn head(&self) -> ObjId {
        self.links.last().map(|l| l.link_root).unwrap_or(ObjId([0; 32]))
    }

    /// Append a sealed segment, chaining it to the current head. Boundaries
    /// must strictly increase (a segment can only extend the spine).
    pub fn append(&mut self, seg: &Segment) -> Result<(), SpineError> {
        if let Some(last) = self.links.last() {
            if seg.boundary <= last.boundary {
                return Err(SpineError::NonMonotoneBoundary {
                    have: last.boundary,
                    got: seg.boundary,
                });
            }
        }
        let prev = self.head();
        let mut material = Vec::with_capacity(72);
        material.extend_from_slice(&prev.0);
        material.extend_from_slice(&seg.root.0);
        material.extend_from_slice(&seg.boundary.to_le_bytes());
        let link_root = ObjId::of(&material);
        self.links.push(SpineLink { boundary: seg.boundary, segment_root: seg.root, link_root });
        Ok(())
    }

    /// Whether `other` extends `self` (same prefix, then only appends) —
    /// the append-only prefix check: `self` continues `base` link for link.
    ///
    /// NOT THE ACCEPTANCE RULE for feeds. Feed anti-rollback is RECORD-SET
    /// MONOTONE (a checkpoint is valid iff its record set is a superset of
    /// ours and our tombstones stay present), because segments are a pure
    /// function of the records in a fixed clock interval: a legitimately
    /// late-arriving OLD record seals a new EARLIER interval, which changes
    /// the link prefix and makes this return false even though nothing was
    /// rolled back. Use this only where segments are genuinely appended in
    /// clock order; gate acceptance on the record set instead.
    pub fn is_extension_of(&self, base: &Spine) -> bool {
        if self.links.len() < base.links.len() {
            return false;
        }
        base.links.iter().zip(&self.links).all(|(a, b)| a == b)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SpineError {
    NonMonotoneBoundary { have: u64, got: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_record, Kind};

    fn sample() -> Vec<Record> {
        vec![
            test_record("a", "u1", "p", 10, Kind::Comment),
            test_record("b", "u2", "p", 20, Kind::Comment),
            test_record("c", "u1", "p", 30, Kind::Comment), // future
        ]
    }

    #[test]
    fn seal_is_deterministic_regardless_of_input_order() {
        let mut recs = sample();
        let s1 = seal(&recs, 25);
        recs.reverse();
        let s2 = seal(&recs, 25);
        assert_eq!(s1.root, s2.root, "same records + boundary -> same root");
        assert_eq!(s1.bytes, s2.bytes);
    }

    #[test]
    fn boundary_excludes_future_records() {
        let s = seal(&sample(), 25);
        assert_eq!(s.records.len(), 2, "clock=30 record is excluded");
        assert!(s.records.iter().all(|r| r.clock <= 25));
    }

    #[test]
    fn different_boundary_different_root() {
        assert_ne!(seal(&sample(), 25).root, seal(&sample(), 35).root);
    }

    #[test]
    fn extents_point_at_the_real_bytes() {
        let s = seal(&sample(), 100);
        for (addr, off, len) in record_extents(&s) {
            let slice = &s.bytes[off as usize..off as usize + len as usize];
            assert_eq!(ObjId::of(slice), addr, "extent locates the record's bytes");
        }
    }

    #[test]
    fn spine_is_monotone_and_detects_rollback() {
        let mut spine = Spine::new();
        spine.append(&seal(&sample(), 15)).unwrap();
        spine.append(&seal(&sample(), 25)).unwrap();
        // A non-increasing boundary is rejected.
        assert!(matches!(
            spine.append(&seal(&sample(), 20)),
            Err(SpineError::NonMonotoneBoundary { .. })
        ));

        // An extension of the same prefix is accepted...
        let mut longer = spine.clone();
        longer.append(&seal(&sample(), 40)).unwrap();
        assert!(longer.is_extension_of(&spine));

        // ...but a divergent spine (different early segment) is not.
        let mut divergent = Spine::new();
        divergent.append(&seal(&sample(), 16)).unwrap(); // different boundary
        assert!(!divergent.is_extension_of(&spine));
        assert!(!spine.is_extension_of(&divergent));
    }
}
