//! Chunk-group bitfield: which 16 KiB groups of an object are present.
//!
//! The successor to the bigfile `Piecefield`, generalized to every EDX
//! object. Internally a sorted set of group-index ranges (a 700 MB file
//! has ~44k groups — ranges stay tiny where a bool-per-group vector
//! would not), with the same alternating run-length wire idea as the
//! legacy piecefield: `runs[0]` counts leading present groups (0 when
//! the field starts absent), and runs alternate present/absent from
//! there. Runs are u64 so they postcard-encode as varints on the wire.

use std::ops::Range;

use bao_tree::{ChunkNum, ChunkRanges};

use crate::BLOCK_SIZE;

/// Bytes per chunk group (16 KiB).
pub const GROUP_BYTES: u64 = BLOCK_SIZE.bytes() as u64;

/// Native BLAKE3 chunks per group.
const CHUNKS_PER_GROUP: u64 = GROUP_BYTES / 1024;

/// Bytes per native BLAKE3 chunk (1 KiB).
const CHUNK_BYTES: u64 = GROUP_BYTES / CHUNKS_PER_GROUP;

/// Safety cap on total groups a peer-supplied bitfield may describe
/// (2^26 groups = 1 TiB object) so unpacking can't allocate unboundedly.
pub const MAX_GROUPS: u64 = 1 << 26;

/// Safety cap on the number of alternating runs a wire bitfield may
/// contain. The EDX frame cap already bounds this well below the limit
/// (a run costs at least one varint byte), but decoding cost must stay
/// bounded independently of whatever framing a caller used.
pub const MAX_WIRE_RUNS: usize = 1 << 17;

/// Which chunk groups of one object are present. Sorted, non-overlapping,
/// non-adjacent ranges of group indices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupBits {
    runs: Vec<Range<u64>>,
}

/// Number of chunk groups needed for an object of `size` bytes.
pub fn group_count(size: u64) -> u64 {
    size.div_ceil(GROUP_BYTES)
}

/// The group-index range covering the byte range (rounded outward).
pub fn groups_for_bytes(bytes: &Range<u64>) -> Range<u64> {
    if bytes.start >= bytes.end {
        return 0..0;
    }
    bytes.start / GROUP_BYTES..bytes.end.div_ceil(GROUP_BYTES)
}

/// The byte range group `g` covers in an object of `size` bytes.
pub fn bytes_of_group(g: u64, size: u64) -> Range<u64> {
    let start = g * GROUP_BYTES;
    start.min(size)..((g + 1) * GROUP_BYTES).min(size)
}

impl GroupBits {
    pub fn new() -> Self {
        Self::default()
    }

    /// A field with all groups of an object of `size` bytes present.
    pub fn complete(size: u64) -> Self {
        let n = group_count(size);
        let mut s = Self::new();
        if n > 0 {
            s.runs.push(0..n);
        }
        s
    }

    pub fn contains(&self, group: u64) -> bool {
        self.runs
            .binary_search_by(|r| {
                if r.end <= group {
                    std::cmp::Ordering::Less
                } else if r.start > group {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Whether every group in `groups` is present.
    pub fn contains_all(&self, groups: &Range<u64>) -> bool {
        if groups.start >= groups.end {
            return true;
        }
        // A sorted non-adjacent run set contains a range iff one run does.
        self.runs.iter().any(|r| r.start <= groups.start && groups.end <= r.end)
    }

    /// Mark a range of groups present.
    pub fn add(&mut self, groups: Range<u64>) {
        if groups.start >= groups.end {
            return;
        }
        // Appending at or past the tail is the common case (bulk decode,
        // sequential fetch); handle it in place instead of rebuilding.
        match self.runs.last().map(|r| r.end) {
            Some(tail_end) if groups.start == tail_end => {
                if let Some(last) = self.runs.last_mut() {
                    last.end = groups.end;
                }
                return;
            }
            Some(tail_end) if groups.start > tail_end => {
                self.runs.push(groups);
                return;
            }
            None => {
                self.runs.push(groups);
                return;
            }
            _ => {}
        }
        // Find all runs overlapping-or-adjacent and coalesce.
        let mut new = Vec::with_capacity(self.runs.len() + 1);
        let mut merged = groups;
        let mut placed = false;
        for r in self.runs.drain(..) {
            if r.end < merged.start || r.start > merged.end {
                // Disjoint and non-adjacent.
                if r.start > merged.end && !placed {
                    new.push(merged.clone());
                    placed = true;
                }
                new.push(r);
            } else {
                merged = merged.start.min(r.start)..merged.end.max(r.end);
            }
        }
        if !placed {
            new.push(merged);
        }
        self.runs = new;
    }

    /// Mark a range of groups absent (eviction, distrusted writes).
    pub fn remove(&mut self, groups: Range<u64>) {
        if groups.start >= groups.end {
            return;
        }
        let mut new = Vec::with_capacity(self.runs.len() + 1);
        for r in self.runs.drain(..) {
            if r.end <= groups.start || r.start >= groups.end {
                new.push(r);
                continue;
            }
            if r.start < groups.start {
                new.push(r.start..groups.start);
            }
            if r.end > groups.end {
                new.push(groups.end..r.end);
            }
        }
        self.runs = new;
    }

    /// Present groups, as sorted ranges.
    pub fn ranges(&self) -> &[Range<u64>] {
        &self.runs
    }

    /// Total present groups.
    pub fn count(&self) -> u64 {
        self.runs.iter().map(|r| r.end - r.start).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Whether an object of `size` bytes is fully present.
    pub fn is_complete(&self, size: u64) -> bool {
        let n = group_count(size);
        n == 0 || (self.runs.len() == 1 && self.runs[0] == (0..n))
    }

    /// Groups in `within` that are absent (what still needs fetching).
    pub fn gaps(&self, within: &Range<u64>) -> Vec<Range<u64>> {
        let mut out = Vec::new();
        let mut cursor = within.start;
        for r in &self.runs {
            if r.end <= cursor {
                continue;
            }
            if r.start >= within.end {
                break;
            }
            if r.start > cursor {
                out.push(cursor..r.start.min(within.end));
            }
            cursor = cursor.max(r.end);
            if cursor >= within.end {
                break;
            }
        }
        if cursor < within.end {
            out.push(cursor..within.end);
        }
        out
    }

    /// Groups present in `other` but not in `self` (the delta a peer
    /// needs after a `HaveRanges` push).
    pub fn added_in(&self, other: &Self) -> Self {
        let mut out = other.clone();
        for r in &self.runs {
            out.remove(r.clone());
        }
        out
    }

    /// Alternating run lengths (present first, 0 when starting absent) —
    /// the wire form, postcard-encoded as varints by the protocol layer.
    pub fn to_wire(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.runs.len() * 2);
        let mut cursor = 0;
        for r in &self.runs {
            out.push(r.start - cursor); // absent run (first may be 0)
            out.push(r.end - r.start); // present run
            cursor = r.end;
        }
        // Canonical form used here: pairs of (absent, present) runs. Flip
        // to the piecefield convention (present first) by prefixing: the
        // encoder emits present-first with a leading 0 absent-run elided.
        if out.first() == Some(&0) {
            out.remove(0);
        } else if !out.is_empty() {
            out.insert(0, 0);
        }
        out
    }

    /// Decode the wire form. Returns `None` on malformed input, if it
    /// would exceed [`MAX_GROUPS`], or if it has more than
    /// [`MAX_WIRE_RUNS`] runs.
    pub fn from_wire(runs: &[u64]) -> Option<Self> {
        if runs.len() > MAX_WIRE_RUNS {
            return None;
        }
        let mut s = Self::new();
        let mut cursor: u64 = 0;
        let mut present = true; // first run counts present groups
        for &run in runs {
            let end = cursor.checked_add(run)?;
            if end > MAX_GROUPS {
                return None;
            }
            if present && run > 0 {
                // Runs arrive sorted and the cursor only moves forward, so
                // append; a zero-length absent run leaves this run adjacent
                // to the previous one, which has to coalesce.
                if s.runs.last().map(|r| r.end) == Some(cursor) {
                    if let Some(last) = s.runs.last_mut() {
                        last.end = end;
                    }
                } else {
                    s.runs.push(cursor..end);
                }
            }
            cursor = end;
            present = !present;
        }
        Some(s)
    }

    /// The bao chunk ranges these groups cover (for verified fetch).
    pub fn to_chunk_ranges(&self) -> ChunkRanges {
        let mut out = ChunkRanges::empty();
        for r in &self.runs {
            out |= ChunkRanges::from(
                ChunkNum(r.start * CHUNKS_PER_GROUP)..ChunkNum(r.end * CHUNKS_PER_GROUP),
            );
        }
        out
    }

    /// Like [`Self::to_chunk_ranges`] but clamped to an object of `size`
    /// bytes. The last group of a non-16-KiB-multiple object covers fewer
    /// than `CHUNKS_PER_GROUP` real chunks, and bao's `valid_ranges` never
    /// yields a chunk past `ceil(size/1024)`. Callers that check a group's
    /// chunk range against `valid_ranges` (revalidate) must clamp, or the
    /// pristine tail group looks unverified and gets dropped.
    pub fn to_chunk_ranges_clamped(&self, size: u64) -> ChunkRanges {
        let chunks = size.div_ceil(CHUNK_BYTES);
        let mut out = ChunkRanges::empty();
        for r in &self.runs {
            let start = (r.start * CHUNKS_PER_GROUP).min(chunks);
            let end = (r.end * CHUNKS_PER_GROUP).min(chunks);
            if start < end {
                out |= ChunkRanges::from(ChunkNum(start)..ChunkNum(end));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(ranges: &[Range<u64>]) -> GroupBits {
        let mut b = GroupBits::new();
        for r in ranges {
            b.add(r.clone());
        }
        b
    }

    #[test]
    fn add_coalesces_and_sorts() {
        let mut b = GroupBits::new();
        b.add(5..7);
        b.add(0..2);
        b.add(7..9); // adjacent to 5..7 -> coalesce
        b.add(1..6); // bridges everything
        assert_eq!(b.ranges(), &[0..9]);
        assert_eq!(b.count(), 9);
    }

    #[test]
    fn remove_splits_runs() {
        let mut b = bits(&[0..10]);
        b.remove(3..5);
        assert_eq!(b.ranges(), &[0..3, 5..10]);
        b.remove(0..3);
        assert_eq!(b.ranges(), &[5..10]);
        b.remove(4..20);
        assert!(b.is_empty());
    }

    #[test]
    fn contains_and_gaps() {
        let b = bits(&[2..4, 8..10]);
        assert!(b.contains(2) && b.contains(3) && !b.contains(4) && !b.contains(0));
        assert!(b.contains_all(&(8..10)));
        assert!(!b.contains_all(&(3..9)));
        assert_eq!(b.gaps(&(0..12)), vec![0..2, 4..8, 10..12]);
        assert_eq!(b.gaps(&(2..4)), Vec::<Range<u64>>::new());
        assert_eq!(b.gaps(&(3..9)), vec![4..8]);
    }

    #[test]
    fn wire_round_trip() {
        for b in [
            GroupBits::new(),
            bits(&[0..5]),
            bits(&[3..5]),
            bits(&[0..1, 2..3, 10..20]),
            bits(&[7..8]),
            GroupBits::complete(1_000_000),
        ] {
            let wire = b.to_wire();
            assert_eq!(GroupBits::from_wire(&wire), Some(b.clone()), "wire {wire:?}");
        }
    }

    #[test]
    fn wire_matches_piecefield_convention() {
        // present groups 0,1 then gap 1 then present 1: [2, 1, 1]
        assert_eq!(bits(&[0..2, 3..4]).to_wire(), vec![2, 1, 1]);
        // starting absent: leading zero present-run: [0, 2, 2]
        assert_eq!(bits(&[2..4]).to_wire(), vec![0, 2, 2]);
    }

    #[test]
    fn from_wire_rejects_overflow_and_huge() {
        assert_eq!(GroupBits::from_wire(&[u64::MAX, 2]), None);
        assert_eq!(GroupBits::from_wire(&[MAX_GROUPS + 1]), None);
        assert!(GroupBits::from_wire(&[MAX_GROUPS]).is_some());
    }

    #[test]
    fn from_wire_handles_many_runs_and_caps_them() {
        // A peer can pack tens of thousands of one-group runs into a
        // single frame; decoding must stay linear.
        let wire = vec![1u64; 60_000];
        let b = GroupBits::from_wire(&wire).expect("in range");
        assert_eq!(b.ranges().len(), 30_000);
        assert_eq!(b.count(), 30_000);
        assert_eq!(b.ranges()[0], 0..1);
        assert_eq!(b.ranges()[29_999], 59_998..59_999);
        assert_eq!(GroupBits::from_wire(&vec![0u64; MAX_WIRE_RUNS + 1]), None);
    }

    #[test]
    fn from_wire_coalesces_zero_length_gaps() {
        // present 2, absent 0, present 3 -> one run 0..5
        assert_eq!(GroupBits::from_wire(&[2, 0, 3]), Some(bits(&[0..5])));
        assert_eq!(GroupBits::from_wire(&[0, 2, 2, 0, 1]), Some(bits(&[2..5])));
    }

    #[test]
    fn add_tail_fast_path_keeps_invariant() {
        let mut b = GroupBits::new();
        b.add(0..2);
        b.add(2..4); // adjacent to the tail -> extend in place
        assert_eq!(b.ranges(), &[0..4]);
        b.add(6..8); // past the tail -> append
        assert_eq!(b.ranges(), &[0..4, 6..8]);
        b.add(4..6); // bridges both -> slow path
        assert_eq!(b.ranges(), &[0..8]);
        b.add(3..5); // fully inside -> no change
        assert_eq!(b.ranges(), &[0..8]);
        b.add(0..0); // empty -> no change
        assert_eq!(b.ranges(), &[0..8]);
    }

    #[test]
    fn delta_added_in() {
        let old = bits(&[0..4]);
        let new = bits(&[0..6, 10..12]);
        assert_eq!(old.added_in(&new).ranges(), &[4..6, 10..12]);
    }

    #[test]
    fn byte_group_mapping() {
        assert_eq!(group_count(0), 0);
        assert_eq!(group_count(1), 1);
        assert_eq!(group_count(16384), 1);
        assert_eq!(group_count(16385), 2);
        assert_eq!(groups_for_bytes(&(0..1)), 0..1);
        assert_eq!(groups_for_bytes(&(16384..16385)), 1..2);
        assert_eq!(groups_for_bytes(&(16000..17000)), 0..2);
        assert_eq!(bytes_of_group(1, 20000), 16384..20000);
        assert_eq!(bytes_of_group(1, 100_000), 16384..32768);
    }

    #[test]
    fn is_complete_matches_size() {
        assert!(GroupBits::complete(0).is_complete(0));
        assert!(GroupBits::complete(16385).is_complete(16385));
        assert!(!bits(&[0..1]).is_complete(16385));
        assert!(bits(&[0..2]).is_complete(16385));
    }

    #[test]
    fn chunk_ranges_conversion() {
        let b = bits(&[1..2]);
        let cr = b.to_chunk_ranges();
        assert!(cr.contains(&ChunkNum(16)));
        assert!(cr.contains(&ChunkNum(31)));
        assert!(!cr.contains(&ChunkNum(15)));
        assert!(!cr.contains(&ChunkNum(32)));
    }
}
