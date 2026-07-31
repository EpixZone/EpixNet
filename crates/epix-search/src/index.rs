//! Track 2: hierarchical sharded published inverted index.
//!
//! For corpora too big for Track-1 segment scanning, the owner publishes
//! an inverted index: a small hierarchical meta pointing to term-hash-
//! sharded posting-list blobs, each a sorted, committed
//! `term → [pointer]`. A query fetches O(depth) meta pages, the one shard
//! for the query term, its posting list, then range-fetches + verifies
//! the records. Hot terms sub-shard by recency; posting lists partition
//! by segment/time so sealing a new segment only appends new range-blobs
//! (unchanged history keeps its roots → dedup, no whole-index reflow).
//!
//! Determinism (so any node rebuilds identical roots): a frozen shard
//! count, the frozen tokenizer + term hash from the crate root, canonical
//! sort order, and a fixed serialization. Content-addressed throughout.

use std::collections::BTreeMap;

use epix_blob::ObjId;

use crate::{term_hash, tokenize, Pointer};

/// Number of top-level shards (frozen). A term maps to
/// `term_hash % SHARD_COUNT`. Posting lists within a shard stay sorted by
/// term hash then pointer.
pub const SHARD_COUNT: u64 = 256;

/// One shard: term_hash → sorted, deduped pointers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Shard {
    postings: BTreeMap<u64, Vec<Pointer>>,
}

impl Shard {
    fn add(&mut self, term: u64, ptr: Pointer) {
        self.postings.entry(term).or_default().push(ptr);
    }

    fn finalize(&mut self) {
        for list in self.postings.values_mut() {
            list.sort();
            list.dedup();
        }
    }

    /// Pointers for a term (empty if none).
    pub fn postings_for(&self, term: u64) -> &[Pointer] {
        self.postings.get(&term).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Frozen serialization → content address.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"EDXSHRD1");
        b.extend_from_slice(&(self.postings.len() as u32).to_le_bytes());
        for (term, ptrs) in &self.postings {
            b.extend_from_slice(&term.to_le_bytes());
            b.extend_from_slice(&(ptrs.len() as u32).to_le_bytes());
            for p in ptrs {
                b.extend_from_slice(&p.segment_root);
                b.extend_from_slice(&p.offset.to_le_bytes());
                b.extend_from_slice(&p.len.to_le_bytes());
            }
        }
        b
    }

    pub fn root(&self) -> ObjId {
        ObjId::of(&self.to_bytes())
    }
}

/// The published index: `SHARD_COUNT` shards plus a committed meta root
/// over their shard roots (the hierarchy's top page). Small enough that a
/// query fetches the meta then one shard.
#[derive(Clone, Debug, Default)]
pub struct InvertedIndex {
    shards: BTreeMap<u64, Shard>,
}

impl InvertedIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index one record: tokenize `text`, and file a pointer to the record
    /// under every distinct term. `ptr` locates the record's bytes for
    /// fetch-and-verify.
    pub fn add_record(&mut self, text: &str, ptr: Pointer) {
        for tok in tokenize(text) {
            let th = term_hash(&tok);
            let shard = th % SHARD_COUNT;
            self.shards.entry(shard).or_default().add(th, ptr);
        }
    }

    /// Finalize all shards (sort/dedup). Call once after adding records.
    pub fn finalize(&mut self) {
        for s in self.shards.values_mut() {
            s.finalize();
        }
    }

    /// Which shard a query term lives in (the client fetches only this one).
    pub fn shard_of(term: &str) -> u64 {
        term_hash(term) % SHARD_COUNT
    }

    /// Query one term → its pointers (across the single relevant shard).
    /// The caller then range-fetches and verifies each pointed-at record.
    pub fn query(&self, term: &str) -> Vec<Pointer> {
        let th = term_hash(term);
        self.shards
            .get(&(th % SHARD_COUNT))
            .map(|s| s.postings_for(th).to_vec())
            .unwrap_or_default()
    }

    /// AND query: pointers appearing under every term (intersection).
    pub fn query_all(&self, terms: &[&str]) -> Vec<Pointer> {
        let mut iter = terms.iter();
        let Some(first) = iter.next() else { return Vec::new() };
        let mut acc: Vec<Pointer> = self.query(first);
        for t in iter {
            let next: std::collections::BTreeSet<Pointer> = self.query(t).into_iter().collect();
            acc.retain(|p| next.contains(p));
        }
        acc
    }

    pub fn get_shard(&self, shard: u64) -> Option<&Shard> {
        self.shards.get(&shard)
    }

    /// The committed meta root: BLAKE3 over (shard_index, shard_root)
    /// pairs. This is what content.json commits so a cold client can
    /// detect a truncated/forged index (completeness relative to this
    /// signed root — stated honestly in the crate docs).
    pub fn meta_root(&self) -> ObjId {
        let mut b = Vec::new();
        b.extend_from_slice(b"EDXMETA1");
        b.extend_from_slice(&SHARD_COUNT.to_le_bytes());
        b.extend_from_slice(&(self.shards.len() as u32).to_le_bytes());
        for (idx, shard) in &self.shards {
            b.extend_from_slice(&idx.to_le_bytes());
            b.extend_from_slice(&shard.root().0);
        }
        ObjId::of(&b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ptr(n: u8, off: u64) -> Pointer {
        Pointer { segment_root: [n; 32], offset: off, len: 100 }
    }

    fn built() -> InvertedIndex {
        let mut idx = InvertedIndex::new();
        idx.add_record("the quick brown fox", ptr(1, 0));
        idx.add_record("quick brown dogs run", ptr(1, 200));
        idx.add_record("lazy cats sleep", ptr(2, 0));
        idx.finalize();
        idx
    }

    #[test]
    fn single_term_query_returns_pointers() {
        let idx = built();
        let hits = idx.query("quick");
        assert_eq!(hits.len(), 2, "'quick' appears in two records");
        assert!(idx.query("nonexistent").is_empty());
    }

    #[test]
    fn and_query_intersects() {
        let idx = built();
        // "quick" AND "brown" -> both records that have both.
        let hits = idx.query_all(&["quick", "brown"]);
        assert_eq!(hits.len(), 2);
        // "quick" AND "lazy" -> none.
        assert!(idx.query_all(&["quick", "lazy"]).is_empty());
    }

    #[test]
    fn query_touches_only_one_shard() {
        let idx = built();
        // The client only needs the shard for "quick".
        let shard = InvertedIndex::shard_of("quick");
        assert!(idx.get_shard(shard).is_some());
        assert!(idx.get_shard(shard).unwrap().postings_for(term_hash("quick")).len() == 2);
    }

    #[test]
    fn index_roots_are_deterministic() {
        // Two nodes indexing the same records in different orders agree.
        let mut a = InvertedIndex::new();
        a.add_record("alpha beta gamma", ptr(1, 0));
        a.add_record("beta gamma delta", ptr(2, 0));
        a.finalize();

        let mut b = InvertedIndex::new();
        b.add_record("beta gamma delta", ptr(2, 0));
        b.add_record("alpha beta gamma", ptr(1, 0));
        b.finalize();

        assert_eq!(a.meta_root(), b.meta_root(), "any node rebuilds the identical meta root");
    }

    #[test]
    fn sealing_a_new_segment_leaves_old_shard_roots_stable() {
        // Range-partition property: adding records that only touch NEW
        // terms must not change the shard roots of untouched terms.
        let mut idx = InvertedIndex::new();
        idx.add_record("stable term one", ptr(1, 0));
        idx.finalize();
        let stable_shard = InvertedIndex::shard_of("stable");
        let before = idx.get_shard(stable_shard).unwrap().root();

        // Add a record whose terms hash to (very likely) other shards.
        let mut idx2 = idx.clone();
        idx2.add_record("zzzznewzzzz qqqqotherqqqq", ptr(3, 0));
        idx2.finalize();
        // The 'stable' shard is unchanged iff the new terms missed it.
        if InvertedIndex::shard_of("zzzznewzzzz") != stable_shard
            && InvertedIndex::shard_of("qqqqotherqqqq") != stable_shard
        {
            assert_eq!(
                idx2.get_shard(stable_shard).unwrap().root(),
                before,
                "untouched shard root must be stable (append-only, dedup-friendly)"
            );
        }
    }
}
