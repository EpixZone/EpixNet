//! Deterministic feed organization — the social-data-at-scale layer.
//!
//! Records are the only source of truth: byte-identical signed
//! `epix-orset-1` records that already gossip peer-to-peer. This crate
//! adds ORGANIZATION on top — segments, checkpoints, indexes, aggregates
//! — with one invariant that makes it work without any privileged online
//! party: **everything here is a pure deterministic function of the
//! record set**, so any node computes byte-identical roots. There is no
//! sealer, no hub, no attester. As long as someone hosts the records, the
//! feed exists and converges.
//!
//! The pieces (see the modules):
//!
//! - [`Record`]: a normalized view over one signed record's canonical
//!   bytes — the bytes are kept verbatim (already signed) and only the
//!   organizing fields (author, target, clock, id, kind) are extracted.
//! - [`segment`]: a closed set `{records : clock ≤ boundary}`, canonically
//!   ordered and content-addressed by its BLAKE3 root — reproducible, so
//!   two nodes produce the identical root.
//! - [`checkpoint`]: the monotone state spine (live records, aggregate
//!   counts, sticky tombstones, history root) — the "pruned blockchain"
//!   state, deterministic and prev-linked so a rollback is detectable.
//! - [`index`]: target → record locations, so "post X's comments" fetches
//!   only X's records.
//! - [`reactions`]: OR-set exact counts keyed by (author, target, kind),
//!   where a re-like supersedes and an un-like retracts (no HyperLogLog —
//!   it can't subtract).
//! - [`rollup`]: one gallery blob of per-item counts.

#![forbid(unsafe_code)]

pub mod checkpoint;
pub mod index;
pub mod reactions;
pub mod rollup;
pub mod segment;

use epix_blob::ObjId;

/// What a record does in a feed. Derived from the record's fields by the
/// app's schema adapter; the library treats these uniformly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A top-level item (a post, a gallery entry).
    Post,
    /// A comment on `target`.
    Comment,
    /// A reaction of the given kind on `target`; `active=false` is an
    /// un-react (retraction) in the same (author, target, kind) lineage.
    Reaction { kind: String, active: bool },
    /// A moderation/delete tombstone on `target` (sticky).
    Tombstone,
}

/// A normalized record: its verbatim signed bytes plus the organizing
/// fields extracted from them. The bytes are what get content-addressed
/// and re-verified; the fields only drive organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The exact signed record bytes (canonical `epix-orset-1` form).
    /// Never re-serialized — byte drift would break the signature.
    pub canonical: Vec<u8>,
    /// The CRDT identity key (stable across supersedes of the same item).
    pub id: String,
    /// Authorized author address (recovered from the signature upstream).
    pub author: String,
    /// The item this record attaches to (empty for a top-level Post whose
    /// own `id` is the target others attach to).
    pub target: String,
    /// Monotone ordering clock (ms). Ties broken deterministically.
    pub clock: u64,
    pub kind: Kind,
}

impl Record {
    /// The content address of this record's canonical bytes.
    pub fn addr(&self) -> ObjId {
        ObjId::of(&self.canonical)
    }

    /// The lineage key an OR-set folds on: same (author, target, kind)
    /// supersedes; a later clock wins.
    pub fn lineage(&self) -> String {
        let kind_tag = match &self.kind {
            Kind::Post => "post",
            Kind::Comment => "comment",
            Kind::Reaction { kind, .. } => kind,
            Kind::Tombstone => "tomb",
        };
        format!("{}\u{1f}{}\u{1f}{}", self.author, self.target, kind_tag)
    }

    /// The per-item identity a checkpoint/rollup fold keys on. Reactions
    /// keep their (author, target, kind) lineage so a re-like supersedes
    /// and an un-like retracts. Everything else (posts, comments,
    /// tombstones) keys on (author, id): `id` is the supersede-stable CRDT
    /// identity (an edit keeps the id, so it collapses to one winner) and
    /// `author` prevents another user from hijacking the id. Unlike
    /// `lineage()` this does not collapse two distinct posts/comments by
    /// the same author on the same target.
    pub fn identity(&self) -> String {
        match &self.kind {
            Kind::Reaction { .. } => self.lineage(),
            _ => format!("{}\u{1f}{}", self.author, self.id),
        }
    }

    /// Total, deterministic ordering used everywhere a record set is
    /// serialized: by clock, then id, then author, then content address.
    /// Two nodes with the same records always produce the same order.
    pub fn order_key(&self) -> (u64, &str, &str, [u8; 32]) {
        (self.clock, &self.id, &self.author, self.addr().0)
    }
}

/// Canonically order a record set (stable, total — the basis of every
/// deterministic root in this crate).
pub fn canonical_order(records: &mut [Record]) {
    records.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
}

#[cfg(test)]
pub(crate) fn test_record(id: &str, author: &str, target: &str, clock: u64, kind: Kind) -> Record {
    // A stand-in for real signed bytes: deterministic function of the
    // fields so tests get stable content addresses without a signer.
    let canonical = format!("{id}|{author}|{target}|{clock}|{kind:?}").into_bytes();
    Record { canonical, id: id.into(), author: author.into(), target: target.into(), clock, kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_order_is_total_and_stable() {
        let mut a = vec![
            test_record("b", "u2", "t", 5, Kind::Comment),
            test_record("a", "u1", "t", 5, Kind::Comment),
            test_record("c", "u1", "t", 1, Kind::Comment),
        ];
        let mut b = a.clone();
        b.reverse();
        canonical_order(&mut a);
        canonical_order(&mut b);
        assert_eq!(a, b, "order is independent of input order");
        // clock 1 sorts first; within clock 5, id 'a' before 'b'.
        assert_eq!(a[0].clock, 1);
        assert_eq!(a[1].id, "a");
        assert_eq!(a[2].id, "b");
    }

    #[test]
    fn lineage_groups_relikes_together() {
        let like1 = test_record("l1", "u1", "post9", 1, Kind::Reaction { kind: "like".into(), active: true });
        let unlike = test_record("l2", "u1", "post9", 2, Kind::Reaction { kind: "like".into(), active: false });
        assert_eq!(like1.lineage(), unlike.lineage(), "same (author,target,kind) lineage");
        let other = test_record("l3", "u2", "post9", 1, Kind::Reaction { kind: "like".into(), active: true });
        assert_ne!(like1.lineage(), other.lineage(), "different author = different lineage");
    }
}
