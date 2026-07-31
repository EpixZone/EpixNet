# EDX slice format (frozen)

Status: **frozen v1**. This byte format is a wire contract between every
EDX node, and — if publisher escrow ever ships — a consensus contract for
the on-chain proof verifier. Changing ANY constant here re-roots every
object on the network. A revision requires a new version tag, a migration
plan, and regenerated golden vectors (`crates/epix-blob/tests/golden.rs`).

## Object identity

- An EDX object (file blob, bundle, or encrypted shard) is identified by
  its **32-byte BLAKE3 hash of the content bytes** (`ObjId`, hex-encoded
  in manifests as the `b3` field).
- This is the *plain* BLAKE3 hash: the chunk-group parameter below does
  not change the root, so the manifest hash, the bao tree root, and
  `blake3sum` of the file are the same value.

## Tree geometry

- Hash tree: BLAKE3's native binary chunk tree, as exposed by the
  `bao-tree` crate (pinned `=0.16.0`).
- Native chunk: 1024 bytes (BLAKE3's chunk).
- **Chunk group: 16 KiB** (`chunk_group_log = 4`, i.e. 16 native chunks).
  Interior hashes below chunk-group level are never stored or
  transmitted; verification granularity is one group, so corruption
  localizes to ≤ 16 KiB.

## Outboard (`.obao`)

- The outboard holds the interior hash pairs of the tree in **pre-order**,
  each node as 64 bytes (left child hash ‖ right child hash), exactly the
  `bao-tree` `PreOrderOutboard` layout with the size/prefix OMITTED.
- The outboard file contains ONLY hash pairs. Root and size travel in the
  signed manifest, never in the outboard.
- Size in bytes: 64 × (number of interior nodes at group granularity);
  ~0.4% of the data for large files, zero for files ≤ 16 KiB.
- Outboards are recomputable from the data alone; they are cached, never
  transferred (verified slices carry the needed interior hashes inline).

## Verified slice (the wire encoding of a range response)

A slice for a set of chunk ranges is the pre-order interleaving of:

1. **Parent nodes** (64 bytes: left hash ‖ right hash) for every interior
   node on the path to the requested ranges, each emitted once, in
   pre-order traversal order;
2. **Chunk-group data** (raw bytes, ≤ 16384 per group; the final group of
   a file may be short) for every group overlapping the requested ranges.

This is the `bao-tree` 0.16 `encode_ranges_validated` stream layout with
no size header (size comes from the signed manifest, requested ranges
from the request itself). Multiple ranges are encoded in one slice; shared
parents are emitted once. Ranges are canonicalized by rounding outward to
chunk-group boundaries and truncating to the object size.

The decoder verifies incrementally: each parent pair must hash to its
expected parent (root first), each group must hash to its leaf. The first
mismatching byte aborts the decode; bytes are only released to the caller
after their group verifies.

- Empty range set → empty slice (zero bytes).
- Whole-object slice for a ≤ 16 KiB object → just the raw bytes (no
  parents), and for ≤ 4 KiB user files implementations may skip the tree
  entirely and verify the whole blob hash (`verify_whole`).

## Golden vectors

`crates/epix-blob/tests/golden_vectors.json` pins: the deterministic test
pattern `byte[i] = (i*31) % 251`, object roots, outboard lengths and
hashes, and slice lengths and hashes for boundary-covering (size, ranges)
cases. CI fails if any output byte drifts.
