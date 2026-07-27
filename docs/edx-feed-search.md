# EDX feeds + search (frozen formats)

Companion to `edx-slice-format.md` and `edx-manifest.md`. Everything here
is a **pure deterministic function of the signed record set** — any node
rebuilds byte-identical bytes/roots, so there is no sealer, hub, or
attester. Convergence needs only that someone hosts the records.

## Feeds (`epix-feed`)

- **Record ordering** (frozen): total order by `(clock, id, author,
  content_addr)`. Every serialization sorts by this.
- **Segment** (`EDXSEG1`): `magic ‖ le64(boundary) ‖ le32(count) ‖
  [le32(len) ‖ canonical_bytes]*` over `{records : clock ≤ boundary}` in
  canonical order. Root = BLAKE3(bytes) = content address.
- **Spine**: prev-linked segment links, `link_root = BLAKE3(prev_link ‖
  segment_root ‖ le64(boundary))`. Boundaries strictly increase; a
  divergent-prefix or non-increasing spine is rejected (rollback
  detection).
- **Checkpoint** (`EDXCKPT1` / history `EDXHIST1`): the pruned-blockchain
  state — live winners (supersede/retract), reaction-count balances,
  sticky tombstones, prev-linked history root. Deterministic, so no
  attester. Counts survive pruning (carried in the checkpoint);
  tombstones are sticky (can't resurrect via higher clock); `extends()`
  rejects a checkpoint not chained to its predecessor.
- **Index** (`EDXIDX1`): `target → sorted [(segment_root, offset, len)]`
  so a per-post view is O(window).
- **Reactions**: OR-set exact count per `(author, target, kind)` lineage;
  re-like supersedes, un-like retracts. No HyperLogLog (can't subtract).
- **Rollup** (`EDXROLL1`): `item → (comment_count, reaction_counts,
  newest_clock)`; tombstoned comments excluded.

Planet scale: the site-wide post index is hierarchical/paginated (never a
flat list); hot objects get count-only reaction seals; global cross-corpus
search is an optional indexer service (below), not the P2P read path.

## Search (`epix-search`)

Trust rule (both tracks): an answer is only a POINTER; the client fetches
the record and verifies it against its BLAKE3 root. An untrusted answerer
can only omit or waste a fetch, never inject a fake match.

- **Tokenizer** (frozen v1): ASCII-lowercase fold, split on non-
  alphanumeric, drop tokens <2 or >40 bytes, dedupe, sort. Non-ASCII is a
  separator in v1 (a vendored normalization table is a future format
  bump, never a silent change).
- **Term hash** (frozen): `BLAKE3(term)[..8]` little-endian → u64.
- **Track 1 — XOR8 skip-filter**: per-segment committed xor filter (no
  false negatives). Walk the spine, pull the tiny filters, skip segments
  rejecting all query terms, fetch+verify candidates. Seed schedule is
  fixed (`xor8::SEEDS`) so the filter is deterministic and content-
  addressable. ~0.39% false positive, ~9.84 bits/entry.
- **Track 2 — inverted index** (`EDXSHRD1` shards, `EDXMETA1` meta):
  `SHARD_COUNT = 256` shards, `term_hash % SHARD_COUNT`; each shard is a
  sorted `term_hash → [pointer]`. A query fetches the meta then one
  shard. Sealing a new segment only appends to touched shards → untouched
  shard roots stay stable (dedup, no whole-index reflow).

Honest completeness bound (shipped, not hidden): **soundness** (no forged
match) is trustless via fetch-and-verify. **Completeness** (no true match
omitted) is trustless only *relative to* the owner-signed committed root
(`meta_root` / spine head committed in content.json) — a malicious
BUILDER can still omit from the committed set, the same owner-trust
EpixNet already accepts for content.json. Ranked/fuzzy/global cross-xite
search stays an optional indexer/app-view service.

## Order + distribution (`epix-blob::policy`)

- **`order_policy`**: `first_paint[]` (tight-deadline shell) + `feed_order`
  (newest/oldest/pinned/custom) + `prefetch[]`. Feeds the EDX scheduler;
  the hardcoded ladder is the default when nothing is declared. EpixTalk =
  newest-first.
- **`distribution`**: per-path `unit` (package | file-refs | feed) +
  `retention` (complete | partial), longest-prefix match. A xite MIXES
  units (forum = package shell + feed + file-refs media). Default is
  package/partial: stream-first, seed what you viewed, never ambush a data
  cap. `retention:complete` completion is consent-gated (reuses the
  existing size-limit prompt). Content-addressing already gives #340's
  cross-site file-by-reference.
