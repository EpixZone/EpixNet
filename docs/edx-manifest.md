# EDX manifest fields (frozen)

Status: **frozen v1** (`"edx": 1`). Companion to `edx-slice-format.md`.
These are plain JSON fields folded into the signed content.json payload —
the signing/verification model is completely unchanged, and pre-EDX
verifiers simply ignore them (unknown fields are already part of the
signed payload and accepted).

## Per-file fields (inside `files` / `files_optional` entries)

| Field | Meaning |
|---|---|
| `b3` | hex BLAKE3 root of THIS file's bytes (see slice-format doc) |
| `bundle` | hex BLAKE3 root of the bundle object holding the bytes (small files only) |
| `off` | byte offset of this file inside the bundle |
| `size` | unchanged legacy field; also the object size for `b3` |
| `sha512` | legacy hash, kept during the migration window only |

A bundled file's `b3` is the hash of its OWN bytes — never of the
bundle — so cross-xite dedup and whole-file verification are independent
of packing. Fetching a bundled file means fetching the byte range
`off .. off+size` of the bundle object (group-aligned superset, per the
slice format).

## `bundles`

```jsonc
"bundles": { "<bundle b3 hex>": {"size": 262144, "seq": 0}, ... }
```

Every bundle referenced by a file entry MUST appear here (fetchers reject
entries referencing undeclared bundles). `seq` records the bundle's
creation order (0-based) so re-signing recovers the append order instead
of the hex-id order this JSON object would otherwise iterate in; it is
optional and legacy manifests without it fall back to key order. Bundle
membership is decided at
signing time by the stable bundler (`epix-blob::bundle`): membership is
carried forward from the previous manifest, new files append to the tail
bundle, and only a changed bundle re-mints. Nothing about membership is
derived from path order at fetch time.

## `files_merkle_root`

A 32-byte commitment to the manifest's file set, used by the optional
on-chain content-root anchor and (if publisher escrow ever ships) its
inclusion proofs.

Frozen construction over all entries of `files` and `files_optional`
that carry a `b3`:

1. Sort entries by path (byte order).
2. Leaf hash: `BLAKE3( 0x00 ‖ le32(len(path)) ‖ path ‖ b3(32 bytes) ‖ le64(size) )`.
3. Parent: `BLAKE3( 0x01 ‖ left ‖ right )` over adjacent pairs; an
   unpaired trailing node is promoted unchanged to the next level.
4. Root of the empty set: 32 zero bytes.

## `content_root`

`edx1:<blake3 hex of canonical content.json>:<files_merkle_root hex>:<rev>`
— mirrors the optional on-chain anchor (`MsgUpdateContentRoot`). A xite
with no anchor is fully functional; an anchor only adds stale-rollback
protection (a fetched content.json older than the anchored rev is
rejected in the background).

## Exclusions

- **CRDT merge-files** carry per-record signatures and have no canonical
  byte string; they keep flowing over the Update/diff path and carry NO
  `b3` (exactly as they carry no `sha512` today).
- **User-content data files** are excluded from BUNDLING (they churn),
  but still carry `b3` when the signing path covers them; sub-4 KiB user
  files are verified whole-blob and ride inline in Update propagation.
