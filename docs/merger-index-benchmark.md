# Signed merger-index benchmark

This harness measures the current node's merger indexing foundation. See
[persistent merger indexing](persistent-merger-index.md) for cache authority,
recovery, and lifecycle behavior. It generates
signed catalogue-shaped OR-set records, serves their signed hubs through
`AppState::add_xite`, builds the merger through `rebuild_merger_dbs`, applies
changed signed segments through `ingest_file`, and queries through `db_query`.
It does not insert fixture rows directly into SQLite or bypass record authority
verification.

The default is 10,000 live items. Use 100,000, 1,000,000, or 10,000,000 to increase
the workload. Smaller sizes are accepted for smoke tests. There are at most
10,000 initial live items per hub and 1,024 initial live items per segment, with
a declared 1 MiB segment cap. The update probe retains signed revisions in its
segment, so its stored-version count exceeds 1,024. This does not enforce the
proposed Trove envelope of 1,024 stored versions per segment.
Every segment keeps its own source identity. Local item IDs intentionally overlap
between hubs. Synthetic keys and source bytes are deterministic across equivalent
runs. These public test identities must never receive funds or be used for real
content.

## Run

Run from the repository root with Rust and the usual EpixNet build dependencies:

```sh
cargo test -p epix-ui --example merger_index_benchmark
cargo build --release -p epix-ui --example merger_index_benchmark
target/release/examples/merger_index_benchmark \
  --root /tmp/epix-index-10k \
  --items 10000 --queries 100 --updates 10 \
  --label candidate-release --output /tmp/epix-index-10k.json
```

The fixture directory must be empty. Existing files are never removed or
overwritten to start a run. The output file's parent directory must exist. The
program exits unsuccessfully on incorrect row counts, source-identity collisions,
incorrect pagination, rejected legitimate updates, accepted unauthorized authors,
or lost state after restart. Do not interpret a partially written report as a
successful run.

The ordinary Rust CI job runs the small example tests with `--locked`. The 1M and
10M runs remain explicit scheduled or manual workloads.

Generation is timed separately. The coordinator then starts a fresh child process
for initial node registration and indexing. A second fresh process restores the
persisted Xite registry and reconciles the merger index. That process must see the
last signed update and the complete live row count. This is a process restart
with the operating system's filesystem cache left intact, not a cold-disk or
power-loss benchmark.

To generate inputs once for multiple binaries:

```sh
target/release/examples/merger_index_benchmark \
  --root /tmp/epix-fixture-master --items 100000 --prepare-only
cp -a /tmp/epix-fixture-master /tmp/epix-fixture-baseline
cp -a /tmp/epix-fixture-master /tmp/epix-fixture-candidate
/path/to/baseline-binary --root /tmp/epix-fixture-baseline --existing \
  --label baseline-release --output /tmp/baseline.json
/path/to/candidate-binary --root /tmp/epix-fixture-candidate --existing \
  --label candidate-release --output /tmp/candidate.json
```

Copy the prepared fixture before either node has run. `--existing` requires that
the prepared fixture has no existing node registry. It does not erase a previous
run's indexes. Use the same build profile, fixture, query count, update count,
machine, power mode and competing workload for a comparison. Record the commits
used to build both binaries: `git_commit_at_run` describes the working directory
where the binary ran, not embedded proof of the binary's source revision. The
label should identify the built binary. Debug results are useful for regression
development but are not release performance evidence.
The report also hashes the executable so retained binaries can be matched to
their results.
Use separate Cargo target directories for separate checkouts. If reusing one
target directory, force a rebuild of changed packages before copying the next
binary; checkout timestamps alone can leave stale artifacts looking fresh.
Confirm that the candidate exposes index counters and a historical baseline
without that API reports null before collecting a comparison.

## Measurements and checks

The JSON report includes:

- Fixture size, hub count, segment size, generation time, platform, CPU count,
  Linux CPU model and total memory where available, and run label.
- Initial registration time, explicit reconciliation time, and time until the
  node answers the correct live row count. Registration includes its normal
  verification and any indexing it performs; it is not just a filesystem timer.
- p50, p95, p99, minimum and maximum latency for first pages, deep keyset pages,
  indexed type filters and indexed exact lookups. Every measured query uses the
  public node query path and checks its result cardinality. The deep-page query
  plan is included.
- Signed single-segment ingest latency, including verification and indexing.
  Producing the peer's signature and writing the source file happen before this
  timer. Subsequent reads must show the new value without duplicating items.
- Rejection of a valid signature from an unauthorized author, followed by a
  same-segment signed tombstone and reinstatement. These are correctness checks,
  not a cross-segment compaction or revocation qualification.
- Live and distinct `(hub, author, item ID)` counts after initial indexing and
  fresh-process restoration.
- Node index counters after readiness and at the end, when the tested revision
  exposes them. The same harness returns null for these fields on older baseline
  revisions; it does not invent counters for the full-rebuild implementation.
  Each measured independent segment update records its counter delta and fails
  if it verifies or replays more than one input source. Reconciliation deltas are
  reported separately. These counters describe accepted JSON inputs and SQL
  source replay. They do not count every manifest traversal, authority lookup or
  filesystem read, and do not prove that all node work has constant cost. The
  elapsed ingest timer includes that additional work.
- Current and peak process RSS from Linux `/proc/self/status`; unsupported
  platforms return null. Peak RSS includes all work in that child process.
  Filesystem cache, browser memory and GPU memory are not measured.
- Data-directory, private-directory, derived-index-cache and total logical file bytes. These are
  file lengths, not allocated filesystem blocks, and include persisted source
  metadata and node state. The derived-index value counts `private/cache/merger-index-v1`,
  including SQLite sidecars. The total also includes fixture and phase-report files.

Useful scales:

| Items | Intended use |
| --- | --- |
| Small smoke fixture | Ordinary correctness test through node APIs |
| 10,000 | Quick baseline/candidate comparison |
| 100,000 | Development profiling and index-growth checks |
| 1,000,000 | Scheduled or manual foundation benchmark |
| 10,000,000 | Large foundation qualification on a suitable machine |

## Limits of the result

This is not the full Trove release qualification. These fixtures use signed
owner-controlled hubs, not xID member directories or independently owned report
sources. They contain no original media, thumbnails, ratings, removal registry,
long revision history, cross-segment tombstone folding or adversarial trust-policy
changes. The generated schema is a benchmark schema, not a frozen Trove format.

The harness measures existing generic indexed SQL queries. It does not implement
or qualify Trove's proposed full-text query service, cursor protocol, browser
rendering, native Android, peer networking, uploads, streaming playback, mixed
transfer load, cancellation or user-facing p95 latency. It does not certify a
1M or 10M release target by itself. Cold filesystem-cache runs, power-loss
recovery, sustained concurrent updates and transfer contention need separate
measurements. Keep these distinctions alongside any published benchmark numbers.

See the [recorded foundation results](benchmark-results/2026-10-28-merger-index/README.md)
for the release-profile 10k baseline comparison and 1M candidate run, including
raw reports and their exact implementation revisions.
