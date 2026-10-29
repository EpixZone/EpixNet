# Persistent merger-index foundation results

All three runs completed their correctness checks. The candidate indexed one
million signed live items, updated one segment at a time, and restored the saved
projection in a fresh process without replaying any SQL sources. These results
measure the indexing foundation, not the full Trove release requirements.

## Revisions and environment

- Baseline node: `5d71d9f67e9122fe19936e754f253d7c3acb35db`, with only the benchmark
  example added. Its dirty-tree flag reflects that added harness.
- Candidate executable: `d6d669d75bcaf08b63f07498d95d61e7f641e134`. Both candidate
  runs used the same executable, with BLAKE3
  `42507ca4144fb5d3d576a8eba298766b93f1707f5b17e7ac2b3d54734dc6ae96`.
  The 1M report's dirty-tree flag records later working-tree edits, not changes
  to the measured executable. Follow-up changes require their own correctness
  validation; these timings retain the implementation revision above.
- Build: Cargo release profile, default features, Rust/Cargo 1.98.1. The same
  harness was compiled against both implementations.
- Host: Linux `7.0.0-38-generic`, x86-64, Intel Xeon E5-1620 at 3.60 GHz,
  8 reported logical CPUs, about 30.27 GiB RAM, ext4 filesystem. Storage-device
  model and power policy were not recorded. No concurrent builds or test suites
  ran during the timed phases.

## Observed results

Each query probe has 100 samples per process. Hot updates have five samples, so
their nearest-rank p95 is the largest of those five measurements. These are one
run per configuration, not repeated hardware qualification.

| Measurement | Baseline 10k | Candidate 10k | Candidate 1M |
| --- | ---: | ---: | ---: |
| Initial verified catalogue readiness, seconds | 7.743 | 4.568 | 342.416 |
| Fresh-process restored catalogue readiness, seconds | 5.777 | 2.777 | 264.362 |
| Hot segment update median, milliseconds | 2,792.879 | 211.560 | 195.241 |
| Hot segment update p95, milliseconds | 2,929.485 | 249.470 | 234.259 |
| Initial-phase first-page p95, milliseconds | 0.059 | 0.072 | 0.211 |
| Initial-phase deep-page p95, milliseconds | 0.052 | 0.065 | 0.156 |
| Largest query-probe p95 across both phases, milliseconds | 0.084 | 0.111 | 0.233 |
| Initial-process peak RSS, MiB | 154.36 | 55.21 | 59.50 |
| Restart-process peak RSS, MiB | 119.46 | 44.98 | 51.02 |
| Derived index cache after restart, MiB | 0 | 5.30 | 534.82 |

The baseline used an in-memory projection; zero derived-cache bytes is not zero
memory use. RSS excludes the operating system's filesystem cache. Index-cache
bytes include SQLite files and sidecars. Initial and restart disk sizes differ
as SQLite checkpoints its WAL.

At both candidate sizes, every timed update verified exactly one input and
replayed exactly one SQL source, without a global reconciliation. The 1M initial
build replayed 1,000 segments. Its fresh-process restart replayed zero sources
and zero bytes, while normal authority and signed-input verification still ran.
The 4 minute 24 second restart does not meet Trove's proposed startup budget.
Persistence avoids SQL repopulation; further verification and startup work is
still required.

## Fixture and scope

The 10k comparison used copies of the same prepared signed fixture. The 1M
fixture used 100 owner-signed hubs and 1,000 segments. Each segment initially
contained up to 1,024 live items. The update probe retained five edits, a
withdrawal, and a reinstatement in the first segment. Its measured final maximum
was **1,031 stored versions**, with 1,000,007 stored versions across the fixture.
The largest segment was 384,709 bytes, below its declared 1 MiB cap. This does not
implement Trove's proposed 1,024 stored-version wire envelope.

Normal node APIs performed signature/authority verification, indexing, updates,
queries and restoration. Checks covered exact ordered query results, titles and
types, complete row counts and distinct logical identities, an unauthorized
author, and same-segment withdrawal/reinstatement. Fixture generation took
210.249 seconds separately and is excluded from node-readiness timers.

The restart used a new process with the operating system's cache left intact.
The queries measured existing indexed SQL through `db_query`; no browser,
WebSocket transport, full-text service or viewer was measured. The fixture had
no media, thumbnails, xID member directories, judgments or removal registry.
Cross-segment conflict resolution, sustained mixed load, native Android,
power-loss recovery and 10M qualification remain outside this run. See the
[harness guide](../../merger-index-benchmark.md) for the full scope and commands.

## Raw evidence

- [Baseline 10k report](baseline-10k.json)
- [Candidate 10k report](candidate-10k.json)
- [Candidate 1M report](candidate-1m.json)
- [Measured fixture inventory and generation time](fixture-inventory.json)

Reports are retained as emitted by the harness. Their executable hashes identify
the actual binaries; Git status at report time is separate from build provenance.
