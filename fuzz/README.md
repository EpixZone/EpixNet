# EVX boundary fuzzing

Six libFuzzer targets exercise the repository's parsers, validator and durable state:

| Target | Boundary and checks |
| --- | --- |
| `declaration` | Strict declaration JSON, manifest binding, broker requests, capability/path/limit invariants and accepted-request round trips. |
| `activation` | Raw envelopes plus mutated bodies signed with a public fixture key, bounded file capture, identity/capability checks and rejection under a different verification grant. |
| `ipc_frames` | Production worker length-prefixed reader/writer, partial and interrupted reads, truncated or oversized frames, strict typed decoding of all six message types and accepted-frame round trips. |
| `wasm_profile` | Actual `evx_runtime::validate_module`, core module header, closed imports and required exports. No compilation or guest execution. |
| `state_sequences` | Disposable SQLite sequences covering occurrence claims, recovery fencing, uncertain effects, consent changes, job replacement, clock rollback, daily budgets, management-revision fencing and separation between two xites. |
| `lifecycle_metadata` | Disposable direct-worker control journals: strict decoding, version migration, corrupt data, unsafe modes, symlink/hardlink refusal and interrupted staging. Does not launch a worker or simulate OS termination. |

All inputs are sacrificial. Activation uses one temporary directory containing a fixed fixture module. No real xites, credentials, chains or network APIs are used. Inputs are bounded to 64 KiB for declaration/activation JSON, 256 KiB plus the four-byte prefix for IPC, 1 MiB for Wasm and 2 KiB for state sequences. Ordinary IPC frames retain their smaller 128 KiB limit; only compiled-artifact replies and guest initialization use the larger envelope. These targets do not test the OS sandbox, scheduler event loop, publication, consent UI or arbitrary runtime effects. The IPC target covers framing and decoding, not the supervisor lifecycle state machine or workspace races.

## Run

From the repository root:

```sh
rustup toolchain install nightly-2026-10-03 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2026-10-03 fetch --locked --manifest-path fuzz/Cargo.toml
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-03 fuzz run declaration --fuzz-dir fuzz --codegen-units 16 -- -max_total_time=45 -timeout=5 -rss_limit_mb=768 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-03 fuzz run activation --fuzz-dir fuzz --codegen-units 16 -- -max_total_time=45 -timeout=5 -rss_limit_mb=768 -max_len=65536
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-03 fuzz run ipc_frames --fuzz-dir fuzz --codegen-units 16 --sanitizer address -- -max_total_time=60 -timeout=5 -rss_limit_mb=1024 -max_len=262148
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-03 fuzz run wasm_profile --fuzz-dir fuzz --features runtime --codegen-units 16 -- -max_total_time=60 -timeout=5 -rss_limit_mb=1024 -max_len=1048576
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-03 fuzz run state_sequences --fuzz-dir fuzz --features state --codegen-units 16 -- -max_total_time=60 -timeout=15 -rss_limit_mb=1024 -max_len=2048
CARGO_NET_OFFLINE=true cargo +nightly-2026-10-03 fuzz run lifecycle_metadata --fuzz-dir fuzz --features lifecycle --codegen-units 16 --sanitizer address -- -max_total_time=120 -timeout=10 -rss_limit_mb=1024 -max_len=65537
```

`cargo-fuzz 0.13.2` has no `run --locked` option. The locked fetch verifies the separate fuzz lockfile before an offline run. AddressSanitizer, debug assertions and overflow checks are enabled by cargo-fuzz by default. `CARGO_BUILD_JOBS=2` was used for the recorded builds. Fuzz time bounds exclude compilation time. For a smaller CI smoke run, also pass `-runs=10000`; that stops at the first reached run or time limit.

This directory is a separate Cargo workspace. Its lockfile pins dependencies without altering the application's workspace configuration. Wasmtime is pinned by `evx-runtime` to `48.0.5`; the validator uses wasmparser `0.254.2`.
The current lockfile aligns shared package versions, sources and checksums
with the application lockfile. `python3 scripts/check-evx-fuzz-lock.py` checks
that identity in CI; it does not claim identical feature selection. CI preserves
logs, revision, tool versions, lock hashes and failure inputs for 14 days. Its
explicit Bash profile preserves fuzz failures through the logging pipelines.
The aligned campaign below completed against a saved source snapshot.

## Aligned source campaign

The 2026-10-04 direct-lifecycle target completed two AddressSanitizer runs:
6,950 executions from an empty corpus and 6,878 with curated journal seeds and
the first run's discoveries. Each reported 121 seconds, with no reported
crash, sanitizer or invariant failure. The second run reached valid legacy
metadata and migration paths; the empty run primarily exercised rejection.
[Its manifest](results/2026-10-04-lifecycle/manifest.json) identifies the frozen
source, locks, seeds, logs and retained 257-file corpus. This tests metadata
handling, not real reboot recovery or OS containment. Later Apple and Windows
changes are outside that snapshot.

The later 2026-10-03 campaign completed **6,466,701 executions** with no
reported crash, sanitizer failure or invariant failure:

| Target | Executions | Reported seconds |
| --- | ---: | ---: |
| Declaration and broker | 1,933,076 | 61 |
| Signed activation | 206,075 | 61 |
| IPC frames | 3,537,542 | 601 |
| Wasm profile | 787,932 | 61 |
| Durable state sequences | 2,076 | 601 |

[The aligned manifest](results/2026-10-03-aligned/manifest.json) records exact
commands, source/archive and lock hashes, per-target logs and complete corpus
archives. All five targets used explicit AddressSanitizer, the pinned nightly,
`--features state,runtime`, a 1,024 MiB RSS bound and one build job. The
standalone runner and immutable source snapshot are retained as local ignored
evidence alongside the logs and corpora. Compilation time is recorded separately
from each target's reported campaign duration; all lock hashes stayed unchanged.
The state target includes schema 9 and management-revision assertions.

Afterward, 85 relevant source files were compared with the working tree:
the local dependency closure, fuzz target sources, locks and included worker
IPC implementation matched. Subsequent node cancellation and Apple supervisor
changes are outside these fuzz targets and need their own regression evidence.
A ten-minute target run is bounded sampling, not a sustained production workload
or an independent security audit. These results do not prove OS containment.

## Earlier campaign

On 2026-10-03, Darwin arm64, `rustc 1.101.0-nightly (0abfedbc7 2026-10-02)` and cargo-fuzz `0.13.2`:

| Target | Executions | Measured seconds | Result |
| --- | ---: | ---: | --- |
| Declaration and broker | 2,122,598 | 46 | No reported crash or invariant failure |
| Signed activation | 62,401 | 46 | No reported crash or invariant failure |
| IPC frames | 1,561,164 | 61 | No reported crash or invariant failure |
| Wasm profile, Wasmtime 48.0.5 lock | 423,328 | 61 | No reported crash or invariant failure |

The IPC campaign reported a peak RSS of 685 MiB under its 768 MiB limit. A separate AddressSanitizer replay exercised both a maximum-size valid frame and a maximum-size truncated frame. The target includes the production worker framing source directly and invokes the production strict decoder for incoming worker, compiler and helper messages. It does not fuzz process spawning or supervisor state transitions. Its temporary 332 MiB build cache was removed after verification.

See [machine-readable results](results/campaign-summary.json). Matching logs in `results/` are local generated output and are ignored by Git, so a fresh checkout does not include them. The profile also had preliminary 48.0.5 and intermediate 48.0.3 runs; those local logs are named separately and are excluded from the table. The final run reused their discovered inputs. Short fuzz campaigns sample possible inputs and do not establish absence of vulnerabilities or constitute an independent audit.

Named JSON and Wasm seeds remain in `corpus/`. Named IPC framing seeds also remain in `corpus/ipc_frames/`, including maximum-length and truncated frames. These deliberate test inputs are committed with the targets. Local copies of the complete corpora are compressed in ignored `results/*-corpus.tar.gz` archives; [corpus-manifest.json](results/corpus-manifest.json) records their counts, byte sizes and SHA-256 hashes. When an archive is available, extract it into a temporary directory and pass its target subdirectory after the fuzz target name to replay or extend it. Archive files and raw logs must be preserved separately when transferring campaign evidence to another machine. Generated build and crash directories are ignored, but a crash reproducer should be retained with a regression test if a campaign finds one.

Two later historical runs are preserved under
[`results/2026-10-03-prealignment/`](results/2026-10-03-prealignment/manifest.json):
3,695,527 extended IPC executions and 5,796 state-sequence executions, each
over 601 seconds, with no reported failure. Their exact original source
snapshots were not retained. The state target subsequently gained additional
cross-xite and management-revision assertions, and both now use the aligned dependency graph, so these
logs do not validate the final source. The archive includes the original
lockfile and hash-checked logs and corpora, stored locally and ignored by Git.
Only the compact manifest is committed from that directory. Named `.seq` seeds
remain trackable; generated coverage, artifacts and unnamed corpus additions
are ignored.

## Dependency check

[dependency-audit.json](results/dependency-audit.json) records the scoped cargo-audit `0.22.2` result against RustSec database commit `ef6173cbc5c50ec8166f9a5b28f07834144373ee`, updated 2026-10-03. The checked closure is the listed EVX crates and their dependencies on this macOS host.

The initial Wasmtime `48.0.3` lock matched three published advisories: [RUSTSEC-2026-0325](https://rustsec.org/advisories/RUSTSEC-2026-0325.html), [RUSTSEC-2026-0326](https://rustsec.org/advisories/RUSTSEC-2026-0326.html) and [RUSTSEC-2026-0327](https://rustsec.org/advisories/RUSTSEC-2026-0327.html). Their affected GC, exception and component paths are disabled by EVX's profile. No exploit of those paths was demonstrated here. The application and fuzz lockfiles now use patched `48.0.5`; the repeated advisory scan reports no known vulnerability in this scoped closure.

Two maintenance warnings remain: `paste 1.0.15` through Tendermint/flex-error and `proc-macro-error 0.4.12` through bao-tree/genawaiter. The registry request for yanked-package status timed out, so that check remains unverified; the completed advisory scan used `--no-yanked`. Findings elsewhere in the full repository are outside this scoped report.
