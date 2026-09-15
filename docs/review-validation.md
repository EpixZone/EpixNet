# Review validation

This review covers the failures reproduced below and the checks listed here. It
does not establish that either repository is free of bugs.

## Core issues verified before implementation changes

New regression tests ran against the original implementations before the fixes.

| Confirmed issue | Failing regression test | Change |
| --- | --- | --- |
| A downloaded schema's index SQL could attach and create an external SQLite database. | `untrusted_schema_index_cannot_attach_an_external_database` | Authorize only table/index creation for the declared table in the main database. |
| A schema column definition could execute additional SQL statements. | `untrusted_schema_column_type_cannot_execute_extra_statements` | Apply the same SQLite authorizer to column DDL and validate interpolated column identifiers. |
| A rejected JSON row left partial replacements and changed metadata in the index. | `failed_json_update_preserves_previous_rows_and_metadata` | Update each JSON document inside a rollback-safe savepoint. |
| An unsuccessful schema upgrade destroyed the previous table and its data. | `failed_schema_upgrade_preserves_existing_data` | Apply schema upgrades atomically. |
| A small file containing many short lines could allocate a quadratic diff matrix before checking the insertion limit. | `diff_falls_back_when_line_comparison_budget_is_exceeded` | Cap the matrix at 4 MiB, compare only the changed middle, and use one flat allocation. |
| Binary insertions changed bytes when serialized as JSON strings. | `diff_rejects_insertions_that_cannot_roundtrip_as_wire_strings` | Fall back to full file transfer when changed content cannot be represented losslessly. |
| Malformed insertion values silently became empty byte strings. | `diff_parser_rejects_non_string_insertions` | Reject the malformed action list. |

Before fixes:

```sh
cargo test -p epix-content -p epix-db --lib --no-fail-fast
```

- `epix-content`: 91 passed, 3 new regressions failed.
- `epix-db`: 15 passed, 4 new regressions failed.

After fixes and additional compatibility checks:

```sh
cargo test --locked -p epix-content -p epix-db
```

- `epix-content`: 96 unit tests and 3 differential tests passed.
- `epix-db`: 20 unit tests passed; documentation tests completed successfully.
- Additional coverage checks exhaustive short-text diff round trips, large
  unchanged regions, enclosing transactions, and schemas using indexes,
  `UNIQUE`, `CHECK`, and `AUTOINCREMENT`.

### Diff microbenchmark

An optimized Rust harness compared the original and revised diff implementations
on a 20,004-byte file: one changed line between two unchanged regions of 2,000
lines each. Both implementations had to reconstruct the exact new bytes.

Five iterations took **280.690 ms before** and **0.188 ms after**, approximately
1,500 times faster for this specific case. The original LCS matrix used about
64 MB; the revised changed-middle matrix used 16 bytes, in addition to linear
line indexes. This measures a synthetic diff operation, not overall browser or
network performance.

## Cancelled commit test synchronization

The existing
`state::tests::cancelled_root_commit_registers_a_newly_accepted_stored_child`
test failed in the workspace run and in 1 of 5 isolated repetitions. It checked
reference counts after file adoption became visible but before detached
registration finished acquiring manifest ownership.

The test now waits for the activation write barrier, which the detached
transaction retains through ownership reconciliation. Runtime behavior was not
changed. The corrected test passed 20 consecutive isolated repetitions, and all
6 cancellation tests passed together with four test threads.

```sh
cargo test --locked -p epix-ui --lib cancelled_root_commit_registers_a_newly_accepted_stored_child
cargo test --locked -p epix-ui --lib cancelled -- --test-threads=4
```

## Workspace and runtime checks

```sh
EPIX_WALLET_SKIP=1 cargo test --workspace --all-targets --locked --no-fail-fast
cargo test --locked -p epix-runtime --test clearnet_idle_reap -- --ignored
```

The initial workspace run compiled every target and reported **1,611 passed,
3 failed, and 16 ignored** across 104 test binaries, excluding nested subprocess
summaries. Two failures required real wallet extension fixtures, which the skip
setting omitted; the subsequent browser suite with the real wallet passed
**31 tests with 1 ignored**. The third failure was the cancelled commit test
corrected above.

The separately enabled idle connection integration test passed in **310.13 s**,
verifying that an idle encrypted clearnet connection releases its socket and
disappears from Stats. Other ignored tests include live-network/devnet checks
and deliberate golden-vector regeneration; they were not collectively enabled.

The final combined run with the rebuilt wallet embedded passed **1,615 tests,
0 failed, 17 ignored** across the same 104 test binaries:

```sh
EPIX_WALLET_DIST=/path/to/epix-wallet/apps/extension/build/firefox \
  cargo test --workspace --all-targets --locked --no-fail-fast
```

The extra ignored test is the real-Firefox startup check, which was also run
separately and passed.

## Desktop/browser

The installed macOS v0.5.7 app's unified logs showed its original launcher
stayed alive while the first visible Firefox startup waited roughly 45 seconds.
An actual fresh-profile Firefox ESR test reproduced the hang with
`--wait-for-browser`; removing that Windows-only flag completed in 2.06 seconds.
The compiled Rust regression using the packaged Firefox then passed in 0.92
seconds. New temporary-profile desktop launches reached Firefox in 6.54 and
3.47 seconds. The HTTPS dashboard rendered and the embedded wallet addon was
active. The wallet provider is injected into xite documents; the wrapper has a stricter
script policy, so checking only the outer frame is insufficient.

```sh
EPIX_TEST_FIREFOX=/path/to/packaged/firefox cargo test -p epix-browser fresh_firefox_warmup_exits -- --ignored
node --test crates/epix-browser/tests/pac-routing.test.cjs
node --test ui/tests/wrapper-permissions.test.cjs
```

Additional tests reproduced and now prevent:

- JavaScript bundle edits being ignored when the wallet manifest is unchanged.
  Three staging tests cover changed/removed/nested assets, bounded file
  comparisons, and reuse of identical trees.
- Onion requests taking a direct route when clearnet Tor routing is disabled.
  The generated PAC is executed against onion, clearnet, local, xite, I2P,
  and chain RPC destinations.
- Clone-progress events erasing the wrapper's full permissions and identity.
  Two tests reproduced the browser's `TypeError` before the fix. Three passing
  tests cover partial progress, early permission requests, and revoked grants.

The local debug build emits an Apple linker warning about large unwind tables;
the executables built successfully. This is separate from the startup defect.

## Mobile

Installed Android API 36 ARM64 tooling and an isolated Pixel 7 emulator.
Verified the published v0.5.7 APK checksum, installed it, and measured a cold
Activity launch of 1,853 ms. The node downloaded and rendered the dashboard;
the wallet popup, import flow, and recovery form rendered without startup crash
logs. This rendered smoke test used the released APK. The changed Kotlin URL
methods were separately compiled to Dex and run on the emulator against real
Android `Uri`/`Intent` classes: six assertions failed before the fix and all
passed after it. The complete modified APK was not rebuilt.

The Swift regression runner compiled actual production methods with Foundation
and WebKit doubles. Before fixes it reproduced seven initial failures plus
separate asynchronous-reply and encoded-traversal failures; the expanded suite
passes. Swift syntax parsing also passes. This covers bridge admission, reply
destinations, encoded path handling, and hash navigation, not WebKit rendering.

Full iOS compilation/simulation was unavailable: only macOS Command Line Tools
were installed (`simctl` and the iOS SDK were absent), and remaining storage was
insufficient for Xcode plus its runtime alongside the Android and Rust builds.
See [mobile test instructions](../shells/tests.md) for reproducible commands.

## Wallet

Companion wallet PR: https://github.com/EpixZone/epix-wallet/pull/17.
All 36 workspace test tasks passed; after the final targeted changes the
extension suite passed 7 suites / 58 tests. Extension typecheck, dependency
consistency, lint/format checks, and production MV2/MV3/Firefox builds passed.

Real Chromium 140 checks used a disposable wallet: creation, invalid password
validation, EPIX balance rendering at desktop and 360px widths, provider ping,
connection approval, account and chain queries, an off-chain ADR36 signature
and successful verification, locking, incorrect-password rejection, and unlock.
No uncaught JavaScript page exceptions were observed. External endpoint failures
and missing-active-tab diagnostics were logged. Automatic approval-window
presentation was not verified in headless Chromium: the actual approval UI was
opened in an extension tab to complete the checks.

Native status requests dropped from six simultaneous calls to one in the
pending-request regression. All routing/storage races were reproduced before
fixes; Firefox's base proxy-permission finding was withdrawn after inspecting
the actual Firefox manifest override. Physical hardware wallet tests and funded
transaction tests were not performed.
