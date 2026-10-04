# EVX implementation review

Review dates: 2026-10-03 to 2026-10-04. Baseline: `evx`, commit `94149a8`.

Scope includes milestones 1, 2 and 3: hostile module validation and compilation,
worker confinement, IPC and native helpers, signed activation, durable state,
consent and management commands, wrapper rendering, scheduling and recovery.
All execution tests use disposable fixtures. No live xites, wallets or chain
actions are involved.

## Reproduced defects

Each regression below was first run against the vulnerable implementation and
failed before its fix was applied. The test name or suite is retained in-tree
so the result can be repeated. Related cases share one row.
The Linux policy findings concern the new platform implementation developed
during this review, not Linux execution in the baseline, which was unsupported.

| Boundary | Observed defect | Fix and regression |
| --- | --- | --- |
| Trusted wrapper | Publisher title markup and repeated template substitution could reach the wrapper script context, including its nonce. Decoded paths also broke JavaScript literals. | Context-specific escaping and one-pass substitution. Real router response regressions in `wrapper_canonical_paths` and `file_manager`. |
| Consent UI | Publisher CSS could inject declarations; wrapper could be framed; expired consent looked enabled. | Restricted color syntax, framing denial, expiration-aware UI. Router, CSP and production JavaScript regressions. |
| Socket authority | Host matching discarded the port, admitting a different local origin with a wrapper key. | Exact host and port matching, HTTP/WebSocket regression. |
| IPC lifecycle | Blocking writes could stall the watchdog; unbounded reader queues accepted floods; truncated trailing headers were accepted. | Nonblocking bounded writes, bounded queues and strict EOF framing. Hostile-peer IPC regressions. |
| Native process boundary | A non-CLOEXEC descriptor leaked into the child. The fixed 3-second CPU backstop killed guests granted longer budgets. | Seal inherited descriptors before exec; enforce the current grant with a separate hard maximum. Native descriptor and CPU regressions. |
| Helper authority | Read operations launched a file helper with native write access. | Select the read-only sandbox before parsing input. A native probe could write before the fix and is denied afterward. |
| Helper identity | Delayed messages from a retired helper could be attributed to its replacement, including commit requests. | Bind every reader event to a unique process instance. Three delayed-result, commit and protocol-error regressions. |
| Cleanup and capacity | Failed helper cleanup could lose ownership and release the workspace; compiler cleanup uncertainty became an ordinary denial. Group-only signaling missed a child that changed process group. | Track peers until confirmed stopped, preserve typed quarantine, retain the workspace lease and stop all new child admission after uncertain cleanup. Signal the still-owned PID as well as its group. Isolated lifecycle regressions. |
| Live limits | CPU/RSS/wall checks used stale limits; guest fuel and memory limits remained the initialization snapshot. | Re-read live limits and cancel on reductions that cannot safely reconfigure an existing store. Lifecycle regressions. |
| Compiler boundary | WAT parsing happened in the host; compilation lacked independent CPU/RSS enforcement and did not stop on revocation. | Parse inside the confined compiler, enforce compiler limits and poll trusted cancellation. Activation-runner and compiler regressions. |
| Activation | Denied workspace admission advanced the version floor; a pending activation could be admitted by a different grant; checkpoint persistence happened after guest effects. | Bind pending activation to its verified grant; persist checkpoint under admission before guest startup. Activation and node checkpoint-failure regressions. |
| Concurrent activation | A loader captured before compilation could overwrite a newer checkpoint admitted by another host. | Compare the durable floor again under the workspace lease. `another_hosts_newer_admission_cannot_be_overwritten_by_a_stale_loader`. |
| Revocation | A limits change could restore a concurrently revoked grant. Replacing consent left a running broker with old authority. | Atomic limits-only state update and serialized policy propagation. Node service regression fixtures. |
| Scheduler wake and admission | Disabling the plugin with no jobs did not wake it. A queued manual run could start after disable. | Dedicated configuration watch, enabled check after queueing and policy epoch check before admission. Idle-disable and queued-disable regressions. |
| Policy cancellation | Disabling EVX counted a cancelled run as a task failure and delayed re-enable with failure backoff. A post-hoc policy check could misclassify an unrelated denial. | Carry a typed host cancellation cause through binding, compilation and guest execution. Preserve claimed slots, spent budgets and prior failures; retain reconciliation for uncertain effects. Pre-admission, active-guest and coincident-error regressions. |
| Replay and budgets | Removing/re-adding jobs and pruning history reopened old slots or reset old daily budgets after clock rollback. Pruning could remove the requested retained replay row. | Persistent replay guards, fail-closed budget history and preserve a requested retained identity. State regressions. |
| Crash recovery | An admitted guest could be rerun after a crash even if its workspace write had succeeded. A later bookkeeping error was reported as an effect-free denial. | Durable execution phase before guest startup; interrupted admitted work becomes `effect_unknown`. Node recovery and post-admission failure regressions. |
| Effect completion | Result completion and reconciliation pause were separate writes. | Atomic result plus pause, including revoked authority and removed jobs. State uncertainty regressions. |
| Quarantine propagation | A quarantined result masked uncertain effects, and revocation could close it without retaining the pause. | Preserve the trusted outcome flag and require reconciliation for quarantine, including the grant-fenced completion fallback. Node and state regressions. |
| Operator controls | Publisher removal and re-addition of a job discarded its reconciliation pause, user pause or disabled state. | Durable host-owned job controls, preserved through re-registration and cleared only by explicit management actions. State removal/re-add and stale-registration regressions. |
| Linux syscall policy | Unrestricted `fcntl` could deliver a signal to another same-user process via asynchronous pipe ownership. | Restrict descriptor-control commands and reject `O_ASYNC`. Reproduced and verified with a disposable signal-handler fixture using the actual seccomp filter. |
| Linux packages | The release build and package contents omitted the adjacent worker executable. | Build and stage `evx-worker` in every format, validate its type, mode and architecture, and check installed or extracted bundles. Nine offline packaging tests pass after seven original failures. |
| Windows products | Default browser and server features reached Unix-only EVX crates and failed Windows compilation. | Restrict the optional node dependency and plugin registration to macOS/Linux. The Windows dependency guard and workspace cross-check failed before the fix; all 11 product graphs pass afterward. |
| Unicode diagnostics | Byte truncation panicked inside a multibyte character in broker errors and guest-controlled Wasm function-name context. | Truncate only at a UTF-8 boundary, keeping the same byte ceilings. `error_limit_preserves_utf8` and `multibyte_function_name_does_not_panic_when_error_is_bounded` both failed before the fix and pass afterward. |
| Artifact API contract | A safe public runtime entry point accepted serialized artifacts without expressing the trusted-compiler provenance required by Wasmtime deserialization. | Make the entry point unsafe with an explicit provenance contract. Its compile-fail doctest failed before the change and now passes; trusted callers document the source of their artifacts. |
| Workspace provenance | An outside hard link could be opened before its workspace alias disappeared, defeating the later single-link check. | Host-owned durable content digests gate every read and write acknowledgement. Fourteen real-broker regressions cover substitutions, uncertain writes, cancellation, commit delivery and helper shutdown. See [workspace provenance](evx-workspace-provenance.md). |
| Linux artifact transport | A small ARM64 module produced a serialized artifact larger than the original transport envelope. A larger envelope also exposed aggregate-output accounting. | A separate bounded artifact envelope leaves ordinary frames unchanged; compiler stdout and stderr share a total budget. See [Linux acceptance](evx-linux-acceptance.md). |
| Linux inherited authority | A privileged parent left workers able to raise their hard CPU limit. The file-helper allowlist also omitted the descriptor duplication its implementation requires. | Drop ambient, effective, permitted and inheritable capabilities before input; allow duplication of existing descriptors. Ordinary and privileged-parent native acceptance both pass. |
| Apple adapter lifecycle | Missing observations skipped termination escalation, failed observations could recover to live, and an interrupted wait abandoned child ownership. | Keep escalation independent of observation success, latch observation failure and retry interrupted waits. Three native lifecycle regressions passed after reproducing their failures. The production App Store profile remains disabled. |
| Request lifetime | Disconnecting a caller released its xite lease while the blocking worker remained active. A replacement could hide the first broker from revocation; an aborted manual job could remain unfinished. | An owned completion task retains the lease through worker cleanup and durable completion. Broker removal checks registration identity. Real-worker abort, revocation and completion regressions pass. |
| Service shutdown | Detached work could continue after shutdown, and queued work could miss a disable/re-enable transition. | Shutdown fences admission and revokes live brokers. Capture the plugin epoch before queueing. Real-worker shutdown and queued-policy regressions pass. |
| Terminal resources | A native peer could exceed its memory budget between live samples, release the allocation and return success despite a known terminal peak. Recovery could accept the same violation. Linux terminal RSS also includes inherited pre-exec parent memory. | Enforce attributable terminal observations before accepting success or recovery. Darwin keeps terminal RSS; Linux uses post-exec samples without charging inherited parent peaks. macOS transient-allocation and both platforms' attribution regressions pass. |
| Apple admission replay | A caller retaining a valid proof could start a second worker on the same XPC connection after the first had been reaped. No guest access to host proof authority was established. | Consume admission once per connection. A real signed, sandboxed service accepted the replay before the fix and explicitly rejected it afterward while preserving the first run. |
| Direct-worker restart | An effect-free native helper substitute released descriptor 3 and survived host termination. A new node service on the same state successfully ran the xite while that helper remained alive. This models a compromised same-xite helper, not a Wasm escape. | A durable host-private journal now covers compilation, execution and recovery. Only an owned terminal reap completes an invocation; unresolved state refuses execution after restart. The node crash regression passes after reproducing the original failure. Legacy roots retain inspection and receive a durable reboot barrier. Later kernel-boot recovery preserves file uncertainty; see the direct lifecycle contract. |
| Direct wait ownership | Interrupted or unknown waits, and a positive PID with a stopped status, could be treated as completion. | Only an owned exited/signalled child completes the durable record. Interrupted or stopped waits retain ownership; unknown ownership quarantines admission and prevents further PID sampling/signalling. Deterministic before/after regressions pass. |
| Apple terminal status | The trusted service could treat a stopped status as a child reap. | Require an exited/signalled status before completion. The deterministic regression failed before the fix and passes afterward; all seven native lifecycle tests and nine signed backend cases pass. |
| Journal lock contention | A temporarily held lifecycle lock immediately refused an otherwise valid operation. | Retry only lock contention for at most one second; never clear records or bypass identity/session validation. A bounded held-lock regression failed before the fix and passes afterward. |

Wasmtime was updated from 48.0.3 to exactly pinned 48.0.5, including its compiled
artifact identity. RustSec flagged RUSTSEC-2026-0325, RUSTSEC-2026-0326 and
RUSTSEC-2026-0327 in the old release. The affected exception, GC and component
features are disabled in EVX, but the patched release removes reliance on that
reachability argument. The final runtime fuzz campaign uses the production pin.

The execution marker deliberately errs on the side of reconciliation. A crash
after marking admission but before process startup can pause a job that made
no changes. This is preferable to automatically repeating an uncertain file
effect. Completed history is an inspection view; pruning it must never erase
replay or reconciliation authority.

The new Linux profile requires Landlock ABI 3 because earlier ABIs do not
mediate truncation. A disposable Debian 13 ARM64 VM subsequently verified
positive confinement on kernel 6.12.111 with Landlock ABI 6, including a
packaged worker under ordinary and privileged parents. The unavailable-kernel
refusal test remains required. See [Linux acceptance](evx-linux-acceptance.md).

Schema 9 migrations preserve surviving records and mark older incomplete
executions as uncertain. They cannot reconstruct guards already erased by an
older build before upgrade. A durable management revision now prevents a slow
recovery from clearing a newer operator pause, including a repeated pause with
the same reason. The comparison and resume happen in one SQLite transaction.

## Verification

The later platform and provenance pass completed 501 native Linux tests and
117 Pulley tests, with strict Clippy and 14 native probes. The affected macOS
workspace, supervisor and host suites passed 97 tests. The Unicode fix then
passed all 20 API/runtime unit tests and the artifact-safety compile-fail
doctest. These are separate snapshots and overlapping suites, not additive
coverage totals. Apple end-to-end platform acceptance remains incomplete.

The subsequent recovery integration passed 153 state tests (plus one
intentionally ignored crash helper), 90 node service tests, 69 supervisor
tests including 16 provenance regressions, 24 file-manager tests, four dispatcher
tests and 34 wrapper JavaScript tests on macOS. Scoped all-target Clippy passed
with `--no-deps`; the full dependency check still reports seven existing
`epix-blob` lints. Root symlinks, failed reconciliation, cancellation,
replacement consent and a newer operator pause have dedicated regressions.
The 2026-10-04 Linux snapshot, including cancellation-safe completion,
terminal-memory attribution and the portable slot registry, passed 539 native
tests, 137 Pulley tests, scoped strict Clippy and ordinary/privileged worker
acceptance. These counts supersede the earlier 524/122 snapshot, without
covering later Apple integration edits. The aligned five-target fuzz campaign completed 6,466,701 executions
without a reported crash, sanitizer failure or invariant failure. Its frozen
source, logs, corpus archives and hashes are retained. See the
[aligned record](../fuzz/results/2026-10-03-aligned/manifest.json).

The final portable snapshot passed 556 native Linux tests, 151 Pulley tests,
strict scoped Clippy, native confinement under ordinary and privileged parents,
and nine package tests. The final macOS supervisor suite passed 102 tests
(one intentionally ignored subprocess entry); node suites passed 100 default
and 103 Apple-feature tests. A signed App Sandbox node fixture also passed
consent refusal, manual execution, pending-file reconciliation, scheduling and
revocation with no direct workspace. The source scope secret scan passed with the
repository configuration, which excludes documented fixture paths. These
results are overlapping suites, not additive coverage. See the frozen
[Linux source record](evx-linux-acceptance.md#final-direct-lifecycle-snapshot).

The combined macOS run passed 468 tests with one intentionally ignored
crash-driver helper. The selected UI Rust integrations passed 65 tests; all
93 JavaScript tests, 13 macOS package tests and 9 Linux EVX package tests passed.
The full desktop Pulley profile passed 86 tests through the real worker,
IPC, lifecycle and authenticated activation. All 11 product dependency guards
and the full native node check passed. The four bounded fuzz campaigns
completed 4,169,491 executions with no reported crash or invariant failure. See the campaign record for toolchain,
durations, versions, corpus hashes and coverage limitations.

Run the suites from [`evx.md`](evx.md). Fuzz targets, reproducible commands and
bounded campaign results live under [`../fuzz/`](../fuzz/). They cover strict
declaration/broker decoding, signed activation admission, the actual Wasm
profile validator, and production IPC framing and typed decoding. Sanitizer
fuzzing of these entry points does not prove OS
containment, compiler correctness or safe native side effects.

The UI regressions inspect actual router and WebSocket responses and execute
the production JavaScript in the Node harness. They do not constitute a full
multi-browser exploitation or usability audit. The package tests compile a
temporary inert executable and check real ad-hoc signatures and tampering.
The Linux EVX package tests use inert ELF fixtures and substitute external
packaging tools. The broader Linux desktop test suite could not complete on
macOS because `desktop-file-validate` and AppArmor are unavailable.
Both authenticated-host integration suites now run on Linux in CI. Their
previous macOS-only test gates silently omitted that platform. Test worker
builds now preserve the Pulley backend; the prior mismatch was reproduced
as an artifact-engine refusal before the helper fix.
The Windows guard proves dependency exclusion, not a full Windows product
build. Unsupported node targets have no EVX plugin or management commands.
Scoped strict Clippy checks passed for the runtime and node service; the full
dependency run still reports unrelated existing warnings in `epix-blob` and
`epix-browser-net`.

## Release gates

The remaining roadmap milestones are **not complete**. Do not infer completion
from a successful unit test, cross-build or signed package.

- Direct lifecycle: perform actual cross-reboot acceptance of the new kernel
  boot-bound migration/recovery path. Same-boot refusal, simulated boot
  transitions and data preservation tests pass; no user-machine reboot was run.
- macOS: validate actual Developer ID signing and the final browser package.
  Its production bootstrap and pool assembly now have signed node fixtures.
  App Store delivery still needs a compatible sandboxed outer host, verified
  provisioning, update/reinstall behavior and supported-version acceptance.
- iOS: implement and device-test the Pulley host, compiler containment,
  cancellation, memory bounds and interruption recovery. This review host has
  Command Line Tools but no iOS SDK.
- Linux: expand the passing ARM64 native acceptance to x86_64, the supported
  kernel range and full installed-package lifecycle tests.
- Windows and Android: execute the standalone isolation fixtures natively,
  then integrate confined compilation/execution, workspace and broker calls,
  durable lifecycle and platform scheduling. The current products exclude EVX.
- Hardening: extend fuzzing to IPC state machines and workspace races, run
  sustained campaigns, test each supported OS release, and obtain an external
  independent security audit. A separate internal reviewer checked the changes
  and found additional cases; that is not an external audit or certification.

[`evx-platforms.md`](evx-platforms.md) records the exact platform acceptance
work. Publication, streams, shared data, chain actions and the resource
dashboard remain outside this review's implementation scope.

The 2026-10-04 follow-up passed 208 combined macOS node/supervisor tests with
one intentionally ignored crash helper. The direct lifecycle migration suite
covers legacy state, same-boot quarantine and simulated boot transitions. A
scheduler test's early status snapshot failed before its observation was made
consistent; its concurrency assertions and the combined suite pass afterward.
Two bounded lifecycle-metadata sanitizer runs completed 13,828 executions.
See the [fuzz manifest](../fuzz/results/2026-10-04-lifecycle/manifest.json) for
the separate frozen source and limits. These results do not replace native
Windows/mobile acceptance or an external audit.

## Build cache cleanup

Removed the unused generated `target/aarch64-linux-android` cache (4.25 GiB)
and the completed `fuzz/target` build cache (2.28 GiB), reclaiming about
6.53 GiB. The later IPC fuzz campaign's temporary 332 MiB build cache was
also removed. Sources, fuzz seeds and results, user data, xite files and the active
debug build cache were retained.
The later disposable Linux acceptance VM was shut down and removed after
validation, reclaiming another 8.3 GiB. Its compact logs and source hashes
were retained outside the repository.

The final disposable Linux VM was shut down after preserving and hashing its
source snapshot and validation logs. Removing its disk and downloads reclaimed
20.09 GiB. Active repository build caches and user data were retained.
