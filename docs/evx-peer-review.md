# EVX peer review record

This internal code review covers the EVX changes from `94149a8` and the fixes
in the current working tree. It is not an external audit or a certification.
The runtime and state changes received a separate pass from their implementers.
The wrapper fixes also received a final source pass by a separate reviewer,
covering rendering contexts, substitution, CSS, WebSocket origins and expiry.
Fixtures used
temporary files, keys and processes, without live xites or private user data.

## Boundaries examined

- Publisher metadata and URLs entering trusted wrapper HTML, script and CSS;
  frame embedding; opaque/content origins; WebSocket wrapper authority;
  elevated request IDs; `ADMIN` and `as`; inert inspection and grant status.
- Current consent and limits reaching running brokers; queued admission;
  plugin disable; compiler cancellation; checkpoint persistence under the
  workspace lease; interrupted occurrences and publisher job updates.
- Bounded process input/output, descriptor inheritance, compiler limits,
  live Wasm limits, file-helper authority, and the Linux syscall/Landlock rules.
- Direct-child macOS package signatures and entitlements, with explicit
  separation from the unimplemented XPC distribution profile.

## Findings and regression status

| Finding | Fix and evidence |
| --- | --- |
| Publisher title text could inject a wrapper script, then template expansion supplied the real CSP nonce or wrapper secret. Decoded document paths could break out of script strings. | Context-specific HTML/JSON escaping and single-pass template substitution. Original HTTP response regressions failed; `wrapper_canonical_paths` now passes all 15 tests. This is response-level evidence, not a browser exploit demonstration. |
| Publisher background hints could add CSS declarations, and the consent wrapper could be framed. | Restrict background color syntax; add CSP `frame-ancestors 'none'` and `X-Frame-Options: DENY`. Both regressions failed before the fix and pass afterward, including path and host modes. |
| Another port on the same loopback host could acquire wrapper authority with a leaked wrapper key. | Compare the full host and port. `same_host_different_port_is_not_the_wrappers_origin` failed before the fix and passes using real local HTTP/WebSocket connections. |
| An expired stored grant appeared enabled in inspection and consent. | Effective status distinguishes expiry. Rust inspection and JavaScript consent regressions failed before the fix and pass afterward. |
| Consent replacement did not stop a broker with old authority; updating limits could restore a concurrently revoked grant. | Serialize policy propagation with broker registration and use an atomic limits-only state update. The service regressions pass. |
| Cancelling a manual request released its xite lock while its blocking worker remained active. A replacement hid the original broker from revocation, and a cancelled manual job left its admitted reservation unfinished. | Keep execution and durable completion in an owned task, share the owned lease with its blocking supervisor, and remove only the matching broker on every exit. Real-worker regressions reproduced the free lease, missed revocation and unfinished reservation before the fix. |
| The execution lease ended before the job result and reconciliation pause were durable; shutdown only stopped scheduler ticks. | Retain the lease through occurrence completion, revoke registered workers during shutdown and deny later admission/recovery. The completion-boundary and live shutdown regressions failed before the fixes. |
| Disabling an idle plugin did not wake the scheduler, and a queued request could start after disable. | Watch plugin changes, recheck enabled state after the run lock, and reject a changed captured epoch at registration/admission. Both regressions failed before the fix and pass afterward. |
| Admission could run before checkpoint persistence, or a stale host could overwrite a newer checkpoint. | Persist and compare the checkpoint while holding admission and the workspace lease. Persistence failure denies guest startup. The persistence and stale-floor regressions pass. |
| Recovery could replay an occurrence that had already changed its workspace. Publisher removal/re-addition could clear reconciliation or operator controls. | Persist execution admission; recover admitted work as `effect_unknown`; store reconciliation and operator controls outside declaration rows. Only explicit resume clears user/reconciliation pauses. Original removal, missing-row completion and automatic-update regressions failed; the revised state suite passes. |
| Blocking pipes, queued floods, inherited descriptors and compilation outside containment weakened process bounds. | Nonblocking bounded writes, bounded reader queues, explicit descriptor closure, confined text parsing and compiler resource checks. Supervisor and activation regression suites pass on macOS. |
| Darwin terminal RSS was recorded but an over-budget guest could return success, and a stopped recovery helper could clear pending provenance despite its known memory violation. Linux terminal RSS could also misattribute inherited parent memory to the worker. | Check attributable terminal usage before accepting guest success or recovery bytes. Native terminal RSS is retained only on Darwin; Linux uses post-exec samples and discloses unobserved short-lived peaks. Bounded native IPC fixtures reproduced both acceptance failures, then passed after the fix; compiler terminal enforcement also passes. These accounting fixtures do not establish sandbox containment. |
| Revocation did not cancel an active compiler; lowering Wasm fuel or memory left the old Store limits in force. | Poll trusted cancellation during compilation and cancel an invocation when either fixed Store limit decreases. `revocation_cancels_an_active_compiler` and both branches of `lowering_active_guest_memory_or_fuel_cancels_computation` failed before the fix and pass afterward. |
| A read request launched a native helper with workspace write authority. The commit protocol also accepted a read request. | The supervisor selects a separate `file-read` mode before parsing input and requires an authorized write for commit. `read_helper_has_no_native_write_authority` created a fixture file before the fix and now verifies native denial on macOS. The read-helper commit refusal regression also failed before the fix and passes afterward. |
| Linux `fcntl` could direct asynchronous pipe signals at another process despite the signal syscall restrictions. ABI 1 also lacked truncation control. | Allowlist descriptor operations and forbid `O_ASYNC`; require Landlock ABI 3 and handle truncation. The actual seccomp policy failed then passed `fcntl_cannot_signal_another_process` in a disposable aarch64 Linux process. Missing-Landlock refusal also passed. Subsequent native acceptance passed on ARM64 with Landlock ABI 6; see [Linux evidence](evx-linux-acceptance.md). Other supported kernels and architectures retain their own release gates. |
| Helper events carried only a role, so delayed frames or EOF from a timed-out helper could be attributed to its replacement. | Bind reader events to a unique process-instance ID and validate it before protocol errors, accounting or dispatch. Three deterministic regressions inject retired-helper results, commit requests and protocol errors; all failed before the fix and pass afterward. |
| A helper removed from tracked peers before failed timeout cleanup escaped the final quarantine decision. Initial helper input also had a fallible send before registration. | Retain ownership before fallible input or cleanup; latch quarantine and retain the workspace lease on unconfirmed termination. Both cleanup-failure regressions failed before the fix and pass afterward, including preservation of an uncertain write outcome. |
| Group-only signaling failed to reap a hostile child that moved to another process group. | Signal both the group and the still-owned, unreaped child PID. A synthetic unsandboxed peer reproduced the cleanup failure and now gets reaped. This test does not establish whether Seatbelt permits a confined process to change groups. |
| A quarantined run can also have an unknown write outcome, but job completion checked only the status enum. | Preserve the trusted unknown-effect flag and require durable reconciliation for quarantine, including a revoked grant's completion fallback and retained-result migration. Both node regressions failed before the fix and pass afterward; the state regressions pass too. |
| Unconfirmed compiler termination became an ordinary refusal, while local workspace quarantine did not stop new workers for another xite. | Preserve typed quarantine and irreversibly stop child admission within the host process. One mutex orders all compiler, guest and helper spawns against that latch. Three isolated subprocess regressions failed before the fix and now confirm that compiler/helper cleanup uncertainty blocks later compiler and guest admission across brokers. |
| Linux release builds and packages omitted the adjacent EVX worker. | Build and stage the worker, include it in native/AppImage contents, validate its file type, mode and architecture, and check installed/extracted packages. Seven offline regressions failed before the fix; all nine package tests now pass. |
| Interpreter integration helpers rebuilt a native worker, mixing artifact backends. | Forward the selected Pulley feature to nested worker builds. The real calculation test failed with an artifact engine mismatch before the fix. The full desktop interpreter worker/IPC/activation run now passes 86 tests. |
| Windows products selected the Unix-only EVX runtime and failed to compile its workspace dependency. | Gate the node dependency and plugin registration to macOS/Linux. The Windows graph guard and an actual `evx-workspace` Windows cross-check failed before the fix. All 11 product/target graph checks and the native node check pass afterward. This does not establish a complete Windows product build. |

The Linux signal path follows the documented
[pipe asynchronous-I/O behavior](https://www.man7.org/linux/man-pages/man7/pipe.7.html)
and [descriptor signal ownership](https://man7.org/linux/man-pages/man2/F_SETSIG.2const.html).
The [kernel Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
explains why write permission alone does not constrain `O_RDONLY | O_TRUNC`.

## Reproduction and evidence limits

The wrapper checks passed 55 selected HTTP/inspection tests, 10 local
HTTP/WebSocket integration tests, 6 targeted dispatcher/CSP unit tests and
89 JavaScript wrapper tests:

```sh
cargo test -p epix-ui --test wrapper_canonical_paths --test routes_polish --test file_manager --test ui_security
cargo test -p epix-ui --test integration
cargo test -p epix-ui --lib evx
cargo test -p epix-ui --lib csp_tests
node --test ui/tests/wrapper-evx.test.cjs ui/tests/wrapper-permissions.test.cjs ui/tests/wrapper-navigation.test.cjs ui/tests/canonical-domain.test.cjs ui/tests/loading-progress.test.cjs
python3 packaging/macos/test-evx-package.py
python3 packaging/linux/test-evx-package.py
python3 scripts/check-evx-platforms.py
cargo test -p evx-api -p evx-runtime -p evx-worker -p evx-supervisor -p evx-host --features evx-runtime/pulley --locked
```

The macOS package suite passed 13 tests, including a real ad-hoc signed inert
executable and rejection after tampering. It does not launch that executable
as an EVX worker. The Linux package suite passed nine offline fixture tests;
native/AppImage external tools were substituted and no Linux code executed.
The reviewed node unit run passed 41 tests; the state run
passed 150 tests with one intentionally ignored crash-driver helper. The
runtime-owner run passed 79 tests across its six crates, followed by a
supervisor run with 44 passing tests after the lifecycle fixes. These are scoped
results, not a claim that every repository or platform test passed.

The IPC fuzz target received a separate source review of its production framing
code, six typed message directions, partial/interrupted reads and round-trip
invariants. Its retained corpus archive matches the recorded count and digest.
See [fuzz evidence](../fuzz/README.md); this covers decoding and framing, not the
supervisor lifecycle or OS containment.

The helper lifecycle tests deliberately inject delayed events and an
unconfirmed cleanup result around real fixture children. They exercise the
supervisor's accounting and authority checks without claiming to reproduce
an unkillable OS process or a spontaneous scheduling race.

The process-wide admission latch has no reset API. Host restart clears
in-process state but does not prove that an old orphan exited. Recovery after
real cleanup uncertainty still requires OS-level confirmation that earlier
children have stopped; this latch is not a persistent process registry.

The subsequent plugin-interruption accounting change passed source review
and the final native aggregate: 468 EVX tests passed, with one intentionally
ignored crash-driver helper. The active-guest regression waits for a real
effect-free broker call before disabling execution. The policy,
admission, checkpoint, compiler-cancellation, live-limit, read-helper and
`fcntl` fixes, helper lifecycle and process-wide admission latch passed the
separate source review, subject to the evidence
limits here. That earlier Linux syscall test used a kernel without Landlock.
Subsequent native acceptance verified the combined boundary on Debian 13 ARM64
with Landlock ABI 6: 501 native tests and 117 Pulley tests passed. See
[the exact snapshot and platform limits](evx-linux-acceptance.md).

The later runtime review reproduced a UTF-8 truncation panic from a Wasm
function name and the same defect in broker error formatting. Both regressions
failed before the fix and pass afterward. The runtime regression also passes
under Pulley.
The final cancellation pass reproduced missed revocation after request abort,
lost manual-job completion, early lease release before occurrence persistence,
and shutdown leaving a live guest enabled. Its final macOS service suite passes
55 unit tests and 41 integration tests, including actual worker admission and
cleanup. A separate source pass checked the owned completion, policy epoch and
lease transfer. A queued disable/re-enable regression also caught and corrected
an epoch-capture regression during the refactor. An unexpected panic of the
completion task still relies on the durable admission marker and restart
recovery; these checks do not claim panic-proof journaling.
The state-sequence target also gained checks for the other xite's jobs and
consent, beyond its original journal snapshot. Its final campaign remains
outstanding after that change and dependency alignment.

The Apple source pass reviewed `crates/evx-supervisor/native/apple_xpc.c`,
`src/apple.rs` in that crate, inherited modes in `crates/evx-worker/src/`, and
the fixtures under `packaging/macos/xpc/`. Five independently rerun native
lifecycle regressions passed: failed observations stay failed, stale samples
are refused, missing measurements do not prevent termination escalation,
interrupted waits retry, and unsafe executable paths refuse. A separate native
resolver fixture verified that changing `HOME` does not change the account-based
authority location, and invalid identifiers or truncated outputs refuse.

The later idle-service change also passed a separate source review and all six
native lifecycle cases. A live or uncertain child blocks idle exit, a reaped
child still blocks until invocation cleanup, and a new connection invalidates
the old timer epoch. Pending listener callbacks count toward the eight-connection
bound before they reach the main queue. This rerun checks the deterministic
guards, not the elapsed-time behavior of a real XPC service.

A disposable signed service reproduced reuse of one valid authority proof on
the same connection after the first worker was reaped. The per-connection
consumed flag now rejects that second start; the independent reproduction
passed after rebuilding the service. This requires a caller already holding a
valid proof. It does not establish that a guest can obtain host authority.
`backend-admission.c` and `test-backend.py` retain the regression. The disposable
worker was an effect-free native executable, so this check proves admission
behavior rather than Wasm containment.

The follow-up source review covered `src/apple_workspace.rs`, the control-root
binding in `src/apple_slots.rs`, broker/backend admission checks and the
`ApplePeer` journal hooks. The possible-invocation record is durable before
native admission; only a trusted reaped observation completes its exact
session/role/invocation. Independent reruns passed 16 library tests, 15 slot
tests and strict feature Clippy. The ignored subprocess fixture is exercised
by the cross-process slot test. Journal cases cover dropped tokens, unresolved
reopen, stale completion, failed start durability, replaced/missing controls,
corrupt metadata and mismatched service or xite bindings.

An independent rerun of all eight signed backend tests also passed, including
file round trips, separate slot contents, uncertain-write reconciliation,
cancellation and the admission-proof regressions. In the host-death test,
`examples/apple_xpc_host.rs` exits after a real file helper reports staged
contents and before commit authorization; a new host process must refuse the
slot as quarantined. This proves persistent refusal, not that an orphan died.
The tests do not inject physical power loss or every possible crash instant,
establish rollback resistance, prove full native container isolation or replace
release packaging and external review. A compiling adapter is not end-to-end
platform acceptance.

This peer pass predates the final node backend and direct-worker lifecycle
journal. Later development transport and containment tests, node integration
and the aligned fuzz campaign are recorded in [implementation review](evx-review.md).
The final peer-review continuation did not complete. Release gates still
include the supported Linux kernel/package matrix, production signing and
App Store assembly, iOS implementation and device acceptance, sustained
fuzzing of the remaining boundaries, and external independent review. Sampled
RSS is still detection, not a hard native-allocation ceiling. See
[platform acceptance](evx-platforms.md) for the specific unresolved checks.
