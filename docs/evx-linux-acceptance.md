# Linux EVX execution acceptance

On 2026-10-03, a disposable Debian 13 ARM64 VM executed the EVX runtime,
worker, supervisor, authenticated activation, durable state and node service
suites. This supplies positive kernel enforcement evidence in addition to the
previous unsupported-Landlock refusal checks.

## Environment and scope

- Linux `6.12.111+deb13-arm64`, Landlock ABI 6, actual page size 4096 bytes.
- The full suites ran as an ordinary user, UID 1000. A separate sacrificial
  privileged-parent probe checked inherited capability removal.
- Rust 1.99.0 and the locked Wasmtime 48.0.5 dependency.
- Apple Virtualization through vfkit 0.6.4, 3 virtual CPUs and 5 GiB RAM.
- Only disposable signed game fixtures and workspace files were used. No real
  xites, keys, wallet data, chain calls or production services were used.

The vfkit binary SHA-256 was checked against the official GitHub release:
`0ed83fc8ca7aa708598835480dba1362406aa7cd1dab3b27464eb76327d9652d`.
The official Debian `debian-13-generic-arm64.tar.xz` image SHA-512 was checked
against Debian's published checksum file:
`cb80554bf05aa9eb42d0b99a9a395fefad04edc8435514c5387e32f4da83b7827c34809f6249b365dedacd3f0688580f2957fd13b388639c987058bbe127fa8d`.
These download checks establish the selected artifacts, not an independent
security audit of those dependencies.

## Reproduced failures and fixes

| Reproduction | Failure before the fix | Verified behavior after the fix |
| --- | --- | --- |
| Tiny authorized computation | A 50-byte Wasm module produced a 132,880-byte artifact. Its 177,176-byte base64 payload exceeded the ordinary 128 KiB envelope, so every such Linux ARM64 guest failed compilation. | Artifact-only 256 KiB envelopes permit the compiler reply and first guest initialization. Ordinary source, guest and helper messages remain capped at 128 KiB. The real confined guest returns 42. |
| Private workspace roundtrip | Every authorized write failed with `workspace descriptor`: seccomp denied the `dup` syscall used by descriptor-relative traversal. | Allowing duplication of already admitted descriptors enables the existing write/read roundtrip without opening any new path authority. |
| Combined compiler output | A synthetic compiler returning a 177 KiB artifact and 128 KiB diagnostics was accepted because each pipe was counted separately. | Combined stdout and stderr exceeding 256 KiB fails with `compiler output quota`, with the child reaped. |
| Home-directory native probe | With HOME cleared, the probe used `/Users` on Linux and failed with ENOENT rather than establishing sandbox denial. | The Linux probe uses `/home` and requires policy denial. The harness also verifies every expected probe ran and protected fixture contents were unchanged. |
| Reconciliation helper shutdown | A real helper closed both pipes before the kernel reported its exit, causing a valid reconciliation to fail with `workspace reconciliation channel closed`. | EOF with both readers closed waits for confirmed exit, while continuing deadline, CPU and memory checks. A controlled close-then-delay fixture and the full recovery suite pass. |
| Privileged parent | A worker launched with `CAP_SYS_RESOURCE` raised its hard CPU limit from 3 to 4 seconds after installing confinement. | The worker clears ambient, effective, permitted and inheritable capabilities before input, then applies Landlock and seccomp. Both a privileged parent and an ordinary user now observe denial. |

Wasmtime deliberately aligns non-macOS Aarch64 artifact sections to 64 KiB,
even on a 4 KiB-page host. This is an upstream portability property, not an
EVX memory-grant adjustment. No engine protection was weakened to shrink the
artifact. Directional framing tests cover normal frames, exact artifact cap,
one byte over, compiler reply type, first guest initialization, and aggregate
output limits.

## Executed gates

The final ten-crate native run passed 501 tests, with one intentionally ignored
crash-test helper. It includes all 14 workspace-provenance integration cases:
concurrent namespace replacement, durable read authority, interrupted writes,
explicit reconciliation, and cancellation or transport failure after authorization.

```sh
EVX_REQUIRE_LINUX_CONFINEMENT=1 cargo test \
  -p evx-api -p evx-declaration -p evx-runtime -p evx-workspace \
  -p evx-activation -p evx-state -p evx-worker -p evx-supervisor \
  -p evx-host -p epix-evx --locked
```

The six runtime-owned crates also passed native Linux Clippy with all targets
and warnings denied. The kernel tests cover file and symlink boundaries,
read-only truncation, network and subprocess denial, process resource limits,
revocation, helper commit uncertainty, cleanup, hostile frames and compiler
cancellation. Missing-Landlock refusal remains a separate required test; the
positive ABI 6 run does not exercise the missing-module branch.

The final Pulley worker, IPC, provenance and authenticated activation profile
passed 117 tests on the same kernel:

```sh
EVX_REQUIRE_LINUX_CONFINEMENT=1 cargo test \
  -p evx-api -p evx-runtime -p evx-worker -p evx-supervisor -p evx-host \
  --features evx-runtime/pulley --locked
```

`packaging/linux/verify-evx-worker.py` passed against debug and optimized release
workers. It runs 14 native authority probes and sends a tiny module through the
real confined compiler and guest. It accepts a path to an installed or extracted
worker and fails when positive confinement cannot be established. Linux CI runs
it against the worker produced by the complete EVX test suite.

The tested release worker SHA-256 after capability removal was:
`571d082efdbc16b3ef9b9724f91dbc1b96e001dc668ea8f12e65bb412914db98`.
The executable came from `cargo build -p evx-worker --release --locked`. This
was not a complete Firefox desktop package build or install test.

The root fixture verified that its parent held `CAP_SYS_RESOURCE` before
launch. CI repeats that condition with `--require-privileged-parent`; a parent
without that capability cannot produce a false passing regression. Capability
removal matters because [`no_new_privs`](https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html)
does not remove existing rights, and [`CAP_SYS_RESOURCE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)
allows hard resource limits to be raised. The seccomp policy forbids capability
changes, identity changes and exec after the drop.

The disposable VM was shut down and removed after validation, recovering
8.3 GiB. The pre-existing Docker and VM state was unchanged; only the new
fixture VM and its downloads were removed. Test logs and source hashes were
retained separately.

## Later integration snapshot

The 2026-10-04 integration snapshot passed 539 native tests (two intentionally
ignored subprocess drivers), 137 Pulley tests (one subprocess driver), scoped
all-target Clippy with warnings denied, and nine package tests. Both ordinary
and privileged-parent worker acceptance repeated all 14 native probes and the
real compiler/guest computation. This run includes cancellation-safe request
completion, schema 9 recovery, terminal-resource attribution and the portable
Apple slot-registry tests. The Apple XPC implementation itself is not exercised
on Linux.

The same Debian kernel and Rust version ran in a separate disposable VM with
two CPUs and 4 GiB RAM. The complete 844-file source archive SHA-256 is
`34901bf499f9f1d53a05872cd2fddcf4790448f04890222cc53ba95bec2c698f`;
its source manifest SHA-256 is
`2ef707e200b7a2562f168d79566006b50a58b8efd6c269557400c9f0b66cc3da`.
Commands, individual log hashes, timing and exit statuses are retained with
the snapshot. Later Apple integration edits need their own validation.

An initial setup attempt reused a stale Cargo library because deterministic
archive timestamps preceded the existing build cache. Its output is retained
and marked invalid. Refreshing all extracted source timestamps forced the
build used for the successful run; source bytes were checked against the
manifest before execution.

Linux `wait4` peak RSS can include memory inherited from the parent before
exec. A disposable reproduction measured approximately 8 MiB for a tiny child
without a large parent allocation and 136 MiB after the parent touched 128 MiB.
The supervisor therefore uses post-exec procfs RSS samples. The platform
regression verifies that it does not attribute the inherited terminal peak to
the worker. Short-lived peaks can escape sampling; these observations are not
a kernel-enforced native memory ceiling.

## Coverage limits

Positive execution was on one ARM64 kernel. The required x86_64 Linux CI gate
and broader supported-kernel/package matrix still need their own recorded runs.
The desktop package compatibility matrix does not imply EVX availability on an
older kernel. Unsupported confinement continues to fail closed.

Kernel tests and internal review are evidence about the tested conditions.
They do not establish the absence of all sandbox vulnerabilities or replace an
independent external security review.

## Final direct-lifecycle snapshot

The later 2026-10-04 run includes the durable direct-worker journal, terminal
wait ownership checks and final portable node integration. All 556 native
tests and 151 Pulley tests passed, with two and one intentionally ignored
subprocess entry points respectively. Strict scoped Clippy, ordinary and
privileged-parent native worker acceptance, and nine package tests passed.
The same Debian 13 ARM64 guest used kernel 6.12.111 and Landlock ABI 6.

The frozen archive contains 858 files. Archive SHA-256:
`e6409aa71c3273c20e01b5618fad366bab58a75aa681e2024a0369c7f727be89`.
Source manifest SHA-256:
`77aa5380e19dae9f1b3bcf92962052d2472fab1ec9c79fbafaa25f38b0a31fd7`.
Commands, log hashes and durations are retained in `linux-final/final-manifest.json`
in the local validation evidence. This supersedes the portable runtime evidence
above. Later Apple-only fixture and documentation changes are outside this
Linux run. No x86_64, additional kernel or full desktop installation acceptance
is implied.

## Continuing platform matrix

`.github/workflows/evx-platforms.yml` runs native and Pulley suites on
`ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm`, then checks the actual worker
under ordinary and privileged parents and runs the package tests. Missing
Landlock support fails the acceptance job. `scripts/evx-platform-acceptance.py`
retains exact commands, kernel/architecture, source hashes, logs, return codes
and incomplete status after failure or timeout. Its four runner regressions
pass locally. Adding this workflow is not evidence that its remote jobs ran.

The later boot-session migration compiles for aarch64 Linux from this macOS
host. That cross-check is not a new native Linux execution or reboot test.
The earlier frozen Linux results remain tied to their stated source.
