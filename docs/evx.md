# EVX: sandboxed execution for xite programs

EVX (Epix Virtual eXecution) runs untrusted WebAssembly programs published by
xites on the user's own machine, inside the EpixNet application, with access
only to explicitly granted capabilities. This document describes the runtime
as implemented in the `evx-*` crates. The product plan, security review and
prior-art research live outside this repository in the planning documents;
this page is the engineering reference for what exists in the tree.

Status: milestones 1 through 3 received an end-to-end implementation review.
The review fixes, regression evidence and release gates are tracked in
[`evx-review.md`](evx-review.md). Platform acceptance is tracked in
[`evx-platforms.md`](evx-platforms.md).
The candidate evidence checklist and source handoff procedure are in
[`evx-release-review.md`](evx-release-review.md).

A signed declaration is inspected inertly, granted through trusted wrapper
consent or the operator socket, and run once or on a durable background
schedule. macOS uses a confined child. Linux adds Landlock plus seccomp and
refuses execution when required confinement is unavailable. Pulley is tested
as an interpreter backend. A separate macOS Developer ID package can select
the signed XPC backend; App Store and mobile product integration remain open.
Windows and Android fixtures do not enable product execution. No mobile OS
wake, publication or chain operations are added.
An external independent security review remains a release gate.
Compiler-free Pulley and mobile limits are described in
[`evx-mobile.md`](evx-mobile.md). Workspace read provenance and explicit
recovery are described in [`evx-workspace-provenance.md`](evx-workspace-provenance.md).

## Crates

| Crate | Role | Trust |
| --- | --- | --- |
| `evx-api` | Shared types: closed capability set, limits, grants, IPC frames, strict JSON decoding, path and identifier validation. No I/O. | Dependency leaf |
| `evx-runtime` | Wasm feature profile, structural validator, Wasmtime engine configuration, precompilation, execution with fuel, epoch deadline and store limits. | Trusted code, hostile input |
| `evx-workspace` | Descriptor-relative workspace file operations: link-refusing reads, staged writes with a commit step, quota accounting. | Trusted code, used inside the confined helper |
| `evx-worker` | The confined binary. Modes `run`, `compile`, `file`, `file-read` and a harness-only `probe`. Confines itself before reading any input. | Untrusted after a guest starts |
| `evx-supervisor` | Broker, workspace lease, child processes, kernel resource observations, commit authorization, effect-outcome semantics. | Trusted |
| `evx-activation` | Ed25519-signed activation envelopes, immutable closure capture, two-phase admission, shared-source record verification. | Trusted |
| `evx-state` | SQLite durable model: grants with separate authority and limits generations, cumulative budgets, idempotent occurrences, atomic checkpoint plus outbox, mock destination. | Trusted |
| `evx-host` | Binds activation to the supervisor; JSON-on-stdin CLI for harnesses. | Trusted |
| `evx-declaration` | Strict parser and manifest binder for the signed `evx` section of a root `content.json`: programs, jobs, capability requests, limits; unsupported items disable only the affected work. | Dependency leaf, hostile input |
| `epix-evx` | The node's EVX plugin: grant store and workspaces under `private/evx/`, the `evx*` WebSocket commands (inspect, status, request, grant, revoke, limits, run once) and the activation of a xite's declared program through `evx-host`. | Trusted |
| `evx-windows` | Windows LPAC/Job Object worker and real Wasm compilation/execution adapter. Native acceptance and node/workspace integration remain pending. | Platform work in progress |
| `evx-android` | Pulley execution and JNI bridge for a separate Android isolated service. Native accounting, lifecycle acceptance and product integration remain pending. | Platform work in progress |

Signed envelope verification also accepts a host-selected bounded reader through
`ActivationLoader::verify_reader`. Signature, identity, capability, version and
closure checks precede every read. Per-file and aggregate limits apply to the
returned bytes. The existing Unix descriptor reader remains available; other
platform hosts must provide their own confined source. Both this envelope path
and the node's signed-content path compile without Unix filesystem dependencies.

## Execution boundary

```text
EpixNet node (epix-evx plugin)
  -> read the xite's root content.json bytes; require the owner's signature and a complete core
  -> evx-declaration: parse the evx section strictly, bind entry + dependencies to the manifest hashes
  -> consent: the wrapper's dialog (Enable / Allow once / Deny) or the operator socket; a page can only ask
  -> evx-state: persistent xite grant (capabilities, profiles, limits, generations), allow-once tokens, run history
  -> evx-host: verify the content activation, capture closure, check binding against grant
  -> evx-supervisor: compile in a confined child, lease workspace, persist admission and version floor
       -> evx-worker run      (no filesystem, no network, no fork/exec; Wasmtime, fuel, epoch, store limits)
            evx.call -------> supervisor authorizes request under grant generation
       -> evx-worker file-read (read-only workspace authority)
       -> evx-worker file      (staged write; commit needs supervisor ack)
  -> reap children, release lease, report RunResult
```

Three layers hold the guest:

1. **Wasm profile.** MVP plus mutable globals, sign extension, saturating
   conversions, multi-value and bulk memory. SIMD, reference types, GC,
   exceptions, tail calls, threads, memory64, multi-memory and the component
   model are disabled at both the validator and the engine. The single import
   is `evx.call(i32,i32,i32,i32) -> i32`. Required exports are `run` and
   `memory`. Start functions and declared memory maxima are refused.
2. **Authority.** Every broker request is decoded strictly (duplicate keys,
   non-finite numbers and extra fields are refused), checked against the
   grant's capabilities and the activation's declared capabilities, and
   re-checked under the grant generation at the file commit boundary. A
   limits change during a helper's lifetime denies that commit.
3. **OS confinement.** On macOS the worker applies a deny-default Seatbelt profile to
   itself through `sandbox_init` before reading its first frame: no network,
   no fork or exec, no Mach lookups, no executable file mappings, read access
   to system libraries and its own binary only, plus one workspace directory
   for the file helper. Hard `RLIMIT_CPU`, `RLIMIT_NOFILE` and `RLIMIT_CORE`
   apply on top. The supervisor samples CPU and RSS from the kernel and kills
   on deadline; it never trusts a worker's own measurements. Linux uses
   Landlock ABI 3 filesystem rules and a seccomp syscall allowlist, installed before
   input. Unsupported kernels fail closed. Child launch seals inherited
   descriptors except the protocol streams and the explicit workspace lease.

## Effect semantics

A write is staged by the file helper as `.pending-<random>`, synced, then the
helper reports `prepared`. The supervisor re-authorizes the original request,
checks the limits generation and the deadlines, and only then sends `commit`.
Any failure after that point yields `effect_unknown`: the file may have
changed and the caller must reconcile before retrying. A helper that blocks is
killed at the native-call deadline without stalling the supervisor. The
workspace lease is an `flock` on the directory descriptor; the helper inherits
it, so a supervisor crash leaves the lease with the helper until the helper is
stopped.

Before authorizing a write, the host durably records its content digest outside
the workspace. Read responses must match an authorized digest before any bytes
reach the guest or response history. This protects against file substitution
that link-count checks alone cannot exclude. An uncertain write retains the
previous and pending digests until explicit host reconciliation. Existing
unregistered files are preserved but not automatically trusted.

Scheduled admission also persists an `execution_started` marker before the
worker starts. After a crash, only reservations that never reached admission
may run in their still-current slot. Admitted reservations close as
`effect_unknown` and require explicit reconciliation before the job resumes.
This is conservative: a crash just before spawning can also require review.
It avoids claiming exactly-once execution for non-transactional file writes.
Completed rows may be pruned, but replay and reconciliation guards survive
publisher removal and re-registration of a job. Limits updates modify limits
atomically and never restore a revoked grant.

## Fixes carried from the proof of concept review

- A denied signed update no longer advances the version floor: `verify` is
  separate from `admit`, and compilation happens between them.
- Durable budgets have separate authority and limits generations. Current
  process limits are enforced live; reducing fixed Wasm memory or fuel limits
  cancels the invocation so it cannot continue under the old store limits.
- Workspace paths reject `..`-prefixed components (covering macOS named forks),
  control and format characters, and the staging prefix.
- The sandbox profile no longer grants the whole interpreter tree; it names the
  system library roots, the binary and the workspace.

## Tests

The suites cover strict parsers, restricted Wasm features, signatures,
workspace containment, hostile IPC, live revocation and limits, durable
recovery, management authority, and the node's real worker path. Current
executed counts and boundaries are in the review report; a test count alone
is not a security guarantee.

```sh
cargo test -p evx-api -p evx-declaration -p evx-runtime -p evx-workspace \
  -p evx-activation -p evx-state -p evx-worker -p evx-supervisor \
  -p evx-host -p epix-evx --locked
cargo test -p evx-runtime --features pulley --locked
python3 packaging/macos/test-evx-package.py
```

The supervisor and host integration tests build and launch the real
`evx-worker` binary and the `hostile_peer` example themselves.

The supervisor and host integration tests run on macOS and Linux. Linux
acceptance requires `EVX_REQUIRE_LINUX_CONFINEMENT=1` and a kernel with
Landlock ABI 3 or newer. The refusal test also runs on kernels without it. Interpreter tests
on a desktop do not establish iOS device support.

## Known limits and remaining milestones

- Ordinary IPC JSON bodies are capped at 131,072 bytes. Compiler artifact
  replies and the initial guest frame have a separate 262,144-byte ceiling.
  Base64 and envelope overhead leave source inputs below 96 KiB and compiled
  artifacts below 192 KiB. Compiler stdout and stderr together are capped at
  262,144 bytes. The validator's 1 MiB module ceiling is
  a structural bound, not a promise that a module fits this transport.
  Oversized compiler inputs and guest initialization frames fail before
  the corresponding child is spawned. Larger programs need a separately
  bounded transport design and resource tests.
- Direct node execution now requires a durable host lifecycle journal. Legacy
  nonempty roots without it receive a reboot barrier and remain inspectable.
  A verified OS boot change permits process recovery while preserving uncertain
  workspace effects. Corrupt metadata remains refused; see
  [`evx-direct-lifecycle.md`](evx-direct-lifecycle.md).
- The Apple XPC adapter now exercises authentication, execution, file effects,
  termination, accounting and restart quarantine in signed development bundles.
  A trusted opt-in development node assembly also tests consent, manual runs,
  scheduling, file recovery and revocation through that backend.
  The Developer ID node bootstrap and package assembly now have signed fixture
  coverage, including installation under `/Applications`. Actual release signing
  and version/device acceptance remain required. App Store packaging still needs
  a compatible outer host and separate acceptance; see
  [`evx-platforms.md`](evx-platforms.md).
- Pulley removes executable-code generation at execution time. Its compiler
  still needs containment, and iOS needs a device-tested host, interruption
  handling and explicit memory policy. The Windows LPAC/Job Object worker and
  Android isolated-service runtime adapter have no product admission path.
  Native platform acceptance and runtime/broker integration remain required;
  see [`evx-windows.md`](evx-windows.md) and [`evx-android.md`](evx-android.md).
  The node includes EVX only on macOS and Linux with its `evx` feature enabled.
  Unsupported targets omit execution and management commands. The current
  supervisor and workspace crates themselves require Unix APIs; the target
  gate excludes them from unsupported products rather than making them portable.
- Linux positive containment passed on Debian 13 ARM64 with Landlock ABI 6.
  Broader supported-kernel, architecture and package coverage remains required;
  see [`evx-linux-acceptance.md`](evx-linux-acceptance.md).
- RSS is sampled, not capped. Native allocations can overshoot between polls.
- Background jobs run inside the desktop node. Mobile OS wake, publication,
  retained streams, shared-data APIs, chain operations and the resource
  dashboard remain separate work.
- The trusted UI boundary includes escaped template values, single-pass
  substitution, framing restrictions and authenticated wrapper commands.
  See [`wrapper-sandbox.md`](wrapper-sandbox.md).
- Bounded fuzz campaigns and a separate internal review are documented in
  [`evx-review.md`](evx-review.md). Longer campaigns, OS-specific crash testing,
  and an external independent audit remain release gates.
