# EVX: sandboxed execution for xite programs

EVX (Epix Virtual eXecution) runs untrusted WebAssembly programs published by
xites on the user's own machine, inside the EpixNet application, with access
only to explicitly granted capabilities. This document describes the runtime
as implemented in the `evx-*` crates. The product plan, security review and
prior-art research live outside this repository in the planning documents;
this page is the engineering reference for what exists in the tree.

Status: milestone 2 (`docs/evx-milestone-2.md`). Execution is macOS only.
A xite's signed `evx` declaration is parsed from its root `content.json`,
inspected inertly, granted through the wrapper's consent dialog or the
operator socket, run once on demand, and revoked. No scheduler or background
lifecycle yet (milestone 3), no publication or chain operations. Not reviewed
independently. Do not enable for untrusted public content.

## Crates

| Crate | Role | Trust |
| --- | --- | --- |
| `evx-api` | Shared types: closed capability set, limits, grants, IPC frames, strict JSON decoding, path and identifier validation. No I/O. | Dependency leaf |
| `evx-runtime` | Wasm feature profile, structural validator, Wasmtime engine configuration, precompilation, execution with fuel, epoch deadline and store limits. | Trusted code, hostile input |
| `evx-workspace` | Descriptor-relative workspace file operations: link-refusing reads, staged writes with a commit step, quota accounting. | Trusted code, used inside the confined helper |
| `evx-worker` | The confined binary. Modes `run`, `compile`, `file` and a harness-only `probe`. Confines itself before reading any input. | Untrusted after a guest starts |
| `evx-supervisor` | Broker, workspace lease, child processes, kernel resource observations, commit authorization, effect-outcome semantics. | Trusted |
| `evx-activation` | Ed25519-signed activation envelopes, immutable closure capture, two-phase admission, shared-source record verification. | Trusted |
| `evx-state` | SQLite durable model: grants with separate authority and limits generations, cumulative budgets, idempotent occurrences, atomic checkpoint plus outbox, mock destination. | Trusted |
| `evx-host` | Binds activation to the supervisor; JSON-on-stdin CLI for harnesses. | Trusted |
| `evx-declaration` | Strict parser and manifest binder for the signed `evx` section of a root `content.json`: programs, jobs, capability requests, limits; unsupported items disable only the affected work. | Dependency leaf, hostile input |
| `epix-evx` | The node's EVX plugin: grant store and workspaces under `private/evx/`, the `evx*` WebSocket commands (inspect, status, request, grant, revoke, limits, run once) and the activation of a xite's declared program through `evx-host`. | Trusted |

## Execution boundary

```text
EpixNet node (epix-evx plugin)
  -> read the xite's root content.json bytes; require the owner's signature and a complete core
  -> evx-declaration: parse the evx section strictly, bind entry + dependencies to the manifest hashes
  -> consent: the wrapper's dialog (Enable / Allow once / Deny) or the operator socket; a page can only ask
  -> evx-state: persistent xite grant (capabilities, profiles, limits, generations), allow-once tokens, run history
  -> evx-host: verify the content activation, capture closure, check binding against grant
  -> evx-supervisor: compile in a confined child, admit (version floor advances here), lease workspace
       -> evx-worker run      (no filesystem, no network, no fork/exec; Wasmtime, fuel, epoch, store limits)
            evx.call -------> supervisor authorizes request under grant generation
       -> evx-worker file     (one workspace read or staged write; commit needs supervisor ack)
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
3. **OS confinement.** The worker applies a deny-default Seatbelt profile to
   itself through `sandbox_init` before reading its first frame: no network,
   no fork or exec, no Mach lookups, no executable file mappings, read access
   to system libraries and its own binary only, plus one workspace directory
   for the file helper. Hard `RLIMIT_CPU`, `RLIMIT_NOFILE` and `RLIMIT_CORE`
   apply on top. The supervisor samples CPU and RSS from the kernel and kills
   on deadline; it never trusts a worker's own measurements.

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

## Fixes carried from the proof of concept review

- A denied signed update no longer advances the version floor: `verify` is
  separate from `admit`, and compilation happens between them.
- A budget change no longer cancels queued effects or fails running
  invocations: `evx-state` keeps an authority generation and a separate limits
  generation.
- Workspace paths reject `..`-prefixed components (covering macOS named forks),
  control and format characters, and the staging prefix.
- The sandbox profile no longer grants the whole interpreter tree; it names the
  system library roots, the binary and the workspace.

## Tests

| Suite | Count | What it proves |
| --- | --- | --- |
| `evx-api` unit | 7 | Strict decoding, path aliases, limit ranges, frame shapes |
| `evx-runtime` unit | 9 | Feature set, validator caps, fuel, epoch deadline, memory limiter, guest-memory boundaries, digest and engine-key checks |
| `evx-workspace` unit | 4 | Round trip, link and special-file refusal, quota, staging cleanup |
| `evx-activation` | 46 | Signatures, capture, rollback, two-phase admission, shared-source policy, Python-signed envelope cross-check |
| `evx-state` | 38 | Reservations, idempotent commit, outbox, revocation ordering, generation split, process-crash recovery |
| `evx-supervisor` `baseline` | 12 | The proof of concept's containment and capability checks against the real worker |
| `evx-supervisor` `ipc` | 8 | Hostile peer (`examples/hostile_peer.rs`): malformed frames, forged telemetry, floods, control characters, environment |
| `evx-supervisor` `lifecycle` | 7 | Stuck helper, revocation mid-run, quota races, lease exclusion, lease survival after supervisor death, uncertain effects |
| `evx-host` | 10 | Signed activation through the contained supervisor; floor unchanged on denial |

Run everything on macOS with:

```sh
cargo test -p evx-api -p evx-runtime -p evx-workspace -p evx-activation -p evx-state -p evx-supervisor -p evx-host
```

The supervisor and host integration tests build and launch the real
`evx-worker` binary and the `hostile_peer` example themselves.

The supervisor and host integration tests are gated to macOS. On other
platforms the worker refuses to run because no confinement is implemented, and
the supervisor refuses because kernel accounting is unavailable. Both are
deliberate: there is no unconfined fallback.

## Known limits and next milestones

- macOS only. Linux (Landlock plus seccomp) and Windows (job object plus
  AppContainer) confinement are not implemented; iOS needs the in-process
  Pulley backend.
- The worker is launched as a child process. For an App Store build it must be
  packaged as an XPC service with its own entitlements; the frame protocol does
  not change.
- RSS is sampled, not capped. A native allocation can overshoot between polls.
- No scheduler and no background lifecycle: a program runs only when the
  user or operator says so (milestone 3). No publication, streams or chain
  operations. The resource dashboard is limited to the inspect/status payloads.
- Grants need the wrapper's consent dialog or the operator socket. The
  wrapper's socket is authenticated by the xite's secret key, the xite page
  runs in an opaque origin (path mode) or its own content host (host mode),
  and neither `ADMIN` nor the `as` command confers EVX authority
  (`docs/wrapper-sandbox.md`). An independent review of the whole boundary is
  still a prerequisite before any xite is opted in.
- Not independently reviewed. No fuzzing campaign has been run.
