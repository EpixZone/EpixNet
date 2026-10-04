# Windows native isolation fixture

Windows EVX execution is still disabled. `evx-windows` is a separate native
acceptance primitive and a real compiler/worker transport. Its `WindowsExecutor`
can compile arbitrary bounded EVX Wasm modules and execute their resulting
Pulley artifacts through `evx-windows-worker`. It does not port the node's
workspace broker, scheduler, consent or recovery integration. Nothing in the
node selects it.

The fixture stages a copy of its own executable in a new disposable directory
and creates a fresh AppContainer identity. Its host API accepts no caller-selected
program, command line, path or capability. The child modes are fixed game output,
native denial checks, a bounded memory request, a CPU loop and sleep. No downloaded
code, real user records, chain activity or external network request is used.

## Boundary implemented

The child is launched as a less-privileged AppContainer (LPAC), with zero
capabilities and the All Application Packages opt-out. Protected ACLs grant the
exact package identity read/execute access only to its staged fixture directory.
A synthetic host-private game record has a separate owner/System ACL. There are
no network, broad filesystem or registry grants.

`PROC_THREAD_ATTRIBUTE_JOB_LIST` attaches the process to its job during
`CreateProcessW`. There is no create-then-assign gap. The process initially stays
suspended while the host verifies its AppContainer SID, LPAC access restrictions,
empty capability list and job membership. The LPAC check uses an impersonation
duplicate with `AccessCheck`: a grant to the exact package must succeed, while
a grant to `ALL_APPLICATION_PACKAGES` must be denied. This avoids relying on
the class-46 token query, which current Windows rejects from user mode.
An unsupported or failed operation refuses
execution. There is no unrestricted fallback.

The job permits one process, disallows breakaway, uses kill-on-last-job-handle
close, and sets 64 MiB process and aggregate committed-memory limits. Its CPU
controls are a 500 ms user-time budget and a 50% scheduling-rate cap. The user-time
budget does not claim to measure kernel time. A separate wall deadline covers
sleep and stalled execution. Child creation is also disabled by the process
creation policy. The only inherited handle is a private reply-pipe writer;
a deliberately inheritable event is excluded and checked by the fixture.
The parent environment and ordinary standard handles are not passed through.
The child environment contains only `SystemRoot` and `LOCALAPPDATA`, resolved
through Windows APIs; AppContainer startup redirects its profile storage.

Normal completion requires a signaled process handle followed by job accounting
showing zero active processes. `TerminateJobObject` returning success, a reply,
pipe closure or an exit-code query alone cannot establish death. A termination
wait or accounting failure retains the disposable stage/profile and returns an
error. The separate kill-on-close case retains an independent process handle to
observe death; its one-process restriction precludes descendants. This is not a
persistent production lifecycle journal or an actual host-crash test.

This primitive does not promise that native code has no filesystem namespace.
LPAC uses Windows access checks, and OS resources may already grant LPAC access.
Its dedicated profile can also have private OS-managed state. Before production,
that storage needs quota, identity, provenance and reuse rules comparable to the
existing EVX host protocols. Closing a job is not a substitute for those rules.

## Reproducible checks

The 2026-10-04 macOS review host has Rust's `x86_64-pc-windows-msvc` target but no
Windows execution environment or SDK. Both commands passed without a Windows SDK
or C build dependency:

```sh
cargo check -p evx-windows --all-targets --target x86_64-pc-windows-msvc --locked --offline
cargo clippy -p evx-windows --all-targets --target x86_64-pc-windows-msvc --locked --offline -- -D warnings
```

Two portable regression tests also pass. They verify that descendant creation
accepts the explicit `ERROR_CHILD_PROCESS_BLOCKED` status (367), while file and
network checks still require `PermissionDenied`, and unrelated launch failures
cannot count as isolation. The former permission-only descendant check failed
this regression before correction. Microsoft's [SDK error definition](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/winerror.h)
identifies 367 as a process-creation block; Rust's current Windows mapping does
not classify it as `PermissionDenied`.

This is portable test/type/lint evidence only. No native Windows result is recorded locally.
`.github/workflows/evx-windows-fixture.yml` builds on Windows and requires:

```powershell
cargo build -p evx-windows --example acceptance --release --locked
& target/release/examples/acceptance.exe
```

The six native cases cover a valid eight-byte game response; explicit access
denials for the synthetic host record, package write, child creation and loopback
connect/listen; rejection of an allocation above the memory cap after a small
allocation succeeds; CPU termination before the wall fallback; confirmed wall
termination; and confirmed death on job close. Non-permission errors do not count
as access-denial evidence, except the specific child-policy status above for
descendant creation. Handle inheritance is checked using the host's original
event object; success operating on a recycled child-local handle number is not
mistaken for a leak. The workflow retains the output and fails on refused
LPAC startup rather than treating an unavailable profile as a passing test.

## Remaining acceptance and integration

A passing native fixture is necessary, not Windows product support. Production
needs a trusted installed worker identity and immutable package, permanent
per-xite container mapping, bounded broker IPC, Windows file/provenance operations,
restart-safe lifecycle records, cancellation and accounting integration, Wasm
engine compilation/execution acceptance, and node/scheduler selection. The
existing macOS/Linux workspace semantics cannot be assumed to hold on NTFS.

Native acceptance must also cover host death, interrupted startup, token and
handle substitution, cross-container access, named-object access, DLL search and
loading, profile storage quotas, and supported Windows versions and security
policies. Fresh fixture profiles are not a product migration/reset mechanism.
External security review remains a release gate. No AppContainer result proves
an absence of all kernel or runtime vulnerabilities.

## Primary API references

Microsoft documents [LPAC creation and the capability opt-out](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[creation-time job lists, handle lists and child restrictions](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information),
[job termination](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject),
and [job accounting queries](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject).
These API contracts motivate the implementation; the pending native run must
establish that the complete configured profile works on a supported host.

## Real compiler and worker transport

`TrustedWorker::open(path, expected_sha256)` accepts only a local disk path and
rejects reparse components, hard-linked files and a wrong trusted hash. Its
held source handle refuses write/delete sharing. The verified bytes are copied
into a fresh LPAC stage, then independently pinned before launch, so staging
does not reopen a replaceable source path. The expected hash is trusted installer
input. No xite or request may choose it. The native fixture hashes its own local
build; that is a test stand-in, not a production signed-package policy.

`WindowsExecutor::compile` sends the common bounded compiler frame to a fresh
LPAC compiler. It validates the artifact digest and engine key after native
completion and returns an opaque `CompiledModule`; publishers cannot construct
or deserialize that type. `run` sends it to a separate fresh LPAC worker and
uses the existing `evx.call` protocol. It enforces request shape, call count,
response limits and host-call elapsed time. The supplied callback is trusted
embedding code and still needs grant/revocation checks before authorizing effects.
No Windows filesystem callback is provided.

Three private byte pipes carry stdin, stdout and stderr. Only their child ends
are inherited; no parent environment is passed. Host ends use nonblocking mode,
check deadlines/cancellation between bounded operations, cap framing before
allocation and enforce a 256 KiB combined stdout/stderr budget. The worker
checks its LPAC token and job restrictions before parsing input. The suspended
startup is verified before resume, with creation-time job membership and child
process creation disabled.

An independent monitor enforces wall time, cancellation, total kernel-plus-user
CPU from process times and resident working-set peaks. Job limits separately
cap committed memory and user CPU time. `NativeUsage` names resident and
committed memory separately. Reported guest fuel/memory never authorize native
budgets. Success requires terminal protocol, no trailing output, a signaled
process handle, zero active job processes, terminal resource checks and clean
exit. An unconfirmed lifetime retains its stage/profile and stops further
admission in that host process. There is no persistent restart journal in this
adapter yet. The host callback must return; native cancellation still kills the
worker while a trusted callback is blocked, but cannot interrupt arbitrary host
callback code.

Native CI now also builds and runs:

```powershell
cargo build -p evx-windows --bins --example execution_acceptance --release --locked
& target/release/examples/execution_acceptance.exe
```

That fixture requires real compilation and return value 42, an `evx.call` game
score roundtrip, cancellation with confirmed cleanup, and successful fresh
execution afterward. It also rejects a wrong worker hash. It has not run on
this macOS machine. Cross-target all-target checks and strict Clippy pass;
they prove type/build compatibility only. The user must run the workflow or
these commands on Windows and retain the actual native result before enabling
any product target.

The next Windows implementation work is durable host lifecycle admission,
trusted installed-package selection, native filesystem/provenance effects,
per-xite storage/identity/quota policy, and mapping the low-level result/error
into node budgets, activation, consent and scheduling. Failed or unmeasured
runs must reserve the full admitted budget instead of reporting zero usage.
The native tests must also confirm the named-pipe behavior, LPAC loader access,
job queries from the child, process exit accounting and cleanup on the supported
Windows versions. Current product gates remain closed.
