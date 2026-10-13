# EVX platform acceptance

macOS direct-child and Linux workers have implemented process boundaries. The
Apple XPC adapter and node backend work in signed development bundles. A
Developer ID package/bootstrap path is implemented and exercised with a
separate ad-hoc fixture profile. Actual release identity validation remains
external; the App Store profile remains disabled. A successful
build, Pulley engine test, or
package signature check does not complete platform acceptance.

## Apple application backend

The separately approved Apple profile permits private service-container access
under App Sandbox. It must keep host secrets, grants and unrelated xite data
outside that service's authority. It does not promise the direct-child profile's
literal no-filesystem authority after a native worker compromise.

The `apple-xpc` features in `evx-supervisor` and `evx-worker` select Pulley
and build the native adapter, `evx-xpc-service`, and inherited `apple-run`,
`apple-compile`, `apple-file` and `apple-file-read` workers. Each signed role
service contains its own pinned worker copy. The service owns a fresh child
and `wait4`; it never compiles or executes Wasm itself. The worker checks its
App Sandbox/inherit entitlements, refuses root, applies an irreversible zero
process-creation limit, and reads bounded EVX frames. It never applies a second
`sandbox_init` profile.

A permanent host-private registry binds a xite to one of 1 to 64 fixed signed
service slots. Guest, compiler and file roles use separate private containers.
`AppleWorkspace` binds the configuration, control metadata, grant xite and
invocation journal to that assignment. A journal entry is durable before a
compiler, guest or helper starts. Only authenticated final child-reap evidence
clears it. A host restart with a possible live child refuses the slot; ordinary
workspace digest reconciliation cannot clear that uncertainty. The slot is
never reassigned, even after consent is revoked. See [slots](evx-apple-slots.md)
and [workspace authority](evx-apple-workspaces.md).

Mutual XPC signing requirements apply before admission. Each connection gets a
fresh challenge. The host creates a 0600 capability record under its private
0700 authority directory and passes a read-only descriptor. The signed
`EVXAuthorityHostIdentifier`, the account home returned by `getpwuid_r`, and a
fixed container suffix determine the expected directory. `HOME` and caller
paths do not select it. The service validates the kernel-reported descriptor
path, flags, owner, mode, link count, exact 304-byte record, challenge,
connection PID and signed service ID. It consumes each admission once. The
proof descriptor never enters the worker. A PID is a connection-bound
consistency field, never a standalone authorization or service signal target.

The file service opens a fixed workspace in its own container and passes
FD 3 to its child. Neither the host's control root nor an arbitrary directory
FD enters that worker. A service-local lock prevents ordinary concurrent
helpers, but is not proof that a compromised or orphaned child has stopped.
Durable invocation quarantine remains necessary. The file-read protocol
rejects writes; a native compromise of that helper can still write its own
file container under this Apple profile. Host-private digest provenance
rejects bytes that were not authorized through the write protocol.

```sh
python3 packaging/macos/xpc/test-backend.py
python3 packaging/macos/xpc/test-backend-lifecycle.py
python3 packaging/macos/xpc/test-native-isolation.py
python3 packaging/macos/xpc/test-package-backend.py
```

The real adapter suite uses an App-Sandboxed host and three permanent slots in
one signed development package. It checks Pulley compilation, returning 42,
cancellation with positive CPU/RSS and confirmed reap, fresh workers, private
file roundtrips, cross-slot rejection, uncertain-write recovery, and durable
quarantine after a host crash. Malformed proof records, writable descriptors,
hardlinks, replaced authority roots and replay on the same or a new connection
are rejected. Seven deterministic native regressions cover observation failures,
staleness, termination, interrupted `wait4`, stopped-child status, executable
binding and idle fencing. Only an exited or signalled child can supply terminal
reap evidence and permit durable journal completion.

A separate native worker probe runs through the production service in a
signed two-slot package. Actual file syscalls cannot read or write a host-private
record or another slot's guest/file records. Its own private write succeeds.
Loopback connection, fork and spawn are denied, the process limit cannot be
raised, and no authority or workspace descriptor reaches the guest role.
These checks exercise native App Sandbox authority, not only Wasm imports.

The service uses public `proc_pidinfo(PROC_PIDTASKINFO)` for its owned child's
live CPU/RSS and `wait4` for final usage. `proc_pid_rusage` is denied by App
Sandbox for this child and is not used. `getrusage(RUSAGE_SELF)` includes trusted
service overhead. Memory is a conservative sum of child and service peaks,
which may occur at different times. A live observation older than one second
fails closed. Termination escalates independently of observation success; the
service also has a 605-second absolute backstop. An unconfirmed exit quarantines
admission. The host only accepts the service's reaped state as child termination.

Direct-child macOS execution retains `wait4` terminal RSS, including when a
child exits before the first live sample. A known terminal budget violation
cannot become a successful guest result or accepted recovery read. Quarantine
and uncertain writes keep precedence over resource-limit reporting. Separate
children's peaks are not added as if they occurred together. Linux retains only
post-exec procfs RSS samples: its `wait4` peak can include memory inherited from
the parent before exec and is not attributable to the worker. Short-lived Linux
memory peaks can therefore go unobserved. These observations detect budget
violations; none of these profiles promises a hard native-allocation ceiling.

After the child is reaped and all connections close, the service exits itself
after 30 idle seconds. Listener admission and timers are serialized, and a
reconnection fences the old idle timer. A real fixture observes reuse before
the deadline and `EVFILT_PROC` exit afterward. It never signals a service PID.

The development pool constructor and verifier are
`packaging/macos/xpc/package_backend.py`. The signed manifest binds every
slot's guest/compiler/file service identity and code-directory hash. Package
checks reject unexpected executables or services, non-system dependencies,
wrong entitlements, role substitution, malformed manifests, symlinks and
modified workers. Worker bytes are SHA-256 pinned by each signed service.
The inherited worker and the package are checked independently.

The default node selects direct workers. The explicit
`apple-xpc-development` feature supports trusted node assembly with an already
verified, provisioned permanent pool. Consent, manual execution, recovery and
scheduling have a signed node fixture. No xite or management command can select
the backend. See [development integration](evx-apple-workspaces.md#explicit-development-node-integration).
The separate browser/node `apple-xpc` feature now selects an authenticated
Developer ID package, with compiled Team ID, sealed manifest admission, fixed
private state and fail-closed first-use provisioning. `build-app.sh` can assemble
that profile through `release_pool.py`. Eleven ad-hoc fixture cases exercise the
mechanics, including actual node execution from `/Applications`. See the
[production package contract](evx-apple-production.md). Release certificate
signing, supported-version acceptance and independent review remain unperformed.
Pool resizing and cross-profile migration have no automatic path. App Store
assembly needs a compatible outer host and provisioning mechanism, as well as
Apple's review.
The development package has exact service hashes but an identifier-only host
requirement because it has no release certificate. Its verifier explicitly
returns `execution_enabled: false`, `app_store_ready: false` and
`runtime_containment_verified: false`. Those are release gates, not xite policy.

## Current macOS package checks

For its default direct-child profile, `packaging/macos/build-app.sh` checks the worker's linked libraries and runs
`verify-evx-package.py` after signing. The verifier requires a real Mach-O
worker at `Contents/MacOS/evx-worker`, rejects symlink substitutions, verifies
the worker and app signatures, and rejects additional worker entitlements or
non-system dependencies. The current direct-child profile needs no worker
entitlements beyond signing metadata. Changing that policy requires a reviewed
runtime profile and tests.

```sh
python3 packaging/macos/test-evx-package.py
python3 packaging/macos/verify-evx-package.py dist/EpixNet.app --profile direct-child
```

The tests include a temporary, ad-hoc signed inert executable. They verify
signature checks and rejection after tampering; they never execute that
fixture as an EVX worker. The verifier's result explicitly reports
`app_store_ready: false` and `runtime_containment_verified: false`. It checks
the package at inspection time, not the identity of a subsequently launched
process. It accepts ad-hoc signatures for local builds and does not attest a
release signing identity or notarization.

`--profile app-store` always fails. Setting `EPIX_EVX_PROFILE=app-store` also
stops the build before it changes the output bundle. There is no fallback to
the direct child profile, and no renamed worker masquerading as an XPC service.

## Remaining macOS XPC work

`packaging/macos/xpc/test-xpc.py` now supplies executable transport evidence:
23 tests run real, signed embedded XPC listeners through launchd, with mutual
code-directory-hash requirements, distinct guest/compiler roles, exact bounded
frames, ordering and budget rejection. Wrong identifiers and replacement code
with the same identifier are rejected. A lifecycle fixture also demonstrates
that cancellation leaves a service running and that kernel usage observations
can disappear after launchd reaps it. Inherited-sandbox file tests distinguish
a pre-opened file descriptor from a directory descriptor, which does not
authorize opening child paths. See the
[fixture scope and limits](../packaging/macos/xpc/README.md).

These fixtures do not execute Wasm. The echo and lifecycle listeners do not
declare App Sandbox entitlements; a separate probe tests inherited App Sandbox.
The separate production-adapter tests above execute Wasm. The production-adapter suite also exercises a file role and durable per-xite
assignment; the separate native suite probes container separation. These do
not establish production team identity or complete release acceptance. The
App Store profile remains disabled. Reserving the entire admitted budget and
quarantining an early or unobserved exit could provide conservative accounting;
it must be integrated with durable job state before it can satisfy that gate.

The public macOS SDK provides audit-token-based process signalling through
`proc_signal_with_audittoken`, but its public XPC and `NSXPCConnection` headers
do not provide an audit-token getter. A PID sample followed by `kill` has a
reuse race, even when process start times are checked. The fixture deliberately
never signals the service. An unavailable stable termination identity must
leave the invocation quarantined, with no slot or workspace reuse.

The saved adapter uses a minimal trusted XPC supervisor that owns fresh
direct child workers. Its intended role is bounded transport and child
lifecycle, keeping Wasm compilation and execution out of its process. Child
ownership preserves `wait4` and termination semantics. The accepted Apple
profile permits private container state, so durable per-xite service assignment
and a tested persistence policy are required before this backend can run jobs.
The real inherited-sandbox fixture verifies the reason for a separate profile: its child inherits
App Sandbox and can be reaped with `wait4`, but `sandbox_init` rejects a second
pure-computation profile. The unsandboxed control accepts the same profile.
The installed public `sandbox.h` documents this refusal. Therefore this
architecture cannot directly reuse the current worker's stricter profile.
The inherited worker modes therefore use the approved Apple profile. Keep
`JoinExistingSession` false and omit app groups, network and user-selected-file
entitlements. Container cleanup alone is not evidence that every persistent
capability is isolated between xites.

Apple starts an embedded XPC service through `launchd`, with an independently
signed service bundle under `Contents/XPCServices`. Its sandbox can differ
from the parent app's sandbox. A helper launched as a child instead inherits
the parent's App Sandbox policy. These are different execution boundaries.
See [Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
and [App Sandbox inheritance](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html).

The XPC implementation must pass these gates before the package profile can
be enabled:

| Gate | Required evidence |
| --- | --- |
| Transport | A real XPC listener and client carry bounded EVX messages and scoped file descriptors. No caller-selected executable, arbitrary endpoint, ambient path, or unrestricted object decoder. Preserve request ordering, commit acknowledgements, output budgets and backpressure. |
| Peer identity | Authenticate both ends using trusted signing requirements before accepting frames or descriptors. Test a wrong signer, wrong identifier and replacement service. A PID, UID, identifier alone or caller-supplied xite is insufficient. |
| Role separation | Guest and compiler receive no workspace descriptor or shared app-group authority. The file role opens only its fixed private workspace and passes that handle and lease. Test a guest impersonating a file helper. Do not combine every role's entitlements into one service. |
| Invocation isolation | Prove fresh worker processes and no cross-xite access, including service container files, queues, descriptor lifetimes and crash restart. Document permitted private persistence within one xite. Multiple connections to a reusable service are not proof of separate processes. |
| Termination | On timeout, revoke, disable, disconnect and host death, prove execution has stopped before releasing the slot and workspace lease. Quarantine uncertainty. Never treat connection cancellation as proof of process death. |
| Accounting | Preserve kernel measurements and final child `wait4` accounting through the trusted service, including helpers that finish between samples. Bound observation age and account for service overhead. Test missing observations, native allocation spikes and a stuck service. Never accept measurements from the guest. |
| Signed package | Verify the final signed service and app on each supported macOS version, with production identity and exact entitlements. Test signature or entitlement tampering and refusal to launch a substituted service. |

The default `evx-supervisor::process::Peer` uses a child process, inherited
descriptor 3, process-group signals and `wait4`. The optional Apple adapter
delegates child ownership to the trusted service. Moving a binary inside a
bundle alone does not preserve those assumptions. Apple documents that
[session cancellation](https://developer.apple.com/documentation/xpc/xpcsession/cancel%28reason%3A%29)
discards pending messages and invalidates the connection. It does not promise
that the remote process has exited. Apple also warns that a
[remote PID can become stale](https://developer.apple.com/documentation/xpc/xpc_connection_get_pid%28_%3A%29).

Use public peer requirements, such as
[XPCPeerRequirement](https://developer.apple.com/documentation/xpc/xpcpeerrequirement),
with an explicit supported-OS floor. The installed SDK marks the older
`xpc_connection_set_peer_code_signing_requirement` API as macOS 12 or later;
the current desktop bundle declares macOS 11. Supporting 11 therefore needs a
separately reviewed identity mechanism or an explicit higher XPC profile floor.
Ad-hoc fixture identity checks cannot establish production team identity.

App Sandbox provides a service with container access. It does not establish a
literal no-filesystem guarantee. Keep sensitive app and other xite data out of
service containers and app groups, and test persistence across invocations.
See [accessing files from App Sandbox](https://developer.apple.com/documentation/security/accessing-files-from-the-macos-app-sandbox).
An acceptable public-API design must replace or explicitly justify the current
deprecated `sandbox_init` profile path for this distribution channel.

App Store review is an external acceptance step. Describe downloadable Wasm
and background execution accurately under the current
[App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/),
including sections 2.4.5, 2.5 and 4.7. A containment test or notarization result
does not establish App Store approval.

Direct-worker crash admission is covered by the host-private
[durable lifecycle journal](evx-direct-lifecycle.md). Workspace locks and PID
absence do not establish prior worker death.

## Other platform gates

Wasmtime's [Pulley interpreter](https://docs.wasmtime.dev/examples-pulley.html)
removes the native-code backend requirement; it does not provide an OS
process boundary or make a blocked host call interruptible. iOS still needs a
device-tested host, scoped broker, cancellation and memory policy, and handling
for suspension, expiration and interrupted effects. In-process failure can
terminate the app. Desktop interpreter tests cannot establish those device
properties or guarantee background scheduling.

The desktop Pulley profile also runs the real confined worker, compiler,
broker, hostile IPC and authenticated activation suites. Test helpers forward
the selected backend when rebuilding workers, so compiler and host artifact
identities agree:

```sh
cargo test -p evx-api -p evx-runtime -p evx-worker -p evx-supervisor -p evx-host --features evx-runtime/pulley --locked
```

This command passed 86 tests on macOS, including cancellation, resource limits
and private workspace operations. Both authenticated host suites are enabled
for Linux CI as well. iOS device behavior still requires its own execution
evidence.

Native Linux acceptance now passes on Debian 13 ARM64, kernel 6.12.111 with
Landlock ABI 6: 539 EVX tests, 137 Pulley tests, strict all-target Clippy,
and 14 native containment probes. The optimized worker also passed compilation
and execution under both ordinary and privileged parents, with inherited
capabilities removed. See [Linux acceptance evidence](evx-linux-acceptance.md).
Nine Linux package tests also pass. Broader supported-kernel, x86_64 and full-application tests still need execution;
cross-compilation does not establish enforcement. Missing Landlock, seccomp or observations must
fail closed, with no unconfined fallback. Keep unavailable-platform refusal
tests even after adding a supported profile. Windows needs its own confined
process and accounting backend.

The new [Windows fixture](evx-windows.md) implements an LPAC/Job Object test
launcher; its MSVC target typecheck and strict Clippy pass on the macOS host.
Its six native Windows cases remain unrun locally. The
[Android fixture](evx-android.md) compiles against official API 36 and passes
32 portable protocol/lifecycle assertions, with no emulator or device result.
Both are separate acceptance fixtures and are not node backends. New CI jobs
require native Windows execution and mobile SDK checks; creating those jobs
does not establish their results.

The node's optional EVX dependency and plugin registration are restricted to
macOS and Linux. Windows and mobile products have no EVX management or execution
commands. The native messaging host also excludes EVX. Enabling the node's
`evx` feature on another target does not bypass the target gate. The direct
supervisor and workspace crates still require Unix APIs.

```sh
python3 scripts/check-evx-platforms.py
```

This guard resolves 11 separate product/target dependency graphs. It requires
EVX for macOS/Linux browser and server builds and excludes the runtime from
Windows browser/server, iOS/Android FFI and native messaging hosts. Before the
fix, the Windows browser graph included `evx-workspace`, and cross-checking that
crate for `x86_64-pc-windows-msvc` failed on unavailable `rustix` filesystem APIs.
After the fix, all 11 graphs and a native node check passed. Graph checks do not
compile or link the full Windows product; its native toolchain build remains
required in Windows release CI.

The Linux package build now builds and stages `evx-worker` beside the node.
Tar, Debian/RPM and AppImage assembly include it, and stage validation rejects
a missing, non-executable, symlinked or mismatched-architecture worker.
`python3 packaging/linux/test-evx-package.py` checks these paths with inert
ELF-header fixtures. The native package metadata and AppImage staging tests
substitute external package tools; the tar test creates and inspects a real
archive. Package-install CI also checks the installed/extracted worker is a
regular executable, and that package removal removes it. These checks do not
execute Linux code or establish confinement.

Platform acceptance also requires bounded fuzzing campaigns and review by
someone independent of the implementation. Regression tests and an internal
peer review are useful evidence, not an external security audit.
