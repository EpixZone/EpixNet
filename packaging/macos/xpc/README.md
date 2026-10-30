# Apple XPC packages and tests

Run on macOS 12 or later with Command Line Tools:

```sh
python3 packaging/macos/xpc/test-xpc.py
python3 packaging/macos/xpc/test-backend-lifecycle.py
python3 packaging/macos/xpc/test-package-backend.py
python3 packaging/macos/xpc/test-native-isolation.py
python3 packaging/macos/xpc/test-backend.py
python3 packaging/macos/xpc/test-node-backend.py
python3 packaging/macos/xpc/test-release-pool.py
```

The default node uses direct workers. Trusted development assembly can select
`epix-evx/apple-xpc-development`; the App Store profile remains disabled.
These tests use disposable game records and signed development
bundles. They do not use real xites, credentials or chain actions.

## Production adapter and private workspaces

`test-backend.py` builds the actual Rust/C adapter and Pulley workers into
`target/apple-xpc`, then constructs an App-Sandboxed host with three fixed
service slots. Each slot has separate guest, compiler and file containers.
One permanent registry binds game-a, game-b and game-crash to those slots.
The suite tests compilation, execution, fresh workers, cancellation with
trusted CPU/RSS and reaping, private file roundtrips, cross-slot rejection,
uncertain-write reconciliation and durable quarantine after a host crash.
It also rejects malformed capability records, writable descriptors, wrong
modes, hardlinks, replaced roots, and replay on the same or a new connection.

The signed `EVXAuthorityHostIdentifier` and public `getpwuid_r` determine the
host-private authority directory. The resolver ignores `HOME`. Fresh,
connection-bound challenges authorize a single start using a read-only
capability descriptor. The service checks the descriptor's kernel path,
metadata and exact record before launching a child. That descriptor never
enters the worker. Public signing requirements apply before the handshake.

The file service opens its own fixed private workspace and passes FD 3 only
to its file worker. The host keeps provenance and lifecycle metadata in its
separate container. The journal becomes durable before each invocation and
clears only after authenticated final reap evidence. Service locks prevent
ordinary concurrent writes; they cannot prove an orphan or native-compromised
child is dead. Reopening an active journal refuses the slot. Digest recovery
does not clear process uncertainty.

The Apple profile intentionally permits private role-container persistence.
A native-compromised file-read worker can write its own file container,
although the EVX read protocol cannot. A real helper probe verifies that such
unregistered bytes are rejected by host-private provenance.

`test-native-isolation.py` uses an effect-free C worker in a separate signed
pool with the production service and adapter. Real native syscalls attempt
host-private and other-slot guest/file reads and writes. Those fail while an
own-container write succeeds. Loopback networking, fork and spawn fail;
non-root workers cannot raise the hard zero process limit; no extra descriptor
reaches the guest. This establishes specific native authority checks, not an
absence of all possible sandbox defects.

The service owns ordinary child processes and `wait4`. It can terminate its
unreaped children without a service-PID reuse race. It retains final usage,
accounts for its own overhead, rejects stale observations and escalates
termination even when observations fail. After child cleanup and all
connections close, the service exits after 30 idle seconds. The real fixture
checks reconnection before that deadline and observes its later exit using
`EVFILT_PROC`, without signalling a PID.

`test-backend-lifecycle.py` compiles the production C adapter with substituted
process observations and signals. Seven deterministic regressions cover permanent
observation failure, stale samples, termination despite missing measurements,
interrupted `wait4`, stopped-child status, unsafe executable paths/modes, and
idle-exit fencing. A stopped status never clears the durable invocation journal.
These tests supplement the actual signed-service runs.

`test-node-backend.py` uses the real node service in a verified signed pool.
It covers consent refusal, manual execution, file roundtrips, recovery, a
scheduled job and refusal after revocation. It checks that the xite has no
direct workspace. See the [development backend contract](../../../docs/evx-apple-workspaces.md#explicit-development-node-integration).

## Development package constructor

Build matching binaries, then construct a new development package:

```sh
CARGO_TARGET_DIR=target/apple-xpc cargo build -p evx-worker -p evx-supervisor \
  --features evx-worker/apple-xpc,evx-supervisor/apple-xpc \
  --bins --example apple_xpc_host --locked
python3 packaging/macos/xpc/package_backend.py build /tmp/Game.app \
  target/apple-xpc/debug/examples/apple_xpc_host \
  target/apple-xpc/debug/evx-worker target/apple-xpc/debug/evx-xpc-service \
  --host-identifier org.example.game.development --slots 3
python3 packaging/macos/xpc/package_backend.py verify /tmp/Game.app
```

The example host is a test driver, not the node. Production provisioning must
establish a fresh exclusive service pool, preserve assignments permanently,
and refuse a lost registry. Do not provision a new registry for an existing
pool merely because a registry directory is absent. See the
[slot contract](../../../docs/evx-apple-slots.md) and
[workspace contract](../../../docs/evx-apple-workspaces.md).

The constructor refuses an existing output, signs separate role services with
private App Sandbox entitlements, pins each inherited worker's SHA-256, and
signs the pool manifest into the outer app. The verifier checks exact service
configuration, identifiers, hashes, entitlement types, executable inventory,
linked libraries and filesystem shape. Eight tests include signature,
entitlement, role, duplicate-key, executable and symlink substitutions.

Development signatures pin service code-directory hashes but use an
identifier-only host requirement. They do not establish a production signing
team. The verifier reports `execution_enabled: false`, `app_store_ready: false`
and `runtime_containment_verified: false`. A package check cannot establish
release containment or App Store approval.

## Transport-only fixtures and cleanup

`test-xpc.py` has 23 real signed-XPC transport tests. Guest and compiler
listeners accept exact dictionaries with 128 KiB frames, a 256 KiB cumulative
limit and 130-frame count. Tests cover ordering, replay, types, unexpected
paths/descriptors, identity replacement and bounded denial. The echo and
lifecycle services do not use App Sandbox and never execute Wasm.

Separate sacrificial inherited-sandbox probes show that a second
`sandbox_init` is rejected, a reexecuted signed host cannot mint authority,
and a pre-opened file descriptor differs from a directory descriptor that
does not permit opening child paths. An unconfined control can perform those
operations. `JoinExistingSession` remains false; app groups, network and
user-selected-file entitlements are absent.

Normal transport services have bounded lifetimes. Production-adapter fixtures
wait for idle retirement before deleting their disposable bundle and owned
workspace files. A fresh unique signed host/service pool is used for each
registry-backed suite so containers are never reassigned to a new registry.
The tests do not remove protected OS container metadata or touch real EpixNet
containers. The older inherited probes reuse fixed fixture identifiers because
they do not provision a registry or retain xite data.

The separate [Developer ID package](../../../docs/evx-apple-production.md)
uses `release_pool.py` and the browser/node `apple-xpc` feature. Its eleven-case
ad-hoc suite verifies sealed package bootstrap, permanent state and real node
execution, including installation into `/Applications`. Release certificate
signing, supported-version coverage and independent review remain outstanding.
App Store assembly requires a compatible outer host and provisioning design;
it remains disabled. There is no automatic pool resizing or state migration.
