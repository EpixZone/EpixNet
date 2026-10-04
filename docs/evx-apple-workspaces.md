# Apple workspace and worker lifecycle

The Apple development profile keeps three service containers per permanent
xite slot: guest, compiler and file. The file service owns a fixed workspace
inside its own private container. Its path comes from the signed service
identity. Neither a xite request nor the host's broker supplies that path.

The node's App Store execution profile remains disabled. This adapter and its
acceptance fixtures do not establish release signing, device support, or an
external security audit.

## Host control binding

`AppleWorkspace::open` accepts only an `AppleSlotAssignment` from the
[permanent slot registry](evx-apple-slots.md). It derives one host control
directory as `registry/workspaces/<slot>`. The registry records that directory's
device/inode, and its binding record names the xite, slot and all three service
identities. Callers cannot choose a second control root for an assignment.
Missing, replaced, unsafe or partially initialized controls refuse admission.
Creating another registry for an already used pool remains forbidden.

`Broker::new_apple` uses the control directory for the invocation lease and
host provenance. It never opens guest data. The existing provenance store is
outside every service container, and the helper never receives its descriptor.
`AppleWorkspace::config` binds the role identities and host session to the
transport. Run, recovery and the workspace's checked compilation methods reject
a different xite, slot, role identity, signing requirement or backend before
starting work. The transport repeats the binding check before every start.

The low-level unbound configuration constructor is for trusted development
transport fixtures. It is not a node-facing activation or declaration API.
The development node constructor selects a bound workspace and the activation
runner checks its backend before compiler launch, then again before execution.

## Process uncertainty is separate from file uncertainty

The host records a possible invocation durably before opening an XPC
connection for any compiler, guest or file worker. The bounded lifecycle
journal stores a host-session number, increasing invocation IDs and active
roles. A guest and its file helper may share a session. Competing guests,
compilers, helpers and reopened sessions cannot overlap.

Only the trusted service's confirmed child-reap observation can clear the
matching role and invocation ID. A stale callback cannot clear a successor.
Dropping a token, losing a connection, failing an admission handshake or
crashing the host leaves the record unresolved. Reopening a slot with any
active role quarantines it. File digest reconciliation does not clear this
condition. There is no automatic orphan-recovery or journal-reset operation.

The file service also holds a local workspace lock across the child lifetime.
This helps serialize operations and normal restarts. It is not proof of death:
a compromised native child could release an inherited descriptor. The durable
host journal is required even when the lock can be acquired again. Native
acceptance separately checks that workers cannot create descendants.

Host metadata uses bounded strict JSON, owner-only directories and files,
no-follow opens, exclusively created staging files, file sync, atomic replacement and
directory sync. Returned authority re-establishes durability after a visible
but uncertain earlier sync. Counters refuse overflow. These checks assume the
unconfined host owns the metadata namespace. They do not authenticate arbitrary
writes or detect valid snapshot rollback by that owner. Restoring an old
journal or slot registry against newer service containers is unsupported.

## File protocol and limits

The signed file service opens its fixed workspace and passes only that private
directory descriptor to its fresh worker. The worker uses the existing bounded
`Init`, `Prepared`, `Commit` and `FileResult` protocol. The host checks current
authority and limits, persists authorized content digests, then permits commit.
Responses and provenance completion still wait for confirmed helper exit.
Uncertain writes retain their authorized candidate digests until explicit
recovery reads and verifies the resulting content.

An Apple read helper has native write access within its own file-service
container. The logical read path refuses write requests and never sends a
commit, but this is weaker than the direct profile's OS-enforced read-only
filesystem boundary. Host provenance rejects altered or unregistered read
bytes before returning them to a guest. The signed `file-roundtrip` fixture
demonstrates this difference by writing a marker during `ReadOnlyWriteProbe`
and then verifying that its unregistered contents are not released.

Storage limits apply to the actual private workspace through the file helper's
existing checks. `Broker::usage` refuses on this profile because counting the
host control files would report the wrong storage. A future usage API must ask
the scoped file service. This does not impose a filesystem quota on all other
native-writable paths in the service container, and does not claim that it does.

## Acceptance evidence

The disposable unit tests cover lifecycle drop/reopen, same-session role
ordering, stale callbacks, failed durability, counter overflow, control
replacement, unsafe metadata, config substitution and recovery refusal while
a worker lifecycle is unresolved.

The signed three-slot App Sandbox fixture covers actual compiler and guest
execution, cancellation, file roundtrips, separate xite contents, cross-slot
substitution denial, uncertain writes followed by recovery and a new write,
and abrupt host exit after a real helper acknowledges staging. A subsequent
host process must refuse the interrupted slot. Other slots remain usable.

```sh
cargo test -p evx-supervisor --features apple-xpc --locked
python3 packaging/macos/xpc/test-backend.py
```

These are internal tests and code review. Production package assembly and
signing, device acceptance and independent external review remain distinct
release gates.

## Explicit development node integration

The `epix-evx/apple-xpc-development` feature adds
`AppleDevelopmentBackend::from_provisioned_registry` and
`EvxPlugin::with_apple_development`. Trusted host assembly supplies the already
verified signed inventory and permanent registry. No environment variable,
xite declaration, browser command or guest request can select this backend,
provide service identities or provision a pool. The default plugin still
selects the direct worker. Selecting Apple never falls back to that worker.

Apple development grants, checkpoints and job history live in
`private/evx-apple-development`. A durable backend marker pins this state to
the registry's installation, root and lock identities. Missing or mismatched
markers refuse adoption, including an existing direct state tree. Changing a
backend is not a workspace migration, and empty Apple state cannot reconcile
a direct workspace's uncertain effects.

The node retains one workspace session per assigned xite. Compilation, manual
execution, the background scheduler and explicit recovery use the same paired
broker and config. Backend validation precedes compilation; broker registration
precedes the compiler too, so policy cancellation reaches every worker role.
Inspection and consent do not allocate slots. Recovery looks up an existing
assignment without allocating one and validates its lifecycle even though no
direct workspace directory exists. File reconciliation cannot clear process
uncertainty or resume an unresolved slot.

Direct execution now also retains a durable host process-lifecycle context.
A fresh empty state root provisions it before state creation. Existing nonempty
roots without this journal receive a durable reboot barrier and remain
inspectable. Execution and workspace recovery require a later verified kernel
boot. The [direct lifecycle contract](evx-direct-lifecycle.md) describes this
migration and recovery path. Corrupt or partial metadata remains refused.
This recovery is specific to direct children; it does not clear Apple slot
journals or accept lost registry/container ownership.

The signed node fixture uses a fresh, verified development pool and the real
node service. It verifies consent refusal, manual execution, private file
roundtrips, explicit recovery, a scheduled job and refusal after revocation.
The recovery case models a lost acknowledgment by moving an already authorized
digest to pending host metadata, then requires the real file service to
reconcile exactly one path. It also requires that the node never creates the
direct workspace for that xite. The backend binding regression proves a substituted config is rejected
before a compiler invocation can be recorded.

```sh
cargo test -p epix-evx --features apple-xpc-development --locked
cargo test -p evx-host --features apple-xpc --test apple_backend_binding --locked
python3 packaging/macos/xpc/test-node-backend.py
```

This is a trusted opt-in development assembly. The App Store profile remains
disabled; these constructors do not verify release packaging or authorize a
weaker mobile isolation model.
