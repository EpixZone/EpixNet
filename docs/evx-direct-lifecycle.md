# Direct worker lifecycle across host restarts

A workspace lock is not evidence that a worker has stopped. A native-compromised
file helper can close its inherited lease descriptor and survive a host crash.
The reproduced failure allowed a restarted host to authorize a new same-xite
write while that old helper remained alive. This did not establish access to
another xite or to host-private metadata.

`evx-supervisor::direct_lifecycle` records possible execution in a dedicated
host-private directory outside every workspace. The node retains one
`Arc<DirectLifecycle>` and derives a `DirectScope` for the admitted xite.
Compilation, guest execution and file helpers, including reconciliation, use
that scope through `Config.direct_lifecycle`. The broker rejects a scope for a
different xite or a simultaneous Apple/direct configuration.

## Admission and completion

The journal is durable before `Command::spawn`. Each entry binds the current
host session, xite, role and monotonic invocation number. It admits concurrent
xites within a bounded 128-entry table. For one xite, only a guest and one file
helper may overlap. Compiler and standalone recovery work require no other
active role for that xite.

Only `wait4` returning the exact owned child PID with an exited or signalled
status permits journal completion. An interrupted wait leaves the child
nonterminal. A stopped status is not a reap. `ECHILD` and other unexpected wait
errors stop host admission and prevent further sampling or signalling of that
PID, because its identity may no longer be owned.

On Windows the owned identity is the process handle, not a PID, so it cannot
be reused under the supervisor. Completion needs the process handle signalled
and the child's Job Object reporting no active process; the exit code is read
afterwards. A host-terminated child exits with `0x45565801`. A termination the
job cannot confirm stops host admission exactly as an unknown wait does.

Physical exit evidence and durable completion are separate. If the child was
reaped but journal persistence fails, reports retain the known exit code and
CPU/RSS. Cleanup still returns quarantine. A displayed exit code does not
release a slot or clear durable uncertainty.

Dropping a token, a failed journaled launch, unconfirmed cleanup, host death or
a transport failure never erases an active record. A launch failure or unknown
child ownership also stops current-process admission. Reopening a journal with
active records refuses all direct execution. Workspace digest reconciliation,
flock acquisition, PID absence and elapsed time cannot clear those records.
A different kernel boot identity can establish that all prior direct children
stopped. This clears process records only, never uncertain workspace effects.

## State integrity and provisioning

`provision_fresh` is explicit and requires an independently established fresh
state namespace. It creates a new directory under an existing host-private
0700 parent. `open` never creates or repairs missing state. Existing nonempty
legacy roots without lifecycle metadata receive a durable reboot barrier.
Their consent, files and inspection state are preserved, and execution stays
disabled until the operating system restarts. Restarting the application alone
does not satisfy this barrier. Missing complete journal directories take the
same conservative path; corrupt or partially missing metadata is never repaired.

The binding pins the canonical directory path, directory device/inode and lock
identity. Metadata must be bounded, regular, singly linked, owned by the host
and mode 0600. The directory must be mode 0700. Unknown or duplicate JSON
fields, unsafe modes, symlinks, replacement identities, missing files and
interrupted staging files refuse admission. Changes use a synced staging file,
atomic rename and directory sync. A visible replacement after a failed sync is
resynced before deriving authority from it.

The same checks run on Windows through `evx-workspace`'s handle-relative
layer: identity is the volume serial number plus the file index, "owned and
private" is the owner SID plus a DACL that names only the owner, SYSTEM and
Administrators, every open refuses reparse points (symbolic links, junctions
and mount points alike), the lock is `LockFileEx` on the lock file, and the
staged rename is `FileRenameInformationEx` with POSIX semantics relative to
the directory handle followed by a directory flush. One difference is in the
host's favour: the retained directory handle pins the namespace, so the state
directory cannot be renamed away while a session holds it.

Journal operations serialize through a host mutex and filesystem lock. A
bounded one-second retry handles a close-on-exec lock description transiently
inherited by another host thread's fork. A lock that remains busy fails closed.
The journal, rather than lock availability, establishes process uncertainty.

The trusted local owner can edit or roll back these files. This is not a
rollback-proof store or protection against a compromised host account.

Journal version 2 records the kernel boot identity. macOS supplies the read-only
[`kern.bootsessionuuid`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sysctl.c);
Linux supplies [`/proc/sys/kernel/random/boot_id`](https://www.kernel.org/doc/html/v6.12/admin-guide/sysctl/kernel.html#random).
Windows has no documented boot UUID; the identity is the SHA-256 of the
machine GUID (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) and the
kernel's boot counter (`HKLM\SYSTEM\CurrentControlSet\Control\Session
Manager\Memory Management\PrefetchParameters\BootId`), which the kernel
increments on every boot; both are machine-wide values that need
administrative rights to change.
The host reads these fixed OS interfaces directly, without environment or
caller overrides. Unavailable, malformed or zero identities refuse admission.
Sleep, application restart, PID reuse and wall-clock changes cannot authorize
recovery. A changed boot clears old process records and advances the session
while preserving monotonic counters. The node still recovers admitted work as
uncertain and requires ordinary file reconciliation.

A clean version-1 journal upgrades in place. A version-1 journal with active
records first persists the current boot identity and requires a subsequent
OS reboot, because its earlier process records have no boot identity. Only
a valid complete journal can use reboot recovery. Corrupt metadata or an
interrupted staging write remains refused for separate integrity investigation.

Raw `Config::new` remains a trusted embedding and test primitive. Without a
`DirectScope` it provides no durable cross-restart admission guarantee. The
production node must not fall back to that primitive when lifecycle state is
unavailable. Apple execution uses its separate permanent-slot journal.

## Verification

```sh
cargo test -p evx-supervisor --lib --test direct_lifecycle --locked
cargo clippy -p evx-supervisor --all-targets --locked --no-deps -- -D warnings
```

Unit tests cover interrupted and unknown waits, nonterminal child status,
completion failure, launch uncertainty, explicit provisioning, stale sessions,
dropped tokens, role compatibility, multiple xites, missing or unsafe metadata,
namespace replacement, failed disk persistence and transient lock contention.
Real-worker tests cover the confined compiler, guest, file helper, uncertain
write reconciliation, successful reopen and cross-xite scope rejection. The
node restart reproduction and migration/refusal tests exercise the retained
host context. Deterministic boot-transition tests cover same-boot refusal,
version-1 upgrades, changed-boot recovery, stale handles and preservation of
external effect records. The local test reads the real macOS boot identity
twice; it does not reboot the user's computer. An actual cross-reboot acceptance
run remains distinct from the simulated-transition tests. Regression evidence
is not an independent security audit.
