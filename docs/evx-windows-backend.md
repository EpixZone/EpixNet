# EVX Windows execution backend

This document is the design the Windows backend is built to. It turns the
native isolation primitive described in [evx-windows.md](evx-windows.md)
into a product backend that the node selects on Windows, with the same
invariants the macOS and Linux direct backend upholds. The numbered risks
and POSIX assumptions it answers are the ones listed in the consolidated
engineering map that preceded it; each section names the Win32 mechanism
chosen and why.

## Approach: port the direct backend, do not twin it

The node service (`epix-evx`) drives one execution contract:
`evx_host::run_content_activation_with_admission` over an
`evx_supervisor::{Broker, Config}` pair, a restart-safe lifecycle journal, a
workspace lease and a reconciliation path. All of that logic is portable;
only four layers underneath it are POSIX: descriptor-relative file access
(`evx-workspace`), `flock` leases, fork/exec/`wait4` child management with
Landlock, seccomp or Seatbelt confinement, and the kernel boot identity.

The Windows backend therefore keeps every portable module and replaces the
four POSIX layers behind small platform seams:

| Layer | Unix today | Windows |
| --- | --- | --- |
| Directory authority and file identity | `openat` on an `O_DIRECTORY` descriptor, `st_dev`/`st_ino`, `st_nlink`, modes 0700/0600, `fsync` | `NtCreateFile` relative to a directory handle, volume serial plus file index, `NumberOfLinks`, owner SID plus protected DACL, `FlushFileBuffers` and POSIX-semantics rename |
| Workspace lease | `flock` on the workspace descriptor, inherited by the file helper as descriptor 3 | A second handle on the workspace directory opened with `DELETE` access and `FILE_SHARE_READ | FILE_SHARE_WRITE`; a second lease fails with a sharing violation, a duplicate is placed in the file helper, and the lease lives as long as any holder |
| Confined children | fork, `pre_exec`, process groups, `wait4`, Landlock/seccomp/Seatbelt installed by the child | `CreateProcessW` into a less-privileged AppContainer and a Job Object, verified by the host before `ResumeThread` and re-verified by the child before it reads input |
| Boot identity | `kern.bootsessionuuid`, `/proc/sys/kernel/random/boot_id` | SHA-256 of the machine GUID and the kernel boot counter, both read from `HKLM` |

The rejected alternative, a separate `WindowsBackend` in the node like the
Apple service pool, would have duplicated the journal, provenance and
effect-outcome logic, and every later fix would have had to be made twice.

## Crates

- `evx-windows-native` (new): the Win32 primitives with no EVX policy in
  them: RAII handles, SDDL and ACL helpers, AppContainer profiles, job
  objects, proc-thread attribute lists, LPAC launch and token validation,
  named-pipe pairs, process usage queries, registry reads. It is empty on
  other targets. `evx-supervisor`, `evx-worker`, `evx-workspace` and the
  `evx-windows` fixture crate use it; nothing in it depends on them.
- `evx-workspace`: cross-platform. `Dir` is an owned directory handle with
  handle-relative operations; `Lease` is the cross-process workspace lease.
  The Unix implementation is the existing `rustix` code behind the new
  names; the Windows implementation is new.
- `evx-supervisor`: cross-platform. `process/common.rs` keeps the portable
  peer state machine, `process/unix.rs` and `process/windows.rs` are the
  platform peers (launch, measurement, termination), `windows/` holds the
  staged image and the profiles; the journal, provenance, broker and
  reconciliation modules use `Dir`.
- `evx-worker`: builds on Windows. Every mode verifies its own confinement
  before reading a byte, as the Unix modes do.
- `evx-host`, `epix-evx`: the crate-level gates are lifted; no logic
  changes beyond Windows arms for worker identity and the private-tree
  checks.
- `evx-windows`: remains the native acceptance fixture, now built on the
  shared primitives.

## Confinement model

Every child runs under a less-privileged AppContainer with zero
capabilities, the ALL APPLICATION PACKAGES opt-out and the child-process
restriction, inside a Job Object with `KILL_ON_JOB_CLOSE`, one active
process, process and job memory limits, user-time limits and
`DIE_ON_UNHANDLED_EXCEPTION`. The host verifies the token and the job
membership while the child is still suspended; the child verifies the same
facts about itself before parsing input, so neither side trusts the other's
word for the boundary.

Three AppContainer profiles exist per workspace, with deterministic names so
the mapping is permanent and needs no registry file, plus one fixed profile
for the compiler, which touches no files and has no workspace when it runs:

```
Epix.Evx.<24 hex of SHA-256(canonical workspace path)>.g   guest
Epix.Evx.<24 hex ...>.f                                   file helper, read and write
Epix.Evx.<24 hex ...>.r                                   file-read helper
Epix.Evx.compiler                                         compiler
```

The guest profile has no ACE anywhere except the staged worker image. The
workspace directory carries inheritable ACEs for the `.f` profile (read,
write, add file, add subdirectory, delete child) and the `.r` profile
(read and list only). The `.evx-provenance` directory, the lifecycle
journal, the SQLite state, the checkpoints and every other xite's workspace
carry no package ACE, so a confined process can reach exactly what the
Unix helper's Landlock rules allow and nothing else. The guest and the file
helper are different identities on purpose: with one container per xite
the guest could have opened the workspace directly and bypassed the
broker's quota and provenance. A native test proves the guest profile
cannot read the workspace while the `.f` and `.r` profiles can.

Measured during implementation: Windows silently skips propagating a new
inheritable DACL to existing children while a lease handle on the directory
is held. Preparation therefore resets every existing descendant to pure
inheritance itself, in a bounded handle-relative walk that skips reparse
points, and runs in `Broker::new` before any lease exists and again at every
spawn that names a workspace. Files created after preparation inherit the
entries at creation.

The staged worker image lives in a host-private staging directory, not in
`%TEMP%`: `<staging>/worker/<sha256>/evx-worker.exe`, written from the
trusted bytes, re-hashed after the write, held open with `FILE_SHARE_READ`
for the life of the service so nothing can replace it, and readable by
`ALL RESTRICTED APPLICATION PACKAGES` (`S-1-15-2-2`), which is the group
every LPAC token carries and no ordinary AppContainer does. The node stages
under `private/evx/windows`; a `Config` without an explicit backend (the
test and harness primitive) stages under `%LOCALAPPDATA%\Epix\evx-stage`.
The enforced property on the image is that it imports no host-only DLL
(`userenv`, `shell32`, `ole32`); the measured import set is `kernel32`,
`ntdll`, `advapi32`, `bcryptprimitives` and the C runtime. The fixture
workflow and `packaging/windows/verify-evx-worker.py` both inspect it.

Guests and compilers run with the staged image's directory as their working
directory, which an LPAC token can open; the `"/"` the Unix compiler driver
passes is ignored on Windows. File helpers run with the workspace as their
working directory and never depend on it.

## Worker identity

The worker is `evx-worker.exe` beside the node executable, which on Windows
is `epix-browser.exe` under `%LOCALAPPDATA%\Epix`. That directory is
writable by the user, exactly as the node executable itself is, so the
worker is trusted to the same degree as the node. The service pins it at
start: local disk only, no reparse point in any component, a regular file
with one link, hashed once, and the handle kept open so the image that is
staged is the image that was hashed. `EVX_WORKER` is not honoured on
Windows; tests pin a worker through `EvxPlugin::with_worker`.

## Lease and durability

The lease handle is opened with `DELETE | SYNCHRONIZE` and shares read and
write. Sharing checks only involve read, write and delete access, so the
broker's ordinary directory handle (list, add file, add subdirectory,
traverse; shares everything) coexists with it, Explorer and antivirus
listings keep working, files inside the directory can still be created
and replaced, and a second lease, which also asks for `DELETE`, fails with
`STATUS_SHARING_VIOLATION`. This was verified empirically: the second open
fails with error 32, a child that holds a copy of the handle keeps the
lease after the parent closed its own, and the lease releases when the
child dies. A quarantined broker never closes its lease handle, matching
the Unix rule that a quarantined lease is never unlocked.

The copy reaches the file helper through `DuplicateHandle` into the
suspended child, and the child reads the handle value as an eight-byte
preamble on its standard input before the first frame. Marking the lease
inheritable instead, even only for the duration of the launch, let any
concurrent `CreateProcess` in the host that inherits handles without an
explicit list copy it too; a long-lived process such as the browser would
then hold the workspace busy for as long as it lived. The duplicate
carries only the rights its role needs: list, traverse and read
attributes for a read-only helper, plus add file and add subdirectory
for a writing helper, never delete; the worker refuses an adopted handle
with more. The pipe ends are created non-inheritable and are marked
inheritable only for the duration of the `CreateProcessW` call, so a
concurrent spawn elsewhere in the host cannot pick them up.

`KILL_ON_JOB_CLOSE` ends a helper when its supervisor dies, so unlike Unix
a Windows lease cannot outlive its supervisor through an orphaned helper.
The lifecycle test for that case shows the helper's copy alone holding the
workspace busy, then the job ending the helper when the supervisor crashes.

Persisting a journal, a provenance record or a checkpoint writes a
`.pending-` sibling, flushes it with `FlushFileBuffers`, renames it over
the target with `FileRenameInfoEx` and `FILE_RENAME_POSIX_SEMANTICS`
relative to the directory handle, and flushes the directory handle. NTFS
journals the rename itself; the directory flush is the closest equivalent
of the POSIX directory `fsync` and is kept for the same reason.

Identity of a directory, lock file or workspace root is the volume serial
number plus the 64-bit file index from `GetFileInformationByHandle`. A
data directory move changes it, which refuses the journal and provenance
bindings until explicit migration, as on Unix.

Private directories are created with an explicit protected DACL: the owner
and SYSTEM only. "Private" checks replace `uid == euid && mode & 077 == 0`
with "owner is this token's owner and every allow ACE names the owner,
SYSTEM or Administrators"; the workspace root is the one directory that
may additionally name its own two helper profiles.

## Boot identity

Windows has no documented boot UUID. The journal's boot session is the
first 16 bytes of SHA-256 over the machine GUID
(`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`) and the kernel's boot
counter (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory
Management\PrefetchParameters\BootId`), which the kernel increments on
every boot. Both are machine-wide registry values that no caller, page or
environment variable can influence; neither depends on wall time. A read
failure disables process recovery exactly as it does on Unix.

## Engine profile

Windows executes through Pulley, the Wasmtime interpreter, with
`signals_based_traps` off, as the native fixture already did and as iOS
does. `evx-runtime` enables the Pulley backend for every Windows build, so
the host's engine key and the worker's always agree without feature
coordination between crates. Cranelift JIT under LPAC is left as a later,
separately measured option.

## Process layer

`Peer::spawn` on Windows: stage the worker (once per service), pick the
profile for the role, create three named pipes with a DACL naming only the
owner and SYSTEM (the host's write end is non-blocking so the bounded input
queue works as on Unix; the host's read ends block so the reader threads
do), create the job with fixed backstop limits (2 GiB committed per process
and per job, 600 s of user time, one active process, kill on close, die on
unhandled exception; the supervisor enforces the real budgets by
observation exactly as on Unix), launch suspended with the explicit handle
list, validate the token, the zero capabilities, the exact package SID and
the job membership, hand over the lease copy for file roles, then resume.
Reader threads over the pipe handles feed the same event channel the Unix
arm uses. `measure` reads `GetProcessTimes` and the process's peak working
set, which is monotonic and therefore the conservative figure for a budget
that must not miss a short peak; terminal accounting comes from the same
objects after the process handle signals and the job reports no active
process. `close` terminates the job and waits; Windows has no cooperative
termination signal, so the grace period is not observed. A termination
that cannot be confirmed quarantines the process-wide child admission
latch, as on Unix.

Exit codes: a child terminated by the host exits with `0x45565801`; the
Unix convention of negative signal numbers does not exist. The supervisor
reports the host's own termination as a cancellation or limit outcome from
its event loop, never from the exit code, on both platforms.

## Known limits, stated

- The operator socket does not exist on Windows, so a node with
  `ui_restrict` set has no caller for the wrapper-only commands. This is a
  pre-existing property of the Windows node, unchanged here.
- A data directory move changes file identities and refuses the journal
  and provenance bindings until the explicit migration that does not exist
  yet, as on Unix.
- NTFS is case-insensitive per directory by default. Two spellings of one
  name are refused as a divergence, never aliased; this matches APFS.
- The reserved device names (`CON`, `NUL`, `COM1` and the others) are
  rejected by the Windows reader. Handle-relative NT opens do not apply the
  Win32 name rewriting, but the host rejects them anyway so no path reaches
  a Win32 call by accident.
- Production profiles are never deleted automatically, matching the Unix
  rule that a workspace is never reassigned after revocation; test fixtures
  delete the profiles they created. Windows gives every profile a package
  folder under `%LOCALAPPDATA%\Packages` with a full-control entry for the
  package; the backend locks that folder down to the owner and SYSTEM when
  it creates or adopts a profile, and a native test proves no container can
  write to or list its own folder. Stale staged images are pruned when a
  newer image is staged.
