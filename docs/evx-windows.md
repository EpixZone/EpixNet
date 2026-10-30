# Windows EVX

Windows runs EVX through the same direct worker backend as macOS and Linux:
the node's `epix-evx` service, its lifecycle journal, workspace broker,
provenance and reconciliation are one code base on all three platforms. On
Windows the confined children are less-privileged AppContainers inside Job
Objects, launched and verified by `evx-supervisor` through the primitives in
`evx-windows-native`, and the worker is `evx-worker.exe` beside
`epix-browser.exe`. The design, the Win32 mechanisms chosen for each POSIX
assumption and the facts measured while building it are in
[evx-windows-backend.md](evx-windows-backend.md). This page records what runs
on Windows, how to reproduce it, and what remains.

`evx-windows` is the native acceptance fixture: six isolation cases and a
real compile/run fixture on the same primitives the backend uses. It is not
selected by the node.

## What the node does on Windows

- The worker is pinned at service start: `evx-worker.exe` beside the running
  executable, on a local disk, with no reparse point in any path component,
  a regular file with one link, hashed once and held open with
  `FILE_SHARE_READ`. `EVX_WORKER` is not honoured on Windows; tests pin a
  worker through `EvxPlugin::with_worker`.
- The image is staged under the node's private tree, re-hashed, protected
  with a DACL for the owner, SYSTEM and `ALL RESTRICTED APPLICATION PACKAGES`,
  and held open. Every child executes the staged copy.
- Each workspace gets three retained AppContainer profiles with deterministic
  names (guest, file helper, file-read helper) and an inheritable DACL that
  lets only the two helper profiles reach it; the compiler uses one fixed
  profile. The guest cannot open the workspace natively; a native test proves
  it.
- The workspace lease is an exclusive handle on the workspace directory; a
  file helper receives a duplicate, so the lease lives as long as either
  holder. `KILL_ON_JOB_CLOSE` ends every child with its supervisor.
- The lifecycle journal, provenance records, checkpoints and the backend
  marker use handle-relative NT opens, volume serial plus file index as
  identity, owner and DACL checks in place of modes, and POSIX-semantics
  renames. The boot identity is a digest of the machine GUID and the kernel's
  boot counter.
- Execution is through the Pulley interpreter; `evx-runtime` enables it for
  every Windows build so the host's and the worker's engine keys agree.
- `evxStatus` reports `host: "windows"`. The operator socket does not exist
  on Windows, so a node with `ui_restrict` set has no caller for the
  wrapper-only commands; this is a pre-existing property of the Windows node.

## Reproducible checks

The native profile runs everything the backend depends on, inside real
AppContainers, and retains the evidence:

```powershell
python scripts/evx-platform-acceptance.py windows --output <new directory>
```

It runs, in order: the ten-crate native test suite (`evx-api`,
`evx-declaration`, `evx-runtime`, `evx-workspace`, `evx-activation`,
`evx-state`, `evx-worker`, `evx-supervisor`, `evx-host`, `epix-evx`), the
`evx-windows-native` and `evx-windows` library tests, the release build of
the fixture and both fixture executables, a build of `evx-worker.exe` and
`packaging/windows/verify-evx-worker.py` on a single-link copy of it (AMD64
image, no `userenv`, `shell32` or `ole32` import, refuses to run outside an
AppContainer), the product dependency gates
(`scripts/check-evx-platforms.py`) and the offline packaging test. The
native suites run two tests at a time: every spawning test starts two or
three AppContainer processes, and on the four-vCPU hosted runner the
default parallelism turned the suites' fixed deadlines into a measurement
of the runner. CI runs the profile as `Windows native EVX (windows-2025)`
in `.github/workflows/evx-platforms.yml`. The fixture workflow
`.github/workflows/evx-windows-fixture.yml` additionally inspects the
fixture images with `dumpbin`.

A developer run (`cargo run -p epix-browser`) finds Cargo's hard-linked
`target/debug/evx-worker.exe` beside the executable and refuses it with
"image has more than one link": the pin requires a single-link file, as
every installed copy is. Copy the worker beside the executable for a
development node; the test suites and the acceptance profile do the same.

The portable claim stays separate:

```powershell
python scripts/evx-platform-acceptance.py windows-core --output <new directory>
```

The supervisor's suites that run on Windows: `baseline`, `ipc` (with the
hostile peer example ported; the process-group and inherited-descriptor
cases stay Unix-only), `lifecycle` (including the orphaned-helper lease
case in its Windows form), `direct_lifecycle`, `workspace_provenance`,
`terminal_resources` and the new `windows_confinement` (guest denied the
workspace and the outside file while the helper profiles are allowed, a
connected pipe cannot be opened by name, the capability gate, the fixed
termination code). The node's `service` and `backend_lifecycle` suites and
the host's `content_activation` suite run on Windows; `activation_runner`
stays Unix-only because the envelope reader is.

## Native evidence

A native run on 2026-10-30 (Windows 11 Pro 10.0.26300, rustc 1.97.0, Wasmtime
48.0.8 through Pulley) passed the whole `windows` profile: 561 tests in the
ten-crate native suite, among them `evx-supervisor` 40 library tests,
`baseline` 11, `ipc` 15, `lifecycle` 18, `direct_lifecycle` 2,
`workspace_provenance` 16, `terminal_resources` 3, `windows_confinement` 7;
`evx-worker` 6; `evx-workspace` 12; `evx-host` 9 plus `content_activation`
11; `epix-evx` 58 plus `service` 39 and `backend_lifecycle` 2 against the
real confined worker; then `evx-windows-native` 22 and `evx-windows` 7, both
release fixtures (the six isolation cases; real compile/run, `evx.call`
roundtrip, cancellation and fresh execution), the worker verifier, the
product dependency gates and the packaging test. Strict Clippy on every EVX
crate and a locked all-targets workspace check passed alongside. The
profile's retained manifest is the record of a complete run.

The six fixture cases cover a valid eight-byte game response; explicit access
denials for the synthetic host record, package write, child creation and
loopback connect/listen; rejection of an allocation above the memory cap
after a small allocation succeeds; CPU termination before the wall fallback;
confirmed wall termination; and confirmed death on job close. Non-permission
errors do not count as access-denial evidence, except the child-creation
block status 367 for descendant creation. The fixture also inspects the
suspended child's handle table: the explicit reply pipe must be inherited
and a deliberately inheritable excluded event must not be.

## Remaining acceptance and integration

- External independent security review remains a release gate, as on every
  platform. No AppContainer result proves an absence of all kernel or
  runtime vulnerabilities.
- An actual cross-reboot acceptance run of the journal's reboot barrier on
  Windows remains distinct from the simulated boot-transition tests.
- Supported Windows versions and security policies: the gate requires
  Windows 10 version 1703 or newer and a working AppContainer profile API
  and fails closed otherwise; environments that disable AppContainers by
  policy have not been exercised.
- Any data directory move changes file identities and the recorded
  canonical path, so the journal and provenance bindings refuse until the
  explicit migration that does not exist yet, as on Unix. After a move the
  node starts with EVX "execution disabled: direct lifecycle state
  unavailable"; inspection and grants keep working.
- A first run as administrator leaves the state directory owned by
  Administrators; a later ordinary run then reports "EVX backend binding
  unavailable or mismatched". The remedy is to take ownership of
  `private/evx` or remove it. The installer never elevates.
- Production profiles are never deleted automatically, matching the Unix
  rule that a workspace is never reassigned after revocation; test fixtures
  delete theirs. A cleanup tool for the profiles of deleted xites is open.
- Cranelift JIT inside the AppContainer is a separately measured option;
  Pulley is the shipped engine.
- Actual release signing of `evx-worker.exe` happens in the release workflow
  with the other top-level executables; a same-publisher signature check at
  service start is a possible hardening on top of the hash pin.

## Primary API references

Microsoft documents [LPAC creation and the capability opt-out](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[creation-time job lists, handle lists and child restrictions](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information),
[job termination](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject),
[job accounting queries](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject),
[handle-relative file creation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile)
and [POSIX-semantics rename](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information).
