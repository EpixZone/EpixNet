# EVX release review package

This is the acceptance checklist and source handoff format for the EVX release
candidate. It does not certify security or mark the platform and hardening
milestones complete. Use the exact final source and packaged binaries for
acceptance. A result from an earlier working tree is historical evidence.

## Prepare a source snapshot

Stop source edits before exporting. From the repository root:

```sh
python3 scripts/test-evx-review-bundle.py -v
python3 scripts/evx-review-bundle.py
python3 scripts/evx-review-bundle.py --output /tmp/evx-review.zip
python3 scripts/evx-review-bundle.py --verify /tmp/evx-review.zip
```

The command without `--output` prints the proposed manifest. Export includes
only tracked files in a fixed EVX review scope, including current edits and
deletions. It records the base commit, per-file SHA-256, original Git blob,
file mode and status. Source files have a 4 MiB individual and 32 MiB total
limit; at most 2,000 files are allowed. ZIP timestamps and entry order are
fixed. No build, test, network request, extraction or upload occurs.

New untracked implementation files are omitted by default and listed under
`omitted_untracked_sources`. Review that list and explicitly select each file
needed for the candidate, for example:

```sh
python3 scripts/evx-review-bundle.py \
  --include-untracked docs/evx-mobile.md \
  --output /tmp/evx-review-with-mobile-notes.zip
```

Do not approve a candidate bundle while required source files remain omitted.
The bundle intentionally excludes raw logs, corpora, executables, caches,
local configuration, credential files and unrelated source. It rejects
symlinks, nonregular input, oversized files and non-UTF-8 content. These rules
reduce accidental disclosure; they are not a secret scanner. Inspect the
selected source and run the repository secret scan before sharing. The tool
never reads Git remotes, environment variables, signing identities or keychains.

The ZIP is a review overlay, not a standalone build tree. A reviewer obtains
the full repository at the manifest's base commit, inspects the archive,
applies its listed source replacements and deletions in a disposable checkout,
then verifies file hashes. No automatic extraction or patch execution is
provided. All ZIP members are deliberately non-executable (`0644`); restore
source executable bits from the manifest's `100755` or `100644` mode after
inspection, rather than relying on archive permissions. The verifier checks
inventory and content hashes without extraction.
Hashes detect changed bytes, but do not authenticate who supplied a bundle;
transfer its hash through the same trusted review channel as the candidate.

## Evidence required with the candidate

Keep test output separate from the source ZIP. For each evidence set, record:

- Candidate bundle SHA-256, commit, target triple, selected features, lockfile
  hashes and worker/application binary hashes.
- OS version and build, architecture, Linux kernel and Landlock ABI where
  relevant, Rust version, Apple SDK/Xcode versions and signing profile type.
- Exact command, start/end times, exit status, test counts, skipped cases and
  any failing result. Include a red-before/fixed-after record for a defect.
- Relative evidence filenames and SHA-256 hashes. Scrub tokens, real xite
  paths and identifying device details before transferring logs.
- Reviewer, review date, scope, findings and disposition. A test pass must
  identify its snapshot; never sum overlapping suites into a coverage claim.

The existing [implementation review](evx-review.md),
[internal peer review](evx-peer-review.md),
[Linux evidence](evx-linux-acceptance.md) and
[fuzz records](../fuzz/README.md) contain useful results and explicit limits.
Linux and Pulley results identify separate source snapshots. Compare their
source manifests with the candidate before relying on them; an earlier pass
does not validate later changes. Review status documents may change during
development, so the final bundle must freeze their reviewed versions too.

`python3 scripts/check-evx-fuzz-lock.py` rejects version, source or checksum
drift for package names shared by the production and fuzz lockfiles. Fuzz-only
tooling is permitted. This identity check does not compare Cargo feature
selection or prove identical dependency edges; retain target/features with
each campaign. `python3 scripts/test-evx-fuzz-lock.py` exercises the guard with
disposable lockfiles.

## Acceptance gates

| Gate | Required candidate evidence | Current source of truth |
| --- | --- | --- |
| Scope and dependency identity | Exact source inventory, production and fuzz lockfiles, signed artifact hashes, current scoped dependency and secret checks. Recheck accepted advisories and document exclusions. | `Cargo.lock`, `fuzz/Cargo.lock`, security workflow and fuzz dependency record. |
| Guest and compiler boundary | Closed Wasm profile, trusted artifact provenance, compiler containment, real fuel/memory/deadline tests, hostile IPC and worker cleanup. Test both selected engine profiles. | `evx-runtime`, `evx-worker`, `evx-supervisor`, [engineering reference](evx.md). |
| Authority and durable effects | Actual signed activation, wrapper consent, live revocation, workspace provenance, unknown effects, explicit recovery and newer-pause fencing. Test migration/reopen and two-xite isolation. | `evx-activation`, `evx-state`, `epix-evx`, wrapper tests, [workspace contract](evx-workspace-provenance.md). |
| Direct macOS package | Final signed installed application finds the correct worker, refuses modified/extra-authority workers, and passes native confinement, lifecycle and effect tests. An inert signing fixture is insufficient. | [Platform record](evx-platforms.md), macOS package verifier. |
| Developer ID XPC package | Actual release identity, final browser bundle, native isolation and supported-version acceptance. Test upgrades without reassigning permanent slots. | [Production package contract](evx-apple-production.md). Ad-hoc signed node fixtures pass; actual release signing remains unverified. |
| App Store macOS profile | Production XPC transport, authenticated host/service, bounded role messages, xite container separation, confirmed termination/accounting and real file effects in the final sandboxed bundle. Test update/reinstall and signing distribution. | [Platform record](evx-platforms.md). Fixture success does not replace this gate. |
| Linux release | Repeat native and Pulley suites after final source changes on supported architectures and kernel range. Test missing Landlock refusal, ordinary/privileged parent, installed package and upgrades. | [Linux acceptance](evx-linux-acceptance.md), native worker verifier. |
| iOS | Accepted separate-process profile, actual SDK build, signed physical-device isolation, native budgets, death observation, interruption and replay tests. Until then mobile EVX admission stays disabled. | [Mobile investigation and fixture gate](evx-mobile.md). |
| Windows and Android | Native isolation fixture execution, worker/compiler and broker integration, confined workspace operations, durable lifecycle, product packaging and background scheduling. | [Windows fixture](evx-windows.md), [Android fixture](evx-android.md). Product execution remains disabled. |
| Unsupported products | Windows/mobile download-only products continue to exclude EVX runtime dependencies. An excluded dependency graph is not a successful full product build. | `scripts/check-evx-platforms.py`. |
| Fuzzing | Final source and aligned dependency hashes, retained inputs, bounded sanitizer campaigns, replayed regressions and documented targets not exercised. | [Fuzz record](../fuzz/README.md). CI smoke or historical campaigns are not sustained final-candidate evidence. |
| Independent security review | A reviewer outside the implementation team examines the frozen boundary, reports findings, and verifies their disposition against the release candidate. | External review remains uncommissioned. The recorded separate internal pass is useful but is not this gate. |

Run the existing native ten-crate EVX suite, real-worker Pulley suite, selected
wrapper Rust/JavaScript suites and platform package verifiers documented in
`evx.md` and the CI workflows. Linux acceptance must set
`EVX_REQUIRE_LINUX_CONFINEMENT=1`, then run the worker verifier under ordinary
and privileged parents. Mobile library cross-checks and source-only platform
guards do not substitute for the corresponding native gates.

## External review brief

Provide the frozen overlay and its base repository, an architecture walk-through,
the retained finding/regression list, final dependency scan, platform evidence
and threat model. Use temporary game-score fixtures. Do not provide real
wallets, production xites, API tokens or user directories.

Ask the reviewer to trace attacker-controlled declarations, modules and
messages through consent, compilation, execution, broker calls, workspace
effects, scheduling and recovery. Focus on unsafe deserialization and native
interfaces, authority widening, stale process identity, cleanup uncertainty,
resource amplification, persistent cross-xite data and replay after crash.
Include wrapper-origin and elevated-command attacks. State which OS profiles
are enabled and which are refused.

The deliverable is a dated report with reproducible findings, severity and
impact, affected snapshot, remediation status and explicit residual limits.
Release requires disposition and regression verification for every finding.
An audit can improve confidence; it cannot establish absence of all future
engine, kernel or integration vulnerabilities. No external reviewer has been
contacted or retained by this work.
