# macOS Developer ID EVX package

The desktop browser can select the signed Apple service pool through its
`apple-xpc` build feature. This is a distinct Developer ID profile. The trusted
browser/node host remains unsandboxed, as in the existing desktop application;
each guest, compiler and file service has its own App Sandbox container. It is
not an App Store package or a claim that the bundled Firefox shell can run
inside the outer App Sandbox unchanged.

## Assembly and identity

```sh
EPIX_EVX_PROFILE=apple-xpc-developer-id \
EPIX_EVX_TEAM_ID=ABCDEFGHIJ \
EPIX_SIGN_ID='Developer ID Application: Example (ABCDEFGHIJ)' \
EPIX_EVX_SLOTS=16 packaging/macos/build-app.sh
```

The Team ID is compiled into the adapter. `release_pool.py` rejects a host
without the matching adapter/build marker, including a stale `EPIX_SKIP_BUILD`
binary. It signs a fixed pool of 1 to 64 permanent slots, each containing
separate guest, compiler and file service bundles. Each service has a private
copy of the inherited Pulley worker. The signed service configuration pins
that worker's SHA-256, role, host identifier and Developer ID client requirement.
The signed host manifest pins each service's exact code-directory hash and
Developer ID requirement. Services and workers have only their expected
sandbox/inherit entitlements, without networking, app groups or JIT permissions.

`build-app.sh` signs the browser's other nested code before the pool and outer
host, verifies the completed pool, then uses the existing optional notarization
step. The release path requires an explicit identity and Team ID. It never
falls back to ad-hoc signing. The fixture profile is separate and has no release
CLI switch.

At node startup, public Security APIs verify the current process and strict
static signature, the compiled Team ID, Developer ID certificate requirements,
hardened runtime, sealed Info.plist policy and manifest SHA-256. The node
selects the pool only after these checks. Missing policy or verification failure
leaves EVX unavailable, without a direct-worker fallback. No xite, management
request or runtime environment variable selects the backend or registry path.

## Private state and first use

The account home comes from `getpwuid_r`, not `HOME`. Production state lives at:

```text
~/Library/Containers/<signed-host-id>/Data/Library/Application Support/EpixNet/
  EVXAuthority/
  EVXProduction/registry/
  EVXProduction/node-state/
```

First use exclusively creates `EVXProduction` and durably records that creation
before checking every fixed service container. All those container roots must
be absent. An existing or uninspectable container refuses provisioning. A
concurrent or interrupted first attempt cannot be mistaken for a fresh pool.
Afterward, the registry must exist and validate. Losing the registry, deleting
its contents, or reinstalling the application does not adopt existing service
data or reset assignments. No automatic reset is provided.

This first-use check uses the unsandboxed trusted host's ordinary ability to
inspect container-root metadata. A sandboxed outer host needs a separately
verified provisioning mechanism. The service never receives the registry,
consent database, authority descriptor, or another slot's workspace.

Assignments remain permanent. Keep the host identifier, slot names and pool
size stable across releases. Updated code hashes may change while preserving
those identities. Pool resizing, identity changes, backup rollback and migration
from direct-worker state require separate, verified migration procedures. The
new production state starts with fresh consent. Existing direct state is kept.
Unresolved Apple child lifecycle records remain quarantined; this path does
not automatically clear them based on elapsed time, missing PIDs or file locks.

Path checks reject symlinks and writable ancestors except root-owned sticky
temporary directories and the exact system `/Applications` directory owned by
root and the OS `admin` group, without world write. Administrators remain trusted
installation authorities. Arbitrary group-writable package paths stay refused.

## Verification evidence and limits

The 2026-10-04 follow-up passed `cargo check -p epix-browser --features apple-xpc
--locked --offline` with the wallet build skipped. The task supplied official
Protobuf 33.0 `protoc`, verified against the release asset's SHA-256, in a
temporary directory. This checks the full browser dependency graph and Rust
integration; it does not assemble or sign the final Firefox application.

`python3 packaging/macos/xpc/test-release-pool.py` builds real adapter/node
fixtures and ad-hoc signs a separate `apple-xpc-fixture` policy. It checks
first-use provisioning, consistent reopening, lost-state refusal, existing
container refusal, tampered manifest rejection, strict release refusal of an
ad-hoc host, compiled identity mismatch and symlink rejection. It also runs
consent, manual calculation, workspace writes/reads, uncertain-write recovery,
scheduling and revocation through the signed services, both in a temporary
bundle and after installation into `/Applications`. Disposable bundles are
removed after service retirement; protected container metadata is left alone.

These fixtures exercise the production bootstrap and node adapter without
using a release signing key. Actual Developer ID certificate signing,
notarization, supported-version coverage and independent review remain external
acceptance work. The current machine has macOS 15.5; the declared minimum is
macOS 12 and needs release testing. App Store assembly remains disabled and
requires both a compatible outer host/provisioning design and Apple's review.
