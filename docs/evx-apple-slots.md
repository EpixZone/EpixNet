# Permanent Apple service slots

`evx-supervisor::apple_slots` assigns each xite a permanent set of signed
guest, compiler and file-service identities. Each identity names a separate
private service container. The registry is a tested building block for the
Apple profile; it does not enable that profile in the node, launch a service,
implement file transport or prove native container isolation.

## Trusted inputs and provisioning

`AppleSlotInventory::new` accepts 1 to 64 slots supplied by trusted packaging.
Every role service ID is globally unique, including case-insensitive collisions.
Slot IDs, service names and signing requirements are bounded. These values
must never come from a xite declaration or guest request. The host must verify
that the actual signed bundles use the declared identities and do not share
containers, app groups, keychain groups or other persistent authority.

`AppleSlotRegistry::provision_fresh` creates a new registry under an existing
host-private `0700` parent. The caller supplies an installation identity from
trusted installation metadata. Provisioning refuses an existing directory,
including an empty directory left by a failed attempt. `open`, `lookup` and
`allocate` never provision, reconstruct or repair missing state.

The provisioning precondition is stronger than a missing directory: the host
must independently establish that every service container is fresh and has
never held another xite's data, and reserve the pool exclusively for this one
trusted registry path. A second registry must not manage the same identities,
even if neither registry has launched work yet. Reinstalling the app, deleting
this registry or choosing a new installation identity does not establish that
condition.
There is no guest API and no automatic provisioning path in the node.

Store the registry outside every service container and outside every service's
native filesystem authority. Ownership and POSIX mode checks are necessary
but do not establish that an App Sandbox service lacks access. The signed
package's sandbox and entitlement acceptance tests must prove that separately.
The unconfined host owns this directory and its namespace; arbitrary writes by
that owner are outside this store's integrity boundary.

## Allocation and upgrades

Each operation opens a new lock file description and takes a bounded exclusive
`flock`. This serializes separate processes as well as simultaneous calls on
one registry handle. Allocation writes a bounded snapshot to a new staging
file, syncs it, atomically replaces the registry and syncs the directory.
Only then does it return an assignment that a caller may use to launch work.
A failed call may have committed an assignment, so retrying the same xite is
idempotent and never frees the slot. Every returned assignment, including an
existing one read after reopening, re-establishes file and directory durability.
A prior rename followed by a failed sync cannot become usable authority merely
because another handle can read it.

Assignments cannot be deleted or reassigned. An exhausted pool refuses new
xites while existing xites retain their identities. Removing a xite, revoking
consent, uninstalling a page or restarting the app does not make its containers
safe for another xite. There is intentionally no release/reset method.

The persisted inventory identity includes slot IDs and all three role service
IDs. Trusted signing requirements are current package policy, so an ordinary
package upgrade can update them without moving a xite to another container.
Adding, removing or renaming slots or service IDs refuses the old registry.
Such changes require a separately reviewed migration preserving every used
assignment; no such migration is implemented here.

On macOS with `apple-xpc`, `AppleWorkspace` binds the assignment to one host
control directory and a durable worker lifecycle journal. Its configuration
selects the guest, compiler and file services. `AppleSlotAssignment::xpc_config`
remains an unbound trusted transport primitive. See the
[workspace and lifecycle contract](evx-apple-workspaces.md) for checked
activation, private file storage and uncertainty handling. Neither API enables
the App Store node profile.

## Failures and backup limits

The registry binds the installation, inventory, directory device/inode,
lock device/inode and any initialized workspace-control directory identities.
It refuses missing files, symlinks, hard-linked files,
unsafe owners/modes, nonregular or oversized input, unknown JSON fields,
duplicate JSON keys, unknown entries, duplicate assignments and out-of-pool
bindings. A crash staging file causes refusal rather than silent cleanup.
An old handle also refuses a lost or replaced directory. None of these checks
provides cryptographic authentication against the trusted local owner.

Never restore an older registry against newer service containers. A valid old
snapshot can omit an allocation made afterward and falsely describe a used
container as unused. There is no external monotonic counter or rollback-proof
keystore, so restoration that preserves all checked identities cannot be
detected here. Copying the store to new inodes also fails closed and requires
an explicit migration. Losing the registry makes the existing service pool
unavailable; it does not justify provisioning an empty replacement.

A supported restore procedure must preserve all historical assignments and
coordinate the registry with the actual service containers, or provision a
different independently fresh set of service identities after stopping all
old services. Filesystem durability and restore behavior remain release
acceptance checks on the deployment filesystem. Backups of the JSON file
alone are not a recovery design.

## Verification

Disposable tests exercise reopen/idempotence, exhaustion, identity validation,
trusted signing-policy upgrades, same-handle thread contention, independent
process allocation, bounded lock waits, lost/corrupt state, unsafe modes/links
and replacement identities. An injected sync failure verifies that reopening a
visible snapshot does not bypass durability. The ignored subprocess entry
point is invoked by the parent test.

```sh
cargo test -p evx-supervisor --lib --test apple_slots --locked
cargo test -p evx-supervisor --lib --test apple_slots --features apple-xpc --locked
```

The second command also checks assignment-to-adapter configuration on macOS.
These tests allocate only temporary host directories and fixture service IDs.
They do not create or inspect real user service containers or launch guests.

The 2026-10-03 internal peer review found no additional registry issue within
the trusted-root contract and independently reran the default tests: 8 unit
and 14 integration tests passed, with the subprocess fixture intentionally
ignored as a standalone test. The macOS feature run passed 8 unit and 15
integration tests, and strict feature Clippy passed. This is internal code
review and fixture validation, not an external audit or Apple release approval.
