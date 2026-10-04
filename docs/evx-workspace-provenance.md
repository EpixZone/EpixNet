# Workspace read provenance

A filename and link count do not prove where file bytes came from. The review
reproduced a race in the descriptor-relative reader: another process creates a
hard link to an outside fixture, the helper opens the workspace alias, and the
alias is replaced before `fstat`. The opened inode then has one remaining link
outside the workspace and passed the old check.

EVX now validates read results against host-owned write provenance before any
bytes reach the guest or the returned response history. The low-level workspace
crate still refuses symlinks, special files and observed multiple links, but it
no longer claims those checks alone eliminate concurrent hard-link replacement.

## Authority and durability

Each broker uses a registry under its workspace parent's `.evx-provenance/`
directory. The directory is outside the workspace, mode 0700, owned by the host
user, and never passed to a worker. Registry files are mode 0600. Symlinked,
linked, oversized, malformed or incorrectly owned authority files are refused.
The records bind the xite, canonical workspace path digest, device and inode.
Another xite, a substituted workspace root or a copied registry cannot silently
inherit those records.

The existing workspace lease serializes readers, writers and reconciliation
across brokers and host processes. Before sending a native helper `Commit`,
the supervisor records the exact authorized path and the SHA-256 of the write
request's text. It writes a temporary registry file, syncs it, renames it and
syncs the authority directory. Failure prevents the native commit. The ordinary
workspace file format remains unchanged.

Each path has at most one committed digest and one pending digest. A clean
helper completion durably promotes the pending digest. Uncertain completion
retains both possible authorized versions. Metadata is bounded to 128 paths
and 128 KiB per workspace. The store cannot grow an unlimited digest history.
Failed commit delivery and cancellation after an acknowledgement still require
reconciliation until helper exit and metadata finalization are confirmed.

For a successful read, the supervisor checks the expected response type,
canonical base64, decoded length, 2 KiB content limit and exact path digest.
Only a committed or pending authorized version is returned. A mismatch becomes
a fixed denial, with the unapproved data discarded. Write acknowledgements
must match the request's byte length and follow commit authorization.

## Explicit reconciliation

`evx_supervisor::reconcile_workspace` is a host management operation. It takes
the workspace lease and reads pending paths through real read-only confined
helpers. It does not execute a guest program, replay a write or give a guest
additional capabilities. The helpers have bounded frames, output, deadlines,
CPU and memory observations, and confirmed cleanup. Cleanup uncertainty
quarantines further child admission.
Closing both helper streams is not proof of process exit. Reconciliation keeps
checking process state and its deadline until the helper is reaped.

An explicit operator action may promote only an observed committed or pending
version. An explicit final-file `ENOENT` observation can clear a pending entry
when the first write never reached rename. Permission, malformed-data and other
read errors cannot stand in for absence. Unknown existing bytes remain denied.
A partial reconciliation is durable if a later path fails.

A disabled or write-only guest grant can be host-reconciled because the operator
owns this management action; the guest grant remains unchanged. Generation
changes interrupt the operation. With no pending entries, reconciliation starts
no child and works without a worker binary. The caller must finish it before
clearing the job's reconciliation pause. New different content is refused while
an earlier write remains pending; retrying the same authorized bytes is allowed.

The node's `evxJobResume` reconciles before clearing a pause. The explicit
`evxRecoverWorkspace {xite?}` command recovers interrupted manual writes without
running a guest or resuming jobs. Both use the xite's execution lock; recovery
keeps that lock on the blocking thread even if its requesting socket disappears.
Recovery brokers receive revocation and limit updates under the host policy
lock. Plugin changes cancel the confined read loop. Quarantine, unknown contents
and failed recovery leave the job paused. With no pending paths, a missing
worker does not prevent recovery.

A durable per-xite management revision fences resume against later pauses,
enable/disable actions and other resumes, even when their value is unchanged.
The comparison and pause clear share a SQLite transaction. Schema 9 adds one
bounded counter per xite; migration preserves existing controls, the counter
survives job withdrawal and restart, and exhaustion fails without mutation.
This lets a later pause take effect immediately while recovery is still busy.

Execution keeps the same xite lease until its run history and job result,
including any reconciliation pause, are persisted. Cancelling the requesting
task does not release a live worker's lease or detach it from revocation.
An owned completion task finishes the record, while the blocking supervisor
retains its own lease reference through native cleanup. Shutdown stops new
admission and revokes registered brokers; completion remains asynchronous.
Plugin policy is captured before task dispatch and lock waiting, so a queued
request cannot miss a disable followed by re-enable.

A resume request reconciles the pending workspace state it finds after
obtaining the execution lock. If it was queued behind a run, that includes
file effects the run reported before releasing the lock. Recording that
outcome does not itself invalidate the queued request. A newer explicit
operator pause, enable/disable action or resume does invalidate it. This is
recovery of current authorized file state, not acknowledgment of one particular
previously displayed result; future non-file effects need their own recovery
contract.

Recovery uses the wrapper's explicit host management confirmation or the local
operator API. It does not require granting the publisher global ADMIN. A page's
request is intercepted by the wrapper, bound to its own xite and never directly
forwarded as a privileged command. The server rejects raw page commands,
forged elevated IDs and ADMIN rebinding. The `/list` panel remains inert and
shows recovery instructions only outside restricted gateways.

## Existing data and limits

Existing files are preserved but are never automatically enrolled from their
contents. Without a prior authorized digest, reading them is denied. A new
authorized write can replace a legacy file normally. If that write stops before
replacement, the unknown old bytes cannot be adopted by reconciliation. An
operator can preserve the old file outside the workspace and reconcile its
absence, or retry the exact authorized write. There is no guest enrollment API.
A restored or replaced workspace root requires an explicit host migration;
inode identity changes are not silently trusted.

This boundary assumes the host authority directory itself is trusted. An
unconfined process with permission to rewrite that directory can change host
authority just as it could rewrite the grant database. The registry protects
against workspace namespace/content replacement; it does not make a compromised
host trustworthy or replace OS containment of native helpers. Private registry
I/O remains trusted host filesystem work.

Tests cover the original broker leak before the fix, a continuous hard-link and
symlink replacement race after the fix, substituted staged bytes, restart,
root/xite binding, bounded metadata, malformed read shapes, corrupt authority
storage, uncertain writes before and after rename, and explicit reconciliation.
They also cover malformed acknowledgements, commit-pipe failure, cancellation
after acknowledgement, hostile reconciliation helpers and stream EOF before
helper exit.
