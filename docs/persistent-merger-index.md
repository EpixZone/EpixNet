# Persistent merger indexing

Version-3 merger databases now use disposable SQLite projections in
`<data-root>/private/cache/merger-index-v1/`. Ordinary per-Xite databases retain
the existing in-memory behavior. The cache filename binds the frontend's canonical
address, storage root, accepted merger types, and complete schema. No Xite can
choose an arbitrary cache path through `db_file`.

## Updates and authority

Each cache stores a private source ledger keyed by canonical hub and input path.
A source version binds the accepted JSON digest and its verified authority
context. Updating or withdrawing a source compares the expected previous version
and commits the source ledger and projected rows in one SQLite transaction.
An unchanged source does not rewrite its rows. A changed authority with identical
accepted JSON updates its checkpoint without replaying the projection.

Existing schemas can map several inputs to the same `json_id`, such as a profile
and its sibling posts file. The index tracks those source relationships and
replays only the connected mapping group in deterministic order. It preserves
profile columns and independent inputs when one sibling changes or disappears.
A UNIQUE constraint that would replace another source's rows fails the whole
transaction. Node-created indexes bound deletion by `json_id` even when the app
schema did not provide that index. Internal tables use the reserved `__epix_`
namespace and are denied to app-supplied queries and schema definitions.

A normal data-file ingest verifies that input and applies it directly when all
merger receipts cover the preceding source generation. A concurrent, pending,
manifest, schema, or filter change falls back to reconciliation. Reconciliation
skips hubs whose authority and source receipts are unchanged within the process,
verifies one changed hub snapshot at a time, and removes obsolete sources. It
does not recreate every merger database or collect every hub's JSON together.

A source checkpoint is not independent permission to expose cached rows. Query
handles are withdrawn before persistent mutations, and receipts are checked
again before installation and after queries. Root authority, source generations,
merger permissions, filters, canonical storage roots, and target membership must
still match. Failed verification never authorizes an old aggregate. A query that
cannot obtain a stable valid receipt returns an error instead of stale rows.
Writer and authority guards belong to completion tasks, so cancelling a caller
cannot release them while a blocking SQL worker is still running.

## Restart, repair, and retirement

During startup, merger reconciliation waits until the complete persisted Xite
registry has been restored. Restoring the frontend first or last cannot publish
an empty aggregate or prune hubs that have not loaded yet. Startup still performs
normal manifest and record verification. SQLite structural validation checks the
cache before opening it, and matching source versions then reuse existing rows.
This saves projection rebuild work; it does not make startup constant time.

A malformed or structurally incomplete private cache can be discarded once and
rebuilt from verified sources. Active database leases prevent recovery from
unlinking a cache still in use. Explicit `dbRebuild`/`dbReload` repairs projections
by clearing the ledger and rows transactionally, then reconciling. Lazy queries
request reconciliation without resetting the whole index.

Removing a frontend or changing its schema retires unused cache generations.
Prepared work stays private across freshness retries for the same schema and
context, reusing completed hubs whose authority and filter receipts still match.
Unpublished preparations are retired on terminal reconciliation failure or when
their schema/context generation is abandoned. SQLite connections, database
handles, and workers retain a shared file lease; deletion waits until the final
lease closes. Normal shutdown preserves
published caches. A verified reopen of the same schema/context can cancel pending
retirement. Durable retirement markers allow a later startup to retry cleanup.
None of these operations deletes signed source files or optional media.

## Measurement and remaining work

Use the [signed benchmark harness](merger-index-benchmark.md) to measure indexing,
existing indexed queries, independent-segment updates, restart reuse, resource
usage, and correctness. Its work counters distinguish skipped sources from SQL
replay. One verified input counter does not imply constant work in the hub's
metadata: the current authority lookup and fingerprint still traverse its
accepted manifests and declarations. Full reconciliation holds one hub snapshot
at a time. Large hubs must therefore remain bounded.

This foundation preserves existing per-file CRDT folding. It retains accepted
source versions and tombstones in the private ledger but does not implement
Trove's future cross-segment winner resolution, authenticated compaction, full-text
query API, pagination protocol, per-application hub selection, or incremental
rating aggregates. Generic SQL query limits are unchanged. Restart signature
verification, cache integrity scans, browser/mobile performance, and sustained
network/transfer workloads remain separate scale requirements. A successful
foundation benchmark does not certify the full Trove release targets.
