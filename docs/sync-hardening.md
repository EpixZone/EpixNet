# Sync-loop hardening

EpixNet's networking has several small robustness behaviors beyond the core
announce/resync. This tracks which are in the Rust node and which remain.

## Done

- **Tracker back-off.** A tracker that has failed more than 5 times and was
  tried within the last `60 * min(30, num_error)` seconds is skipped for that
  announce pass, so a reliably-dead tracker is not hammered every round. A
  manual `siteAnnounce` still hits everything. The per-tracker stats this reads
  (`num_error`, `time_request`) were already recorded; the back-off just
  consults them. (`announce_to_trackers` / `tracker_backed_off`.)
- **Wakeup watcher.** A 30-second self-check detects a wall-clock jump larger
  than 3 minutes - the signature of the machine sleeping and resuming, which
  tokio's monotonic timers otherwise hide - and forces a fresh announce (via
  the trackers-changed notify) plus a connection sweep. A laptop that closes
  and reopens rejoins at once instead of on the next 20-minute pass.
  (`wakeup_loop` in epix-runtime.)

## Remaining (scoped, not yet built)

These are lower-frequency robustness items. Each has a clear hook into the
existing loops; none is a correctness gap (updates still propagate through the
5-minute resync and direct pushes), so they are follow-ups, not blockers.

- **retryBadFiles.** The worker returns `SyncReport.failed`, but `resync_xite`
  currently uses only `report.bytes`. The `cache.bad_files` map exists on
  settings but nothing writes it at runtime. The fix: persist `report.failed`
  into `bad_files` (with a retry count), and add a probabilistic-backoff retry
  pass (`random(0, min(40, tries)) < 4`, like EpixNet) at the tail of the
  resync tick. No new loop needed.
- **60-second modification poll.** Changes flow on the 5-minute resync or a
  direct push. EpixNet also runs a cheap ~60s `listModified` poll of connected
  peers to catch a missed push sooner. The server-side `list_modified`
  responder exists; this needs a client poll loop (new `poll_interval`) that
  issues `listModified` to a few peers per xite and enqueues changed paths.
- **Tiered idle-connection eviction.** The connection pool evicts only on a
  failed ping and caps new dials. EpixNet also closes connections idle beyond
  tiered thresholds (with a longer allowance for onion). This needs a
  `last_active` timestamp on the pooled connection and an `evict_idle` pass in
  `manage_connections`; the "close all idle after a wakeup" tier folds into the
  wakeup watcher above.

## Not needed

- **RateLimit on setSiteInfo.** EpixNet coalesces rapid `setSiteInfo` pushes
  (a burst of file-done events). A clean trailing-debounce needs an
  `Arc<AppState>` at the push site, which `ingest_file_from` (a deeply nested
  `&self` method) does not have without a wider refactor. Left for when the
  push chokepoints are next touched; the flood only causes extra page
  re-renders, not incorrect state.
