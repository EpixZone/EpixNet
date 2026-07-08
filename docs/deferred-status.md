# Deferred items: status

Where the remaining PLAN.md follow-ups stand after the parity sweep. Grouped
by whether they are done, not-applicable, or waiting on something outside the
code.

## Done in this sweep

- Authoring CLI (siteCreate/siteSign/siteVerify/dbRebuild/dbQuery/importBundle,
  crypt*, peer*).
- Plugin toggles gate their features, not just command groups.
- Tracker back-off and the wakeup watcher.
- optionalHelp / optionalHelpRemove / optionalHelpAll (opt into distributing a
  directory of optional files, or the whole site).
- Missing WS commands (siteAdd, siteClone, as, fileQuery, badCert,
  serverPortcheck/Update/Shutdown, siteSetSettingsValue, real
  siteListModifiedFiles).
- The DHT client announce/lookup loop and xid reverse/batch turned out to be
  already implemented; PLAN.md listed them as open by mistake.

## Not applicable to the Rust node

- **Stats debug pages (`/Dumpobj`, `/GcCollect`, `/Env`).** These introspect
  the Python runtime: `Dumpobj` counts live gevent/Python objects by class,
  `GcCollect` runs Python's garbage collector, `Env` dumps the interpreter
  environment. Rust has no tracing GC and no per-class live-object registry, so
  there is nothing to port. The real Stats page (peers, transfer, tracker
  health, the world map) is already served at `/Stats`.

## Genuinely deferred (own layer, not a parity gap)

- **i18n + TranslateSite.** A translation layer for the UI chrome plus the
  per-site translation plugin. Large, self-contained, and orthogonal to the
  network protocol; it changes no wire or storage behavior. Best done as one
  focused pass when the UI strings settle, especially since the xites are about
  to change shape for mobile anyway.
- **OptionalManager full accounting DB.** Per-optional-file upload / peer /
  access statistics in a dedicated table (EpixNet's `file_optional` counters).
  The hashfield subsystem that would feed it exists; the accounting table and
  its counters do not. A seeding-analytics feature, not a correctness item -
  optional files download, verify, pin, and serve today without it.
- **The three remaining sync-hardening items** (retryBadFiles, the 60-second
  listModified poll, tiered idle-connection eviction) are scoped in
  `sync-hardening.md`.

## Waiting on external resources (not code)

- **Vault + background throttling + Trayicon** (Phase 8a desktop tail). The
  vault design is carried over from Ratspeak; Trayicon and background
  throttling are desktop-shell concerns for the Tauri build.
- **Signed + notarized macOS release, Windows/Linux installers.** The build
  scripts exist; the signed release needs an Apple Developer ID, and the
  Windows/Linux installers need those machines. See `shells/README.md`.
- **Onion sign-proof to a challenging tracker** - blocked on Arti exposing the
  hidden-service key. See `tor-tail.md`.
- **Live checkpoints that need infrastructure**: a Python peer reaching our
  onion inbound, the `--tor always` zero-direct-IP clone, and real Ledger /
  Keystone / BLE-mesh device tests. All are verification runs needing a
  connected environment or hardware, not new code.
- **iOS dApp provider injection** (window.keplr into browsed pages) - deferred
  in the wallet plan; needs a persistent background bridge and a dApp to verify
  against.
