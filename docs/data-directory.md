# Change the node data directory

Open **Config > Storage**, enter an absolute path, and save. The change waits
for a restart. You can keep using the current node until then, or cancel the
queued move by saving its current directory again.

At the next start, EpixNet copies the latest saved node data before opening its
databases. It switches the configured directory only after the copy finishes.
The original data stays in place as a backup.

This setting moves `private/` and `data/`: node identities, settings, downloaded
xites and statistics. Browser profiles, wallet extension storage, browser
certificates and other files outside those two directories remain in their
original folder. An existing destination profile keeps its own data.

After using the Config restart button for a data move, wait for the EpixNet tray
to return, close the old browser window, and open Epix Browser from the tray.
The old window uses the previous folder's profile and certificate trust. The
restart page shows these instructions instead of reloading that window.

Choose a new directory or an existing complete node directory. EpixNet does not
merge a partially copied destination with the source. Selecting an existing
node directory switches to that identity without overwriting it.

Windows destinations must support persistent access permissions, such as NTFS.
New copies restrict private files to the current Windows user. Paths containing
spaces, Unicode, `#` or `%` are supported; browser proxy-file URLs encode the
path separately from its filesystem spelling.

## If a move fails

The startup error names the failing operation and pending move metadata. Fix
the reported problem, such as insufficient space or another running node, and
start EpixNet again. Interrupted copies recover from their operation record
and take a fresh snapshot before switching. Do not delete source data or
manually merge partial destination folders.

`lock.pid` is an operating-system lock used by the node and offline commands.
The file may remain after a normal exit. Do not delete it to bypass a running
process; close that process instead.

The destination must have room for a full copy. Keeping the source backup uses
additional space until you separately choose to remove it.

## Regression checks

Run `python scripts/test_data_relocation.py` for the actual migration and path
modules, including interrupted-copy recovery and SQLite WAL preservation. Run
`node --test crates/epix-browser/tests/pac-routing.test.cjs` for generated proxy
settings and native file URLs. On a fresh machine, set `EPIX_TEST_FETCH_DEPS=1`
for the latter command to download its locked test dependencies first.

The Windows CI job runs both suites. Runtime acceptance also needs the built
launcher, Config restart, distinct disk volumes, and the reopened browser's
HTTPS pages.
