#!/usr/bin/env bash
#
# Reclaim disk from cargo's target/ dir.
#
# cargo never garbage-collects old build artifacts: every `cargo build`/`test`
# leaves a fresh hashed binary in target/*/deps and keeps all the previous
# ones. After a few dozen release builds of epix-server that is tens of GB of
# dead weight (each epix_server-<hash> is ~100 MB).
#
# Default run prunes safely without a full rebuild:
#   - drops target/*/incremental (regenerated on the next build)
#   - in target/{debug,release}/deps, keeps only the newest artifact of each
#     name and deletes the older duplicates
# The newest set is what the last build linked, so the current binaries still
# run; at worst a later build with a different feature set recompiles a crate.
#
# Usage:
#   scripts/clean-build-cache.sh          # safe prune (default)
#   scripts/clean-build-cache.sh --deep   # full `cargo clean` (rebuilds all)
#   scripts/clean-build-cache.sh --dry-run # show what would be removed
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET="${CARGO_TARGET_DIR:-target}"
DRY_RUN=0
DEEP=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --deep) DEEP=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

avail() { df -g . | awk 'NR==2 {print $4}'; }
before=$(avail)

if [ ! -d "$TARGET" ]; then
  echo "no $TARGET/ dir, nothing to do"
  exit 0
fi

if [ "$DEEP" -eq 1 ]; then
  echo "cargo clean (full wipe)…"
  [ "$DRY_RUN" -eq 1 ] || cargo clean
  echo "reclaimed $(( $(avail) - before )) GB (was ${before}GB free)"
  exit 0
fi

# 1. Incremental caches - always safe to drop.
for inc in "$TARGET"/*/incremental; do
  [ -d "$inc" ] || continue
  echo "rm incremental: $inc"
  [ "$DRY_RUN" -eq 1 ] || rm -rf "$inc"
done

# 2. Stale duplicates in deps/: keep the newest file per stem (name with the
#    trailing -<hash> and extension stripped), delete older ones + their .d.
for dir in "$TARGET"/debug/deps "$TARGET"/release/deps; do
  [ -d "$dir" ] || continue
  # newest first, so the first time we see a stem we keep it and delete the rest
  find "$dir" -maxdepth 1 -type f ! -name '*.d' -exec stat -f '%m %N' {} + \
    | sort -rn \
    | awk '{
        path = substr($0, index($0, " ") + 1)
        file = path; sub(/.*\//, "", file)              # basename
        # Group by name with the -<hash> removed but the extension kept, so
        # libfoo-<h1>.rlib and libfoo-<h2>.rlib share a key (keep newest) while
        # libfoo-<h>.rlib and libfoo-<h>.rmeta stay distinct (both kept).
        if (match(file, /-[0-9a-f]{8,}(\.[a-z0-9]+)?$/)) {
          hstart = RSTART                               # start of -<hash>
          tail = substr(file, hstart)                   # -<hash>[.ext]
          ext = ""
          if (match(tail, /\.[a-z0-9]+$/)) ext = substr(tail, RSTART)
          key = substr(file, 1, hstart - 1) ext
        } else {
          key = file                                    # no hash: unique, keep
        }
        if (seen[key]++) print path                     # a stale duplicate
      }' \
    | while IFS= read -r f; do
        echo "rm stale: $f"
        [ "$DRY_RUN" -eq 1 ] || { rm -f "$f" "${f%.*}.d"; }
      done
done

after=$(avail)
if [ "$DRY_RUN" -eq 1 ]; then
  echo "(dry run) nothing deleted"
else
  echo "reclaimed $(( after - before )) GB (now ${after}GB free)"
fi
