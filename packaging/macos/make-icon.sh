#!/usr/bin/env bash
# Install the Epix app icon. Argument: output path.
# The .icns is pre-built from images/icons/epix-icon.svg in the assets repo
# (scripts/generate-icons.mjs) and checked in next to this script.
set -euo pipefail
OUT="${1:-AppIcon.icns}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/AppIcon.icns"
[ -f "$SRC" ] || { echo "missing $SRC"; exit 1; }
cp "$SRC" "$OUT"
