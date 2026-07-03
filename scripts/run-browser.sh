#!/usr/bin/env bash
# Run the Epix desktop browser for local testing.
#
# `cargo run -p epix-browser` does NOT build the native-messaging host
# (epix-nmh), which the extension talks to for the Tor status icon and name
# resolution. If that binary is missing or stale the Tor icon shows "Off". This
# helper builds both, then runs the browser. Pass a xite as an argument, e.g.
#   scripts/run-browser.sh talk.epix
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p epix-nmh
exec cargo run --release -p epix-browser -- "$@"
