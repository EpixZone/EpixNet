#!/usr/bin/env bash
# Launch the full desktop from this checkout, optionally opening a xite.
# Example: ./scripts/run-browser.sh talk.epix
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" == Linux && -z "${EPIX_FIREFOX:-}" ]]; then
  cache="$PWD/packaging/firefox-esr"
  mkdir -p "$cache"
  (
    flock -x 9
    packaging/fetch-firefox-esr.sh linux --if-needed
    packaging/linux/prepare-firefox.sh "$cache/firefox"
  ) 9>"$cache/.desktop-setup.lock"
  export EPIX_FIREFOX="$cache/firefox/firefox"
fi

cargo build --release --locked -p epix-nmh -p evx-worker
exec cargo run --release --locked -p epix-browser -- "$@"
