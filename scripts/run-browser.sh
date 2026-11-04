#!/usr/bin/env bash
# Launch the full desktop from this checkout, optionally opening a xite.
# Example: ./scripts/run-browser.sh talk.epix
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Linux ]]; then
  cargo build --release --locked -p epix-nmh -p evx-worker
  exec cargo run --release --locked -p epix-browser -- "$@"
fi

if [[ -z "${EPIX_FIREFOX:-}" ]]; then
  cache="$PWD/packaging/firefox-esr"
  mkdir -p "$cache"
  (
    flock -x 9
    packaging/fetch-firefox-esr.sh linux --if-needed
    packaging/linux/prepare-firefox.sh "$cache/firefox"
  ) 9>"$cache/.desktop-setup.lock"
  export EPIX_FIREFOX="$cache/firefox/firefox"
fi

# Build all three together so subsequent launches reuse the same Cargo
# feature graph. Cargo reports the executable even with a custom target dir.
browser=$(cargo build --release --locked -p epix-browser -p epix-nmh -p evx-worker \
  --message-format=json-render-diagnostics | python3 -c '
import json, sys
browser = None
for line in sys.stdin:
    event = json.loads(line)
    if event["reason"] == "compiler-artifact" and event["target"]["name"] == "epix-browser" and event["executable"]:
        browser = event["executable"]
if not browser:
    sys.exit("Cargo did not produce the epix-browser executable.")
print(browser)
')
exec "$browser" "$@"
