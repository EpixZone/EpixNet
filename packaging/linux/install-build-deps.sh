#!/usr/bin/env bash
# Ubuntu/Debian development host or ephemeral CI/container dependencies.
set -euo pipefail
if (( EUID != 0 )); then
  exec sudo -- bash "$0" "$@"
fi
apt-get update
ALSA=libasound2
if apt-cache show libasound2t64 >/dev/null 2>&1; then ALSA=libasound2t64; fi
apt-get install -y --no-install-recommends \
  build-essential binutils ca-certificates curl git python3 pkg-config \
  protobuf-compiler libudev-dev libgtk-3-dev libayatana-appindicator3-dev \
  libxdo-dev libssl-dev zlib1g-dev librsvg2-dev libgirepository1.0-dev \
  libnss3-tools libdbus-glib-1-2 "$ALSA" \
  dpkg-dev desktop-file-utils xdg-utils file xz-utils \
  shellcheck xvfb xauth
