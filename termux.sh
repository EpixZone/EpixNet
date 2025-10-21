#!/usr/bin/env bash
# Script for running epixnet in Termux on Android

REPO_DIR="epixnet"
VENV_SCRIPT="start-venv.sh"

if [[ -d "$REPO_DIR" ]]; then
    (cd "$REPO_DIR" && git pull --ff-only)
else
    git clone https://github.com/EpixZone/EpixNet "$REPO_DIR"
fi

pkg update -y
pkg install -y python automake git binutils tor

echo "Starting tor..."
tor --ControlPort 9051 --CookieAuthentication 1 >/dev/null &

echo "Starting epixnet..."
(cd "$REPO_DIR" && ./"$VENV_SCRIPT")
