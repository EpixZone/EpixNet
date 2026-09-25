#!/bin/sh
# Package-manager hooks run as root. Never write into a user's home or start
# the network here; desktop discovery is system-wide, user settings are not.
set -eu
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t /usr/share/icons/hicolor || true
fi
if [ -f /usr/share/epixnet/enable-sandbox.sh ]; then
    bash /usr/share/epixnet/enable-sandbox.sh --if-needed ||
        echo 'EpixNet: run sudo bash /usr/share/epixnet/enable-sandbox.sh to enable the Firefox sandbox.' >&2
fi
