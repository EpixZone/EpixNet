#!/bin/sh
# Replacing Firefox libraries under a running browser can leave it unable to
# start new processes. Refuse the upgrade; never kill unrelated user browsers.
set -eu
for executable in /proc/[0-9]*/exe; do
    target=$(readlink "$executable" 2>/dev/null) || continue
    case "$target" in
        /opt/epixnet/*)
            echo 'Quit EpixNet from its tray menu and stop any standalone EpixNet server before installing or upgrading.' >&2
            exit 1
            ;;
    esac
done
