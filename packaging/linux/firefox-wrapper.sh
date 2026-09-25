#!/bin/sh
# Keep Mozilla's ELF files intact. Rewriting their program headers with
# patchelf can break Firefox's own ELF loader. Limit the library search path
# to Firefox and its children so host tools launched by EpixNet stay isolated.
set -eu
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
LD_LIBRARY_PATH="$HERE:$HERE/../../lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export LD_LIBRARY_PATH
exec "$HERE/firefox" "$@"
