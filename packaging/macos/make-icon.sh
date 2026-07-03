#!/usr/bin/env bash
# Render a simple Epix app icon and convert it to .icns. Argument: output path.
set -euo pipefail
OUT="${1:-AppIcon.icns}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Render a 1024x1024 base PNG (Epix-blue rounded field with an "E").
python3 - "$TMP/icon.png" <<'PY'
import zlib, struct, sys
W = H = 1024
def px(x, y):
    # rounded corners
    r = 180
    cx = min(max(x, r), W - r); cy = min(max(y, r), H - r)
    if (x - cx) ** 2 + (y - cy) ** 2 > r * r:
        return None
    # An "E" mark.
    if 300 <= x <= 720 and 300 <= y <= 720:
        bars = (300 <= y <= 380) or (462 <= y <= 542) or (640 <= y <= 720)
        if (bars and 340 <= x <= 700) or (340 <= x <= 420):
            return (11, 14, 20)
        return (203, 213, 225)
    return (56, 189, 248)
raw = bytearray()
for y in range(H):
    raw.append(0)
    for x in range(W):
        p = px(x, y)
        if p is None:
            raw += bytes((0, 0, 0, 0))
        else:
            raw += bytes((p[0], p[1], p[2], 255))
def chunk(t, d):
    c = t + d
    return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
PY

# Build the iconset at the sizes macOS wants, then pack to .icns.
ICONSET="$TMP/Epix.iconset"
mkdir -p "$ICONSET"
for s in 16 32 64 128 256 512 1024; do
  sips -z "$s" "$s" "$TMP/icon.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
done
# Retina variants.
cp "$ICONSET/icon_32x32.png"   "$ICONSET/icon_16x16@2x.png"
cp "$ICONSET/icon_64x64.png"   "$ICONSET/icon_32x32@2x.png"
cp "$ICONSET/icon_256x256.png" "$ICONSET/icon_128x128@2x.png"
cp "$ICONSET/icon_512x512.png" "$ICONSET/icon_256x256@2x.png"
cp "$ICONSET/icon_1024x1024.png" "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o "$OUT"
