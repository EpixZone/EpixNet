#!/usr/bin/env bash
# Stage the managed desktop's resources in a private Linux Firefox copy.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
firefox="${1:?pass the private Firefox directory}"
[[ -d "$firefox" && ! -L "$firefox" && -x "$firefox/firefox" ]]

# Prepare complete files before replacing them. A second launch may find the
# first Firefox process still running with these resources open.
stage=$(mktemp -d "$firefox/.epix-prepare.XXXXXX")
trap 'rm -rf "$stage"' EXIT
"${CC:-cc}" -shared -fPIC -O2 -Wall -Wextra -Werror \
  "$repo/packaging/linux/sandbox-probe.c" -o "$stage/libepix-sandbox-probe.so"
mkdir -p "$stage/distribution"
cat > "$stage/distribution/policies.json" <<'POLICIES'
{
  "policies": {
    "DisableAppUpdate": true,
    "Certificates": {
      "Install": ["epix-ca.pem"]
    },
    "SearchEngines": {
      "Default": "DuckDuckGo"
    }
  }
}
POLICIES
# Let the installer check Mozilla's original update inventory as it does for
# a packaged build. Only our own resources are installed below.
if [[ -f "$firefox/precomplete" ]]; then cp "$firefox/precomplete" "$stage/precomplete"; fi
python3 "$repo/packaging/firefox-addons/install.py" "$stage"
rm -f "$stage/precomplete"
while IFS= read -r -d '' file; do
  dest="$firefox/${file#"$stage/"}"
  if cmp -s "$file" "$dest"; then continue; fi
  mkdir -p "$(dirname "$dest")"
  mv -f "$file" "$dest"
done < <(find "$stage" -type f -print0)
