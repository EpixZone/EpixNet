#!/usr/bin/env bash
# Permit Firefox's own user-namespace sandbox on Ubuntu's restricted setup.
# Installed packages call this directly; the launcher embeds it for pkexec.
set -euo pipefail

original_args=("$@")
firefox_path=''
if_needed=0
print_profile=0
while (( $# )); do
    case "$1" in
        --if-needed) if_needed=1; shift ;;
        --print-profile) print_profile=1; shift ;;
        --firefox-path) firefox_path="${2:?Missing Firefox path}"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

profile=epixnet-firefox
attachment='/{opt/epixnet/firefox/firefox{,-bin},tmp/.mount_EpixNe??????/usr/bin/firefox/firefox{,-bin},tmp/appimage_extracted_*/usr/bin/firefox/firefox{,-bin}}'

# Quote literal path characters before adding our own mount suffix wildcard.
# AppImage replaces its final six mount-name characters on every launch.
escape_path() {
    local value="$1" char index
    for (( index=0; index<${#value}; index++ )); do
        char="${value:index:1}"
        case "$char" in
            "\\"|'"'|'*'|'?'|'['|']'|'{'|'}'|'^'|'@') printf '\\%s' "$char" ;;
            *) printf '%s' "$char" ;;
        esac
    done
}
if [[ -n "$firefox_path" ]]; then
    if [[ "$firefox_path" != /*/firefox || "$firefox_path" =~ [[:cntrl:]] ]]; then
        echo 'Invalid Firefox path.' >&2
        exit 1
    fi
    case "$firefox_path" in
        /opt/epixnet/firefox/firefox|/tmp/.mount_EpixNe??????/usr/bin/firefox/firefox|/tmp/appimage_extracted_*/usr/bin/firefox/firefox)
            ;; # The standard rule already covers this path.
        *)
            mount="${firefox_path%/usr/bin/firefox/firefox}"
            name="${mount##*/}"
            if [[ "$mount" != "$firefox_path" && "$name" =~ ^(\.mount_.{6})[a-zA-Z0-9]{6}$ ]]; then
                attachment="$(escape_path "${mount%/*}/${BASH_REMATCH[1]}")??????/usr/bin/firefox/firefox{,-bin}"
            elif [[ "$mount" != "$firefox_path" && "$name" =~ ^appimage_extracted_[a-zA-Z0-9]+$ ]]; then
                attachment="$(escape_path "${mount%/*}/appimage_extracted_")*/usr/bin/firefox/firefox{,-bin}"
            else
                attachment="$(escape_path "$firefox_path"){,-bin}"
            fi
            digest="$(printf '%s' "$attachment" | sha256sum)"
            profile="epixnet-firefox-${digest:0:16}"
            ;;
    esac
fi

write_profile() {
cat <<PROFILE
# Firefox needs user namespaces for its own content-process sandbox.
# Do not change the system-wide unprivileged-userns restriction.
abi <abi/4.0>,
include <tunables/global>
profile $profile "$attachment" flags=(unconfined) {
  userns,
}
PROFILE
}
if (( print_profile )); then write_profile; exit 0; fi
if [[ ! -f /etc/apparmor.d/abi/4.0 ]] || ! command -v apparmor_parser >/dev/null 2>&1; then
    echo 'No AppArmor 4 setup is needed on this system.'
    exit 0
fi
if (( if_needed )) &&
   [[ ! -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ||
      "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" != 1 ]]; then
    exit 0
fi
if (( EUID != 0 )); then
    exec sudo -- bash "$0" "${original_args[@]}"
fi
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
write_profile > "$temporary"
apparmor_parser --skip-kernel-load --skip-read-cache "$temporary"
destination="/etc/apparmor.d/$profile"
if [[ -f "$destination" ]] && ! cmp -s "$temporary" "$destination"; then
    # AppArmor skips names ending in ~ when it loads the profile directory.
    cp --preserve=mode,timestamps --backup=numbered "$destination" "$destination~"
fi
install -m 0644 "$temporary" "$destination"
apparmor_parser --replace "$destination"
echo 'EpixNet Firefox sandbox permission is ready.'
