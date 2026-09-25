#!/usr/bin/env bash
# Run as root only INSIDE a disposable distro container with /packages mounted.
# Test install/reinstall/remove and preserve a user-data sentinel. This tests
# the loaders and packaging; GUI startup has a separate Xvfb smoke test.
set -euo pipefail
case "${1:?expected deb, rpm-fedora, appimage-suse or appimage}" in
  deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y /packages/*.deb
    dpkg -i /packages/*.deb
    remove=(apt-get remove -y epixnet)
    ;;
  rpm-fedora)
    dnf -y --setopt=install_weak_deps=False --nogpgcheck install /packages/*.rpm
    rpm -U --replacepkgs /packages/*.rpm
    remove=(dnf -y remove epixnet)
    ;;
  appimage|appimage-suse)
    # Minimal containers need the font and graphics stack normally supplied
    # by a desktop. linuxdeploy deliberately leaves these libraries to the OS.
    if [[ "$1" == appimage ]]; then
        pacman -Syu --noconfirm ca-certificates fontconfig fribidi harfbuzz alsa-lib libglvnd mesa dbus glib2
    else
        zypper --non-interactive --gpg-auto-import-keys refresh
        zypper --non-interactive install --no-recommends fontconfig \
            'libfribidi.so.0()(64bit)' 'libharfbuzz.so.0()(64bit)' \
            'libasound.so.2()(64bit)' \
            'libGL.so.1()(64bit)' 'libgbm.so.1()(64bit)' 'libX11.so.6()(64bit)' \
            'libXext.so.6()(64bit)' 'libXrender.so.1()(64bit)'
    fi
    mkdir -p /tmp/appimage-test
    cd /tmp/appimage-test
    cp /packages/*.AppImage ./EpixNet.AppImage
    chmod +x EpixNet.AppImage
    EPIX_DATA_DIR=/tmp/epix-loader-test ./EpixNet.AppImage --appimage-extract-and-run --quit
    ./EpixNet.AppImage --appimage-extract >/dev/null
    ./squashfs-root/usr/bin/firefox/appimage-firefox --headless --version
    echo 'PASS: AppImage extraction, launcher, and Firefox loader checks'
    exit 0
    ;;
  *) echo "Unknown test format: $1" >&2; exit 2 ;;
esac
desktop-file-validate /usr/share/applications/epix.desktop
EPIX_DATA_DIR=/tmp/epix-loader-test epix-browser --quit
/opt/epixnet/firefox/firefox --headless --version
if [[ "${EPIX_TEST_GUI:-0}" == 1 ]]; then
    apt-get install -y python3 xvfb xauth
    useradd --create-home epix-smoke
    runuser -u epix-smoke -- xvfb-run -a python3 /tests/smoke-desktop.py /usr/bin/epix-browser
fi
mkdir -p /root/.local/share/EpixNet
printf 'keep user data\n' > /root/.local/share/EpixNet/package-test-sentinel
"${remove[@]}"
test -f /root/.local/share/EpixNet/package-test-sentinel
test ! -e /opt/epixnet/epix-browser
test ! -e /usr/share/applications/epix.desktop
echo 'PASS: install, reinstall, loader checks, removal, and user-data preservation'
