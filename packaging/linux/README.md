# Linux desktop installers

`build-linux.sh` stages the browser, native messaging host, standalone server, EVX worker,
matching Firefox ESR, policies and icons once, then produces:

| Format | Target desktops (x86_64) |
| --- | --- |
| `.deb` | Ubuntu 22.04+, Zorin 17/18, Mint 21/22, Pop!_OS 22.04+, Debian 12+ |
| `.rpm` | Current Fedora |
| `.AppImage` | openSUSE and other glibc desktops, including Arch, Manjaro and EndeavourOS |
| `.tar.gz` | Manual installs and the standalone headless server |

These are compatibility targets, not a claim that every desktop/version has
been tested. Releases build on Ubuntu 22.04 (glibc 2.35). Newer glibc systems
can run those builds, but a build made on Ubuntu 26.04 cannot be assumed to run
on Zorin 18. `EPIX_RELEASE_BUILD=1` rejects binaries requiring newer glibc.
Alpine/musl, old distributions, and ARM native installers are outside this
matrix. The Firefox downloader and tar validation support aarch64 source builds.

## Build on Ubuntu 22.04

Install Rust stable, then:

```sh
sudo bash packaging/linux/install-build-deps.sh
packaging/fetch-firefox-esr.sh linux
EPIX_RELEASE_BUILD=1 EPIX_VERSION=0.5.14 packaging/linux/build-linux.sh
```

`EPIX_VERSION` should be the release tag without `v`. Without it the script
uses the most recent reachable tag, matching the Rust version stamp. Local
test builds should use a prerelease such as `0.5.14-dev.1`.

Use `EPIX_FORMATS=deb,rpm` to select outputs, or `EPIX_SKIP_BUILD=1` to repackage
existing release binaries without compiling again. `CARGO_TARGET_DIR` is
honored. A missing/incomplete/wrong-architecture Firefox bundle is an error,
even for tarballs. Mozilla's `os=linux` means **32-bit i686**; x86_64 must use
`os=linux64`, and aarch64 must use `os=linux64-aarch64`.

The native packages put the application in `/opt/epixnet`, commands in
`/usr/bin`, and the desktop entry/icons in `/usr/share`. Package-manager
removal deletes those installed files but leaves all user profiles, keys and
xites alone. The preinstall hook refuses an upgrade while an executable from
`/opt/epixnet` is running. It does not kill processes. No service or login
autostart is enabled by installation.

Every format keeps `evx-worker` beside the node executable. Packaging rejects
a missing, symlinked, non-executable or mismatched-architecture worker. Worker
presence does not establish sandbox support; EVX requires the runtime's Linux
confinement checks to succeed on the installed host.

EVX execution requires Landlock ABI 3 or newer, seccomp filters, descriptor
sealing and kernel process accounting. A distribution supported by the desktop
package can still have a kernel that cannot run EVX. Missing confinement fails
closed; upgrading or enabling a security module is an operator decision.

The AppImage bundles GTK resources and shared libraries with linuxdeploy's GTK
plugin. Firefox and the native host remain beside the launcher, including in
the temporary AppImage mount. Policies are baked in so no write into the
read-only bundle is necessary. Mozilla ELF files stay unmodified; a Firefox-only
wrapper selects the bundled libraries. The Firefox updater is disabled: upgrade the
whole EpixNet package to get its next ESR build.

Linux first uses Firefox's certificate policy to import the local CA. A newer
host's `certutil` can report success while writing trust records the bundled
ESR does not honor. Keeping that tool as a fallback for system Firefox avoids
the AppImage's `SEC_ERROR_UNKNOWN_ISSUER` failure without bypassing TLS checks.

Ubuntu's user-namespace restriction needs an AppArmor rule for EpixNet's
Firefox paths. Native package hooks install it when AppArmor 4 and the
restriction are present. The launcher checks the actual Firefox executable's
namespace permissions before startup. If permission is missing, it uses the
desktop's Polkit password prompt to install the embedded rule and checks again
before opening Firefox. Later launches do not prompt. Background launches
never prompt; they report that foreground setup is needed instead.

The probe library runs only in a short-lived `firefox --version` child and
exits before Firefox starts. It creates a user namespace and then separately
tests a PID namespace, matching the capability restriction Firefox encounters
on Ubuntu. It is not loaded in the browser session. The helper escapes custom
paths and covers changing AppImage mount suffixes, leaves the global restriction
enabled, and also remains available as `enable-epixnet-sandbox.sh` for recovery.

Debian dependencies are calculated with `dpkg-shlibdeps`. RPM dependencies
use shared-library capabilities on Fedora. openSUSE uses AppImage because
its libxdo ABI differs from the Ubuntu build environment.
Build tools (nFPM, linuxdeploy, its GTK plugin, and the AppImage runtime) are
downloaded into `dist/.packaging/tools` and verified against `tools.json`,
including cache hits. To upgrade a tool, review the upstream release and
update its versioned URL and SHA-256 together. Downloads use versioned releases
or commit URLs. A changed digest fails the build until the pin is reviewed.

## Build from a newer Linux host

Podman provides the Ubuntu 22.04 toolchain without changing the host's libc:

```sh
podman build --network=slirp4netns -t localhost/epixnet-linux-builder packaging/linux
mkdir -p .store-build/cargo
podman run --rm --network=slirp4netns --userns=keep-id \
  -v "$PWD:/src" -w /src \
  -e CARGO_HOME=/src/.store-build/cargo \
  -e CARGO_TARGET_DIR=/src/.store-build/target-ubuntu22 \
  -e EPIX_RELEASE_BUILD=1 -e EPIX_VERSION=0.5.14-dev.1 \
  localhost/epixnet-linux-builder \
  bash -c 'packaging/fetch-firefox-esr.sh linux && packaging/linux/build-linux.sh dist/linux-ubuntu22'
```

Docker can use the same Dockerfile; omit Podman's `--userns=keep-id` and network
option and arrange output-directory ownership for your user.

## Validate

```sh
python3 packaging/test-firefox-download.py
python3 packaging/linux/test-packaging.py
python3 packaging/linux/test-evx-package.py
shellcheck packaging/linux/*.sh packaging/linux/AppRun packaging/fetch-firefox-esr.sh
desktop-file-validate packaging/linux/epix.desktop
cd dist
sha256sum -c SHA256SUMS
```

The regression tests reject mixed/32-bit Firefox bundles, check download
architecture selection, reject modified build-tool caches, and actually launch
a relocated tarball desktop entry through GIO with spaces and reserved
characters in the pathname. The build/release workflows install the generated
`.deb` and launch both it and the AppImage under Xvfb on Ubuntu 22.04. The
compatibility workflow checks installation, reinstallation and removal on
Ubuntu 24.04, Debian 12 and Fedora 44, plus AppImage loaders on Arch and
openSUSE Tumbleweed. Ubuntu 24.04 also runs the desktop startup test.

The EVX package tests use inert ELF-header fixtures, check build/staging and
native package metadata, and inspect a real tar archive. They substitute the
external AppImage and native-package tools. Install tests also check the
worker in the actual installed or extracted bundle.

On a supported native Linux host, verify the executable itself as an ordinary
user. This runs 14 harmless native authority probes and a confined compiler and
guest roundtrip against only temporary fixtures:

```sh
python3 packaging/linux/verify-evx-worker.py /opt/epixnet/evx-worker
# Or pass the worker from the extracted AppImage or tarball.
```

The verifier fails when Landlock is unavailable, a forbidden operation succeeds,
or the compiled artifact cannot execute. It reports the kernel, ABI and worker
digest so acceptance evidence identifies the exact executable. See
[`docs/evx-linux-acceptance.md`](../../docs/evx-linux-acceptance.md) for executed
tests and remaining platform coverage.

CI also runs the verifier with `--require-privileged-parent` under a test parent
holding `CAP_SYS_RESOURCE`. The worker must discard that inherited capability
and still refuse to raise its hard CPU limit. This requires no global capability
or security-policy changes.

The smoke test uses an isolated profile and checks that the actual Firefox
window process stays running and loads `https://dashboard.epix/`. It enables
Marionette only for that test and explicitly keeps certificate verification
enabled, so a certificate error fails the test. `--check-wallet` also verifies
that the wallet loads, renders its popup, and can read status and routing settings
through the native messaging host. Build and release workflows enable this check
for both the installed package and AppImage. `--check-quit` additionally tests shutdown IPC
when a working desktop session bus is available. These checks do not replace
testing Zorin's complete desktop session. Issue #511's exit status 255 alone
does not prove its cause.
