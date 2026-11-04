# Install EpixNet on Linux

## Desktop installer

Download the package for your system from [EpixNet releases](https://github.com/EpixZone/EpixNet/releases).
For a Git checkout, see [launch the full desktop from source](#the-full-desktop-app-managed-firefox).
The desktop packages include Firefox ESR and the Epix Wallet; you do not need
Rust or a separate Firefox installation. These packages target 64-bit Intel/AMD
PCs. See the release notes for the platforms validated for a particular build.

| Your system | Package |
| --- | --- |
| Ubuntu 22.04+, Zorin 17/18, Mint 21/22, Pop!_OS 22.04+, Debian 12+ | `.deb` |
| Current Fedora | `.rpm` |
| openSUSE, Arch, Manjaro, EndeavourOS and other current glibc desktops | `.AppImage` |

**Ubuntu, Zorin, Mint, Pop!_OS, Debian:** open the downloaded `.deb` with your
software installer, or install it with `sudo apt install ./epixnet_*.deb` from
the download folder. APT installs any missing desktop libraries automatically.

**Fedora:** run `sudo dnf install ./epixnet-*.rpm`.

After installation, choose **EpixNet** from the applications menu. `epix://`
links can open it directly. The install does not change your default web browser.

**AppImage:** mark `EpixNet-*-x86_64.AppImage` executable in your file manager
(or run `chmod +x EpixNet-*-x86_64.AppImage`), then open it. Keep it in a
permanent folder. If your desktop cannot mount AppImages, run it with
`--appimage-extract-and-run`. This format requires glibc 2.35 or newer; Alpine
Linux's musl C library is not supported.

We recommend [Gear Lever](https://gearlever.mijorus.it/) for managing the
AppImage. It can keep AppImages in one folder and add EpixNet to your
applications menu. Install Gear Lever using its official instructions, then
open the downloaded EpixNet AppImage with it to integrate the app.

On Ubuntu 24.04 and newer, the AppImage asks for administrator approval on
first launch if the browser sandbox needs permission. Approve the system
password prompt and EpixNet continues automatically. Later launches reuse
that permission. No separate script or restart is needed. Native packages
set this up during installation. Removing the permission or changing the
AppImage's name or temporary folder may require approval again.

Before upgrading, use **Quit** in EpixNet's tray menu. Upgrade by installing the
new package or replacing the AppImage. To remove a native package, use your
software manager, `sudo apt remove epixnet`, `sudo dnf remove epixnet`, or
delete the AppImage file. Profiles, keys, wallets and sites remain in your
user data directory; uninstalling does not erase them.

If a release only has the older `.tar.gz`, extract the entire archive into a
permanent folder and run its `install.sh`. Keep the `firefox` folder alongside
`epix-browser`. Moving/deleting the extracted tree breaks its menu shortcut;
run `install.sh` again after moving it.

## Build from source

Install the tools and clone the source once. Keep that checkout for [updates from GitHub](#update-a-source-checkout-with-git).

Type the commands into your terminal.

## 1. Install the build tools

EpixNet needs Git, a C compiler and build tools. The update commands below use curl and Python 3 to read the release tag from GitHub.

**Debian or Ubuntu:**

```sh
sudo apt update
sudo apt install -y build-essential pkg-config git curl python3 protobuf-compiler
```

**Fedora:**

```sh
sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config git curl python3 protobuf-compiler
```

**Arch:**

```sh
sudo pacman -S --needed base-devel git curl python protobuf
```

## 2. Install Rust

Rust is the language EpixNet is written in. This command installs it:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Press Enter to accept the default when it asks. When it is done, load it into your current terminal:

```sh
source "$HOME/.cargo/env"
```

Check it worked:

```sh
rustc --version
```

You should see a version number.

## 3. Download EpixNet

Use your normal login account. Replace `v0.6.3` with the tag shown on the [latest stable release](https://github.com/EpixZone/EpixNet/releases/latest). The shallow clone downloads that snapshot.

```sh
cd "$HOME" &&
git clone --depth 1 --no-tags --branch v0.6.3 https://github.com/EpixZone/EpixNet.git &&
cd EpixNet
```

## 4. Build it

```sh
cargo build --release --locked -p epix-server -p evx-worker &&
./target/release/epix-server --version
```

The first build downloads dependencies and can take a while. Cargo prints `Finished` when the executables are ready. The version should match the tag you chose.

These two packages build the node and the worker it launches for EVX modules. Building the whole workspace (`cargo build --release`, with no `-p`)
also builds the Ledger hardware-wallet bridge, and that one talks to the device
over HID, which on Linux goes through udev. For that you need the udev
DEVELOPMENT package as well, and having `libudev.so.1` already on your system
is not enough:

```sh
sudo apt install -y libudev-dev        # Debian or Ubuntu
sudo dnf install -y systemd-devel      # Fedora
sudo pacman -S --needed systemd-libs   # Arch
```

## 5. Run it

```sh
./target/release/epix-server
```

Your browser opens the EpixNet dashboard. If it does not open on its own, go to **http://127.0.0.1:42222/**. If that port was taken, use the selected port saved in `ui_port` inside your data folder instead.

To open a specific site, add its name:

```sh
./target/release/epix-server talk.epix
```

## Run a headless node from a release binary (Ubuntu server)

The prebuilt Linux tarball contains the headless node, the desktop launcher and Firefox. The headless service runs without Firefox, but downloading the archive transfers the whole bundle. For smaller update downloads, you can [build from source](#build-from-source) and keep the Git checkout.

Tarball users can skip the source build steps above. The service setup below assumes Ubuntu or Debian.

### 1. Download the latest release and extract it

The release is one `epix-linux-<version>.tar.gz` file. This finds the latest one and unpacks it into `/opt/epix`:

```sh
cd /tmp
url=$(curl -fsSL https://api.github.com/repos/EpixZone/EpixNet/releases/latest \
  | grep -o 'https://[^"]*epix-linux-[^"]*\.tar\.gz' | head -1)
curl -fL -o epix-linux.tar.gz "$url"

sudo mkdir -p /opt/epix
sudo tar xzf epix-linux.tar.gz -C /opt/epix --strip-components=1
```

For a **new service built from source**, skip the tarball commands above. Instead, run these commands from the checkout after step 4 of the source guide, then continue with the service account in step 2 below.

```sh
sudo install -d /opt/epix &&
sudo install -m 0755 target/release/epix-server target/release/evx-worker /opt/epix/
```

### 2. Create a user to run it

A dedicated system user keeps the node off your login account and gives it a home for its data:

```sh
sudo useradd --system --create-home --home-dir /var/lib/epix epix
sudo chown -R epix:epix /opt/epix
```

The node keeps its data in that user's home, at `/var/lib/epix/.local/share/EpixNet`.

**Run it only as the `epix` user.** If you ever launch `epix-server` as `root` (for example to test it by hand), it creates `root`-owned files in that data directory, and the service — running as `epix` — can no longer write there. The node needs to create a `lock.pid` file in the data root on startup; when it cannot, it prints the misleading message `Epix is already running (lock held in …)` even though nothing is running. If you hit that, fix the ownership:

```sh
sudo systemctl stop epix
sudo chown -R epix:epix /var/lib/epix/.local/share/EpixNet
sudo systemctl start epix
```

### 3. Set up the service

Create the systemd unit, pointing `ExecStart` at the extracted directory:

```sh
sudo tee /etc/systemd/system/epix.service >/dev/null <<'UNIT'
[Unit]
Description=EpixNet node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=epix
WorkingDirectory=/opt/epix
ExecStart=/opt/epix/epix-server
Environment=EPIX_HEADLESS=1
Environment=EPIX_UI_ADDR=127.0.0.1:42222
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
```

`EPIX_HEADLESS=1` stops it from trying to open a browser. `EPIX_UI_ADDR` sets the address the dashboard listens on. The default port `42222` increases one at a time if taken; a non-default port must be available. `LimitNOFILE=65536` gives the node room for many peer connections; the default limit is low enough that a busy public node can hit it.

### 4. Start it and check it

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now epix
systemctl status epix
journalctl -u epix -f
```

You can also ask the node itself. `/StatsJson` is exempt from the origin check, so it answers a plain request. If the dashboard selected another port, replace `42222` with the port saved in `/var/lib/epix/.local/share/EpixNet/ui_port`:

```sh
curl -s http://127.0.0.1:42222/StatsJson
```

### 5. Reach the dashboard

The node listens on `127.0.0.1:42222` on the server itself by default. If it selected another port, use that port for the remote end of the tunnel and any reverse proxy below. From your own machine, open an SSH tunnel and then visit **http://127.0.0.1:42222/** in a browser:

```sh
ssh -L 42222:127.0.0.1:42222 you@server
```

Open it in a real browser. The node has a DNS-rebinding guard that blocks untraceable requests to a site path, so a bare `curl http://127.0.0.1:42222/<xite>/` returns `403 Cross-origin request blocked`. That is expected; browser page loads carry a `Sec-Fetch-Mode: navigate` header and are always allowed. Use `/StatsJson` (above) when you want a scripted health check.

To serve it publicly instead, put a reverse proxy (for example nginx) in front and point it at `127.0.0.1:42222`. If you reach it by a hostname rather than an IP, add that hostname to the `ui_host` config key so the node accepts the `Host` header.

### Updating to a new release

For an existing service, you can [switch to Git-based updates](#update-a-source-checkout-with-git) and keep the same service and data directory.

To stay with prebuilt releases, stop the service, repeat the download and extraction from step 1, then start it again. The service keeps its existing data directory.

```sh
sudo systemctl stop epix
# repeat the curl + tar commands from step 1
sudo chown -R epix:epix /opt/epix
sudo systemctl start epix
```

## Running headless from a source build

If you built from source (steps 1 to 5 at the top), the server binary runs headless directly. It serves the network but never tries to open a browser:

```sh
EPIX_HEADLESS=1 ./target/release/epix-server
```

Then visit **http://127.0.0.1:42222/** from a browser (use an SSH tunnel if the server is remote: `ssh -L 42222:127.0.0.1:42222 you@server`).

## Update a source checkout with Git

Reuse the checkout from step 3. If you installed the tarball and have no checkout yet, follow [source steps 1 to 3](#build-from-source) once. Git fetches source objects your checkout is missing. Keeping the checkout, Cargo's cache and `target/` lets later builds reuse downloaded dependencies and compiled files. New dependencies can still require downloads. Prebuilt Linux release packages are still full downloads.

Run this from your login account. It looks up the [latest stable release](https://github.com/EpixZone/EpixNet/releases/latest) on GitHub, fetches that tag into your existing clean checkout, and prints the selected version.

```sh
cd "$HOME/EpixNet" &&
tag=$(curl -fsSL https://api.github.com/repos/EpixZone/EpixNet/releases/latest |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])') &&
git fetch --no-tags origin tag "$tag" &&
git switch --detach "refs/tags/$tag" &&
git describe --tags --exact-match
```

If you intentionally track development builds and your checkout is already on `main`, use `git pull --ff-only origin main` in place of the fetch and switch commands. `main` can include changes beyond the latest release.

For a desktop, quit EpixNet from the tray, update the checkout, then [run the desktop launcher](#the-full-desktop-app-managed-firefox) again.

### Update the headless service

For the `epix.service` above, build the node and its matching worker in the updated checkout. Leave the old node running during the build.

```sh
cargo build --release --locked -p epix-server -p evx-worker &&
./target/release/epix-server --version
```

Check the printed version, then stage both executables before stopping the service.

```sh
sudo install -d /opt/epix-stage &&
sudo install -m 0755 target/release/epix-server target/release/evx-worker /opt/epix-stage/ &&
sudo systemctl stop epix &&
sudo mv /opt/epix-stage/epix-server /opt/epix-stage/evx-worker /opt/epix/ &&
sudo systemctl start epix &&
systemctl status epix
```

The service continues to use the same `epix` account and its existing identities and sites in `/var/lib/epix/.local/share/EpixNet`. If you run the node directly, stop the old process and start the newly built server with the same account and data directory.

## The full desktop app (managed Firefox)

From a graphical Linux session, one command opens the managed Firefox window, starts the embedded EpixNet node and connects the wallet through its native messaging host. Use your normal desktop account. Complete source steps 1 to 3 and install the desktop dependencies for your distribution once.

```sh
# Debian or Ubuntu
sudo apt install -y libgtk-3-dev libxdo-dev libayatana-appindicator3-dev libudev-dev xz-utils util-linux

# Fedora
sudo dnf install -y gtk3-devel libxdo-devel libappindicator-gtk3-devel systemd-devel xz util-linux

# Arch
sudo pacman -S --needed gtk3 xdotool libayatana-appindicator systemd-libs xz util-linux
```

From the checkout, launch the full desktop:

```sh
./scripts/run-browser.sh
```

The helper prepares a private copy of the release’s supported Firefox ESR, stages the trusted extension resources, and builds the launcher, native messaging host and EVX worker. The launcher opens the dashboard with the bundled Epix Wallet. To open a specific xite, run `./scripts/run-browser.sh talk.epix`.

The first launch can take a while. Later launches reuse the Firefox download while the pin, architecture and language match. Cargo also reuses its build output, and the wallet build reuses the staged extension while its pin matches. After [updating the Git checkout](#update-a-source-checkout-with-git), run the same launch command. Select **Quit** in the tray to stop the desktop node.

**On the v0.6.3 tag**, the older helper expects you to prepare Firefox and the worker first. From the checkout, run these setup commands once:

```sh
packaging/fetch-firefox-esr.sh linux &&
python3 packaging/firefox-addons/install.py packaging/firefox-esr/firefox &&
cargo build --release --locked -p evx-worker
```

Then start that release with one command:

```sh
EPIX_FIREFOX="$PWD/packaging/firefox-esr/firefox/firefox" ./scripts/run-browser.sh
```

## Where your data lives

EpixNet keeps your sites, keys, and settings in:

```
~/.local/share/EpixNet
```

(or `$XDG_DATA_HOME/EpixNet` if you set that variable).

## If something goes wrong

- **`cc` or `linker` not found:** step 1 did not finish. Re-run the install command for your distribution.
- **`cargo: command not found`:** run `source "$HOME/.cargo/env"`, or open a new terminal.
- **The build stops asking for a library:** install its development package (for example `sudo apt install -y zlib1g-dev`) and build again.
- **`unable to find library -lxdo`:** you are building the desktop app, which
  needs the desktop development libraries listed under "The full desktop app
  (managed Firefox)" above. The node itself needs none of them.
- **`Unable to find libudev` / `Package 'libudev' was not found`:** you are
  building the whole workspace, which includes the `hidapi` crate behind the
  Ledger bridge. It needs the udev DEVELOPMENT package: having `libudev.so.1`
  is not enough, the build wants the headers and the `libudev.pc` file. Install
  it as shown under step 4, or build just what you need instead, for example
  `cargo build --release -p epix-server`, which does not depend on `hidapi` at
  all.
- **Port already in use:** If dashboard port `42222` is taken, EpixNet tries `42223`, `42224`, and so on until one is available. The selected port is saved in `ui_port` inside your data folder. The file server does the same from its configured port, `26552` by default; use the selected port from the node log for port forwarding. You can also pick your own with `EPIX_UI_ADDR=127.0.0.1:9000 ./target/release/epix-server`. A non-default dashboard port must be available or startup fails.
