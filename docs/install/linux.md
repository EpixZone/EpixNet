# Install EpixNet on Linux

This guide starts from a fresh Linux machine with nothing installed. Follow the steps in order. You only do steps 1 to 3 once; after that, building again is just step 5.

Type the commands into your terminal.

## 1. Install the build tools

EpixNet needs `git` (to download the code), a C compiler, and a couple of small helpers.

**Debian or Ubuntu:**

```sh
sudo apt update
sudo apt install -y build-essential pkg-config git curl
```

**Fedora:**

```sh
sudo dnf install -y gcc gcc-c++ make pkgconf-pkg-config git curl
```

**Arch:**

```sh
sudo pacman -S --needed base-devel git curl
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

```sh
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet
```

## 4. Build it

```sh
cargo build --release -p epix-server
```

The first build downloads a lot and can take several minutes, that is normal. It is finished when you see `Finished`.

## 5. Run it

```sh
./target/release/epix-server
```

Your browser opens the EpixNet dashboard. If it does not open on its own, go to **http://127.0.0.1:42222/**.

To open a specific site, add its name:

```sh
./target/release/epix-server talk.epix
```

## Run a headless node from a release binary (Ubuntu server)

If you just want to keep a node running on a server, you do not need to install Rust or build anything. The release tarball includes `epix-server`, a standalone node with no Firefox and no desktop libraries. Download it, extract it, and run it under systemd.

The steps in this section replace steps 1 to 5 above. These commands assume Ubuntu (or Debian); adjust the package names for other distributions.

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

After this, `/opt/epix/epix-server` is the node. The tarball also carries the desktop launcher (`epix-browser`) and a bundled Firefox for desktop use; a headless server ignores them.

`epix-server` links only against the standard C library, which every Ubuntu already has, so there are no extra packages to install.

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

`EPIX_HEADLESS=1` stops it from trying to open a browser. `EPIX_UI_ADDR` sets the address the dashboard listens on (change the port if `42222` is taken). `LimitNOFILE=65536` gives the node room for many peer connections; the default limit is low enough that a busy public node can hit it.

### 4. Start it and check it

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now epix
systemctl status epix
journalctl -u epix -f
```

You can also ask the node itself. `/StatsJson` is exempt from the origin check, so it answers a plain request:

```sh
curl -s http://127.0.0.1:42222/StatsJson
```

### 5. Reach the dashboard

The node listens on `127.0.0.1:42222` on the server itself. From your own machine, open an SSH tunnel and then visit **http://127.0.0.1:42222/** in a browser:

```sh
ssh -L 42222:127.0.0.1:42222 you@server
```

Open it in a real browser. The node has a DNS-rebinding guard that blocks untraceable requests to a site path, so a bare `curl http://127.0.0.1:42222/<xite>/` returns `403 Cross-origin request blocked`. That is expected; browser page loads carry a `Sec-Fetch-Mode: navigate` header and are always allowed. Use `/StatsJson` (above) when you want a scripted health check.

To serve it publicly instead, put a reverse proxy (for example nginx) in front and point it at `127.0.0.1:42222`. If you reach it by a hostname rather than an IP, add that hostname to the `ui_host` config key so the node accepts the `Host` header.

### Updating to a new release

Stop the service, re-run the download and extract from step 1, then start again. The data directory is separate, so upgrading does not touch the node's identity or its sites:

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

## The full desktop app (managed Firefox)

On a machine with a screen, EpixNet can run inside a managed copy of Firefox that understands `.epix` names directly. Install Firefox with your package manager first, then:

```sh
cargo run -p epix-browser
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
- **Port already in use:** EpixNet automatically tries `43110` if `42222` is taken. You can also pick your own with `EPIX_UI_ADDR=127.0.0.1:9000 ./target/release/epix-server`.
