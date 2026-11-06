# Install EpixNet on macOS

This guide starts from a fresh Mac with nothing installed. Follow the steps in order. You only do steps 1 to 3 once; after that, building again is just step 5.

You will type the commands into the **Terminal** app (press `Cmd + Space`, type `Terminal`, press Enter).

For the full desktop, complete steps 1 to 3 and follow
[the EpixNet Browser setup](#the-full-desktop-app-managed-firefox). Steps 4 and
5 build the standalone node and explicitly use your system browser.

## 1. Install the Apple build tools

These give you `git` (to download the code) and a C compiler (to build it). Run:

```sh
xcode-select --install
```

A window pops up. Click **Install** and wait for it to finish.

## 2. Install Rust

Rust is the language EpixNet is written in. This command installs it:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Press Enter to accept the default when it asks. When it is done, either close and reopen Terminal, or run:

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
./target/release/epix-server --browser system
```

Your system browser opens the EpixNet dashboard. If it does not open on its own, go to **http://127.0.0.1:42222/**. If that port was taken, use the selected port saved in `ui_port` inside your data folder instead.

For **v0.6.4 and earlier**, omit `--browser system`; those releases already
use the system browser and do not support this flag.

To open a specific site, add its name:

```sh
./target/release/epix-server --browser system talk.epix
```

The default choice is EpixNet Browser, launched through the `epix-browser`
executable beside `epix-server`. The standalone build above does not include
it. Use the desktop setup below or explicitly select the system browser.
Save your choice under **Browser for standalone node startup** on the Config
page. `--browser epix|system` overrides `EPIX_BROWSER=epix|system`, then the
saved choice. Turning off browser opening on startup or setting
`EPIX_HEADLESS=1` disables automatic browser opening. This does not change
macOS's default browser.

EpixNet Browser requires a loopback UI address. For a LAN-facing bind such as
`EPIX_UI_ADDR=0.0.0.0:42222`, use `--browser system` or `EPIX_HEADLESS=1`.

## Running headless (no browser window)

For a Mac you leave running as a server, start it without opening any browser:

```sh
EPIX_HEADLESS=1 ./target/release/epix-server
```

Then visit **http://127.0.0.1:42222/** from any browser when you want the dashboard.

## The full desktop app (managed Firefox)

EpixNet Browser runs the node, managed Firefox and wallet together. Prepare a
matching Firefox ESR runtime using the [local desktop setup](../xite-extensions.md#local-desktop-builds),
including its extension adapter and `EPIX_FIREFOX` path, then run:

```sh
EPIX_FIREFOX="/absolute/path/to/Firefox.app/Contents/MacOS/firefox" ./scripts/run-browser.sh
```

## Where your data lives

EpixNet keeps your sites, keys, and settings in:

```
~/Library/Application Support/EpixNet
```

## If something goes wrong

- **`xcrun: error` or `cc` not found:** step 1 did not finish. Run `xcode-select --install` again.
- **`cargo: command not found`:** close and reopen Terminal, or run `source "$HOME/.cargo/env"`.
- **Port already in use:** If dashboard port `42222` is taken, EpixNet tries `42223`, `42224`, and so on until one is available. The selected port is saved in `ui_port` inside your data folder. The file server does the same from its configured port, `26552` by default; use the selected port from the node log for port forwarding. You can also pick your own with `EPIX_UI_ADDR=127.0.0.1:9000 ./target/release/epix-server --browser system`. A non-default dashboard port must be available or startup fails.
