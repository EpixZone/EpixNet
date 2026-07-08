# EpixNet

EpixNet lets you **visit and build websites that live on people's own computers** instead of on a big company's servers.

When you open an EpixNet site, your computer downloads its own copy and then helps share it with the next person. So the more people who visit a site, the stronger and faster it gets, and no single company can quietly take it down or watch who is reading it.

Privacy comes built in. EpixNet can send your traffic through **Tor** and **I2P** (two networks that hide where you are), and both are turned on for you out of the box.

## What you get

- **A web that nobody owns.** Sites (EpixNet calls them *xites*) are signed by their author and copied from person to person, so they stay online even when computers switch off.
- **Privacy without the setup.** Tor and I2P run inside EpixNet and are on by default. There is nothing extra to download or configure.
- **You help hold it up.** Your node shares the sites you have visited and helps other people find each other, like a tiny piece of the network living on your machine.
- **A dashboard.** See the sites you keep, live network activity, and a world map of the people you are connected to.
- **Built-in apps.** A chat board, mail, and a newsfeed that all run on the network, with no account on anyone's server.
- **Runs almost anywhere.** Windows, macOS, Linux, Android, and iOS.

## Get started

EpixNet is built from its source code. Pick your system below. Each guide starts from a brand new machine with nothing installed yet and walks you through every step.

- [Windows](docs/install/windows.md)
- [Linux](docs/install/linux.md)
- [macOS](docs/install/macos.md)
- [Android](docs/install/android.md)
- [iOS](docs/install/ios.md)

## Ways to run it (desktop)

Once it is built, there are three ways to start it:

```sh
# 1. The full desktop app: opens a managed Firefox that understands .epix names,
#    so typing dashboard.epix or talk.epix just works.
cargo run -p epix-browser

# 2. Just the node, no Firefox wrapper: it opens the dashboard in your normal
#    browser. Good if you already have a browser you like.
cargo run -p epix-server

# 3. Headless, for a server or seedbox with no screen: serve the network but
#    do not open any browser. Then visit the dashboard yourself.
EPIX_HEADLESS=1 cargo run -p epix-server
```

The dashboard lives at **http://127.0.0.1:42222/**. Open a specific site by passing its name:

```sh
cargo run -p epix-server talk.epix
```

## Command line actions

The same binary doubles as the authoring and diagnostics CLI, with the
action name as the first argument (the EpixNet CLI shape):

```sh
epix-server siteCreate                          # new xite: address + private key
epix-server siteSign <address> [privatekey]     # re-sign after editing files
epix-server siteVerify <address>                # check files against the signed content.json
epix-server dbRebuild <address>                 # rebuild the xite's sql cache
epix-server dbQuery <address> "<sql>"           # query the xite db, JSON out
epix-server importBundle <bundle.zip>           # import xites from a zip

epix-server cryptSign <message> <privatekey>
epix-server cryptVerify <message> <sign> <address>
epix-server cryptGetPrivatekey <master_seed> [index]
epix-server cryptPrivatekeyToAddress <privatekey>

epix-server peerPing <ip> <port>                # wire-protocol ping
epix-server peerGetFile <ip> <port> <site> <inner_path>
epix-server peerCmd <ip> <port> <cmd> '<json params>'
```

The authoring actions work against the data dir directly (no running
node needed). `siteSign` uses the key saved at `siteCreate` when you
don't pass one. Anything that is not an action name is treated as a
xite to open, as before.

## Settings you can change

Set these before you start EpixNet to change how it runs:

| Setting | What it does | Default |
| --- | --- | --- |
| `EPIX_HEADLESS=1` | Serve the network but never open a browser (for servers). | off |
| `EPIX_UI_ADDR` | The address the dashboard listens on. | `127.0.0.1:42222` |
| `EPIX_TOR` | Tor mode: `enable`, `disable`, or `always` (route everything through Tor). | `enable` |
| `EPIX_DATA_DIR` | Where EpixNet keeps its data (sites, keys, settings). | see below |

If port `42222` is already taken, EpixNet falls back to `43110`.

Your data folder by default:

- Windows: `%APPDATA%\EpixNet`
- macOS: `~/Library/Application Support/EpixNet`
- Linux: `~/.local/share/EpixNet` (or `$XDG_DATA_HOME/EpixNet`)

## Checking which version you are running

Open the dashboard, then **Settings**. It shows the version and the exact code the build was made from, for example `0.3.0 (rev1a2b3c4)`. You can match that `rev` against the commits in this repository to confirm what you are running.

## Under the hood (for the curious)

EpixNet is a set of small Rust pieces (in `crates/`) that fit together:

- `epix-server` is the node you run on a desktop.
- `epix-browser` wraps a real Firefox so `.epix` names load like normal web pages.
- `epix-ffi` is the same node packaged for Android and iOS.
- The rest handle the network, signing and verifying sites, storage, Tor, I2P, and the dashboard.

Contributor notes for the phone and Firefox shells live in [`shells/README.md`](shells/README.md).
