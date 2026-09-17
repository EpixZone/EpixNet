# EpixNet

EpixNet lets you **visit and build websites that live on people's own computers** instead of on a big company's servers.

When you open an EpixNet site, your computer downloads content and can share it with other peers. More available copies can improve access, but speed and availability depend on reachable peers, bandwidth, and the content they retain.

EpixNet supports **Tor** and **I2P** in builds that include those features. Routing depends on the build and your settings: enabling Tor does not send every connection through Tor. Direct peers and services can see your IP address, and destinations may record requests. These features do not guarantee anonymity.

## What you get

- **Peer-hosted websites.** Sites (EpixNet calls them *xites*) use signed content and peer replication. A copy must remain available locally or from a reachable peer to load it. A valid signature does not establish that content is safe or lawful.
- **Routing choices.** Supported builds include embedded Tor and I2P. The default Tor `enable` mode supports onion peers while allowing other peer connections to go directly. Browser traffic has separate routing controls. Check your platform's settings before relying on a route.
- **You help hold it up.** Your node shares the xites you have visited and helps other people find each other, like a tiny piece of the network living on your machine.
- **A dashboard.** See the xites you keep, live network activity, and a world map of the people you are connected to.
- **Network applications.** Discover a chat board, mail, and a newsfeed. Identity or wallet requirements depend on the application and the action you take.
- **Desktop and mobile projects.** Source and build guides are available for Windows, macOS, Linux, Android, and iOS. Features and distribution availability vary by platform; mobile store releases are in preparation.

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

The dashboard lives at **http://127.0.0.1:42222/**. Open a specific xite by passing its name:

```sh
cargo run -p epix-server talk.epix
```

## The wallet is pinned

`epix-browser` embeds the Epix Wallet build pinned by `shells/wallet-ext.rev`
(an epix-wallet commit on its `epix` branch). `build.rs` downloads that build's
immutable `wallet-<rev>` release when the staged copy is missing or does not
match the pin, so a given EpixNet commit always embeds the same wallet. When the
staged copy already matches the pin, the build reuses it with no network access.

To adopt a newer wallet, bump the pin to the new epix-wallet commit and open a
PR:

```sh
echo <epix-wallet-commit> > shells/wallet-ext.rev   # 12-char short SHA
cargo build --release -p epix-browser               # re-fetches the pinned build
```

## Testing a local wallet build

To test **local, unpushed** wallet changes, point the build at your wallet
checkout with `EPIX_WALLET_DIST` (it re-copies whenever your build changes, and
overrides the pin):

```sh
# 1. build the wallet (in your epix-wallet checkout)
cd ../epix-wallet
yarn install && yarn workspace @keplr-wallet/extension build   # yarn install only needed if deps changed

# 2. rebuild the browser against your build
cd ../EpixNet
EPIX_WALLET_DIST=../epix-wallet/apps/extension/build/firefox cargo run --release -p epix-browser
```

To go back to the pinned wallet, build without the env var; `build.rs` re-fetches
the pinned `wallet-<rev>` release:

```sh
cargo build --release -p epix-browser
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
| `EPIX_TOR` | Node Tor mode: `enable`, `disable`, or `always`. `always` requires Tor for node peer traffic; browser and wallet routing have separate controls. | `enable` |
| `EPIX_DATA_DIR` | Where EpixNet keeps its data (xites, keys, settings). | see below |

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
- The rest handle the network, signing and verifying xites, storage, Tor, I2P, and the dashboard.

Contributor notes for the phone and Firefox shells live in [`shells/README.md`](shells/README.md).
