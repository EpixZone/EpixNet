# Install EpixNet on macOS

This guide starts from a fresh Mac with nothing installed. Follow the steps in order. You only do steps 1 to 3 once; after that, building again is just step 5.

You will type the commands into the **Terminal** app (press `Cmd + Space`, type `Terminal`, press Enter).

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
./target/release/epix-server
```

Your browser opens the EpixNet dashboard. If it does not open on its own, go to **http://127.0.0.1:42222/**.

To open a specific site, add its name:

```sh
./target/release/epix-server talk.epix
```

## Running headless (no browser window)

For a Mac you leave running as a server, start it without opening any browser:

```sh
EPIX_HEADLESS=1 ./target/release/epix-server
```

Then visit **http://127.0.0.1:42222/** from any browser when you want the dashboard.

## The full desktop app (managed Firefox)

EpixNet can also run inside a managed copy of Firefox that understands `.epix` names directly. You need Firefox installed first ([download it here](https://www.mozilla.org/firefox/)), then:

```sh
cargo run -p epix-browser
```

## Where your data lives

EpixNet keeps your sites, keys, and settings in:

```
~/Library/Application Support/EpixNet
```

## If something goes wrong

- **`xcrun: error` or `cc` not found:** step 1 did not finish. Run `xcode-select --install` again.
- **`cargo: command not found`:** close and reopen Terminal, or run `source "$HOME/.cargo/env"`.
- **Port already in use:** EpixNet automatically tries `43110` if `42222` is taken. You can also pick your own with `EPIX_UI_ADDR=127.0.0.1:9000 ./target/release/epix-server`.
