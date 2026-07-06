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
git clone https://github.com/EpixZone/Epix.git
cd Epix
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

## Running headless (a server with no screen)

This is the usual way to run EpixNet on a server you reach over SSH. It serves the network but never tries to open a browser:

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
