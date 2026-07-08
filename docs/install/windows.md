# Install EpixNet on Windows

This guide starts from a fresh Windows PC with nothing installed. Follow the steps in order. You only do steps 1 to 4 once; after that, building again is just step 6.

You will use **PowerShell**. To open it, press the Start button, type `PowerShell`, and click it.

## 1. Install the C++ build tools

EpixNet needs Microsoft's C++ compiler to build.

1. Download **Build Tools for Visual Studio**: https://visualstudio.microsoft.com/downloads/ (scroll down to "Tools for Visual Studio" and pick "Build Tools for Visual Studio").
2. Run the installer.
3. On the **Workloads** screen, check **Desktop development with C++**.
4. Click **Install** and wait for it to finish.

## 2. Install Git

Download and install **Git for Windows**: https://git-scm.com/download/win . Click Next through the installer; the defaults are fine.

## 3. Install Rust

Rust is the language EpixNet is written in.

1. Download **rustup-init.exe**: https://rustup.rs
2. Run it. A black window opens.
3. Type `1` and press Enter to choose the standard install.

Close PowerShell and open a **new** PowerShell window so it picks up Rust. Check it worked:

```powershell
rustc --version
```

You should see a version number.

## 4. Download EpixNet

```powershell
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet
```

## 5. Build it

```powershell
cargo build --release -p epix-server
```

The first build downloads a lot and can take several minutes, that is normal. It is finished when you see `Finished`.

## 6. Run it

```powershell
.\target\release\epix-server.exe
```

Your browser opens the EpixNet dashboard. If it does not open on its own, go to **http://127.0.0.1:42222/**.

To open a specific site, add its name:

```powershell
.\target\release\epix-server.exe talk.epix
```

## Running headless (no browser window)

To run EpixNet as a background server without opening a browser:

```powershell
$env:EPIX_HEADLESS = "1"
.\target\release\epix-server.exe
```

Then visit **http://127.0.0.1:42222/** from any browser.

## The full desktop app (managed Firefox)

EpixNet can also run inside a managed copy of Firefox that understands `.epix` names directly. Install Firefox first ([download it here](https://www.mozilla.org/firefox/)), then:

```powershell
cargo run -p epix-browser
```

## Where your data lives

EpixNet keeps your sites, keys, and settings in:

```
%APPDATA%\EpixNet
```

Paste that into the File Explorer address bar to open it.

## If something goes wrong

- **`link.exe` not found` or a C++ error:** step 1 did not finish. Re-open the Visual Studio Build Tools installer and make sure **Desktop development with C++** is checked.
- **`cargo` or `git` not recognized:** close PowerShell and open a new one so it picks up the new programs.
- **Port already in use:** EpixNet automatically tries `43110` if `42222` is taken. You can also pick your own: `$env:EPIX_UI_ADDR = "127.0.0.1:9000"` before running.
