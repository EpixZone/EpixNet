# Windows packaging

The Windows installer is built by the release workflow (`.github/workflows/
release.yml`, `windows` job) on a `windows-latest` runner, signed with Azure
Trusted Signing. Locally: `packaging/windows/build-windows.sh` assembles the
tree and compiles `installer.nsi` with NSIS.

Not run in CI on this repo's non-Windows dev machine, but: the NSIS script
compiles (verified with `makensis`), and the Windows Rust build (including the
`winreg` native-host registry step) compiles on the Windows runner - it can't
be cross-compiled from macOS because `ring`/`aws-lc-sys` need a Windows C
toolchain.

## Layout

Ship a self-contained install directory:

```
Epix\
  epix-browser.exe        # the launcher
  epix-nmh.exe            # native-messaging host
  firefox\                # bundled Firefox ESR (extract the ESR installer)
    firefox.exe
    ...
```

The launcher already finds the bundled Firefox at `firefox\firefox.exe` next to
itself (see `bundled_firefox()` in `crates/epix-browser/src/main.rs`).

## Build steps

1. Build the binaries:
   ```
   cargo build --release -p epix-browser -p epix-nmh
   ```
2. Get Firefox ESR (`packaging/fetch-firefox-esr.sh win64` downloads the
   installer; extract it with 7-Zip into `Epix\firefox\`).
3. Package with an installer. NSIS (extends the existing `EpixNet/installer.nsi`)
   or WiX. The installer must:
   - copy the tree to `%LOCALAPPDATA%\Epix` (per-user, no admin) or Program Files;
   - register the `epix://` scheme in the registry:
     ```
     HKCU\Software\Classes\epix\(Default) = "URL:Epix Protocol"
     HKCU\Software\Classes\epix\URL Protocol = ""
     HKCU\Software\Classes\epix\shell\open\command\(Default) =
        "\"C:\path\to\epix-browser.exe\" \"%1\""
     ```
   - the native-messaging host manifest is written by the launcher at first run
     to `%APPDATA%\Mozilla\NativeMessagingHosts\zone.epix.nmh.json` **and** must
     be referenced from the registry key
     `HKCU\Software\Mozilla\NativeMessagingHosts\zone.epix.nmh` pointing at that
     JSON (Windows reads the manifest location from the registry, unlike
     macOS/Linux which use a fixed dir). This registry step is the one Windows
     specific bit still to add to `install_native_host()`.

## Signing

Sign `epix-browser.exe`, `epix-nmh.exe`, and the installer with an Authenticode
certificate (`signtool sign /fd sha256 /tr <timestamp> /td sha256 ...`).
