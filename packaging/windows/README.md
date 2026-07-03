# Windows packaging (scaffold)

Untested in CI here - this documents the Windows installer approach; the Rust
cores (`epix-browser`, `epix-nmh`) build the same as on other platforms.

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
