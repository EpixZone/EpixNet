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

## Branding

`installer.nsi` brands the wizard with `app.ico` and two MUI2 bitmaps
committed next to it: `welcome.bmp` (164x314, the welcome/finish sidebar) and
`header.bmp` (150x57, the page header). All three are prebuilt from the assets
repo. Regenerate the bitmaps with `python scripts/generate-installer-bmps.py`
there (needs Pillow; writes into this directory). The finish page offers a
"Launch EpixNet" checkbox, checked by default.

## Layout

Ship a self-contained install directory:

```
Epix\
  epix-browser.exe        # the launcher (GUI subsystem - no console window)
  epix-nmh.exe            # native-messaging host
  firefox\                # bundled Firefox ESR (extract the ESR installer)
    firefox.exe
    distribution\
      policies.json       # trusts the launcher's local CA (https://*.epix)
    ...
```

The launcher already finds the bundled Firefox at `firefox\firefox.exe` next to
itself (see `bundled_firefox()` in `crates/epix-browser/src/main.rs`).

`distribution\policies.json` is the Firefox enterprise-policy file
(`Certificates.Install`): Windows has no NSS `certutil`, so this is how the
bundled Firefox trusts the launcher's per-install CA and `https://*.epix`
stays a secure context. `build-windows.sh` bakes it into the stage; the
launcher also writes it at runtime when missing (the install dir under
`%LOCALAPPDATA%` is user-writable), which covers dev runs and older installs.
The CA itself is written by the launcher to
`%LOCALAPPDATA%\Mozilla\Certificates\epix-ca.pem` on each launch.

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
     to `%APPDATA%\Mozilla\NativeMessagingHosts\zone.epix.nmh.json` **and**
     referenced from the registry key
     `HKCU\Software\Mozilla\NativeMessagingHosts\zone.epix.nmh` pointing at that
     JSON (Windows reads the manifest location from the registry, unlike
     macOS/Linux which use a fixed dir). Both are done by
     `install_native_host()` in `crates/epix-browser/src/ext.rs`; the
     uninstaller removes the key.

## Signing

Sign `epix-browser.exe` and `epix-nmh.exe` **before** the NSIS pack (so the
copies inside the installer are signed - SmartScreen and Defender judge what
runs after install, not just the download), then the installer itself. The
release workflow does this with Azure Trusted Signing around the script's two
phases:

1. `EPIX_PHASE=stage packaging/windows/build-windows.sh` - build + assemble
   `dist/epix-windows/`
2. sign `dist/epix-windows/*.exe` (non-recursive: the `firefox/` subtree keeps
   Mozilla's signatures and its self-update ability - the Epix window icon is
   stamped at runtime by the launcher, not patched into firefox.exe)
3. `EPIX_PHASE=pack packaging/windows/build-windows.sh` - makensis
4. sign `dist/Epix-Setup-<version>.exe`

Locally (`signtool sign /fd sha256 /tr <timestamp> /td sha256 ...`) follow the
same order. The NSIS-generated `uninstall.exe` stays unsigned (signing it needs
the `!uninstfinalize` dance; SmartScreen does not gate uninstalls).
