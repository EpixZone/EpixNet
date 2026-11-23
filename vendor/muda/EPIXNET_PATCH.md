# GTK 0.19 menu bindings

EpixNet's Linux startup window, tray and menus all use GTK 3. The 0.19 Rust
bindings use glib 0.22, which contains the fix for RUSTSEC-2024-0429.

This copy starts from the published muda 0.21.1 archive, SHA-256
`9a7b000cca0783af26837fe2ebd9ddf1c42279463c085b97622ee1d2f444b89e`.
It contains the upstream library source, build script, registry manifest,
README and licenses. The GTK 3 dependency advances to 0.19 and two calls
use the renamed `GtkWindowExt::window_type`. Those changes come from
[the upstream GTK port](https://github.com/tauri-apps/muda/pull/403).
The base includes the macOS Objective-C class registration fix from 0.21.1.

Use a registry release when tray-icon and muda both resolve to the new GTK
bindings with AppIndicator enabled. Check the startup window, tray menu
updates, checkbox actions and the complete workspace lockfile after updating.
