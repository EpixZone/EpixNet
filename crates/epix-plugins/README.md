# Plugins

EpixNet ships its features as Python plugins that monkeypatch the core. Epix
folds the same features into the Rust crates instead, either always-on or behind
a cargo feature. Desktop/auth plugins are gated off for mobile, where a phone's
UI is already local to the device.

## Ported

| Plugin | Where it lives | Gate |
| --- | --- | --- |
| Sidebar | `epix-plugins` media + ws commands | always on |
| Stats | `epix-ui` Stats page + chart db | always on |
| Cors | `epix-ui` command (`cors_target`, `corsPermission`) | always on |
| PeerDb | `epix-ui` state (`peers.json`) | always on |
| Notification | `epix-ui` command + state | always on |
| FilePack | `epix-ui` state (tar.gz/zip inner paths) | always on |
| UiFileManager | `epix-ui` `/list` route | always on |
| AnnounceLocal | `epix-runtime` UDP LAN discovery | `local-discovery` (off on mobile) |
| AnnounceShare | `epix-ui` state (`shared_trackers`) | always on |
| AnnounceBitTorrent | `epix-discovery` (`announce_bittorrent`) | always on |
| NoNewSites | `epix-ui` dispatch gate (`no_new_sites`) | always on |
| UiPassword | `epix-ui` login gate + `/Login` `/Logout` | `ui-password` (off on mobile) |
| Multiuser | `epix-ui` identity store + user commands | `multiuser` (off on mobile) |
| Benchmark | `epix-ui` `/Benchmark` page | `benchmark` (off by default) |

The `desktop` feature on `epix-server` turns on `ui-password`, `multiuser`, and
`benchmark` together. Build a mobile node with `--no-default-features`.

## Removed

- **DonationMessage** - dropped on purpose.

## Deferred to their own layer

These are not UI-server features; they belong to subsystems built in later
phases, so they land there rather than as dead code here.

- **Bootstrapper** - runs a tracker/announce service that other peers announce
  to. It needs the node to accept inbound P2P connections and handle the
  `announce` wire command, which the current node does not do (it dials out
  only). Lands with the inbound P2P server.
- **Trayicon** - a desktop system-tray icon. This is a shell concern with no
  node logic (the reference plugin has no ws actions); it lands in the Tauri
  desktop shell (`epix-tauri` / `src-tauri`, Phase 8).
- **StemPort** - controls an existing Tor daemon over its control port instead
  of spawning one. It belongs in the Tor transport (`epix-transport`), which is
  itself gated off for mobile.
- **TranslateSite** - waits on the i18n layer.
