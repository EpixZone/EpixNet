# shells/wallet-ext

This directory holds the built **Epix Wallet** Firefox WebExtension that
`epix-browser` embeds into the managed Firefox profile. It is a build artifact,
not source - the source lives in the separate `EpixZone/epix-wallet` repo
(branch `epix`).

You normally do not stage it by hand. When this directory is empty,
`epix-browser`'s `build.rs` downloads the prebuilt artifact from the
epix-wallet repo's rolling `wallet-dist` GitHub release (published by its CI on
every push to the `epix` branch), so a fresh clone of this repo builds with no
wallet checkout at all.

Overrides:

- `EPIX_WALLET_DIST=/path/to/epix-wallet/apps/extension/build/firefox cargo build -p epix-browser`
  copies a local wallet build instead of downloading. Use this while working on
  the wallet itself.
- `EPIX_WALLET_SKIP=1` skips staging (offline builds; the browser launches
  without the wallet).

A populated directory is left alone. To pick up a newer wallet build, delete
the staged files (keep this README) and rebuild:

```
find shells/wallet-ext -mindepth 1 ! -name README.md -delete
cargo build -p epix-browser
```

To build the artifact from source, from a checkout of `epix-wallet`:

```
yarn && yarn build:libs
yarn workspace @keplr-wallet/extension build
```

The output is `apps/extension/build/firefox/`. Everything here except this
README is gitignored; `ext.rs` embeds whatever is staged at compile time via
`include_dir!`.
