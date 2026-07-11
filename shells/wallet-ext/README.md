# shells/wallet-ext

This directory holds the built **Epix Wallet** Firefox WebExtension that
`epix-browser` embeds into the managed Firefox profile. It is a build artifact,
not source - the source lives in the separate `EpixZone/epix-wallet` repo
(branch `epix`).

You normally do not stage it by hand. The wallet build is pinned by
`shells/wallet-ext.rev` (an epix-wallet commit on its `epix` branch). When this
directory is missing or does not match the pin, `epix-browser`'s `build.rs`
downloads that commit's immutable `wallet-<rev>` GitHub release (the wallet CI
publishes one per push to `epix`), so a fresh clone builds with no wallet
checkout at all. When the staged copy already matches the pin, the build reuses
it with no network access.

Bumping the wallet is a one-line change to the pin (open a PR):

```
echo <epix-wallet-commit> > shells/wallet-ext.rev   # 12-char short SHA
cargo build -p epix-browser                         # re-fetches the pinned build
```

Overrides:

- `EPIX_WALLET_DIST=/path/to/epix-wallet/apps/extension/build/firefox cargo build -p epix-browser`
  copies a local wallet build instead of downloading (re-copied whenever it
  changes, and overrides the pin). Use this while working on the wallet itself.
- `EPIX_WALLET_SKIP=1` skips staging (offline builds; the browser launches
  without the wallet).

To build the artifact from source, from a checkout of `epix-wallet`:

```
yarn && yarn build:libs
yarn workspace @keplr-wallet/extension build
```

The output is `apps/extension/build/firefox/`. Everything here except this
README is gitignored; `ext.rs` embeds whatever is staged at compile time via
`include_dir!`.
