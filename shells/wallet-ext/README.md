# shells/wallet-ext

This directory holds the built **Epix Wallet** Firefox WebExtension that
`epix-browser` embeds into the managed Firefox profile. It is a build artifact,
not source - the source lives in the separate `EpixZone/epix-wallet` repo.

To populate it, from a checkout of `epix-wallet`:

```
yarn && yarn build:libs
cd apps/extension && yarn build
```

then copy `apps/extension/build/firefox/` into this directory:

```
cp -R /path/to/epix-wallet/apps/extension/build/firefox/. shells/wallet-ext/
```

Everything except this README is gitignored. `epix-browser`'s `ext.rs` embeds
whatever is here at compile time via `include_dir!`, so a fresh checkout (with
only this README) still compiles - the wallet is just empty until you stage a
real build.
