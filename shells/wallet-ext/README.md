# shells/wallet-ext

This directory holds the built **Epix Wallet** Firefox WebExtension that
`epix-browser` embeds into the managed Firefox profile. It is a build artifact,
not source - the source lives in the separate `EpixZone/epix-wallet` repo
(branch `epix`).

You normally do not stage it by hand. The wallet build is pinned by
`shells/wallet-ext.rev` (an epix-wallet source commit). When this
directory is missing or does not match the pin, `epix-browser`'s `build.rs`
downloads that commit's versioned `wallet-<rev>` GitHub release (the wallet CI
publishes on `epix` or a manually selected review branch), so a fresh clone builds with no wallet
checkout at all. When the staged copy already matches the pin, the build reuses
it with no network access.

Bumping the wallet updates both its source revision and archive checksum (open a PR):

```
echo <epix-wallet-commit> > shells/wallet-ext.rev   # 12-char short SHA
# Download epix-wallet-firefox.zip from that commit's wallet-<rev> release.
shasum -a 256 epix-wallet-firefox.zip > shells/wallet-ext.sha256
cargo build -p epix-browser                         # verifies and stages the pinned build
python3 scripts/check-mobile-wallet.py shells/wallet-ext --release
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

Store artifacts must be built from committed, clean source with
`EPIX_MOBILE_STORE_BUILD=1`,
`EPIX_TERMS_URL=https://techsonix.com/epixnet/terms/`, and
`EPIX_PRIVACY_URL=https://techsonix.com/epixnet/privacy/`. Analytics settings
must be absent. The release validator checks the emitted source revision,
source cleanliness, provider assets, policy URLs, and analytics declaration.
Android stages the same release automatically; iOS uses this directory and
validates it before a Release build. A local development override is not an
immutable release artifact.
