# Firefox wallet signing preparation

Issue #758 is reproducible because the desktop launcher installs an unsigned
profile extension. This tooling prepares a Mozilla submission. It does not
change the installed wallet, remove the warning, or alter private-window access.
The issue remains open until a real signed artifact is verified and adopted.

The launcher currently changes the wallet's manifest, version, toolbar icons,
background HTML and JavaScript. Signing the upstream ZIP and then applying these
changes would invalidate its signature. `epix-browser --export-wallet` uses the
same packing code as the current installer and exports its final bytes without
opening a browser or touching a profile. Preparation sets the selected AMO release version. For older wallet builds it
renames the Firefox manifest key `applications` to `browser_specific_settings`.
It applies the reviewed data declaration and a Firefox minimum of 142 for this
XPI. Mozilla validates the shared minimum against both desktop (consent since
140) and Android (since 142). EpixNet desktop ships a newer ESR. The extension
keeps its ID and private-window settings.

## Publisher prerequisites

1. Sign in to the [AMO Developer Hub](https://addons.mozilla.org/developers/) with
   the publisher account, enable two-factor authentication and accept the Firefox
   Add-on Distribution Agreement. Confirm the account can create or update
   `wallet@epix.zone`. If it already exists, check its latest submitted version.
2. Generate a [JWT issuer and secret](https://addons.mozilla.org/developers/addon/api/key/).
   In [EpixNet Actions secrets](https://github.com/EpixZone/EpixNet/settings/secrets/actions),
   save the issuer as `AMO_JWT_ISSUER` and the secret as `AMO_JWT_SECRET`.
   The workflow maps those secrets to the two environment variables used by
   `web-ext`. Keep their values in the secret store.
3. Choose an unused numeric version higher than both the installed wallet and
   the highest version submitted to AMO. The developer can check the former
   in the preparation receipt. Only the publisher can confirm unlisted AMO history.
4. Use the [reviewed wallet disclosure](DATA-DISCLOSURE.md) for this submission.
   Review it again when the wallet pin or EpixNet's packaging or native bridge
   changes. Preparation checks the wallet revision against the declaration.

By default, the workflow requires zero lint errors and warnings. For the
publisher-reviewed wallet `39d6afd0e243`, version `0.13.41.1`, the publisher
can select **Use the publisher review**. Strict Mozilla lint still runs. The
submission must match the exact unsigned XPI, validator versions, bundle bytes
and all six complete diagnostics recorded in [the review](mozilla-review.json).
Any difference stops submission. Mozilla makes its own approval decision.

The source upload includes committed EpixNet and wallet source, lockfiles and
build instructions. It preserves original commit objects and tracked file modes
so `rebuild.py restore` restores exact detached revisions and clean Git status.
The source bundle records the public terms/privacy URLs from the checksum-verified
wallet build metadata, unsets analytics credentials, and enables the upstream
store-build validation. `BUILD.txt` includes commands to verify every rebuilt
upstream file and final transformed payload against the submission. A complete
independent rebuild must pass those comparisons before publishing; source recipe
validation alone is not proof of reproducibility.

Wallet revision `88a545a37c95` was rebuilt independently from the extracted source
bundle: all 108 upstream files matched the release byte for byte. That build
used Node 22.22.1, Yarn 3.4.1 and the complete protoc 3.21.3 distribution. The
[original release run](https://github.com/EpixZone/epix-wallet/actions/runs/42530606913)
used Node 22.23.4 and protoc 23.4. Install the compiler together with its standard
`include/google/protobuf` headers, including `descriptor.proto`, and preserve
the distribution's `bin`/`include` layout. A system compiler without these headers
fails before generating the wallet libraries. On Debian/Ubuntu, the headers are
provided by `libprotobuf-dev`. Keep the original release tool versions in the
source review record when updating the wallet pin.

See Mozilla's
[signing guide](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/)
and [source submission requirements](https://extensionworkshop.com/documentation/publish/source-code-submission/).

## Manual workflow

Run **Prepare Firefox wallet signing** from Actions with a unique numeric
version newer than both the last submitted version and the installed wallet. Its default prepares inputs
without contacting Mozilla and runs strict lint. A lint failure marks the run
failed and retains the inputs and full report for review. Select **Submit to Mozilla**
when the candidate passes the selected gate and the publisher credentials, account
and sources are ready. The pinned `web-ext` 10.8.0 tool submits an
unlisted extension for self-distribution and uploads the readable source bundle.
The workflow keeps the preparation and service response as workflow artifacts;
it does not publish a release or update the wallet pin.

For local preparation, use committed source checkouts and Node 22, Python 3,
Git, Rust, and the platform's normal desktop build dependencies. Check out the
wallet commit named by `shells/wallet-ext.rev`, download that commit's
`wallet-<revision>` release asset `epix-wallet-firefox.zip`, then run:

```sh
cargo build --locked -p epix-browser --no-default-features
python3 packaging/firefox-wallet/prepare.py \
  --browser /absolute/path/to/EpixNet/target/debug/epix-browser \
  --wallet-source /absolute/path/to/pinned-epix-wallet \
  --wallet-archive /absolute/path/to/epix-wallet-firefox.zip \
  --version 0.13.41.1 \
  --output /absolute/path/to/new-wallet-submission
```

Choose the release version for the actual publisher account; the example is not
a reserved version. The current install has a content-stamped fourth version
component, so use a higher earlier component to ensure the signed release can
upgrade it. Preparation rejects equal or lower versions. A stale launcher, dirty tracked source, mismatched wallet
revision, modified release archive, or locally overridden wallet build is
rejected. The export receipt binds the embedded wallet files to the pinned
archive. The output includes the original export, prepared extension,
`unsigned.xpi`, `source.zip`, and source revisions and SHA-256 digests in
`provenance.json`. Existing output directories and exports are not overwritten.

Install the locked tools and submit after securely injecting the two credential
environment variables:

```sh
npm ci --prefix packaging/firefox-wallet --ignore-scripts --no-fund
npm audit --prefix packaging/firefox-wallet --audit-level=low
python3 packaging/firefox-wallet/sign.py /absolute/path/to/new-wallet-submission --lint-only
python3 packaging/firefox-wallet/sign.py /absolute/path/to/new-wallet-submission \
  --output /absolute/path/to/new-mozilla-response
```

The entry point checks that the prepared inputs have not changed and repeats
strict lint before submitting. For the single reviewed candidate above, add
`--reviewed-warnings` to both `sign.py` commands. This submits private approval
notes to AMO and uploads `review-source.zip`. It contains both repositories,
the build instructions, the complete fresh `mozilla-lint.json` and
`reviewed-findings.json` with the reason for each reported line and column.
The workflow retains the exact submission materials for inspection. It also checks
that the returned XPI's payload matches the submission. It does not treat
`META-INF` filenames as proof of a valid Mozilla signature. `result.json`
explicitly leaves Firefox signature verification outstanding.

## Required adoption step

Before updating the application, run the returned XPI in the supported Firefox
ESR with signature verification enabled. Confirm Firefox reports an ordinary
Mozilla signature, the wallet works, existing storage and UUID survive an
in-place update, and private-window consent and disabled state are preserved.
Offer the signed file through a user-confirmed Firefox install or update. In
ESR 153.7.0 the current managed profile sideload activates the wallet and grants
the declared data permissions silently on both first install and upgrade.
Verify that declining the real offer prevents the new wallet from activating
and that the launcher's Tor routing works while the user decides.
Also check restart and the next version update. Run all PR security and Sonar
checks before merging the adoption change.

Publish the verified XPI as an immutable release artifact with its SHA-256 pin.
The adoption change must stage those exact bytes. It must not repack, rewrite the
manifest, patch scripts or substitute icons after signing. Only then restore
`xpinstall.signatures.required=true` for the wallet's profile. Keep the extension
ID unchanged and use Firefox's update lifecycle, never uninstall the old wallet.

Application-built-in migration was investigated separately. It preserves storage
with an offline fallback, but Gecko automatically grants built-ins private-window
access and can reset their disabled state. That path is not used here.

## Validation

```sh
python3 packaging/firefox-wallet/test-signing.py
cargo test -p epix-browser --locked signing_export_matches_installed_bytes
```
