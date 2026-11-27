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

The default gate requires zero lint errors and warnings. Selecting the
publisher-reviewed warnings option accepts only the unsigned XPI, wallet
revision, extension ID, release version, validator versions, bundle digests
and full diagnostics recorded in [the review](mozilla-review.json).
A changed candidate or diagnostic needs a fresh review.

The source upload includes committed EpixNet and wallet source, lockfiles and
build instructions. It preserves original commit objects and tracked file modes
so `rebuild.py restore` restores exact detached revisions and clean Git status.
The source bundle records the public terms/privacy URLs from the checksum-verified
wallet build metadata, unsets analytics credentials, and enables the upstream
store-build validation. `BUILD.txt` includes commands to verify every rebuilt
upstream file and final transformed payload against the submission. A complete
independent rebuild must pass those comparisons before publishing; source recipe
validation alone is not proof of reproducibility.

Record the release workflow run and its Node, Yarn and protoc versions in
[data-disclosure.json](data-disclosure.json) when reviewing a new wallet pin.
The generated build recipe includes these versions and checks the Yarn version
against the wallet's committed package manager. Install the compiler together
with its standard `include/google/protobuf` headers, including
`descriptor.proto`, and preserve its `bin` and `include` layout.

See Mozilla's
[signing guide](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/)
and [source submission requirements](https://extensionworkshop.com/documentation/publish/source-code-submission/).

## Manual workflow

Run **Prepare Firefox wallet signing** from Actions with a unique numeric
version newer than both the last submitted version and the installed wallet.
The default run validates the XPI and saves `wallet-review/review-source.zip`
and `wallet-review/amo-metadata.json` for testing before submission. A lint failure marks the run
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
  --version "${WALLET_VERSION:?Set the unused AMO version}" \
  --output /absolute/path/to/new-wallet-submission
```

The current install has a content-stamped fourth version
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
python3 packaging/firefox-wallet/sign.py /absolute/path/to/new-wallet-submission \
  --prepare-only --output /absolute/path/to/review-materials
python3 packaging/firefox-wallet/sign.py /absolute/path/to/new-wallet-submission \
  --output /absolute/path/to/new-mozilla-response
```

The entry point checks that the prepared inputs have not changed and repeats
strict lint before submitting. Every submission sends the reviewer notes to
AMO, uploads a source archive with both repositories, and includes its
`BUILD.txt`, `REVIEWER.txt` and complete `mozilla-lint.json`. Reviewers can
verify the project identity, permissions and data recipients and test the
requested signing text with a disposable account. Use `--reviewed-warnings` on
both commands only for an exact publisher-reviewed candidate. This also
includes `reviewed-findings.json` with the explanation for each diagnostic.
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
