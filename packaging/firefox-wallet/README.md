# Firefox wallet signing preparation

Issue #758 is reproducible because the desktop launcher installs an unsigned
profile extension. This tooling prepares a Mozilla submission. It does not
change the installed wallet, remove the warning, or alter private-window access.
The issue remains open until a real signed artifact is verified and adopted.

The launcher currently changes the wallet's manifest, version, toolbar icons,
background HTML and JavaScript. Signing the upstream ZIP and then applying these
changes would invalidate its signature. `epix-browser --export-wallet` uses the
same packing code as the current installer and exports its final bytes without
opening a browser or touching a profile. Preparation changes only the manifest
version to the explicitly selected AMO release version.

## Publisher prerequisites

The publisher needs an AMO developer account authorized to submit the existing
`wallet@epix.zone` identity, the required Mozilla developer agreements, and AMO
API credentials. Configure repository secrets `AMO_JWT_ISSUER` and
`AMO_JWT_SECRET` through GitHub's secret settings. Do not paste credentials into
issues, pull requests or chat. The signing process reads them through
`WEB_EXT_API_KEY` and `WEB_EXT_API_SECRET`; no credentials go in artifacts.

Mozilla can require review, supporting information, or changes before returning
an artifact. The current pinned wallet also needs publisher and upstream review
before submission. With `web-ext` 10.8.0, the prepared artifact has zero errors
and 66 warnings: deprecated `applications` metadata (1), missing Firefox
`data_collection_permissions` (1), `DANGEROUS_EVAL` (32),
`UNSAFE_VAR_ASSIGNMENT` (9), unsupported APIs (5), and desktop/Android API
compatibility (9 each). These are linter findings, not 66 confirmed
vulnerabilities. The publisher must supply truthful data collection declarations;
the wallet maintainers must review the code patterns and supported API versions.
This tooling does not invent declarations or waive findings. It retains
`lint.json` and stops submission when any lint error or warning remains.

The source upload includes committed EpixNet and wallet source, lockfiles and
build instructions. It preserves original commit objects and tracked file modes
so `rebuild.py restore` restores exact detached revisions and clean Git status.
The source bundle records the public terms/privacy URLs from the checksum-verified
wallet build metadata, unsets analytics credentials, and enables the upstream
store-build validation. `BUILD.txt` includes commands to verify every rebuilt
upstream file and final transformed payload against the submission. A complete
independent rebuild must pass those comparisons before publishing; source recipe
validation alone is not proof of reproducibility. See Mozilla's
[signing guide](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/)
and [source submission requirements](https://extensionworkshop.com/documentation/publish/source-code-submission/).

## Manual workflow

Run **Prepare Firefox wallet signing** from Actions with a unique numeric
version newer than the last submitted version. Its default prepares inputs
without contacting Mozilla and runs strict lint. A lint failure marks the run
failed but retains the inputs and report for review. Select **Submit to Mozilla**
only when lint passes and the publisher credentials, account and source review
are ready. The pinned `web-ext` 10.8.0 tool submits an
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
  --version 0.13.40.1 \
  --output /absolute/path/to/new-wallet-submission
```

Choose the release version for the actual publisher account; the example is not
a reserved version. A stale launcher, dirty tracked source, mismatched wallet
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
strict lint before submitting. It also checks
that the returned XPI's payload matches the submission. It does not treat
`META-INF` filenames as proof of a valid Mozilla signature. `result.json`
explicitly leaves Firefox signature verification outstanding.

## Required adoption step

Before updating the application, run the returned XPI in the supported Firefox
ESR with signature verification enabled. Confirm Firefox reports an ordinary
Mozilla signature, the wallet works, existing storage and UUID survive an
in-place update, and private-window consent and disabled state are preserved.
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
