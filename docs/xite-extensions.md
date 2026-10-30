# Extensions published on xites

The extension manager installs Firefox WebExtensions from verified xites on
desktop and Android. It checks both the xite publisher's signed file entry and
the browser engine's Mozilla signature. A xite signature alone does not grant
extension privileges or replace the browser's permission prompt.

On desktop, open **Extensions from xites** from the toolbar. On Android,
long-press the Epix icon, then choose **Extensions**. Enter the package's xite
URL, review its publisher, extension identity and permissions, then approve the native install
prompt. Closing or cancelling the review does not approve an installation.

## Publishing and updating

Publish the unchanged Mozilla-signed XPI under the xite's signed `files` or
`files_optional` entries. The entry must declare its exact size and supported
file hash. Every declared supported hash must match. Delegated content must
also have a valid signature chain from the accepted xite root.

The node must already know the verified publisher and accepted xite authority.
The manager does not clone an unknown xite or use a stale name mapping. A
missing standalone package with a signed BLAKE3 object identity can be fetched
within the package limit. A bundled package must already be downloaded.

Package addresses use `https://publisher.epix/path/extension.xpi`, `http://`
or `epix://` with the same xite host and path. Queries, fragments, percent
escapes, backslashes and traversal components are rejected. Use a simple
published path. Packages cannot be installed from arbitrary local paths,
ordinary websites or unsigned entries through this manager.

Updates are manual. Choose the installed extension's update action and review
the new package. Its canonical publisher, path and extension ID must match the
original installation. Each update must pass the same signature, byte and
permission checks as an install. An extension already installed outside this
manager cannot be silently adopted.

The manager supports enable, disable and removal for its installed extensions.
Windows retains Firefox's own security updates. Other packages retain their
existing browser update mechanism. Managed extension updates do
not follow an extension's separate update URL or substitute an AMO package for
the reviewed xite package.

## Permissions and platform scope

These are ordinary extensions. They receive only the engine permissions the
user approves. The manager rejects reserved Epix extension IDs and packages
requesting native messaging, extension management, experimental APIs or
GeckoView's privileged addon APIs. It does not attach the wallet's native
message handlers to third-party extensions.

Host permissions still have the browser's normal scope. In particular,
permission for the local node's loopback origin can cover several xites served
by that origin. Publisher verification is not a separate per-xite browser
permission boundary.

The initial native adapters target the packaged Firefox 153 ESR series from
153.4.0 and the pinned Android GeckoView build. Desktop startup checks the
adapter resources and supported engine version before opening the profile.
Android selects and checks its existing Gecko profile before creating the
runtime. Compatibility must be reviewed when changing the engine pin.

The shared Rust verifier and typed mobile interface do not make XPIs portable
to iOS. iOS installation is currently unsupported and rejected explicitly.
A future WebKit adapter needs a distinct compatible-package contract, native
permissions and runtime validation. It must not reinterpret an XPI as an
unsigned WebKit package or disable engine verification.

## Installation and recovery boundaries

The core verifies the accepted authority chain, exact package bytes and ZIP
structure before returning a short-lived candidate. It checks authority and
bytes again before handing an immutable private spool file to the native
adapter. An install is limited to a 32 MiB archive, with up to 256 managed
extensions per profile. Updates remain available at that limit. Parsing, decompression,
manifest size, downloads and private spool storage have separate bounds.

The browser or Android shell verifies the engine result against the candidate.
A durable native-consent record is written only after the user allows the
actual permission prompt. Merely preparing or staging a file is not consent.
The core records ownership only after the exact engine result is reconciled.

Pending installs, updates and removals survive a restart. Startup verifies the
managed archive and browser metadata against the approved receipts before
the engine can activate a staged update. Unknown bytes, inconsistent receipts
or missing required state stop startup or installation with a visible error.
Do not delete receipt files to dismiss that error. Keep the affected profile
and logs for diagnosis, and close the browser before repairing its state.

The desktop adapter uses a fixed privileged browser page and an authenticated
loopback protocol. Credentials are passed to the launched process in its
environment, not stored in the profile. Requests and responses bind their
exact bytes; requests also bind a timestamp and a single-use nonce. Page
origins cannot call this interface. Android calls the typed Rust interface
directly. Neither route is exposed as a xite frame command or wallet API.

This boundary protects against untrusted xites and ordinary extensions. It
does not claim protection against a compromised browser engine, a privileged
extension, or a local process with the user's native access.

## Packaged desktop theme

The Epix theme is a static application resource registered through Firefox's
built-in add-on API. It contains only light and dark colors, and the launcher
checks its manifest and registration module against the exact bundled bytes
before opening Firefox. It is not an AMO-signed download or an extension from
a xite. Its updates ship with EpixNet.

Existing profiles migrate the old unsigned theme through Firefox's add-on
lifecycle. The current theme selection is preserved, including a deliberate
switch back to the System theme. The launcher no longer repacks the theme or
edits Firefox's add-on database to activate it. This does not change the
signature requirements for extensions installed from xites or the separate
bundled-wallet installation policy.

## Local desktop builds

The platform packaging scripts stage the fixed adapter into the bundled
Firefox. A local `cargo run -p epix-browser` also needs those matching resources;
an unrelated system Firefox installation does not satisfy the startup check.

Extract or copy the supported Firefox ESR bundle into a development directory
you own. From the EpixNet checkout, stage the adapter into that copy's resources
directory, then select its executable explicitly:

```sh
python3 packaging/firefox-addons/install.py /absolute/path/to/development/firefox
EPIX_FIREFOX=/absolute/path/to/development/firefox/firefox cargo run -p epix-browser
```

The example is for Linux. On Windows the executable is `firefox.exe`; on macOS
the staging argument is the copied Firefox app's `Contents/Resources` directory
and the executable is `Contents/MacOS/firefox`. Restage and rebuild after editing
adapter files, because the launcher checks them against its compiled resources.
Use a disposable data directory and profile for install and failure tests.

## Validation

Focused automated checks:

```sh
cargo test --locked -p epix-ui --lib addon
cargo test --locked -p epix-runtime addon
cargo test --locked -p epix-browser addon
node --test packaging/firefox-addons/tests/*.test.mjs
python3 shells/android/tests/run-addon-policy-regressions.py
```

Native acceptance must also use the actual packaged Firefox and full Android
APK. Use disposable profiles and a public signed xite fixture. Verify a real
signed installation and native denial; unsigned, changed and foreign-ID
packages; manual updates with unchanged and expanded permissions; cancellation
and expiry; interrupted install/removal; restart; and existing wallet profile
preservation. Test the release configuration as well as debug diagnostics.
Source-level tests and generated bindings do not replace these engine checks.
