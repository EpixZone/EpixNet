# Engineering review notes

This work spans four repositories. EpixDash changes were committed, pushed and
merged in [PR #37](https://github.com/EpixZone/EpixDash-Xite/pull/37), then signed
and published by the owner. EpixNet mobile changes are committed on `codex/mobile-store-release`, with
current main-branch startup/navigation changes merged. Wallet changes were merged in
[PR #18](https://github.com/EpixZone/epix-wallet/pull/18), at
`c31832e1aabd89ee29691951ac673cfe961a3f1a`. EpixSites-Xite changes
remain local and unpublished. No store uploads have been made.

## EpixNet

The iOS shell previously served browsed xites and wallet documents through
loopback paths. The new shared `epix-browser-net` crate gives xites distinct
HTTPS origins and redirects cross-xite path links before serving their files.
The desktop uses the same extracted proxy. A per-install CA signs only valid
private Epix hosts; it must never issue certificates for public domains.

WebKit's native security origin, frame URL, port and visible-tab identity control
dApp requests. Page-supplied origins and router metadata are replaced. Only
external background messages are forwarded, through the existing wallet router.
The native layer allows one outstanding request, applies readiness/request
timeouts and cancels on tab/page changes, close and backgrounding. These are
security boundaries, not a mechanism for bypassing transaction approvals.

Wallet-only storage/settings bridges remain limited to the exact loopback
wallet document and main frame. Storage failures propagate to JavaScript and
do not overwrite the last valid vault. The wallet uses a nonpersistent WebKit
store and iOS file protection; its document is removed on backgrounding.

iOS now explicitly links the Rust static archive. Using `-lepix_ffi` previously
selected a dynamic library with an absolute developer-machine path when both
archive and dylib were present. The package checker rejects that dependency.

Android packaging updates address API/16 KB native compatibility. Android
and desktop keep BitTorrent. The shared FFI now initializes a private-origin
proxy as part of node startup; Android still uses its existing browser routing.
Validate the modest extra listener/CA initialization in sustained-device QA.

## epix-wallet

`mobile-provider.ts` installs the public provider into a browsed iOS page.
`mobile-env.ts` moves external interaction UI into the persistent wallet
document while retaining external message classification and approval guards.
Cancellation during UI replacement cannot later forward the protected request.
Ordinary browser extensions and internal requests retain their existing transport.

The inherited privileged website allowlist is empty, so those upstream sites
do not bypass normal wallet permission prompts in Epix. Terms and privacy links
are separately configured HTTPS pages; missing configuration is a store-build
failure. `epix-mobile-build.json` records revision, source cleanliness, provider
protocol, policy URLs and whether analytics was configured (no secret values).

Publish the reviewed wallet source as a new immutable artifact before changing
EpixNet's revision/SHA pins. Do not stamp the local QA directory as a released build.

## EpixSites-Xite

Rules acceptance and local contributor/owner blocking were added. Flagged audit
rows withhold original text, destinations and report notes. Tests use benign
fixtures. The signed content manifest was deliberately not regenerated; the
operator's publication and moderation workflow must make these changes live.

## EpixDash-Xite

The DeFlix discovery tile and its unused style were removed. The small-screen
toggle says **Discover** with no feed entries and **Feed** when entries exist,
using the existing translation strings. Rendered-output checks cover those
transitions and the ten remaining discovery tiles. The published files have
reached the iPad node and match its content manifest; see the
[publication evidence](release-validation.md#dashboard-publication).

## Review limitations

Focused tests and simulator smoke checks do not certify the wallet or network
stack. Full signing/approval/recovery, device permission behavior, privacy/export
validation and the final pinned artifacts remain release gates. See the
[validation record](release-validation.md) and [blocker list](README.md).
