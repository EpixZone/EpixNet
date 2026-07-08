# iOS secure-context spike (Phase 8b spike #1): decision memo

Date: 2026-07-07
Status: DECIDED - option (c) loopback HTTP, plus App-Bound Domains for service
workers. Option (b) stays on the shelf as a later upgrade. Option (a) is
rejected for this app because the entitlement bans CoreBluetooth, which the
BLE mesh needs.

## The question

Custom-scheme pages served through `WKURLSchemeHandler` cannot register
service workers, so the "intercept `epix://` in a scheme handler" plan from
Workstream C does not give xites a full web platform. Today the iOS shell
(`shells/ios/EpixBrowser/AppDelegate.swift`) sidesteps that by pointing the
WKWebView at the node's loopback UI server (`http://127.0.0.1:42222/<name>/`).
Three escapes were on the table:

- (a) the managed `com.apple.developer.web-browser` entitlement
- (b) iOS 17 `WKWebsiteDataStore.proxyConfigurations` plus a synthetic
  `https://name.epix/` origin terminated by an in-process proxy with a local CA
- (c) accept the loopback origin and document what is lost

One premise update since PLAN.md was written: current WebKit main treats
origins whose scheme is handled by a `WKURLSchemeHandler` as potentially
trustworthy (`LegacySchemeRegistry::schemeIsHandledBySchemeHandler` in
`Source/WebCore/page/SecurityOrigin.cpp`), so `crypto.subtle` can appear on
custom-scheme pages. But service worker registration is hard-coded to reject
non-HTTP(S) script URLs in `ServiceWorkerContainer.cpp` ("serviceWorker.register()
must be called with a script URL whose protocol is either HTTP or HTTPS"), and
WebKit engineers have explained why it cannot be fixed: scheme handlers are
per-WKWebView while service workers are shared across web views (WebKit bug
206741, still open). So the custom-scheme route stays dead for service workers
regardless. Confidence: high.

## Finding 0, the one that changes everything: loopback HTTP is a secure context

`http://127.0.0.1` and `http://localhost` ARE secure contexts in WKWebView on
iOS 16, 17, and 18. The check is in WebCore (`SecurityOrigin.cpp`,
`shouldTreatAsPotentiallyTrustworthy` returns true for
`isLocalHostOrLoopbackIPAddress(host)`), shared by Safari and WKWebView, with
no app-level gate. It shipped with WebKit's Secure Contexts implementation in
2017 (bug 158121, refined by bug 173457) and is present in every iOS version
we target. `window.isSecureContext` is true and `window.crypto.subtle` works
(SubtleCrypto is gated only on `[SecureContext]` since iOS 15, bug 227725).
Confidence: high (primary source: WebKit code and bug tracker; corroborated by
field reports).

Host-string caveats (all from the WebKit source):
- IPv4 must be a full dotted quad starting with `127.` (`127.0.0.1` works,
  `127.1` does not). IPv6 must be exactly `[::1]`.
- `localhost` and `*.localhost` are trusted by name.
- Only the top-level page counts if there are frames: every ancestor must be
  potentially trustworthy too.

Sources:
- https://github.com/WebKit/WebKit/blob/main/Source/WebCore/page/SecurityOrigin.cpp
- https://bugs.webkit.org/show_bug.cgi?id=158121 (Secure Contexts, 2017)
- https://bugs.webkit.org/show_bug.cgi?id=173457 (loopback refactor)
- https://bugs.webkit.org/show_bug.cgi?id=227725 (crypto.subtle secure-context gate, iOS 15)
- https://w3c.github.io/webappsec-secure-contexts/#is-origin-trustworthy

## Finding 1: service workers in WKWebView are gated separately, and loopback gets the best deal

Service workers in WKWebView require one of:
1. the `com.apple.developer.web-browser` entitlement (service workers on all
   domains, no App-Bound restrictions), or
2. `limitsNavigationsToAppBoundDomains = true` on the configuration plus a
   `WKAppBoundDomains` array in Info.plist (max 10 domains).

This linkage is officially undocumented (an Apple frameworks engineer wrote in
2025 "There's no supported way for you to explicitly support service workers in
iOS WKWebView with the APIs currently available", forums thread 773539), but it
is real in the WebKit source and proven in shipping apps (Hotwire Native's
offline mode uses exactly this recipe). Confidence: high that it works,
medium that Apple will ever document it.

The loopback-specific good news, straight from WebKit source:
- `localhost` and `127.0.0.1` are valid `WKAppBoundDomains` entries
  (`WebsiteDataStoreCocoa.mm` parses them fine), and loopback is additionally
  treated as always app-bound for navigation
  (`shouldTreatURLProtocolAsAppBound` in `WebPageProxy.cpp`).
- `SWServer::allowLoopbackIPAddress` exempts localhost/127.x/[::1] from
  app-bound registration validation AND from the cap of 3 unique non-loopback
  service worker registrations per data store (`defaultMaxRegistrationCount = 3`
  in `SWServer.cpp`).
- Registration only requires the script URL protocol to be HTTP or HTTPS plus
  a trustworthy origin, so plain HTTP on loopback registers fine. Field
  confirmation: Masilotti's Hotwire Native offline-mode writeup (Oct 2025,
  iOS 18 era) with `localhost` in WKAppBoundDomains over plain HTTP.

That last point matters enormously for us: an unlimited number of xites served
from the loopback origin can register service workers (scoped by path), while
option (b)'s synthetic per-name `https://name.epix` origins would be
non-loopback and hit the 3-registration cap and the 10-domain plist limit.
Without the entitlement, option (b) cannot scale service workers to arbitrary
xites at all. Confidence: high on the source reading, medium-high on field
behavior (verify on device, step 1 below).

The cost of `limitsNavigationsToAppBoundDomains = true`: that web view can only
navigate to app-bound domains (loopback plus up to 10 listed), and script
injection/message handlers only work on app-bound domains. For us this is
nearly free: xites live on loopback (app-bound, so our wallet bridge and user
scripts keep working) and clearnet is blocked by default per the EpixNet
policy anyway. Clearnet browsing just has to happen in a second web view
configuration without the flag (which then has no service workers, which is
fine, it is someone else's website). Confidence: high.

Sources:
- https://webkit.org/blog/10882/app-bound-domains/
- https://developer.apple.com/forums/thread/773539
- https://bugs.webkit.org/show_bug.cgi?id=206741 (WKWebView service workers, custom schemes)
- https://newsletter.masilotti.com/p/offline-mode-for-hotwire-native-apps
- https://github.com/hotwired/hotwire-native-ios/issues/188
- https://github.com/ionic-team/capacitor/issues/7069 (custom schemes rejected)
- WebKit source: SWServer.cpp, ServiceWorkerContainer.cpp, WebPageProxy.cpp,
  WebsiteDataStoreCocoa.mm

## Option (a): the web-browser entitlement

What it unlocks (high confidence, Apple's own capability list): load pages
from all domains with full script access, service workers in all WKWebView
instances, eligibility to be the user's default browser, Add to Home Screen in
the share sheet. In WebKit terms it simply lifts all App-Bound Domain
restrictions ("All WKWebView instances ... will therefore have unrestricted
API access on all domains", WebKit blog).

What it does NOT do: it does not change secure-context classification, does
not make custom schemes service-worker-capable, and does not permit non-WebKit
engines (that is the separate EU/Japan BrowserEngineKit program,
`com.apple.developer.web-browser-engine.*`, EU-distribution-only, iOS 17.4+).
Confidence: high.

Eligibility and process: the app must be a real general-purpose browser (text
field for arbitrary URLs, handles all http/https navigations directly, no
unexpected redirection). We qualify on purpose grounds, since Epix Browser is
a browser. Apply via https://developer.apple.com/contact/request/default-browser-entitlement/
with team ID and bundle ID. It is granted per team + bundle ID, requires
manually generated provisioning profiles (no Xcode auto-signing), takes
anywhere from weeks to about 7 months per public accounts, and contributor/dev
builds without the granted profile must strip it (Mozilla's focus-ios keeps a
separate no-entitlement configuration for this). Confidence: high on process,
medium on timing.

The disqualifier for us: apps holding the entitlement are banned from a list
of privacy-sensitive Info.plist keys, including
`NSBluetoothAlwaysUsageDescription`. Since iOS 13, ANY CoreBluetooth use
requires that key. Our roadmap has BLE mesh (CoreBluetooth) running inside
this same app. Taking the entitlement therefore means giving up the BLE mesh,
or shipping the mesh as a separate app. The entitled-browser rules also ban
HomeKit, HealthKit, always-on location, and Universal Links claims.
Confidence: high (Apple's "Preparing your app to be the default web browser"
doc lists the banned keys).

Sources:
- https://developer.apple.com/documentation/xcode/preparing-your-app-to-be-the-default-web-browser
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.web-browser
- https://developer.apple.com/support/alternative-browser-engines/
- https://developer.apple.com/forums/thread/660585 (provisioning mechanics)
- https://github.com/mozilla-mobile/focus-ios/issues/1781 (contributor-build pain)
- https://www.andyibanez.com/posts/default-apps-may-not-be-possible-all-devs/

## Option (b): proxyConfigurations plus synthetic https://name.epix origins

The mechanism is real and shipping. `WKWebsiteDataStore.proxyConfigurations`
(iOS 17+) accepts HTTP CONNECT and SOCKSv5 proxies with
`matchDomains`/`excludedDomains` scoping. Onion Browser 3.1 uses it to route
WKWebView through embedded Tor; Proxyman uses HTTP CONNECT to a local MITM
proxy. Our own shell already uses it for the Tor clearnet toggle
(`applyClearnetRouting()` in AppDelegate.swift, SOCKS to 127.0.0.1:43111 with
loopback excluded). And the repo already contains the exact server piece this
option needs, built for desktop B2/B3: `crates/epix-browser/src/proxy.rs` is a
CONNECT proxy that TLS-terminates `*.epix` with per-host leaf certs minted by
`crates/epix-browser/src/ca.rs`, feeding the same axum UI router through the
host rewrite in `crates/epix-ui`. Wiring that listener into the iOS process
via epix-ffi is straightforward. Confidence: high.

The trust problem is where it dies today:
- There is no public API to hand WKWebView a custom CA anchor. The only in-app
  path is the `webView(_:didReceive challenge:)` server-trust override.
- That delegate is confirmed for direct connections, but we found NO primary
  confirmation that it fires and is honored for hosts reached through a
  proxyConfigurations proxy. Apple guidance and every working MITM deployment
  (Proxyman, the forums example) instead assume the CA is installed as a
  user-trusted root via a configuration profile (Settings, install profile,
  then toggle Certificate Trust Settings). Confidence that in-app-only trust
  suffices: low. Confidence that a user-installed profile works: high, but the
  UX is terrible for a consumer app and is exactly the "install our CA on your
  device" flow we do not want to ship.
- Even where a delegate override makes a page load, there is a real risk
  WebKit still counts the origin as having a certificate error and withholds
  full secure-context treatment (service workers especially). Unconfirmed
  either way. Confidence: medium.
- Service workers again: without the entitlement, each `name.epix` is a
  non-loopback registrable domain, so at most 10 can be app-bound and only 3
  unique origins can hold service worker registrations per data store. Does
  not scale to arbitrary xites.

App Store: no guideline forbids a bundled CA used only inside the app's own
web view, and MITM-style apps ship (Proxyman, Charles). The user-installed
profile variant is review-visible and adds friction but has precedent.
Confidence: medium.

Sources:
- https://developer.apple.com/documentation/webkit/wkwebsitedatastore/proxyconfigurations-cdc1
- https://developer.apple.com/documentation/network/proxyconfiguration
- https://developer.apple.com/videos/play/wwdc2023/10002/
- https://developer.apple.com/forums/thread/110312 (proxy + "installed as a trusted root cert on your device")
- https://github.com/OnionBrowser/OnionBrowser/blob/3.X/CHANGELOG.md
- https://docs.proxyman.com/proxyman-ios/vpn-and-proxyman-certificate
- https://bugs.webkit.org/show_bug.cgi?id=140197 (challenge-delegate trust, direct connections)

## Option (c): keep the loopback origin

Given finding 0 and finding 1, "accept degraded" turns out to be barely
degraded at all:

What we get on `http://127.0.0.1:42222`:
- secure context: yes. `isSecureContext === true`, `crypto.subtle`,
  getUserMedia, and every secure-context-gated API. High confidence.
- service workers: yes, once the xite web view opts into App-Bound Domains
  with loopback listed. No registration cap on loopback. High confidence from
  source, needs on-device verification.
- The address bar is ours (native UITextField), so the user sees `talk.epix`,
  not the raw loopback URL. The port is only visible to someone reading
  page-JS `location.href`, not in the chrome.

What we actually lose, honestly:
1. Per-xite origin isolation. All xites share one origin
   (`http://127.0.0.1:42222`), path-scoped like ZeroNet. localStorage,
   IndexedDB, cookies, and permissions are shared across xites. Service worker
   scopes are path-limited, so per-xite SWs under `/<name>/` still work, but a
   malicious xite's script is same-origin with every other xite. This is the
   inherited ZeroNet model; the mitigations are the ones already planned
   (server-side strict CSP per site, sandboxed wrapper, EpixNet#15 clearnet
   block, host allowlist / DNS-rebinding protection from the Tier 1 UI
   security list). Options (a) and (c) share this weakness equally; only (b)
   fixes it, which is why (b) stays on the shelf rather than in the bin.
2. Origin stability is port stability. The origin is port-scoped, so site
   storage and SW registrations are tied to port 42222. The current
   ephemeral-port fallback (`127.0.0.1:0`) would silently orphan all storage.
   Keep the port fixed on device; fallback only in the simulator (where the
   Mac's shared loopback makes collisions possible and storage does not
   matter).
3. `https://` cosmetics. No padlock semantics for embedded third-party
   content expecting https, and historically WebKit blocked https pages from
   fetching http loopback subresources (mixed content, fixed around iOS 18.4,
   WebKit bug 279249). Not relevant to top-level loopback pages.

Real-world precedent for exactly this shape: Firefox iOS served its internal
pages from a plain-HTTP GCDWebServer on localhost for years (guarded by a
session token; a weak token design there just produced CVE-2026-8706, a good
reminder to keep our loopback server's host allowlist and auth wrapper
strict). Hotwire Native apps ship offline mode via localhost App-Bound service
workers. GCDWebServer never got HTTPS and its users lean on the
loopback-is-trustworthy rule; Telegraph exists for those who need real TLS but
its self-signed flow needs the challenge-delegate dance.

Sources:
- https://github.com/mozilla-mobile/firefox-ios/blob/main/firefox-ios/Client/Application/WebServer.swift
- https://www.mozilla.org/en-US/security/advisories/mfsa2026-49/
- https://github.com/swisspol/GCDWebServer (no HTTPS, README)
- https://github.com/Building42/Telegraph
- https://bugs.webkit.org/show_bug.cgi?id=279249 (iOS 18 loopback mixed-content regression, fixed 18.4)

## Comparison

| | (a) entitlement | (b) proxy + local CA | (c) loopback HTTP + ABD |
|---|---|---|---|
| Secure context | yes (loopback already is) | only with user-installed CA profile | yes, today |
| crypto.subtle | yes | yes if trusted | yes, today |
| Service workers, arbitrary xites | yes, all domains | no (3 non-loopback registrations max) | yes (loopback exempt from cap) |
| Per-xite origin isolation | no (still one loopback origin) | yes (its one real win) | no |
| Address shown to user | native bar, ours | native bar, ours | native bar, ours |
| iOS floor | 14+ | 17+ | 14+ (ABD), matches current shell |
| Gatekeeping | Apple grant, weeks to ~7 months, manual profiles | none | none |
| Kills BLE mesh | YES (NSBluetoothAlways banned) | no | no |
| User friction | none | install + trust CA profile in Settings | none |
| New code | none, but ships nothing by itself | proxy wiring, CA UX, cert pinning | ~20 lines (plist + config + 2nd webview) |
| Unproven parts | grant timing | delegate trust through proxy (low confidence) | SW on loopback on-device (medium-high) |

## Recommendation: option (c), loopback HTTP plus App-Bound Domains

Rationale:
1. The premise behind "accept degraded" was wrong in our favor. Loopback HTTP
   is a full secure context in WKWebView, and with `localhost`/`127.0.0.1` in
   `WKAppBoundDomains` plus `limitsNavigationsToAppBoundDomains = true`,
   service workers register on loopback with no registration cap. Nothing
   about the web platform is actually degraded except per-xite origin
   isolation, which options (a) and (c) both lack anyway.
2. Option (a) is poisoned for this app: the entitlement bans
   `NSBluetoothAlwaysUsageDescription`, which the BLE mesh requires. It also
   gates every dev build on Apple-granted provisioning. The one thing it would
   buy us over (c) is service workers on clearnet sites in the browsing web
   view, which we do not need. Revisit only if the mesh moves to a separate
   app AND we want default-browser placement; those are product decisions, not
   spike outcomes.
3. Option (b) is the only route to real per-xite origins, but its trust story
   today requires a user-installed CA profile (unacceptable onboarding for a
   consumer P2P browser) because the in-app challenge-delegate override is
   unconfirmed for proxied hosts, and without the entitlement it caps service
   workers at 3 xites. Park it. If per-xite isolation becomes a hard
   requirement, the desktop machinery (`crates/epix-browser/src/proxy.rs`,
   `ca.rs`, the `epix-ui` host rewrite) ports over and the open questions are
   narrow and testable.

Confidence in the recommendation: high. The single medium-confidence link is
on-device service worker registration on loopback HTTP under ABD, which is
step 1 below and takes an afternoon to verify; if it fails, nothing else about
(c) changes, and the fallback is precisely scoped (SW-needing xites) rather
than existential.

## Implementation steps (option c)

1. Verify on device first (the one thin-evidence link). Add to
   `shells/ios/EpixBrowser/Info.plist`:
   `WKAppBoundDomains = ["localhost", "127.0.0.1"]`
   and set `configuration.limitsNavigationsToAppBoundDomains = true` on the
   xite web view. Load a test xite that registers a service worker under its
   `/<name>/` path and exercises `crypto.subtle` and Cache Storage. Check
   `navigator.serviceWorker.controller` after reload, on a real device, iOS 17
   and 18. Also confirm `evaluateJavaScript` and the wallet message bridge
   still work (loopback is app-bound, so they should).
2. Split web view configurations. Xite web view: app-bound limits on, loopback
   only, service workers available, wallet bridge injected. Clearnet web view:
   no app-bound flag, Tor proxyConfigurations as today, no bridge injection.
   Route navigations between them in `decidePolicyFor` (clearnet links from
   xites are policy-blocked by default anyway, so this mostly formalizes the
   existing block).
3. Pin the port. On device, always bind 42222 and surface a hard error on
   bind failure instead of falling back to an ephemeral port; keep the
   `127.0.0.1:0` fallback simulator-only. Persist and reuse the port if it
   ever must change, and document that changing it wipes xite storage.
4. Keep the Tor proxy exclusion as is. `excludedDomains = ["127.0.0.1",
   "localhost"]` on the SOCKS ProxyConfiguration already guarantees xite
   traffic never detours through Tor. No interaction with ABD.
5. Harden the loopback server (the Firefox CVE lesson). Finish the Tier 1
   items that this architecture leans on: `isHostAllowed` host allowlist with
   the `.epix` wildcard (DNS-rebinding defense), strict per-site CSP from
   `epix-ui`, and the wrapper auth token with a strong random value per
   session, checked on the WebSocket too.
6. Fix the error-page nit. `showError` uses `loadHTMLString(_, baseURL: nil)`,
   which is not a secure context; pass `baseURL: URL(string: nodeBase)` if any
   error-page script ever needs platform APIs (cosmetic today).
7. Xite audit (carried over from the spike definition). Enumerate which real
   xites use service workers, `crypto.subtle`, Cache Storage, or WebRTC, and
   add a CI-able smoke xite covering each API so WebKit regressions (like the
   iOS 18.0 loopback mixed-content one) show up in testing, not in the field.
8. Document the shared-origin model. One paragraph in the iOS README stating
   that xites share the loopback origin, what the CSP/sandbox mitigations are,
   and that per-xite origins have a designed upgrade path (option b) if ever
   needed.

## What would reopen this decision

- On-device verification in step 1 fails (service workers refuse to register
  on loopback HTTP under ABD): re-test with plain `localhost` naming, then
  re-evaluate (b) with the user-installed-profile cost accepted, or (a) with
  the mesh split into a companion app.
- Apple confirms the challenge-delegate trust override works for
  proxyConfigurations hosts, or adds a real custom-anchor API for WKWebView:
  option (b) becomes cheap; revisit for per-xite origin isolation.
- The BLE mesh moves out of the browser app: option (a) becomes viable and
  brings default-browser placement; weigh it then as a product question.
