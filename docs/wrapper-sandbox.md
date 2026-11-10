# The wrapper sandbox: how a xite page is kept out of the node

Every xite is shown inside the wrapper page (`ui/wrapper.html` plus
`ui/media/all.js`), which the node serves at `/{address}/`. The wrapper owns
the WebSocket to the node; the xite page lives in an iframe and reaches the
node only through `postMessage` to the wrapper, which forwards page commands
over that socket. This document describes what keeps that boundary real and
what a xite loses because of it.

## Shared-origin serving keeps the iframe opaque

When the page's files share the wrapper's host, the inner iframe's `sandbox`
attribute has no `allow-same-origin`. The xite page therefore runs in an
opaque ("null") origin. This remains the fallback for LAN and public gateway
access. Local loopback access and the desktop browser use separate content
origins, described below. An opaque page:

- it cannot read or script the wrapper window, its globals or its DOM;
- a WebSocket, fetch or XHR it opens itself carries `Origin: null`;
- it has no `localStorage`, cookies, IndexedDB or service worker (the
  wrapper offers `wrapperGetLocalStorage` / `wrapperSetLocalStorage`
  instead, keyed by xite and identity);
- its subresources (scripts, styles, images) load with no `Referer` and
  `Sec-Fetch-Site: cross-site`; newer Gecko also sends `Origin: null` on
  these no-cors loads. Its CORS-mode loads (fonts, ES modules, fetch, XHR)
  carry `Origin: null` too.

The `NOSANDBOX` permission is exactly `allow-same-origin`. A same-origin page
could open the node's WebSocket as the wrapper's origin and script a wrapper
instance through a popup, so that grant is full trust and the prompt says so.

## The wrapper authenticates with a secret

Each xite has two random, persisted secrets in its settings (`XiteSettings`
in `crates/epix-xite`): `wrapper_key` and `ajax_key`. They are rendered only
into the wrapper page's own script block and are stripped from every
`siteInfo` and xite event a page can receive (`AppState::public_settings`).

- The wrapper opens `/EpixNet-Internal/Websocket?wrapper_key=<secret>`. The
  node resolves the secret to the xite and marks the session as a **wrapper
  socket** (`WsSession::wrapper`). Only on such a socket do the chrome's own
  commands, numbered from `WRAPPER_ID_BASE` (1 000 000), carry wrapper
  authority (`WsSession::elevated`): admin commands without a grant,
  `permissionAdd` after the user tapped Grant, and answers to server-pushed
  confirm/prompt dialogs. Page commands the wrapper forwards keep the page's
  small ids and the page's authority.
- Any other socket (an address or name as the key, an unknown key, no key) is
  a page-level session: it binds to the address for events and ordinary
  commands, and an elevated id on it is just a number the client chose.
- An upgrade with `Origin: null` or a reserved xite content origin is refused
  outright. Only the trusted wrapper origin can open its privileged socket.
- A wrapper rendered while its xite is still being added (the loading
  screen) gets keys reserved for that address; `add_xite` adopts them, so the
  page already open keeps its authority once the xite lands.

## The file gate accepts the opaque frame's own loads

`security_gate` in `crates/epix-ui/src/lib.rs` decides which requests may
read xite files when the cross-origin check is on (`ui_check_cors`, the
default for loopback binds). For the opaque frame:

| Request shape | Decision |
| --- | --- |
| Navigation (`Sec-Fetch-Mode: navigate`) | allowed, as before |
| No `Origin`, no `Referer`, `Sec-Fetch-Mode: no-cors` with a destination | allowed for xite paths: a script, style or image the page runs or renders but cannot read. Backup and operator pages stay blocked. |
| No `Origin`, no `Referer`, no `Sec-Fetch-Mode` | blocked (untraceable, as before) |
| `Origin: null`, `Sec-Fetch-Mode: no-cors`, destination `script`, `style`, `image`, `font`, `audio`, `video` or `track` | allowed for xite files, without a CORS read grant. This covers newer Gecko's sandboxed subresources. Wrapper documents, backup and operator pages stay blocked. |
| `Origin: null` with a valid `ajax_key` | allowed when the key's xite is the target or holds `Cors:<target>`; the response gets `Access-Control-Allow-Origin: null` so the page can read it |
| `Origin: null`, no key, `Sec-Fetch-Dest: font` or `script` in CORS mode | allowed with the CORS grant: the xite's own fonts and ES modules, which execute or render without exposing bytes |
| `Origin: null` otherwise | blocked, and never given a CORS grant even with the gate off |
| A real foreign origin | blocked, as before |

The frame library (`epixframe.js`) asks the wrapper for the `ajax_key` and
appends it to the page's XHR and fetch URLs once the page calls
`monkeyPatchAjax()`; that is what makes a xite's own `fetch("data.json")`
work from the opaque origin. A page that fetches its own files without the
key does not get them in path mode (the shipped dashboard's translation
loader does this today and must enable the patch). The key never reads the
wrapper document itself, which carries the xite's secrets. The one write a page makes
over HTTP, the Bigfile upload POST, is accepted from a null origin because
its one-time `upload_nonce` authorises it.

## The waiting placeholder announces itself

While a xite is still downloading, the node answers the inner document
request with a placeholder page (`download_wait_response`). The wrapper used
to recognise it by reading the frame's document, which an opaque frame
forbids; the placeholder now posts `{cmd: "innerLoadState", params:
"waiting"}` to the wrapper from inside the frame. The wrapper keeps its
loading screen up while that state stands and reloads the frame once, when
the clone completes. A frame still on `about:blank` is never counted as the
loaded xite. `ui/tests/loading-browser.cjs` exercises this flow in a real
browser against the production wrapper.

## Documents in the opaque frame

The chrome cannot read the frame's document, so it cannot tell one document
from the next by identity, and the frame's `load` event does not count
documents either: a missing subresource holds a document's load event back
for minutes while the user may reload, and Chromium fires it for the chrome's
own fragment-only src writes on the same cross-origin document. What
identifies a document is its own word. Readiness (`innerReady`), the
`wrapperOpenedWebsocket` announcement and the placeholder state belong to one
document and start over for the next (`Wrapper.prototype.newInnerDocument`
in `ui/media/all.js`):

- the frame library sends `innerReady` once, at construction, so an
  `innerReady` from a document that already introduced itself is its
  replacement (an in-frame reload keeps the WindowProxy and the URL);
- only the first document can have spoken before the chrome listened
  (`script_init` navigates the frame before `all.js` runs), so a document
  that has not spoken is probed at every load with a `ping`, which the
  library answers with `pong` on the chrome's own message id. That reply
  never looks like a new document, unlike the repeated `innerReady` that
  `wrapperReady` provokes: a page whose library starts at `load` can have its
  load event reach the chrome before its own `innerReady` does;
- a page without a frame library is invisible: it inherits the previous
  document's state (an announcement addressed to nobody costs nothing) and
  the next document that has a library introduces itself;
- the chrome's own reload (`reloadIframe`) starts a new document when it
  navigates the frame, so a late nonce reply cannot act on the next one; a
  real document that arrives by itself while that reload awaits its nonce
  releases it;
- the placeholder's `innerLoadState` is accepted only from a document that
  has not introduced itself, and the answer to one of the chrome's own
  commands (ids from 1000000 up) whose callback was released is dropped,
  never forwarded to the page. A page can neither make the chrome reload the
  frame on its say-so nor read the fresh wrapper nonce such a reload asks
  the node for.

`ui/tests/wrapper-startup.test.cjs` covers the event orders synthetically and
`ui/tests/wrapper-startup-browser.cjs` drives them through Chromium with the
production wrapper.

## What a xite author must know

- Use the wrapper storage commands for portable storage. Guard direct
  `localStorage` and `navigator.serviceWorker` access with `try`/`catch`:
  they remain unavailable in the opaque fallback. Separate content origins
  provide browser storage scoped to that xite without a `NOSANDBOX` grant.
- Fonts and ES modules load from the xite's own files. Fetching another
  xite's files needs `Cors:<address>`, requested through the wrapper.

## Shared xID avatar thumbnails

A xite can vendor the node's [avatar helper](../ui/media/epix-avatar.js) in
its signed files. Call `EpixAvatar.bind(img, profile.avatar, 80)` for an
80-pixel image, or pass `{background: true}` for a CSS background. Pass the
original profile URL and the displayed side length in pixels (1 to 128).
The helper uses the xite's `Page` frame by default. An explicit `{frame}`
can be supplied to `bind`. Clearing or replacing the URL supersedes a pending
image. `EpixAvatar.get(url, size, frame)` returns a promise for a PNG data URL
or null for renderers with their own fallback.

The wrapper looks up the original URL and size in a private node cache scoped
to the selected user. Other xites on the same node can use that thumbnail.
Entries expire after one day and the cache holds at most 128 across users.
The node stores hashes of the keys and PNGs encoded from bounded RGBA pixels.
Xites can request a known URL and size. As with other shared caches, response
timing or availability offline can reveal that such an image was used before.

On a miss a separate, opaque, node-supplied frame fetches an eligible remote
raster image under the browser's network policy. It omits credentials and
referrers, requires a readable CORS response, and rejects redirects and
`Cache-Control: no-store`. It limits input to 5 MiB and 32 megapixels, requests
Gravatars at the display size, and center-crops and downsamples larger images
using Lanczos3 (Pica 10.0.3, MIT). The processor sends pixels to the wrapper
over a private port. Only a local wrapper socket can populate the cache.
A separate port returns the result to the requesting xite document, so a
navigation during a download cannot deliver the image to its successor.

Older nodes and images ineligible for caching use the xite's ordinary image
display path. The helper still selects the display size for Gravatar URLs.

## Host mode: a real origin per xite

In the Epix browsers (desktop, iOS) every xite is served under its own
`.epix` host through a local TLS proxy. There the page does not need to be
opaque, because it can have a real origin that is still not the wrapper's:

- `https://talk.epix/` is the **chrome host**: it serves the wrapper and
  nothing else. Any xite file requested there is redirected to the content
  host, so no xite HTML can ever run as the wrapper's origin.
- `https://talk.content.epix/` is the **content host**: the iframe loads from
  it, the xite's files are served from it, and it is the page's own origin.
  The sandbox keeps `allow-same-origin` here, so the page has `localStorage`,
  IndexedDB and service workers, scoped to that xite.
- A document navigation that reaches a content host (a `_top` link from
  inside the page, a typed URL) is redirected back to the chrome host.
- The node accepts no WebSocket on a content host and none whose `Origin`
  is a content host; the wrapper's socket comes only from the chrome host.
- The wrapper page is unreadable from the content origin (no CORS grant),
  so the keys stay with the chrome. `content.epix` is a reserved name.

`crates/epix-evx/examples/wrapper_fixture.rs --host` serves host mode through
the browser's proxy for a real-browser check.

## Loopback access: a canonical address origin per xite

When the node listens on loopback and the wrapper is opened through
`127.0.0.1`, `localhost`, or `::1`, its inner page uses
`http://epix-<canonical-address>.localhost:<node-port>/`. The browser resolves
these reserved localhost names locally. The wrapper remains on the node's
trusted origin. The content iframe can keep `allow-same-origin` because it
shares neither the wrapper's origin nor another xite's origin.

The host contains the full checksum-valid bech32 address. Names and address
aliases that resolve to the same xite use that same content host. The node
port remains part of the origin. Wallet account grants therefore belong to
the xite and local node instance, rather than every path on a shared
`127.0.0.1` origin. Provider messaging uses its normal exact-origin transport.

The content-host route is separate from node routing and remains enforced
when `ui_check_cors` is disabled:

- File reads are bound to the xite and its existing grants. The content host never renders the
  wrapper, Login, configuration, backup, wallet UI, or other node controls.
  Malformed and trailing-dot content-host aliases are rejected as well.
- Raw file requests to the local node also redirect to the canonical content
  host, including iframe requests and URLs containing a forged wrapper nonce.
  Only trusted wrapper pages render on the node origin. Non-HTML files remain
  on their content origin for viewing or downloading, avoiding a redirect loop.
- Content hosts cannot open the node WebSocket, even with a wrapper key.
  Encoded separators, traversal, raw routes, and another xite's path cannot
  place that other xite's active content under the current wallet identity.
- Top-level navigation returns to the node wrapper. The dashboard's exact
  configuration, plugin, statistics, and backup links redirect to the node
  UI only for top-level GET navigation. These redirects happen before content
  cookie checks because partitioned iframe cookies do not follow top-level
  navigation; the destination node still authenticates with its own session.
  Inner-file nonce parameters are removed so the destination renders its wrapper.
  A top-level image or download without a content session first returns through
  the node's normal authentication and receives a fresh content bootstrap.
  The return address uses the trusted connection's loopback address family. Passive cross-xite
  resources are redirected to their own canonical content host.
- Authorized merger and `Cors:` data reads keep their existing same-origin
  URL and authenticated session. Each request rechecks the source, target,
  and grant; another origin cannot borrow those grants. Foreign file responses
  use `Content-Security-Policy: sandbox`, `nosniff`, and `no-store`, so a
  headerless navigation cannot execute those bytes as the requesting xite.
  `Cross-Origin-Resource-Policy: same-origin` also blocks foreign classic
  script embeds, including clients without fetch metadata. Known foreign
  active/data requests without source identity are denied.
  Document, iframe, object, and embed requests instead go to the target's own
  content origin. Revoking a grant invalidates subsequent data reads.
- Two existing xite endpoints remain available under narrow rules: passive
  audio/video reads of `/bt/stream`, and same-origin `BigfileUpload` POSTs
  with a one-time upload grant bound to that xite. Other global routes remain
  blocked. Stream and upload responses are sandboxed and cannot act as pages.
- The existing UI password remains required. A content document can inherit
  authenticated access only through its issued wrapper nonce or a valid
  content-host session. Authorized cross-xite redirects reuse the existing
  one-use nonce bootstrap for the target host. Content cookies are host-only,
  `Secure`, `HttpOnly`, and `SameSite=None` so the isolated iframe can retain
  its own session. The node cookie is unchanged. This does not grant access
  to node routes.

The wrapper also binds both directions of its page transport to the
configured content origin. It checks the source WindowProxy and exact origin
before handling a message, including xID link completion. Normal EpixFrame
commands retain their existing nonce check.
Replies and events use the exact target origin. Navigating the same iframe
to a merged xite cannot transfer the first xite's wrapper authority or
pending replies. The opaque fallback accepts the browser's literal `null`
origin and retains its existing opaque-frame response transport.

Loopback content hosts are not advertised for LAN or public gateway
visitors: their localhost would refer to a different machine. Those modes
retain the opaque sandbox unless their deployment supplies the existing
separate `.epix` content hosts. The wrapper's script-nonce CSP is unchanged.

## Known limits

- The existence of a xite file can still be probed by a `no-cors` load from
  a page that suppresses its `Referer`; the bytes are not readable. Modern
  browsers' local-network-access rules and the browser extension's clearnet
  block both stand in front of this.
- LAN and public-gateway path mode still has an opaque origin. Wallets that
  require an exact-origin page transport need a local node or a deployment
  with separate content hosts; removing the shared-origin sandbox is not a
  substitute.

## Trusted rendering and consent

Publisher titles are HTML-escaped. Paths, queries and other values placed in
JavaScript literals use JSON escaping with HTML script delimiters escaped.
Template substitution scans only the template, so publisher text containing
`{script_nonce}` or `{wrapper_key}` cannot cause a second substitution.
Background-color hints cannot add CSS declarations. The wrapper sends
`frame-ancestors 'none'` and `X-Frame-Options: DENY`, preventing a foreign page
from overlaying its consent controls. WebSocket origin matching includes the
port, since another local server is a different origin. Expired grants are
shown as expired rather than enabled in both the inspection page and dialog.

## Troubleshooting a wrapper CSP warning

The wrapper's `script-src` policy requires its scripts to carry the nonce
generated for that page response. `wasm-unsafe-eval` permits WebAssembly
compilation, not JavaScript `eval` or inline scripts without that nonce.
An extension that inserts a script into the page without the nonce can
therefore produce a CSP warning while the wrapper itself works normally.

A Firefox console source such as `sandbox eval code` is a clue, not proof
that an extension caused the warning. If it appears in an ordinary window
but not a private window, compare the enabled extensions: Firefox disables
extensions in private windows unless the user permits them there. See
[Mozilla's private browsing extension guidance](https://support.mozilla.org/en-US/kb/extensions-private-browsing).
Private browsing also changes browser state, so this comparison alone does
not identify the cause or a particular extension.

Retest the same URL in a fresh Firefox profile or temporary
[Troubleshoot Mode](https://support.mozilla.org/en-US/kb/troubleshoot-firefox-issues-using-safe-mode).
If an extension is responsible, identify it by enabling extensions one at
a time. Where that extension supports site exclusions, exclude the local
node URL from its page injection. Keep EpixNet's CSP enabled. If the warning
persists in a clean profile, report the Firefox version, URL, console source
location, and whether the page works, so a first-party script failure can
be investigated.
