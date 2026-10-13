# The wrapper sandbox: how a xite page is kept out of the node

Every xite is shown inside the wrapper page (`ui/wrapper.html` plus
`ui/media/all.js`), which the node serves at `/{address}/`. The wrapper owns
the WebSocket to the node; the xite page lives in an iframe and reaches the
node only through `postMessage` to the wrapper, which forwards page commands
over that socket. This document describes what keeps that boundary real and
what a xite loses because of it.

## The iframe is an opaque origin

The inner iframe's `sandbox` attribute has no `allow-same-origin`. The xite
page therefore runs in an opaque ("null") origin even though its files are
served from the node's own host:

- it cannot read or script the wrapper window, its globals or its DOM;
- a WebSocket, fetch or XHR it opens itself carries `Origin: null`;
- it has no `localStorage`, cookies, IndexedDB or service worker (the
  wrapper offers `wrapperGetLocalStorage` / `wrapperSetLocalStorage`
  instead, keyed by xite and identity);
- its subresources (scripts, styles, images) load with no `Referer` and
  `Sec-Fetch-Site: cross-site`; its CORS-mode loads (fonts, ES modules,
  fetch, XHR) carry `Origin: null`.

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
- An upgrade with `Origin: null` is refused outright: the wrapper is never an
  opaque origin, the xite frame always is.
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

## What a xite author must know

- Use the wrapper storage commands, not `localStorage`; guard any direct use
  with `try`/`catch` (it throws `SecurityError` in the sandbox).
- `navigator.serviceWorker` throws in the sandbox; do not touch it unless
  the xite holds `NOSANDBOX`. A xite that needs a service worker needs that
  grant, or a future per-xite origin (see below).
- Fonts and ES modules load from the xite's own files. Fetching another
  xite's files needs `Cors:<address>`, requested through the wrapper.

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

Path mode (the loopback UI, Chrome and other browsers, the Android shell)
keeps the opaque sandbox above: there every xite would share the node's
origin. `crates/epix-evx/examples/wrapper_fixture.rs --host` serves host mode through the
browsers' proxy for a real-browser check.

## Known limits

- The existence of a xite file can still be probed by a `no-cors` load from
  a page that suppresses its `Referer`; the bytes are not readable. Modern
  browsers' local-network-access rules and the browser extension's clearnet
  block both stand in front of this.
- Path mode cannot give a xite a real origin of its own; a xite that needs
  storage or a service worker there needs `NOSANDBOX` or the Epix browser.

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
