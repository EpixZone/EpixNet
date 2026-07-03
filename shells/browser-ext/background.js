// Epix browser extension - background script.
//
// Enforces the xite security contract in the browser:
//   1. Clearnet block - a page on a `.epix` origin may not make requests to
//      clearnet (tracking / deanonymization), unless the user has allowed that
//      site. This is the EpixNet #15 rule, browser-side.
//   2. CSP reinforcement - make sure a `.epix` document response carries a
//      Content-Security-Policy (the node sets one; this is belt-and-suspenders
//      so a proxy hiccup can't drop it).
// Per-site "allow clearnet" is stored in extension storage and mirrored to the
// native host so the node/launcher share the setting.

const NATIVE_HOST = "zone.epix.nmh";

// In-memory allowlist of `.epix` hosts permitted to reach clearnet.
let allowed = new Set();

// Load the allowlist from storage at startup and keep it in sync.
browser.storage.local.get("clearnetAllow").then((data) => {
  const list = (data && data.clearnetAllow) || [];
  allowed = new Set(list);
});
browser.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.clearnetAllow) {
    allowed = new Set(changes.clearnetAllow.newValue || []);
  }
});

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}

function isEpix(host) {
  return host.endsWith(".epix");
}

function isLocal(host) {
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]";
}

// 1. Clearnet block.
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const originHost = hostOf(details.originUrl || details.documentUrl || "");
    // Only police requests made by a `.epix` page.
    if (!isEpix(originHost)) return {};

    const url = details.url || "";
    // Non-network schemes are always fine.
    if (
      url.startsWith("data:") ||
      url.startsWith("blob:") ||
      url.startsWith("about:") ||
      url.startsWith("moz-extension:")
    ) {
      return {};
    }
    const targetHost = hostOf(url);
    // Same-network (other `.epix`) and loopback (the node) are allowed.
    if (isEpix(targetHost) || isLocal(targetHost)) return {};

    // A clearnet request from a `.epix` page: block unless the site is allowed.
    if (allowed.has(originHost)) return {};
    console.warn(`Epix: blocked clearnet request from ${originHost} -> ${url}`);
    return { cancel: true };
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// 2. CSP reinforcement on `.epix` documents (only add if missing, so we never
// weaken or fight the node's own wrapper/sandbox CSP).
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    const host = hostOf(details.url);
    if (!isEpix(host)) return {};
    const headers = details.responseHeaders || [];
    const hasCsp = headers.some(
      (h) => h.name.toLowerCase() === "content-security-policy"
    );
    if (!hasCsp) {
      headers.push({
        name: "Content-Security-Policy",
        // Allow self + the wrapper runtime + the local node's WS; no clearnet.
        value:
          "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
      });
      return { responseHeaders: headers };
    }
    return {};
  },
  { urls: ["<all_urls>"], types: ["main_frame", "sub_frame"] },
  ["blocking", "responseHeaders"]
);

// Popup <-> background messaging: get/set the current site's clearnet allow.
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "getAllow") {
    sendResponse({ allow: allowed.has(msg.host) });
    return false;
  }
  if (msg.type === "setAllow") {
    if (msg.allow) allowed.add(msg.host);
    else allowed.delete(msg.host);
    const list = Array.from(allowed);
    browser.storage.local.set({ clearnetAllow: list });
    // Mirror to the native host (best effort - it persists for the node).
    try {
      browser.runtime.sendNativeMessage(NATIVE_HOST, {
        cmd: "setClearnetAllow",
        site: msg.host,
        allow: msg.allow,
      });
    } catch (e) {
      /* native host optional */
    }
    sendResponse({ ok: true });
    return false;
  }
  return false;
});
