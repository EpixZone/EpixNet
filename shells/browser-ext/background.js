// Epix browser extension - background script.
//
// Three jobs:
//   1. Proxy routing (B5): `.epix` hosts go to the node's browser proxy (https);
//      clearnet goes DIRECT, or through the node's Tor SOCKS listener when the
//      user turns on "route clearnet through Tor".
//   2. Clearnet block (EpixNet #15): a `.epix` page may not reach clearnet
//      unless the user allowed that site.
//   3. Tor status icon: poll the node (via the native host) and reflect the Tor
//      state in the toolbar icon, like Brave's Tor indicator.

const NATIVE_HOST = "zone.epix.nmh";
const PROXY_PORT = 43112; // node browser proxy (TLS-terminates .epix)
const SOCKS_PORT = 43111; // node Tor SOCKS listener

// State kept in memory, synced from storage / the native host.
let allowed = new Set(); // .epix sites permitted to reach clearnet
let torClearnet = false; // route clearnet browsing through Tor

browser.storage.local.get(["clearnetAllow", "torClearnet"]).then((data) => {
  allowed = new Set((data && data.clearnetAllow) || []);
  torClearnet = !!(data && data.torClearnet);
  applyProxy(); // take over routing from the launcher's file PAC
});
browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.clearnetAllow) allowed = new Set(changes.clearnetAllow.newValue || []);
  if (changes.torClearnet) torClearnet = !!changes.torClearnet.newValue;
});

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}
const isEpix = (h) => h.endsWith(".epix");
const isLocal = (h) => h === "127.0.0.1" || h === "localhost" || h === "[::1]";

// 1. Proxy routing, via the proxy.settings API with a generated PAC. `.epix`
// always goes to the node's browser proxy; clearnet goes DIRECT, or through the
// node's Tor SOCKS listener when the user turns it on. Regenerated live when
// the toggle changes (a clean override of the launcher's file PAC).
function applyProxy() {
  const clearnet = torClearnet
    ? `return "SOCKS5 127.0.0.1:${SOCKS_PORT}";`
    : `return "DIRECT";`;
  const pac =
    `function FindProxyForURL(url, host) {` +
    `if (shExpMatch(host, "*.epix")) return "PROXY 127.0.0.1:${PROXY_PORT}";` +
    `if (host === "127.0.0.1" || host === "localhost") return "DIRECT";` +
    `${clearnet}}`;
  const dataUrl = "data:application/x-ns-proxy-autoconfig," + encodeURIComponent(pac);
  browser.proxy.settings.set({ value: { proxyType: "autoConfig", autoConfigUrl: dataUrl } });
}

// 2. Clearnet block.
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    const originHost = hostOf(details.originUrl || details.documentUrl || "");
    if (!isEpix(originHost)) return {};
    const url = details.url || "";
    if (
      url.startsWith("data:") ||
      url.startsWith("blob:") ||
      url.startsWith("about:") ||
      url.startsWith("moz-extension:")
    ) {
      return {};
    }
    const targetHost = hostOf(url);
    if (isEpix(targetHost) || isLocal(targetHost)) return {};
    if (allowed.has(originHost)) return {};
    console.warn(`Epix: blocked clearnet request from ${originHost} -> ${url}`);
    return { cancel: true };
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// CSP reinforcement on .epix documents (only add if missing).
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!isEpix(hostOf(details.url))) return {};
    const headers = details.responseHeaders || [];
    if (!headers.some((h) => h.name.toLowerCase() === "content-security-policy")) {
      headers.push({
        name: "Content-Security-Policy",
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

// 3. Tor status icon.
let lastStatus = { tor_status: "Unknown" };

function iconFor(status) {
  // Ready + routing clearnet through Tor -> green; ready -> purple;
  // bootstrapping -> amber; otherwise off/gray.
  if (status.tor_enabled) return torClearnet ? "icons/tor-routed.png" : "icons/tor-ready.png";
  if (status.tor_status === "Bootstrapping") return "icons/tor-boot.png";
  return "icons/tor-off.png";
}

function titleFor(status) {
  if (status.tor_enabled) {
    return torClearnet
      ? "Tor: on - clearnet routed through Tor"
      : "Tor: ready (clearnet direct)";
  }
  if (status.tor_status === "Bootstrapping") return "Tor: connecting…";
  return "Tor: off";
}

async function pollStatus() {
  try {
    lastStatus = await browser.runtime.sendNativeMessage(NATIVE_HOST, { cmd: "status" });
  } catch (e) {
    lastStatus = { tor_status: "Unknown" };
  }
  browser.browserAction.setIcon({ path: { 32: iconFor(lastStatus) } });
  browser.browserAction.setTitle({ title: titleFor(lastStatus) });
}
setInterval(pollStatus, 5000);
pollStatus();

// Popup <-> background messaging.
browser.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "getState") {
    sendResponse({
      status: lastStatus,
      torClearnet,
      allow: msg.host ? allowed.has(msg.host) : false,
    });
    return false;
  }
  if (msg.type === "setAllow") {
    if (msg.allow) allowed.add(msg.host);
    else allowed.delete(msg.host);
    browser.storage.local.set({ clearnetAllow: Array.from(allowed) });
    try {
      browser.runtime.sendNativeMessage(NATIVE_HOST, {
        cmd: "setClearnetAllow",
        site: msg.host,
        allow: msg.allow,
      });
    } catch (e) {}
    sendResponse({ ok: true });
    return false;
  }
  if (msg.type === "setTorClearnet") {
    torClearnet = !!msg.on;
    browser.storage.local.set({ torClearnet });
    applyProxy(); // reroute clearnet live
    try {
      browser.runtime.sendNativeMessage(NATIVE_HOST, { cmd: "setTorClearnet", on: torClearnet });
    } catch (e) {}
    pollStatus(); // refresh the icon immediately
    sendResponse({ ok: true });
    return false;
  }
  return false;
});
