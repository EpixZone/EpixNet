// Epix extension popup: Tor status + the route-clearnet-through-Tor toggle, and
// the current site's per-site clearnet allow.

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}

async function currentTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function renderTor(status, torClearnet) {
  const dot = document.getElementById("dot");
  const text = document.getElementById("torText");
  const onion = document.getElementById("onion");
  dot.className = "dot";
  if (status.tor_enabled) {
    if (torClearnet) {
      dot.classList.add("routed");
      text.textContent = "Tor: on - clearnet routed through Tor";
    } else {
      dot.classList.add("ready");
      text.textContent = "Tor: ready (clearnet direct)";
    }
  } else if (status.tor_status === "Bootstrapping") {
    dot.classList.add("boot");
    text.textContent = "Tor: connecting…";
  } else {
    text.textContent = "Tor: off";
  }
  onion.textContent = status.onion_address ? status.onion_address + ".onion" : "";
}

(async () => {
  const tab = await currentTab();
  const host = hostOf(tab && tab.url);
  const state = await browser.runtime.sendMessage({ type: "getState", host });

  renderTor(state.status || {}, state.torClearnet);

  const torBox = document.getElementById("torClearnet");
  torBox.checked = !!state.torClearnet;
  torBox.addEventListener("change", async () => {
    await browser.runtime.sendMessage({ type: "setTorClearnet", on: torBox.checked });
    const s = await browser.runtime.sendMessage({ type: "getState", host });
    renderTor(s.status || {}, s.torClearnet);
    const onion = document.getElementById("onion");
    onion.textContent = "Restart Epix to apply the clearnet routing change.";
  });

  // Per-site clearnet allow.
  const siteEl = document.getElementById("site");
  const allowBox = document.getElementById("allow");
  const note = document.getElementById("note");
  if (!host.endsWith(".epix")) {
    siteEl.textContent = "Not an Epix site";
    allowBox.disabled = true;
    note.textContent = "Open a .epix site to manage its clearnet access.";
  } else {
    siteEl.textContent = host;
    allowBox.checked = !!state.allow;
    note.textContent = "Off by default: this page can't contact the open internet.";
    allowBox.addEventListener("change", async () => {
      await browser.runtime.sendMessage({ type: "setAllow", host, allow: allowBox.checked });
      const t = await currentTab();
      if (t) browser.tabs.reload(t.id);
    });
  }
})();
