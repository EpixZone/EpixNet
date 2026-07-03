// Epix extension popup: show the current .epix site and toggle its clearnet allow.

async function currentTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}

(async () => {
  const tab = await currentTab();
  const host = hostOf(tab && tab.url);
  const siteEl = document.getElementById("site");
  const box = document.getElementById("allow");
  const note = document.getElementById("note");

  if (!host.endsWith(".epix")) {
    siteEl.textContent = "Not an Epix site";
    box.disabled = true;
    note.textContent = "Open a .epix site to manage its clearnet access.";
    return;
  }

  siteEl.textContent = host;
  const { allow } = await browser.runtime.sendMessage({ type: "getAllow", host });
  box.checked = !!allow;

  box.addEventListener("change", async () => {
    await browser.runtime.sendMessage({ type: "setAllow", host, allow: box.checked });
    // Reload so the new policy takes effect on the page.
    const tab = await currentTab();
    if (tab) browser.tabs.reload(tab.id);
  });
})();
