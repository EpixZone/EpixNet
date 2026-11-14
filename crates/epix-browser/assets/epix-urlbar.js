// Managed by epix-browser (added at pack time).
(() => {
  const api = globalThis.browser || globalThis.chrome;
  if (!api?.webRequest) return;
  const ADDR = /^epix1[a-z0-9]{20,80}$/;
  // Search-term query keys: q (DuckDuckGo/Google/Bing/Brave/Ecosia/Startpage),
  // p (Yahoo), query (some engines), wd (Baidu), text (Yandex), eq/kw (misc).
  const KEYS = ["q", "query", "p", "text", "wd", "eq", "kw"];
  const redirect = (details) => {
    try {
      const u = new URL(details.url);
      // A bare-address HOST navigates to its dotted alias, keeping
      // path + query (clicked links, typed https://epix1.../ URLs).
      if (ADDR.test(u.hostname)) {
        return { redirectUrl: "https://" + u.hostname + ".epix" + u.pathname + u.search };
      }
      // A search whose term is a bare address goes to the xite.
      for (const k of KEYS) {
        const v = (u.searchParams.get(k) || "").trim();
        if (ADDR.test(v)) return { redirectUrl: "https://" + v + ".epix/" };
      }
    } catch (_) {
      // Not a URL this script can read: leave the navigation alone.
    }
    return {};
  };
  // Firefox records a blocking listener that is added while the background
  // page loads. At the next browser start it holds every request the
  // listener matches until the page has loaded again, so the first page
  // stayed blank for that long. A listener added after the page has started
  // is not recorded, and nothing is held for it. The launch URL is already a
  // dotted name, so the first navigation needs no rewrite.
  let added = false;
  const add = () => {
    if (added) return;
    added = true;
    api.webRequest.onBeforeRequest.addListener(
      redirect,
      { urls: ["*://*/*"], types: ["main_frame"] },
      ["blocking"]
    );
  };
  // onStartup fires right after Firefox marks the page started. It does not
  // fire after an install, an update or a re-enable: the timer covers those.
  api.runtime?.onStartup?.addListener(add);
  const arm = () => setTimeout(add, 1000);
  if (globalThis.document && globalThis.document.readyState !== "complete") {
    globalThis.addEventListener("load", arm, { once: true });
  } else {
    arm();
  }
})();
