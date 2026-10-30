// Run: EPIX_BROWSER_TEST_TOOLS=/path/to/node_modules node ui/tests/wrapper-startup-browser.cjs
// The production wrapper (wrapper.html + all.js) in Chromium with an opaque
// inner frame and a controlled WebSocket peer, driven through the document
// changes a xite page goes through: first load, in-frame reload, in-frame
// navigation to pages whose frame library starts before load, at load and
// after load, a page without one, a same-document hash change, and a socket
// reconnect. Each inner document counts the wrapperOpenedWebsocket and ping
// messages it receives; every document must be told the socket is open
// exactly once per connection (docs/wrapper-sandbox.md,
// ui/tests/wrapper-startup.test.cjs).
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const assert = require("node:assert/strict");
const tools = process.env.EPIX_BROWSER_TEST_TOOLS;
const { Server: WebSocketServer } = require(tools ? path.join(tools, "ws") : "ws");
const { chromium } = require(tools ? path.join(tools, "playwright") : "playwright");
const repo = path.resolve(__dirname, "../..");
const out = process.env.EPIX_BROWSER_TEST_OUTPUT ||
  fs.mkdtempSync(path.join(require("node:os").tmpdir(), "epix-wrapper-startup-"));
fs.mkdirSync(out, { recursive: true });
const address = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
const errors = [], commands = [], clients = new Set();
let nonce = 1;
const info = {
  address, peers: 2, size_limit: 10, next_size_limit: 20,
  settings: { size: 9000, permissions: [], own: false },
  content: { title: "Startup fixture" },
  tasks: 0, bad_files: 0, started_task_num: 0, peers_serving: 1,
  clone_status: { state: "complete", attempt: 1, reason: null, next_retry_at: null },
};
function source(name) {
  return fs.readFileSync(path.join(repo, "ui", name === "wrapper.html" ? name : "media/" + name));
}
// A xite page with the frame library's startup protocol: innerReady once at
// construction, pong in reply to a ping, innerReady again only in reply to
// wrapperReady. `mode` says when the library is constructed; `none` is a page
// without one.
function xitePage(name) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${name}</title></head><body>
<h1 id="doc">${name}</h1><img src="slow.png?doc=${name}&t=${Date.now()}" alt="">
<script>
(function () {
  var mode = new URLSearchParams(location.search).get("mode") || "early";
  var nonce = (location.search.match(/wrapper_nonce=([A-Za-z0-9]+)/) || [])[1];
  window.__stats = { name: ${JSON.stringify(name)}, mode: mode, opens: 0, asks: 0, readies: 0, born: performance.timeOrigin };
  function send() {
    window.__stats.readies++;
    parent.postMessage({ cmd: "innerReady", params: {}, id: window.__stats.readies, wrapper_nonce: nonce }, "*");
  }
  function start() {
    window.addEventListener("message", function (e) {
      var m = e.data;
      if (!m || !m.cmd) return;
      if (m.cmd === "wrapperOpenedWebsocket") window.__stats.opens++;
      if (m.cmd === "ping") {
        window.__stats.asks++;
        parent.postMessage({ cmd: "response", to: m.id, result: "pong", wrapper_nonce: nonce }, "*");
      }
      if (m.cmd === "wrapperReady") send();
    });
    send();
  }
  if (mode === "early") start();
  else if (mode === "onload") window.addEventListener("load", start);
  else if (mode === "lazy") window.addEventListener("load", function () { setTimeout(start, 300); });
})();
</script></body></html>`;
}
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/uimedia/")) {
    const name = url.pathname.slice("/uimedia/".length);
    if (name.includes("..")) { res.writeHead(400).end(); return; }
    try {
      const data = source(name);
      const type = name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" :
        name.endsWith(".svg") ? "image/svg+xml" : "image/png";
      res.writeHead(200, { "Content-Type": type }).end(data);
    } catch { res.writeHead(404).end(); }
    return;
  }
  if (url.pathname === `/${address}/slow.png`) {
    // Keeps the frame's load event well after an early innerReady.
    setTimeout(() => res.writeHead(200, { "Content-Type": "image/x-icon", "Cache-Control": "no-store" })
      .end(source("img/favicon.ico")), 700);
    return;
  }
  const page = url.pathname.match(new RegExp(`^/${address}/([a-z]+)\\.html$`));
  if (page) {
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" }).end(xitePage(page[1]));
    return;
  }
  if (url.pathname === `/${address}/`) {
    const vars = {
      title: "Startup fixture", rev: "review", meta_tags: "", body_style: "", themeclass: "",
      homepage: `/${address}`, resolving_host: "", is_homepage: "false", ui_restrict: "false",
      site_file_server: "", file_url: `/${address}/index.html`, query_string: "?mode=early&wrapper_nonce=n1",
      address, wrapper_nonce: "n1", wrapper_key: address, ajax_key: "review",
      postmessage_nonce_security: "true", file_inner_path: "index.html", permissions: "[]",
      show_loadingscreen: "false", server_url: `http://127.0.0.1:${server.address().port}`,
      script_nonce: "reviewnonce", sandbox_permissions: "", lang: "en",
    };
    const html = source("wrapper.html").toString().replace(/\{(\w+)\}/g, (all, key) => vars[key] ?? all);
    res.writeHead(200, {
      "Content-Type": "text/html",
      "Content-Security-Policy": "default-src 'none'; script-src 'nonce-reviewnonce' 'wasm-unsafe-eval'; img-src * blob: data:; media-src * blob: data:; font-src * data:; style-src 'self' blob: 'unsafe-inline'; connect-src *; frame-src *",
    }).end(html);
    return;
  }
  res.writeHead(404).end();
});
const wss = new WebSocketServer({ server });
wss.on("connection", (ws) => {
  clients.add(ws);
  ws.on("close", () => clients.delete(ws));
  ws.on("message", (raw) => {
    const msg = JSON.parse(raw);
    commands.push(msg);
    let result = "ok";
    if (msg.cmd === "siteInfo") result = info;
    if (msg.cmd === "announcerInfo") result = { address, stats: {} };
    if (msg.cmd === "serverInfo") result = { tor_status: "Disabled", ip_external: false };
    if (msg.cmd === "notificationCount") result = { count: 0 };
    if (msg.cmd === "serverGetWrapperNonce") result = { wrapper_nonce: "n" + (++nonce) };
    if (msg.cmd === "ping") result = "pong";
    if (msg.id !== undefined) ws.send(JSON.stringify({ cmd: "response", to: msg.id, result }));
  });
});

(async () => {
  let browser;
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    browser = await chromium.launch({ headless: true, executablePath: process.env.EPIX_TEST_CHROMIUM || undefined });
    const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
    page.on("pageerror", (e) => errors.push(e.message));
    // onWrapperLoad deletes window.wrapper once the page is up; keep a
    // reference for the assertions below without changing what the page sees.
    await page.addInitScript(() => {
      Object.defineProperty(window, "wrapper", {
        configurable: true,
        get() { return undefined; },
        set(value) {
          window.__wrapperRef = value;
          Object.defineProperty(window, "wrapper", { configurable: true, writable: true, value });
        },
      });
    });
    const results = { steps: [] };
    const inner = () => page.frames().find((f) => f.parentFrame() === page.mainFrame());
    async function stats() { return inner().evaluate(() => window.__stats || null); }
    async function wrapperState() {
      return page.evaluate(() => {
        const w = window.__wrapperRef;
        return {
          generation: w.inner_generation, ready: w.inner_ready, announced: w.wrapperWsInited,
          inner_loaded: w.inner_loaded, load_state: w.inner_load_state,
        };
      });
    }
    // A document is settled once it has been announced to and nothing more
    // arrives for a while; `born` tells one document from the next.
    async function settle(step, previousBorn) {
      const deadline = Date.now() + 8000;
      let s = null;
      while (Date.now() < deadline) {
        s = await stats().catch(() => null);
        if (s && s.born !== previousBorn && (s.mode === "none" || s.opens >= 1)) break;
        await page.waitForTimeout(100);
      }
      await page.waitForTimeout(1500);
      s = await stats().catch(() => null);
      const w = await wrapperState();
      results.steps.push({ step, stats: s, wrapper: w });
      console.log(step, JSON.stringify(s), JSON.stringify(w));
      return s;
    }

    await page.goto(`http://127.0.0.1:${server.address().port}/${address}/`, { waitUntil: "domcontentloaded" });
    const first = await settle("first document (library before load)", null);
    assert.equal(first.opens, 1, "first document is told the socket is open once");

    await inner().evaluate(() => location.reload());
    const reloaded = await settle("in-frame reload, same URL and nonce", first.born);
    assert.notEqual(reloaded.born, first.born, "the reload produced a new document");
    assert.equal(reloaded.opens, 1, "the reloaded document is told the socket is open once");

    await inner().evaluate(() => { location.href = "second.html?mode=onload&wrapper_nonce=n1"; });
    const onload = await settle("navigation to a page whose library starts at load", reloaded.born);
    assert.equal(onload.name, "second");
    assert.equal(onload.opens, 1, "a library constructed at load is announced to once");

    await inner().evaluate(() => { location.href = "third.html?mode=lazy&wrapper_nonce=n1"; });
    const lazy = await settle("navigation to a page whose library starts after load", onload.born);
    assert.equal(lazy.name, "third");
    assert.equal(lazy.opens, 1, "a library constructed after load is announced to once");

    await inner().evaluate(() => { location.href = "fourth.html?mode=none&wrapper_nonce=n1"; });
    const none = await settle("navigation to a page without a frame library", lazy.born);
    assert.equal(none.name, "fourth");
    assert.equal(none.opens, 0);
    // A page without a frame library is invisible to the chrome; the next
    // document that has one introduces itself regardless.
    const generationAtNone = (await wrapperState()).generation;

    await inner().evaluate(() => { location.href = "fifth.html?mode=early&wrapper_nonce=n1"; });
    const afterNone = await settle("navigation from a silent page to one with a library", none.born);
    assert.equal(afterNone.name, "fifth");
    assert.equal(afterNone.opens, 1);
    assert.notEqual((await wrapperState()).generation, generationAtNone, "the introduction starts a new document");

    await inner().evaluate(() => { location.hash = "#section"; });
    await page.waitForTimeout(800);
    const hashed = await stats();
    results.steps.push({ step: "same-document hash change", stats: hashed, wrapper: await wrapperState() });
    assert.equal(hashed.born, afterNone.born, "a hash change keeps the document");
    assert.equal(hashed.opens, 1, "a hash change announces nothing");
    assert.equal(hashed.asks, 0, "a ready document is not asked again");

    // Socket loss: the wrapper reconnects on its own and must announce the
    // reopened socket to the same document exactly once more.
    for (const ws of clients) ws.close();
    const reopenDeadline = Date.now() + 25000;
    let reconnected = null;
    while (Date.now() < reopenDeadline) {
      reconnected = await stats();
      if (reconnected.opens >= 2) break;
      await page.waitForTimeout(250);
    }
    await page.waitForTimeout(1500);
    reconnected = await stats();
    results.steps.push({ step: "socket reconnect", stats: reconnected, wrapper: await wrapperState() });
    console.log("socket reconnect", JSON.stringify(reconnected));
    assert.equal(reconnected.born, afterNone.born);
    assert.equal(reconnected.opens, 2, "the reopened socket is announced once");

    await inner().evaluate(() => location.reload());
    const afterReconnect = await settle("in-frame reload after the reconnect", reconnected.born);
    assert.equal(afterReconnect.opens, 1);

    results.errors = errors;
    results.nonceRequests = commands.filter((c) => c.cmd === "serverGetWrapperNonce").length;
    await page.screenshot({ path: path.join(out, "wrapper-startup-final.png"), fullPage: true });
    fs.writeFileSync(path.join(out, "wrapper-startup-results.json"), JSON.stringify(results, null, 2));
    assert.deepEqual(errors, []);
    console.log("wrapper startup browser fixture passed; results in", out);
  } finally {
    if (browser) await browser.close();
    for (const ws of clients) ws.terminate();
    wss.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
