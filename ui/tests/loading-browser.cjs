// Run against the production wrapper, stylesheet, and script with a controlled
// WebSocket peer-discovery stream. No live peers or wallet are required.
// See docs/discovery-validation.md for setup and the boundaries of this test.
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const assert = require("node:assert/strict");
const tools = process.env.EPIX_BROWSER_TEST_TOOLS;
const { Server: WebSocketServer } = require(tools
  ? path.join(tools, "ws")
  : "ws");
const { chromium } = require(tools
  ? path.join(tools, "playwright")
  : "playwright");
const repo = path.resolve(__dirname, "../..");
const out =
  process.env.EPIX_BROWSER_TEST_OUTPUT ||
  path.join(require("node:os").tmpdir(), "epix-discovery-browser-results");
fs.mkdirSync(out, { recursive: true });
const label = "discovery";
const address = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
const errors = [],
  commands = [],
  clients = new Set();
let wrapperRequests = 0,
  fileRequests = 0,
  ready = false,
  nonce = 1;
let info = {
  address,
  peers: 0,
  size_limit: 10,
  next_size_limit: 20,
  settings: { size: 0, permissions: [], own: false },
  content: {},
  tasks: 0,
  bad_files: 0,
  started_task_num: 0,
  peers_serving: 0,
  clone_status: {
    state: "discovering",
    attempt: 1,
    reason: null,
    next_retry_at: null,
  },
};
function source(name) {
  return fs.readFileSync(
    path.join(repo, "ui", name === "wrapper.html" ? name : "media/" + name)
  );
}
function publish(delta) {
  info = { ...info, ...delta };
  for (const ws of clients)
    if (ws.readyState === 1)
      ws.send(JSON.stringify({ cmd: "setSiteInfo", params: info }));
}
const server = http.createServer((req, res) => {
  const pathname = new URL(req.url, "http://localhost").pathname;
  if (pathname.startsWith("/uimedia/")) {
    const name = pathname.slice("/uimedia/".length);
    if (name.includes("..")) {
      res.writeHead(400).end();
      return;
    }
    try {
      const data = source(name);
      res
        .writeHead(200, {
          "Content-Type": name.endsWith(".js")
            ? "text/javascript"
            : name.endsWith(".css")
            ? "text/css"
            : name.endsWith(".svg")
            ? "image/svg+xml"
            : "image/png",
        })
        .end(data);
    } catch {
      res.writeHead(404).end();
    }
    return;
  }
  if (pathname === `/${address}/index.html`) {
    fileRequests++;
    if (ready) {
      res
        .writeHead(200, {
          "Content-Type": "text/html",
          "Cache-Control": "no-store",
        })
        .end(
          '<!doctype html><html><head><title>Rare xite</title></head><body><h1 id="xite-ready">The rare xite is ready</h1></body></html>'
        );
    } else {
      res
        .writeHead(503, {
          "Content-Type": "text/html",
          "Cache-Control": "no-store",
          "Retry-After": "30",
        })
        .end(
          '<!doctype html><html data-epix-load-state="waiting"><body>Waiting for this xite</body></html>'
        );
    }
    return;
  }
  if (pathname === `/${address}/`) {
    wrapperRequests++;
    const vars = {
      title: "Rare xite",
      rev: "review",
      meta_tags: "",
      body_style: "",
      themeclass: "",
      homepage: `/${address}`,
      resolving_host: "",
      is_homepage: "false",
      site_file_server: "",
      file_url: `/${address}/index.html`,
      query_string: "?wrapper_nonce=waiting",
      address,
      wrapper_nonce: "waiting",
      wrapper_key: address,
      ajax_key: "review",
      postmessage_nonce_security: "false",
      file_inner_path: "index.html",
      permissions: "[]",
      show_loadingscreen: "true",
      server_url: `http://127.0.0.1:${server.address().port}`,
      script_nonce: "reviewnonce",
      sandbox_permissions: "",
      lang: "en",
    };
    let html = source("wrapper.html")
      .toString()
      .replace(/\{(\w+)\}/g, (all, key) => vars[key] ?? all);
    res
      .writeHead(200, {
        "Content-Type": "text/html",
        "Content-Security-Policy":
          "default-src 'none'; script-src 'nonce-reviewnonce' 'wasm-unsafe-eval'; img-src * blob: data:; media-src * blob: data:; font-src * data:; style-src 'self' blob: 'unsafe-inline'; connect-src *; frame-src *",
      })
      .end(html);
    return;
  }
  res
    .writeHead(200, { "Content-Type": "text/html" })
    .end(
      "<!doctype html><title>Connection settings</title>Connection settings"
    );
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
    if (msg.cmd === "announcerInfo")
      result = { address, stats: { tracker: { status: "announced" } } };
    if (msg.cmd === "serverInfo")
      result = {
        tor_status: "Disabled",
        ip_external: false,
        i2p_status: "Ready",
      };
    if (msg.cmd === "notificationCount") result = { count: 0 };
    if (msg.cmd === "serverGetWrapperNonce") result = "review" + nonce++;
    if (msg.cmd === "ping") result = "pong";
    if (msg.id !== undefined)
      ws.send(JSON.stringify({ cmd: "response", to: msg.id, result }));
  });
});
(async () => {
  let browser;
  try {
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    browser = await chromium.launch({
      headless: true,
      executablePath: process.env.EPIX_TEST_CHROMIUM || undefined,
    });
    const page = await browser.newPage({
      viewport: { width: 1280, height: 900 },
    });
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(`http://127.0.0.1:${server.address().port}/${address}/`, {
      waitUntil: "load",
    });
    await page.waitForTimeout(400);
    async function shot(stage) {
      await page.screenshot({
        path: path.join(out, `${label}-${stage}.png`),
        fullPage: true,
      });
      return page.locator("body").innerText();
    }
    const results = { label, initial: await shot("searching") };
    const wrapperCountBeforeRetry = wrapperRequests;
    const documentBeforeRetry = await page.evaluate(() => {
      window.automaticRetryDocument = "same-wrapper";
      return performance.timeOrigin;
    });
    publish({
      event: ["file_failed", "content.json"],
      reason: "no_peers",
      clone_status: {
        state: "waiting",
        attempt: 2,
        reason: "no_peers",
        next_retry_at: Date.now() / 1000 + 3,
      },
    });
    const automaticRetry = setTimeout(() => publish({
      event: ["clone_status", "discovering"],
      clone_status: { state: "discovering", attempt: 3, reason: null, next_retry_at: null },
    }), 3000);
    await page.waitForTimeout(300);
    results.waiting = await shot("waiting");
    const countdown = page.locator(".loading-retry-note");
    const firstCountdown = await countdown.innerText();
    await page.waitForTimeout(1100);
    results.countdownAdvanced =
      firstCountdown !== (await countdown.innerText());
    results.retryButtons = await page.locator(".button-retry").count();
    await page.waitForFunction(() => document.querySelector(".loading-attempt")?.textContent === "Attempt 3");
    clearTimeout(automaticRetry);
    results.automaticAttempt = await page.locator(".loading-attempt").innerText();
    results.automaticFeedback = await page.locator(".loading-retry-note").innerText();
    results.automatic = await shot("automatic-retry");
    results.automaticReloaded = wrapperRequests !== wrapperCountBeforeRetry || await page.evaluate(
      (origin) => window.automaticRetryDocument !== "same-wrapper" || performance.timeOrigin !== origin,
      documentBeforeRetry
    );
    publish({
      event: ["file_added", "index.html"],
      settings: { size: 9000, permissions: [], own: false },
      content: { title: "Rare xite" },
      tasks: 4,
      bad_files: 4,
      started_task_num: 6,
      peers: 2,
      peers_serving: 1,
      clone_status: {
        state: "downloading",
        attempt: 3,
        reason: null,
        next_retry_at: null,
      },
    });
    await page.waitForTimeout(250);
    publish({
      event: ["file_done", "index.html"],
      tasks: 3,
      bad_files: 3,
      clone_status: {
        state: "downloading",
        attempt: 3,
        reason: null,
        next_retry_at: null,
      },
    });
    await page.waitForTimeout(300);
    results.partial = await shot("partial");
    results.partialOverlay =
      (await page.locator(".loadingscreen").isVisible()) &&
      !(await page
        .locator(".loadingscreen")
        .evaluate((el) => el.classList.contains("done")));
    await page.setViewportSize({ width: 360, height: 800 });
    publish({
      event: ["file_failed", "style.css"],
      reason: "files_unavailable",
      clone_status: {
        state: "waiting",
        attempt: 3,
        reason: "files_unavailable",
        next_retry_at: Date.now() / 1000 + 30,
      },
    });
    await page.waitForTimeout(300);
    results.mobile = await shot("mobile");
    results.savedProgress = await page.locator(".transfer-count").innerText();
    results.waitingTransferText = await page
      .locator(".transfer-peers")
      .innerText();
    await page.emulateMedia({ colorScheme: "dark" });
    await page.waitForTimeout(450);
    results.dark = await shot("dark");
    const settingsLink = page.locator(".loading-config");
    results.settingsTapTarget = await settingsLink.boundingBox();
    await settingsLink.focus();
    results.settingsKeyboardFocus = await settingsLink.evaluate(
      (el) => document.activeElement === el
    );
    const details = page.locator(".loading-details summary");
    if (await details.count()) {
      await details.focus();
      await page.keyboard.press("Enter");
      results.detailsExpanded = await details.evaluate(
        (el) => el.parentElement.open
      );
    }
    results.mobileOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth
    );
    await page.emulateMedia({ reducedMotion: "reduce" });
    results.reducedMotion = await page.evaluate(() =>
      Array.from(document.querySelectorAll(".loadingscreen *"))
        .filter((el) => {
          const s = getComputedStyle(el);
          return (
            s.animationName !== "none" && parseFloat(s.animationDuration) > 0.01
          );
        })
        .map((el) => el.className)
    );
    ready = true;
    publish({
      event: ["file_done", "style.css"],
      tasks: 0,
      bad_files: 0,
      clone_status: {
        state: "complete",
        attempt: 3,
        reason: null,
        next_retry_at: null,
      },
    });
    await page.waitForTimeout(2800);
    results.completedFrame = await page
      .locator("#inner-iframe")
      .evaluate(
        (el) =>
          el.contentDocument?.querySelector("#xite-ready")?.textContent || null
      );
    results.completed = await shot("completed");
    results.overlayDismissed =
      (await page.locator(".loadingscreen").count()) === 0;
    results.retryCommands = commands.filter((c) => c.cmd === "networkRetry");
    results.errors = errors;
    results.wrapperRequests = wrapperRequests;
    results.fileRequests = fileRequests;
    fs.writeFileSync(
      path.join(out, `${label}-results.json`),
      JSON.stringify(results, null, 2)
    );
    console.log(JSON.stringify(results, null, 2));
    {
      assert.equal(results.retryButtons, 0);
      assert.equal(results.countdownAdvanced, true);
      assert.equal(results.automaticReloaded, false);
      assert.equal(results.automaticAttempt, "Attempt 3");
      assert.match(results.automaticFeedback, /automatically/i);
      assert.deepEqual(results.retryCommands, []);
      assert.equal(results.partialOverlay, true);
      assert.equal(results.mobileOverflow, false);
      assert.equal(results.savedProgress, "3 of 6 files");
      assert.equal(results.waitingTransferText, "Downloaded files are kept");
      assert.ok(results.settingsTapTarget.height >= 44);
      assert.equal(results.settingsKeyboardFocus, true);
      assert.equal(results.detailsExpanded, true);
      assert.equal(results.reducedMotion.length, 0);
      assert.ok(results.completedFrame);
      assert.equal(results.overlayDismissed, true);
      assert.deepEqual(errors, []);
    }
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
