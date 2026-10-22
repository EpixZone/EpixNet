// Run: EPIX_BROWSER_TEST_TOOLS=/path/to/node_modules node ui/tests/control-scale-browser.cjs
// Full production wrapper and Sidebar, served locally with controlled WebSocket replies.
// Chrome mobile emulation checks author scale separately from simulated user zoom.
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
const os = require("node:os");
const crypto = require("node:crypto");
const out = process.env.EPIX_BROWSER_TEST_OUTPUT || fs.mkdtempSync(path.join(os.tmpdir(), "epix-control-scale-"));
fs.mkdirSync(out, { recursive: true });
const hint = scale => `width=device-width, initial-scale=${scale}, minimum-scale=0.25, maximum-scale=4, user-scalable=yes`;
let renderedHint = hint(1), manifestHint = hint(1);
const address = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
const errors = [], clients = new Set();
let nonce = 1;
let info = {
  address,
  peers: 0,
  size_limit: 10,
  next_size_limit: 10,
  settings: { size: 9000, permissions: [], own: false },
  content: {title: "Viewport scale fixture"},
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
// Freeze the five production inputs per run, even while a developer is editing.
const production = new Map();
for (const name of ["ui/wrapper.html", "ui/media/all.js", "ui/media/all.css",
  "crates/epix-plugins/media/sidebar/all.js", "crates/epix-plugins/media/sidebar/all.css"]) {
  production.set(name, fs.readFileSync(path.join(process.env.EPIX_BROWSER_TEST_SOURCE || repo, name)));
}
const provenance = Object.fromEntries([...production].map(([name, bytes]) =>
  [name, crypto.createHash("sha256").update(bytes).digest("hex")]));
function source(name) {
  if (name === "wrapper.html") return production.get("ui/wrapper.html");
  if (name === "all.js" || name === "all.css") {
    return Buffer.concat([production.get("ui/media/" + name), Buffer.from("\n"),
      production.get("crates/epix-plugins/media/sidebar/" + name)]);
  }
  if (name.startsWith("globe/")) return fs.readFileSync(path.join(repo, "crates/epix-plugins/media/sidebar", name));
  return fs.readFileSync(path.join(repo, "ui/media", name));
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
    res.writeHead(200, {"Content-Type": "text/html", "Cache-Control": "no-store"})
      .end('<!doctype html><html><head><title>Viewport fixture</title></head><body><h1>Viewport fixture</h1></body></html>');
    return;
  }
  if (pathname === `/${address}/`) {
    const vars = {
      title: "Rare xite",
      rev: "review",
      meta_tags: renderedHint ? `<meta name="viewport" id="viewport" content="${renderedHint}">` : "",
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
      show_loadingscreen: "false",
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
    let result = "ok";
    if (msg.cmd === "siteInfo") result = {...info, content: {...info.content, ...(manifestHint ? {viewport: manifestHint} : {})}};
    if (msg.cmd === "sidebarGetHtmlTag") result = '<div><a href="#Close" class="close">&times;</a><h1>Viewport fixture</h1><p>Controlled test content. Production drawer CSS and JS.</p><ul class="fields"><li><label>Storage</label><input class="text" value="10" readonly></li></ul><a href="#Fixture" class="button">Fixture control</a><div class="flex"><input class="text" id="input-contents" value="content.json"><a href="#Sign-or-Publish" id="menu-sign-publish">Menu</a></div></div><div class="menu template"><a href="#" class="menu-item template">Template</a></div>';
    if (msg.cmd === "sidebarGetPeers") result = [];
    if (msg.cmd === "announcerInfo")
      result = { address, stats: { tracker: { status: "announced" } } };
    if (msg.cmd === "serverInfo")
      result = {
        tor_status: "Disabled",
        ip_external: false,
        i2p_status: "Ready",
      };
    if (msg.cmd === "consoleLogRead") result = {lines: [], num_found: 0, pos_start: 0, pos_end: 0};
    if (msg.cmd === "consoleLogStream") result = {stream_id: "fixture"};
    if (msg.cmd === "notificationCount") result = { count: 0 };
    if (msg.cmd === "serverGetWrapperNonce") result = "review" + nonce++;
    if (msg.cmd === "ping") result = "pong";
    if (msg.id !== undefined)
      ws.send(JSON.stringify({ cmd: "response", to: msg.id, result }));
  });
});

(async () => {
  let browser;
  const results = {provenance, cases: [], errors, failures: []};
  const fail = (label, actual, expected) => results.failures.push({label, actual, expected});
  const near = (label, actual, expected, tolerance = 2) => {
    if (!Number.isFinite(actual) || Math.abs(actual - expected) > tolerance) fail(label, actual, expected);
  };
  const equal = (label, actual, expected) => {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(label, actual, expected);
  };
  const settle = async page => {
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await page.waitForTimeout(600); // Existing drawer/hover transitions finish in 500 ms.
  };
  async function measure(page) {
    return page.evaluate(() => {
      const vv = window.visualViewport || {scale: 1, width: innerWidth, height: innerHeight, offsetLeft: 0, offsetTop: 0};
      const bounds = selector => {
        const element = document.querySelector(selector);
        if (!element) return null;
        const r = element.getBoundingClientRect();
        const x = (r.x - vv.offsetLeft) * vv.scale, y = (r.y - vv.offsetTop) * vv.scale;
        const width = r.width * vv.scale, height = r.height * vv.scale;
        return {x, y, width, height,
          visibleWidth: Math.max(0, Math.min(x + width, vv.width * vv.scale) - Math.max(0, x)),
          visibleHeight: Math.max(0, Math.min(y + height, vv.height * vv.scale) - Math.max(0, y))};
      };
      return {
        viewport: {scale: vv.scale, width: vv.width, height: vv.height, offsetLeft: vv.offsetLeft, offsetTop: vv.offsetTop},
        tags: [...document.querySelectorAll('meta[name="viewport"]')].map(el => el.content),
        button: bounds('.fixbutton-bg'), drawer: bounds('.sidebar .content'),
        control: bounds('.sidebar .button'), close: bounds('.sidebar .close'),
        title: bounds('.sidebar h1'),
        menu: bounds('.menu.visible'), console: bounds('.console-container .console'),
        consoleTab: bounds('.console-tabs a'),
        chrome: sidebar.wrapper.chrome && {baseline: sidebar.wrapper.chrome.baseline, width: sidebar.wrapper.chrome.width, height: sidebar.wrapper.chrome.height},
        sidebar: {opened: sidebar.opened, width: sidebar.width, pageWidth: sidebar.page_width, pageHeight: sidebar.page_height},
      };
    });
  }
  async function pointer(page, type, points) {
    const scale = await page.evaluate(() => visualViewport.scale);
    points = points.map(point => ({x: point.x / scale, y: point.y / scale}));
    const cdp = type === 'touch' ? await page.context().newCDPSession(page) : null;
    try {
      if (cdp) await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [points[0]]});
      else { await page.mouse.move(points[0].x, points[0].y); await page.mouse.down(); }
      await page.waitForTimeout(130); // Distinguish drag from existing tap-to-home behavior.
      for (const point of points.slice(1)) {
        if (cdp) await cdp.send('Input.dispatchTouchEvent', {type: 'touchMove', touchPoints: [point]});
        else await page.mouse.move(point.x, point.y);
        await page.waitForTimeout(35);
      }
      if (cdp) await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
      else await page.mouse.up();
    } finally { if (cdp) await cdp.detach(); }
  }
  async function drag(page, type, direction) {
    const before = await measure(page);
    const button = before.button;
    assert.ok(button && button.visibleWidth > 10 && button.visibleHeight > 10,
      'drag must begin on a visible handle');
    const x = button.x + button.width / 2, y = button.y + button.height / 2;
    const end = direction === 'open' ? 30 : before.viewport.width * before.viewport.scale - 28;
    const sign = direction === 'open' ? -1 : 1;
    await pointer(page, type, [
      {x, y}, {x: x + sign * 8, y}, {x: x + sign * 24, y},
      {x: x + (end - x) / 2, y}, {x: end, y},
    ]);
    try {
      await page.waitForFunction(opened => sidebar.opened === opened, direction === 'open', {timeout: 3000});
    } catch (error) {
      const state = await page.evaluate(() => ({opened: sidebar.opened, lock: sidebar.move_lock,
        dragging: sidebar.fixbutton.hasClass('dragging'), left: sidebar.fixbutton[0].style.left,
        top: sidebar.fixbutton[0].style.top, targetX: sidebar.fixbutton_targetx, width: sidebar.width,
        viewport: {scale: visualViewport.scale, width: visualViewport.width, height: visualViewport.height},
        events: window.controlScaleEvents}));
      throw new Error(type + ' drag ' + direction + ': ' + JSON.stringify({before, state}));
    }
    if (direction === 'open') await page.waitForSelector('.sidebar-container.loaded', {timeout: 3000});
    await page.mouse.move(2, 200); // Restore the 48px resting button after mouse hover.
    await settle(page);
  }
  async function closeButton(page) {
    const m = await measure(page), box = m.close;
    assert.ok(box && box.visibleWidth > 10, 'close button is visible');
    await page.mouse.click((box.x + box.width / 2) / m.viewport.scale, (box.y + box.height / 2) / m.viewport.scale);
    await page.waitForFunction(() => !sidebar.opened, null, {timeout: 3000});
    await settle(page);
  }
  async function openByHashEntry(page) {
    // Existing hash-open entry point isolates geometry from gesture assertions.
    await page.evaluate(() => {
      sidebar.startDrag(); sidebar.moved('x');
      sidebar.fixbutton_targetx = sidebar.fixbutton_initx - sidebar.width;
      sidebar.stopDrag();
    });
    await page.waitForSelector('.sidebar-container.loaded', {timeout: 3000});
    await settle(page);
  }
  async function scenario(name, setup, run) {
    if (process.env.EPIX_BROWSER_TEST_CASE && !name.includes(process.env.EPIX_BROWSER_TEST_CASE)) return;
    renderedHint = setup.rendered === undefined ? hint(setup.scale || 1) : setup.rendered;
    manifestHint = setup.manifest === undefined ? renderedHint : setup.manifest;
    const page = await browser.newPage({viewport: setup.viewport || {width: 360, height: 800}, isMobile: setup.mobile !== false, hasTouch: true});
    page.on('pageerror', error => errors.push({name, message: error.message}));
    const record = {name}; results.cases.push(record);
    try {
      await page.goto(`http://127.0.0.1:${server.address().port}/${address}/`, {waitUntil: 'load'});
      await page.waitForFunction(() => window.sidebar && sidebar.wrapper.xite_info, null, {timeout: 5000});
      await settle(page);
      await page.evaluate(() => {
        window.controlScaleEvents = [];
        for (const name of ['mousedown', 'mousemove', 'mouseup', 'touchstart', 'touchmove', 'touchend']) {
          document.addEventListener(name, event => {
            const point = event.touches?.[0] || event.changedTouches?.[0] || event;
            controlScaleEvents.push({type: name, x: point.pageX, y: point.pageY, target: event.target.className});
            if (controlScaleEvents.length > 20) controlScaleEvents.shift();
          }, true);
        }
      });
      await run(page, record);
    } catch (error) {
      fail(name, error.message, 'scenario completes');
    } finally {
      await page.screenshot({path: path.join(out, name + '.png')}).catch(() => {});
      await page.close();
    }
  }
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({headless: true});
    for (const scale of [0.5, 1, 2]) {
      await scenario('scale-' + scale, {scale}, async (page, record) => {
        record.closed = await measure(page);
        near('scale ' + scale + ' effective author viewport', record.closed.viewport.scale, scale, 0.02);
        near('scale ' + scale + ' button width', record.closed.button.width, 48);
        near('scale ' + scale + ' button fully visible', record.closed.button.visibleWidth, 48);
        // Geometry remains inspectable even if the pre-fix button is offscreen.
        await openByHashEntry(page);
        record.open = await measure(page);
        near('scale ' + scale + ' drawer width', record.open.drawer.width, 360);
        near('scale ' + scale + ' drawer fully visible', record.open.drawer.visibleWidth, 360);
        near('scale ' + scale + ' touch control height', record.open.control.height, 44);
        equal('scale ' + scale + ' raw viewport unchanged', record.open.tags, record.closed.tags);
        await page.setViewportSize({width: 800, height: 360}); await settle(page);
        record.landscape = await measure(page);
        near('scale ' + scale + ' landscape drawer width', record.landscape.drawer.width, 420);
        near('scale ' + scale + ' rotated open drawer remains fully visible', record.landscape.drawer.visibleWidth, 420);
        await closeButton(page);
        for (const type of ['mouse', 'touch']) {
          await drag(page, type, 'open'); await drag(page, type, 'close');
        }
        await page.setViewportSize({width: 360, height: 800}); await settle(page);
        for (const type of ['mouse', 'touch']) {
          await drag(page, type, 'open'); await closeButton(page);
        }
        record.gestures = ['landscape mouse/touch open and close', 'portrait mouse/touch open and close button'];
        equal('scale ' + scale + ' viewport unchanged by rotation and gestures', (await measure(page)).tags, record.closed.tags);
      });
    }
    for (const width of [360, 720]) {
      await scenario('width-only-rotation-' + width, {rendered: `width=${width}, minimum-scale=0.25, maximum-scale=4, user-scalable=yes`}, async (page, record) => {
        record.before = await measure(page);
        near('width-only ' + width + ' initial button', record.before.button.width, 48);
        await page.setViewportSize({width: 800, height: 360}); await settle(page);
        record.after = await measure(page);
        near('width-only ' + width + ' rotated button', record.after.button.width, 48);
        await openByHashEntry(page); record.drawer = await measure(page);
        near('width-only ' + width + ' rotated drawer', record.drawer.drawer.width, 420);
        await page.setViewportSize({width: 360, height: 800}); await settle(page);
        record.returned = await measure(page);
        near('width-only ' + width + ' return button', record.returned.button.width, 48);
        near('width-only ' + width + ' return drawer', record.returned.drawer.visibleWidth, 360);
        equal('width-only ' + width + ' rotation preserves raw directive', record.returned.tags, record.before.tags);
      });
    }
    await scenario('pinch', {scale: 1}, async (page, record) => {
      await openByHashEntry(page); record.before = await measure(page);
      const cdp = await page.context().newCDPSession(page);
      await cdp.send('Emulation.setPageScaleFactor', {pageScaleFactor: 2}); await settle(page);
      record.zoomed = await measure(page);
      near('pinch remains 2x', record.zoomed.viewport.scale, 2, 0.02);
      near('pinch magnifies controls', record.zoomed.control.height, record.before.control.height * 2);
      near('pinch magnifies title text', record.zoomed.title.height, record.before.title.height * 2);
      near('zoomed drawer fits available viewport', record.zoomed.drawer.visibleWidth, 360);
      equal('pinch preserves viewport directives', record.zoomed.tags, record.before.tags);
      await cdp.detach();
    });
    await scenario('trusted-pinch-pan', {scale: 1}, async (page, record) => {
      record.before = await measure(page);
      const cdp = await page.context().newCDPSession(page);
      // Genuine two-contact input changes both page scale and viewport offsets.
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [{x: 120, y: 400, id: 1}, {x: 240, y: 400, id: 2}]});
      for (let step = 1; step <= 10; step++) {
        await cdp.send('Input.dispatchTouchEvent', {type: 'touchMove', touchPoints: [{x: 120 - step * 5, y: 400, id: 1}, {x: 240 + step * 5, y: 400, id: 2}]});
        await page.waitForTimeout(30);
      }
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
      await settle(page); record.zoomed = await measure(page);
      assert.ok(record.zoomed.viewport.scale > 1.5, 'trusted pinch changes browser page scale');
      assert.ok(record.zoomed.viewport.offsetLeft > 0 && record.zoomed.viewport.offsetTop > 0, 'trusted pinch moves visual viewport origin');
      near('trusted pinch magnifies button', record.zoomed.button.width, 48 * record.zoomed.viewport.scale);
      near('trusted pinch keeps button visible', record.zoomed.button.visibleWidth, record.zoomed.button.width);
      // Pan through the page below the controls. The open drawer would consume
      // scrolling, so exercise the closed wrapper before opening it again.
      const x = record.zoomed.viewport.width / 2, y = record.zoomed.viewport.height * 0.85;
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchStart', touchPoints: [{x, y, id: 1}]});
      for (let step = 1; step <= 5; step++) {
        await cdp.send('Input.dispatchTouchEvent', {type: 'touchMove', touchPoints: [{x: x - step * 4, y: y - step * 4, id: 1}]});
        await page.waitForTimeout(30);
      }
      await cdp.send('Input.dispatchTouchEvent', {type: 'touchEnd', touchPoints: []});
      await settle(page); record.panned = await measure(page);
      assert.ok(record.panned.viewport.offsetLeft > record.zoomed.viewport.offsetLeft, 'trusted pan changes horizontal visual viewport offset');
      assert.ok(record.panned.viewport.offsetTop > record.zoomed.viewport.offsetTop, 'trusted pan changes vertical visual viewport offset');
      near('pan preserves user scale', record.panned.viewport.scale, record.zoomed.viewport.scale, 0.02);
      near('panned button remains fully visible', record.panned.button.visibleWidth, record.panned.button.width);
      await openByHashEntry(page); record.open = await measure(page);
      near('panned drawer fills physical viewport', record.open.drawer.visibleWidth, 360);
      near('panned close button remains fully visible', record.open.close.visibleWidth, record.open.close.width);
      near('panned close button remains vertically visible', record.open.close.visibleHeight, record.open.close.height);
      equal('trusted pinch and pan preserve raw viewport', record.open.tags, record.before.tags);
      await closeButton(page);
      await cdp.detach();
    });
    await scenario('delayed-viewport', {rendered: null, manifest: null}, async (page, record) => {
      record.before = await measure(page);
      manifestHint = hint(0.5);
      publish({content: {...info.content, viewport: manifestHint}});
      await page.waitForFunction(expected => document.querySelector('#viewport')?.content === expected, manifestHint);
      await settle(page); record.after = await measure(page);
      near('delayed author scale applied', record.after.viewport.scale, 0.5, 0.02);
      near('delayed viewport keeps button 48px', record.after.button.width, 48);
      near('delayed viewport keeps button visible', record.after.button.visibleWidth, 48);
      await drag(page, 'touch', 'open'); record.drawer = await measure(page);
      near('delayed viewport keeps drawer 360px', record.drawer.drawer.width, 360);
      equal('delayed directive preserved exactly', record.after.tags.at(-1), manifestHint);
    });
    await scenario('mobile-pinch-width-update', {scale: 1}, async (page, record) => {
      const cdp = await page.context().newCDPSession(page);
      await cdp.send('Emulation.setPageScaleFactor', {pageScaleFactor: 2}); await settle(page);
      record.zoomed = await measure(page);
      const directive = 'width=980, initial-scale=1, minimum-scale=0.25, maximum-scale=4, user-scalable=yes';
      await page.evaluate(value => sidebar.wrapper.setViewport(value), directive); await settle(page);
      record.after = await measure(page);
      near('layout-only author update preserves user scale', record.after.viewport.scale, 2, 0.02);
      near('layout-only author update preserves control magnification', record.after.button.width, record.zoomed.button.width);
      equal('layout-only author directive remains exact', record.after.tags.at(-1), directive);
      await cdp.detach();
    });
    for (const scale of [0.5, 1, 2]) {
      await scenario('panels-' + scale, {scale}, async (page, record) => {
        await openByHashEntry(page);
        await page.locator('#menu-sign-publish').click(); await settle(page);
        record.menu = await measure(page);
        assert.ok(record.menu.menu, 'real drawer menu opens after global wrapper deletion');
        near('scale ' + scale + ' menu stays fully visible', record.menu.menu.visibleWidth, record.menu.menu.width);
        equal('menu uses controls layer', await page.evaluate(() => visible_menu.elem[0].parentElement.id), 'wrapper-controls');
        await page.evaluate(() => visible_menu.hide());
        await closeButton(page);
        await page.evaluate(() => sidebar.console.open()); await settle(page);
        record.console = await measure(page);
        equal('scale ' + scale + ' console opens', await page.evaluate(() => sidebar.console.opened), true);
        near('scale ' + scale + ' console width', record.console.console.width, 360);
        near('scale ' + scale + ' console tab height', record.console.consoleTab.height, 44);
        equal('console uses controls layer', await page.evaluate(() => sidebar.console.container[0].parentElement.id), 'wrapper-controls');
        await page.evaluate(() => sidebar.console.close()); await settle(page);
        equal('scale ' + scale + ' console closes', await page.evaluate(() => sidebar.console.opened), false);
      });
    }
    await scenario('desktop-pinch-meta', {mobile: false, scale: 1}, async (page, record) => {
      record.before = await measure(page);
      const cdp = await page.context().newCDPSession(page);
      await cdp.send('Emulation.setPageScaleFactor', {pageScaleFactor: 2}); await settle(page);
      record.zoomed = await measure(page);
      await page.evaluate(value => sidebar.wrapper.setViewport(value), hint(0.5)); await settle(page);
      record.after = await measure(page);
      near('desktop ignores author scale without cancelling pinch', record.after.viewport.scale, 2, 0.02);
      near('ignored desktop meta update preserves chrome pinch magnification', record.after.button.width, record.zoomed.button.width);
      await cdp.detach();
    });
    equal('no page errors', errors, []);
    console.log(JSON.stringify(results, null, 2));
    assert.deepEqual(results.failures, [], 'wrapper controls normalize author scale and retain user zoom');
  } finally {
    fs.writeFileSync(path.join(out, 'results.json'), JSON.stringify(results, null, 2));
    console.log('Control-scale artifacts: ' + out);
    if (browser) await browser.close();
    for (const client of clients) client.terminate();
    await new Promise(resolve => wss.close(resolve));
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
