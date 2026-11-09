// Run: EPIX_BROWSER_TEST_TOOLS=/path/to/node_modules node ui/tests/sidebar-properties-browser.cjs
// Requires Playwright, ws, Cargo, and cached serde_json dependencies (cargo build is offline).
// Production wrapper, sidebar renderer, JS, CSS and globe run against local WebSocket fixtures.
// This verifies browser rendering and command wiring, not backend command execution or disk persistence.
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const dependencies = process.env.EPIX_BROWSER_TEST_TOOLS;
const {chromium} = require(dependencies ? path.join(dependencies, "playwright") : "playwright");
const {Server: WebSocketServer} = require(dependencies ? path.join(dependencies, "ws") : "ws");
const repo = path.resolve(__dirname, "../..");
const sourceRoot = process.env.EPIX_BROWSER_TEST_SOURCE || repo;
const output = process.env.EPIX_BROWSER_TEST_OUTPUT || fs.mkdtempSync(path.join(os.tmpdir(), "epix-sidebar-properties-"));
fs.mkdirSync(output, {recursive: true});
const render = require("./helpers/sidebar-renderer.cjs")(sourceRoot, output);
const address = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
const includes = ["data/users/content.json", "data/groups/content.json"];
const hint = scale => `width=device-width, initial-scale=${scale}, minimum-scale=0.25, maximum-scale=4, user-scalable=yes`;
const commands = [], requests = [], clients = new Set(), errors = [];
const production = new Map();
for (const name of ["ui/wrapper.html", "ui/media/all.js", "ui/media/all.css",
  "crates/epix-plugins/src/sidebar.rs", "crates/epix-plugins/media/sidebar/all.js",
  "crates/epix-plugins/media/sidebar/all.css", "crates/epix-plugins/media/sidebar/globe/all.js"]) {
  production.set(name, fs.readFileSync(path.join(sourceRoot, name)));
}
const provenance = Object.fromEntries([...production].map(([name, bytes]) =>
  [name, crypto.createHash("sha256").update(bytes).digest("hex")]));
let scale = 1, nonce = 1, globalSettings = {}, peerFailure = false, info;
let heldCommand = null;
const heldReplies = [];
function releaseReplies() {heldCommand = null; for (const reply of heldReplies.splice(0)) reply();}
const counts = {total: 318, connected: 3, connectable: 318, onion: 49, local: 3};
function reset() {
  info = {
    address, peers: 3, peers_serving: 3, size_limit: 100, next_size_limit: 100,
    auth_address: "epix1fixtureauthor", cert_user_id: null, privatekey: false,
    settings: {size: 24 * 1024 * 1024, serving: true, favorite: false, own: false,
      permissions: [], download_optional: true, autodownloadoptional: false,
      size_optional: 32 * 1024 * 1024, optional_downloaded: 8 * 1024 * 1024,
      cache: {bad_files: {"index.html": 1, "data/post.json": 1}}},
    content: {title: "Properties fixture", description: "Fixture description", domain: "fixture.epix", files: 124},
    optional_progress: {total_files: 3, done_files: 1, failed_files: 1, percent: 25,
      current: "data/media/cover.jpg", status: "Downloading 25%", files: [
        {path: "data/media/one.jpg", size: 2000000, state: "done"},
        {path: "data/media/cover.jpg", size: 8000000, state: "active"},
        {path: "data/media/three.jpg", size: 4000000, state: "failed"}]},
    tasks: 0, bad_files: 0, started_task_num: 0,
    clone_status: {state: "complete", attempt: 1, reason: null, next_retry_at: null},
  };
  peerFailure = false;
}
reset();
function fixtureHtml() {
  return render({address, info, counts, includes, received: 13002342, sent: 3334471,
    peer_map_open: globalSettings.sidebar_peer_map_open !== false});
}
function source(name) {
  if (name === "wrapper.html") return production.get("ui/wrapper.html");
  if (name === "all.js" || name === "all.css") return Buffer.concat([
    production.get("ui/media/" + name), Buffer.from("\n"),
    production.get("crates/epix-plugins/media/sidebar/" + name)]);
  if (name.startsWith("globe/")) return production.get("crates/epix-plugins/media/sidebar/" + name) ||
    fs.readFileSync(path.join(sourceRoot, "crates/epix-plugins/media/sidebar", name));
  return fs.readFileSync(path.join(sourceRoot, "ui/media", name));
}
function publish() {
  for (const ws of clients) if (ws.readyState === 1) ws.send(JSON.stringify({cmd: "setSiteInfo", params: info}));
}
const server = http.createServer((req, res) => {
  const pathname = new URL(req.url, "http://localhost").pathname;
  requests.push(pathname);
  if (pathname.startsWith("/uimedia/")) {
    const name = pathname.slice(9);
    if (name.includes("..")) return res.writeHead(400).end();
    try {
      const type = name.endsWith(".js") ? "text/javascript" : name.endsWith(".css") ? "text/css" :
        name.endsWith(".svg") ? "image/svg+xml" : name.endsWith(".jpg") ? "image/jpeg" : "image/png";
      return res.writeHead(200, {"Content-Type": type}).end(source(name));
    } catch { return res.writeHead(404).end(); }
  }
  if (pathname === "/EpixNet-Internal/Zip") return res.writeHead(200, {
    "Content-Type": "application/zip", "Content-Disposition": "attachment; filename=xite.zip",
  }).end(Buffer.from("PK\x05\x06" + "\x00".repeat(18), "binary"));
  if (pathname === `/${address}/`) {
    const vars = {
      title: "Properties fixture", rev: "test", meta_tags: `<meta name="viewport" id="viewport" content="${hint(scale)}">`,
      body_style: "", themeclass: "", homepage: "/home", resolving_host: "", is_homepage: "false", ui_restrict: "false",
      site_file_server: "", file_url: `/${address}/index.html`, query_string: "?wrapper_nonce=waiting", address,
      wrapper_nonce: "waiting", wrapper_key: address, ajax_key: "fixture", postmessage_nonce_security: "false",
      file_inner_path: "index.html", permissions: "[]", show_loadingscreen: "false",
      server_url: `http://127.0.0.1:${server.address().port}`, script_nonce: "fixturenonce",
      sandbox_permissions: "", wake_lock_allowlist: "*", lang: "en",
    };
    const html = source("wrapper.html").toString().replace(/\{(\w+)\}/g, (all, key) => vars[key] ?? all);
    return res.writeHead(200, {"Content-Type": "text/html", "Content-Security-Policy":
      "default-src 'none'; script-src 'nonce-fixturenonce' 'wasm-unsafe-eval'; img-src * blob: data:; media-src * blob: data:; font-src * data:; style-src 'self' blob: 'unsafe-inline'; connect-src *; frame-src *"}).end(html);
  }
  res.writeHead(200, {"Content-Type": "text/html"}).end("<!doctype html><title>Fixture</title><p>Fixture content</p>");
});
const wss = new WebSocketServer({server});
wss.on("connection", ws => {
  clients.add(ws); ws.on("close", () => clients.delete(ws));
  ws.on("message", raw => {
    const message = JSON.parse(raw), {cmd, params} = message;
    commands.push({cmd, params});
    let result = "ok", changed = false;
    const first = Array.isArray(params) ? params[0] : params;
    if (cmd === "siteInfo") result = {...info, content: {...info.content, viewport: hint(scale)}};
    else if (cmd === "sidebarGetHtmlTag") result = fixtureHtml();
    else if (cmd === "sidebarGetPeers") result = [51.5, -0.1, 0.02, 48.9, 2.3, 0.025, 40.7, -74, 0.03];
    else if (cmd === "serverInfo") result = {tor_status: "Disabled", ip_external: false, i2p_status: "Ready", user_settings: globalSettings};
    else if (cmd === "userGetGlobalSettings") result = globalSettings;
    else if (cmd === "userSetGlobalSettings") globalSettings = {...globalSettings, ...first};
    else if (cmd === "announcerInfo") result = {address, stats: {tracker: {status: "announced"}}};
    else if (cmd === "serverGetWrapperNonce") result = "fixture" + nonce++;
    else if (cmd === "notificationCount") result = {count: 0};
    else if (cmd === "ping") result = "pong";
    else if (cmd === "peerAdd") result = peerFailure ? {error: "Invalid <peer> endpoint"} : "updated";
    else if (cmd === "sitePause" || cmd === "siteResume") {info.settings.serving = cmd === "siteResume"; changed = true;}
    else if (cmd === "siteFavourite" || cmd === "siteUnfavourite") {info.settings.favorite = cmd === "siteFavourite"; changed = true;}
    else if (cmd === "siteSetOwned") {info.settings.own = first; changed = true;}
    else if (cmd === "siteSetDownloadoptional") {info.settings.download_optional = first; changed = true;}
    else if (cmd === "siteSetAutodownloadoptional") {info.settings.autodownloadoptional = first; if (first) info.settings.download_optional = true; changed = true;}
    else if (cmd === "siteSetLimit") {info.size_limit = Number(first); changed = true;}
    else if (cmd === "certXid") {info.cert_user_id = "fixture.epix"; changed = true;}
    else if (cmd === "fileGet") result = JSON.stringify({...info.content, includes: Object.fromEntries(includes.map(name => [name, {}]))});
    else if (cmd === "fileRules") result = {signers: [info.auth_address]};
    else if (cmd === "fileWrite") {info.content = {...info.content, ...JSON.parse(Buffer.from(params[1], "base64").toString())}; changed = true;}
    const reply = () => {if (message.id !== undefined) ws.send(JSON.stringify({cmd: "response", to: message.id, result}));};
    if (cmd === heldCommand) heldReplies.push(reply); else reply();
    if (changed) setImmediate(publish);
  });
});

// The production CSP forbids the eval used by Playwright's waitForFunction.
async function waitFor(page, predicate, argument, timeout = 5000) {
  const deadline = Date.now() + timeout;
  while (!(await page.evaluate(predicate, argument))) {
    if (Date.now() > deadline) throw new Error("Browser condition timed out: " + predicate.toString());
    await page.waitForTimeout(50);
  }
}
async function command(page, name, action) {
  const offset = commands.length;
  await action();
  const deadline = Date.now() + 5000;
  while (!commands.slice(offset).some(item => item.cmd === name)) {
    if (Date.now() > deadline) throw new Error("Expected command " + name);
    await page.waitForTimeout(25);
  }
  return commands.slice(offset).find(item => item.cmd === name);
}
async function open(page) {
  await waitFor(page, () => window.sidebar && sidebar.wrapper.xite_info);
  await page.evaluate(() => {sidebar.startDrag(); sidebar.moved("x"); sidebar.fixbutton_targetx = sidebar.fixbutton_initx - sidebar.width; sidebar.stopDrag();});
  await page.locator(".sidebar-container.loaded").waitFor();
  await page.waitForTimeout(550);
}
async function tab(page, name) {
  await page.locator("#sidebar-tab-" + name).click();
  assert.equal(await page.locator("#sidebar-tab-" + name).getAttribute("aria-selected"), "true");
  assert.equal(await page.locator("#sidebar-panel-" + name).isVisible(), true);
}
async function refresh(page, title) {
  info.content.title = title;
  await command(page, "sidebarGetHtmlTag", () => page.evaluate(() => sidebar.updateHtmlTag()));
  await waitFor(page, text => document.querySelector(".sidebar h1").textContent === text, title);
}
async function clearTimedNotifications(page) {
  // This suite triggers many operations faster than a person. Let their real
  // timed notifications close before testing pointer access to the popup menu.
  await waitFor(page, () => document.querySelectorAll(".notifications .notification:not(.template)").length === 0, null, 15000);
}
async function noOverflow(page) {
  const result = await page.evaluate(() => {
    const content = document.querySelector(".sidebar .content"), bounds = content.getBoundingClientRect();
    const offenders = [...content.querySelectorAll("*")].filter(element => {
      if (!element.getClientRects().length) return false;
      const style = getComputedStyle(element);
      if (style.visibility === "hidden" || style.display === "none") return false;
      const rect = element.getBoundingClientRect();
      return rect.width > 1 && (rect.left < bounds.left - 1 || rect.right > bounds.right + 1);
    }).map(element => element.id || element.className || element.tagName);
    return {client: content.clientWidth, scroll: content.scrollWidth, offenders};
  });
  assert.ok(result.scroll <= result.client + 1, JSON.stringify(result));
  assert.deepEqual(result.offenders, [], JSON.stringify(result));
}

async function watchGlobe(page) {
  await waitFor(page, () => sidebar.globe && sidebar.globe.points && document.querySelector(".globe canvas"));
  await waitFor(page, () => sidebar.globe.scene.children.some(mesh => {
    const texture = mesh.material?.uniforms?.texture?.value;
    return texture?.image?.complete && texture.image.naturalWidth > 0;
  }));
  await page.evaluate(() => {
    const globe = sidebar.globe, render = globe.renderer.render;
    window.globeFrames = {count: 0, position: null};
    globe.renderer.render = function(scene, camera) {
      window.globeFrames.count++;
      window.globeFrames.position = [camera.position.x, camera.position.y, camera.position.z];
      return render.apply(this, arguments);
    };
  });
  await waitFor(page, () => window.globeFrames.count > 2);
  assert.equal(await page.locator("#globe-zoom-in, #globe-zoom-out, #globe-reset, .sidebar-globe-controls").count(), 0);
  assert.equal((await page.locator("#sidebar-peer-map-panel").innerText()).trim(), "", "The map has no visible instructions or control labels");
  assert.equal(await page.locator("#sidebar-peer-map-panel button").count(), 0);
  assert.match(await page.locator(".globe").getAttribute("aria-label"), /arrow keys/);
  assert.equal(await page.evaluate(() => sidebar.globe.renderer.getClearAlpha()), 0, "The canvas exposes the themed panel background");
  assert.ok(await page.evaluate(() => sidebar.globe.points.geometry.vertices.length > 0), "Fixture peers render through the production globe");
}

async function globePalette(page) {
  return page.evaluate(() => sidebar.globe.scene.children.map(mesh => {
    const colors = {};
    for (const [name, uniform] of Object.entries(mesh.material?.uniforms || {})) {
      const value = uniform.value;
      if (value && typeof value.r === "number") colors[name] = [value.r, value.g, value.b];
    }
    return colors;
  }).filter(colors => Object.keys(colors).length));
}

async function waitForGlobePalette(page, expected, differs = false) {
  const serialized = JSON.stringify(expected), deadline = Date.now() + 5000;
  while ((JSON.stringify(await globePalette(page)) === serialized) === differs) {
    if (Date.now() > deadline) throw new Error("Globe palette did not respond to the theme");
    await page.waitForTimeout(50);
  }
}

async function setGlobeTheme(page, theme, previousPalette) {
  await page.evaluate(theme => {
    document.body.classList.remove("theme-light", "theme-dark");
    if (theme !== "system") document.body.classList.add("theme-" + theme);
  }, theme);
  if (previousPalette) await waitForGlobePalette(page, previousPalette, true);
  await page.waitForTimeout(150);
  const palette = await globePalette(page);
  assert.ok(palette.length > 0, "The WebGL globe has themed material colors");
  return palette;
}

async function globeInteraction(page) {
  const globe = page.locator(".globe"), box = await globe.boundingBox();
  const before = await page.evaluate(() => window.globeFrames.position);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width / 2 + 65, box.y + box.height / 2 + 20, {steps: 8});
  await page.mouse.up();
  await waitFor(page, before => Math.hypot(...window.globeFrames.position.map((v, i) => v - before[i])) > 20, before);
  const distance = await page.evaluate(() => Math.hypot(...window.globeFrames.position));
  await page.mouse.wheel(0, -200);
  await waitFor(page, before => Math.hypot(...window.globeFrames.position) < before - 50, distance);
  const zoomed = await page.evaluate(() => Math.hypot(...window.globeFrames.position));
  await globe.focus(); await globe.press("ArrowDown");
  await waitFor(page, before => Math.hypot(...window.globeFrames.position) > before + 30, zoomed);
  await page.evaluate(() => sidebar.globe.reset());
  await page.waitForTimeout(500);
}

(async () => {
  let browser;
  const results = {provenance, cases: [], errors};
  try {
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    browser = await chromium.launch({headless: true});
    const url = `http://127.0.0.1:${server.address().port}/${address}/`;
    async function newPage(options = {}) {
      const page = await browser.newPage({viewport: {width: 1280, height: 900}, ...options});
      page.setDefaultTimeout(5000);
      page.on("pageerror", error => errors.push(error.message));
      await page.goto(url); await open(page); return page;
    }
    const page = await newPage();
    await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
    await waitFor(page, () => sidebar.globe && sidebar.globe.points && document.querySelector(".globe canvas"));
    assert.equal(await page.locator("#sidebar-peer-map-toggle").getAttribute("aria-expanded"), "true");
    await command(page, "userSetGlobalSettings", () => page.locator("#sidebar-peer-map-toggle").click());
    assert.equal(globalSettings.sidebar_peer_map_open, false);
    assert.equal(await page.locator("#sidebar-peer-map-panel").isVisible(), false);
    await refresh(page, "Map refresh");
    assert.equal(await page.locator("#sidebar-peer-map-toggle").getAttribute("aria-expanded"), "false");
    await page.reload(); await open(page);
    assert.equal(await page.locator("#sidebar-peer-map-toggle").getAttribute("aria-expanded"), "false");
    await command(page, "userSetGlobalSettings", () => page.locator("#sidebar-peer-map-toggle").press("Enter"));
    await waitFor(page, () => sidebar.globe && sidebar.globe.points && document.querySelector(".globe canvas"));
    assert.equal(await page.locator("#sidebar-peer-map-panel").isVisible(), true);
    await watchGlobe(page);
    await globeInteraction(page);
    const lightPalette = await setGlobeTheme(page, "light");
    const lightMap = await page.locator(".globe canvas").screenshot();
    await page.evaluate(() => {window.themeGlobeCanvas = sidebar.globe.renderer.domElement;});
    const darkPalette = await setGlobeTheme(page, "dark", lightPalette);
    const darkMap = await page.locator(".globe canvas").screenshot();
    assert.notDeepEqual(darkMap, lightMap, "The actual WebGL image changes with the theme");
    assert.equal(await page.evaluate(() => sidebar.globe.renderer.domElement === window.themeGlobeCanvas), true, "Theme changes preserve the globe instance");
    assert.deepEqual(await setGlobeTheme(page, "light", darkPalette), lightPalette);
    await page.emulateMedia({colorScheme: "dark"});
    assert.deepEqual(await setGlobeTheme(page, "system", lightPalette), darkPalette);
    await page.emulateMedia({colorScheme: "light"});
    await waitForGlobePalette(page, lightPalette);
    results.cases.push("map default, fixture preference reload, reopen, production WebGL, drag/wheel/keyboard, and live light/dark/system themes");

    await page.locator("#peer-endpoint").fill("  192.0.2.10:42424  ");
    const added = await command(page, "peerAdd", () => page.locator("#peer-endpoint").press("Enter"));
    assert.deepEqual(added.params, {peer: "192.0.2.10:42424", site_address: address});
    await waitFor(page, () => document.querySelector("#peer-endpoint").value === "");
    peerFailure = true; await page.locator("#peer-endpoint").fill("bad-peer");
    await command(page, "peerAdd", () => page.locator("#form-addpeer [type=submit]").click());
    assert.equal(await page.locator("#peer-endpoint").inputValue(), "bad-peer"); peerFailure = false;
    await waitFor(page, () => document.querySelector("#peer-add-status").textContent.includes("Invalid <peer> endpoint"));
    await refresh(page, "Peer error retained");
    assert.ok((await page.locator("#peer-add-status").textContent()).includes("Invalid <peer> endpoint"));
    await command(page, "certXid", () => page.locator("#button-identity").click());
    await page.locator("#link-copypeers").click();
    assert.ok((await page.evaluate(() => navigator.clipboard.readText())).includes(address), "Copy retains the current xite address");
    for (const [id, name] of [["button-update", "siteUpdate"], ["button-pause", "sitePause"],
      ["button-resume", "siteResume"], ["button-favourite", "siteFavourite"], ["button-unfavourite", "siteUnfavourite"]]) {
      await command(page, name, () => page.locator("#" + id).click());
    }
    results.cases.push("peer submission and failure retention, identity, update, serving and favorite actions");

    await tab(page, "files");
    await page.locator("#input-xitelimit").fill("250");
    const limit = await command(page, "siteSetLimit", () => page.locator("#button-xitelimit").click());
    assert.equal(Array.isArray(limit.params) ? limit.params[0] : limit.params, "250");
    heldCommand = "siteSetLimit";
    await page.locator("#input-xitelimit").fill("275");
    await command(page, "siteSetLimit", () => page.locator("#button-xitelimit").click());
    await page.locator("#input-xitelimit").fill("450");
    await command(page, "sidebarGetHtmlTag", async () => releaseReplies());
    await refresh(page, "Late storage save response");
    assert.equal(await page.locator("#input-xitelimit").inputValue(), "450", "A completed save cannot clear a newer limit draft");
    await command(page, "siteSetDownloadoptional", () => page.locator("#checkbox-downloadoptional").uncheck());
    await command(page, "siteSetAutodownloadoptional", () => page.locator("#checkbox-autodownloadoptional").check());
    await waitFor(page, () => document.querySelector("#checkbox-downloadoptional").checked);
    await page.locator("#optional-files-toggle").click();
    await page.locator("#optional-file-list").waitFor({state: "visible"});
    assert.equal(await page.locator("#browse-files").getAttribute("href"), "/list/" + address);
    assert.equal(await page.locator("#sidebar-panel-files #link-directory").isVisible(), true);
    await command(page, "serverShowdirectory", () => page.locator("#link-directory").click());
    const downloadEvent = page.waitForEvent("download"); await page.locator("#link-zip").click();
    assert.equal((await downloadEvent).suggestedFilename(), "xite.zip");
    info.settings.size_optional = 0; info.optional_progress = null;
    await refresh(page, "No optional files"); assert.equal(await page.locator("#checkbox-downloadoptional").count(), 0);
    info.settings.size_optional = 32 * 1024 * 1024;
    await refresh(page, "Optional files restored"); assert.equal(await page.locator("#checkbox-downloadoptional").count(), 1);
    results.cases.push("files, storage limit, conditional optional files, dependency, progress and ZIP");

    await tab(page, "manage");
    for (const [id, name] of [["button-dbreload", "dbReload"], ["button-dbrebuild", "dbRebuild"]]) {
      await command(page, name, () => page.locator("#" + id).click());
    }
    await command(page, "siteRecoverPrivatekey", () => page.locator("#checkbox-owned").check());
    await page.locator("#settings-title").fill("Edited title");
    await page.locator("#settings-description").fill("Edited description");
    await page.locator("#settings-xid-name").fill("edited.epix");
    const written = await command(page, "fileWrite", () => page.locator("#button-settings").click());
    const saved = JSON.parse(Buffer.from(written.params[1], "base64").toString());
    assert.equal(saved.title, "Edited title"); assert.equal(saved.description, "Edited description"); assert.equal(saved.domain, "edited.epix");
    heldCommand = "fileWrite";
    await page.locator("#settings-title").fill("Submitted title");
    await command(page, "fileWrite", () => page.locator("#button-settings").click());
    await page.locator("#settings-title").fill("Newer title draft");
    await command(page, "sidebarGetHtmlTag", async () => releaseReplies());
    await refresh(page, "Late settings save response");
    assert.equal(await page.locator("#settings-title").inputValue(), "Newer title draft", "A completed save cannot clear newer metadata edits");
    await page.locator('.contents-content[data-content-path="data/users/content.json"]').click();
    assert.equal(await page.locator("#input-contents").inputValue(), "data/users/content.json");
    assert.equal(await page.locator('.contents-content[data-content-path="data/users/content.json"]').getAttribute("aria-pressed"), "true");
    const published = await command(page, "sitePublish", () => page.locator("#button-sign-publish").click());
    assert.equal(published.params.inner_path, "data/users/content.json"); assert.equal(published.params.sign, true);
    await clearTimedNotifications(page);
    await page.locator("#menu-sign-publish").click();
    await page.locator(".menu.visible .menu-item").filter({hasText: /^Sign$/}).evaluate(item => {item.focus(); window.focusedPublishItem = item;});
    await refresh(page, "Live publishing refresh");
    assert.equal(await page.evaluate(() => document.activeElement === window.focusedPublishItem && window.focusedPublishItem.isConnected), true,
      "Live updates preserve the focused publishing menu item");
    const signed = await command(page, "siteSign", () => page.locator(".menu.visible .menu-item").filter({hasText: /^Sign$/}).click());
    assert.equal(signed.params.inner_path, "data/users/content.json");
    await clearTimedNotifications(page);
    await page.locator("#menu-sign-publish").click();
    const publishOnly = await command(page, "sitePublish", () => page.locator(".menu.visible .menu-item").filter({hasText: /^Publish$/}).click());
    assert.equal(publishOnly.params.sign, false);
    results.cases.push("maintenance, ownership recovery, metadata, manifest choice, sign and publish variants");

    await page.locator("#settings-title").fill("Unsaved title draft");
    await page.locator("#input-contents").fill("custom/content.json");
    await page.locator("#input-contents").evaluate(input => {input.focus(); input.setSelectionRange(2, 9);});
    await refresh(page, "Live server title");
    assert.equal(await page.locator("#sidebar-tab-manage").getAttribute("aria-selected"), "true");
    assert.equal(await page.locator("#settings-title").inputValue(), "Unsaved title draft");
    assert.equal(await page.locator("#input-contents").inputValue(), "custom/content.json");
    assert.deepEqual(await page.locator("#input-contents").evaluate(input => [document.activeElement === input, input.selectionStart, input.selectionEnd]), [true, 2, 9]);
    assert.equal(await page.locator('.contents-content[aria-pressed="true"]').count(), 0);
    await page.locator('.contents-content[data-content-path="content.json"]').click();
    await refresh(page, "Root manifest retained");
    assert.equal(await page.locator('.contents-content[data-content-path="content.json"]').getAttribute("aria-pressed"), "true");
    await tab(page, "files"); await page.locator("#input-xitelimit").fill("400");
    await refresh(page, "Storage draft retained"); assert.equal(await page.locator("#input-xitelimit").inputValue(), "400");
    await tab(page, "overview"); await page.locator("#peer-endpoint").fill("rns:unfinished");
    await refresh(page, "Peer draft retained"); assert.equal(await page.locator("#peer-endpoint").inputValue(), "rns:unfinished");
    results.cases.push("active tab, drafts, focus, text selection and manifest selection survive live refresh");
    results.cases.push("delayed saves retain newer edits, peer error survives refresh and publishing menu focus remains intact");
    await page.screenshot({path: path.join(output, "desktop.png")});
    await tab(page, "files");
    await Promise.all([page.waitForURL("**/list/" + address), page.locator("#browse-files").click()]);
    assert.ok(requests.includes("/list/" + address), "Browse files uses the current xite route");
    await page.close();

    reset();
    const cleanDesktop = await newPage();
    await watchGlobe(cleanDesktop);
    for (const theme of ["light", "dark"]) {
      await setGlobeTheme(cleanDesktop, theme);
      await cleanDesktop.screenshot({path: path.join(output, `desktop-globe-${theme}.png`)});
    }
    await cleanDesktop.close();
    for (const setup of [{width: 320, scale: 1}, {width: 390, scale: 1}, {width: 390, scale: 0.5}]) {
      scale = setup.scale;
      const mobile = await newPage({viewport: {width: setup.width, height: 844}, isMobile: true, hasTouch: true});
      for (const name of ["overview", "files", "manage"]) {await tab(mobile, name); await noOverflow(mobile);}
      await mobile.screenshot({path: path.join(output, `mobile-${setup.width}-scale-${scale}.png`)});
      if (setup.width === 390 && scale === 1) {
        await tab(mobile, "overview");
        await watchGlobe(mobile);
        for (const theme of ["light", "dark"]) {
          await setGlobeTheme(mobile, theme);
          await mobile.screenshot({path: path.join(output, `mobile-globe-${theme}.png`)});
        }
      }
      await mobile.close();
    }
    results.cases.push("320px, 390px and reduced author viewport scale fit every tab");
    scale = 1;
    for (const mode of ["delete", "blacklist", "saved-key"]) {
      reset(); info.privatekey = mode === "saved-key";
      const deleting = await newPage(); await tab(deleting, "manage"); await deleting.locator("#button-delete").click();
      if (mode === "saved-key") {
        assert.ok(await deleting.locator(".notification").filter({hasText: "saved private key"}).isVisible());
        assert.equal(await deleting.locator(".button-confirm").filter({hasText: "Blacklist"}).count(), 0);
        await command(deleting, "siteDelete", () => deleting.getByText("Forget private key and delete xite", {exact: true}).click());
      } else if (mode === "blacklist") {
        await deleting.getByText("Blacklist", {exact: true}).click();
        await deleting.locator('.notification input[placeholder="Reason"]').fill("Fixture reason");
        const blocked = await command(deleting, "siteblockAdd", () => deleting.getByText("Delete and Blacklist", {exact: true}).click());
        assert.deepEqual(blocked.params, [address, "Fixture reason"]);
      } else await command(deleting, "siteDelete", () => deleting.getByText("Delete this xite", {exact: true}).click());
      await deleting.close();
    }
    results.cases.push("ordinary delete, blacklist reason and saved signing key warning");
    assert.deepEqual(errors, [], "No production browser errors");
    console.log(JSON.stringify(results, null, 2));
  } catch (error) {
    results.failure = error.stack;
    results.recentCommands = commands.slice(-20);
    let index = 0;
    for (const context of browser?.contexts() || []) for (const page of context.pages()) {
      await page.screenshot({path: path.join(output, `failure-${index++}.png`)}).catch(() => {});
    }
    throw error;
  } finally {
    fs.writeFileSync(path.join(output, "results.json"), JSON.stringify(results, null, 2));
    console.log("Sidebar properties artifacts: " + output);
    if (browser) await browser.close();
    for (const client of clients) client.terminate();
    await new Promise(resolve => wss.close(resolve)); await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
