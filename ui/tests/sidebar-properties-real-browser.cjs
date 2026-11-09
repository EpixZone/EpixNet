// Invoked by the isolated Rust sidebar_real_server test. Every HTTP and
// WebSocket response comes from production handlers. Never point this at a user node.
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
const {execFileSync} = require("node:child_process");
const tools = process.env.EPIX_BROWSER_TEST_TOOLS;
const {chromium} = require(tools ? path.join(tools, "playwright") : "playwright");
const fixture = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
assert.ok(fixture.root && fixture.xite_dir.startsWith(fixture.root + path.sep), "isolated test storage required");
const results = {kind: "production UiServer and SidebarPlugin", cases: [], errors: [], uncovered: [
  "Positive peer publish/download transfers are covered by separate controlled-network tests.",
  "Identity uses a local signed test identity; external chain discovery is not exercised.",
]};
let browser;
async function wait(page, predicate, arg, timeout = 12000) {
  const deadline = Date.now() + timeout;
  while (!(await page.evaluate(predicate, arg))) {
    if (Date.now() > deadline) throw new Error("Timed out: " + predicate.toString());
    await page.waitForTimeout(50);
  }
}
async function open(page, url = fixture.url) {
  await page.goto(url);
  await wait(page, () => window.sidebar && sidebar.wrapper.xite_info);
  await page.evaluate(() => {
    const ws = sidebar.wrapper.ws, original = ws.cmd;
    window.sidebarReplies = [];
    ws.cmd = function(command, params, callback) {
      return original.call(this, command, params, function(result) {
        window.sidebarReplies.push({command, result});
        if (callback) return callback(result);
      });
    };
    sidebar.startDrag(); sidebar.moved("x");
    sidebar.fixbutton_targetx = sidebar.fixbutton_initx - sidebar.width; sidebar.stopDrag();
  });
  await page.locator(".sidebar-container.loaded").waitFor();
  await page.waitForTimeout(600);
}
async function call(page, command, params = {}) {
  return page.evaluate(({command, params}) => new Promise(resolve => sidebar.wrapper.ws.cmd(command, params, resolve)), {command, params});
}
async function action(page, command, perform) {
  const offset = await page.evaluate(() => window.sidebarReplies.length);
  await perform();
  await wait(page, ({offset, command}) => window.sidebarReplies.slice(offset).some(reply => reply.command === command), {offset, command});
  return page.evaluate(({offset, command}) => window.sidebarReplies.slice(offset).find(reply => reply.command === command).result, {offset, command});
}
async function tab(page, name) {
  await page.locator("#sidebar-tab-" + name).click();
  assert.equal(await page.locator("#sidebar-panel-" + name).isVisible(), true);
}
async function refresh(page) {
  await action(page, "sidebarGetHtmlTag", () => page.evaluate(() => sidebar.updateHtmlTag()));
  await page.waitForTimeout(100);
}
async function notification(page, text) {
  await wait(page, text => [...document.querySelectorAll(".notification")].some(element => element.textContent.includes(text)), text);
}
async function clearNotifications(page) {
  // Close actual dismissible notifications through their existing UI.
  const existing = await page.locator(".notification:not(.template)").elementHandles();
  for (const element of existing) {
    const close = await element.$(".close");
    if (close && await close.isVisible()) await close.click().catch(() => {});
  }
  // Timed notifications have no close button. Wait only for this snapshot;
  // subsequent background notices must not hold up an unrelated control test.
  const deadline = Date.now() + 15000;
  while ((await Promise.all(existing.map(element => element.evaluate(node => node.isConnected)))).some(Boolean)) {
    if (Date.now() > deadline) throw new Error("Existing notifications did not finish closing");
    await page.waitForTimeout(50);
  }
  await Promise.all(existing.map(element => element.dispose()));
}
async function blockFile(file, operation) {
  const backup = file + ".sidebar-test-backup";
  const existed = fs.existsSync(file);
  if (existed) fs.renameSync(file, backup);
  fs.mkdirSync(file);
  try { return await operation(); }
  finally { fs.rmSync(file, {recursive: true}); if (existed) fs.renameSync(backup, file); }
}
async function noOverflow(page) {
  const width = await page.locator(".sidebar .content").evaluate(element => [element.clientWidth, element.scrollWidth]);
  assert.ok(width[1] <= width[0] + 1, "sidebar width " + width);
}
(async () => {
  try {
    browser = await chromium.launch({headless: true});
    const context = await browser.newContext({viewport: {width: 1280, height: 950}, permissions: ["clipboard-read", "clipboard-write"]});
    context.on("page", page => page.on("pageerror", error => results.errors.push(error.message)));
    const page = await context.newPage(); await open(page);
    const originalPeers = (await call(page, "siteInfo")).peers;
    await page.locator("#link-copypeers").click();
    const copied = new URL(await page.evaluate(() => navigator.clipboard.readText()));
    assert.equal(copied.pathname, "/" + fixture.address + "/");
    const peers = copied.searchParams.get("epixnet_peers");
    assert.ok(peers.includes("8.8.8.8:26552") && peers.includes("8.8.4.4:26552"));
    assert.ok(!peers.includes("192.168.100.15") && !peers.includes("127.0.0.1"));
    await open(page, fixture.url + "?epixnet_peers=9.9.9.9%3A26552,127.0.0.1%3A1&route=kept");
    assert.equal((await call(page, "siteInfo")).peers, originalPeers + 1);
    assert.ok(!(await page.locator("#inner-iframe").getAttribute("src")).includes("epixnet_peers"));
    results.cases.push({items: [2], check: "Copied real public peer endpoints and imported them through the production wrapper route"});

    const globe = await call(page, "sidebarGetPeers");
    assert.ok(globe.length >= 6 && globe.some((n, i) => i % 3 === 2 && n === -0.135), "GeoIP includes the real configured self marker");
    const positions = globe.filter((_, index) => index % 3 === 0).map((lat, index) => `${lat},${globe[index * 3 + 1]}`);
    assert.equal(new Set(positions).size, positions.length, "Coincident real GeoIP peer locations are separated");
    await wait(page, () => sidebar.globe && sidebar.globe.points);
    assert.equal(await page.locator("#globe-zoom-in, #globe-zoom-out, #globe-reset").count(), 0);
    await page.screenshot({path: path.join(fixture.output, "real-desktop-overview.png")});
    results.cases.push({items: [22], check: "Production GeoIP endpoint and WebGL self marker render"});

    assert.ok((await page.locator("#sidebar-panel-overview").innerText()).includes(fixture.identity));
    assert.ok((await page.locator("#sidebar-panel-overview").innerText()).includes("Storage used"));
    assert.equal(await page.locator(".sidebar-donation, .sidebar-donation-note").count(), 0);
    assert.equal(await page.locator('.sidebar a[href^="bitcoin:"], .sidebar a[href^="monero:"], .sidebar a[href^="web+cardano:"]').count(), 0);
    assert.ok(!(await page.locator(".sidebar").innerText()).includes("example.org/support"));
    assert.equal(await action(page, "certSet", () => page.locator("#button-cert-disconnect").click()), "ok");
    assert.equal((await call(page, "siteInfo")).auth_address, null);
    assert.equal(await call(page, "certXid", {xid_name: "sidebaruser"}), "ok");
    await refresh(page);
    assert.equal((await call(page, "siteInfo")).auth_address, fixture.identity);
    results.cases.push({items: [16, 21], check: "Donation UI is absent despite metadata, as requested; linked identity address and delegated content quota render"});

    await tab(page, "files");
    assert.equal(await page.locator("#sidebar-panel-files #link-directory").isVisible(), true);
    await page.locator(".sidebar-details summary").click();
    const breakdown = await page.locator(".sidebar-storage-types").innerText();
    for (const category of ["HTML", "CSS", "JavaScript", "Images", "JSON", "User data", "Other"]) assert.ok(breakdown.includes(category));
    assert.ok((await page.locator("#sidebar-panel-files").innerText()).includes("Available disk space"));
    assert.ok((await page.locator(".sidebar-pending-files").innerText()).includes("updates/missing.json"));
    assert.ok((await page.locator(".sidebar-pending-files").innerText()).includes("2 tries"));
    results.cases.push({items: [17, 18, 19], check: "Verified manifest file-type totals, filesystem free space, and restored pending-file paths/retries render"});
    if (fixture.test_opener) {
      const failed = await action(page, "serverShowdirectory", () => page.locator("#link-directory").click());
      assert.ok(failed.error); await notification(page, "Could not open directory");
      assert.equal(fs.readFileSync(path.join(fixture.root, "opener-log"), "utf8"), fixture.xite_dir);
      fs.writeFileSync(path.join(fixture.root, "opener-status"), "0");
      assert.equal(await action(page, "serverShowdirectory", () => page.locator("#link-directory").click()), "ok");
      results.cases.push({items: [], check: "Show Directory executes the OS launcher with the real path and distinguishes exit failure from success"});
    }

    await page.locator("#input-xitelimit").fill("-1");
    const invalidLimit = await action(page, "siteSetLimit", () => page.locator("#button-xitelimit").click());
    assert.ok(invalidLimit.error); await notification(page, "Could not save storage limit");
    await page.locator("#input-xitelimit").fill("275");
    assert.equal(await action(page, "siteSetLimit", () => page.locator("#button-xitelimit").click()), "ok");
    assert.equal((await call(page, "siteInfo")).size_limit, 275);
    results.cases.push({items: [9], check: "Negative storage limit rejects visibly; valid limit changes actual backend state"});

    if (await page.locator("#checkbox-downloadoptional").isChecked()) {
      assert.equal(await action(page, "siteSetDownloadoptional", () => page.locator("#checkbox-downloadoptional").uncheck()), "ok");
    }
    assert.equal(await action(page, "siteSetAutodownloadoptional", () => page.locator("#checkbox-autodownloadoptional").check()), "ok");
    let info = await call(page, "siteInfo");
    assert.equal(info.settings.download_optional, true); assert.equal(info.settings.autodownloadoptional, true);
    await refresh(page);
    assert.equal(await action(page, "siteSetDownloadoptional", () => page.locator("#checkbox-downloadoptional").uncheck()), "ok");
    info = await call(page, "siteInfo");
    assert.equal(info.settings.download_optional, false); assert.equal(info.settings.autodownloadoptional, false);
    await page.locator("#input-autodownload_bigfile_size_limit").fill("3");
    assert.equal(await action(page, "siteSetAutodownloadBigfileLimit", () => page.locator("#button-autodownload_bigfile_size_limit").click()), "ok");
    assert.equal((await call(page, "siteInfo")).settings.autodownload_bigfile_size_limit, 3);
    const previous = await action(page, "siteDownloadOptionalPrevious", () => page.locator("#button-autodownload_previous").click());
    assert.ok(previous.error || ["complete", "started"].includes(previous.status));
    info = await call(page, "siteInfo");
    assert.equal(info.settings.download_optional, false); assert.equal(info.settings.autodownloadoptional, false);
    results.cases.push({items: [1, 14, 15], check: "Optional switches persist coupled state; per-xite threshold saves; one-shot does not change policy (network bytes tested separately)"});

    const downloadPromise = page.waitForEvent("download"); await page.locator("#link-zip").click();
    const download = await downloadPromise, zip = path.join(fixture.output, "real-xite.zip"); await download.saveAs(zip);
    const entries = execFileSync("python3", ["-c", "import zipfile,sys,json; z=zipfile.ZipFile(sys.argv[1]); print(json.dumps(z.namelist())); assert any(n.endswith('index.html') for n in z.namelist()); assert not any('users.json' in n or '/private/' in n for n in z.namelist())", zip], {encoding:"utf8"});
    results.cases.push({items: [], check: "Real ZIP export contains public xite files", entries: JSON.parse(entries)});

    await clearNotifications(page); await tab(page, "manage");
    assert.ok((await page.locator("#sidebar-panel-manage").innerText()).includes("Search feeds"));
    assert.equal(await action(page, "dbReload", () => page.locator("#button-dbreload").click()), "ok");
    assert.equal(await action(page, "dbRebuild", () => page.locator("#button-dbrebuild").click()), "ok");
    assert.equal((await call(page, "dbQuery", ["SELECT title FROM post WHERE post_id = 7"]))[0].title, "Real database row");
    const schemaPath = path.join(fixture.xite_dir, "dbschema.json"), schema = fs.readFileSync(schemaPath);
    try {
      fs.writeFileSync(schemaPath, "{ invalid schema");
      const rejected = await action(page, "dbReload", () => page.locator("#button-dbreload").click());
      assert.ok(rejected.error); await notification(page, "Could not reload database schema");
    } finally { fs.writeFileSync(schemaPath, schema); }
    results.cases.push({items: [3, 6, 20], check: "Real database maintenance and row query; malformed schema is visibly rejected"});

    const contentPath = path.join(fixture.xite_dir, "content.json"), before = fs.readFileSync(contentPath);
    try {
      fs.writeFileSync(contentPath, "{ invalid settings");
      await page.locator("#settings-title").fill("Cannot save invalid JSON");
      await action(page, "fileGet", () => page.locator("#button-settings").click());
      await notification(page, "Could not read xite settings");
      assert.equal(fs.readFileSync(contentPath, "utf8"), "{ invalid settings");
    } finally { fs.writeFileSync(contentPath, before); }
    await page.locator("#settings-title").fill("Saved through the real sidebar");
    assert.equal(await action(page, "siteSign", () => page.locator("#button-settings").click()), "ok");
    assert.equal(JSON.parse(fs.readFileSync(contentPath)).title, "Saved through the real sidebar");
    results.cases.push({items: [10], check: "Malformed settings fail visibly; real metadata write and observed signing both complete"});

    await clearNotifications(page);
    await page.locator("#privatekey-forget").click();
    assert.equal(await action(page, "userSetSitePrivatekey", () => page.locator(".button-confirm").filter({hasText: /^Forget$/}).click()), "ok");
    await page.locator("#privatekey-add").waitFor();
    await page.locator("#privatekey-add").click();
    const keyPrompt = page.locator(".notification-ask").filter({has: page.locator('input[type="password"]')}).last();
    await keyPrompt.locator('input[type="password"]').fill("invalid-key");
    const invalidKey = await action(page, "userSetSitePrivatekey", () => keyPrompt.getByRole("link", {name:"Save", exact:true}).click());
    assert.ok(invalidKey.error); assert.equal((await call(page, "siteInfo")).privatekey, false);
    await clearNotifications(page); await page.locator("#privatekey-add").click();
    await keyPrompt.locator('input[type="password"]').fill(fixture.key);
    assert.equal(await action(page, "userSetSitePrivatekey", () => keyPrompt.getByRole("link", {name:"Save", exact:true}).click()), "ok");
    assert.equal((await call(page, "siteInfo")).privatekey, true);
    results.cases.push({items: [13], check: "Saved key forget/add controls mutate real user storage and reject an invalid key"});

    await clearNotifications(page);
    const publish = await action(page, "sitePublish", () => page.locator("#button-sign-publish").click());
    assert.ok(publish.error, "An offline backend must not claim network publish acceptance");
    await notification(page, "Publishing failed");
    assert.ok(!(await page.locator(".notifications").innerText()).includes("Signed and published!"));
    results.cases.push({items: [7], check: "Offline publish reports actual failure without contradictory success"});

    await tab(page, "overview"); await clearNotifications(page);
    await action(page, "siteUpdate", () => page.locator("#button-update").click());
    await notification(page, "Update failed");
    assert.ok(!(await page.locator(".notifications").innerText()).includes("Xite updated!"));
    results.cases.push({items: [5], check: "Update waits for the real asynchronous failure outcome"});

    const registryFile = path.join(fixture.root, "private/xites.json");
    await blockFile(registryFile, async () => {
      const failed = await action(page, "siteFavourite", () => page.locator("#button-favourite").click());
      assert.ok(failed.error); assert.equal((await call(page, "siteInfo")).settings.favorite, false);
      await notification(page, "Could not change xite settings");
    });
    assert.equal(await action(page, "siteFavourite", () => page.locator("#button-favourite").click()), "ok");
    assert.equal(await action(page, "sitePause", () => page.locator("#button-pause").click()), "ok");
    const usersFile = path.join(fixture.root, "private/users.json");
    await blockFile(usersFile, async () => {
      const failed = await action(page, "userSetGlobalSettings", () => page.locator("#sidebar-peer-map-toggle").click());
      assert.ok(failed.error); await notification(page, "Could not save the peer map preference");
      assert.notEqual((await call(page, "userGetGlobalSettings")).sidebar_peer_map_open, false);
    });
    assert.equal(await action(page, "userSetGlobalSettings", () => page.locator("#sidebar-peer-map-toggle").click()), "ok");
    assert.equal(await action(page, "userSetGlobalSettings", () => page.locator("#sidebar-peer-map-toggle").click()), "ok");
    assert.equal((await call(page, "userGetGlobalSettings")).sidebar_peer_map_open, false);
    results.cases.push({items: [4, 11, 12], check: "Real filesystem failures reject and retain old state; valid favorite/pause/map state persists (Rust reopens disk afterward)"});

    assert.equal(await call(page, "configSet", ["language", "es"]), "ok"); await refresh(page);
    assert.equal(await page.locator("#sidebar-tab-files").innerText(), "Ficheros");
    assert.ok((await page.locator("#sidebar-panel-overview").innerText()).includes("Pares"));
    assert.equal(await call(page, "configSet", ["language", "en"]), "ok"); await refresh(page);
    results.cases.push({items: [23], check: "Server-selected Spanish translations render, then English restores"});

    await clearNotifications(page);
    for (const width of [320, 390]) {
      await page.setViewportSize({width, height: 844});
      for (const name of ["overview", "files", "manage"]) { await tab(page, name); await noOverflow(page); }
      await page.screenshot({path: path.join(fixture.output, `real-mobile-${width}.png`)});
    }
    await page.setViewportSize({width: 1280, height: 950});
    for (let i = 0; i < fixture.deletion.length; i++) {
      const address = fixture.deletion[i], deleting = await context.newPage();
      await open(deleting, new URL("/" + address + "/", fixture.url).href);
      if (i === 1) { assert.equal(await call(deleting, "userSetSitePrivatekey", [""]), "ok"); await refresh(deleting); }
      await tab(deleting, "manage");
      if (i === 0) {
        // Registry compaction can safely defer after a durable deletion intent.
        // Fail the intent write itself to exercise a genuine precommit error.
        await blockFile(path.join(fixture.root, "private/xite-removals.json"), async () => {
          await deleting.locator("#button-delete").click();
          const failure = await action(deleting, "siteDelete", () => deleting.getByText("Forget private key and delete xite", {exact:true}).click());
          assert.ok(failure.error); await notification(deleting, "Could not delete xite");
          assert.ok(deleting.url().includes(address)); assert.ok(fs.existsSync(path.join(fixture.root, "data", address)));
        });
      } else {
        await blockFile(path.join(fixture.root, "private/filters.json"), async () => {
          const deletionsBefore = await deleting.evaluate(() => window.sidebarReplies.filter(reply => reply.command === "siteDelete").length);
          await deleting.locator("#button-delete").click();
          await deleting.getByText("Blacklist", {exact:true}).click();
          await deleting.locator('input[placeholder="Reason"]').fill("Rejected test block reason");
          const failure = await action(deleting, "siteblockAdd", () => deleting.getByText("Delete and Blacklist", {exact:true}).click());
          assert.ok(failure.error); await notification(deleting, "Could not blacklist xite");
          assert.ok(deleting.url().includes(address));
          assert.ok(fs.existsSync(path.join(fixture.root, "data", address)));
          assert.equal(await deleting.evaluate(() => window.sidebarReplies.filter(reply => reply.command === "siteDelete").length), deletionsBefore,
            "Rejected blacklist must not invoke deletion");
        });
      }
      await clearNotifications(deleting); await deleting.locator("#button-delete").click();
      if (i === 1) {
        await deleting.getByText("Blacklist", {exact:true}).click();
        await deleting.locator('input[placeholder="Reason"]').fill("Integration test block reason");
        await deleting.getByText("Delete and Blacklist", {exact:true}).click();
      } else await deleting.getByText("Forget private key and delete xite", {exact:true}).click();
      await deleting.waitForURL(url => url.pathname.split("/")[1] === fixture.address, {waitUntil: "domcontentloaded"});
      assert.ok(!fs.existsSync(path.join(fixture.root, "data", address)));
      await deleting.close();
    }
    results.cases.push({items: [8], check: "Actual failed deletion and blacklist retain page/files; blacklist failure never invokes delete; successful retries remove isolated xites"});
    assert.deepEqual(results.errors, [], "No browser runtime errors");
  } catch (error) {
    results.failure = error.stack;
    for (const [i, page] of (browser?.contexts().flatMap(context => context.pages()) || []).entries()) {
      await page.screenshot({path: path.join(fixture.output, `real-failure-${i}.png`)}).catch(() => {});
    }
    throw error;
  } finally {
    fs.writeFileSync(path.join(fixture.output, "real-results.json"), JSON.stringify(results, null, 2));
    console.log(JSON.stringify({cases: results.cases, errors: results.errors, uncovered: results.uncovered, failure: results.failure}, null, 2));
    if (browser) await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
