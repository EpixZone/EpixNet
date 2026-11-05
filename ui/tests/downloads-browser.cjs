// Run: EPIX_BROWSER_TEST_TOOLS=/path/to/node_modules node ui/tests/downloads-browser.cjs
// Exercise the production iframe policy with browser downloads. The payloads
// must reach disk intact while the xite still cannot access its parent.
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const assert = require("node:assert/strict");
const tools = process.env.EPIX_BROWSER_TEST_TOOLS;
const { chromium } = require(tools ? path.join(tools, "playwright") : "playwright");
const source = path.resolve(process.env.EPIX_BROWSER_TEST_SOURCE || path.join(__dirname, "../.."));
const blocked = process.env.EPIX_DOWNLOAD_EXPECT_BLOCKED === "1";
const output = process.env.EPIX_BROWSER_TEST_OUTPUT ||
  fs.mkdtempSync(path.join(require("node:os").tmpdir(), "epix-downloads-"));
fs.mkdirSync(output, { recursive: true });
const template = fs.readFileSync(path.join(source, "ui/wrapper.html"), "utf8");
const sandbox = template.match(/id='inner-iframe' sandbox="([^"]+)"/)[1]
  .replace("{sandbox_permissions}", "").trim();
const expected = "EpixNet download fixture\n";
const inner = `<!doctype html><button id="blob">Save generated text</button>
<a id="attachment" href="/file">Save attachment</a><script>
  document.getElementById("blob").onclick = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([${JSON.stringify(expected)}], {type: "text/plain"}));
    a.download = "generated.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
  };
  try { parent.document.body; window.parentReadable = true; }
  catch { window.parentReadable = false; }
</script>`;
const server = http.createServer((req, res) => {
  if (req.url === "/file") {
    res.writeHead(200, {
      "content-type": "application/octet-stream",
      "content-disposition": 'attachment; filename="attachment.txt"',
    });
    res.end(expected);
  } else {
    res.setHeader("content-type", "text/html");
    res.end(req.url === "/inner" ? inner :
      `<!doctype html><iframe src="/inner" sandbox="${sandbox}"></iframe>`);
  }
});

(async () => {
  let browser;
  const results = [];
  try {
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ acceptDownloads: true });
    const page = await context.newPage();
    for (const type of ["blob", "attachment"]) {
      await page.goto(`http://127.0.0.1:${server.address().port}/`);
      const frame = page.frames().find(f => f.url().endsWith("/inner"));
      assert.equal(await frame.evaluate(() => window.parentReadable), false,
        "xite must not read the wrapper");
      const pending = page.waitForEvent("download", { timeout: blocked ? 1800 : 5000 })
        .catch(error => {
          if (blocked && error.name === "TimeoutError") return null;
          throw error;
        });
      await frame.locator("#" + type).click();
      const download = await pending;
      if (blocked) {
        assert.equal(download, null, "baseline download remains blocked");
        results.push({ type, blocked: true, parentIsolated: true });
      } else {
        assert.ok(download, `${type} download must start`);
        const filename = type === "blob" ? "generated.txt" : "attachment.txt";
        assert.equal(download.suggestedFilename(), filename);
        const destination = path.join(output, filename);
        await download.saveAs(destination);
        assert.equal(fs.readFileSync(destination, "utf8"), expected);
        results.push({ type, saved: filename, bytes: fs.statSync(destination).size, parentIsolated: true });
      }
    }
    const report = { mode: blocked ? "before" : "after", sandbox, results };
    fs.writeFileSync(path.join(output, "results.json"), JSON.stringify(report, null, 2) + "\n");
    console.log(JSON.stringify(report, null, 2));
  } finally {
    if (browser) await browser.close();
    server.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
