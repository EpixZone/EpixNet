// Run: node --test ui/tests/wrapper-deletion-progress.test.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const source = fs.readFileSync(path.join(__dirname, "../media/all.js"), "utf8");
function method(name) {
  const start = source.indexOf(`Wrapper.prototype.${name} = function`);
  assert.ok(start >= 0, `missing production method ${name}`);
  const end = source.indexOf("\n    };", start);
  assert.ok(end > start, `missing method end for ${name}`);
  return source.slice(start, end + "\n    };".length);
}

function progress(params) {
  const calls = [];
  const context = vm.createContext({
    message: JSON.stringify({ params }),
    displayProgress: (key, html, percent) => calls.push({ key, html, percent }),
  });
  vm.runInContext(`
    var Wrapper = function() {};
    ${method("actionProgress")}
    ${method("toHtmlSafe")}
    var wrapper = new Wrapper();
    wrapper.displayProgress = displayProgress;
    wrapper.actionProgress(JSON.parse(message));
  `, context);
  assert.equal(calls.length, 1);
  return calls[0];
}

test("deletion progress renders an exact name and a separate file counter", () => {
  assert.deepEqual(progress([
    "delete-epix1example", "Deleting site A & B...\nDeleting file 298564/999999", 42, true,
  ]), {
    key: "page-delete-epix1example",
    html: "Deleting site A &amp; B...<br>Deleting file 298564/999999",
    percent: "42",
  });
});

test("plain-text progress never interprets names as allowed formatting or script", () => {
  const rendered = progress([
    "delete-epix1example",
    'Deleting site <b>A</b> <script>alert("x")</script> &amp; \'name\'...\nDeleting file 1/2',
    55,
    true,
  ]);
  assert.equal(rendered.html,
    "Deleting site &lt;b&gt;A&lt;/b&gt; &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; &amp;amp; &apos;name&apos;...<br>Deleting file 1/2");
  assert.doesNotMatch(rendered.html, /<(?:b|script)>/);
});

test("plain-text progress handles line endings and terminal percentages", () => {
  assert.equal(progress(["delete-site", "one\r\ntwo\rthree\nfour", 100, true]).html,
    "one<br>two<br>three<br>four");
  assert.equal(progress(["delete-site", "Finished", 100, true]).percent, "100");
  assert.equal(progress(["delete-site", "Failed", -1, true]).percent, "-1");
});

test("legacy progress retains its allowed markup and escaped unsafe content", () => {
  for (const flag of [undefined, false, "true"]) {
    const params = ["publish", '<b>A & B</b><br><small>Done</small><script>bad</script>', 100];
    if (flag !== undefined) params.push(flag);
    assert.deepEqual(progress(params), {
      key: "page-publish",
      html: "<b>A &amp; B</b><br><small>Done</small>&lt;script&gt;bad&lt;/script&gt;",
      percent: "100",
    });
  }
});
