// Run the production sidebar renderer; the server supplies the current xite's link.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const source = fs.readFileSync(
  path.join(__dirname, "../../crates/epix-plugins/media/sidebar/all.js"), "utf8",
);
const start = source.indexOf("Sidebar.prototype.setHtmlTag = function");
const end = source.indexOf("\n    };", start);
assert.ok(start >= 0 && end > start, "production sidebar renderer exists");

function sidebar(url) {
  const content = { populated: false };
  const browse = {
    href: null,
    attr(name, value) {
      assert.equal(name, "href");
      if (value !== undefined) this.href = value;
      return this.href;
    },
  };
  const control = { off() { return this; }, on() { return this; } };
  const context = vm.createContext({
    document: { location: new URL(url) },
    morphdom(element, html) {
      assert.equal(element, content);
      // Stand in for insertion/replacement of the server-rendered anchor.
      browse.href = html.match(/<a href='([^']+)' id='browse-files'>/)[1];
      content.populated = true;
    },
  });
  vm.runInContext(`var Sidebar = function() {};\n${source.slice(start, end + 7)}`, context);
  const instance = Object.create(context.Sidebar.prototype);
  Object.assign(instance, {
    log() {},
    container: { addClass() {} },
    when_loaded: { resolve() {} },
    updateOptionalProgress() {},
    tag: {
      find(selector) {
        if (selector === "#browse-files") return browse;
        if (selector === ".content") {
          return { 0: content, children: () => ({ length: Number(content.populated) }) };
        }
        return control;
      },
    },
  });
  return { instance, browse };
}

for (const url of [
  "https://dashboard.epix/",
  "https://dashboard.epix/docs/index.html?view=files#section",
  "https://epix1exampleaddressfornavigation.epix/",
  "http://127.0.0.1:42222/dashboard.epix/docs/index.html",
]) {
  test(`Browse Files keeps the current xite on initial render and refresh: ${url}`, () => {
    const { instance, browse } = sidebar(url);
    // The server resolves names/aliases to the session's canonical xite key.
    const target = "/list/epix1currentxiteaddress";
    const html = `<a href='${target}' id='browse-files'>Browse files</a>`;
    instance.setHtmlTag(html);
    assert.equal(browse.href, target, "initial properties panel targets its xite");
    instance.setHtmlTag(html);
    assert.equal(browse.href, target, "live properties refresh preserves the target");
    assert.equal(new URL(browse.href, url).pathname, target);
  });
}
