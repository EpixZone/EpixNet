// Run the production siteInfo handler with deterministic browser navigation.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const source = fs.readFileSync(path.join(__dirname, "../media/all.js"), "utf8");
const ADDRESS = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
const OTHER = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
function method(name) {
  const start = source.indexOf(`Wrapper.prototype.${name} = function`);
  if (start < 0) return "";
  return source.slice(start, source.indexOf("\n    };", start) + 7);
}
function fixture(href) {
  const navigation = [], history = [], commands = [];
  let current = new URL(href);
  const savedState = { topic: "saved" };
  const location = { get href() { return current.href; }, replace(url) { navigation.push(url); } };
  const window = {
    address: ADDRESS, location,
    history: { state: savedState, replaceState(state, title, url) {
      history.push({ state, title, url }); current = new URL(url, current);
    } },
  };
  const $ = Object.assign(() => ({ attr: () => "?view=existing" }), { extend: Object.assign });
  const context = vm.createContext({ window, URL, $, console });
  vm.runInContext("var Wrapper = function() {};\n" +
    ["setXiteInfo", "applyCanonicalDomain"].map(method).join("\n"), context);
  const wrapper = Object.assign(Object.create(context.Wrapper.prototype), {
    xite_info: null, address: null, inner_loaded: false,
    event_xite_info: { resolve() {} },
    loading: { screen_visible: true, printLine() {} },
    ws: { cmd(...args) { commands.push(args); } },
  });
  function info(extra = {}) {
    wrapper.setXiteInfo({ address: ADDRESS, peers: 0, content: {},
      settings: { size: 0, permissions: [], own: false }, size_limit: 10, ...extra });
  }
  return { wrapper, window, info, navigation, history, commands, savedState, url: () => current.href };
}

for (const host of [ADDRESS, `${ADDRESS}.epix`]) {
  test(`verified name replaces raw desktop host once: ${host}`, () => {
    const suffix = "/docs/a%23b%252Fc.html?view=a%2Fb#section%202";
    const f = fixture(`https://${host}${suffix}`);
    f.info({ canonical_domain: "talk.epix" });
    f.info({ canonical_domain: "talk.epix" });
    assert.deepEqual(f.navigation, [`https://talk.epix${suffix}`]);
    assert.equal(f.history.length, 0, "cross-origin promotion uses replace navigation");
    assert.equal(f.commands.length, 0, "promotion never restarts discovery");
  });
}

for (const reference of [ADDRESS, `${ADDRESS}.epix`]) {
  test(`mobile changes only the address segment without reloading: ${reference}`, () => {
    const suffix = "/docs/a%23b%252Fc.html?view=a%2Fb#section%202";
    const f = fixture(`http://127.0.0.1:42222/${reference}${suffix}`);
    f.info({ canonical_domain: "talk.epix" });
    f.info({ canonical_domain: "talk.epix" });
    assert.equal(f.url(), `http://127.0.0.1:42222/talk.epix${suffix}`);
    assert.equal(f.history.length, 1);
    assert.equal(f.history[0].state, f.savedState);
    assert.equal(f.navigation.length, 0, "the loading document and iframe stay in place");
    assert.equal(f.commands.length, 0);
    assert.equal(f.wrapper.loading.screen_visible, true);
  });
}

test("a verified name can arrive after an ordinary loading snapshot", () => {
  const f = fixture(`https://${ADDRESS}.epix/`);
  f.info({ display: "unverified.epix", content: { domain: "claimed.epix" } });
  assert.equal(f.navigation.length, 0, "display metadata and content claims are not verification");
  f.info({ canonical_domain: "talk.epix" });
  assert.deepEqual(f.navigation, ["https://talk.epix/"]);
});

test("an explicit index.html path is retained", () => {
  const f = fixture(`https://${ADDRESS}.epix/myindex.html?keep=1#anchor`);
  f.info({ canonical_domain: "talk.epix" });
  assert.deepEqual(f.navigation, ["https://talk.epix/myindex.html?keep=1#anchor"]);
});

test("a name for another xite cannot rename the current page", () => {
  const f = fixture(`https://${ADDRESS}.epix/`);
  f.info({ address: OTHER, canonical_domain: "dashboard.epix" });
  assert.equal(f.navigation.length, 0);
});

for (const href of [
  "https://already.epix/docs/", `http://127.0.0.1:42222/already.epix/docs/`,
  `https://ordinary.example/${ADDRESS}/`, "http://127.0.0.1:42222/Config",
]) {
  test(`named or unrelated navigation is left unchanged: ${href}`, () => {
    const f = fixture(href); f.info({ canonical_domain: "talk.epix" });
    assert.equal(f.navigation.length + f.history.length, 0);
    assert.equal(f.url(), href);
  });
}

for (const domain of [null, "", "https://talk.epix", "talk.com", "talk.epix/path",
  "user@talk.epix", "talk.epix:443", "talk..epix", "-talk.epix", "talk-.epix", "talk.epix#fragment"]) {
  test(`invalid or absent canonical name is ignored: ${domain}`, () => {
    const f = fixture(`https://${ADDRESS}.epix/`);
    f.info({ canonical_domain: domain });
    assert.equal(f.navigation.length + f.history.length, 0);
  });
}
