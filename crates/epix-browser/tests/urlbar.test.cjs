// Run the URL-bar background script the launcher packs into the wallet.
// Run: node --test crates/epix-browser/tests/urlbar.test.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const { pathToFileURL } = require("node:url");

const script = path.join(__dirname, "../assets/epix-urlbar.js");
const validator = path.join(__dirname, "../assets/epix-address.js");
const source = fs.readFileSync(script, "utf8");
const ADDRESS = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
// The script runs in its own realm, so its objects have another Object
// prototype. Copy them into this one before a strict comparison.
const plain = (value) => JSON.parse(JSON.stringify(value));

// One background page: the WebExtension API, the document and its timers.
function page({ readyState = "loading", onStartup = true } = {}) {
  const added = [];
  const startup = [];
  const events = {};
  const timers = [];
  const api = {
    webRequest: { onBeforeRequest: { addListener: (...args) => added.push(args) } },
    runtime: onStartup ? { onStartup: { addListener: (listener) => startup.push(listener) } } : {},
  };
  const context = {
    browser: api,
    URL,
    document: { readyState },
    addEventListener: (type, listener) => (events[type] = listener),
    setTimeout: (run, delay) => timers.push({ run, delay }),
  };
  context.globalThis = context;
  // Named as the real file, so a coverage run attributes the lines to it.
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(validator, "utf8"), context, { filename: pathToFileURL(validator).href });
  vm.runInContext(source, context, { filename: pathToFileURL(script).href });
  return { added, startup, events, timers };
}

test("adds no blocking listener while the background page loads", () => {
  const { added, startup, events, timers } = page();
  assert.equal(added.length, 0);
  assert.equal(startup.length, 1, "waits for Firefox to report the page started");
  assert.equal(typeof events.load, "function", "and for the load event as a fallback");
  assert.equal(timers.length, 0);
});

test("adds the listener when Firefox reports the page started", () => {
  const { added, startup, events, timers } = page();
  startup[0]();
  assert.equal(added.length, 1);
  const [, filter, extra] = added[0];
  assert.deepEqual(plain(filter), { urls: ["*://*/*"], types: ["main_frame"] });
  assert.deepEqual(plain(extra), ["blocking"]);

  // The fallback timer must not add it a second time.
  events.load();
  timers[0].run();
  assert.equal(added.length, 1);
});

test("adds the listener one second after load when no startup event arrives", () => {
  for (const onStartup of [true, false]) {
    const { added, events, timers } = page({ onStartup });
    events.load();
    assert.equal(added.length, 0);
    assert.equal(timers.length, 1);
    assert.equal(timers[0].delay, 1000);
    timers[0].run();
    assert.equal(added.length, 1);
  }
});

test("starts the fallback timer at once on a page that has already loaded", () => {
  const { added, events, timers } = page({ readyState: "complete" });
  assert.equal(events.load, undefined);
  assert.equal(timers.length, 1);
  timers[0].run();
  assert.equal(added.length, 1);
});

test("rewrites only bare address hosts and preserves search requests", () => {
  const { added, startup } = page();
  startup[0]();
  const redirect = added[0][0];
  assert.deepEqual(plain(redirect({ url: `https://${ADDRESS}/topic/1?x=2` })), {
    redirectUrl: `https://${ADDRESS}.epix/topic/1?x=2`,
  });
  assert.equal(redirect({ url: `https://${ADDRESS.toUpperCase()}/` }).redirectUrl, `https://${ADDRESS}.epix/`);
  for (const key of ["q", "query", "p", "text", "wd", "eq", "kw"]) {
    assert.deepEqual(plain(redirect({ url: `https://search.example/?${key}=%20${ADDRESS}%20` })), {});
  }
  for (const url of [
    "https://dashboard.epix/",
    "https://epix1bookclubmembership2026/",
    `https://${ADDRESS.slice(0, -1)}q/`,
    `https://${"epix1" + "i".repeat(38)}/`,
    `https://${ADDRESS}.epix/`,
    "https://search.example/?q=epix",
    `https://search.example/?other=${ADDRESS}`,
    "not a url",
  ]) {
    assert.deepEqual(plain(redirect({ url })), {});
  }
});
