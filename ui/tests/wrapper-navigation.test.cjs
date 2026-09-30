const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const template = fs.readFileSync(path.join(__dirname, "../wrapper.html"), "utf8");
const guard = template.match(/<script[^>]*>\s*(\/\/ If we are inside iframe[\s\S]*?)<\/script>/)[1];

function runGuard({ framed = false, opener = null, url = "http://127.0.0.1:42222/blocktone.epix/" } = {}) {
  const navigation = [];
  const windows = [];
  const writes = [];
  const stops = [];
  const window = {
    opener,
    location: { toString: () => url },
    open: (...args) => windows.push(args),
    stop: () => stops.push("window"),
  };
  window.self = window;
  window.top = framed ? { location: { set href(url) { navigation.push(url); } } } : window;
  const document = {
    write: text => writes.push(text),
    execCommand: command => stops.push(command),
  };
  vm.runInNewContext(guard, { window, document });
  return { navigation, windows, writes, stops };
}

test("a nested wrapper navigates its tab without opening a child window", () => {
  const result = runGuard({ framed: true });
  assert.deepEqual(result.navigation, ["http://127.0.0.1:42222/blocktone.epix/"]);
  assert.deepEqual(result.windows, [], "window.open can set the top window's opener in Gecko");
  assert.deepEqual(result.stops, ["window", "Stop"]);
  assert.deepEqual(result.writes, []);
});

test("escaping a frame removes the wrapper nonce and preserves the xite route", () => {
  const result = runGuard({
    framed: true,
    url: "http://127.0.0.1:42222/blocktone.epix/a%20b/?sort=new&wrapper_nonce=abc123#section",
  });
  assert.deepEqual(result.navigation, ["http://127.0.0.1:42222/blocktone.epix/a%20b/?sort=new#section"]);
});

test("an independent top-level wrapper loads normally", () => {
  assert.deepEqual(runGuard(), { navigation: [], windows: [], writes: [], stops: [] });
});

test("an actual same-origin popup still stops at the opener guard", () => {
  const result = runGuard({ opener: { location: { toString: () => "http://127.0.0.1:42222/source.epix/" } } });
  assert.deepEqual(result.navigation, []);
  assert.deepEqual(result.writes, ["Opened as child-window, stopping..."]);
  assert.deepEqual(result.stops, ["window", "Stop"]);
});
