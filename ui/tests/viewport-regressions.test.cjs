// Run: node --test ui/tests/viewport-regressions.test.cjs
// Exercise production wrapper methods with delayed WebSocket metadata.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const source = fs.readFileSync(path.join(__dirname, "../media/all.js"), "utf8");
const ADDRESS = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
const OTHER = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
const DEFAULT = "width=device-width, initial-scale=1";
const MANIFEST = "width=device-width, initial-scale=0.5, minimum-scale=0.5, maximum-scale=2, user-scalable=yes";
const CHANGED = "width=device-width, initial-scale=0.75, user-scalable=no";

function method(name) {
  const start = source.indexOf(`Wrapper.prototype.${name} = function`);
  assert.ok(start >= 0, `missing production method ${name}`);
  const end = source.indexOf("\n    };", start);
  assert.ok(end > start, `missing method end for ${name}`);
  return source.slice(start, end + "\n    };".length);
}

function fixture(renderedViewport) {
  const tags = [{ name: "viewport", content: DEFAULT }];
  if (renderedViewport !== undefined) {
    tags.push({ name: "viewport", id: "viewport", content: renderedViewport });
  }
  const writes = [];
  let appends = 0;
  function selection(nodes) {
    return {
      length: nodes.length,
      attr(name, value) {
        if (value === undefined) return nodes[0]?.[name];
        for (const node of nodes) {
          if (value === null) delete node[name];
          else node[name] = String(value);
          if (name === "content") writes.push(node[name]);
        }
        return this;
      },
      appendTo(target) {
        assert.equal(target, "head");
        for (const node of nodes) {
          if (!tags.includes(node)) { tags.push(node); appends++; }
        }
        return this;
      },
    };
  }
  function $(selector) {
    if (selector === "#viewport") return selection(tags.filter(tag => tag.id === "viewport"));
    if (/^<meta\b/.test(selector)) {
      assert.match(selector, /name=["']viewport["']/);
      assert.match(selector, /id=["']viewport["']/);
      return selection([{ name: "viewport", id: "viewport" }]);
    }
    throw new Error(`unexpected DOM selector: ${selector}`);
  }
  $.extend = Object.assign;
  const context = vm.createContext({
    window: { address: ADDRESS, file_inner_path: "index.html", show_loadingscreen: true },
    $, console,
  });
  vm.runInContext("var Wrapper = function() {}; var indexOf = [].indexOf;\n" +
    ["setXiteInfo", "handleMessageWebsocket", "actionSetViewport", "toHtmlSafe", "setViewport"]
      .map(name => method(name)).join("\n"), context);
  const wrapper = Object.assign(Object.create(context.Wrapper.prototype), {
    address: null, xite_info: null, inner_loaded: false,
    event_xite_info: { resolve() {} },
    loading: { screen_visible: true, printLine() {}, noteProgress() {}, setStage() {} },
    noteContentSync() {}, log() {}, sendInner() {}, updateProgress() {},
  });
  context.wrapper = wrapper;
  function publish(delta = {}) {
    wrapper.handleMessageWebsocket({ cmd: "setSiteInfo", params: {
      address: ADDRESS, peers: 0, size_limit: 10, content: {},
      settings: { size: 0, own: false, permissions: ["ADMIN"] }, ...delta,
    } });
  }
  function override(params) {
    // Browser messages are parsed in the wrapper's realm. Keep arrays in that
    // realm too, since the existing toHtmlSafe implementation uses instanceof.
    context.message = JSON.stringify({ params });
    vm.runInContext("wrapper.actionSetViewport(JSON.parse(message))", context);
  }
  return {
    wrapper, publish, override, writes, tags, appends: () => appends,
    viewport: () => tags.find(tag => tag.id === "viewport")?.content,
  };
}

test("a manifest arriving after network discovery applies its viewport", () => {
  const f = fixture();
  f.publish();
  assert.equal(f.viewport(), undefined);
  assert.equal(f.tags[0].content, DEFAULT);
  f.publish({ content: { viewport: MANIFEST }, settings: { size: 128 }, event: ["file_done", "content.json"] });
  assert.equal(f.viewport(), MANIFEST);
  assert.deepEqual(f.writes, [MANIFEST]);
  assert.equal(f.appends(), 1);
  assert.deepEqual(Array.from(f.wrapper.xite_info.settings.permissions), ["ADMIN"]);
});

test("partial clone events preserve the viewport and full snapshot fields", () => {
  const f = fixture();
  f.publish({ content: { title: "Original title", viewport: MANIFEST } });
  f.publish({ content: { title: "Updated title" }, settings: { size: 128 }, event: ["peers_added", 1] });
  f.publish({ content: {}, settings: { size: 256 }, event: ["peers_added", 2] });
  assert.equal(f.viewport(), MANIFEST);
  assert.deepEqual(f.writes, [MANIFEST]);
  assert.equal(f.wrapper.xite_info.content.viewport, MANIFEST);
  assert.equal(f.wrapper.xite_info.content.title, "Updated title");
  assert.deepEqual(Array.from(f.wrapper.xite_info.settings.permissions), ["ADMIN"]);
});

test("unchanged viewport metadata does not rewrite the DOM or duplicate its tag", () => {
  const f = fixture(MANIFEST);
  f.publish({ content: { viewport: MANIFEST } });
  f.publish({ content: { viewport: MANIFEST }, settings: { size: 128 }, event: ["peers_added", 1] });
  assert.deepEqual(f.writes, [], "reapplying the same viewport can reset pinch zoom");
  f.publish({ content: { viewport: CHANGED } });
  f.publish({ content: { viewport: CHANGED } });
  assert.equal(f.viewport(), CHANGED);
  assert.deepEqual(f.writes, [CHANGED]);
  assert.equal(f.appends(), 0);
  assert.equal(f.tags.filter(tag => tag.id === "viewport").length, 1);
});

test("an explicit viewport set before metadata keeps string and array API forms", () => {
  for (const params of [CHANGED, [CHANGED], [""]]) {
    const f = fixture();
    const expected = String(params);
    f.override(params);
    assert.equal(f.viewport(), expected);
    f.publish({ content: { viewport: MANIFEST }, event: ["file_done", "content.json"] });
    assert.equal(f.viewport(), expected);
    assert.deepEqual(f.writes, [expected]);
  }
});

test("an explicit viewport set after metadata wins over later snapshots", () => {
  for (const params of [CHANGED, [CHANGED], [""]]) {
    const f = fixture(MANIFEST);
    const expected = String(params);
    f.publish({ content: { viewport: MANIFEST } });
    f.override(params);
    f.publish({ content: { viewport: MANIFEST } });
    f.publish({ content: {}, settings: { size: 128 }, event: ["peers_added", 1] });
    assert.equal(f.viewport(), expected);
    assert.deepEqual(f.writes, [expected]);
  }
});

test("explicitly selecting the current viewport still overrides later metadata", () => {
  const f = fixture(MANIFEST);
  f.publish({ content: { viewport: MANIFEST } });
  f.override([MANIFEST]);
  f.publish({ content: { viewport: CHANGED } });
  assert.equal(f.viewport(), MANIFEST);
  assert.deepEqual(f.writes, [], "an unchanged explicit value needs no DOM rewrite");
});

test("events for another xite cannot replace the active viewport or snapshot", () => {
  const f = fixture(MANIFEST);
  f.publish({ content: { viewport: MANIFEST } });
  const current = f.wrapper.xite_info;
  f.publish({ address: OTHER, content: { viewport: CHANGED }, event: ["file_done", "content.json"] });
  assert.equal(f.viewport(), MANIFEST);
  assert.equal(f.wrapper.xite_info, current);
  assert.deepEqual(f.writes, []);
});

test("the bound xite address takes precedence over the initial window address", () => {
  const f = fixture(MANIFEST);
  f.publish({ content: { viewport: MANIFEST } });
  f.wrapper.address = OTHER;
  const current = f.wrapper.xite_info;
  f.publish({ content: { viewport: CHANGED }, event: ["file_done", "content.json"] });
  assert.equal(f.viewport(), MANIFEST, "events for the old window address are stale");
  assert.equal(f.wrapper.xite_info, current);
  assert.deepEqual(f.writes, []);
  f.publish({ address: OTHER, content: { viewport: CHANGED }, event: ["file_done", "content.json"] });
  assert.equal(f.viewport(), CHANGED);
  assert.deepEqual(f.writes, [CHANGED]);
});

test("a direct snapshot for another xite cannot apply its viewport", () => {
  const f = fixture(MANIFEST);
  f.publish({ content: { viewport: MANIFEST } });
  f.wrapper.setXiteInfo({
    address: OTHER, peers: 0, size_limit: 10, content: { viewport: CHANGED },
    settings: { size: 0, own: false, permissions: [] },
  });
  assert.equal(f.viewport(), MANIFEST);
  assert.deepEqual(f.writes, []);
});

test("blank and non-string hints leave the default or current viewport intact", () => {
  for (const initial of [undefined, MANIFEST]) {
    const f = fixture(initial);
    f.publish();
    for (const viewport of ["", " \t ", null, 1, {}, [CHANGED]]) {
      f.publish({ content: { viewport } });
      assert.equal(f.viewport(), initial);
    }
    assert.equal(f.tags[0].content, DEFAULT);
    assert.deepEqual(f.writes, []);
    assert.equal(f.appends(), 0);
  }
});

test("manifest viewport strings retain their exact directives and characters", () => {
  const f = fixture();
  const viewport = '  width=device-width, initial-scale=0.5, minimum-scale=0.25, maximum-scale=3, user-scalable=no, x-note="a&b"  ';
  f.publish({ content: { viewport } });
  assert.equal(f.viewport(), viewport);
  assert.deepEqual(f.writes, [viewport]);
});
