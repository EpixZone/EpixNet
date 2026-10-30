// Run: node --test ui/tests/wrapper-permissions.test.cjs
// Exercise the production wrapper methods without starting its DOM/WebSocket boot.
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

function deferred() {
  let ready = false;
  const callbacks = [];
  return {
    done(callback) {
      if (ready) callback();
      else callbacks.push(callback);
      return this;
    },
    resolve() {
      ready = true;
      callbacks.splice(0).forEach(callback => callback());
      return this;
    },
  };
}

function wrapper(windowOverrides) {
  const context = vm.createContext({
    window: Object.assign({ is_homepage: true }, windowOverrides || {}),
    $: { when: value => value, extend: Object.assign },
  });
  vm.runInContext(`var Wrapper = function() {}; var indexOf = [].indexOf;
    ${method("setXiteInfo")}
    ${method("actionPermissionAdd")}
    ${method("handleMessage")}
  `, context);
  const instance = Object.create(context.Wrapper.prototype);
  const prompts = [];
  const commands = [];
  const replies = [];
  const forwarded = [];
  const logs = [];
  Object.assign(instance, {
    xite_info: null,
    event_xite_info: deferred(),
    inner_loaded: false,
    loading: {
      screen_visible: true,
      noteProgress() {}, printLine() {}, setStage() {},
    },
    noteContentSync() {},
    displayConfirm(message, label, accept) { prompts.push({ message, label, accept }); },
    ws: {
      cmd(command, params, callback) { commands.push({ command, params }); callback("ok"); },
      send(message) { forwarded.push(message); },
      ws: { readyState: 0 },
    },
    sendInner(message) { replies.push(message); },
    log(...args) { logs.push(args.join(" ")); },
  });
  return { instance, prompts, commands, replies, forwarded, logs };
}

function fullInfo(permissions) {
  return {
    address: "dashboard.epix", auth_address: "test-identity", peers: 2,
    size_limit: 10, content: {}, settings: { size: 0, own: false, permissions },
  };
}

// The partial shape emitted by AppState::push_clone_event.
function cloneProgress() {
  return {
    address: "dashboard.epix", peers: 2, size_limit: 10, content: {},
    settings: { size: 0 }, event: ["peers_added", 2],
  };
}

test("clone progress preserves permissions and identity from the full snapshot", () => {
  const { instance, prompts, commands, replies } = wrapper();
  instance.setXiteInfo(fullInfo(["ADMIN"]));
  instance.setXiteInfo(cloneProgress());
  assert.doesNotThrow(() => instance.actionPermissionAdd({ id: 1, params: "ADMIN" }));
  assert.equal(instance.xite_info.auth_address, "test-identity");
  assert.deepEqual(Array.from(instance.xite_info.settings.permissions), ["ADMIN"]);
  assert.equal(prompts.length, 0);
  assert.equal(commands.length, 0);
  assert.equal(replies.length, 0, "already granted permissions retain their existing response behavior");
});

test("a permission request waits for full settings when clone progress arrives first", () => {
  const { instance, prompts, commands, replies } = wrapper();
  instance.setXiteInfo(cloneProgress());
  assert.doesNotThrow(() => instance.actionPermissionAdd({ id: 2, params: "ADMIN" }));
  assert.equal(prompts.length, 0, "progress does not establish permission state");
  assert.equal(commands.length, 0);
  instance.setXiteInfo(fullInfo([]));
  assert.equal(prompts.length, 1);
  assert.equal(commands.length, 0, "permission still requires the user's grant");
  prompts[0].accept();
  assert.deepEqual(commands, [{ command: "permissionAdd", params: "ADMIN" }]);
  assert.equal(replies.length, 1);
  assert.equal(replies[0].to, 2);
  assert.equal(replies[0].result, "ok");
});

test("a later full snapshot can revoke previously granted permissions", () => {
  const { instance, prompts, commands } = wrapper();
  instance.setXiteInfo(fullInfo(["ADMIN"]));
  instance.setXiteInfo(fullInfo([]));
  instance.actionPermissionAdd({ id: 3, params: "ADMIN" });
  assert.equal(prompts.length, 1, "a revoked grant must not survive a new full snapshot");
  assert.equal(commands.length, 0);
});

// The node refuses a page's own permissionAdd; the chrome also never forwards
// it, so an old page that calls the raw command still gets the user's prompt.
test("a raw permissionAdd from the page is routed to the prompt, never forwarded", () => {
  const { instance, prompts, commands, forwarded } = wrapper();
  instance.setXiteInfo(fullInfo([]));
  instance.handleMessage({ cmd: "permissionAdd", params: ["ADMIN"], id: 4 });
  assert.equal(forwarded.length, 0, "the page's permissionAdd must not reach the node");
  assert.equal(prompts.length, 1, "the user decides in the chrome");
  assert.equal(commands.length, 0);
  prompts[0].accept();
  assert.deepEqual(commands, [{ command: "permissionAdd", params: "ADMIN" }]);
});

test("a page cannot answer the node's dialogs or claim an elevated id", () => {
  const { instance, forwarded, logs } = wrapper();
  instance.handleMessage({ cmd: "response", to: 12, result: true, id: 5 });
  instance.handleMessage({ cmd: "siteList", params: [], id: 1000000 });
  instance.handleMessage({ cmd: "siteList", params: [], id: 1000001 });
  assert.equal(forwarded.length, 0);
  assert.equal(logs.length, 3);
  // An ordinary page command with its own small id is still forwarded.
  instance.handleMessage({ cmd: "siteInfo", params: [], id: 6 });
  assert.deepEqual(forwarded, [{ cmd: "siteInfo", params: [], id: 6 }]);
});

// A public gateway grants nothing to any visitor (the node refuses every
// grant that is not the operator's), so the chrome answers the page instead
// of opening a dialog whose Allow could only fail - on every load, for
// everyone, as the dashboard's unconditional ADMIN request would otherwise do.
test("on a public gateway the permission prompt is skipped and the page is told", () => {
  const { instance, prompts, commands, replies } = wrapper({ ui_restrict: true });
  instance.setXiteInfo(fullInfo([]));
  instance.actionPermissionAdd({ id: 5, params: "ADMIN" });
  assert.equal(prompts.length, 0, "no dead-end dialog");
  assert.equal(commands.length, 0, "nothing is sent to the node");
  assert.equal(replies.length, 1);
  assert.equal(replies[0].to, 5);
  assert.match(replies[0].result.error, /gateway/);
});

test("a grant the operator already made on a gateway keeps the silent contract", () => {
  const { instance, prompts, commands, replies } = wrapper({ ui_restrict: true });
  instance.setXiteInfo(fullInfo(["ADMIN"]));
  instance.actionPermissionAdd({ id: 6, params: "ADMIN" });
  assert.equal(prompts.length, 0);
  assert.equal(commands.length, 0);
  assert.equal(replies.length, 0, "already granted: no answer, as on a normal node");
});
