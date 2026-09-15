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

function wrapper() {
  const context = vm.createContext({
    window: { is_homepage: true },
    $: { when: value => value, extend: Object.assign },
  });
  vm.runInContext(`var Wrapper = function() {}; var indexOf = [].indexOf;
    ${method("setXiteInfo")}
    ${method("actionPermissionAdd")}
  `, context);
  const instance = Object.create(context.Wrapper.prototype);
  const prompts = [];
  const commands = [];
  const replies = [];
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
    ws: { cmd(command, params, callback) { commands.push({ command, params }); callback("ok"); } },
    sendInner(message) { replies.push(message); },
  });
  return { instance, prompts, commands, replies };
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
