// Run: node --test ui/tests/wrapper-evx.test.cjs
// The EVX consent prompt (docs/evx-milestone-2.md section 5), exercised on the
// production wrapper methods without its DOM/WebSocket boot. The node's
// commands are stubbed: what matters here is which of them the chrome sends,
// with what, and what the page is told.
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

const DIGEST = "3f2a9c0e1b7d4e6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f";
const ENTRY_HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

// The inert payload `evxInspect` answers with: a usable run-once program, a
// program this node cannot honour, one interval job and a stream it refuses.
function inspectPayload(overrides) {
  return Object.assign({
    xite: "game.epix",
    publisher: "epix1publisherrootaddress",
    declaration_digest: DIGEST,
    integrity: "verified",
    grant: null,
    programs: {
      presence: {
        usable: true,
        entry: { path: "evx/presence.wasm", size: 4096, sha512: ENTRY_HASH },
        dependencies: [{ path: "evx/lib.wasm", size: 1024, sha512: ENTRY_HASH }],
        capabilities: ["workspace.read", "workspace.write"],
        limits: { memory_bytes: 67108864, fuel: 1000000 },
        allow_run_once: true,
        reasons: [],
      },
      stats: { usable: false, reasons: ["capabilities[0]: unknown api chain.read"] },
    },
    jobs: {
      refresh: {
        usable: true,
        program: "presence",
        schedule: { type: "interval", seconds: 1800, anchor: "unix_epoch", missed: "skip" },
        max_concurrency: 1,
        reasons: [],
      },
    },
    unsupported: [{ path: "streams.presence", reason: "retained streams not supported" }],
    effective_limits: { memory_bytes: 33554432, fuel: 1000000 },
  }, overrides || {});
}

function wrapper(windowOverrides, results) {
  const context = vm.createContext({
    window: Object.assign({ is_homepage: false }, windowOverrides || {}),
    $: { when: value => value, extend: Object.assign },
  });
  vm.runInContext(`var Wrapper = function() {}; var indexOf = [].indexOf;
    ${method("setXiteInfo")}
    ${method("handleMessage")}
    ${method("actionEvxRequest")}
    ${method("evxRunnableOnce")}
    ${method("evxGrantOutcome")}
    ${method("evxPromptBody")}
    ${method("toHtmlSafe")}
  `, context);
  const instance = Object.create(context.Wrapper.prototype);
  const dialogs = [];
  const commands = [];
  const replies = [];
  const forwarded = [];
  const logs = [];
  const answers = Object.assign({
    evxInspect: () => inspectPayload(),
    evxGrant: params => ({ granted: true, mode: params.mode, token: params.mode === "once" ? "one-shot-token" : undefined }),
    evxRunOnce: () => ({ ok: true, exit: 0 }),
  }, results || {});
  Object.assign(instance, {
    xite_info: null,
    event_xite_info: deferred(),
    inner_loaded: false,
    loading: { screen_visible: true, noteProgress() {}, printLine() {}, setStage() {} },
    noteContentSync() {},
    displayConfirm() { throw new Error("the EVX prompt is not a plain confirm"); },
    displayChoice(id, body, choices, cb) { dialogs.push({ id, body, choices, cb }); },
    ws: {
      cmd(command, params, callback) {
        commands.push({ command, params });
        const answer = answers[command];
        assert.ok(answer, `unexpected command ${command}`);
        callback(answer(params));
      },
      send(message) { forwarded.push(message); },
      ws: { readyState: 0 },
    },
    sendInner(message) { replies.push(message); },
    log(...args) { logs.push(args.join(" ")); },
  });
  instance.setXiteInfo({
    address: "game.epix", auth_address: "test-identity", peers: 2,
    size_limit: 10, content: {}, settings: { size: 0, own: false, permissions: [] },
  });
  return { instance, dialogs, commands, replies, forwarded, logs };
}

// Objects built inside the vm context have that context's Object.prototype,
// which deepStrictEqual treats as a different type; compare their JSON shape.
function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

function captions(dialog) {
  return plain(dialog.choices).map(choice => choice.caption);
}

test("an evxRequest inspects the xite and shows the dialog built from the digest-bearing payload", () => {
  const { instance, dialogs, commands, replies, forwarded } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 7 });
  assert.deepEqual(plain(commands), [{ command: "evxInspect", params: { xite: "game.epix" } }], "inspect only: nothing grants");
  assert.equal(forwarded.length, 0, "the request itself never reaches the node as a page command");
  assert.equal(replies.length, 0, "the page waits for the user");
  assert.equal(dialogs.length, 1);
  const dialog = dialogs[0];
  assert.deepEqual(captions(dialog), ["Enable EVX for this xite", "Allow once", "Deny"]);
  assert.deepEqual(plain(dialog.choices).map(choice => choice.value), ["enable", "once", "deny"]);
  assert.equal(dialog.id, "evx-7");
  const body = dialog.body;
  assert.match(body, /game\.epix/, "xite");
  assert.match(body, /epix1publisherrootaddress/, "publisher");
  assert.match(body, /Integrity: verified/);
  assert.match(body, new RegExp(DIGEST.slice(0, 16)), "declaration digest prefix");
  assert.match(body, /<b>presence<\/b>/, "the usable program");
  assert.match(body, new RegExp(`evx/presence\\.wasm \\(sha512 ${ENTRY_HASH.slice(0, 16)}`), "entry path with its hash prefix");
  assert.match(body, /evx\/lib\.wasm/, "dependency");
  assert.match(body, /workspace\.read, workspace\.write/, "capabilities");
  assert.match(body, /fuel 1000000, memory_bytes 67108864/, "limits");
  assert.match(body, /run once: allowed/);
  assert.match(body, /<b>stats<\/b> &mdash; unsupported: capabilities\[0\]: unknown api chain\.read/, "unsupported program with its reason");
  assert.match(body, /<b>refresh<\/b> runs presence every 1800 s from unix_epoch, missed: skip, concurrency 1/, "trigger");
  assert.match(body, /streams\.presence: retained streams not supported/, "unsupported item");
  assert.match(body, /Effective limits on this node: fuel 1000000, memory_bytes 33554432/);
  assert.match(body, /Enabling also covers authenticated updates to this xite from the same publisher within these capabilities and limits/);
  assert.match(body, /Allow once runs <b>presence<\/b> one time/);
});

test("deny sends nothing to the node and answers the page granted:false", () => {
  const { instance, dialogs, commands, replies } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 8 });
  dialogs[0].cb("deny");
  assert.deepEqual(commands.map(c => c.command), ["evxInspect"], "no grant command after Deny");
  assert.deepEqual(plain(replies), [{ cmd: "response", to: 8, result: { granted: false } }]);
});

test("dismissing the dialog sends nothing and answers the page granted:false once", () => {
  const { instance, dialogs, commands, replies } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 9 });
  dialogs[0].cb(null);
  dialogs[0].cb("enable");
  assert.deepEqual(commands.map(c => c.command), ["evxInspect"], "a settled dialog cannot grant later");
  assert.deepEqual(plain(replies), [{ cmd: "response", to: 9, result: { granted: false } }]);
});

test("enable sends evxGrant with the inspected digest and mode enable, then answers the page", () => {
  const { instance, dialogs, commands, replies } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 10 });
  dialogs[0].cb("enable");
  assert.deepEqual(plain(commands), [
    { command: "evxInspect", params: { xite: "game.epix" } },
    { command: "evxGrant", params: { xite: "game.epix", declaration_digest: DIGEST, mode: "enable" } },
  ]);
  assert.deepEqual(plain(replies), [{ cmd: "response", to: 10, result: { granted: true, mode: "enable" } }]);
});

test("a refused enable answers the page granted:false with the node's reason", () => {
  const { instance, dialogs, replies } = wrapper({}, {
    evxGrant: () => ({ error: "declaration digest does not match the current declaration" }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 11 });
  dialogs[0].cb("enable");
  assert.deepEqual(plain(replies), [{
    cmd: "response", to: 11,
    result: { granted: false, mode: "enable", error: "declaration digest does not match the current declaration" },
  }]);
});

test("allow once sends evxGrant mode once for the requested program, then evxRunOnce with the token", () => {
  const { instance, dialogs, commands, replies } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 12 });
  dialogs[0].cb("once");
  assert.deepEqual(plain(commands), [
    { command: "evxInspect", params: { xite: "game.epix" } },
    { command: "evxGrant", params: { xite: "game.epix", declaration_digest: DIGEST, mode: "once", program: "presence" } },
    { command: "evxRunOnce", params: { xite: "game.epix", program: "presence", token: "one-shot-token" } },
  ]);
  assert.deepEqual(plain(replies), [{
    cmd: "response", to: 12,
    result: { granted: true, mode: "once", result: { ok: true, exit: 0 } },
  }]);
  assert.equal(JSON.stringify(replies).includes("one-shot-token"), false, "the token stays in the chrome");
});

test("allow once without a token from the node runs nothing", () => {
  const { instance, dialogs, commands, replies } = wrapper({}, {
    evxGrant: params => ({ granted: true, mode: params.mode }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 13 });
  dialogs[0].cb("once");
  assert.deepEqual(commands.map(c => c.command), ["evxInspect", "evxGrant"], "no evxRunOnce without its token");
  assert.equal(replies.length, 1);
  assert.equal(replies[0].result.granted, false);
  assert.match(replies[0].result.error, /token/);
});

test("allow once is not offered when the page names no run-once program", () => {
  const { instance, dialogs } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: {}, id: 14 });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "stats" }, id: 15 });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "constructor" }, id: 16 });
  assert.equal(dialogs.length, 3);
  for (const dialog of dialogs) {
    assert.deepEqual(captions(dialog), ["Enable EVX for this xite", "Deny"]);
  }
  assert.match(dialogs[1].body, /asked to run <b>stats<\/b> once, which this declaration does not allow/);
});

// The node refuses every wrapper-only command from a page id; the chrome also
// never forwards one, so the user's prompt is what a raw call gets.
test("a raw inner evxGrant is routed to the prompt and never forwarded", () => {
  const { instance, dialogs, commands, forwarded } = wrapper();
  instance.handleMessage({ cmd: "evxGrant", params: { xite: "game.epix", declaration_digest: "forged", mode: "enable" }, id: 17 });
  assert.equal(forwarded.length, 0, "the page's evxGrant must not reach the node");
  assert.deepEqual(plain(commands), [{ command: "evxInspect", params: { xite: "game.epix" } }], "inspected, not granted");
  assert.equal(dialogs.length, 1, "the user decides in the chrome");
  dialogs[0].cb("enable");
  assert.equal(commands[1].params.declaration_digest, DIGEST, "the digest comes from the inspection, never from the page");
});

test("a raw inner evxRunOnce is routed to the prompt and evxRevoke or evxSetLimits are dropped", () => {
  const { instance, dialogs, commands, forwarded, replies, logs } = wrapper();
  instance.handleMessage({ cmd: "evxRunOnce", params: { xite: "game.epix", program: "presence", token: "stolen" }, id: 18 });
  assert.equal(dialogs.length, 1);
  assert.deepEqual(captions(dialogs[0]), ["Enable EVX for this xite", "Allow once", "Deny"]);
  instance.handleMessage({ cmd: "evxRevoke", params: { xite: "game.epix" }, id: 19 });
  instance.handleMessage({ cmd: "evxSetLimits", params: { xite: "game.epix", limits: {} }, id: 20 });
  assert.equal(forwarded.length, 0, "nothing wrapper-only is forwarded");
  assert.deepEqual(commands.map(c => c.command), ["evxInspect"]);
  assert.equal(logs.length, 2);
  assert.deepEqual(replies.map(r => r.to), [19, 20]);
  assert.match(replies[0].result.error, /evxRevoke/);
  assert.match(replies[1].result.error, /evxSetLimits/);
});

test("on a public gateway the page is told and no dialog or command follows", () => {
  const { instance, dialogs, commands, replies } = wrapper({ ui_restrict: true });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 21 });
  assert.equal(dialogs.length, 0, "no dead-end dialog");
  assert.equal(commands.length, 0, "not even an inspect");
  assert.deepEqual(plain(replies), [{ cmd: "response", to: 21, result: { error: "EVX cannot be enabled on a public gateway" } }]);
});

test("an inspection without a declaration digest shows no dialog and answers the page with the reason", () => {
  const failing = wrapper({}, { evxInspect: () => ({ error: "no evx section" }) });
  failing.instance.handleMessage({ cmd: "evxRequest", params: {}, id: 22 });
  assert.equal(failing.dialogs.length, 0);
  assert.deepEqual(plain(failing.replies), [{ cmd: "response", to: 22, result: { error: "no evx section" } }]);
  const digestless = wrapper({}, { evxInspect: () => inspectPayload({ declaration_digest: null }) });
  digestless.instance.handleMessage({ cmd: "evxRequest", params: {}, id: 23 });
  assert.equal(digestless.dialogs.length, 0, "nothing can be granted without the expected-version digest");
  assert.equal(digestless.replies.length, 1);
  assert.match(digestless.replies[0].result.error, /digest/);
});

test("every payload string is HTML-escaped before it reaches the dialog", () => {
  const hostile = "<script>alert(1)</script>\"'";
  const { instance, dialogs } = wrapper({}, {
    evxInspect: () => inspectPayload({
      xite: hostile,
      publisher: hostile,
      integrity: hostile,
      programs: {
        [hostile]: {
          usable: true,
          entry: { path: hostile, sha512: hostile },
          dependencies: [hostile],
          capabilities: [hostile],
          limits: { [hostile]: hostile },
          allow_run_once: true,
          reasons: [],
        },
        broken: { usable: false, reasons: [hostile] },
      },
      jobs: {
        [hostile]: { usable: true, program: hostile, schedule: { type: "interval", seconds: hostile, anchor: hostile, missed: hostile }, max_concurrency: hostile, reasons: [] },
        bad: { usable: false, reasons: [hostile] },
      },
      unsupported: [{ path: hostile, reason: hostile }],
      effective_limits: { [hostile]: hostile },
    }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: hostile }, id: 24 });
  const body = dialogs[0].body;
  assert.equal(body.includes("<script"), false);
  assert.equal(body.includes("alert(1)</script>"), false);
  assert.equal(body.includes("\""), false);
  assert.equal(body.includes("'"), false, "attribute-safe too, for the single-quoted markup around it");
  assert.ok((body.match(/&lt;script&gt;alert\(1\)&lt;\/script&gt;&quot;&apos;/g) || []).length >= 15, "each field is shown escaped");
});
