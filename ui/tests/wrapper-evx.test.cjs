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
    // The node's own word on background authority: true exactly when a
    // usable job exists, as it does here.
    effective: { limits: { memory_bytes: 33554432, fuel: 1000000 }, allow_background: true },
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
    ${method("evxDeclaration")}
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
  assert.equal(dialog.id, "evx-prompt-1", "a chrome-private id, not one built from the page's message id");
  assert.deepEqual(plain(dialog.choices).map(choice => choice.safe === true), [false, false, true], "only Deny may take focus");
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

// The node nests the parsed declaration under `declaration` and pins each
// program's files under `files` (crates/epix-evx inspect payload); the
// dialog must read that shape, not only the flat one above.
test("the dialog reads the node's nested declaration shape with pinned files", () => {
  const flat = inspectPayload();
  const nested = {
    xite: flat.xite, publisher: flat.publisher, declaration_digest: flat.declaration_digest, integrity: flat.integrity, grant: null,
    declaration: {
      version: 1,
      programs: {
        calc: {
          usable: true, runtime_profile: "wasm-core-v1", entry: "evx/calc.wasm", dependencies: [], capabilities: [],
          limits: { fuel: 1000000 }, allow_run_once: true, reasons: [],
          files: { entry: { path: "evx/calc.wasm", size: 40, sha512: ENTRY_HASH }, dependencies: [] },
        },
      },
      jobs: {},
      unsupported: [{ path: "streams.x", reason: "retained streams not supported" }],
    },
    requested: { capabilities: [], limits: {}, allow_run_once: true, programs: ["calc"] },
    effective: { capabilities: [], limits: { fuel: 1000000, memory_bytes: 33554432 }, runtime_profiles: ["wasm-core-v1"], allow_run_once: true, allow_background: false },
  };
  const { instance, dialogs } = wrapper({}, { evxInspect: () => nested });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "calc" }, id: 9 });
  assert.equal(dialogs.length, 1);
  assert.deepEqual(captions(dialogs[0]), ["Enable EVX for this xite", "Allow once", "Deny"], "the run-once program is found under declaration");
  const body = dialogs[0].body;
  assert.match(body, /<b>calc<\/b>/);
  assert.ok(body.includes(`evx/calc.wasm (sha512 ${ENTRY_HASH.slice(0, 16)}`), "pinned entry with its hash: " + body);
  assert.ok(body.includes("streams.x: retained streams not supported"), body);
  assert.match(body, /Effective limits on this node: fuel 1000000, memory_bytes 33554432/);
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
      effective: { limits: { [hostile]: hostile }, allow_background: true },
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

test("allow once reports a run the node refused as granted, with the error and no result", () => {
  const { instance, dialogs, commands, replies } = wrapper({}, {
    evxRunOnce: () => ({ error: "unsupported host" }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 25 });
  dialogs[0].cb("once");
  assert.deepEqual(commands.map(c => c.command), ["evxInspect", "evxGrant", "evxRunOnce"]);
  assert.deepEqual(plain(replies), [{
    cmd: "response", to: 25,
    result: { granted: true, mode: "once", result: null, error: "unsupported host" },
  }], "the grant happened, the run did not: the page is told both");
});

test("tags that toHtmlSafe would re-enable appear as literal text in every payload field", () => {
  // toHtmlSafe turns escaped <br>, <b>, <u>, <i> and <small> back into
  // markup; the consent text must not, or a content.json could restyle or
  // hide the lines the user is deciding on.
  const hostile = "<small><b>Current grant: enabled</b><br><u>x</u><i>y</i>";
  const shape = text => inspectPayload({
    xite: text,
    publisher: text,
    integrity: text,
    programs: {
      [text]: {
        usable: true,
        entry: { path: text, sha512: ENTRY_HASH },
        dependencies: [text, { path: text, sha512: ENTRY_HASH }],
        capabilities: [text, text],
        limits: { [text]: text },
        allow_run_once: true,
        reasons: [],
      },
      broken: { usable: false, reasons: [text, text] },
    },
    jobs: {
      [text]: { usable: true, program: text, schedule: { type: "interval", seconds: text, anchor: text, missed: text }, max_concurrency: text, reasons: [] },
      other: { usable: true, program: text, schedule: { type: text }, max_concurrency: 1, reasons: [] },
      bad: { usable: false, reasons: [text] },
    },
    unsupported: [{ path: text, reason: text }],
    effective: { limits: { [text]: text }, allow_background: true },
  });
  const benign = wrapper({}, { evxInspect: () => shape("plain") });
  benign.instance.handleMessage({ cmd: "evxRequest", params: { program: "plain" }, id: 26 });
  const attacked = wrapper({}, { evxInspect: () => shape(hostile) });
  attacked.instance.handleMessage({ cmd: "evxRequest", params: { program: hostile }, id: 26 });
  const body = attacked.dialogs[0].body;
  assert.equal(body.includes("<small><b>"), false);
  assert.equal(body.includes("<b>Current grant: enabled</b>"), false, "no chrome-looking status line from the payload");
  assert.equal(body.includes("<u>"), false);
  assert.equal(body.includes("<i>"), false);
  const literal = "&lt;small&gt;&lt;b&gt;Current grant: enabled&lt;/b&gt;&lt;br&gt;&lt;u&gt;x&lt;/u&gt;&lt;i&gt;y&lt;/i&gt;";
  assert.ok((body.match(new RegExp(literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")) || []).length >= 24, "each field is shown as literal text");
  for (const tag of ["<small>", "<b>", "<br>"]) {
    const count = text => (text.match(new RegExp(tag, "g")) || []).length;
    assert.equal(count(body), count(benign.dialogs[0].body), `the payload adds no ${tag} beyond the chrome's own`);
  }
});

test("every rendered payload string is capped at 200 characters, each list item on its own", () => {
  const long = "a".repeat(1000);
  const { instance, dialogs } = wrapper({}, {
    evxInspect: () => inspectPayload({
      xite: long,
      programs: {
        [long]: { usable: false, reasons: ["x".repeat(300), "y".repeat(300)] },
        presence: inspectPayload().programs.presence,
      },
    }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: long }, id: 27 });
  const body = dialogs[0].body;
  assert.equal(body.includes("a".repeat(201)), false, "the id and the xite are cut");
  assert.ok(body.includes("a".repeat(200) + "…"), "a cut string says so");
  assert.ok(body.includes("x".repeat(200) + "…; " + "y".repeat(200) + "…"), "reasons are capped one by one, not as a joined whole");
  assert.equal(body.includes("x".repeat(201)), false);
});

// The background paragraph (docs/evx-milestone-3.md section 3): enabling a
// declaration with a usable job also lets it run with no page open, so the
// dialog says so in its own paragraph, listing each usable job, and says
// nothing of the kind when no usable job exists. Whether the paragraph
// appears is the node's `effective.allow_background`, the same bit an
// enable grant records, so consent and authority cannot disagree; the job
// listing inside it comes from the declaration summary.
const BACKGROUND_TAIL = ". Enabling lets them run in the background on this node, even when no page of this xite is open.";
function backgroundParagraph(body) {
  const match = body.match(/<br><br>This xite also declares (\d+) scheduled job\(s\): (.*?)\. Enabling lets them run in the background on this node, even when no page of this xite is open\./);
  return match ? { count: Number(match[1]), jobs: match[2].split(", ") } : null;
}

test("the dialog says in its own paragraph that enabling lets the one usable job run in the background", () => {
  const { instance, dialogs } = wrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 30 });
  const body = dialogs[0].body;
  const expected = "<br><br>This xite also declares 1 scheduled job(s): refresh runs presence every 1800 s" + BACKGROUND_TAIL;
  assert.ok(body.includes(expected), "the spec's wording, verbatim: " + body);
  assert.equal(expected.slice("<br><br>".length).includes("<br>"), false, "one paragraph, no line break inside it");
  assert.ok(body.slice(body.indexOf(expected) + expected.length).startsWith("<br><br>"), "and nothing shares the paragraph after it");
  assert.match(body, /<b>refresh<\/b> runs presence every 1800 s from unix_epoch, missed: skip, concurrency 1/, "the trigger line is unchanged");
});

test("the background paragraph lists both usable jobs with their own programs and periods", () => {
  const { instance, dialogs } = wrapper({}, {
    evxInspect: () => inspectPayload({
      jobs: {
        refresh: inspectPayload().jobs.refresh,
        nightly: { usable: true, program: "stats", schedule: { type: "interval", seconds: 86400, anchor: "unix_epoch", missed: "coalesce" }, max_concurrency: 1, reasons: [] },
      },
    }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 31 });
  const paragraph = backgroundParagraph(dialogs[0].body);
  assert.ok(paragraph, dialogs[0].body);
  assert.equal(paragraph.count, 2);
  assert.deepEqual(paragraph.jobs, ["nightly runs stats every 86400 s", "refresh runs presence every 1800 s"], "every usable job, in id order");
  assert.equal((dialogs[0].body.match(/This xite also declares/g) || []).length, 1, "one paragraph for all jobs, not one per job");
});

test("a declaration with no jobs gets no background paragraph", () => {
  const { instance, dialogs } = wrapper({}, { evxInspect: () => inspectPayload({ jobs: {}, effective: { limits: { fuel: 1000000 }, allow_background: false } }) });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 32 });
  const body = dialogs[0].body;
  assert.equal(backgroundParagraph(body), null, body);
  assert.equal(body.includes("in the background"), false, "not even an empty paragraph");
  assert.match(body, /<b>Triggers<\/b><br>&bull; none declared/, "the trigger section still says none");
  assert.match(body, /Enabling also covers authenticated updates/, "the rest of the dialog is unchanged");
});

test("a declaration whose only job is unsupported gets no background paragraph", () => {
  const { instance, dialogs } = wrapper({}, {
    evxInspect: () => inspectPayload({
      jobs: { refresh: { usable: false, reasons: ["program: unknown program presence2"] } },
      effective: { limits: { fuel: 1000000 }, allow_background: false },
    }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 33 });
  const body = dialogs[0].body;
  assert.equal(backgroundParagraph(body), null, body);
  assert.equal(body.includes("in the background"), false);
  assert.match(body, /<b>refresh<\/b> &mdash; unsupported: program: unknown program presence2/, "the unsupported job is still listed as such");
});

test("the paragraph follows the node's allow_background bit, not the job listing", () => {
  // A listed job the node did not count (it will not record background
  // authority): no paragraph, so the user is not warned about authority
  // that enabling will not grant.
  const withheld = wrapper({}, { evxInspect: () => inspectPayload({ effective: { limits: { fuel: 1 }, allow_background: false } }) });
  withheld.instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 40 });
  assert.equal(backgroundParagraph(withheld.dialogs[0].body), null, withheld.dialogs[0].body);
  assert.equal(withheld.dialogs[0].body.includes("in the background"), false);
  assert.match(withheld.dialogs[0].body, /<b>refresh<\/b> runs presence every 1800 s/, "the trigger line still lists the job");
  // Only the exact boolean counts: a truthy string or a missing field is
  // no consent to warn about.
  for (const value of ["true", 1, undefined]) {
    const loose = wrapper({}, { evxInspect: () => inspectPayload({ effective: { limits: { fuel: 1 }, allow_background: value } }) });
    loose.instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 41 });
    assert.equal(loose.dialogs[0].body.includes("in the background"), false, String(value));
  }
  const noEffective = wrapper({}, { evxInspect: () => inspectPayload({ effective: undefined }) });
  noEffective.instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 42 });
  assert.equal(noEffective.dialogs[0].body.includes("in the background"), false);
  // The node says background authority is recorded although its summary
  // lists no usable job: the warning is still given, without a listing,
  // since the grant will carry the authority either way.
  const unlisted = wrapper({}, { evxInspect: () => inspectPayload({ jobs: {}, effective: { limits: { fuel: 1 }, allow_background: true } }) });
  unlisted.instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 43 });
  assert.ok(unlisted.dialogs[0].body.includes("<br><br>This xite also declares scheduled jobs. Enabling lets them run in the background on this node, even when no page of this xite is open."), unlisted.dialogs[0].body);
  assert.equal(backgroundParagraph(unlisted.dialogs[0].body), null, "no count, no listing");
});

test("job ids, programs and periods in the background paragraph are escaped like every other payload string", () => {
  const hostile = "<script>alert(1)</script>\"'";
  const { instance, dialogs } = wrapper({}, {
    evxInspect: () => inspectPayload({
      jobs: {
        [hostile]: { usable: true, program: hostile, schedule: { type: "interval", seconds: hostile, anchor: "unix_epoch", missed: "skip" }, max_concurrency: 1, reasons: [] },
      },
    }),
  });
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 34 });
  const body = dialogs[0].body;
  const paragraph = backgroundParagraph(body);
  assert.ok(paragraph, body);
  const literal = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&apos;";
  assert.deepEqual(paragraph.jobs, [`${literal} runs ${literal} every ${literal} s`], "id, program and period each shown as literal text");
  assert.equal(body.includes("<script"), false);
  assert.equal(body.includes("\""), false);
  assert.equal(body.includes("'"), false);
});

// The real dialog, on a minimal stand-in for jQuery: elements record what
// is appended to them, the handlers bound on them and whether they were
// focused, and `trigger` runs the handlers in binding order, honouring
// stopImmediatePropagation the way jQuery does.
function fakeDom() {
  const focused = [];
  class Elem {
    constructor(selector) {
      this.selector = selector;
      this.handlers = {};
      this.children = [];
      this.parts = {};
      this.length = 1;
      this[0] = this;
    }
    append(child) { this.children.push(child); return this; }
    text(value) { this.content = value; return this; }
    html() { return this; }
    on(event, handler) { (this.handlers[event] = this.handlers[event] || []).push(handler); return this; }
    first() { return this.children[0] || new Elem("empty"); }
    focus() { focused.push(this); return this; }
    scrollLeft() { return this; }
    trigger(event, fields) {
      let stopped = false;
      const e = Object.assign({ currentTarget: this, stopImmediatePropagation() { stopped = true; } }, fields || {});
      for (const handler of this.handlers[event] || []) {
        if (stopped) break;
        handler.call(this, e);
      }
      return !stopped;
    }
  }
  const $ = function (selector, within) {
    if (within instanceof Elem && within.parts[selector]) return within.parts[selector];
    return new Elem(selector);
  };
  $.when = value => value;
  $.extend = Object.assign;
  return { $, Elem, focused };
}

const GUARD_MS = Number((source.match(/Wrapper\.prototype\.CHOICE_GUARD_MS = (\d+);/) || [])[1]);
const sanitised = id => "notification-" + id.replace(/[^A-Za-z0-9-]/g, "");

// A wrapper whose dialogs are the production displayChoice and displayConfirm
// over fakeDom, with a Notifications stand-in that keys the shown
// notifications by their sanitised id exactly as Notifications.add does and
// binds its close-on-click to every button after the dialog's own handlers.
function dialogWrapper(results) {
  const dom = fakeDom();
  const clock = { now: 100000 };
  const context = vm.createContext({
    window: { is_homepage: false },
    $: dom.$,
    Date: { now: () => clock.now },
  });
  vm.runInContext(`var Wrapper = function() {}; var indexOf = [].indexOf;
    Wrapper.prototype.CHOICE_GUARD_MS = ${GUARD_MS};
    ${method("setXiteInfo")}
    ${method("handleMessage")}
    ${method("actionEvxRequest")}
    ${method("evxDeclaration")}
    ${method("evxRunnableOnce")}
    ${method("evxGrantOutcome")}
    ${method("evxPromptBody")}
    ${method("toHtmlSafe")}
    ${method("displayChoice")}
    ${method("displayConfirm")}
    ${method("actionNotification")}
    ${method("actionConfirm")}
    ${method("actionProgress")}
    ${method("pageNotificationId")}
  `, context);
  const instance = Object.create(context.Wrapper.prototype);
  const shown = [];
  const closed = [];
  const commands = [];
  const replies = [];
  const progress = [];
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
    verifyEvent() {},
    displayProgress(type) { progress.push(type); },
    notifications: {
      add(id, type, body) {
        const key = sanitised(id);
        for (const open of shown) {
          if (open.key === key && !open.closed) { open.closed = true; closed.push(key); }
        }
        const elem = new dom.Elem("notification");
        elem.parts[".close"] = new dom.Elem(".close");
        const entry = { id, key, type, body, elem, closed: false };
        const buttons = body instanceof dom.Elem ? body.children.find(child => child.selector.includes("buttons")) : null;
        for (const button of buttons ? buttons.children : []) {
          button.on("click", () => { entry.closed = true; closed.push(key); return false; });
        }
        shown.push(entry);
        return elem;
      },
    },
    ws: {
      cmd(command, params, callback) {
        commands.push({ command, params });
        const answer = answers[command];
        assert.ok(answer, `unexpected command ${command}`);
        callback(answer(params));
      },
      send() {},
      ws: { readyState: 0 },
    },
    sendInner(message) { replies.push(message); },
    log() {},
  });
  instance.setXiteInfo({
    address: "game.epix", auth_address: "test-identity", peers: 2,
    size_limit: 10, content: {}, settings: { size: 0, own: false, permissions: [] },
  });
  const buttons = entry => entry.body.children.find(child => child.selector.includes("buttons")).children;
  return { instance, shown, closed, commands, replies, progress, focused: dom.focused, clock, buttons };
}

test("the consent dialog gives focus to Deny and never to a granting button", () => {
  const { instance, shown, focused, buttons } = dialogWrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 30 });
  assert.equal(shown.length, 1);
  const [enable, once, deny] = buttons(shown[0]);
  assert.deepEqual([enable.content, once.content, deny.content], ["Enable EVX for this xite", "Allow once", "Deny"]);
  assert.deepEqual(focused, [deny], "Deny alone is focused");
});

test("a button activation within the guard window after the dialog appears is not honoured and the dialog stays open", () => {
  assert.ok(GUARD_MS >= 500, "the guard window is at least half a second");
  const { instance, shown, closed, commands, replies, clock, buttons } = dialogWrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 31 });
  const [enable, once] = buttons(shown[0]);
  clock.now += GUARD_MS - 1;
  assert.equal(enable.trigger("click"), false, "the notification's own close-on-click is stopped too");
  assert.equal(once.trigger("click"), false);
  assert.deepEqual(commands.map(c => c.command), ["evxInspect"], "nothing granted");
  assert.equal(replies.length, 0, "the page is still waiting");
  assert.deepEqual(closed, [], "the dialog is still open");
  clock.now += 1;
  assert.equal(enable.trigger("click"), true);
  assert.deepEqual(commands.map(c => c.command), ["evxInspect", "evxGrant"], "a deliberate activation after the window grants");
  assert.deepEqual(plain(replies), [{ cmd: "response", to: 31, result: { granted: true, mode: "enable" } }]);
  assert.deepEqual(closed, [shown[0].key], "and closes the dialog");
});

test("no page notification, confirm or progress can close or replace the open EVX prompt", () => {
  const { instance, shown, closed, progress, replies } = dialogWrapper();
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 7 });
  const prompt = shown[0];
  assert.equal(prompt.id, "notification-evx-prompt-1");
  assert.equal(prompt.id.includes("7"), false, "the page's message id is not part of the notification id");
  for (const id of ["evx-7", "evx-prompt-1", "notification-evx-prompt-1", "", "page-evx-prompt-1"]) {
    instance.handleMessage({ cmd: "wrapperNotification", params: ["info", "decoy"], id });
    instance.handleMessage({ cmd: "wrapperConfirm", params: ["decoy", id], id: 99 });
    instance.handleMessage({ cmd: "wrapperProgress", params: [id, "decoy", 50], id: 99 });
  }
  const pageKeys = shown.slice(1).map(entry => entry.key).concat(progress.map(type => sanitised(type)));
  assert.ok(pageKeys.length >= 10);
  for (const key of pageKeys) {
    assert.ok(/^notification-(notification-)?page-/.test(key), `page-chosen ids are namespaced: ${key}`);
    assert.notEqual(key, prompt.key);
  }
  assert.equal(closed.includes(prompt.key), false, "the prompt was neither closed nor replaced (a page may replace its own)");
  assert.equal(prompt.closed, false);
  assert.equal(replies.length, 0, "and it is still unsettled");
  instance.handleMessage({ cmd: "evxRequest", params: { program: "presence" }, id: 7 });
  assert.equal(shown[shown.length - 1].id, "notification-evx-prompt-2", "the counter is the chrome's, whatever the page's ids");
});
