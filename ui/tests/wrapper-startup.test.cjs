// Run: node --test ui/tests/wrapper-startup.test.cjs
// Exercise the production Wrapper without its automatic DOM/WebSocket startup.
// The inner frame is an opaque origin (docs/wrapper-sandbox.md): the chrome
// cannot read its document, so every fixture frame refuses that access. What
// the chrome sees is the frame's load event and the documents' own messages.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

const source = fs.readFileSync(path.join(__dirname, "../media/all.js"), "utf8");
const start = source.indexOf("  Wrapper = (function () {");
const end = source.indexOf("\n  origin = ", start);
assert.ok(start >= 0 && end > start, "production Wrapper class must be available");
const wrapperClass = source.slice(start, end);
const transportStart = source.indexOf("/* ---- lib/EpixWebsocket.coffee ---- */");
const transportEnd = source.indexOf("/* ---- lib/jquery.cssanim.js ---- */", transportStart);
assert.ok(transportStart >= 0 && transportEnd > transportStart, "production WebSocket transport must be available");
const transportClass = source.slice(transportStart, transportEnd);

function fixture(options = {}) {
  const initialSrc = options.src || "https://current.epix/index.html?wrapper_nonce=oldNonce";
  let frame;
  let onPost = null;
  const messages = [], writes = [], requests = [], timers = [];
  const window = {
    wrapper_nonce: "oldNonce",
    postmessage_nonce_security: true,
    resolving_host: "",
    show_loadingscreen: false,
    location: new URL("https://current.epix/"),
    document: { title: "Fixture" },
  };
  const inner = {
    get document() { throw new Error("Cross-origin document"); },
    postMessage(message) {
      messages.push(message);
      if (onPost) onPost(message);
    },
  };
  function makeFrame(src) {
    let currentSrc = src;
    return {
      contentWindow: inner,
      get contentDocument() { throw new Error("Cross-origin document"); },
      get src() { return currentSrc; },
      set src(value) {
        writes.push({ frame: this, src: value, expectedNonce: window.wrapper_nonce });
        currentSrc = value;
      },
      getAttribute(name) { return name === "src" ? currentSrc : null; },
      setAttribute(name, value) { if (name === "src") this.src = value; },
    };
  }
  frame = makeFrame(initialSrc);
  const decoy = options.decoy ? makeFrame("https://current.epix/other.html?wrapper_nonce=otherNonce") : null;
  function $(selector) {
    const element = selector === "iframe" ? (decoy || frame) : frame;
    return {
      0: element, length: element ? 1 : 0,
      attr(name, value) {
        if (value === undefined) return element?.getAttribute(name);
        element?.setAttribute(name, value);
        return this;
      },
    };
  }
  const context = vm.createContext({
    window, document: { getElementById: id => id === "inner-iframe" ? frame : null },
    $, URL, console,
    setTimeout(fn) { timers.push(fn); return timers.length; },
    clearTimeout() {}, setInterval() { return 1; }, clearInterval() {},
  });
  vm.runInContext(`${transportClass}
    var Wrapper, indexOf = [].indexOf, slice = [].slice;
    var bind = function(fn, self) { return function() { return fn.apply(self, arguments); }; };
    ${wrapperClass}`, context);
  const transport = new window.EpixWebsocket("ws://current.epix/Websocket");
  Object.assign(transport, {
    connected: options.connected !== false,
    next_message_id: 1000000,
    message_queue: [],
    log() {},
    ws: {
      readyState: options.connected === false ? 0 : 1,
      send(payload) {
        const message = JSON.parse(payload);
        requests.push({ command: message.cmd, params: message.params, id: message.id });
      },
    },
  });
  const wrapper = Object.assign(Object.create(context.Wrapper.prototype), {
    inner, inner_ready: false, inner_loaded: false, wrapperWsInited: false,
    inner_generation: 0, inner_load_state: null, inner_probe_id: 0, inner_probe_counter: 0,
    opener_tested: false, iframe_reload_request: null, iframe_recovery_pending: false,
    ws_lost_timer: null, ws_error: null,
    xite_info: { content: { title: "Fixture" }, settings: { size: 1 }, size_limit: 1, clone_status: { state: "complete", attempt: 1 } },
    loading: { screen_visible: false, hideScreen() {} },
    notifications: { add() {} },
    log() {}, reloadXiteInfo() {}, pollNotificationCount() {},
    ws: transport,
  });
  transport.onOpen = event => wrapper.onOpenWebsocket(event);
  transport.onClose = event => wrapper.onCloseWebsocket(event);
  return {
    wrapper, window, inner, messages, writes, requests, decoy,
    get frame() { return frame; },
    opens: () => messages.filter(message => message.cmd === "wrapperOpenedWebsocket").length,
    asks: () => messages.filter(message => message.cmd === "ping").length,
    ready(nonce = window.wrapper_nonce, sender = inner) {
      return wrapper.onMessageInner({ source: sender, data: { cmd: "innerReady", id: 1, wrapper_nonce: nonce } });
    },
    // The frame library's answer to the chrome's probe, for the given ping
    // (the latest by default).
    pong(index = -1, nonce = window.wrapper_nonce, sender = inner) {
      const pings = messages.filter(message => message.cmd === "ping");
      const ping = pings.at(index);
      assert.ok(ping, "a probe must have been sent");
      return wrapper.onMessageInner({ source: sender, data: { cmd: "response", to: ping.id, result: "pong", wrapper_nonce: nonce } });
    },
    // The inner frame's own load event: once per document it shows.
    load() { wrapper.onPageLoad({ target: frame }); },
    // The wrapper window's load event, which says nothing about the frame.
    outerLoad() { wrapper.onPageLoad({ target: window.document }); },
    open() { transport.ws.readyState = 1; transport.onOpenWebsocket({}); },
    close() { transport.ws.readyState = 3; transport.onCloseWebsocket({}); },
    replaceFrame() { frame = makeFrame(initialSrc); },
    onPost(callback) { onPost = callback; },
    nonceReply(index, result) {
      const nonceRequests = requests.filter(request => request.command === "serverGetWrapperNonce");
      assert.ok(nonceRequests[index], "nonce request must have been sent");
      wrapper.onMessageWebsocket({ data: JSON.stringify({ cmd: "response", to: nonceRequests[index].id, result }) });
    },
  };
}

test("initial ready/socket/load order announces exactly once", () => {
  for (const order of [["ready", "load", "open"], ["load", "open", "ready"], ["open", "ready", "load"], ["load", "ready", "open"]]) {
    const f = fixture({ connected: false });
    for (const event of order) f[event]();
    f.outerLoad();
    assert.equal(f.opens(), 1, order.join(" -> "));
    assert.equal(f.wrapper.inner_ready, true, order.join(" -> "));
  }
});

test("the chrome never reads the inner document", () => {
  const f = fixture();
  assert.doesNotThrow(() => {
    f.load(); f.ready(); f.close(); f.open(); f.ready(); f.load();
    f.wrapper.reloadIframe(); f.nonceReply(0, "nextNonce"); f.ready(); f.load();
  });
  assert.equal(f.opens(), 4);
});

test("a document that introduces itself again is its replacement", () => {
  // An in-frame reload keeps the frame's WindowProxy and URL; the frame
  // library introduces each document once, so a second innerReady is the
  // next document, announced to at once and not probed at its load.
  const f = fixture(); f.ready(); f.load();
  f.ready();
  assert.equal(f.opens(), 2);
  f.load();
  assert.equal(f.opens(), 2);
  assert.equal(f.asks(), 0);
  assert.equal(f.wrapper.inner_generation, 1);
});

test("a reload before the old document's load event still gets its announcement", () => {
  // A missing subresource holds a load event back for minutes; the user
  // reloads meanwhile. The new document's word is enough.
  const f = fixture(); f.ready();
  f.ready();
  assert.equal(f.opens(), 2);
  f.load();
  assert.equal(f.opens(), 2);
  assert.equal(f.wrapper.inner_generation, 1);
});

test("a load without a new document changes nothing", () => {
  // Chromium fires the frame's load event for the chrome's own fragment-only
  // src writes on a frame of another origin.
  const f = fixture(); f.ready(); f.load();
  f.load(); f.load();
  assert.equal(f.opens(), 1);
  assert.equal(f.asks(), 0);
  assert.equal(f.wrapper.inner_generation, 0);
  assert.equal(f.wrapper.inner_ready, true);
});

test("the first document is probed at load until it answers", () => {
  // It can speak before the chrome listens; later documents cannot.
  const f = fixture(); f.load();
  assert.equal(f.asks(), 1);
  assert.equal(f.messages.at(-1).cmd, "ping");
  f.load();
  assert.equal(f.asks(), 2);
  f.ready(); f.outerLoad(); f.load();
  assert.equal(f.asks(), 2);
  assert.equal(f.opens(), 1);
});

test("a probe answered with pong readies the document without starting another", () => {
  const f = fixture(); f.load();
  f.pong();
  assert.equal(f.opens(), 1);
  assert.equal(f.wrapper.inner_ready, true);
  assert.equal(f.wrapper.inner_generation, 0);
  f.pong();
  assert.equal(f.opens(), 1, "a probe is answered once");
});

test("a first document whose library starts at load is announced to once when its load arrives first", () => {
  // Chromium can deliver the frame's load event before the innerReady the
  // page posted from its own load handler: the chrome probes, then the page
  // introduces itself and also answers the probe.
  const f = fixture(); f.load();
  f.ready();
  assert.equal(f.opens(), 1);
  f.pong();
  assert.equal(f.opens(), 1, "the probe reply is not a new document");
  assert.equal(f.wrapper.inner_generation, 0);
});

test("a later document whose library starts at load is announced to once", () => {
  const f = fixture(); f.ready(); f.load();
  f.load();
  assert.equal(f.asks(), 0, "later documents are never probed");
  f.ready();
  assert.equal(f.opens(), 2);
  assert.equal(f.wrapper.inner_generation, 1);
});

test("a pong for an earlier probe, a wrong nonce or another window is ignored", () => {
  const f = fixture(); f.load(); f.load();
  assert.equal(f.asks(), 2);
  f.pong(0);
  assert.equal(f.wrapper.inner_ready, false, "only the latest probe is answered");
  f.pong(-1, "wrong");
  assert.equal(f.wrapper.inner_ready, false);
  f.pong(-1, undefined, {});
  assert.equal(f.wrapper.inner_ready, false);
  f.pong();
  assert.equal(f.wrapper.inner_ready, true);
  assert.equal(f.opens(), 1);
});

test("a page's other responses are ignored", () => {
  const f = fixture(); f.load();
  f.wrapper.onMessageInner({ source: f.inner, data: { cmd: "response", to: 12, result: "pong", wrapper_nonce: "oldNonce" } });
  f.wrapper.onMessageInner({ source: f.inner, data: { cmd: "response", to: f.messages.at(-1).id, result: true, wrapper_nonce: "oldNonce" } });
  assert.equal(f.wrapper.inner_ready, false);
  assert.equal(f.opens(), 0);
});

test("the outer window load retains readiness", () => {
  const f = fixture(); f.ready(); f.load();
  f.outerLoad(); f.outerLoad();
  assert.equal(f.opens(), 1);
  assert.equal(f.asks(), 0);
  assert.equal(f.wrapper.inner_ready, true);
});

test("reconnect announces once to a ready document", () => {
  const f = fixture(); f.ready(); f.load(); f.close(); f.open();
  assert.equal(f.opens(), 2);
  f.close(); f.open();
  assert.equal(f.opens(), 3);
});

test("a replacement that spoke while offline is announced to on reconnect", () => {
  const f = fixture(); f.ready(); f.load(); f.close();
  f.ready();
  assert.equal(f.opens(), 1);
  f.open();
  assert.equal(f.opens(), 2);
  f.load();
  assert.equal(f.opens(), 2);
});

test("a silent replacement is invisible until a document speaks", () => {
  // A page without a frame library cannot be told from the document before
  // it; the reconnect announcement it inherits is addressed to nobody, and
  // the next document that has a library introduces itself.
  const f = fixture(); f.ready(); f.load(); f.close();
  f.load(); f.open();
  assert.equal(f.opens(), 2);
  f.ready();
  assert.equal(f.opens(), 3);
  assert.equal(f.wrapper.inner_generation, 1);
});

test("invalid nonce and unrelated-source ready cannot establish readiness", () => {
  for (const [nonce, sender] of [["wrong", null], [undefined, null], ["oldNonce", {}]]) {
    const f = fixture();
    f.wrapper.onMessageInner({ source: sender || f.inner, data: { cmd: "innerReady", wrapper_nonce: nonce } });
    assert.equal(f.wrapper.inner_ready, false);
    assert.equal(f.opens(), 0);
  }
});

test("a document that introduces itself clears the placeholder state", () => {
  const f = fixture();
  f.wrapper.inner_load_state = "waiting";
  f.ready();
  assert.equal(f.wrapper.inner_load_state, null);
});

test("announcement is marked before posting to prevent reentrant duplicates", () => {
  // A page may react to the announcement at once; whatever that triggers in
  // the chrome (another announce attempt, a probe reply) must not announce
  // the same document twice.
  for (const react of [f => f.wrapper.announceWebsocket(), f => f.pong()]) {
    const f = fixture(); f.load();
    f.onPost(message => {
      if (message.cmd === "wrapperOpenedWebsocket" && f.opens() === 1) react(f);
    });
    f.ready();
    assert.equal(f.opens(), 1);
  }
});

test("the waiting placeholder keeps its state across its own refreshes and loads", () => {
  // The node's placeholder announces itself during parse and loads right
  // after; every 30 s it refreshes into another placeholder until the
  // clone completes. Its state must survive all of that.
  const f = fixture();
  f.wrapper.xite_info.clone_status = { state: "downloading", attempt: 1 };
  f.wrapper.setInnerLoadState("waiting"); f.load();
  assert.equal(f.wrapper.inner_load_state, "waiting");
  assert.equal(f.wrapper.inner_loaded, false);
  f.wrapper.setInnerLoadState("waiting"); f.load();
  assert.equal(f.wrapper.inner_load_state, "waiting");
  assert.equal(f.requests.filter(r => r.command === "serverGetWrapperNonce").length, 0);
  assert.equal(f.opens(), 0);
});

test("placeholder, recovery reload and real document handshake end to end", () => {
  const f = fixture();
  f.wrapper.xite_info.clone_status = { state: "complete", attempt: 2 };
  // The placeholder announces itself after the clone completed: one reload.
  f.wrapper.setInnerLoadState("waiting");
  assert.equal(f.wrapper.iframe_recovery_pending, true);
  assert.equal(f.requests.filter(r => r.command === "serverGetWrapperNonce").length, 1);
  f.load();
  assert.equal(f.wrapper.inner_loaded, false, "the placeholder is not the xite");
  assert.equal(f.wrapper.iframe_reload_request !== null, true, "the placeholder's own load keeps the reload");
  f.wrapper.setInnerLoadState("waiting");
  assert.equal(f.requests.filter(r => r.command === "serverGetWrapperNonce").length, 2, "retried once the guard dropped");
  f.nonceReply(1, { wrapper_nonce: "freshNonce" });
  assert.equal(f.writes.length, 1);
  assert.equal(f.wrapper.inner_load_state, null);
  assert.equal(f.wrapper.inner_ready, false);
  f.ready(); f.load();
  assert.equal(f.opens(), 1);
  assert.equal(f.wrapper.inner_loaded, true);
  assert.equal(f.wrapper.iframe_recovery_pending, false);
  f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, 1, "the superseded reply is dead");
});

test("a real document arriving on its own releases the reload made for the placeholder", () => {
  const f = fixture();
  f.wrapper.setInnerLoadState("waiting");
  const nonceId = f.requests.find(r => r.command === "serverGetWrapperNonce").id;
  f.ready();
  assert.equal(Object.hasOwn(f.wrapper.ws.waiting_cb, nonceId), false);
  assert.equal(f.wrapper.iframe_recovery_pending, false);
  f.nonceReply(0, "lateNonce");
  assert.equal(f.writes.length, 0);
  assert.equal(f.opens(), 1);
});

test("nonce recovery accepts object and legacy string replies and updates expected nonce first", () => {
  for (const reply of [{ wrapper_nonce: "nextNonce" }, "nextNonce"]) {
    const f = fixture();
    f.wrapper.reloadIframe(); f.nonceReply(0, reply);
    assert.equal(f.frame.src, "https://current.epix/index.html?wrapper_nonce=nextNonce");
    assert.equal(f.window.wrapper_nonce, "nextNonce");
    assert.equal(f.writes.length, 1);
    assert.equal(f.writes[0].expectedNonce, "nextNonce", "strict validation changes before navigation");
  }
});

test("nonce recovery preserves route query bytes and fragment", () => {
  const f = fixture({ src: "https://current.epix/index.html?route=%2fA%2BB&wrapper_nonce=oldNonce&empty=&flag#view?wrapper_nonce=fragment" });
  f.wrapper.reloadIframe(); f.nonceReply(0, { wrapper_nonce: "nextNonce" });
  assert.equal(f.frame.src, "https://current.epix/index.html?route=%2fA%2BB&wrapper_nonce=nextNonce&empty=&flag#view?wrapper_nonce=fragment");
});

test("nonce recovery adds a missing query parameter before the fragment", () => {
  const f = fixture({ src: "https://current.epix/index.html?route=%2fA%2BB#view" });
  f.wrapper.reloadIframe(); f.nonceReply(0, { wrapper_nonce: "nextNonce" });
  assert.equal(f.frame.src, "https://current.epix/index.html?route=%2fA%2BB&wrapper_nonce=nextNonce#view");
});

test("nonce recovery targets the inner frame when another iframe exists", () => {
  const f = fixture({ decoy: true });
  const otherSrc = f.decoy.src;
  f.wrapper.reloadIframe(); f.nonceReply(0, "nextNonce");
  assert.equal(f.decoy.src, otherSrc);
  assert.equal(f.frame.src, "https://current.epix/index.html?wrapper_nonce=nextNonce");
});

test("invalid nonce responses leave navigation intact and allow recovery retry", () => {
  for (const response of [null, {}, { error: "offline" }, { error: "offline", wrapper_nonce: "invalidNonce" }, { wrapper_nonce: "" }, "", true, "bad&token", "bad\n", { wrapper_nonce: 42 }]) {
    const f = fixture();
    const oldSrc = f.frame.src;
    f.wrapper.iframe_recovery_pending = true;
    f.wrapper.reloadIframe(); f.nonceReply(0, response);
    assert.equal(f.frame.src, oldSrc, JSON.stringify(response));
    assert.equal(f.window.wrapper_nonce, "oldNonce");
    assert.equal(f.wrapper.iframe_recovery_pending, false);
    assert.equal(f.writes.length, 0);
  }
});

test("a superseded nonce response cannot undo a newer recovery", () => {
  const f = fixture();
  f.wrapper.reloadIframe(); f.wrapper.reloadIframe();
  f.nonceReply(1, "newestNonce"); f.nonceReply(0, "staleNonce");
  assert.equal(f.frame.src, "https://current.epix/index.html?wrapper_nonce=newestNonce");
  assert.equal(f.window.wrapper_nonce, "newestNonce");
  assert.equal(f.writes.length, 1);
});

test("a replacement document while awaiting a nonce cannot be reverted by the late reply", () => {
  // Seen as a new document introducing itself, or as a load while no
  // placeholder stands.
  for (const replace of [f => f.ready(), f => f.load()]) {
    const f = fixture(); f.ready(); f.load();
    f.wrapper.iframe_recovery_pending = true;
    f.wrapper.reloadIframe();
    replace(f);
    f.nonceReply(0, "staleNonce");
    assert.equal(f.writes.length, 0);
    assert.equal(f.window.wrapper_nonce, "oldNonce");
    assert.equal(f.wrapper.iframe_recovery_pending, false);
  }
});

test("replacing the iframe element invalidates its pending nonce reply", () => {
  const f = fixture();
  f.wrapper.reloadIframe(); f.replaceFrame(); f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, 0);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
});

test("an src change while awaiting a nonce cannot be reverted by its late reply", () => {
  const f = fixture();
  f.wrapper.reloadIframe();
  f.frame.src = "https://current.epix/next.html?wrapper_nonce=oldNonce";
  const writesBeforeReply = f.writes.length;
  f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, writesBeforeReply);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
  assert.equal(f.wrapper.iframe_recovery_pending, false);
});

test("socket loss releases nonce recovery and ignores its late reply after a retry", () => {
  const f = fixture();
  f.wrapper.reloadIframe();
  assert.equal(f.wrapper.iframe_recovery_pending, true);
  f.close();
  assert.equal(f.wrapper.iframe_recovery_pending, false);
  f.open(); f.wrapper.reloadIframe();
  f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, 0);
  assert.equal(f.wrapper.iframe_recovery_pending, true, "old reply cannot release the new request's guard");
  f.nonceReply(1, "freshNonce");
  assert.equal(f.window.wrapper_nonce, "freshNonce");
  assert.equal(f.writes.length, 1);
});

test("a disconnected reload leaves recovery available for the reconnect snapshot", () => {
  const f = fixture({ connected: false });
  f.wrapper.iframe_recovery_pending = true;
  f.wrapper.reloadIframe();
  assert.equal(f.requests.length, 0, "nonce requests must not be lost in the transport's disconnected queue");
  assert.equal(f.wrapper.iframe_recovery_pending, false);
  f.open(); f.wrapper.reloadIframe(); f.nonceReply(0, "freshNonce");
  assert.equal(f.window.wrapper_nonce, "freshNonce");
  assert.equal(f.writes.length, 1);
});

test("nonce completion and cancellation release only their own transport callbacks", () => {
  const cases = {
    success: { settle: f => f.nonceReply(0, { wrapper_nonce: "freshNonce" }) },
    invalid: { settle: f => f.nonceReply(0, { error: "offline" }) },
    superseded: { settle: f => f.wrapper.reloadIframe() },
    disconnected: { settle: f => { f.wrapper.ws.ws.readyState = 0; f.wrapper.reloadIframe(); } },
    closed: { settle: f => f.close() },
    loaded: { setup: f => { f.ready(); f.load(); }, settle: f => f.load() },
    spoken: { setup: f => { f.ready(); f.load(); }, settle: f => f.ready() },
    "real document after placeholder": { setup: f => { f.wrapper.inner_load_state = "waiting"; }, settle: f => f.ready() },
  };
  for (const [name, { setup, settle }] of Object.entries(cases)) {
    const f = fixture(), sentinel = () => {};
    if (setup) setup(f);
    const sentinelId = f.wrapper.ws.next_message_id;
    f.wrapper.ws.cmd("unrelated", [], sentinel);
    f.wrapper.reloadIframe();
    const nonceId = f.requests.find(request => request.command === "serverGetWrapperNonce").id;
    assert.equal(typeof f.wrapper.ws.waiting_cb[nonceId], "function", name);
    settle(f);
    assert.equal(Object.hasOwn(f.wrapper.ws.waiting_cb, nonceId), false, name);
    assert.equal(f.wrapper.ws.waiting_cb[sentinelId], sentinel, name);
    if (name === "superseded") {
      assert.equal(Object.keys(f.wrapper.ws.waiting_cb).length, 2, "only sentinel and replacement request remain");
    } else {
      assert.equal(Object.keys(f.wrapper.ws.waiting_cb).length, 1, name);
    }
  }
});

test("cleanup preserves a callback that replaced its registry slot", () => {
  const f = fixture();
  f.wrapper.reloadIframe();
  const id = f.requests[0].id;
  const oldCallback = f.wrapper.ws.waiting_cb[id];
  const replacement = () => {};
  f.wrapper.ws.waiting_cb[id] = replacement;
  f.close(); oldCallback("staleNonce");
  assert.equal(f.wrapper.ws.waiting_cb[id], replacement);
  assert.equal(f.writes.length, 0);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
});

test("successful nonce cleanup starts a new document and keeps navigation pending until it loads", () => {
  const f = fixture(); f.ready(); f.load();
  f.wrapper.reloadIframe(); f.nonceReply(0, "freshNonce");
  assert.equal(Object.keys(f.wrapper.ws.waiting_cb).length, 0);
  assert.equal(f.wrapper.iframe_recovery_pending, true);
  assert.equal(f.wrapper.inner_ready, false, "the old document's readiness does not carry over");
  assert.equal(f.wrapper.wrapperWsInited, false);
  f.ready();
  assert.equal(f.wrapper.iframe_recovery_pending, true, "early ready does not start another recovery");
  assert.equal(f.opens(), 2, "the replacement is told the socket is open");
  f.load();
  assert.equal(f.wrapper.iframe_recovery_pending, false);
  assert.equal(f.opens(), 2);
  assert.equal(f.asks(), 0);
});

test("a document that introduced itself cannot pose as the waiting placeholder", () => {
  // The placeholder never speaks the frame protocol; a page that did and
  // then claims to be waiting would otherwise make the chrome reload the
  // frame and ask the node for a nonce on its behalf.
  const f = fixture(); f.ready(); f.load();
  f.wrapper.onMessageInner({ source: f.inner, data: { cmd: "innerLoadState", params: "waiting", wrapper_nonce: "oldNonce" } });
  assert.equal(f.wrapper.inner_load_state, null);
  assert.equal(f.wrapper.inner_loaded, true);
  assert.equal(f.requests.filter(r => r.command === "serverGetWrapperNonce").length, 0);
  assert.equal(f.wrapper.iframe_recovery_pending, false);
});

test("an orphaned chrome response never reaches the page", () => {
  // A released recovery request still gets its answer from the node, and
  // that answer holds a fresh wrapper nonce. Page-owned ids are forwarded.
  const f = fixture(); f.ready(); f.load();
  f.wrapper.handleMessageWebsocket({ cmd: "response", to: 1000005, result: { wrapper_nonce: "FRESH" } });
  assert.equal(f.messages.filter(m => m.cmd === "response").length, 0);
  f.wrapper.handleMessageWebsocket({ cmd: "response", to: 7, result: "ok" });
  assert.deepEqual(f.messages.filter(m => m.cmd === "response").map(m => m.to), [7]);
});

test("a page cannot harvest the nonce of a reload it provoked", () => {
  // Before it introduces itself a page can still claim to be waiting. The
  // reload that provokes is released when the page speaks, and the node's
  // reply is dropped rather than forwarded; once ready, it provokes nothing.
  const f = fixture();
  f.wrapper.onMessageInner({ source: f.inner, data: { cmd: "innerLoadState", params: "waiting", wrapper_nonce: "oldNonce" } });
  assert.equal(f.requests.filter(r => r.command === "serverGetWrapperNonce").length, 1);
  f.ready();
  f.nonceReply(0, { wrapper_nonce: "FRESH" });
  assert.equal(f.writes.length, 0);
  assert.equal(f.messages.filter(m => m.cmd === "response").length, 0);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
  f.wrapper.onMessageInner({ source: f.inner, data: { cmd: "innerLoadState", params: "waiting", wrapper_nonce: "oldNonce" } });
  assert.equal(f.requests.filter(r => r.command === "serverGetWrapperNonce").length, 1, "a ready page provokes nothing more");
  assert.equal(f.opens(), 1);
});

test("a repeated introduction keeps the document counted as loaded", () => {
  // A legacy page with two frame instances introduces itself twice; the
  // second counts as a replacement, which must not leave the loading
  // overlay waiting for a load event that never comes.
  const f = fixture(); f.ready(); f.load();
  assert.equal(f.wrapper.inner_loaded, true);
  f.ready();
  assert.equal(f.wrapper.inner_generation, 1);
  assert.equal(f.wrapper.inner_loaded, true);
  assert.equal(f.opens(), 2);
});
