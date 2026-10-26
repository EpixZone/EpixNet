// Run: node --test ui/tests/wrapper-startup.test.cjs
// Exercise the production Wrapper without its automatic DOM/WebSocket startup.
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
  let activeDocument = makeDocument(initialSrc);
  let documentInaccessible = false;
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
    get document() {
      if (documentInaccessible) throw new Error("Cross-origin document");
      return activeDocument;
    },
    postMessage(message) {
      messages.push(message);
      if (onPost) onPost(message);
    },
  };
  function makeDocument(href, readyState = "complete") {
    return { location: { href }, readyState, documentElement: { dataset: {} } };
  }
  function makeFrame(src) {
    let currentSrc = src;
    return {
      contentWindow: inner,
      get contentDocument() { return inner.document; },
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
    opener_tested: false, iframe_recovery_pending: false,
    ws_lost_timer: null, ws_error: null,
    xite_info: { content: { title: "Fixture" }, settings: { size: 1 }, size_limit: 1 },
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
    get document() { return activeDocument; },
    opens: () => messages.filter(message => message.cmd === "wrapperOpenedWebsocket").length,
    ready(nonce = window.wrapper_nonce, sender = inner) {
      return wrapper.onMessageInner({ source: sender, data: { cmd: "innerReady", id: 1, wrapper_nonce: nonce } });
    },
    load() { wrapper.onPageLoad({ target: frame }); },
    open() { transport.ws.readyState = 1; transport.onOpenWebsocket({}); },
    close() { transport.ws.readyState = 3; transport.onCloseWebsocket({}); },
    replaceDocument(href = activeDocument.location.href, readyState) {
      activeDocument = makeDocument(href, readyState);
      return activeDocument;
    },
    inaccessible(value = true) { documentInaccessible = value; },
    nullDocument() { activeDocument = null; },
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
  for (const order of [["ready", "load", "open"], ["load", "open", "ready"], ["open", "ready", "load"]]) {
    const f = fixture({ connected: false });
    for (const event of order) f[event]();
    f.ready(); f.load();
    assert.equal(f.opens(), 1, order.join(" -> "));
  }
});

test("same-URL iframe replacement boots without a new outer socket", () => {
  const f = fixture(); f.ready(); f.load();
  const oldDocument = f.document;
  f.replaceDocument();
  assert.notEqual(f.document, oldDocument);
  f.ready(); f.load(); f.ready();
  assert.equal(f.opens(), 2, "each Document receives its own initial socket announcement");
});

test("a replacement load requests readiness from the new document", () => {
  const f = fixture(); f.ready(); f.load();
  f.replaceDocument("https://current.epix/next.html?wrapper_nonce=oldNonce");
  f.load();
  assert.equal(f.wrapper.inner_ready, false);
  assert.equal(f.messages.at(-1).cmd, "wrapperReady");
  f.ready();
  assert.equal(f.opens(), 2);
});

test("replacement early-ready does not wait for slow subresources or repeat after load", () => {
  const f = fixture(); f.ready(); f.load();
  f.replaceDocument(undefined, "interactive");
  f.ready();
  assert.equal(f.opens(), 2, "the application can initialize before iframe load");
  f.document.readyState = "complete";
  f.load(); f.ready();
  assert.equal(f.opens(), 2);
});

test("same-document location changes and repeated outer loads retain readiness", () => {
  const f = fixture(); f.ready(); f.load();
  f.document.location.href = "https://current.epix/new-route#section";
  f.load(); f.ready(); f.wrapper.onPageLoad({ target: f.window });
  assert.equal(f.opens(), 1);
});

test("reconnect announces once for a ready unchanged document", () => {
  const f = fixture(); f.ready(); f.close(); f.open(); f.ready();
  assert.equal(f.opens(), 2);
});

test("reconnect cannot reuse readiness from a replaced document", () => {
  const f = fixture(); f.ready(); f.close(); f.replaceDocument();
  f.open();
  assert.equal(f.opens(), 1, "wait for the new document's ready message");
  f.ready();
  assert.equal(f.opens(), 2);
});

test("invalid nonce and unrelated-source ready cannot establish readiness", () => {
  for (const [nonce, sender] of [["wrong", null], [undefined, null], ["oldNonce", {}]]) {
    const f = fixture();
    f.wrapper.onMessageInner({ source: sender || f.inner, data: { cmd: "innerReady", wrapper_nonce: nonce } });
    assert.equal(f.wrapper.inner_ready, false);
    assert.equal(f.opens(), 0);
  }
});

test("an inaccessible or missing document cannot retain old readiness", () => {
  for (const makeUnavailable of [f => f.inaccessible(), f => f.nullDocument()]) {
    const f = fixture(); f.ready(); f.close(); makeUnavailable(f);
    assert.doesNotThrow(() => { f.open(); f.ready(); });
    assert.equal(f.opens(), 1);
    assert.equal(f.wrapper.inner_ready, false);
  }
});

test("announcement is marked before posting to prevent reentrant duplicate ready", () => {
  const f = fixture();
  f.onPost(message => {
    if (message.cmd === "wrapperOpenedWebsocket" && f.opens() === 1) f.ready();
  });
  f.ready();
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

test("navigation while awaiting a nonce cannot be reverted by its late reply", () => {
  const f = fixture();
  f.wrapper.iframe_recovery_pending = true;
  f.wrapper.reloadIframe();
  f.replaceDocument("https://current.epix/next.html?wrapper_nonce=oldNonce");
  f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, 0);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
  assert.equal(f.wrapper.iframe_recovery_pending, false);
});

test("replacing the iframe element invalidates its pending nonce reply", () => {
  const f = fixture();
  f.wrapper.reloadIframe(); f.replaceFrame(); f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, 0);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
});

test("route or src changes while awaiting a nonce cannot be reverted by its late reply", () => {
  for (const navigate of [
    f => { f.document.location.href = "https://current.epix/new-route#section"; },
    f => { f.frame.src = "https://current.epix/next.html?wrapper_nonce=oldNonce"; },
  ]) {
    const f = fixture();
    f.wrapper.reloadIframe(); navigate(f);
    const writesBeforeReply = f.writes.length;
    f.nonceReply(0, "staleNonce");
    assert.equal(f.writes.length, writesBeforeReply);
    assert.equal(f.window.wrapper_nonce, "oldNonce");
    assert.equal(f.wrapper.iframe_recovery_pending, false);
  }
});

test("a reload that cannot access its document still supersedes a prior nonce request", () => {
  const f = fixture();
  f.wrapper.reloadIframe();
  f.inaccessible();
  assert.doesNotThrow(() => f.wrapper.reloadIframe());
  assert.equal(f.wrapper.iframe_recovery_pending, false);
  f.inaccessible(false); f.nonceReply(0, "staleNonce");
  assert.equal(f.writes.length, 0);
  assert.equal(f.window.wrapper_nonce, "oldNonce");
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
    success: f => f.nonceReply(0, { wrapper_nonce: "freshNonce" }),
    invalid: f => f.nonceReply(0, { error: "offline" }),
    superseded: f => f.wrapper.reloadIframe(),
    inaccessible: f => { f.inaccessible(); f.wrapper.reloadIframe(); },
    disconnected: f => { f.wrapper.ws.ws.readyState = 0; f.wrapper.reloadIframe(); },
    closed: f => f.close(),
    navigated: f => { f.replaceDocument(); f.ready(); },
  };
  for (const [name, settle] of Object.entries(cases)) {
    const f = fixture(), sentinel = () => {};
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

test("successful nonce cleanup keeps navigation pending until the replacement loads", () => {
  const f = fixture();
  f.wrapper.reloadIframe(); f.nonceReply(0, "freshNonce");
  assert.equal(Object.keys(f.wrapper.ws.waiting_cb).length, 0);
  assert.equal(f.wrapper.iframe_recovery_pending, true);
  f.replaceDocument(f.frame.src, "interactive"); f.ready();
  assert.equal(f.wrapper.iframe_recovery_pending, true, "early ready does not start another recovery");
  f.document.readyState = "complete"; f.load();
  assert.equal(f.wrapper.iframe_recovery_pending, false);
});
