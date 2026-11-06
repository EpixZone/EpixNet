// Run: node --test ui/tests/wrapper-origin-security.test.cjs
// Navigation keeps an iframe's WindowProxy. Its new document must not inherit
// the previous xite's wrapper authority, even if its URL contains the nonce.
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
const A = "http://epix-epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu.localhost:42222";
const B = "http://epix-epix1xauthduuyn63k6kj54jzgp4l8nnjlhrsyaku8c.localhost:42222";
const NODE = "http://127.0.0.1:42222";

function fixture({ opaque = false, nonceSecurity = true, src = `${A}/index.html?wrapper_nonce=fixtureNonce` } = {}) {
  const accepted = [], directCommands = [], outgoing = [];
  const inner = { postMessage(message, targetOrigin) { outgoing.push({ message, targetOrigin }); } };
  const sandbox = opaque ? "allow-scripts allow-forms" : "allow-scripts allow-forms allow-same-origin";
  const frame = {
    contentWindow: inner,
    src,
    sandbox: { contains: token => sandbox.split(" ").includes(token) },
    getAttribute: name => name === "src" ? src : name === "sandbox" ? sandbox : null,
  };
  const window = {
    wrapper_nonce: "fixtureNonce", postmessage_nonce_security: nonceSecurity,
    iframe_src: src, location: new URL(`${NODE}/alpha.epix/`),
  };
  const document = {
    baseURI: `${NODE}/alpha.epix/`,
    getElementById: id => id === "inner-iframe" ? frame : null,
  };
  const context = vm.createContext({ window, document, URL, console });
  vm.runInContext(`var Wrapper, indexOf = [].indexOf, slice = [].slice;
    var bind = function(fn, self) { return function() { return fn.apply(self, arguments); }; };
    ${wrapperClass}`, context);
  const wrapper = Object.assign(Object.create(context.Wrapper.prototype), {
    inner, opener_tested: true,
    log() {},
    handleMessage(message) { accepted.push(message); },
    ws: { cmd(command, params) { directCommands.push({ command, params }); } },
  });
  function send(origin, overrides = {}) {
    const message = { cmd: "fileWrite", params: ["data/fixture.txt", "fixture"], wrapper_nonce: "fixtureNonce" };
    wrapper.onMessageInner(Object.assign({ source: inner, origin, data: message }, overrides));
    return message;
  }
  return { wrapper, window, frame, inner, accepted, directCommands, outgoing, send };
}

test("another xite in the same WindowProxy cannot reuse the wrapper nonce", () => {
  for (const nonceSecurity of [true, false]) {
    const f = fixture({ nonceSecurity });
    f.send(B);
    assert.equal(f.accepted.length, 0, `foreign origin accepted with nonce security ${nonceSecurity}`);
  }
});

test("the configured content origin can still send page commands", () => {
  const f = fixture();
  const message = f.send(A);
  assert.equal(f.accepted.length, 1);
  assert.equal(f.accepted[0], message);
});

test("origin binding rejects missing, malformed, opaque and different-port senders", () => {
  for (const origin of [undefined, null, "", "null", `${A}/`, `${A}/page.html`, A.replace(":42222", ":31234"), NODE]) {
    const f = fixture();
    f.send(origin);
    assert.equal(f.accepted.length, 0, `accepted ${String(origin)}`);
  }
});

test("opaque frames accept only the browser's literal null origin", () => {
  const valid = fixture({ opaque: true });
  valid.send("null");
  assert.equal(valid.accepted.length, 1);
  for (const origin of [A, B, NODE, undefined, null, ""]) {
    const f = fixture({ opaque: true });
    f.send(origin);
    assert.equal(f.accepted.length, 0, `opaque frame accepted ${String(origin)}`);
  }
});

test("an allowed origin does not replace the source-window or nonce checks", () => {
  const foreignWindow = fixture();
  foreignWindow.send(A, { source: {} });
  assert.equal(foreignWindow.accepted.length, 0);
  const wrongNonce = fixture();
  wrongNonce.send(A, { data: { cmd: "fileWrite", wrapper_nonce: "wrongNonce" } });
  assert.equal(wrongNonce.accepted.length, 0);
});

test("a foreign document cannot bypass origin binding with the xID message shortcut", () => {
  const f = fixture();
  f.send(B, { data: { type: "xid-identity-linked", address: "fixture-address", wrapper_nonce: "fixtureNonce" } });
  assert.equal(f.directCommands.length, 0);
  f.send(A, { data: { type: "xid-identity-linked", address: "fixture-address" } });
  assert.equal(f.directCommands.length, 1);
  assert.equal(f.directCommands[0].command, "identityLinkComplete");
});

test("origin comparison uses the trusted initial URL after cross-origin navigation", () => {
  const f = fixture();
  // A document navigation keeps the frame element and WindowProxy. The
  // server-provided iframe_src remains A even if the current frame navigates B.
  f.frame.src = `${B}/index.html?wrapper_nonce=fixtureNonce`;
  f.send(B);
  assert.equal(f.accepted.length, 0);
  f.send(A);
  assert.equal(f.accepted.length, 1);
});

test("existing proxy content hosts and explicit same-origin grants retain their exact origin", () => {
  for (const [src, origin] of [
    ["//talk.content.epix/index.html?wrapper_nonce=fixtureNonce", "http://talk.content.epix"],
    ["/alpha.epix/index.html?wrapper_nonce=fixtureNonce", NODE],
  ]) {
    const f = fixture({ src });
    f.send(origin);
    assert.equal(f.accepted.length, 1, origin);
    f.send(B);
    assert.equal(f.accepted.length, 1, "a foreign document was accepted");
  }
});

test("pending responses target the original content origin after frame navigation", () => {
  for (const [src, expected] of [
    [`${A}/index.html`, A],
    ["//talk.content.epix/index.html", "http://talk.content.epix"],
    ["/alpha.epix/index.html", NODE],
  ]) {
    const f = fixture({ src });
    f.frame.src = `${B}/index.html`;
    const message = { cmd: "response", to: 7, result: "private fixture" };
    f.wrapper.sendInner(message);
    assert.equal(f.outgoing.length, 1);
    assert.equal(f.outgoing[0].message, message);
    assert.equal(f.outgoing[0].targetOrigin, expected);
  }
});

test("only opaque frames retain a wildcard response target", () => {
  const f = fixture({ opaque: true });
  f.wrapper.sendInner({ cmd: "response", to: 7, result: "fixture" });
  assert.equal(f.outgoing.length, 1);
  assert.equal(f.outgoing[0].targetOrigin, "*");
});

test("missing and non-HTTP configured origins cannot receive responses", () => {
  for (const src of [undefined, "", "about:blank", "data:text/html,fixture", "http://["]) {
    const f = fixture();
    f.window.iframe_src = src;
    f.wrapper.sendInner({ cmd: "response", to: 7, result: "private fixture" });
    assert.equal(f.outgoing.length, 0, String(src));
  }
});
