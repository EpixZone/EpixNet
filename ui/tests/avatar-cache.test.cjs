const assert = require("node:assert/strict");
const {test} = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const script = fs.readFileSync(path.join(__dirname, "../media/epix-avatar.js"), "utf8");
const png = "data:image/png;base64,iVBORw0KGgoAAA==";
const original = "https://2.gravatar.com/avatar/" + "0".repeat(32) + "?size=2048&d=retro";

function client() {
  const calls = [];
  const window = {parent: {postMessage(message, origin, ports) {
    calls.push({command: message.cmd, params: message.params, reply(value) {
      ports[0].postMessage(value); ports[0].close();
    }});
  }}, Page: {cmd(command, params, reply) { assert.equal(command, "wrapperAvatarThumbnailVersion"); reply(1); }}};
  vm.runInNewContext(script, {window, URL, setTimeout, clearTimeout, MessageChannel});
  const image = {style: {}, setAttribute(k, v) { this[k] = v; }, removeAttribute(k) { delete this[k]; }};
  return {avatar: window.EpixAvatar, calls, image};
}

test("matching requests share a lookup without changing the URL or the requested size", async () => {
  const {avatar, calls} = client();
  const first = avatar.get(original, 80), second = avatar.get(original, 80);
  const small = avatar.get(original, 20);
  await Promise.resolve(); await Promise.resolve();
  assert.equal(calls.length, 2);
  assert.equal(calls[0].command, "wrapperGetAvatarThumbnail");
  assert.equal(calls[0].params.url, original);
  assert.deepEqual(calls.map(c => c.params.size), [80, 20]);
  calls[0].reply({thumbnail: png});
  calls[1].reply({error: "unsupported"});
  assert.deepEqual(await Promise.all([first, second, small]), [png, png, null]);
});

test("rebinding or clearing an element discards late results", async () => {
  const {avatar, calls, image} = client();
  const old = avatar.bind(image, original, 80);
  const current = avatar.bind(image, "https://example.com/new.png", 80);
  await Promise.resolve(); await Promise.resolve();
  calls[1].reply(null);
  await current;
  calls[0].reply({thumbnail: png});
  await old;
  assert.equal(image.src, "https://example.com/new.png");
  assert.equal(image.referrerpolicy, "no-referrer");
  const pending = avatar.bind(image, original, 56);
  await avatar.bind(image, "", 56);
  await Promise.resolve(); await Promise.resolve();
  calls[2].reply({thumbnail: png});
  await pending;
  assert.equal(image.src, undefined);
});

test("legacy fallback sizes Gravatars and quotes a single background URL", async () => {
  const {avatar, calls, image} = client();
  const render = avatar.bind(image, original, 56, {background: true});
  await Promise.resolve(); await Promise.resolve();
  calls[0].reply({error: "unknown command"});
  await render;
  assert.equal(image.style.backgroundImage, 'url("https://2.gravatar.com/avatar/' + "0".repeat(32) + '?d=retro&s=56")');
  await avatar.bind(image, 'images/my"avatar.png', 56, {background: true});
  assert.equal(image.style.backgroundImage, 'url("images/my\\22 avatar.png")');
  assert.equal(calls.length, 1);
});
