// Native browser checks supplement these production URL and observer regressions.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const source = fs.readFileSync(path.join(__dirname, "../media/all.js"), "utf8");
const ADDRESS = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
function method(name) {
  const start = source.indexOf(`Wrapper.prototype.${name} = function`);
  assert.ok(start >= 0, `production method ${name}`);
  return source.slice(start, source.indexOf("\n    };", start) + 7);
}
const methods = ["canonicalXiteLink", "updateXiteLinks"].map(method).join("\n");
const context = vm.createContext({ URL });
vm.runInContext("var Wrapper = function() {};\n" + methods, context);
const canonical = context.Wrapper.prototype.canonicalXiteLink;
const DESKTOP = "https://blog.epix/index.html?wrapper_nonce=source";
const MOBILE = "http://127.0.0.1:42222/blog.epix/index.html?wrapper_nonce=source";

test("desktop legacy links expose the actual origin, keeping encoded URL suffixes", () => {
  for (const href of ["target.epix", "/target.epix/", "./target.epix/", "/TaRget.EPIX/"]) {
    assert.equal(canonical(href, DESKTOP, DESKTOP, ""), "https://target.epix/", href);
  }
  for (const suffix of ["docs/a%23b%252Fc.html?view=a%2Fb#part%202", "data.json?", "#", "?q=#"]) {
    assert.equal(canonical(`target.epix/${suffix}`, DESKTOP, DESKTOP, ""), `https://target.epix/${suffix}`);
  }
  const insecure = "http://blog.epix/index.html";
  assert.equal(canonical("target.epix/", insecure, insecure, ""), "http://target.epix/");
});

test("only valid addresses become dotted origins", () => {
  for (const ref of [ADDRESS, ADDRESS.toUpperCase(), `${ADDRESS}.epix`, `${ADDRESS.toUpperCase()}.EPIX`]) {
    assert.equal(canonical(`${ref}/?q=1#part`, DESKTOP, DESKTOP, ""), `https://${ADDRESS}.epix/?q=1#part`);
  }
  for (const ref of [ADDRESS.slice(0, -1) + "q", "E" + ADDRESS.slice(1), ADDRESS.slice(0, 30)]) {
    for (const suffix of ["", ".epix"]) {
      assert.equal(canonical(`${ref}${suffix}/`, DESKTOP, DESKTOP, ""), null, ref + suffix);
    }
  }
  for (const ref of ["epix1shop.epix", "epix1fans.epix", "epix1bobsbigblog2026extra.epix"]) {
    assert.equal(canonical(`${ref}/`, DESKTOP, DESKTOP, ""), `https://${ref}/`);
  }
});

test("unsupported authority shapes and escaped delimiters remain untouched", () => {
  for (const ref of ["-bad.epix", "bad-.epix", "bad_.epix", "nested.target.epix", "a".repeat(64) + ".epix",
    "target.epix:443", "target.epix@evil.example", "evil.example%23.epix", "evil.example%2fignored.epix",
    "evil.example%5cignored.epix", "%74arget.epix", "target%20.epix", "é.epix", "epix1shop"]) {
    assert.equal(canonical(`/${ref}/`, DESKTOP, DESKTOP, ""), null, ref);
  }
});

test("normal links and explicit destinations keep their authored meaning", () => {
  for (const href of ["", "#target.epix/", "?route=target.epix/", "docs/target.epix/", "example.com/path",
    "mailto:a@example.com", "javascript:alert(1)", "data:text/html,test", "https://target.epix/",
    "https://blog.epix/target.epix/", "//target.epix/", "///target.epix/", " target.epix/",
    "target.epix/\n", "target.epix\\docs/", "target.epix/?wrapper_nonce=keep",
    "target.epix/?%77rapper_nonce=keep"]) {
    assert.equal(canonical(href, DESKTOP, DESKTOP, "_top"), null, href);
  }
  const nested = "https://blog.epix/docs/index.html";
  assert.equal(canonical("target.epix/", nested, nested, ""), null);
  assert.equal(canonical("../target.epix/", nested, nested, ""), "https://target.epix/");
  assert.equal(canonical("target.epix/", "https://external.example/", DESKTOP, ""), null);
  assert.equal(canonical("target.epix/", DESKTOP, "file:///blog/index.html", ""), null);
});

test("path mode removes only the current source prefix for supported navigations", () => {
  for (const ref of ["target.epix", ADDRESS, `${ADDRESS}.epix`]) {
    const origin = ref === ADDRESS ? `${ADDRESS}.epix` : ref;
    for (const suffix of ["", "/", "/docs/a%23b%252Fc/?q=a%2Fb#part"]) {
      assert.equal(canonical(ref + suffix, MOBILE, MOBILE, ""),
        `http://127.0.0.1:42222/${origin}${suffix || "/"}`);
    }
  }
  for (const href of ["/target.epix/", "/other.epix/target.epix/", "docs/target.epix/",
    "target.epix/page.html", "target.epix/page.htm", "target.epix/data.json"]) {
    assert.equal(canonical(href, MOBILE, MOBILE, ""), null, href);
  }
  for (const target of ["_top", "_parent", "_blank", "_TOP"]) {
    assert.equal(canonical("target.epix/page.html?keep=1#part", MOBILE, MOBILE, target),
      "http://127.0.0.1:42222/target.epix/page.html?keep=1#part");
  }
  for (const target of ["", "_self", "named-window"]) {
    assert.equal(canonical("target.epix/page.html", MOBILE, MOBILE, target), null);
  }
  for (const href of ["target.epix/data.json", "target.epix/page.HTML"]) {
    assert.equal(canonical(href, MOBILE, MOBILE, "_top"), null);
  }
  const invalidHost = "https://nested.blog.epix/blog.epix/index.html";
  assert.equal(canonical("target.epix/", invalidHost, invalidHost, ""), null);
});

// Minimal DOM fixture with queued, filtered mutation delivery. URL expectations
// above are independent of the fixture; these checks exercise lifecycle effects.
class Element {
  constructor(name, attributes = {}) {
    this.nodeType = 1;
    this.localName = name;
    this.attributes = { ...attributes };
    this.children = [];
    this.parentNode = null;
    this.ownerDocument = null;
  }
  getAttribute(name) { return Object.hasOwn(this.attributes, name) ? this.attributes[name] : null; }
  hasAttribute(name) { return Object.hasOwn(this.attributes, name); }
  setAttribute(name, value) {
    this.attributes[name] = String(value);
    this.ownerDocument?.emit({ type: "attributes", attributeName: name, target: this });
  }
  removeAttribute(name) {
    delete this.attributes[name];
    this.ownerDocument?.emit({ type: "attributes", attributeName: name, target: this });
  }
  matches(selector) {
    return selector.split(",").some(part => {
      const [, tag, attribute] = part.match(/^(\w+)?(?:\[(\w+)\])?$/) || [];
      return (!tag || this.localName === tag) && (!attribute || this.hasAttribute(attribute));
    });
  }
  closest(selector) {
    for (let node = this; node && node.nodeType === 1; node = node.parentNode) {
      if (node.matches(selector)) return node;
    }
    return null;
  }
  querySelectorAll(selector) {
    return this.children.flatMap(node => [
      ...(node.matches(selector) ? [node] : []), ...node.querySelectorAll(selector),
    ]);
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  get baseURI() { return this.ownerDocument.baseURI; }
  append(child) {
    child.parentNode = this;
    const doc = this.nodeType === 9 ? this : this.ownerDocument;
    function attach(node) { node.ownerDocument = doc; node.children.forEach(attach); }
    attach(child);
    this.children.push(child);
    doc.emit({ type: "childList", target: this, addedNodes: [child], removedNodes: [] });
    return child;
  }
  remove(child) {
    this.children.splice(this.children.indexOf(child), 1);
    child.parentNode = null;
    this.ownerDocument.emit({ type: "childList", target: this, addedNodes: [], removedNodes: [child] });
  }
}
class Document extends Element {
  constructor(url) {
    super("#document"); this.nodeType = 9; this.location = new URL(url);
    this.observers = new Set(); this.ownerDocument = this; this.listeners = new Map();
  }
  get baseURI() {
    const base = this.querySelector("base[href]");
    return base ? new URL(base.getAttribute("href"), this.location.href).href : this.location.href;
  }
  emit(change) {
    for (const observer of this.observers) {
      if (change.type !== "attributes" || observer.options.attributeFilter.includes(change.attributeName)) {
        observer.changes.push(change);
      }
    }
  }
  addEventListener(type, callback, capture) {
    assert.equal(capture, true, "revalidate before native or page link actions");
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(callback);
  }
  removeEventListener(type, callback, capture) {
    assert.equal(capture, true);
    this.listeners.get(type)?.delete(callback);
  }
  interact(type, target) {
    for (const callback of this.listeners.get(type) || []) callback({ type, target });
  }
  flush() {
    for (let round = 0; round < 20; round++) {
      const pending = [...this.observers].filter(observer => observer.changes.length);
      if (!pending.length) return;
      pending.forEach(observer => observer.callback(observer.changes.splice(0)));
    }
    assert.fail("normalization must settle without an observer feedback loop");
  }
}
function fixture(url = DESKTOP) {
  const doc = new Document(url);
  const frame = { contentDocument: doc };
  class Observer {
    constructor(callback) { this.callback = callback; this.changes = []; }
    observe(doc, options) { this.doc = doc; this.options = options; doc.observers.add(this); }
    disconnect() { this.doc.observers.delete(this); this.changes = []; }
  }
  const window = { location: new URL(url), MutationObserver: Observer };
  const context = vm.createContext({ URL, window, document: { getElementById: () => frame } });
  vm.runInContext("var Wrapper = function() {};\n" + methods, context);
  const wrapper = new context.Wrapper();
  return { doc, frame, wrapper, start() { wrapper.updateXiteLinks(); doc.flush(); } };
}

test("initial and dynamic anchors normalize while other resource/control attributes stay unchanged", () => {
  const f = fixture();
  const first = f.doc.append(new Element("a", { href: "target.epix/", target: "_top" }));
  const image = f.doc.append(new Element("img", { src: "target.epix/picture.png" }));
  const script = f.doc.append(new Element("script", { src: "target.epix/script.js" }));
  const form = f.doc.append(new Element("form", { action: "target.epix/" }));
  const download = f.doc.append(new Element("a", { href: "target.epix/", download: "" }));
  f.start();
  assert.equal(first.getAttribute("href"), "https://target.epix/");
  assert.equal(first.getAttribute("target"), "_top");
  assert.equal(image.getAttribute("src"), "target.epix/picture.png");
  assert.equal(script.getAttribute("src"), "target.epix/script.js");
  assert.equal(form.getAttribute("action"), "target.epix/");
  assert.equal(download.getAttribute("href"), "target.epix/");
  const subtree = f.doc.append(new Element("div"));
  const added = subtree.append(new Element("a", { href: `${ADDRESS}/` }));
  f.doc.flush();
  assert.equal(added.getAttribute("href"), `https://${ADDRESS}.epix/`);
  added.setAttribute("href", "https://example.com/path"); f.doc.flush();
  assert.equal(added.getAttribute("href"), "https://example.com/path");
  first.setAttribute("download", "saved"); f.doc.flush();
  assert.equal(first.getAttribute("href"), "target.epix/", "download restores the authored URL");
});

test("base and target changes recompute from authored links and restore ordinary resolutions", () => {
  const f = fixture(MOBILE);
  const base = f.doc.append(new Element("base", { target: "_top" }));
  const link = f.doc.append(new Element("a", { href: "target.epix/page.html" }));
  f.start();
  assert.equal(link.getAttribute("href"), "http://127.0.0.1:42222/target.epix/page.html");
  link.setAttribute("target", "_self"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "target.epix/page.html");
  link.removeAttribute("target"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "http://127.0.0.1:42222/target.epix/page.html");
  base.setAttribute("href", "https://external.example/"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "target.epix/page.html", "foreign bases retain their meaning");
  base.removeAttribute("href"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "http://127.0.0.1:42222/target.epix/page.html");
  f.doc.remove(base); f.doc.flush();
  assert.equal(link.getAttribute("href"), "target.epix/page.html");
});

test("editor transitions preserve raw links and later display uses the edited destination", () => {
  const f = fixture();
  const field = f.doc.append(new Element("div"));
  const link = field.append(new Element("a", { href: "target.epix/" }));
  const existingEditor = f.doc.append(new Element("div", { contenteditable: "true" }));
  const draft = existingEditor.append(new Element("a", { href: "draft.epix/" }));
  f.start();
  assert.equal(link.getAttribute("href"), "https://target.epix/");
  assert.equal(draft.getAttribute("href"), "draft.epix/");
  field.setAttribute("contenteditable", "true"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "target.epix/");
  link.setAttribute("href", "edited.epix/"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "edited.epix/");
  field.removeAttribute("contenteditable"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "https://edited.epix/");
  field.setAttribute("contenteditable", "true"); f.doc.flush();
  assert.equal(link.getAttribute("href"), "edited.epix/", "edits replace the old authored URL");
});

test("history path changes without DOM mutations preserve relative links before browser interactions", () => {
  for (const type of ["pointerover", "pointermove", "focusin", "click", "auxclick", "contextmenu", "dragstart"]) {
    const f = fixture();
    const link = f.doc.append(new Element("a", { href: "target.epix/" }));
    const text = link.append(new Element("span"));
    const rootLink = f.doc.append(new Element("a", { href: "/other.epix/" }));
    f.start();
    assert.equal(link.getAttribute("href"), "https://target.epix/");
    // Like pushState, this changes document/base URLs without a DOM mutation.
    f.doc.location = new URL("/docs/", f.doc.location);
    f.doc.flush();
    f.doc.interact(type, text);
    assert.equal(new URL(link.getAttribute("href"), link.baseURI).href,
      "https://blog.epix/docs/target.epix/", type);
    assert.equal(rootLink.getAttribute("href"), "https://other.epix/", "root links keep their destination");
    f.doc.location = new URL("/index.html", f.doc.location);
    f.doc.interact(type, text);
    assert.equal(link.getAttribute("href"), "https://target.epix/", "back navigation permits canonical links again");
    f.doc.flush();
    f.doc.interact("pointermove", text);
    assert.equal([...f.doc.observers][0].changes.length, 0, "ordinary pointer movement does not mutate anchors");
  }
});

test("navigating the frame disconnects the old observer and never inspects a foreign origin", () => {
  const f = fixture();
  f.start(); f.wrapper.updateXiteLinks();
  assert.equal(f.doc.observers.size, 1, "repeated load callbacks do not duplicate observers");
  const foreign = new Document("https://foreign.epix/index.html");
  const untouched = foreign.append(new Element("a", { href: "target.epix/" }));
  f.frame.contentDocument = foreign;
  f.wrapper.updateXiteLinks();
  assert.equal(f.doc.observers.size, 0);
  assert.equal([...f.doc.listeners.values()].reduce((count, callbacks) => count + callbacks.size, 0), 0,
    "the old document retains no interaction listeners");
  assert.equal(foreign.observers.size, 0);
  assert.equal(foreign.listeners.size, 0);
  assert.equal(untouched.getAttribute("href"), "target.epix/");
  const next = new Document(DESKTOP);
  const link = next.append(new Element("a", { href: "target.epix/" }));
  f.frame.contentDocument = next;
  f.wrapper.updateXiteLinks();
  assert.equal(next.observers.size, 1);
  assert.equal(link.getAttribute("href"), "https://target.epix/");
  Object.defineProperty(f.frame, "contentDocument", { get() { throw new Error("cross-origin access"); } });
  assert.doesNotThrow(() => f.wrapper.updateXiteLinks());
  assert.equal(next.observers.size, 0);
  assert.equal([...next.listeners.values()].reduce((count, callbacks) => count + callbacks.size, 0), 0);
});
