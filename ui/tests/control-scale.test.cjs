// Run: node --test ui/tests/control-scale.test.cjs
// Exercise the production viewport controller across browser event sequences.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../media/all.js'), 'utf8');
const start = source.indexOf('/* Wrapper controls use their own coordinates.');
const end = source.indexOf('/* ---- Fixbutton.coffee ---- */', start);
assert.ok(start >= 0 && end > start);

function fixture(scale = 1, content = 'width=device-width, initial-scale=' + scale) {
  let frames = [], events = 0;
  const listeners = new Map();
  const visualViewport = {scale, width: 360 / scale, height: 800 / scale, pageLeft: 0, pageTop: 0,
    addEventListener(name, cb) {listeners.set(name, cb);}};
  const classes = new Set();
  const element = {style: {setProperty(name, value) {this[name] = value;}},
    classList: {toggle(name, value) {if (value) classes.add(name); else classes.delete(name);}}};
  const document = {documentElement: {clientWidth: Math.max(360, 360 / scale), clientHeight: 800},
    getElementById() {return element;}, querySelectorAll() {return [{content}];}};
  const window = {visualViewport, pageXOffset: 0, pageYOffset: 0,
    addEventListener() {}, dispatchEvent() {events++;}};
  const context = vm.createContext({document, window, Event: class {constructor(type) {this.type = type;}},
    requestAnimationFrame(cb) {frames.push(cb); return frames.length;}});
  vm.runInContext(source.slice(start, end), context);
  const chrome = new window.WrapperChrome();
  function flush() {while (frames.length) {const pending = frames; frames = []; for (const cb of pending) cb();}}
  function viewport(delta, event = 'resize') {Object.assign(visualViewport, delta); listeners.get(event)(); flush();}
  return {chrome, visualViewport, element, classes, document, flush, viewport, events: () => events};
}

for (const scale of [0.5, 1, 2]) test('initial scale ' + scale + ' keeps control coordinates at 360 by 800', () => {
  const f = fixture(scale);
  assert.equal(f.chrome.baseline, scale);
  assert.equal(f.chrome.width, 360);
  assert.equal(f.chrome.height, 800);
  assert.ok(f.classes.has('controls-narrow'));
  assert.equal(f.element.style.transform, `translate(0px,0px) scale(${1 / scale})`);
});

test('pinch and pan preserve magnification and use viewport-local pointer coordinates', () => {
  const f = fixture(0.5);
  f.viewport({scale: 1, width: 360, height: 800, pageLeft: 25, pageTop: 60});
  assert.equal(f.chrome.baseline, 0.5);
  assert.equal(f.chrome.width, 180);
  assert.equal(f.chrome.point(125, 160).left, 50);
  assert.equal(f.chrome.point(125, 160).top, 50);
  const eventCount = f.events();
  f.viewport({}, 'scroll');
  assert.equal(f.events(), eventCount, 'unchanged geometry does not restart control animations');
});

test('a keyboard height change does not adopt current user zoom', () => {
  const f = fixture();
  f.viewport({scale: 2, width: 180, height: 400});
  f.viewport({height: 200});
  assert.equal(f.chrome.baseline, 1);
  assert.equal(f.chrome.height, 200);
});

test('an ignored desktop viewport edit preserves an existing pinch', () => {
  const f = fixture();
  f.viewport({scale: 2, width: 180, height: 400});
  f.chrome.beforeViewportChange('width=device-width, initial-scale=0.5');
  f.flush();
  assert.equal(f.chrome.baseline, 1);
  assert.equal(f.chrome.width, 180);
});

test('a delayed mobile viewport change adopts the browser-applied author scale', () => {
  const f = fixture();
  f.chrome.beforeViewportChange('width=device-width, initial-scale=0.5');
  Object.assign(f.visualViewport, {scale: 0.5, width: 720, height: 1600});
  f.document.documentElement.clientWidth = 720;
  f.flush();
  assert.equal(f.chrome.baseline, 0.5);
  assert.equal(f.chrome.width, 360);
});

test('rotation fits a width-only viewport without absorbing user pinch', () => {
  const f = fixture(0.5, 'width=720');
  f.viewport({scale: 1, width: 360, height: 800});
  // Physical width doubles; user zoom relative to the fitted width stays 2x.
  f.viewport({scale: 2, width: 360, height: 180});
  assert.equal(f.chrome.baseline, 1);
  assert.equal(f.chrome.width, 360);
  f.viewport({scale: 1, width: 360, height: 800});
  assert.equal(f.chrome.baseline, 0.5);
});

test('a width-only page initially fitting at scale one can rotate in both directions', () => {
  const f = fixture(1, 'width=360');
  f.viewport({scale: 800 / 360, width: 360, height: 162});
  assert.equal(f.chrome.baseline, 800 / 360);
  assert.equal(f.chrome.width, 800);
  f.viewport({scale: 1, width: 360, height: 800});
  assert.equal(f.chrome.baseline, 1);
});

test('desktop resizing with an ignored numeric viewport width does not change the baseline', () => {
  const f = fixture(1, 'width=360');
  f.viewport({width: 800});
  assert.equal(f.chrome.baseline, 1);
  assert.equal(f.chrome.width, 800);
});

test('a layout-only author edit does not absorb an existing pinch', () => {
  const f = fixture();
  f.viewport({scale: 2, width: 180, height: 400});
  f.chrome.beforeViewportChange('width=980, initial-scale=1, maximum-scale=4');
  f.document.documentElement.clientWidth = 980;
  f.flush();
  assert.equal(f.chrome.baseline, 1);
  assert.equal(f.chrome.width, 180);
});
