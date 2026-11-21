const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const assets = path.join(__dirname, '../app/src/main/assets/browser-controls');
const source = readFileSync(path.join(assets, 'scroll.js'), 'utf8');
const attribute = 'data-epix-native-chrome-hidden';

function fixture(iframe = false) {
    const attributes = new Map();
    const events = new Map();
    const ports = [];
    const window = {addEventListener: (name, listener) => events.set(name, listener)};
    window.top = iframe ? {} : window;
    const browser = {runtime: {connectNative(name) {
        assert.equal(name, 'epix_browser_controls');
        const port = {
            onMessage: {addListener(listener) {port.message = listener;}},
            onDisconnect: {addListener(listener) {port.disconnected = listener;}},
            disconnect() {port.closed = true; port.disconnected();},
        };
        ports.push(port);
        return port;
    }}};
    const document = {documentElement: {
        setAttribute: (name, value) => attributes.set(name, value),
        removeAttribute: name => attributes.delete(name),
    }};
    vm.runInNewContext(source, {window, document, browser});
    return {attributes, events, ports};
}

test('only a top-level local content script receives the native visibility flag', () => {
    const f = fixture();
    assert.equal(f.ports.length, 1);
    assert.equal(f.attributes.size, 0);
    f.ports[0].message({hidden: true});
    assert.equal(f.attributes.get(attribute), 'true');
    for (const message of [null, {}, {hidden: 'false'}, {hidden: 0}, {command: 'run'}]) {
        f.ports[0].message(message);
        assert.equal(f.attributes.get(attribute), 'true');
    }
    f.ports[0].message({hidden: false});
    assert.equal(f.attributes.size, 0);
    assert.deepEqual([...f.events.keys()].sort(), ['pagehide', 'pageshow']);
    assert.equal(fixture(true).ports.length, 0);
});

test('disconnect and cached-page restoration clear hidden state and ignore obsolete ports', () => {
    const f = fixture();
    const original = f.ports[0];
    original.message({hidden: true});
    original.disconnected();
    assert.equal(f.attributes.size, 0);
    f.events.get('pageshow')();
    assert.equal(f.ports.length, 2);
    original.message({hidden: true});
    assert.equal(f.attributes.size, 0);
    f.ports[1].message({hidden: true});
    assert.equal(f.attributes.get(attribute), 'true');
    original.disconnected();
    assert.equal(f.attributes.get(attribute), 'true');
    f.events.get('pagehide')();
    assert.equal(f.ports[1].closed, true);
    assert.equal(f.attributes.size, 0);
    f.events.get('pageshow')();
    f.events.get('pageshow')();
    assert.equal(f.ports.length, 3);
});

test('the builtin has no background script, remote host scope, or iframe injection', () => {
    const manifest = JSON.parse(readFileSync(path.join(assets, 'manifest.json'), 'utf8'));
    assert.equal(manifest.browser_specific_settings.gecko.id, 'browser-ext@epix.zone');
    assert.equal(manifest.background, undefined);
    assert.deepEqual(manifest.content_scripts[0].matches, ['http://127.0.0.1/*']);
    assert.equal(manifest.content_scripts[0].all_frames, false);
    assert.deepEqual(manifest.content_scripts[0].js, ['scroll.js']);
    assert.deepEqual(manifest.content_scripts[0].css, ['scroll.css']);
});
