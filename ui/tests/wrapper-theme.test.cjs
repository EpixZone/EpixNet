// Run: node --test ui/tests/wrapper-theme.test.cjs
// Exercise production theme propagation without starting the wrapper UI.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../media/all.js'), 'utf8');
const methods = ['setServerInfo', 'updateTheme', 'handleMessageWebsocket', 'onOpenWebsocket'].map(name => {
  const start = source.indexOf(`Wrapper.prototype.${name} = function`);
  const end = source.indexOf('\n    };', start);
  assert.ok(start >= 0 && end > start, `production ${name} method exists`);
  return source.slice(start, end + '\n    };'.length);
}).join('\n');

function fixture(options = {}) {
  const classes = new Set(['theme-light', 'controls-narrow', 'sidebar-open']);
  const listeners = [], requests = [], forwarded = [], mediaQueries = [];
  const media = {matches: options.dark === true};
  if (options.legacyMedia) {
    media.addListener = callback => listeners.push(callback);
  } else {
    media.addEventListener = (event, callback) => {
      assert.equal(event, 'change');
      listeners.push(callback);
    };
  }
  const body = {
    classList: {
      toggle(name, enabled) {
        if (enabled) classes.add(name);
        else classes.delete(name);
      },
    },
  };
  const window = {
    resolving_host: '',
    show_loadingscreen: options.loading === true,
  };
  if (!options.noMedia) {
    window.matchMedia = query => {mediaQueries.push(query); return media;};
  }
  const context = vm.createContext({
    document: {body}, window,
    setInterval() {return 1;}, setTimeout() {return 1;}, clearTimeout() {},
  });
  vm.runInContext('var Wrapper = function() {}; var indexOf = [].indexOf;\n' + methods, context);
  const wrapper = Object.assign(Object.create(context.Wrapper.prototype), {
    server_info: null,
    ws: {cmd(command, params, done) {requests.push({command, params, done});}, waiting_cb: {}},
    sendInner(message) {forwarded.push(message);},
    announceWebsocket() {}, reloadXiteInfo() {}, pollNotificationCount() {}, setAnnouncerInfo() {},
  });
  return {
    wrapper, body, classes, listeners, requests, forwarded, mediaQueries,
    push(settings, extra = {}) {
      const message = {cmd: 'setServerInfo', params: {...extra, user_settings: settings}};
      wrapper.handleMessageWebsocket(message);
      return message;
    },
    systemTheme(dark) {
      media.matches = dark;
      listeners.forEach(callback => callback({matches: dark}));
    },
  };
}

function assertTheme(fixture, theme) {
  assert.equal(fixture.classes.has('theme-dark'), theme === 'dark');
  assert.equal(fixture.classes.has('theme-light'), theme === 'light');
  assert.ok(fixture.classes.has('controls-narrow'), 'responsive layout class is preserved');
  assert.ok(fixture.classes.has('sidebar-open'), 'open sidebar class is preserved');
}

test('initial and reconnect snapshots apply the theme with or without a loading screen', () => {
  for (const loading of [false, true]) {
    const f = fixture({loading});
    f.wrapper.onOpenWebsocket();
    const first = f.requests.filter(request => request.command === 'serverInfo');
    assert.equal(first.length, 1);
    const channelJoin = f.requests.find(request => request.command === 'channelJoin');
    assert.ok(channelJoin.params.channels.includes('serverChanged'));
    first[0].done({user_settings: {theme: 'dark', use_system_theme: false}});
    assertTheme(f, 'dark');
    f.wrapper.onOpenWebsocket();
    const second = f.requests.filter(request => request.command === 'serverInfo');
    assert.equal(second.length, 2, 'reconnect obtains the current settings');
    second[1].done({user_settings: {theme: 'light', use_system_theme: false}});
    assertTheme(f, 'light');
    assert.equal(f.listeners.length, 1, 'reconnect reuses the media listener');
  }
});

test('pushed settings repaint the existing body and still reach the inner app', () => {
  const f = fixture();
  const first = f.push({theme: 'dark', use_system_theme: false}, {version: 'fixture'});
  assertTheme(f, 'dark');
  assert.equal(f.wrapper.server_info, first.params);
  assert.equal(f.forwarded[0], first, 'forward the original event unchanged');
  const second = f.push({theme: 'light', use_system_theme: false});
  assertTheme(f, 'light');
  assert.equal(f.forwarded[1], second);
  assert.equal(f.requests.length, 0, 'applying a pushed snapshot needs no refresh or command');
});

test('explicit light and dark preferences override the system theme', () => {
  const f = fixture({dark: true});
  f.push({theme: 'light', use_system_theme: false});
  assertTheme(f, 'light');
  f.systemTheme(false);
  f.push({theme: 'dark', use_system_theme: false});
  assertTheme(f, 'dark');
  f.systemTheme(true);
  f.systemTheme(false);
  assertTheme(f, 'dark');
});

test('system mode responds immediately and installs one listener across repeated updates', () => {
  for (const legacyMedia of [false, true]) {
    const f = fixture({dark: true, legacyMedia});
    f.push({theme: 'light', use_system_theme: true});
    assertTheme(f, 'dark');
    f.systemTheme(false);
    assertTheme(f, 'light');
    f.systemTheme(true);
    assertTheme(f, 'dark');
    f.push({theme: 'light', use_system_theme: false});
    assertTheme(f, 'light');
    f.push({theme: 'light', use_system_theme: true});
    assertTheme(f, 'dark');
    f.push({theme: 'light', use_system_theme: true});
    assert.deepEqual(f.mediaQueries, ['(prefers-color-scheme: dark)']);
    assert.equal(f.listeners.length, 1);
  }
});

test('an omitted system preference defaults to following the OS', () => {
  const f = fixture({dark: true});
  f.push({theme: 'light'});
  assertTheme(f, 'dark');
  f.systemTheme(false);
  assertTheme(f, 'light');
});

test('without matchMedia the stored resolved theme remains usable', () => {
  const f = fixture({noMedia: true});
  f.push({theme: 'dark', use_system_theme: true});
  assertTheme(f, 'dark');
  f.push({theme: 'light', use_system_theme: true});
  assertTheme(f, 'light');
  assert.equal(f.listeners.length, 0);
});

test('incomplete or malformed snapshots do not change the current theme', () => {
  const invalidSettings = [undefined, null, [], 'dark', 1, {}, {sidebar_peer_map_open: false}, {theme: 'sepia'}];
  for (const user_settings of invalidSettings) {
    const f = fixture();
    f.push({theme: 'dark', use_system_theme: false});
    const message = f.push(user_settings);
    assertTheme(f, 'dark');
    assert.equal(f.forwarded.at(-1), message, 'non-theme updates still reach the inner app');
  }
  for (const snapshot of [null, undefined, [], 'dark', 1, {error: 'Unavailable'}, {}]) {
    const f = fixture();
    f.push({theme: 'dark', use_system_theme: false});
    assert.doesNotThrow(() => f.wrapper.setServerInfo(snapshot));
    assertTheme(f, 'dark');
  }
});
