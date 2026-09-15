// Run: node --test ui/tests/loading-progress.test.cjs
// Run production loading methods with a deterministic clock, without node/network startup.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../media/all.js'), 'utf8');
function method(name) {
  const start = source.indexOf(`Wrapper.prototype.${name} = function`);
  if (start < 0) return '';
  const end = source.indexOf('\n    };', start);
  return source.slice(start, end + 7);
}
function fixture() {
  let now = 1000000, next = 0, reloaded = 0;
  const timers = new Map(), elements = new Map();
  function $(key) {
    if (key && typeof key === 'object') return key;
    if (!elements.has(key)) {
      const node = {
        0: { offsetWidth: 0 }, length: 1, values: {}, events: {},
        find(selector) { return $(key + ' ' + selector); },
        text(value) { if (value === undefined) return this.values.text || ''; this.values.text = value; return this; },
        attr(name, value) { if (value === undefined) return this.values[name]; this.values[name] = value; return this; },
        prop(name, value) { return this.attr(name, value); },
        on(name, fn) { this.events[name] = fn; return this; },
        toggleClass() { return this; }, addClass() { return this; }, removeClass() { return this; },
        addClassLater() { return this; }, css() { return this; }, append() { return this; },
        appendTo() { return this; }, insertBefore() { return this; }, remove() { return this; },
        hide() { return this; }, show() { return this; }, removeLater() { return this; },
      };
      elements.set(key, node);
    }
    return elements.get(key);
  }
  $.extend = Object.assign;
  const innerDocument = { documentElement: { dataset: {} }, location: { href: 'https://test.epix/index.html' }, readyState: 'complete' };
  const inner = { document: innerDocument, location: innerDocument.location };
  const context = vm.createContext({
    window: { show_loadingscreen: false, resolving_host: '', file_inner_path: 'index.html',
      location: { reload() { reloaded++; } }, document: {}, },
    document: { getElementById: () => ({ contentWindow: inner, contentDocument: innerDocument }) },
    $, console, Date: { now: () => now },
    setTimeout(fn, delay) { const id = ++next; timers.set(id, { fn, at: now + delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(fn, delay) { const id = ++next; timers.set(id, { fn, at: now + delay, interval: delay }); return id; },
    clearInterval(id) { timers.delete(id); },
    RateLimit(delay, fn) { fn(); },
  });
  const loading = source.slice(source.indexOf('/* ---- Loading.coffee ---- */'), source.indexOf('/* ---- Notifications.coffee ---- */'));
  vm.runInContext(loading + '\nvar Wrapper=function(){};\n' + ['setXiteInfo', 'onPageLoad', 'startResolvePoll', 'pollResolveStatus', 'setResolveStatus', 'loadingDocumentReady', 'onOpenWebsocket', 'handleMessageWebsocket'].map(method).join('\n'), context);
  const wrapper = Object.assign(Object.create(context.Wrapper.prototype), {
    xite_info: null, inner, inner_loaded: false, inner_ready: true,
    event_xite_info: { resolve() {} }, noteContentSync() {}, log() {}, reloadXiteInfo() {},
    sendInner() {}, updateProgress() {}, pollNotificationCount() {}, setAnnouncerInfo() {}, ws: { connected: true, ws: { readyState: 1 }, cmd() {} },
  });
  const load = new context.window.Loading(wrapper);
  wrapper.loading = load; load.screen_visible = true; context.window.show_loadingscreen = true;
  const stages = [], lines = [];
  load.renderStage = (label, detail, next, error) => stages.push({ label, detail, error });
  load.printLine = (text) => { lines.push(text); return $('log-line'); };
  load.hideScreen = () => { load.screen_visible = false; };
  return { context, wrapper, load, stages, lines, innerDocument, renderedHTML: () => [...elements.keys()].filter(k => k.startsWith('<')).join(''), reloaded: () => reloaded,
    advance(ms) {
      const end = now + ms;
      while (true) {
        const due = [...timers].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        const [id, t] = due; now = t.at;
        if (t.interval) t.at += t.interval; else timers.delete(id);
        t.fn();
      }
      now = end;
    },
  };
}
function info(event, extra = {}) {
  return { address: 'test.epix', content: {}, settings: { size: 100, permissions: [] },
    size_limit: 10, started_task_num: 4, tasks: 2, bad_files: 2, peers: 1,
    event, ...extra };
}

test('a slow discovery round does not diagnose a connection problem after 30 seconds', () => {
  const f = fixture(); f.load.startWatchdog(); f.advance(30000);
  const status = f.stages.at(-1);
  assert.ok(status, 'keep the user informed during a long search');
  assert.doesNotMatch(status.detail, /check your connection/i);
  assert.match(status.detail, /rare|less.common|longer|still/i);
});

test('stalled downloads keep receiving gentle updates after a peer was discovered', () => {
  const f = fixture(); f.load.setStage(1, 'A peer found'); f.load.noteProgress();
  f.advance(45000);
  assert.ok(f.stages.length > 1, 'progress must not permanently disable stalled-load feedback');
});

test('discovery failure does not claim no one is sharing the xite', () => {
  const f = fixture();
  assert.doesNotMatch(f.load.failureText('no_peers'), /no one is sharing|nobody is sharing/i);
});

test('Tor failure does not rule out other routes or invent a retry schedule', () => {
  const f = fixture();
  const detail = f.load.failureText('no_peers', 'Failed');
  assert.match(detail, /less common xites can take longer/i);
  assert.match(detail, /Tor/i);
  assert.doesNotMatch(detail, /only xites.*regular internet|every \d+ seconds/i);
});

test('name lookup Tor recovery does not advertise an unsupported retry interval', () => {
  const f = fixture();
  f.context.window.resolving_host = 'unseeded.epix';
  f.load.showResolveStatus({ state: 'failed', reason: 'tor_required', tor_status: 'Failed' });
  assert.match(f.stages.at(-1).detail, /Tor/i);
  assert.doesNotMatch(f.stages.at(-1).detail, /every \d+ seconds/i);
});

test('waiting, paused, and quiet loading states never ask the user to retry', () => {
  for (const state of ['waiting', 'paused']) {
    const f = fixture();
    f.load.showCloneStatus({ state, attempt: 2, reason: 'no_peers', next_retry_at: 1008 });
    assert.doesNotMatch(f.renderedHTML(), /button-retry|Retry now/i, state);
  }
  const f = fixture(); f.load.startWatchdog(); f.advance(30000);
  assert.doesNotMatch(f.renderedHTML(), /button-retry|Retry now/i, 'quiet search');
});

test('an offline_policy snapshot explains the setting that pauses automatic downloads', () => {
  const f = fixture();
  f.wrapper.setXiteInfo(info(['clone_status', 'paused'], {
    clone_status: { state: 'paused', attempt: 2, reason: 'offline_policy', next_retry_at: null },
  }));
  assert.equal(f.stages.at(-1).label, 'Offline mode');
  assert.match(f.stages.at(-1).detail, /offline mode/i);
  assert.match(f.context.$('.loading-retry-note').text(), /turn off offline mode in connection settings/i);
  assert.doesNotMatch(f.context.$('.loading-retry-note').text(), /automatically when a route/i);
  assert.doesNotMatch(f.renderedHTML(), /button-retry|Retry now/i);
  assert.equal(f.load.screen_visible, true);
});

test('lookup recovery explains automatic retries without rendering a retry button', () => {
  for (const status of [
    { state: 'waiting_network' },
    { state: 'failed', reason: 'not_found' },
    { state: 'failed', reason: 'tor_required', tor_status: 'Failed' },
    { state: 'resolving', reason: 'rpc_error', attempts: 3 },
  ]) {
    const f = fixture(); f.context.window.resolving_host = 'rare.epix';
    f.load.showResolveStatus(status);
    assert.doesNotMatch(f.renderedHTML(), /button-retry|Retry now/i, status.reason || status.state);
    assert.match(f.stages.at(-1).detail, /automatically|keep checking|continue when/i);
  }
});

test('receiving index.html before the other core files does not dismiss the loader', () => {
  const f = fixture(); f.wrapper.setXiteInfo(info(['file_done', 'index.html']));
  assert.equal(f.load.screen_visible, true);
  assert.equal(f.load.stage_index, 2, 'still downloading the remaining core files');
});

test('a retryable error document never counts as the loaded xite', () => {
  const f = fixture(); f.wrapper.xite_info = info(null);
  f.innerDocument.documentElement.dataset.epixLoadState = 'waiting';
  f.wrapper.onPageLoad();
  assert.equal(f.load.screen_visible, true);
  assert.equal(f.wrapper.inner_loaded, false);
});

test('automatic retry countdown follows the backend deadline without scheduling a retry itself', () => {
  const f = fixture(); let commands = 0; f.wrapper.ws.cmd = () => commands++;
  f.load.showCloneStatus({ state: 'waiting', attempt: 2, reason: 'no_peers', next_retry_at: 1006 });
  assert.match(f.context.$('.loading-retry-note').text(), /6s/);
  f.advance(5000);
  assert.match(f.context.$('.loading-retry-note').text(), /1s/);
  f.advance(5000);
  assert.match(f.context.$('.loading-retry-note').text(), /waiting/i);
  assert.equal(commands, 0, 'only the node schedules automatic retries');
  assert.equal(f.stages.at(-1).error, false);
});

test('a waiting state with no deadline never invents a countdown', () => {
  const f = fixture();
  f.load.showCloneStatus({ state: 'waiting', attempt: 1, reason: 'files_unavailable', next_retry_at: null });
  assert.match(f.context.$('.loading-retry-note').text(), /automatically/);
  assert.doesNotMatch(f.context.$('.loading-retry-note').text(), /\d+s/);
  assert.equal(f.load.retry_timer, null);
});

test('the next discovery attempt restores searching while retaining downloaded progress', () => {
  const f = fixture(); f.load.setTransfer(3, 10, 1);
  f.load.showCloneStatus({ state: 'downloading', attempt: 1 });
  f.load.showCloneStatus({ state: 'waiting', attempt: 1, next_retry_at: 1030 });
  f.load.showCloneStatus({ state: 'discovering', attempt: 2, peers: 0 });
  assert.equal(f.load.stage_index, 0);
  assert.equal(f.load.files_done, 3);
  assert.equal(f.context.$('.transfer-count').text(), '3 of 10 files');
  assert.equal(f.load.retry_timer, null);
  f.load.showCloneStatus({ state: 'waiting', attempt: 1, next_retry_at: 1030 });
  assert.equal(f.load.clone_status.attempt, 2, 'late events cannot resurrect an earlier retry');
});

test('automatic attempts retain the wrapper and saved files without issuing retry commands', () => {
  const f = fixture(), requests = [];
  f.wrapper.ws.cmd = (cmd) => requests.push(cmd);
  f.load.setTransfer(3, 6, 1);
  f.load.showCloneStatus({ state: 'waiting', attempt: 2, reason: 'files_unavailable', next_retry_at: 1003 });
  f.advance(3000);
  f.load.showCloneStatus({ state: 'discovering', attempt: 3, peers: 0 });
  assert.equal(f.context.$('.loading-attempt').text(), 'Attempt 3');
  assert.match(f.context.$('.loading-retry-note').text(), /automatically/i);
  assert.equal(f.context.$('.transfer-count').text(), '3 of 6 files');
  assert.equal(f.reloaded(), 0);
  assert.deepEqual(requests, []);
  assert.equal(f.load.screen_visible, true);
});

test('name lookup keeps observing backend recovery without a manual retry command', () => {
  const f = fixture(), requests = [];
  f.context.window.resolving_host = 'rare.epix';
  f.wrapper.ws.cmd = (cmd, params, callback) => {
    requests.push(cmd);
    callback({ state: 'waiting_network' });
  };
  f.wrapper.startResolvePoll();
  f.advance(5000);
  assert.equal(requests.length, 6);
  assert.ok(requests.every(cmd => cmd === 'resolveStatus'));
  assert.equal(f.reloaded(), 0);
});

test('a completed clone retries a waiting iframe once and dismisses only its real document', () => {
  const f = fixture(); let reloads = 0;
  f.innerDocument.documentElement.dataset.epixLoadState = 'waiting';
  f.wrapper.reloadIframe = () => reloads++;
  const complete = info(['clone_status', 'complete'], { tasks: 0, bad_files: 0, clone_status: { state: 'complete', attempt: 2 } });
  f.wrapper.setXiteInfo(complete); f.wrapper.setXiteInfo(complete);
  assert.equal(reloads, 1);
  assert.equal(f.load.screen_visible, true);
  delete f.innerDocument.documentElement.dataset.epixLoadState;
  f.wrapper.onPageLoad();
  assert.equal(f.load.screen_visible, false);
  assert.equal(f.wrapper.inner_loaded, true);
});

test('the first retry event reaches the loader before siteInfo establishes its address', () => {
  const f = fixture(); f.context.window.address = 'test.epix'; f.wrapper.address = null;
  f.wrapper.handleMessageWebsocket({ cmd: 'setSiteInfo', params: info(['clone_status', 'waiting'], {
    clone_status: { state: 'waiting', attempt: 1, reason: 'no_peers', next_retry_at: 1030 },
  }) });
  assert.equal(f.load.clone_status && f.load.clone_status.state, 'waiting');
  f.wrapper.handleMessageWebsocket({ cmd: 'setSiteInfo', params: info(['clone_status', 'complete'], {
    address: 'unrelated.epix', clone_status: { state: 'complete', attempt: 2 },
  }) });
  assert.equal(f.load.clone_status.state, 'waiting', 'other xites never change this loader');
});

test('a waiting iframe fetches the current clone status as soon as the websocket opens', () => {
  const f = fixture(); let refreshes = 0;
  f.wrapper.inner_loaded = false;
  f.wrapper.reloadXiteInfo = () => refreshes++;
  f.wrapper.onOpenWebsocket();
  assert.equal(refreshes, 1, 'waiting documents need an immediate snapshot too');
});

test('waiting and paused states never report a stale peer as actively sending files', () => {
  for (const state of ['waiting', 'paused', 'discovering']) {
    const f = fixture(); f.load.setTransfer(3, 6, 1);
    f.load.showCloneStatus({ state, attempt: 2, reason: 'files_unavailable', next_retry_at: 1030 });
    assert.equal(f.context.$('.transfer-count').text(), '3 of 6 files');
    assert.doesNotMatch(f.context.$('.transfer-peers').text(), /sending/i, state);
    f.load.showCloneStatus({ state: 'downloading', attempt: 2 });
    f.load.setTransfer(4, 6, 2);
    assert.equal(f.context.$('.transfer-peers').text(), '2 peers sending files');
  }
});

test('a reconnect snapshot restores saved download progress without waiting for another file event', () => {
  const f = fixture();
  f.wrapper.setXiteInfo(info(null, {
    started_task_num: 6, tasks: 3, bad_files: 3, peers_serving: 1,
    clone_status: { state: 'waiting', attempt: 3, reason: 'files_unavailable', next_retry_at: 1030 },
  }));
  assert.equal(f.context.$('.transfer-count').text(), '3 of 6 files');
  assert.equal(f.context.$('.transfer-peers').text(), 'Downloaded files are kept');
});
