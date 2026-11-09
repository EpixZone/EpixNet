// Exercise production action methods with controlled command completion.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../crates/epix-plugins/media/sidebar/all.js'), 'utf8');
const methods = ['t', 'escapeText', 'notify', 'notifyError', 'setActionBusy', 'sign', 'withSigningKey'].map(name => {
  const start = source.indexOf(`Sidebar.prototype.${name} = function(`);
  const end = source.indexOf('\n    };', start);
  assert.ok(start >= 0 && end > start, `production ${name} method exists`);
  return source.slice(start, end + 7);
}).join('\n');

function fixture() {
  const context = vm.createContext({});
  vm.runInContext('var Sidebar = function() {};\n' + methods, context);
  const sidebar = Object.create(context.Sidebar.prototype);
  const requests = [], prompts = [], progress = [], notices = [];
  sidebar.wrapper = {
    xite_info: {auth_address: 'selected-author', privatekey: false},
    ws: {cmd(command, params, done) {requests.push({command, params, done});}},
    displayPrompt(message, type, label, placeholder, done) {prompts.push({message, type, done});},
    displayProgress(...args) {progress.push(args);},
    notifications: {add(...args) {notices.push(args);}},
  };
  return {sidebar, requests, prompts, progress, notices};
}

test('repeated signing clicks share one outstanding rules lookup', () => {
  const f = fixture(), keys = [];
  f.sidebar.withSigningKey('content.json', key => keys.push(key));
  f.sidebar.withSigningKey('content.json', key => keys.push(key));
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].command, 'fileRules');
  assert.equal(f.requests[0].params.inner_path, 'content.json');
  f.requests[0].done({signers: ['selected-author']});
  assert.deepEqual(keys, [null]);
  assert.equal(f.sidebar.signing_key_pending, false);
});

test('dismissing the password prompt without its callback permits another signing attempt', () => {
  const f = fixture(), keys = [];
  f.sidebar.withSigningKey('content.json', key => keys.push(key));
  f.requests[0].done({signers: ['owner']});
  assert.equal(f.prompts.length, 1);
  assert.equal(f.prompts[0].type, 'password');
  // Wrapper.displayPrompt dismissal deliberately does not call done.
  f.sidebar.withSigningKey('content.json', key => keys.push(key));
  assert.equal(f.requests.length, 2, 'a dismissed prompt cannot strand the lookup guard');
  f.requests[1].done({signers: ['owner']});
  assert.equal(f.prompts.length, 2);
  f.prompts[1].done('supplied-private-key');
  assert.deepEqual(keys, ['supplied-private-key']);
});

test('failed rules lookup releases the guard and reports the error', () => {
  const f = fixture();
  f.sidebar.withSigningKey('content.json', () => assert.fail('invalid rules cannot sign'));
  f.requests[0].done({error: '<unavailable>'});
  assert.equal(f.sidebar.signing_key_pending, false);
  assert.equal(f.notices[0][1], 'error');
  assert.ok(f.notices[0][2].includes('&lt;unavailable&gt;'));
  f.sidebar.withSigningKey('content.json', () => {});
  assert.equal(f.requests.length, 2);
});

test('signing suppresses duplicate commands and lookups until completion, then allows retry', () => {
  const f = fixture();
  f.sidebar.sign('content.json', 'stored');
  f.sidebar.sign('content.json', 'stored');
  f.sidebar.withSigningKey('content.json', () => assert.fail('already signing'));
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].command, 'siteSign');
  assert.equal(f.requests[0].params.privatekey, 'stored');
  assert.equal(f.sidebar.pending_actions['#button-sign-publish'], true);
  f.requests[0].done({error: 'Signing rejected'});
  assert.equal(f.sidebar.pending_actions['#button-sign-publish'], undefined);
  assert.equal(f.progress.at(-1)[2], -1);
  assert.equal(f.notices.at(-1)[1], 'error');
  f.sidebar.sign('content.json', 'stored');
  assert.equal(f.requests.length, 2);
  f.requests[1].done('ok');
  assert.equal(f.progress.at(-1)[2], 100);
  assert.equal(f.sidebar.pending_actions['#button-sign-publish'], undefined);
});

test('repeated prompt submissions cannot send duplicate siteSign requests', () => {
  const f = fixture();
  f.sidebar.withSigningKey('content.json', key => f.sidebar.sign('content.json', key));
  f.requests[0].done({signers: ['owner']});
  f.prompts[0].done('supplied-private-key');
  f.prompts[0].done('supplied-private-key');
  assert.deepEqual(f.requests.map(request => request.command), ['fileRules', 'siteSign']);
  assert.equal(f.requests[1].params.inner_path, 'content.json');
  f.requests[1].done('ok');
  assert.equal(f.progress.at(-1)[2], 100);
});
