const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../crates/epix-plugins/media/sidebar/all.js'), 'utf8');
const start = source.indexOf('Sidebar.prototype.addPeer = function()');
const end = source.indexOf('\n    };', start);
assert.ok(start >= 0 && end > start);
function fixture(value) {
  const context = vm.createContext({});
  vm.runInContext('var Sidebar = function() {};\n' + source.slice(start, end + 7), context);
  const calls = [], notices = [];
  let callback, refreshes = 0;
  const input = {val(next) { if (next !== undefined) value = next; return value; }};
  const instance = Object.create(context.Sidebar.prototype);
  Object.assign(instance, {
    tag: {find(selector) { assert.equal(selector, '#peer-endpoint'); return input; }},
    wrapper: {xite_info: {address:'current-xite'}, ws: {cmd(command, args, cb) {calls.push({command,...args}); callback=cb;}}, notifications:{add(...args) {notices.push(args);}}},
    updateHtmlTag() {refreshes++;}
  });
  return {instance,calls,notices, reply(result) {callback(result);}, value:()=>value, refreshes:()=>refreshes};
}
test('sidebar submits one trimmed endpoint for its selected xite and refreshes on success', () => {
  const f=fixture('  rns:0123456789abcdef0123456789abcdef  ');
  f.instance.addPeer(); f.instance.addPeer();
  assert.deepEqual(f.calls,[{command:'peerAdd',peer:'rns:0123456789abcdef0123456789abcdef',site_address:'current-xite'}]);
  f.reply('updated'); assert.equal(f.value(),''); assert.equal(f.refreshes(),1);
});
test('sidebar keeps failed endpoint editable and escapes untrusted server errors', () => {
  const f=fixture('bad-peer'); f.instance.addPeer(); f.reply({error:'<img src=x onerror="bad">'});
  assert.equal(f.value(),'bad-peer'); assert.equal(f.refreshes(),0);
  assert.equal(f.notices[0][2],'&lt;img src=x onerror=&quot;bad&quot;&gt;');
  f.instance.addPeer(); assert.equal(f.calls.length,2);
});
test('empty endpoint does not send a command', () => {const f=fixture('  ');f.instance.addPeer();assert.equal(f.calls.length,0);});
