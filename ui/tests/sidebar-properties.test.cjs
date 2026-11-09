const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../crates/epix-plugins/media/sidebar/all.js'), 'utf8');
function instance(method) {
  const start = source.indexOf(`Sidebar.prototype.${method} = function`);
  const end = source.indexOf('\n    };', start);
  assert.ok(start >= 0 && end > start);
  const context = vm.createContext({});
  vm.runInContext('var Sidebar = function() {};\n' + source.slice(start, end + 7), context);
  return Object.create(context.Sidebar.prototype);
}

test('rapid peer-map choices save in order and finish with the latest preference', () => {
  const sidebar = instance('savePeerMapPreference'), requests = [];
  sidebar.peer_map_open = false;
  sidebar.wrapper = {ws: {cmd(command, params, callback) { requests.push({command, value: params[0].sidebar_peer_map_open, callback}); }}, notifications: {add() { assert.fail('unexpected save failure'); }}};
  sidebar.savePeerMapPreference();
  sidebar.peer_map_open = true;
  sidebar.savePeerMapPreference();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].command, 'userSetGlobalSettings');
  assert.equal(requests[0].value, false);
  requests[0].callback('ok');
  assert.equal(requests.length, 2);
  assert.equal(requests[1].value, true);
  requests[1].callback('ok');
  assert.equal(sidebar.peer_map_saving, false);
});

test('failed preference saves report failure without reverting the visible choice or retrying forever', () => {
  const sidebar = instance('savePeerMapPreference'), notices = [];
  let callback, requests = 0;
  sidebar.peer_map_open = false;
  sidebar.wrapper = {ws: {cmd(command, params, done) { requests++; callback = done; }}, notifications: {add(...args) { notices.push(args); }}};
  sidebar.savePeerMapPreference();
  callback({error: 'unavailable'});
  assert.equal(sidebar.peer_map_open, false);
  assert.equal(sidebar.peer_map_saving, false);
  assert.equal(requests, 1);
  assert.equal(notices[0][1], 'error');
});

test('content choices highlight only the exact editable path, including after a custom path', () => {
  const sidebar = instance('updateContentSelection');
  let value = 'content.json';
  const choices = ['content.json', 'data/users/content.json'].map(content => ({
    selected: false, pressed: null,
    getAttribute(name) { assert.equal(name, 'data-content-path'); return content; },
    setAttribute(name, pressed) { assert.equal(name, 'aria-pressed'); this.pressed = pressed; },
    classList: {toggle(name, selected) { assert.equal(name, 'selected'); choices.find(choice => choice.classList === this).selected = selected; }},
  }));
  sidebar.tag = {find(selector) {
    if (selector === '#input-contents') return {val: () => value};
    assert.equal(selector, '.contents-content');
    return {each(callback) { choices.forEach(choice => callback.call(choice)); }};
  }};
  sidebar.updateContentSelection();
  assert.deepEqual(choices.map(choice => choice.pressed), ['true', 'false']);
  value = 'data/users/content.json'; sidebar.updateContentSelection();
  assert.deepEqual(choices.map(choice => choice.selected), [false, true]);
  value = 'custom/content.json'; sidebar.updateContentSelection();
  assert.deepEqual(choices.map(choice => choice.pressed), ['false', 'false']);
  value = 'content.json'; sidebar.updateContentSelection();
  assert.deepEqual(choices.map(choice => choice.selected), [true, false]);
});
