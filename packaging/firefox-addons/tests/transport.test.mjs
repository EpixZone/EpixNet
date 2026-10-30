import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createHmac, webcrypto } from 'node:crypto';
import { LIMITS, macInput } from '../policy.sys.mjs';

const source = fs.readFileSync(new URL('../manager.sys.mjs', import.meta.url), 'utf8');
const body = source.slice(source.indexOf('function hex(bytes)'), source.indexOf('function managedDigest('));
const requestLimit = 6 * 1024 * 1024;
const credential = '1'.repeat(64), clientId = '2'.repeat(64);
function fixture() {
  const requests = [];
  const window = {
    closed: false, crypto: webcrypto, AbortController,
    async fetch(endpoint, options) {
      const { headers, body } = options;
      requests.push(body);
      const fields = [clientId, headers['X-Epix-Addon-Nonce'], headers['X-Epix-Addon-Time']];
      assert.equal(headers['X-Epix-Addon-Mac'], createHmac('sha256', credential)
        .update(macInput('EpixNet addon broker request v1\0', [...fields, body])).digest('hex'));
      const reply = new TextEncoder().encode('{"ok":true,"result":{"accepted":true}}');
      const signature = createHmac('sha256', credential)
        .update(macInput('EpixNet addon broker response v1\0', [...fields, reply], 200)).digest('hex');
      let read = false;
      return {
        status: 200,
        headers: { get: name => name === 'Content-Length' ? String(reply.length) : signature },
        body: { getReader: () => ({
          async read() { if (read) return { done: true }; read = true; return { value: reply, done: false }; },
          async cancel() {}, releaseLock() {},
        }) },
      };
    },
  };
  const context = vm.createContext({
    Services: { wm: { getMostRecentWindow: () => window } },
    LIMITS, macInput, TextEncoder, TextDecoder, Uint8Array, setTimeout, clearTimeout,
    HEX: /^[0-9a-f]{64}$/, credential,
    client: { client_id: clientId, endpoint: 'http://127.0.0.1:42111/EpixNet-Internal/AddonBroker' },
  });
  vm.runInContext(body, context);
  return { send: value => context.request(value), requests };
}

test('full accepted inventory survives worst-case JSON escaping without truncation', async () => {
  const addons = Array.from({ length: 2048 }, (_, index) => ({
    addon_id: String(index).padStart(4, '0') + '\u0001'.repeat(251),
    version: '\u0001'.repeat(128), archive_sha256: 'a'.repeat(64), enabled: true,
  }));
  const value = { command: 'reconcile', inventory: { addons, has_pending_installs: false } };
  const expected = Buffer.from(JSON.stringify(value));
  assert.ok(expected.length > 65536 && expected.length < requestLimit);
  const transport = fixture();
  assert.equal((await transport.send(value)).accepted, true);
  assert.equal(transport.requests.length, 1);
  assert.deepEqual(Buffer.from(transport.requests[0]), expected);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(transport.requests[0])), value);
});

test('request transport accepts its exact UTF-8 byte limit and rejects one extra byte before fetch', async () => {
  assert.equal(LIMITS.request, requestLimit);
  // Exercise the transport boundary independently of the broker's command schema.
  const value = { command: 'prepare', source_url: '' };
  const overhead = Buffer.byteLength(JSON.stringify(value));
  value.source_url = 'x'.repeat(requestLimit - overhead);
  const transport = fixture();
  assert.equal((await transport.send(value)).accepted, true);
  assert.equal(transport.requests[0].byteLength, requestLimit);
  await assert.rejects(transport.send({ ...value, source_url: value.source_url + 'x' }), /request exceeds its limit/);
  assert.equal(transport.requests.length, 1);
});

test('request limit counts UTF-8 bytes rather than JavaScript character length', async () => {
  const value = { command: 'prepare', source_url: 'é'.repeat(requestLimit / 2) };
  assert.ok(JSON.stringify(value).length < requestLimit);
  assert.ok(Buffer.byteLength(JSON.stringify(value)) > requestLimit);
  const transport = fixture();
  await assert.rejects(transport.send(value), /request exceeds its limit/);
  assert.equal(transport.requests.length, 0);
});
