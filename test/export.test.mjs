import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

const KEY = 'fdn_' + 'e'.repeat(43);

test('hands the owner everything they have, secrets included', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets?name=notes/plan', { method: 'PUT', token: KEY, raw: 'read me', type: 'text/plain' });
  await f.request('/v1/secrets?name=keys/token', { method: 'PUT', token: KEY, raw: 'sh-secret-value', type: 'text/plain' });

  const exported = await f.request('/v1/export');
  assert.equal(exported.status, 200, exported.text);
  assert.match(exported.headers.get('content-disposition'), /attachment; filename="foundation-\d{4}-\d{2}-\d{2}\.json"/);
  const value = exported.json;
  assert.equal(value.owner, 'owner@example.test');
  const byPath = Object.fromEntries(value.secrets.map(entry => [entry.name, entry]));
  assert.deepEqual(Object.keys(byPath).sort(), ['keys/token', 'notes/plan']);
  assert.equal(Buffer.from(byPath['notes/plan'].content, 'base64').toString(), 'read me');
  assert.equal(Buffer.from(byPath['keys/token'].content, 'base64').toString(), 'sh-secret-value');
  
  assert.equal(value.principals.length, 1);
});

test('keeps the export to the owner\'s own session', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets?name=keys/token', { method: 'PUT', token: KEY, raw: 'sh-secret-value', type: 'text/plain' });

  const asAKey = await f.request('/v1/export', { token: KEY, anonymous: true });
  assert.equal(asAKey.status, 403);
  assert.ok(!asAKey.text.includes('sh-secret-value'));

  await f.login('other@example.test');
  const asAnother = await f.request('/v1/export');
  assert.equal(asAnother.status, 200);
  assert.deepEqual(asAnother.json.secrets, []);
});
