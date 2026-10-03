import test from 'node:test';
import assert from 'node:assert/strict';
import { open, openContent } from '../cli/envelope.mjs';
import { fixture, USER_A } from './helpers.mjs';

let KEY;

test('hands the owner everything they have, secrets included', async (t) => {
  const f = await fixture(t);
  KEY = (await f.approveKey()).token;
  await f.request('/v1/principals/me/resources?kind=secret&name=notes/plan', { method: 'PUT', token: KEY, raw: 'read me', type: 'text/plain' });
  await f.request('/v1/principals/me/resources?kind=secret&name=keys/token', { method: 'PUT', token: KEY, raw: 'sh-secret-value', type: 'text/plain' });

  const exported = await f.request('/v1/export');
  assert.equal(exported.status, 200, exported.text);
  assert.match(exported.headers.get('content-disposition'), /attachment; filename="foundation-\d{4}-\d{2}-\d{2}\.json"/);
  const value = exported.json;
  assert.equal(value.owner, 'owner@example.test');
  const byPath = Object.fromEntries(value.secrets.map(entry => [entry.name, entry]));
  assert.deepEqual(Object.keys(byPath).sort(), ['keys/token', 'notes/plan']);
  // Sealed as kept: opened with the owner's own key, from the envelope made for them.
  const own = await f.keyOf({});
  const opened = entry => openContent(open(Buffer.from(entry.envelopes[USER_A], 'base64url'), own.privateKey), Buffer.from(entry.content, 'base64url')).toString();
  assert.equal(byPath['notes/plan'].encoding, 'base64url');
  assert.equal(opened(byPath['notes/plan']), 'read me');
  assert.equal(opened(byPath['keys/token']), 'sh-secret-value');
  
  assert.equal(value.principals.length, 1);
});

test('keeps the export to the owner\'s own session', async (t) => {
  const f = await fixture(t);
  KEY = (await f.approveKey()).token;
  await f.request('/v1/principals/me/resources?kind=secret&name=keys/token', { method: 'PUT', token: KEY, raw: 'sh-secret-value', type: 'text/plain' });

  const asAKey = await f.request('/v1/export', { token: KEY, anonymous: true });
  assert.equal(asAKey.status, 403);
  assert.ok(!asAKey.text.includes('sh-secret-value'));

  await f.signin('other@example.test');
  const asAnother = await f.request('/v1/export');
  assert.equal(asAnother.status, 200);
  assert.deepEqual(asAnother.json.secrets, []);
});
