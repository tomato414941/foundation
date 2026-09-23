import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

const KEY = 'fdn_' + 'r'.repeat(43);

test('lets the owner change what something is called, without the value being handed back', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets/cloudflare/registrar-api-token?secret=true',
    { method: 'PUT', token: KEY, raw: 'cf-token-value', type: 'text/plain' });

  const moved = await f.request('/api/secrets/' + encodeURIComponent('cloudflare/registrar-api-token'),
    { method: 'PATCH', data: { path: 'cloudflare/cloudflare-api-token' } });
  assert.equal(moved.status, 200, moved.text);
  assert.equal(moved.json.secret.path, 'cloudflare/cloudflare-api-token');

  // The name a command receives it under follows the new path.
  const delivered = await f.request('/v1/deliver', { method: 'POST', token: KEY, anonymous: true, data: { paths: ['cloudflare/cloudflare-api-token'] } });
  assert.deepEqual(delivered.json.delivery.environment, { CLOUDFLARE_API_TOKEN: 'cf-token-value' });
});

test('refuses to move something onto a name already in use', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  for (const path of ['a/one', 'a/two']) {
    await f.request('/v1/secrets/' + path + '?secret=true', { method: 'PUT', token: KEY, raw: 'x', type: 'text/plain' });
  }
  const refused = await f.request('/api/secrets/' + encodeURIComponent('a/one'), { method: 'PATCH', data: { path: 'a/two' } });
  assert.equal(refused.status, 409);
  assert.equal(refused.json.error.code, 'path_taken');
});

test('hands the same value over under whatever names the caller asks for', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets/github/token?secret=true', { method: 'PUT', token: KEY, raw: 'ghp_value', type: 'text/plain' });
  const delivered = await f.request('/v1/deliver', { method: 'POST', token: KEY, anonymous: true,
    data: { paths: [{ path: 'github/token', as: 'GH_TOKEN' }, { path: 'github/token', as: 'GITHUB_TOKEN' }] } });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.delivery.environment, { GH_TOKEN: 'ghp_value', GITHUB_TOKEN: 'ghp_value' });
});

test('says so when a path gives no usable name', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets/notes/2026-09-23?secret=true', { method: 'PUT', token: KEY, raw: 'x', type: 'text/plain' });
  const refused = await f.request('/v1/deliver', { method: 'POST', token: KEY, anonymous: true, data: { paths: ['notes/2026-09-23'] } });
  assert.equal(refused.status, 400);
  assert.equal(refused.json.error.code, 'no_variable');
});

test('asks for several things at once, and keeps them together or not at all', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  const asked = await f.request('/v1/access-requests', { method: 'POST', token: KEY, anonymous: true, data: {
    store: [
      { path: 'apple/auth-key', label: '.p8 の中身', multiline: true, type: 'text/plain' },
      { path: 'apple/key-id', label: 'Key ID', secret: false },
      { path: 'apple/issuer-id', label: 'Issuer ID', secret: false },
    ],
    purpose: 'ビルドの提出に使います。' } });
  assert.equal(asked.status, 201, asked.text);
  assert.equal(asked.json.request.kind, 'store');
  assert.deepEqual(asked.json.request.store.map(one => one.path), ['apple/auth-key', 'apple/key-id', 'apple/issuer-id']);

  // One missing value keeps none of them.
  const partial = await f.request('/api/access-requests/' + asked.json.request.id + '/store',
    { method: 'POST', data: { contents: { 'apple/auth-key': 'KEY', 'apple/key-id': 'ABC123' } } });
  assert.equal(partial.status, 400);
  assert.deepEqual((await f.request('/v1/secrets', { token: KEY, anonymous: true })).json.secrets, []);

  const stored = await f.request('/api/access-requests/' + asked.json.request.id + '/store',
    { method: 'POST', data: { contents: { 'apple/auth-key': 'KEY', 'apple/key-id': 'ABC123', 'apple/issuer-id': 'UUID' } } });
  assert.equal(stored.status, 200, stored.text);
  const kept = await f.request('/v1/secrets', { token: KEY, anonymous: true });
  assert.deepEqual(kept.json.secrets.map(one => one.path), ['apple/auth-key', 'apple/issuer-id', 'apple/key-id']);
  assert.equal(kept.json.secrets.find(one => one.path === 'apple/key-id').readable, true, 'an identifier is not a secret');
  assert.equal(kept.json.secrets.find(one => one.path === 'apple/auth-key').readable, false);
});

test('lets the owner put something there themselves', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  const put = await f.request('/api/secrets/' + encodeURIComponent('aws/session-token'),
    { method: 'PUT', raw: 'sh-token-value', type: 'text/plain' });
  assert.equal(put.status, 200, put.text);
  assert.equal(put.json.secret.path, 'aws/session-token');
  assert.equal(put.json.secret.readable, false, 'a secret unless said otherwise');

  const delivered = await f.request('/v1/deliver', { method: 'POST', token: KEY, anonymous: true, data: { paths: ['aws/session-token'] } });
  assert.deepEqual(delivered.json.delivery.environment, { SESSION_TOKEN: 'sh-token-value' });

  const open = await f.request('/api/secrets/' + encodeURIComponent('aws/region') + '?secret=false',
    { method: 'PUT', raw: 'ap-northeast-1', type: 'text/plain' });
  assert.equal(open.json.secret.readable, true);
});
