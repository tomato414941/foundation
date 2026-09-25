import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

const KEY = 'fdn_' + 'r'.repeat(43);

test('lets the owner change what something is called, without the value being handed back', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets?name=cloudflare/registrar-api-token',
    { method: 'PUT', token: KEY, raw: 'cf-token-value', type: 'text/plain' });

  const moved = await f.request('/v1/secrets?name=' + encodeURIComponent('cloudflare/registrar-api-token'),
    { method: 'PATCH', data: { name: 'cloudflare/cloudflare-api-token' } });
  assert.equal(moved.status, 200, moved.text);
  assert.equal(moved.json.secret.name, 'cloudflare/cloudflare-api-token');

  // Renaming storage does not decide the environment variable.
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token: KEY, anonymous: true, data: { names: [{ name: 'cloudflare/cloudflare-api-token', as: 'CLOUDFLARE_API_TOKEN' }] } });
  assert.deepEqual(delivered.json.delivery.environment, { CLOUDFLARE_API_TOKEN: 'cf-token-value' });
});

test('refuses to move something onto a name already in use', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  for (const path of ['a/one', 'a/two']) {
    await f.request('/v1/secrets?name=' + path + '', { method: 'PUT', token: KEY, raw: 'x', type: 'text/plain' });
  }
  const refused = await f.request('/v1/secrets?name=' + encodeURIComponent('a/one'), { method: 'PATCH', data: { name: 'a/two' } });
  assert.equal(refused.status, 409);
  assert.equal(refused.json.error.code, 'name_taken');
});

test('hands the same value over under whatever names the caller asks for', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets?name=github/token', { method: 'PUT', token: KEY, raw: 'ghp_value', type: 'text/plain' });
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token: KEY, anonymous: true,
    data: { names: [{ name: 'github/token', as: 'GH_TOKEN' }, { name: 'github/token', as: 'GITHUB_TOKEN' }] } });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.delivery.environment, { GH_TOKEN: 'ghp_value', GITHUB_TOKEN: 'ghp_value' });
});

test('requires the caller to specify the delivery variable', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets?name=notes/2026-09-23', { method: 'PUT', token: KEY, raw: 'x', type: 'text/plain' });
  const refused = await f.request('/v1/deliveries', { method: 'POST', token: KEY, anonymous: true, data: { names: ['notes/2026-09-23'] } });
  assert.equal(refused.status, 400);
  assert.equal(refused.json.error.code, 'no_variable');
});

test('asks for several things at once, and keeps them together or not at all', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  const asked = await f.request('/v1/requests', { method: 'POST', token: KEY, anonymous: true, data: {
    store: [
      { name: 'apple/auth-key', label: '.p8 の中身', multiline: true, type: 'text/plain' },
      { name: 'apple/key-id', label: 'Key ID', readable: true },
      { name: 'apple/issuer-id', label: 'Issuer ID', readable: true },
    ],
    purpose: 'ビルドの提出に使います。' } });
  assert.equal(asked.status, 201, asked.text);
  assert.equal(asked.json.request.kind, 'store');
  assert.deepEqual(asked.json.request.store.map(one => one.name), ['apple/auth-key', 'apple/key-id', 'apple/issuer-id']);

  // One missing value keeps none of them.
  const partial = await f.request('/v1/requests/' + asked.json.request.id + '/done',
    { method: 'POST', data: { entries: [{ name: 'apple/auth-key', content: 'KEY' }, { name: 'apple/key-id', content: 'ABC123' }] } });
  assert.equal(partial.status, 400);
  assert.deepEqual((await f.request('/v1/secrets', { token: KEY, anonymous: true })).json.secrets, []);

  const stored = await f.request('/v1/requests/' + asked.json.request.id + '/done',
    { method: 'POST', data: { entries: [{ name: 'apple/auth-key', content: 'KEY' }, { name: 'apple/key-id', content: 'ABC123' }, { name: 'apple/issuer-id', content: 'UUID' }] } });
  assert.equal(stored.status, 200, stored.text);
  const kept = await f.request('/v1/secrets', { token: KEY, anonymous: true });
  assert.deepEqual(kept.json.secrets.map(one => one.name), ['apple/auth-key', 'apple/issuer-id', 'apple/key-id']);
  assert.equal((await f.request('/v1/secrets?name=apple%2Fkey-id', { token: KEY, anonymous: true })).status, 200, 'an identifier asked for as readable is on a line to the asker');
  assert.equal((await f.request('/v1/secrets?name=apple%2Fauth-key', { token: KEY, anonymous: true })).status, 403);
});

test('lets the owner put something there themselves', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  const put = await f.request('/v1/secrets?name=' + encodeURIComponent('aws/session-token'),
    { method: 'PUT', raw: 'sh-token-value', type: 'text/plain' });
  assert.equal(put.status, 200, put.text);
  assert.equal(put.json.secret.name, 'aws/session-token');

  const delivered = await f.request('/v1/deliveries', { method: 'POST', token: KEY, anonymous: true, data: { names: [{ name: 'aws/session-token', as: 'SESSION_TOKEN' }] } });
  assert.deepEqual(delivered.json.delivery.environment, { SESSION_TOKEN: 'sh-token-value' });

  const open = await f.request('/v1/secrets?name=' + encodeURIComponent('aws/region') + '',
    { method: 'PUT', raw: 'ap-northeast-1', type: 'text/plain' });
});
