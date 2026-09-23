import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

const KEY = 'fdn_' + 'r'.repeat(43);

test('lets the owner change what something is called and how it reaches a command', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  await f.request('/v1/secrets/cloudflare/registrar-api-token?env=CLOUDFLARE_API_TOKEN&secret=true',
    { method: 'PUT', token: KEY, raw: 'cf-token-value', type: 'text/plain' });

  const moved = await f.request('/api/secrets/' + encodeURIComponent('cloudflare/registrar-api-token'),
    { method: 'PATCH', data: { path: 'cloudflare/registrar', env: 'CF_REGISTRAR_TOKEN' } });
  assert.equal(moved.status, 200, moved.text);
  assert.equal(moved.json.secret.path, 'cloudflare/registrar');
  assert.equal(moved.json.secret.env, 'CF_REGISTRAR_TOKEN');

  const delivered = await f.request('/v1/deliver', { method: 'POST', token: KEY, anonymous: true, data: { paths: ['cloudflare/registrar'] } });
  assert.deepEqual(delivered.json.delivery.environment, { CF_REGISTRAR_TOKEN: 'cf-token-value' });
});

test('refuses to move something onto a name already in use', async (t) => {
  const f = await fixture(t);
  await f.approveKey(KEY);
  for (const path of ['a/one', 'a/two']) {
    await f.request('/v1/secrets/' + path + '?env=ONE&secret=true', { method: 'PUT', token: KEY, raw: 'x', type: 'text/plain' });
  }
  const refused = await f.request('/api/secrets/' + encodeURIComponent('a/one'), { method: 'PATCH', data: { path: 'a/two', env: 'ONE' } });
  assert.equal(refused.status, 409);
  assert.equal(refused.json.error.code, 'path_taken');
});
