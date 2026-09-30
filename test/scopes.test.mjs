import test from 'node:test';
import assert from 'node:assert/strict';
import { googleOauth } from '../src/adapters/google/index.mjs';
import { openrouterOauth } from '../src/adapters/openrouter/index.mjs';
import { FakeOpenRouter } from '../src/adapters/openrouter/fixture.mjs';
import { fixture, FakeGoogle, entry } from './helpers.mjs';

const READONLY = 'https://www.googleapis.com/auth/gmail.readonly';

async function scoped(t) {
  const google = new FakeGoogle();
  return fixture(t, { google, services: [entry('google', { oauth: googleOauth(google) }), entry('openrouter', { oauth: openrouterOauth(new FakeOpenRouter()) })] });
}

test('頼む権限は接続先の権限名の配列で受け付け、重複を除いて並べる', async t => {
  const f = await scoped(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'connection', service: 'google', scopes: [READONLY, 'openid', READONLY] }], binding_message: 'メールを読みます。' } });
  assert.equal(asked.status, 201, asked.text);
  assert.deepEqual(asked.json.request.authorization_details[0].scopes, ['https://www.googleapis.com/auth/gmail.readonly', 'openid']);
});

test('形の正しくない権限の指定を、依頼でも接続の開始でも断る', async t => {
  const f = await scoped(t), { token } = await f.issueKey();
  for (const scopes of ['openid', [''], ['a b'], ['a"b'], [42], Array.from({ length: 101 }, (_, n) => 'scope.' + n)]) {
    const asked = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'connection', service: 'google', scopes }], binding_message: 'x' } });
    assert.equal(asked.json.error.code, 'invalid_scopes', JSON.stringify(scopes));
    const started = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', scopes } });
    assert.equal(started.json.error.code, 'invalid_scopes', JSON.stringify(scopes));
  }
});

test('権限を指定できない接続に権限を頼むと、何も始めずに断る', async t => {
  const f = await scoped(t);
  const started = await f.request('/v1/connections', { method: 'POST', data: { service: 'openrouter', scopes: ['anything'] } });
  assert.equal(started.status, 400); assert.equal(started.json.error.code, 'scopes_unsupported');
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'openrouter' } })).status, 200);
});

test('接続の一覧で、頼める権限の基本と説明の場所を示す', async t => {
  const f = await scoped(t);
  const catalog = (await f.request('/v1/services', { anonymous: true })).json.services;
  const google = catalog.find(item => item.id === 'google').auth_schemes.oauth, openrouter = catalog.find(item => item.id === 'openrouter').auth_schemes.oauth;
  assert.deepEqual(google.scopes.base, ['openid', 'https://www.googleapis.com/auth/userinfo.email']);
  assert.match(google.scopes.documentation_url, /^https:\/\/developers\.google\.com\//);
  assert.equal(openrouter.scopes, null);
});
