import test from 'node:test';
import assert from 'node:assert/strict';
import { googleOauth } from '../src/connectors/google/index.mjs';
import { openrouterOauth } from '../src/connectors/openrouter/index.mjs';
import { FakeOpenRouter } from '../src/connectors/openrouter/fixture.mjs';
import { fixture, FakeGoogle } from './helpers.mjs';

const READONLY = 'https://www.googleapis.com/auth/gmail.readonly';

async function scoped(t) {
  const google = new FakeGoogle();
  return fixture(t, { google, connectors: [googleOauth(google), openrouterOauth(new FakeOpenRouter())] });
}

test('頼む権限は接続先の権限名の配列で受け付け、重複を除いて並べる', async t => {
  const f = await scoped(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { connector: 'google.oauth', scopes: [READONLY, 'openid', READONLY] }, purpose: 'メールを読みます。' } });
  assert.equal(asked.status, 201, asked.text);
  assert.deepEqual(asked.json.request.input.scopes, ['https://www.googleapis.com/auth/gmail.readonly', 'openid']);
});

test('形の正しくない権限の指定を、依頼でも接続の開始でも断る', async t => {
  const f = await scoped(t), { token } = await f.issueKey();
  for (const scopes of ['openid', [''], ['a b'], ['a"b'], [42], Array.from({ length: 101 }, (_, n) => 'scope.' + n)]) {
    const asked = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { connector: 'google.oauth', scopes }, purpose: 'x' } });
    assert.equal(asked.json.error.code, 'invalid_scopes', JSON.stringify(scopes));
    const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'google.oauth', scopes } });
    assert.equal(started.json.error.code, 'invalid_scopes', JSON.stringify(scopes));
  }
});

test('権限を指定できない接続に権限を頼むと、何も始めずに断る', async t => {
  const f = await scoped(t);
  const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'openrouter.oauth', scopes: ['anything'] } });
  assert.equal(started.status, 400); assert.equal(started.json.error.code, 'scopes_unsupported');
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'openrouter.oauth' } })).status, 200);
});

test('接続の一覧で、頼める権限の基本と説明の場所を示す', async t => {
  const f = await scoped(t);
  const catalog = (await f.request('/v1/connectors', { anonymous: true })).json.connectors;
  const google = catalog.find(item => item.id === 'google.oauth'), openrouter = catalog.find(item => item.id === 'openrouter.oauth');
  assert.deepEqual(google.scopes.base, ['openid', 'https://www.googleapis.com/auth/userinfo.email']);
  assert.match(google.scopes.documentation_url, /^https:\/\/developers\.google\.com\//);
  assert.equal(openrouter.scopes, null);
});
