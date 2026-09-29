import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './helpers.mjs';

const oauth = { authorize: 'https://service.example/authorize', token: 'https://service.example/token',
  scopes: { base: [] }, identity: { from: 'token', id: 'account' }, injection: { NOTES_TOKEN: '{access_token}' } };
const register = (f, name, options = {}) => f.request('/v1/resources?kind=service&name=' + encodeURIComponent(name), {
  method: 'PUT', data: { version: 1, name }, ...options,
});
const serviceFetcher = async () => ({ ok: true, status: 200, text: JSON.stringify({ access_token: 'notes-access', refresh_token: 'notes-refresh', account: 'one' }) });

test('サービスを名前だけで登録し、後からOAuthを設定して接続する', async t => {
  const f = await fixture(t, { serviceFetcher }), { token } = await f.issueKey();
  const registered = await register(f, '社内ツール', { token });
  assert.equal(registered.status, 200, registered.text);
  const service = registered.json.resource.id;
  assert.deepEqual(registered.json.resource.definition, { version: 1, name: '社内ツール', auth_schemes: {} });
  assert.equal((await f.request('/v1/overview')).json.services.find(item => item.id === service).service.name, '社内ツール');
  const pending = await f.request('/v1/credentials', { method: 'POST', data: { service } });
  assert.equal(pending.status, 409, pending.text);
  assert.equal(pending.json.error.code, 'auth_scheme_required');
  const configured = await f.request('/v1/resources/' + service, { method: 'PATCH', token, data: { auth_schemes: { oauth } } });
  assert.equal(configured.status, 200, configured.text);
  assert.equal(configured.json.resource.id, service);

  const app = await f.request('/v1/resources?kind=app&name=Notes', { method: 'PUT', data: { service, client_id: 'notes-client', client_secret: 'notes-secret' } });
  assert.equal(app.status, 200, app.text);
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { service, app: app.json.resource.id }, purpose: 'ノートを取得します。' } });
  assert.equal(asked.status, 201, asked.text);
  const started = await f.request('/v1/credentials', { method: 'POST', data: { request_id: asked.json.request.id } });
  assert.equal(started.status, 200, started.text);
  const callback = await f.callback(new URL(started.json.url), 'notes-code');
  assert.match(callback.headers.get('location'), /result=connected/);
  const completed = (await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request;
  assert.equal(completed.status, 'done');
  const connected = (await f.request('/v1/resources/' + completed.result.credential_id)).json.resource;
  assert.equal(connected.service.id, service);
  const injected = await f.inject(connected, { token });
  assert.equal(injected.status, 200, injected.text);
  assert.deepEqual(injected.json.injection.environment, { NOTES_TOKEN: 'notes-access' });

  assert.equal((await f.request('/v1/resources/' + service, { method: 'DELETE', data: {} })).json.error.code, 'service_in_use');
  await f.request('/v1/resources/' + connected.id, { method: 'DELETE', data: { revoke: false } });
  await f.request('/v1/resources/' + app.json.resource.id, { method: 'DELETE', data: {} });
  assert.equal((await f.request('/v1/resources/' + service, { method: 'DELETE', data: {} })).status, 200);
});

test('OAuthアプリが必要な依頼では登録先を示し、登録後に接続を依頼する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const registered = await register(f, 'Notes', { data: { version: 1, name: 'Notes', auth_schemes: { oauth } } });
  const service = registered.json.resource.id;
  const request = input => f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input, purpose: 'ノートを取得します。' } });
  const refused = await request({ service });
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.json.error.code, 'app_required');
  const app = await f.request('/v1/resources?kind=app&name=Notes', { method: 'PUT', data: { service, client_id: 'own-client', client_secret: 'own-secret' } });
  assert.equal((await request({ service, app: app.json.resource.id })).status, 201);
});

test('OAuth設定の追加と再送でサービス情報を保ち、異なる設定への上書きは競合として返す', async t => {
  const f = await fixture(t);
  const registered = await register(f, 'Notes', { data: { version: 1, name: 'Notes', api: 'https://service.example/api', docs: 'https://service.example/docs' } });
  const service = registered.json.resource.id;
  for (const result of await Promise.all([1, 2].map(() => f.request('/v1/resources/' + service, { method: 'PATCH', data: { auth_schemes: { oauth } } })))) {
    assert.equal(result.status, 200, result.text);
    assert.deepEqual(result.json.resource.definition.auth_schemes, { oauth });
    assert.equal(result.json.resource.definition.api, 'https://service.example/api');
    assert.equal(result.json.resource.definition.docs, 'https://service.example/docs');
  }
  const conflict = await f.request('/v1/resources/' + service, { method: 'PATCH', data: {
    name: '別の名前', auth_schemes: { oauth: { ...oauth, token: 'https://service.example/other' } },
  } });
  assert.equal(conflict.status, 409, conflict.text);
  assert.equal(conflict.json.error.code, 'auth_scheme_exists');
  assert.equal((await f.request('/v1/resources/' + service)).json.resource.name, 'Notes');
});

test('同名サービスの新規登録が競合したとき、保存済みの設定を保つ', async t => {
  const f = await fixture(t), data = { version: 1, name: 'Notes', auth_schemes: { oauth } };
  const first = await register(f, 'Notes', { data, headers: { 'if-none-match': '*' } });
  assert.equal(first.status, 200, first.text);
  const conflict = await register(f, 'Notes', { headers: { 'if-none-match': '*' } });
  assert.equal(conflict.status, 412, conflict.text);
  assert.equal(conflict.json.error.code, 'name_taken');
  assert.deepEqual((await f.request('/v1/resources/' + first.json.resource.id)).json.resource.definition, data);
});

test('不正な接続方法の追加を断り、変更前の名前と設定を保つ', async t => {
  const f = await fixture(t), service = (await register(f, 'Notes')).json.resource.id;
  for (const auth_schemes of [null, [], { oauth: {} }, { unknown: oauth }]) {
    const result = await f.request('/v1/resources/' + service, { method: 'PATCH', data: { name: '変更後', auth_schemes } });
    assert.equal(result.status, 400, result.text);
    const saved = (await f.request('/v1/resources/' + service)).json.resource;
    assert.equal(saved.name, 'Notes');
    assert.deepEqual(saved.definition.auth_schemes, {});
  }
});

test('他の利用者による接続方法の追加を断り、持ち主のサービスを保護する', async t => {
  const f = await fixture(t), service = (await register(f, 'Notes')).json.resource.id;
  await f.login('other@example.test');
  const result = await f.request('/v1/resources/' + service, { method: 'PATCH', data: { auth_schemes: { oauth } } });
  assert.equal(result.status, 403, result.text);
  await f.login();
  assert.deepEqual((await f.request('/v1/resources/' + service)).json.resource.definition.auth_schemes, {});
});
