import test from 'node:test';
import assert from 'node:assert/strict';
import { definitionOf } from '../src/catalog.mjs';
import { tokenScheme } from '../src/schemes/token.mjs';
import { oauthScheme, oauthClient } from '../src/schemes/oauth.mjs';
import { fixture, USER_A } from './helpers.mjs';

const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, text: JSON.stringify(body) });
// Notion as the catalog describes it: OAuth (with no app of Foundation's here) and a token its holder makes.
async function notion(t) {
  const definition = definitionOf('notion'), checks = [];
  const fetcher = async (url, options) => {
    checks.push({ url, options });
    const token = options.headers.authorization.replace('Bearer ', '');
    return token === 'ntn_revoked' ? reply(401, { code: 'unauthorized' }) : reply(200, { id: 'bot-' + token.slice(-4), bot: { workspace_name: 'Workspace ' + token.slice(-4) } });
  };
  const f = await fixture(t, { services: [{ definition, schemes: { oauth: oauthScheme(definition, oauthClient(definition, {})), token: tokenScheme(definition, { fetcher }) } }] });
  return { ...f, checks };
}

test('AIはトークンでの接続を依頼でき、持ち主が作ったトークンをサービスに確かめて預かり、AIは変数で受け取る', async t => {
  const f = await notion(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { service: 'notion', auth_scheme: 'token' }, purpose: '議事録をまとめます。',
    steps: ['Notionで内部インテグレーションを作ります。', '議事録のページをインテグレーションに共有します。'] } });
  assert.equal(asked.status, 201, asked.text);
  assert.deepEqual(asked.json.request.service.auth_schemes.token.fields.map(field => [field.name, field.secret]), [['token', true]]);
  assert.equal(asked.json.request.auth_scheme, 'token');
  assert.equal(asked.json.request.service.auth_schemes.token.verifies_token, true);
  const refused = await f.request('/v1/credentials', { method: 'POST', data: { request_id: asked.json.request.id, fields: { token: 'ntn_revoked' } } });
  assert.equal(refused.json.error.code, 'token_refused');
  const made = await f.request('/v1/credentials', { method: 'POST', data: { request_id: asked.json.request.id, fields: { token: 'ntn_first' } } });
  assert.equal(made.status, 200, made.text);
  assert.equal(made.json.credential.label, 'Workspace irst');
  assert.ok(made.json.credential.facts.checked_at > 0);
  assert.equal(f.checks.at(-1).options.headers['notion-version'], '2022-06-28');
  const done = (await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request;
  assert.equal(done.status, 'done'); assert.equal(done.result.credential_id, made.json.credential.id);
  const injected = await f.inject(made.json.credential, { token });
  assert.deepEqual(injected.json.injection.environment, { NOTION_TOKEN: 'ntn_first' });
  assert.doesNotMatch(JSON.stringify(done) + JSON.stringify(made.json), /ntn_first/);
  // A new token for the same bot keeps the credential; one for another bot is refused.
  const renewed = await f.request('/v1/credentials', { method: 'POST', data: { service: 'notion', auth_scheme: 'token', credential_id: made.json.credential.id, fields: { token: 'ntn_second_first' } } });
  assert.equal(renewed.status, 200, renewed.text);
  assert.equal(renewed.json.credential.id, made.json.credential.id);
  const other = await f.request('/v1/credentials', { method: 'POST', data: { service: 'notion', auth_scheme: 'token', credential_id: made.json.credential.id, fields: { token: 'ntn_other' } } });
  assert.equal(other.json.error.code, 'account_changed');
});

test('預けてあったシークレットを、IDと名前を保ったままサービスのトークンにする', async t => {
  const f = await notion(t);
  const kept = await f.keep('credential', 'notion/team', 'ntn_kept');
  const adopted = await f.request('/v1/credentials', { method: 'POST', data: { service: 'notion', auth_scheme: 'token', credential_id: kept.json.resource.id } });
  assert.equal(adopted.status, 200, adopted.text);
  assert.equal(adopted.json.credential.id, kept.json.resource.id);
  assert.equal(adopted.json.credential.name, 'notion/team');
  assert.equal(adopted.json.credential.service.id, 'notion');
  assert.equal((await f.request('/v1/resources/' + kept.json.resource.id + '/content')).status, 405, 'it is read no more, only injected');
  assert.deepEqual((await f.inject(adopted.json.credential)).json.injection.environment, { NOTION_TOKEN: 'ntn_kept' });
  assert.deepEqual(f.app.credentials.list(USER_A, { secret: true }), []);
});

test('Foundationのアプリがないサービスへのアプリなしの接続は、依頼の時点で断り、アプリの登録かトークンを案内する', async t => {
  const f = await notion(t), { token } = await f.issueKey();
  const refused = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { service: 'notion' }, purpose: '議事録をまとめます。' } });
  assert.equal(refused.status, 409);
  assert.equal(refused.json.error.code, 'app_required');
  assert.match(refused.json.error.message, /kind "app"/);
  assert.match(refused.json.error.message, /auth_scheme "token"/);
  const app = await f.request('/v1/resources?kind=app&name=Notion', { method: 'PUT', data: { service: 'notion', client_id: 'id', client_secret: 'secret' } });
  const accepted = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { service: 'notion', app: app.json.resource.id }, purpose: '議事録をまとめます。' } });
  assert.equal(accepted.status, 201, accepted.text);
});

test('AIが持ち主のためにサービスを定義でき、使われている間は消せない', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const definition = { version: 1, name: 'Notes', auth_schemes: { token: { fields: [{ name: 'token', label: 'APIトークン', secret: true }], injection: { NOTES_TOKEN: '{token}' } } } };
  const described = await f.request('/v1/resources?kind=service&name=Notes', { method: 'PUT', token, data: definition });
  assert.equal(described.status, 200, described.text);
  const service = described.json.resource.id;
  assert.equal(described.json.resource.service.name, 'Notes');
  const made = await f.request('/v1/credentials', { method: 'POST', data: { service, fields: { token: 'notes-token' } } });
  assert.equal(made.status, 200, made.text);
  assert.equal(made.json.credential.service.name, 'Notes');
  assert.deepEqual((await f.inject(made.json.credential, { token })).json.injection.environment, { NOTES_TOKEN: 'notes-token' });
  const inUse = await f.request('/v1/resources/' + service, { method: 'DELETE', data: {} });
  assert.equal(inUse.json.error.code, 'service_in_use');
  await f.request('/v1/resources/' + made.json.credential.id, { method: 'DELETE', data: { revoke: false } });
  assert.equal((await f.request('/v1/resources/' + service, { method: 'DELETE', data: {} })).status, 200);
});

const genericToken = { fields: [{ name: 'token', label: 'トークン', secret: true }], injection: { API_TOKEN: '{token}' } };
const genericOAuth = { authorize: 'https://service.example/authorize', token: 'https://service.example/token',
  scopes: { base: [] }, injection: { OAUTH_ACCESS_TOKEN: '{access_token}' } };
const register = (f, name, options = {}) => f.request('/v1/resources?kind=service&name=' + encodeURIComponent(name), {
  method: 'PUT', data: { version: 1, name }, ...options,
});

test('サービスを名前だけで登録し、接続方法を後から追加してトークンを利用する', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const registered = await register(f, '社内ツール', { token });
  assert.equal(registered.status, 200, registered.text);
  const service = registered.json.resource.id;
  assert.deepEqual(registered.json.resource.definition, { version: 1, name: '社内ツール', auth_schemes: {} });
  assert.deepEqual(registered.json.resource.service.auth_schemes, {});
  const listed = (await f.request('/v1/overview')).json.services.find(item => item.id === service);
  assert.equal(listed.service.name, '社内ツール');
  const pending = await f.request('/v1/credentials', { method: 'POST', data: { service } });
  assert.equal(pending.status, 409, pending.text);
  assert.equal(pending.json.error.code, 'auth_scheme_required');

  const configured = await f.request('/v1/resources/' + service, { method: 'PATCH', token, data: { auth_schemes: { token: genericToken } } });
  assert.equal(configured.status, 200, configured.text);
  assert.equal(configured.json.resource.id, service);
  assert.equal(configured.json.resource.service.auth_schemes.token.verifies_token, false);
  const connected = await f.request('/v1/credentials', { method: 'POST', data: { service, auth_scheme: 'token', fields: { token: 'private-token' } } });
  assert.equal(connected.status, 200, connected.text);
  assert.equal(connected.json.credential.facts.checked_at, null);
  assert.deepEqual((await f.inject(connected.json.credential, { token })).json.injection.environment, { API_TOKEN: 'private-token' });
});

test('名前だけのサービスへシークレットを移し、元のID・名前・値を利用する', async t => {
  const f = await fixture(t), kept = (await f.keep('credential', '任意の名前/a', 'kept-private-token')).json.resource;
  const registered = await register(f, '自作アプリ'), service = registered.json.resource.id;
  await f.request('/v1/resources/' + service, { method: 'PATCH', data: { auth_schemes: { token: genericToken } } });
  const result = await f.request('/v1/credentials', { method: 'POST', data: { service, auth_scheme: 'token', credential_id: kept.id } });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.credential.id, kept.id);
  assert.equal(result.json.credential.name, kept.name);
  assert.equal(result.json.credential.facts.checked_at, null);
  assert.deepEqual((await f.inject(result.json.credential)).json.injection.environment, { API_TOKEN: 'kept-private-token' });
  const overview = (await f.request('/v1/overview')).json;
  assert.equal(overview.credentials.find(item => item.id === kept.id).service.id, service);
  assert.doesNotMatch(JSON.stringify(overview), /kept-private-token/);
});

test('OAuthとトークンを別々に追加し、既存の接続とサービス情報を保つ', async t => {
  const f = await fixture(t);
  const registered = await register(f, 'Notes', { data: { version: 1, name: 'Notes', api: 'https://service.example/api', docs: 'https://service.example/docs' } });
  const service = registered.json.resource.id;
  const results = await Promise.all([genericOAuth, genericToken].map((scheme, index) => f.request('/v1/resources/' + service, {
    method: 'PATCH', data: { auth_schemes: { [index ? 'token' : 'oauth']: scheme } },
  })));
  for (const result of results) assert.equal(result.status, 200, result.text);
  const connected = await f.request('/v1/credentials', { method: 'POST', data: { service, auth_scheme: 'token', fields: { token: 'notes-token' } } });
  assert.equal(connected.status, 200, connected.text);
  const repeated = await f.request('/v1/resources/' + service, { method: 'PATCH', data: { auth_schemes: { token: { injection: genericToken.injection, fields: genericToken.fields } } } });
  assert.equal(repeated.status, 200, repeated.text);
  assert.deepEqual(repeated.json.resource.definition.auth_schemes, { oauth: genericOAuth, token: genericToken });
  assert.equal(repeated.json.resource.definition.api, 'https://service.example/api');
  assert.equal(repeated.json.resource.definition.docs, 'https://service.example/docs');
  const conflict = await f.request('/v1/resources/' + service, { method: 'PATCH', data: {
    name: '別の名前', auth_schemes: { token: { ...genericToken, injection: { DIFFERENT_TOKEN: '{token}' } } },
  } });
  assert.equal(conflict.status, 409, conflict.text);
  assert.equal(conflict.json.error.code, 'auth_scheme_exists');
  assert.equal((await f.request('/v1/resources/' + service)).json.resource.name, 'Notes');
  assert.deepEqual((await f.inject(connected.json.credential)).json.injection.environment, { API_TOKEN: 'notes-token' });
});

test('同名サービスの新規登録が競合したとき、保存済みの設定を保つ', async t => {
  const f = await fixture(t), data = { version: 1, name: 'Notes', auth_schemes: { token: genericToken } };
  const first = await register(f, 'Notes', { data, headers: { 'if-none-match': '*' } });
  assert.equal(first.status, 200, first.text);
  const conflict = await register(f, 'Notes', { headers: { 'if-none-match': '*' } });
  assert.equal(conflict.status, 412, conflict.text);
  assert.equal(conflict.json.error.code, 'name_taken');
  assert.deepEqual((await f.request('/v1/resources/' + first.json.resource.id)).json.resource.definition, data);
});

test('不正な接続方法の追加を断り、変更前の名前と設定を保つ', async t => {
  const f = await fixture(t), service = (await register(f, 'Notes')).json.resource.id;
  for (const auth_schemes of [null, [], { token: {} }, { unknown: genericToken }]) {
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
  const result = await f.request('/v1/resources/' + service, { method: 'PATCH', data: { auth_schemes: { token: genericToken } } });
  assert.equal(result.status, 403, result.text);
  await f.login();
  assert.deepEqual((await f.request('/v1/resources/' + service)).json.resource.definition.auth_schemes, {});
});

test('入力欄から付けたアカウント名と、接続先でのトークン検証を区別する', async t => {
  const f = await fixture(t);
  const definition = { version: 1, name: '社内ツール', auth_schemes: { token: {
    ...genericToken, fields: [...genericToken.fields, { name: 'account', label: 'アカウント', secret: false }],
    identity: { from: 'fields', id: 'account' },
  } } };
  const registered = await register(f, '社内ツール', { data: definition });
  assert.equal(registered.status, 200, registered.text);
  assert.equal(registered.json.resource.service.auth_schemes.token.verifies_token, false);
  const connected = await f.request('/v1/credentials', { method: 'POST', data: {
    service: registered.json.resource.id, auth_scheme: 'token', fields: { token: 'private-token', account: '任意のアカウント名' },
  } });
  assert.equal(connected.status, 200, connected.text);
  assert.equal(connected.json.credential.facts.account, '任意のアカウント名');
  assert.equal(connected.json.credential.facts.checked_at, null);
});
