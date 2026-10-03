import test from 'node:test';
import assert from 'node:assert/strict';
import { open, openContent } from '../cli/envelope.mjs';
import { fixture } from './helpers.mjs';
import { entry } from '../src/catalog.mjs';

const tokenFixture = t => fixture(t, { services: [entry('github'), entry('kintone'), entry('openrouter'), entry('zendesk')] });
const paste = (f, data, options = {}) => f.request('/v1/connections', { method: 'POST', data: { auth_scheme: 'token', ...data }, ...options });

test('貼られたトークンをその場で接続にし、定義どおりの環境変数でAIに渡す', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const made = await paste(f, { service: 'github', fields: { token: ' ghp_first ' } });
  assert.equal(made.status, 201, made.text);
  const connection = made.json.connection;
  assert.equal(connection.name, 'GitHubのトークン');
  assert.equal(connection.auth_scheme, 'token');
  assert.equal(connection.status, 'usable');
  assert.equal(connection.subject, null);
  assert.deepEqual(connection.facts, {});
  const injected = await f.inject(connection);
  assert.equal(injected.status, 200, injected.text);
  assert.deepEqual(injected.json.injection.environment, { GH_TOKEN: 'ghp_first', GITHUB_TOKEN: 'ghp_first' });
});

test('トークンの接続に名前を付け、同じサービスにいくつでも接続を作る', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const work = await paste(f, { service: 'github', name: '仕事用', fields: { token: 'ghp_work' } });
  const personal = await paste(f, { service: 'github', name: '個人用', fields: { token: 'ghp_personal' } });
  assert.equal(work.status, 201, work.text);
  assert.equal(personal.status, 201, personal.text);
  const listed = (await f.request('/v1/resources?kind=connection')).json.resources.filter(item => item.service.id === 'github').map(item => item.name).sort();
  assert.deepEqual(listed, ['仕事用', '個人用']);
});

test('既存の接続に貼り直すと、IDと名前を保ったまま値を差し替える', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const made = (await paste(f, { service: 'github', name: '仕事用', fields: { token: 'ghp_old' } })).json.connection;
  const replaced = await paste(f, { service: 'github', connection_id: made.id, fields: { token: 'ghp_new' } });
  assert.equal(replaced.status, 200, replaced.text);
  assert.equal(replaced.json.connection.id, made.id);
  assert.equal(replaced.json.connection.name, '仕事用');
  assert.equal(replaced.json.connection.generation, made.generation + 1);
  assert.equal((await f.inject(made)).json.injection.environment.GH_TOKEN, 'ghp_new');
});

test('鍵で動くAIも、接続を任されていればトークンで接続する', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const agent = await f.issueKey();
  const refused = await paste(f, { service: 'github', fields: { token: 'ghp_agent' } }, { token: agent.token, anonymous: true });
  assert.equal(refused.status, 403);
  const given = await f.request('/v1/principals/' + agent.id + '/relations', { method: 'POST', data: { relation: 'connection_connect_grant', object_type: 'principal', object_id: agent.acts_for[0] } });
  assert.equal(given.status, 201, given.text);
  const made = await paste(f, { service: 'github', fields: { token: 'ghp_agent' } }, { token: agent.token, anonymous: true });
  assert.equal(made.status, 201, made.text);
  assert.equal(made.json.connection.owner_id, agent.acts_for[0]);
});

test('トークンの項目が定義に合わなければ、接続を作らずに断る', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  for (const fields of [{}, { token: '' }, { token: 'a\nb' }, { token: 'ok', extra: 'x' }]) {
    const refused = await paste(f, { service: 'github', fields });
    assert.equal(refused.status, 400, JSON.stringify(fields));
    assert.equal(refused.json.error.code, 'invalid_fields');
  }
  const wrongDomain = await paste(f, { service: 'kintone', fields: { domain: 'example.com', token: 'k' } });
  assert.equal(wrongDomain.status, 400);
  const withScopes = await paste(f, { service: 'github', scopes: ['repo'], fields: { token: 'ghp' } });
  assert.equal(withScopes.status, 400);
  assert.equal((await f.request('/v1/resources?kind=connection')).json.resources.length, 0);
});

test('トークンそのものは見せず、ドメインのような秘密でない項目だけを接続の説明に示す', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const made = await paste(f, { service: 'kintone', fields: { domain: 'example.cybozu.com', token: 'kintone-secret' } });
  assert.equal(made.status, 201, made.text);
  assert.deepEqual(made.json.connection.facts, { domain: 'example.cybozu.com' });
  const listed = await f.request('/v1/resources?kind=connection');
  assert.doesNotMatch(listed.text, /kintone-secret/);
  assert.deepEqual((await f.inject(made.json.connection)).json.injection.environment, { KINTONE_DOMAIN: 'example.cybozu.com', KINTONE_API_TOKEN: 'kintone-secret' });
});

test('書き出しには、接続の状態を封じたまま封筒とともに含め、持ち主の鍵で開くと貼ったトークンがある', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  await paste(f, { service: 'github', fields: { token: 'ghp_export' } });
  const exported = await f.request('/v1/export');
  assert.equal(exported.status, 200, exported.text);
  const [kept] = exported.json.connections, own = await f.keyOf({});
  assert.equal(kept.encoding, 'base64url');
  assert.doesNotMatch(exported.text, /ghp_export/, 'nothing goes out in the clear');
  const state = JSON.parse(openContent(open(Buffer.from(kept.envelopes[own.id], 'base64url'), own.privateKey), Buffer.from(kept.content, 'base64url')).toString());
  assert.deepEqual(state.private_state.fields, { token: 'ghp_export' });
});

test('サービスの説明に、トークンで接続するときの項目と作る場所を示す', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const catalog = (await f.request('/v1/services')).json.services;
  const github = catalog.find(item => item.id === 'github').auth_schemes.token;
  assert.equal(github.console, 'https://github.com/settings/tokens');
  assert.deepEqual(github.fields.map(field => field.name), ['token']);
  assert.deepEqual(github.variables, ['GH_TOKEN', 'GITHUB_TOKEN']);
});

test('トークンでの接続を頼まれた人が貼ると、依頼は叶い、頼んだAIに接続のIDを返す', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const agent = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, anonymous: true,
    data: { authorization_details: [{ type: 'connection', service: 'github', auth_scheme: 'token' }], binding_message: 'リポジトリを読みます。' } });
  assert.equal(asked.status, 201, asked.text);
  const made = await paste(f, { request_id: asked.json.request.id, fields: { token: 'ghp_asked' } });
  assert.equal(made.status, 201, made.text);
  const seen = await f.request('/v1/requests/' + asked.json.request.id, { token: agent.token, anonymous: true });
  assert.equal(seen.json.request.status, 'granted');
  assert.deepEqual(seen.json.request.result, { connection_id: made.json.connection.id });
});

test('サインインで接続するサービスでも、サービスが出すキーを貼って接続し、同じ環境変数で渡す', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const made = await paste(f, { service: 'openrouter', fields: { token: 'sk-or-v1-pasted' } });
  assert.equal(made.status, 201, made.text);
  assert.equal(made.json.connection.name, 'OpenRouterのトークン');
  assert.deepEqual((await f.inject(made.json.connection)).json.injection.environment, { OPENROUTER_API_KEY: 'sk-or-v1-pasted' });
});

test('サイトやメールと組にして使うトークンは、それぞれを別の環境変数で渡す', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const made = await paste(f, { service: 'zendesk', fields: { subdomain: 'example', email: 'owner@example.test', token: 'zendesk-token' } });
  assert.equal(made.status, 201, made.text);
  assert.deepEqual((await f.inject(made.json.connection)).json.injection.environment,
    { ZENDESK_SUBDOMAIN: 'example', ZENDESK_EMAIL: 'owner@example.test', ZENDESK_API_TOKEN: 'zendesk-token' });
});

test('トークンの欄はシークレットを参照でき、使うたびに中身と線を見て、参照されている間は消せない', async t => {
  const f = await tokenFixture(t);
  await f.signin();
  const secret = (await f.keep('secret', 'gh', 'ghp_referenced')).json.resource;
  const made = await paste(f, { service: 'github', name: '参照', fields: { token: { reference: secret.id } } });
  assert.equal(made.status, 201, made.text);
  assert.deepEqual(made.json.connection.references, [secret.id]);
  assert.doesNotMatch(made.text, /ghp_referenced/);
  const delivered = await f.request('/v1/injections', { method: 'POST', data: { names: [{ id: made.json.connection.id }] } });
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(delivered.json.injection.environment.GITHUB_TOKEN, 'ghp_referenced');
  // The secret changes: the connection follows.
  await f.request('/v1/resources/' + secret.id + '/content', { method: 'PUT', raw: 'ghp_rotated' });
  assert.equal((await f.request('/v1/injections', { method: 'POST', data: { names: [{ id: made.json.connection.id }] } })).json.injection.environment.GITHUB_TOKEN, 'ghp_rotated');
  // Referenced, it is not removed; the connection replaced with a value, it is.
  const refused = await f.request('/v1/resources/' + secret.id, { method: 'DELETE', data: {} });
  assert.equal(refused.status, 409); assert.equal(refused.json.error.code, 'secret_in_use');
  assert.equal((await paste(f, { service: 'github', connection_id: made.json.connection.id, fields: { token: 'ghp_value' } })).status, 200);
  assert.deepEqual((await f.request('/v1/resources/' + made.json.connection.id)).json.resource.references, []);
  assert.equal((await f.request('/v1/resources/' + secret.id, { method: 'DELETE', data: {} })).status, 200);
  // A secret one may not read, or that does not exist, is not referred to.
  assert.equal((await paste(f, { service: 'github', fields: { token: { reference: '11111111-1111-4111-8111-111111111111' } } })).status, 404);
  assert.equal((await paste(f, { service: 'github', fields: { token: { reference: 'nope' } } })).status, 400);
});

test('別の持ち主のシークレットを参照する接続は、その線が消えた次の使用から止まる', async t => {
  const f = await tokenFixture(t), other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const theirs = { token: other.json.token, anonymous: true, as: other.json.principal.id };
  await f.allowFoundation(theirs);
  const secret = (await f.keep('secret', 'shared', 'ghp_shared')).json.resource;
  f.app.principals.relate(other.json.principal.id, 'viewer', 'resource', secret.id);
  const made = await paste(f, { service: 'github', name: '借り物', fields: { token: { reference: secret.id } } }, theirs);
  assert.equal(made.status, 201, made.text);
  const inject = () => f.request('/v1/injections', { ...theirs, method: 'POST', data: { names: [{ id: made.json.connection.id }] } });
  assert.equal((await inject()).json.injection.environment.GITHUB_TOKEN, 'ghp_shared');
  f.app.principals.unrelate(other.json.principal.id, 'viewer', 'resource', secret.id);
  const stopped = await inject();
  assert.equal(stopped.status, 404, stopped.text);
  f.app.principals.relate(other.json.principal.id, 'viewer', 'resource', secret.id);
  assert.equal((await inject()).status, 200, 'drawn again, it goes on');
});
