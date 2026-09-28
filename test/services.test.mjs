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
  const refused = await f.request('/v1/credentials', { method: 'POST', data: { request_id: asked.json.request.id, fields: { token: 'ntn_revoked' } } });
  assert.equal(refused.json.error.code, 'token_refused');
  const made = await f.request('/v1/credentials', { method: 'POST', data: { request_id: asked.json.request.id, fields: { token: 'ntn_first' } } });
  assert.equal(made.status, 200, made.text);
  assert.equal(made.json.credential.label, 'Workspace irst');
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
