import test from 'node:test';
import assert from 'node:assert/strict';
import { cloudflareOauth } from '../src/adapters/cloudflare/index.mjs';
import { FakeCloudflare } from '../src/adapters/cloudflare/fixture.mjs';
import { openrouterOauth } from '../src/adapters/openrouter/index.mjs';
import { FakeOpenRouter } from '../src/adapters/openrouter/fixture.mjs';
import { fixture, FakeGoogle, USER_A, entry } from './helpers.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';

const WORK = { service: 'cloudflare', client_id: 'work-app-id', client_secret: 'work-app-secret' };

// Foundation's own Cloudflare app is configured here too; the owner's apps sit beside it.
async function withApps(t, { offered = true } = {}) {
  const cloudflare = new FakeCloudflare();
  if (!offered) { cloudflare.enabled = false; cloudflare.clientId = ''; cloudflare.clientSecret = ''; }
  cloudflare.scopes = 'offline_access user-details.read dns.write';
  const f = await fixture(t, { services: [entry('cloudflare', { oauth: cloudflareOauth(cloudflare) }), entry('openrouter', { oauth: openrouterOauth(new FakeOpenRouter()) }), entry('google', { oauth: googleOauth(new FakeGoogle()) })] });
  const register = (name, values = WORK) => f.request('/v1/resources?kind=app&name=' + encodeURIComponent(name), { method: 'PUT', data: values });
  async function connect(input = {}, code = 'personal') {
    const started = await f.request('/v1/connections', { method: 'POST', data: { service: 'cloudflare', ...input } });
    assert.equal(started.status, 200, started.text);
    const url = new URL(started.json.url), done = await f.callback(url, code);
    assert.match(done.headers.get('location'), /result=connected/, done.headers.get('location'));
    return { url, connection: (await f.request('/v1/resources?kind=connection')).json.resources.filter(item => item.service?.id === 'cloudflare').at(-1) };
  }
  const tokenCalls = () => cloudflare.calls.filter(call => call.url.endsWith('/token')).map(call => call.options.body);
  return { ...f, cloudflare, register, connect, tokenCalls };
}

test('アプリは持ち物の一つとして登録し、Foundationのアプリと並べて一覧に出し、秘密は誰にも返さない', async t => {
  const f = await withApps(t), { token } = await f.issueKey();
  const made = await f.register('仕事用');
  assert.equal(made.status, 200, made.text);
  assert.equal(made.json.resource.kind, 'app'); assert.equal(made.json.resource.client_id, 'work-app-id');
  const listed = (await f.request('/v1/resources?kind=app', { token })).json.resources;
  assert.deepEqual(listed.filter(app => app.service.id === 'cloudflare').map(app => [app.name, app.service.id, app.foundation]).sort(), [['Foundationのアプリ', 'cloudflare', true], ['仕事用', 'cloudflare', false]]);
  assert.equal((await f.request('/v1/resources/' + made.json.resource.id + '/content')).status, 405);
  const everything = JSON.stringify([made.json, listed]) + await f.visible();
  assert.doesNotMatch(everything, /work-app-secret/);
  assert.equal((await f.register('OpenRouter', { service: 'openrouter', client_id: 'a', client_secret: 'b' })).json.error.code, 'app_unsupported');
  assert.equal((await f.register('足りない', { service: 'cloudflare', client_id: 'a' })).json.error.code, 'invalid_app');
});

test('持ち主のアプリで接続し、更新・つなぎ直し・取り消しもそのアプリで行う。運営のアプリがなくても使える', async t => {
  const f = await withApps(t, { offered: false }), app = (await f.register('仕事用')).json.resource;
  const { url, connection } = await f.connect({ app: app.id });
  assert.equal(url.searchParams.get('client_id'), 'work-app-id');
  assert.equal(f.tokenCalls()[0].get('client_secret'), 'work-app-secret');
  assert.deepEqual(connection.app, { id: app.id, name: '仕事用', foundation: false });
  f.expire(connection.id);
  assert.equal((await f.inject(connection)).status, 200);
  assert.equal(f.tokenCalls().at(-1).get('grant_type'), 'refresh_token');
  assert.equal(f.tokenCalls().at(-1).get('client_secret'), 'work-app-secret');
  const again = await f.connect({ connection_id: connection.id });
  assert.equal(again.url.searchParams.get('client_id'), 'work-app-id', 'reconnecting keeps the app the connection was made through');
  const removed = await f.request('/v1/resources/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  assert.equal(f.cloudflare.calls.find(call => call.url.endsWith('/revoke')).options.body.get('client_id'), 'work-app-id');
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'cloudflare' } })).status, 503, "without an app, Foundation's is used, and here it has none");
});

test('アプリの秘密を新しくしても、そのアプリの接続はそのまま使える', async t => {
  const f = await withApps(t), app = (await f.register('仕事用')).json.resource, { connection } = await f.connect({ app: app.id });
  const changed = await f.request('/v1/resources/' + app.id, { method: 'PATCH', data: { client_id: 'work-app-id', client_secret: 'rotated-secret' } });
  assert.equal(changed.status, 200, changed.text);
  assert.equal(changed.json.resource.id, app.id);
  f.expire(connection.id);
  assert.equal((await f.inject(connection)).status, 200);
  assert.equal(f.tokenCalls().at(-1).get('client_secret'), 'rotated-secret');
});

test('アプリを消すと、そのアプリの接続は権限を保ったままつなぎ直し待ちになり、別のアプリで同じ接続としてつなぎ直せる', async t => {
  const f = await withApps(t), app = (await f.register('仕事用')).json.resource;
  const { connection } = await f.connect({ app: app.id, scopes: ['dns.write'] });
  const refused = await f.request('/v1/resources/' + app.id, { method: 'DELETE', data: {} });
  assert.equal(refused.status, 409); assert.equal(refused.json.error.code, 'app_in_use');
  assert.equal(refused.json.error.connections, 1); assert.deepEqual(refused.json.error.yours.map(row => row.id), [connection.id]);
  const removed = await f.request('/v1/resources/' + app.id, { method: 'DELETE', data: { confirm: true } });
  assert.equal(removed.json.connections_stopped, 1);
  const stopped = (await f.request('/v1/resources?kind=connection')).json.resources.find(item => item.id === connection.id);
  assert.equal(stopped.status, 'reconnect_required');
  assert.equal(stopped.app, null, 'it names no app, rather than one it was not made through');
  assert.deepEqual(stopped.facts.requested_scopes, ['dns.write', 'offline_access', 'user-details.read']);
  assert.equal((await f.inject(connection)).status, 409);
  const other = (await f.register('個人用', { ...WORK, client_id: 'personal-app-id' })).json.resource;
  // Changing the app a connection goes through is shown to the owner before it is kept.
  const started = await f.request('/v1/connections', { method: 'POST', data: { service: 'cloudflare', connection_id: connection.id, app: other.id } });
  const url = new URL(started.json.url);
  assert.equal(url.searchParams.get('client_id'), 'personal-app-id');
  const review = new URL((await f.callback(url, 'personal')).headers.get('location'), f.base);
  assert.equal(review.searchParams.get('result'), 'review');
  const shown = await f.request('/v1/connections/confirmation?state=' + review.searchParams.get('state'));
  assert.ok(shown.json.changes.some(change => change.label === 'OAuthアプリ'));
  assert.equal((await f.request('/v1/connections/confirmation', { method: 'POST', data: { state: review.searchParams.get('state') } })).status, 200);
  const again = (await f.request('/v1/resources?kind=connection')).json.resources.find(item => item.id === connection.id);
  assert.equal(again.id, connection.id); assert.equal(again.status, 'usable');
  assert.deepEqual(again.app, { id: other.id, name: '個人用', foundation: false });
});

test('線を引かれた人は、そのアプリで自分のアカウントを接続できるが、秘密は読めず、変えるには編集の線が要る', async t => {
  const f = await withApps(t), app = (await f.register('会社のアプリ')).json.resource;
  await f.signin('member@example.test');
  const member = (await f.request('/v1/principals/me')).json.principal.id;
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'cloudflare', app: app.id } })).status, 403);
  await f.signin();
  assert.equal((await f.request('/v1/principals/' + member + '/relations', { method: 'POST', data: { relation: 'viewer', object_type: 'resource', object_id: app.id } })).status, 201);
  await f.signin('member@example.test');
  assert.deepEqual((await f.request('/v1/resources?kind=app')).json.resources.filter(item => !item.foundation).map(item => item.name), ['会社のアプリ']);
  const { url, connection } = await f.connect({ app: app.id }, 'work');
  assert.equal(url.searchParams.get('client_id'), 'work-app-id');
  assert.equal(connection.label, 'work@example.test');
  assert.equal((await f.request('/v1/resources/' + app.id + '/content')).status, 405);
  assert.equal((await f.request('/v1/resources/' + app.id, { method: 'PATCH', data: { client_id: 'x', client_secret: 'y' } })).status, 403);
  assert.equal((await f.request('/v1/resources/' + app.id, { method: 'DELETE', data: { confirm: true } })).status, 403);
  // The app is the owner's to let be used, every time: the line taken back stops the connection through it.
  assert.equal((await f.inject(connection)).status, 200);
  await f.signin();
  assert.equal((await f.request('/v1/principals/' + member + '/relations', { method: 'DELETE', data: { relation: 'viewer', object_type: 'resource', object_id: app.id } })).status, 200);
  await f.signin('member@example.test');
  const stopped = await f.inject(connection);
  assert.equal(stopped.status, 403, stopped.text); assert.equal(stopped.json.error.code, 'app_not_usable');
  await f.signin();
  assert.equal((await f.request('/v1/principals/' + member + '/relations', { method: 'POST', data: { relation: 'viewer', object_type: 'resource', object_id: app.id } })).status, 201);
  await f.signin('member@example.test');
  assert.equal((await f.inject(connection)).status, 200, 'drawn again, it goes on');
  await f.signin();
  const owner = await f.request('/v1/resources/' + app.id, { method: 'DELETE', data: {} });
  assert.equal(owner.json.error.connections, 1, "the member's connection counts");
  assert.deepEqual(owner.json.error.yours, [], "but is not named to the owner");
});

test('AIはアプリの登録を依頼でき、持ち主が秘密を入力し、AIはアプリのIDだけを受け取って接続を依頼する', async t => {
  const f = await withApps(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'app', service: 'cloudflare' }], binding_message: 'メール転送を設定できるアプリを使います。' } });
  assert.equal(asked.status, 201, asked.text);
  assert.deepEqual(asked.json.request.service.auth_schemes.oauth.app_fields.map(field => [field.name, Boolean(field.sealed)]), [['client_id', false], ['client_secret', true]]);
  const done = await f.request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: { name: 'メール用', client_id: 'mail-app-id', client_secret: 'mail-app-secret' } });
  assert.equal(done.status, 200, done.text);
  const result = (await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request;
  assert.equal(result.status, 'granted');
  assert.doesNotMatch(JSON.stringify(result), /mail-app-secret/);
  const appId = result.result.app_id;
  const connect = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'connection', service: 'cloudflare', app: appId, scopes: ['dns.write'] }], binding_message: 'DNSを設定します。' } });
  assert.equal(connect.status, 201, connect.text);
  assert.deepEqual(connect.json.request.app, { id: appId, name: 'メール用', foundation: false });
  const started = await f.request('/v1/connections', { method: 'POST', data: { service: 'cloudflare', request_id: connect.json.request.id } });
  assert.equal(new URL(started.json.url).searchParams.get('client_id'), 'mail-app-id');
  const wrong = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'connection', service: 'google', app: appId }], binding_message: 'x' } });
  assert.equal(wrong.json.error.code, 'app_mismatch');
  assert.equal((await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'app', service: 'openrouter' }], binding_message: 'x' } })).json.error.code, 'app_unsupported');
  assert.equal(f.app.apps.list(USER_A).length, 1);
});
