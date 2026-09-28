import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { oauth2 } from './index.mjs';
import { FakeOAuth2Service, SERVICE } from './fixture.mjs';
import { fixture } from '../../../test/helpers.mjs';

const APP = { connector: 'oauth2', service_name: 'Notes', client_id: 'notes-client', client_secret: 'notes-secret', ...SERVICE };

async function generic(t, app = APP) {
  const service = new FakeOAuth2Service(), f = await fixture(t, { connectors: [oauth2(service.client())] });
  const registered = await f.request('/v1/holdings?kind=app&name=Notes', { method: 'PUT', data: app });
  assert.equal(registered.status, 200, registered.text);
  const appId = registered.json.holding.id;
  async function start(input = {}) {
    const started = await f.request('/v1/connections', { method: 'POST', data: { connector: 'oauth2', app: appId, ...input } });
    assert.equal(started.status, 200, started.text);
    return new URL(started.json.url);
  }
  const connections = async () => (await f.request('/v1/overview')).json.grants.filter(item => item.connector === 'oauth2');
  async function connect(account = 'personal', input = {}) {
    const before = new Set((await connections()).map(item => item.id));
    const url = await start(input), done = await f.callback(url, account);
    assert.match(done.headers.get('location'), /connection=connected/, done.headers.get('location'));
    return (await connections()).find(item => input.connection_id ? item.id === input.connection_id : !before.has(item.id));
  }
  const tokenCalls = () => service.calls.filter(call => call.url === SERVICE.token_url);
  return { ...f, service, appId, start, connect, tokenCalls };
}

test('どのサービスでも、登録したOAuthアプリの同意画面へ、PKCE・state・頼んだ権限付きで案内する', async t => {
  const f = await generic(t), url = await f.start({ scopes: ['notes.read', 'notes.write'] });
  assert.equal(url.origin + url.pathname, SERVICE.authorize_url);
  assert.equal(url.searchParams.get('client_id'), 'notes-client');
  assert.equal(url.searchParams.get('scope'), 'notes.read notes.write');
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/oauth2/callback');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state'));
  assert.equal(url.searchParams.has('client_secret'), false);
  assert.match((await f.callback(url, 'personal')).headers.get('location'), /connection=connected/);
  const call = f.tokenCalls()[0], params = new URLSearchParams(call.options.body);
  assert.equal(call.options.headers.authorization, 'Basic ' + Buffer.from('notes-client:notes-secret').toString('base64'));
  assert.equal(params.get('grant_type'), 'authorization_code');
  assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), url.searchParams.get('code_challenge'));
});

test('利用者情報のURLがあれば、誰が許可したかを確かめ、サービス名とアカウントで一覧に出し、トークンを渡す', async t => {
  const f = await generic(t), agent = await f.issueKey(), connection = await f.connect();
  assert.equal(connection.service.name, 'Notes');
  assert.equal(connection.label, 'personal@service.example');
  assert.equal(connection.subject, 'user:id-personal');
  assert.deepEqual(connection.app, { id: f.appId, name: 'Notes', foundation: false });
  assert.equal(connection.can_revoke, true);
  const delivered = await f.deliver(connection, { token: agent.token });
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(delivered.json.delivery.environment.OAUTH_ACCESS_TOKEN, 'access-personal-0');
  assert.equal(delivered.json.delivery.environment.OAUTH_TOKEN_TYPE, 'Bearer');
  assert.ok(Number(delivered.json.delivery.environment.OAUTH_EXPIRES_AT) > Date.now());
  assert.doesNotMatch(JSON.stringify(connection) + delivered.text, /refresh-personal|notes-secret/);
  const again = await f.start({ connection_id: connection.id });
  assert.match((await f.callback(again, 'work')).headers.get('location'), /connection=wrong_account/);
});

test('利用者情報のURLがなければ、接続ごとに別のアカウントとして扱い、つなぎ直しでは同じ接続を保つ', async t => {
  const { userinfo_url, revoke_url, ...plain } = APP;
  const f = await generic(t, plain), connection = await f.connect();
  assert.equal(connection.label, 'Notes');
  assert.match(connection.subject, /^connection:/);
  assert.equal(connection.can_revoke, false);
  const again = await f.connect('anyone', { connection_id: connection.id });
  assert.equal(again.id, connection.id); assert.equal(again.subject, connection.subject);
  const removed = await f.request('/v1/holdings/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, null, 'nothing was asked of the service');
});

test('期限が近ければ更新トークンで更新し、失効していれば再接続待ちにし、期限を言わないトークンは更新しない', async t => {
  const f = await generic(t), connection = await f.connect();
  f.expire(connection.id);
  const refreshed = await f.deliver(connection);
  assert.equal(refreshed.json.delivery.environment.OAUTH_ACCESS_TOKEN, 'access-personal-1');
  assert.equal(new URLSearchParams(f.tokenCalls().at(-1).options.body).get('grant_type'), 'refresh_token');
  f.expire(connection.id);
  f.service.refreshHandler = () => ({ status: 400, body: { error: 'invalid_grant' } });
  assert.equal((await f.deliver(connection)).json.error.code, 'reconnect_required');
  f.service.refreshHandler = undefined; f.service.expiresIn = null;
  const lasting = await f.connect('lasting');
  const delivered = await f.deliver(lasting);
  assert.equal(delivered.json.delivery.environment.OAUTH_EXPIRES_AT, undefined);
  assert.equal((await f.deliver(lasting)).json.delivery.environment.OAUTH_ACCESS_TOKEN, delivered.json.delivery.environment.OAUTH_ACCESS_TOKEN);
});

test('頼んだ権限に対して、サービスが付与を知らせた権限との差を返す', async t => {
  const f = await generic(t);
  f.service.scope = 'notes.read';
  const connection = await f.connect('personal', { scopes: ['notes.read', 'notes.write'] });
  assert.deepEqual(connection.facts.missing_scopes, ['notes.write']);
});

test('取り消しのURLがあれば、解除のときにサービス側の許可も取り消す', async t => {
  const f = await generic(t), connection = await f.connect();
  const removed = await f.request('/v1/holdings/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  assert.ok(f.service.revoked.has('refresh-personal'));
});

test('アプリの登録では、サービス名と、インターネット上のhttpsのURLを求める', async t => {
  const f = await generic(t);
  for (const change of [{ service_name: '' }, { token_url: 'http://service.example/token' }, { authorize_url: 'https://localhost/authorize' },
    { token_url: 'https://10.0.0.1/token' }, { userinfo_url: 'https://metadata.internal/me' }, { token_url: 'not a url' }]) {
    const refused = await f.request('/v1/holdings?kind=app&name=Other', { method: 'PUT', data: { ...APP, ...change } });
    assert.equal(refused.status, 400, JSON.stringify(change) + ' ' + refused.text);
  }
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'oauth2' } })).json.error.code, 'app_required');
  const listed = (await f.request('/v1/holdings?kind=app')).json.holdings;
  assert.deepEqual(listed.map(app => [app.name, app.service.name, app.settings.token_url]), [['Notes', 'Notes', SERVICE.token_url]]);
});
