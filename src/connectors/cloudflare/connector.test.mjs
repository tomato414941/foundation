import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { CloudflareClient, CLOUDFLARE_SCOPES } from './client.mjs';
import { cloudflareOauth, configuration } from './index.mjs';
import { FakeCloudflare } from './fixture.mjs';
import { fixture, json, USER_A } from '../../../test/helpers.mjs';

async function cloudflareFixture(t, cloudflare = new FakeCloudflare()) {
  const f = await fixture(t, { connectors: [cloudflareOauth(cloudflare)] });
  async function start(input = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth', ...input } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  const connections = async () => (await f.request('/v1/overview')).json.connections;
  async function connect(code = 'personal', input = {}) {
    const done = await f.callback(await start(input), code);
    assert.match(done.headers.get('location'), /connection=connected/);
    return (await connections()).find(item => item.subject === (code === 'work' ? '2' : '1').repeat(32));
  }
  const secret = connection => f.app.connections.state(f.app.connections.get(USER_A, connection.id)).private_state;
  return { ...f, cloudflare, start, connect, connections, secret };
}

test('Cloudflareの設定を読み込み、未設定なら利用不可として案内する', async t => {
  assert.deepEqual(configuration({ FOUNDATION_CLOUDFLARE_CLIENT_ID: 'id', FOUNDATION_CLOUDFLARE_CLIENT_SECRET: 'secret' }), { clientId: 'id', clientSecret: 'secret' });
  for (const config of [{ clientId: 'id' }, { clientSecret: 'secret' }]) assert.throws(() => new CloudflareClient(config), /Both Foundation Cloudflare/);
  const f = await cloudflareFixture(t, new CloudflareClient());
  const listed = await f.request('/v1/connectors');
  assert.equal(listed.json.connectors[0].available, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'cloudflare.oauth' } })).status, 503);
});

test('Cloudflareの認可をstate・PKCE・継続利用の権限付きで要求し、同じセッションで完了する', async t => {
  const f = await cloudflareFixture(t), url = await f.start();
  assert.equal(url.origin + url.pathname, 'https://dash.cloudflare.com/oauth2/auth');
  assert.equal(url.searchParams.get('client_id'), 'test-cloudflare-client');
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/cloudflare.oauth/callback');
  assert.deepEqual(url.searchParams.get('scope').split(' '), CLOUDFLARE_SCOPES);
  assert.equal(url.searchParams.get('prompt'), 'consent');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state'));
  assert.match((await f.callback(url, 'personal', { anonymous: true })).headers.get('location'), /connection=expired/);
  const valid = await f.start();
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /connection=connected/);
  const call = f.cloudflare.calls.find(call => call.url.endsWith('/token')), params = call.options.body;
  assert.equal(params.get('client_id'), 'test-cloudflare-client');
  assert.equal(params.get('client_secret'), 'test-cloudflare-secret');
  assert.equal(params.get('grant_type'), 'authorization_code');
  assert.equal(params.get('redirect_uri'), f.base + '/oauth/cloudflare.oauth/callback');
  assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), valid.searchParams.get('code_challenge'));
  assert.equal(call.options.redirect, 'error');
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /connection=expired/);
  assert.equal(f.cloudflare.exchanges, 1);
});

test('接続依頼を完了し、許可された権限と認証情報を分けて返す', async t => {
  const f = await cloudflareFixture(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: {
    kind: 'connect', input: { connector: 'cloudflare.oauth' }, purpose: 'ドメインとDNSを管理します。' } });
  assert.equal(asked.status, 201, asked.text);
  const connection = await f.connect('personal', { request_id: asked.json.request.id });
  const completed = await f.request('/v1/requests/' + asked.json.request.id, { token });
  assert.equal(completed.json.request.status, 'done');
  assert.equal(completed.json.request.result.connection_id, connection.id);
  const listed = await f.request('/v1/connections', { token });
  assert.equal(listed.json.connections[0].label, 'personal@example.test');
  assert.equal(listed.json.connections[0].facts.user_id, '1'.repeat(32));
  assert.deepEqual(listed.json.connections[0].facts.scopes, CLOUDFLARE_SCOPES);
  assert.doesNotMatch(listed.text, /cf-access-|cf-refresh-|test-cloudflare-secret/);
  const delivery = await f.deliver(connection, { token });
  assert.equal(delivery.status, 200, delivery.text);
  assert.equal(delivery.json.delivery.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-0');
  assert.ok(Number(delivery.json.delivery.environment.CLOUDFLARE_OAUTH_EXPIRES_AT) > Date.now());
  assert.doesNotMatch(delivery.text, /cf-refresh-|test-cloudflare-secret/);
});

test('利用者IDで接続を識別し、同じ利用者で再接続して表示名を更新する', async t => {
  const f = await cloudflareFixture(t), personal = await f.connect(), work = await f.connect('work');
  assert.notEqual(personal.id, work.id);
  assert.match((await f.callback(await f.start(), 'personal')).headers.get('location'), /connection=already_connected/);
  assert.match((await f.callback(await f.start({ connection_id: personal.id }), 'work')).headers.get('location'), /connection=wrong_account/);
  f.cloudflare.identityHandler = () => json({ success: true, result: { id: '1'.repeat(32), email: 'new@example.test' } });
  const same = await f.connect('personal', { connection_id: personal.id });
  assert.equal(same.id, personal.id);
  assert.equal(same.label, 'new@example.test');
  await f.login('second@example.test');
  const stranger = await f.issueKey();
  assert.deepEqual((await f.connections()), []);
  assert.equal((await f.deliver(personal, { token: stranger.token })).status, 404);
});

test('Cloudflareで拒否された認可を依頼の結果に反映する', async t => {
  const f = await cloudflareFixture(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { kind: 'connect', input: { connector: 'cloudflare.oauth' } } });
  const url = await f.start({ request_id: asked.json.request.id });
  const denied = await f.request('/oauth/cloudflare.oauth/callback?state=' + url.searchParams.get('state') + '&error=access_denied');
  assert.match(denied.headers.get('location'), /connection=denied/);
  const request = (await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request;
  assert.ok(request.events.some(event => event.event === 'connect_failed' && event.code === 'authorization_denied'));
});

test('権限の不足と追加をCloudflareの応答に従って報告する', async t => {
  const f = await cloudflareFixture(t);
  f.cloudflare.scopes = 'user-details.read offline_access workers-r2.read';
  const connection = await f.connect(), delivered = await f.deliver(connection);
  assert.equal(delivered.status, 200);
  assert.deepEqual(delivered.json.facts.missing_scopes, ['account-settings.read', 'dns.write', 'registrar-domains.admin', 'zone.read']);
  assert.deepEqual(delivered.json.facts.additional_scopes, ['workers-r2.read']);
});

test('有効期限が近づいた認証情報を更新し、ローテーション後の更新トークンを次回に使用する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  await f.deliver(connection);
  assert.equal(f.cloudflare.refreshes, 0);
  f.expire(connection.id);
  const first = await f.deliver(connection);
  assert.equal(first.json.delivery.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-1');
  assert.equal(f.secret(connection).refresh_token, 'cf-refresh-personal-1');
  f.expire(connection.id);
  const second = await f.deliver(connection);
  assert.equal(second.json.delivery.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-2');
  assert.equal(f.cloudflare.calls.filter(call => call.options.body?.get('grant_type') === 'refresh_token')[1].options.body.get('refresh_token'), 'cf-refresh-personal-1');
  assert.equal(second.json.facts.user_id, connection.subject);
});

test('更新応答で省略された権限と更新トークンを元の認可から引き継ぐ', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.expire(connection.id);
  f.cloudflare.refreshHandler = () => json({ access_token: 'cf-next-access', token_type: 'Bearer', expires_in: 3600 });
  const delivered = await f.deliver(connection);
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(f.secret(connection).refresh_token, 'cf-refresh-personal-0');
  assert.deepEqual(delivered.json.facts.scopes, CLOUDFLARE_SCOPES);
});

test('複数の同時要求を一回の更新にまとめ、保存した認証情報を後から受け渡す', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), { token } = await f.issueKey();
  f.expire(connection.id);
  let release;
  const hold = new Promise(resolve => release = resolve);
  f.cloudflare.refreshHandler = async () => { await hold; };
  const row = f.app.connections.get(USER_A, connection.id), one = f.app.connections.obtain(row), two = f.app.connections.obtain(row);
  release();
  await Promise.all([one, two]);
  assert.equal(f.cloudflare.refreshes, 1);
  const saved = await f.request('/v1/functions/connection.credentials', { method: 'POST', token,
    data: { connection_id: connection.id, save: { CLOUDFLARE_API_TOKEN: 'cloudflare-example' } } });
  assert.equal(saved.status, 200, saved.text);
  assert.doesNotMatch(saved.text, /cf-access-|cf-refresh-/);
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token, data: { names: [{ name: 'cloudflare-example', as: 'CHOSEN_TOKEN' }] } });
  assert.equal(delivered.json.delivery.environment.CHOSEN_TOKEN, 'cf-access-personal-1');
});

test('失効した更新トークンでは再接続を案内し、一時的な通信障害は再試行できる状態を維持する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.expire(connection.id);
  f.cloudflare.refreshHandler = () => json({ error: 'temporarily_unavailable' }, 503);
  assert.equal((await f.deliver(connection)).status, 502);
  assert.equal((await f.connections())[0].status, 'connected');
  f.cloudflare.refreshHandler = () => json({ error: 'invalid_grant' }, 400);
  assert.equal((await f.deliver(connection)).status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('クライアント認証の失敗を接続設定の問題として報告する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.expire(connection.id);
  f.cloudflare.refreshHandler = () => json({ error: 'invalid_client', error_description: 'test-cloudflare-secret' }, 401);
  const delivered = await f.deliver(connection);
  assert.equal(delivered.status, 503);
  assert.equal(delivered.json.error.code, 'cloudflare_unavailable');
  assert.equal((await f.connections())[0].status, 'connected');
  assert.doesNotMatch(delivered.text, /test-cloudflare-secret/);
});

test('設定されたクライアントが変更された接続には再接続を要求する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.clientId = 'another-client';
  assert.equal((await f.deliver(connection)).status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('Cloudflareの認証応答を検証し、不正な値を安全なエラーとして返す', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  for (const change of [{ access_token: 'bad\r\nvalue' }, { refresh_token: '' }, { expires_in: 0 }, { expires_in: Number.MAX_SAFE_INTEGER },
    { token_type: 'Basic' }, { scope: 'dns.write\nadmin' }, { scope: {} }]) {
    f.expire(connection.id);
    f.cloudflare.refreshHandler = () => json({ access_token: 'test-access', refresh_token: 'test-refresh', token_type: 'Bearer', expires_in: 3600, scope: 'dns.write', ...change });
    const delivered = await f.deliver(connection);
    assert.equal(delivered.status, 502, delivered.text);
    assert.equal(delivered.json.error.code, 'service_response');
  }
});

test('再接続では新たな継続利用の許可と確認できる利用者情報を要求する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.exchangeHandler = () => json({ access_token: 'cf-access-work-0', token_type: 'Bearer', expires_in: 3600, scope: CLOUDFLARE_SCOPES.join(' ') });
  assert.match((await f.callback(await f.start({ connection_id: connection.id }), 'work')).headers.get('location'), /connection=retry/);
  assert.equal(f.secret(connection).identity.user_id, '1'.repeat(32));
  f.cloudflare.exchangeHandler = undefined;
  for (const result of [{ id: 'bad', email: 'person@example.test' }, { id: '1'.repeat(32), email: 'bad\n@example.test' }]) {
    f.cloudflare.identityHandler = () => json({ success: true, result });
    assert.match((await f.callback(await f.start({ connection_id: connection.id }), 'personal')).headers.get('location'), /connection=failed/);
  }
});

test('接続解除時にCloudflareの更新トークンとアクセストークンを取り消す', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), secret = f.secret(connection);
  const removed = await f.request('/v1/connections/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200, removed.text);
  assert.equal(removed.json.service_revoked, true);
  assert.ok(f.cloudflare.revoked.has(secret.refresh_token));
  assert.ok(f.cloudflare.revoked.has(secret.access_token));
  assert.deepEqual(await f.connections(), []);
});

test('Cloudflareの取消処理が失敗してもFoundationの接続を解除し、取消結果を報告する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.revokeHandler = () => json({ error: 'temporarily_unavailable' }, 503);
  const removed = await f.request('/v1/connections/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200, removed.text);
  assert.equal(removed.json.service_revoked, false);
  assert.deepEqual(await f.connections(), []);
});
