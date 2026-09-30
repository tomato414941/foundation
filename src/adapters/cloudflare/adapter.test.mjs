import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { CloudflareClient, CLOUDFLARE_BASE_SCOPES } from './client.mjs';
import { cloudflareOauth, configuration } from './index.mjs';
import { FakeCloudflare } from './fixture.mjs';
import { fixture, json, USER_A, entry } from '../../../test/helpers.mjs';

// What these tests ask Cloudflare for, and what that asks the consent screen for with Foundation's own base.
const ASKED = ['account-settings.read', 'dns.write', 'zone.read'];
const GRANTED = [...new Set([...CLOUDFLARE_BASE_SCOPES, ...ASKED])].sort();

async function cloudflareFixture(t, cloudflare = new FakeCloudflare()) {
  const f = await fixture(t, { services: [entry('cloudflare', { oauth: cloudflareOauth(cloudflare) })] });
  async function start(input = {}) {
    const result = await f.request('/v1/credentials', { method: 'POST', data: { service: 'cloudflare', ...(input.request_id ? {} : { scopes: ASKED }), ...input } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  const connections = async () => (await f.request('/v1/overview')).json.credentials;
  async function connect(code = 'personal', input = {}) {
    const ids = new Set((await connections()).map(item => item.id));
    const done = await f.callback(await start(input), code);
    assert.match(done.headers.get('location'), /result=connected/, done.headers.get('location'));
    return (await connections()).find(item => input.credential_id ? item.id === input.credential_id : !ids.has(item.id));
  }
  const secret = connection => f.app.credentials.state(f.app.credentials.held(USER_A, connection.id)).private_state;
  return { ...f, cloudflare, start, connect, connections, secret };
}

test('Cloudflareの設定を読み込み、未設定なら利用不可として案内する', async t => {
  assert.deepEqual(configuration({ FOUNDATION_CLOUDFLARE_CLIENT_ID: 'id', FOUNDATION_CLOUDFLARE_CLIENT_SECRET: 'secret' }), { clientId: 'id', clientSecret: 'secret' });
  for (const config of [{ clientId: 'id' }, { clientSecret: 'secret' }]) assert.throws(() => new CloudflareClient(config), /Both Foundation Cloudflare/);
  const f = await cloudflareFixture(t, new CloudflareClient());
  const listed = await f.request('/v1/services');
  assert.equal(listed.json.services[0].auth_schemes.oauth.available, false);
  assert.equal((await f.request('/v1/credentials', { method: 'POST', data: { service: 'cloudflare' } })).status, 503);
});

test('Cloudflareの認可を、頼まれた権限と継続利用・本人確認の権限、state・PKCE付きで要求し、同じセッションで完了する', async t => {
  const f = await cloudflareFixture(t), url = await f.start();
  assert.equal(url.origin + url.pathname, 'https://dash.cloudflare.com/oauth2/auth');
  assert.equal(url.searchParams.get('client_id'), 'test-cloudflare-client');
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/callback');
  assert.deepEqual(url.searchParams.get('scope').split(' '), GRANTED);
  assert.equal(url.searchParams.get('prompt'), 'consent');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('state'));
  assert.match((await f.callback(url, 'personal', { anonymous: true })).headers.get('location'), /result=expired/);
  const valid = await f.start();
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /result=connected/);
  const call = f.cloudflare.calls.find(call => call.url.endsWith('/token')), params = call.options.body;
  assert.equal(params.get('client_id'), 'test-cloudflare-client');
  assert.equal(params.get('client_secret'), 'test-cloudflare-secret');
  assert.equal(params.get('grant_type'), 'authorization_code');
  assert.equal(params.get('redirect_uri'), f.base + '/oauth/callback');
  assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), valid.searchParams.get('code_challenge'));
  assert.equal(call.options.redirect, 'error');
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /result=expired/);
  assert.equal(f.cloudflare.exchanges, 1);
});

test('接続依頼を完了し、許可された権限と認証情報を分けて返す', async t => {
  const f = await cloudflareFixture(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: {
    authorization_details: [{ type: 'credential', service: 'cloudflare', scopes: ASKED }], binding_message: 'ドメインとDNSを管理します。' } });
  assert.equal(asked.status, 201, asked.text);
  const connection = await f.connect('personal', { request_id: asked.json.request.id });
  const completed = await f.request('/v1/requests/' + asked.json.request.id, { token });
  assert.equal(completed.json.request.status, 'granted');
  assert.equal(completed.json.request.result.credential_id, connection.id);
  const listed = await f.request('/v1/resources?kind=credential', { token });
  assert.equal(listed.json.resources[0].label, 'personal@example.test');
  assert.equal(listed.json.resources[0].facts.user_id, '1'.repeat(32));
  assert.deepEqual(listed.json.resources[0].facts.scopes, GRANTED);
  assert.deepEqual(listed.json.resources[0].facts.requested_scopes, GRANTED);
  assert.doesNotMatch(listed.text, /cf-access-|cf-refresh-|test-cloudflare-secret/);
  const delivery = await f.inject(connection, { token });
  assert.equal(delivery.status, 200, delivery.text);
  assert.equal(delivery.json.injection.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-0');
  assert.ok(Number(delivery.json.injection.environment.CLOUDFLARE_OAUTH_EXPIRES_AT) > Date.now());
  assert.doesNotMatch(delivery.text, /cf-refresh-|test-cloudflare-secret/);
});

test('同じユーザーの認可を別の接続として保存し、指定した接続だけを更新する', async t => {
  const f = await cloudflareFixture(t), personal = await f.connect(), work = await f.connect('work');
  assert.notEqual(personal.id, work.id);
  const second = await f.connect();
  assert.notEqual(second.id, personal.id);
  assert.notEqual(f.secret(second).refresh_token, f.secret(personal).refresh_token);
  assert.match((await f.callback(await f.start({ credential_id: personal.id }), 'work')).headers.get('location'), /result=wrong_account/);
  f.cloudflare.identityHandler = () => json({ success: true, result: { id: '1'.repeat(32), email: 'new@example.test' } });
  const same = await f.connect('personal', { credential_id: personal.id });
  assert.equal(same.id, personal.id);
  assert.equal(same.label, 'new@example.test');
  assert.equal((await f.connections()).find(item => item.id === second.id).label, 'personal@example.test');
  await f.login('second@example.test');
  const stranger = await f.issueKey();
  assert.deepEqual((await f.connections()), []);
  assert.equal((await f.inject(personal, { token: stranger.token })).status, 404);
});

test('Cloudflareで拒否された認可を依頼の結果に反映する', async t => {
  const f = await cloudflareFixture(t), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'credential', service: 'cloudflare' }] } });
  const url = await f.start({ request_id: asked.json.request.id });
  const denied = await f.request('/oauth/callback?state=' + url.searchParams.get('state') + '&error=access_denied');
  assert.match(denied.headers.get('location'), /result=denied/);
  const request = (await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request;
  assert.ok(request.events.some(event => event.event === 'connect_failed' && event.code === 'authorization_denied'));
});

test('頼んだ権限に対する不足と追加を、Cloudflareの応答に従って報告する', async t => {
  const f = await cloudflareFixture(t);
  f.cloudflare.scopes = 'user-details.read offline_access workers-r2.read';
  const connection = await f.connect(), delivered = await f.inject(connection);
  assert.equal(delivered.status, 200);
  const facts = await f.credentialFacts(connection);
  assert.deepEqual(facts.missing_scopes, ASKED);
  assert.deepEqual(facts.additional_scopes, ['workers-r2.read']);
});

test('有効期限が近づいた認証情報を更新し、ローテーション後の更新トークンを次回に使用する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  await f.inject(connection);
  assert.equal(f.cloudflare.refreshes, 0);
  f.expire(connection.id);
  const first = await f.inject(connection);
  assert.equal(first.json.injection.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-1');
  assert.equal(f.secret(connection).refresh_token, 'cf-refresh-personal-1');
  f.expire(connection.id);
  const second = await f.inject(connection);
  assert.equal(second.json.injection.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-2');
  assert.equal(f.cloudflare.calls.filter(call => call.options.body?.get('grant_type') === 'refresh_token')[1].options.body.get('refresh_token'), 'cf-refresh-personal-1');
  assert.equal((await f.credentialFacts(connection)).user_id, connection.subject);
});

test('更新応答で省略された権限と更新トークンを元の認可から引き継ぐ', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.expire(connection.id);
  f.cloudflare.refreshHandler = () => json({ access_token: 'cf-next-access', token_type: 'Bearer', expires_in: 3600 });
  const delivered = await f.inject(connection);
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(f.secret(connection).refresh_token, 'cf-refresh-personal-0');
  assert.deepEqual((await f.credentialFacts(connection)).scopes, GRANTED);
});

test('複数の同時要求を一回の更新にまとめ、後続の取得でも更新済みの認証情報を渡す', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), { token } = await f.issueKey();
  f.expire(connection.id);
  let release;
  const hold = new Promise(resolve => release = resolve);
  f.cloudflare.refreshHandler = async () => { await hold; };
  const names = [{ id: connection.id }];
  const one = f.app.inputs.inject(USER_A, names), two = f.app.inputs.inject(USER_A, names);
  release();
  const results = await Promise.all([one, two]);
  for (const result of results) {
    assert.equal(result.injection.environment.CLOUDFLARE_API_TOKEN, 'cf-access-personal-1');
    assert.doesNotMatch(JSON.stringify(result), /cf-refresh-/);
  }
  assert.deepEqual(results[0].injection, results[1].injection);
  assert.equal(f.cloudflare.refreshes, 1);
  const delivered = await f.inject(connection, { token });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.injection, results[0].injection);
  assert.equal(f.cloudflare.refreshes, 1);
});

test('失効した更新トークンでは再接続を案内し、一時的な通信障害は再試行できる状態を維持する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.expire(connection.id);
  f.cloudflare.refreshHandler = () => json({ error: 'temporarily_unavailable' }, 503);
  assert.equal((await f.inject(connection)).status, 502);
  assert.equal((await f.connections())[0].status, 'usable');
  f.cloudflare.refreshHandler = () => json({ error: 'invalid_grant' }, 400);
  assert.equal((await f.inject(connection)).status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('クライアント認証の失敗を接続設定の問題として報告する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.expire(connection.id);
  f.cloudflare.refreshHandler = () => json({ error: 'invalid_client', error_description: 'test-cloudflare-secret' }, 401);
  const delivered = await f.inject(connection);
  assert.equal(delivered.status, 503);
  assert.equal(delivered.json.error.code, 'cloudflare_unavailable');
  assert.equal((await f.connections())[0].status, 'usable');
  assert.doesNotMatch(delivered.text, /test-cloudflare-secret/);
});

test('設定されたクライアントが変更された接続には再接続を要求する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.clientId = 'another-client';
  assert.equal((await f.inject(connection)).status, 409);
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('Cloudflareの認証応答を検証し、不正な値を安全なエラーとして返す', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  for (const change of [{ access_token: 'bad\r\nvalue' }, { refresh_token: '' }, { expires_in: 0 }, { expires_in: Number.MAX_SAFE_INTEGER },
    { token_type: 'Basic' }, { scope: 'dns.write\nadmin' }, { scope: {} }]) {
    f.expire(connection.id);
    f.cloudflare.refreshHandler = () => json({ access_token: 'test-access', refresh_token: 'test-refresh', token_type: 'Bearer', expires_in: 3600, scope: 'dns.write', ...change });
    const delivered = await f.inject(connection);
    assert.equal(delivered.status, 502, delivered.text);
    assert.equal(delivered.json.error.code, 'service_response');
  }
});

test('再接続では新たな継続利用の許可と確認できる利用者情報を要求する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.exchangeHandler = () => json({ access_token: 'cf-access-work-0', token_type: 'Bearer', expires_in: 3600, scope: GRANTED.join(' ') });
  assert.match((await f.callback(await f.start({ credential_id: connection.id }), 'work')).headers.get('location'), /result=retry/);
  assert.equal(f.secret(connection).identity.user_id, '1'.repeat(32));
  f.cloudflare.exchangeHandler = undefined;
  for (const result of [{ id: 'bad', email: 'person@example.test' }, { id: '1'.repeat(32), email: 'bad\n@example.test' }]) {
    f.cloudflare.identityHandler = () => json({ success: true, result });
    assert.match((await f.callback(await f.start({ credential_id: connection.id }), 'personal')).headers.get('location'), /result=failed/);
  }
});

test('接続解除時にCloudflareの更新トークンとアクセストークンを取り消す', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), secret = f.secret(connection);
  const removed = await f.request('/v1/resources/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200, removed.text);
  assert.equal(removed.json.service_revoked, true);
  assert.ok(f.cloudflare.revoked.has(secret.refresh_token));
  assert.ok(f.cloudflare.revoked.has(secret.access_token));
  assert.deepEqual(await f.connections(), []);
});

test('Cloudflareの取消処理が失敗してもFoundationの接続を解除し、取消結果を報告する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.revokeHandler = () => json({ error: 'temporarily_unavailable' }, 503);
  const removed = await f.request('/v1/resources/' + connection.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.status, 200, removed.text);
  assert.equal(removed.json.service_revoked, false);
  assert.deepEqual(await f.connections(), []);
});

test('同じユーザーが異なるアカウントへの許可を追加し、それぞれの対象と権限を確認する', async t => {
  const f = await cloudflareFixture(t), first = await f.connect();
  f.cloudflare.listedAccounts = [{ id: 'b'.repeat(32), name: 'Work account' }, { id: 'c'.repeat(32), name: 'Shared account' }];
  f.cloudflare.scopes = 'user-details.read account-settings.read zone.read offline_access';
  const second = await f.connect();
  assert.equal(first.facts.user_id, second.facts.user_id);
  assert.notEqual(first.id, second.id);
  assert.equal(second.facts.client_id, 'test-cloudflare-client');
  assert.deepEqual(second.facts.observed_accounts.items, f.cloudflare.listedAccounts);
  assert.deepEqual((await f.credentialFacts(first)).observed_accounts.items, [{ id: 'a'.repeat(32), name: 'Personal account' }]);
  assert.deepEqual((await f.credentialFacts(first)).scopes, GRANTED);
  assert.equal((await f.inject(first)).status, 200);
  assert.equal((await f.inject(second)).status, 200);
});

test('Cloudflareのアカウント一覧をページごとに取得して確認時刻とともに保持する', async t => {
  const f = await cloudflareFixture(t);
  f.cloudflare.accountsHandler = url => {
    const page = Number(url.searchParams.get('page'));
    return json({ success: true, result: [{ id: String(page).repeat(32), name: 'Account ' + page }], result_info: { total_pages: 2 } });
  };
  const connection = await f.connect(), accounts = connection.facts.observed_accounts;
  assert.deepEqual(accounts.items.map(item => item.name), ['Account 1', 'Account 2']);
  assert.equal(accounts.complete, true);
  assert.ok(accounts.checked_at <= Date.now());
});

test('アカウント一覧の取得に失敗しても認可を保存し、対象を未確認として返す', async t => {
  const f = await cloudflareFixture(t);
  f.cloudflare.accountsHandler = () => json({ success: false }, 403);
  const connection = await f.connect();
  assert.equal(connection.facts.observed_accounts, null);
  assert.equal((await f.inject(connection)).status, 200);
});

test('再接続依頼で指定したIDを維持し、その依頼を完了する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), original = f.secret(connection), { token } = await f.issueKey();
  const input = { service: 'cloudflare', credential_id: connection.id };
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'credential', ...input }] } });
  assert.equal(asked.status, 201, asked.text);
  const request = asked.json.request;
  assert.deepEqual(request.authorization_details, [{ type: 'credential', ...input, auth_scheme: 'oauth' }]);
  assert.equal(request.credential.id, connection.id);
  const done = await f.callback(await f.start({ request_id: request.id }), 'personal');
  assert.match(done.headers.get('location'), /result=connected/);
  const completed = (await f.request('/v1/requests/' + request.id, { token })).json.request;
  assert.equal(completed.status, 'granted');
  assert.equal(completed.result.credential_id, connection.id);
  assert.equal((await f.connections()).length, 1);
  assert.notEqual(f.secret(connection).refresh_token, original.refresh_token);
});

test('新規接続の依頼と再接続の依頼を、それぞれ指定された対象に固定する', async t => {
  const f = await cloudflareFixture(t), one = await f.connect(), two = await f.connect(), { token } = await f.issueKey();
  const ask = async connectionId => (await f.request('/v1/requests', { method: 'POST', token, data: {
    authorization_details: [{ type: 'credential', service: 'cloudflare', ...(connectionId ? { credential_id: connectionId } : {}) }] } })).json.request;
  const renewal = await ask(one.id), addition = await ask();
  for (const [request, target] of [[renewal, two.id], [addition, one.id]]) {
    const started = await f.request('/v1/credentials', { method: 'POST', data: { service: 'cloudflare', request_id: request.id, credential_id: target } });
    assert.equal(started.status, 409, started.text);
    assert.equal(started.json.error.code, 'credential_changed');
  }
  assert.equal(f.cloudflare.exchanges, 2);
  await f.login('second@example.test');
  const other = await f.issueKey();
  const refused = await f.request('/v1/requests', { method: 'POST', token: other.token, data: {
    authorization_details: [{ type: 'credential', service: 'cloudflare', credential_id: one.id }] } });
  assert.equal(refused.status, 404);
});

test('新しいOAuthアプリへの再接続で変更内容を確認し、既存IDを維持して移行する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), old = f.secret(connection), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: {
    authorization_details: [{ type: 'credential', service: 'cloudflare', credential_id: connection.id }] } });
  f.cloudflare.clientId = 'new-cloudflare-client';
  f.cloudflare.scopes = 'user-details.read account-settings.read offline_access';
  f.cloudflare.listedAccounts = [{ id: 'b'.repeat(32), name: 'Another account' }];
  const done = await f.callback(await f.start({ request_id: asked.json.request.id }), 'personal');
  const location = new URL(done.headers.get('location'), f.base), state = location.searchParams.get('state');
  assert.equal(location.searchParams.get('result'), 'review');
  const review = await f.request('/v1/credentials/confirmation?state=' + state);
  assert.equal(review.status, 200, review.text);
  assert.deepEqual(review.json.changes.map(item => item.label), ['OAuthアプリ', '権限', '確認できたアカウント']);
  assert.doesNotMatch(review.text, /cf-access-|cf-refresh-/);
  assert.deepEqual(f.secret(connection), old);
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request.status, 'pending');
  const approved = await f.request('/v1/credentials/confirmation', { method: 'POST', data: { state } });
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.credential.id, connection.id);
  assert.equal(approved.json.credential.facts.client_id, 'new-cloudflare-client');
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id, { token })).json.request.result.credential_id, connection.id);
  assert.equal((await f.inject(connection, { token })).status, 200);
  assert.equal((await f.request('/v1/credentials/confirmation', { method: 'POST', data: { state } })).status, 400);
});

test('変更の確認をキャンセルして元の接続を利用し続ける', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), old = f.secret(connection);
  f.cloudflare.listedAccounts = [{ id: 'b'.repeat(32), name: 'Another account' }];
  const done = await f.callback(await f.start({ credential_id: connection.id }), 'personal');
  const state = new URL(done.headers.get('location'), f.base).searchParams.get('state');
  assert.ok(state);
  assert.equal((await f.request('/v1/credentials/confirmation', { method: 'DELETE', data: { state } })).status, 200);
  assert.deepEqual(f.secret(connection), old);
  assert.equal((await f.inject(connection)).status, 200);
  assert.equal(f.cloudflare.revoked.size, 0);
});

test('確認待ちに別の更新が完了した場合は、先に完了した接続を維持する', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect();
  f.cloudflare.listedAccounts = [{ id: 'b'.repeat(32), name: 'Another account' }];
  const done = await f.callback(await f.start({ credential_id: connection.id }), 'personal');
  const state = new URL(done.headers.get('location'), f.base).searchParams.get('state');
  const row = f.app.credentials.held(USER_A, connection.id), context = f.app.credentials.context(row);
  const result = await cloudflareOauth(f.cloudflare).authorization.complete({ code: 'personal', verifier: 'test', redirectUri: f.base }, context);
  const fresh = f.app.credentials.save(USER_A, 'cloudflare', 'oauth', result, { previous: row });
  const confirmed = await f.request('/v1/credentials/confirmation', { method: 'POST', data: { state } });
  assert.equal(confirmed.status, 409);
  assert.equal(confirmed.json.error.code, 'credential_changed');
  assert.equal(f.app.credentials.held(USER_A, connection.id).generation, fresh.generation);
  assert.equal(f.secret(connection).refresh_token, result.privateState.refresh_token);
});

test('取り消された依頼や別のブラウザーでは確認待ちの変更を確定しない', async t => {
  const f = await cloudflareFixture(t), connection = await f.connect(), old = f.secret(connection), { token } = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: {
    authorization_details: [{ type: 'credential', service: 'cloudflare', credential_id: connection.id }] } });
  f.cloudflare.listedAccounts = [];
  const done = await f.callback(await f.start({ request_id: asked.json.request.id }), 'personal');
  const state = new URL(done.headers.get('location'), f.base).searchParams.get('state');
  assert.equal((await f.request('/v1/credentials/confirmation?state=' + state, { anonymous: true })).status, 401);
  assert.equal((await f.request('/v1/credentials/confirmation', { method: 'POST', token, data: { state } })).status, 403);
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id, { method: 'DELETE', token, data: {} })).status, 200);
  assert.equal((await f.request('/v1/credentials/confirmation', { method: 'POST', data: { state } })).status, 409);
  await f.login('second@example.test');
  assert.equal((await f.request('/v1/credentials/confirmation?state=' + state)).status, 400);
  assert.deepEqual(f.secret(connection), old);
});
