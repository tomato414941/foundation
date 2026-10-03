import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { EbayClient, EBAY_API, EBAY_BASE_SCOPES } from './client.mjs';

// What these tests ask eBay for, and what that asks the consent screen for with Foundation's own base.
const ASKED = ['https://api.ebay.com/oauth/api_scope/sell.account', 'https://api.ebay.com/oauth/api_scope/sell.inventory'];
const GRANTED = [...new Set([...EBAY_BASE_SCOPES, ...ASKED])].sort();
import { ebayOauth, configuration, create } from './index.mjs';
import { FakeEbay } from './fixture.mjs';
import { fixture, json, USER_A, entry } from '../../../test/helpers.mjs';

const grant = (change = {}) => ({ access_token: 'ebay-access-personal-0', refresh_token: 'ebay-refresh-personal',
  expires_in: 7200, refresh_token_expires_in: 47304000, token_type: 'User Access Token', ...change });
const inspected = (change = {}) => ({ active: true, sub: '1001', username: 'personal-seller', scope: GRANTED.join(' '),
  client_id: 'test-ebay-client', exp: Math.floor(Date.now() / 1000) + 7200, token_type: 'Bearer', ...change });

async function ebayFixture(t, ebay = new FakeEbay()) {
  const f = await fixture(t, { services: [entry('ebay', { oauth: ebayOauth(ebay) })] });
  const connections = async () => (await f.request('/v1/principals/me/resources?kind=connection')).json.resources;
  async function start(input = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { service: 'ebay', ...(input.request_id ? {} : { scopes: ASKED }), ...input } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  // eBay resolves the RuName to this registered callback before returning the query.
  const callback = (url, code = 'personal', options = {}, extra = {}) => f.request('/oauth/callback?' + new URLSearchParams({ state: url.searchParams.get('state'), code, ...extra }), options);
  async function connect(code = 'personal', input = {}) {
    const ids = new Set((await connections()).map(item => item.id));
    const done = await callback(await start(input), code);
    assert.match(done.headers.get('location'), /result=connected/);
    return (await connections()).find(item => input.connection_id ? item.id === input.connection_id : !ids.has(item.id));
  }
  const state = id => f.app.connections.state(f.app.connections.held(USER_A, id));
  return { ...f, ebay, start, callback, connect, connections, state };
}

test('eBayの設定を読み込み、設定済みの場合に接続を利用可能として返す', async t => {
  const env = { FOUNDATION_EBAY_CLIENT_ID: 'id', FOUNDATION_EBAY_CLIENT_SECRET: 'secret', FOUNDATION_EBAY_RUNAME: 'runame' };
  assert.deepEqual(configuration(env), { clientId: 'id', clientSecret: 'secret', ruName: 'runame' });
  const scheme = create(env);
  assert.equal(scheme.available, true); assert.equal(typeof scheme.revoke, 'function');
  assert.deepEqual(scheme.variables, ['EBAY_ACCESS_TOKEN', 'EBAY_ACCOUNT_ID', 'EBAY_USERNAME', 'EBAY_OAUTH_EXPIRES_AT']);
  for (const config of [{ clientId: 'id' }, { clientSecret: 'secret' }, { ruName: 'runame' }, { clientId: 'id', clientSecret: 'secret' },
    { clientId: 'id', clientSecret: 'secret', ruName: ' ' }]) assert.throws(() => new EbayClient(config), /all required/);
  const f = await ebayFixture(t, new EbayClient());
  assert.equal((await f.request('/v1/services')).json.services[0].auth_schemes.oauth.available, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'ebay' } })).status, 503);
});

test('RuNameとstateで同意を開始し、同じセッションで一度だけ認証コードを交換する', async t => {
  const f = await ebayFixture(t), url = await f.start();
  assert.equal(url.origin + url.pathname, 'https://auth.ebay.com/oauth2/authorize');
  assert.equal(url.searchParams.get('redirect_uri'), 'Test-Foundation-RuName');
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('prompt'), 'login');
  assert.deepEqual(url.searchParams.get('scope').split(' '), GRANTED);
  assert.ok(url.searchParams.get('state'));
  assert.match((await f.callback(url, 'personal', { anonymous: true })).headers.get('location'), /result=expired/);
  assert.match((await f.callback(url, 'personal', {}, { state: 'wrong' })).headers.get('location'), /result=expired/);
  assert.equal(f.ebay.exchanges, 0);
  const denied = await f.start();
  assert.match((await f.callback(denied, '', {}, { error: 'access_denied' })).headers.get('location'), /result=denied/);
  const valid = await f.start();
  const code = 'v^1.1#i^1#r^0#f^0#p%20+/=';
  f.ebay.exchangeHandler = () => json(grant());
  assert.match((await f.callback(valid, code)).headers.get('location'), /result=connected/);
  const exchange = f.ebay.calls.find(call => call.url.endsWith('/token'));
  assert.equal(exchange.options.body.get('code'), code);
  assert.equal(new URLSearchParams(exchange.options.body.toString()).get('code'), code);
  assert.equal(exchange.options.body.get('redirect_uri'), 'Test-Foundation-RuName');
  assert.equal(exchange.options.headers.authorization, 'Basic ' + Buffer.from('test-ebay-client:test-ebay-secret').toString('base64'));
  assert.match((await f.callback(valid, code)).headers.get('location'), /result=expired/);
  assert.equal(f.ebay.exchanges, 1);
});

test('依頼を完了し、確認済みのアカウント情報とAPI用トークンを分けて渡す', async t => {
  const f = await ebayFixture(t), agent = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { authorization_details: [{ type: 'connection', service: 'ebay', scopes: ASKED }], binding_message: '出品情報を管理します。' } });
  assert.equal(asked.status, 201);
  const a = await f.connect('personal', { request_id: asked.json.request.id });
  const done = (await f.request('/v1/requests/' + asked.json.request.id, { token: agent.token })).json.request;
  assert.equal(done.status, 'granted'); assert.equal(done.result.connection_id, a.id);
  const catalog = await f.request('/v1/principals/me/resources?kind=connection', { token: agent.token });
  assert.equal(catalog.json.resources[0].label, 'personal-seller');
  assert.deepEqual(catalog.json.resources[0].facts.scopes, GRANTED);
  assert.doesNotMatch(catalog.text, /ebay-access-|ebay-refresh-|test-ebay-secret/);
  const delivered = await f.inject(a, { token: agent.token });
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(delivered.json.injection.environment.EBAY_ACCESS_TOKEN, 'ebay-access-personal-0');
  assert.equal(delivered.json.injection.environment.EBAY_ACCOUNT_ID, '1001');
  assert.equal(delivered.json.injection.environment.EBAY_USERNAME, 'personal-seller');
  assert.equal(Number(delivered.json.injection.environment.EBAY_OAUTH_EXPIRES_AT), delivered.json.expires_at);
  assert.doesNotMatch(delivered.text, /ebay-refresh-|test-ebay-secret/);
  assert.equal(f.ebay.refreshes, 0);
  const kept = (await f.request('/v1/principals/me/resources?kind=connection')).json.resources;
  assert.deepEqual(kept.map(item => ({ id: item.id, auth_scheme: item.auth_scheme })), [{ id: a.id, auth_scheme: 'oauth' }]);
});

test('アカウントを固定IDで区別し、名前の変更を反映して別の所有者から分離する', async t => {
  const f = await ebayFixture(t), a = await f.connect(), b = await f.connect('work');
  assert.notEqual(a.id, b.id);
  assert.equal(a.subject, '1001'); assert.equal(b.subject, '1002');
  assert.match((await f.callback(await f.start(), 'personal')).headers.get('location'), /result=connected/);
  assert.equal((await f.request('/v1/principals/me/resources?kind=connection')).json.resources.length, 3);
  assert.match((await f.callback(await f.start({ connection_id: a.id }), 'work')).headers.get('location'), /result=wrong_account/);
  f.ebay.inspectHandler = () => json(inspected({ username: 'renamed-seller' }));
  const reconnected = await f.connect('personal', { connection_id: a.id });
  assert.equal(reconnected.id, a.id); assert.equal(reconnected.label, 'renamed-seller');
  await f.signin('second@example.test');
  const stranger = await f.issueKey();
  assert.deepEqual((await f.request('/v1/principals/me/resources?kind=connection', { token: stranger.token })).json.resources, []);
  assert.equal((await f.inject(a, { token: stranger.token })).status, 404);
  assert.equal((await f.request('/v1/resources/' + a.id, { method: 'DELETE', data: { revoke: true } })).status, 403);
});

test('eBayが報告した権限と有効期限を利用し、頼んだ権限に対する不足や追加を返す', async t => {
  const f = await ebayFixture(t), agent = await f.issueKey();
  const exp = Math.floor(Date.now() / 1000) + 300, extra = 'https://api.ebay.com/oauth/api_scope/sell.fulfillment.readonly';
  f.ebay.inspectHandler = () => json(inspected({ username: undefined, exp, scope: ASKED[0] + ' ' + extra }));
  const a = await f.connect(), delivered = await f.inject(a, { token: agent.token });
  assert.equal(a.label, '1001');
  assert.equal(delivered.json.expires_at, exp * 1000);
  const facts = await f.connectionFacts(a, { token: agent.token });
  assert.deepEqual(facts.missing_scopes, [EBAY_BASE_SCOPES[0], ASKED[1]]);
  assert.deepEqual(facts.additional_scopes, [extra]);
  f.ebay.inspectHandler = () => json(inspected({ scope: '' }));
  const updated = await f.inject(a, { token: agent.token });
  assert.equal(updated.status, 200, updated.text);
  assert.deepEqual((await f.connectionFacts(a, { token: agent.token })).missing_scopes, GRANTED);
});

test('同時取得をまとめて期限切れトークンを更新し、更新用トークンの元の期限を保持する', async t => {
  const f = await ebayFixture(t), a = await f.connect(), agent = await f.issueKey();
  const before = f.state(a.id).private_state;
  f.expire(a.id);
  let release, entered;
  const started = new Promise(resolve => entered = resolve);
  f.ebay.refreshHandler = async () => { entered(); await new Promise(resolve => release = resolve); return json(grant({ access_token: 'ebay-access-personal-new', refresh_token: undefined, refresh_token_expires_in: undefined })); };
  const one = f.inject(a, { token: agent.token });
  await started;
  const two = f.inject(a, { token: agent.token });
  release();
  const results = await Promise.all([one, two]);
  for (const result of results) assert.equal(result.status, 200, result.text);
  assert.deepEqual(results[0].json.injection, results[1].json.injection);
  assert.equal(f.ebay.refreshes, 1);
  const updated = f.state(a.id).private_state;
  assert.equal(updated.refresh_token, before.refresh_token);
  assert.equal(updated.refresh_expires_at, before.refresh_expires_at);
  assert.equal(updated.access_token, 'ebay-access-personal-new');
  // Reporting the same refresh token again cannot renew its lifetime by accident.
  const original = { ...updated, refresh_expires_at: Date.now() + 600_000 };
  assert.equal(f.ebay.grant(grant(), original).refresh_expires_at, original.refresh_expires_at);
  const rotated = f.ebay.grant(grant({ refresh_token: 'ebay-refresh-rotated', refresh_token_expires_in: 3600 }), original);
  assert.equal(rotated.refresh_token, 'ebay-refresh-rotated');
  assert.ok(rotated.refresh_expires_at > original.refresh_expires_at);
});

test('異なるアカウントの更新を停止し、保存済みの認証情報を保護する', async t => {
  const f = await ebayFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  f.ebay.inspectHandler = () => json(inspected({ sub: '1002', username: 'other-seller' }));
  const delivered = await f.inject(a, { token: agent.token });
  assert.equal(delivered.json.error.code, 'account_changed');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
  assert.equal(f.state(a.id).private_state.access_token, 'ebay-access-personal-0');
});

test('更新用トークンの期限切れでは再接続を求める', async t => {
  const f = await ebayFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  const state = f.state(a.id);
  f.app.connections.saveState(f.app.connections.held(USER_A, a.id), { ...state, private_state: { ...state.private_state, refresh_expires_at: Date.now() - 1 } });
  const delivered = await f.inject(a, { token: agent.token });
  assert.equal(delivered.json.error.code, 'reconnect_required');
  assert.equal(f.ebay.refreshes, 0);
});

test('eBayの障害やアプリ設定の失敗は再試行可能にし、許可の失効は再接続待ちにする', async t => {
  const f = await ebayFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  for (const status of [401, 403, 429, 500]) {
    f.ebay.refreshHandler = () => json({ error: status === 401 ? 'invalid_client' : 'private-provider-error', error_description: 'ebay-refresh-private' }, status);
    const result = await f.inject(a, { token: agent.token });
    assert.ok(result.status >= 500);
    assert.doesNotMatch(result.text, /private-provider|ebay-refresh/);
    assert.equal((await f.connections())[0].status, 'usable');
  }
  f.ebay.refreshHandler = () => json({ error: 'invalid_grant', error_description: 'private-provider-error' }, 400);
  assert.equal((await f.inject(a, { token: agent.token })).json.error.code, 'reconnect_required');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('利用するたびに許可を確認し、有効期限内でも取り消された認証情報を停止する', async t => {
  const f = await ebayFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.ebay.inspectHandler = () => json({ active: false });
  const result = await f.inject(a, { token: agent.token });
  assert.equal(result.json.error.code, 'reconnect_required');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
  assert.equal(f.ebay.refreshes, 0);
});

test('不正な認証応答と別アプリ向けの認証情報を秘密値を含まないエラーで扱う', async () => {
  const ebay = new FakeEbay();
  for (const change of [{ access_token: '' }, { access_token: 'secret\r\nvalue' }, { expires_in: '7200' }, { expires_in: -1 }, { expires_in: Number.MAX_SAFE_INTEGER },
    { token_type: 'Application Access Token' }, { refresh_token: null }, { refresh_token_expires_in: undefined }, { refresh_token_expires_in: -1 }]) {
    assert.throws(() => ebay.grant(grant(change)), { code: 'service_response' });
  }
  assert.throws(() => ebay.grant(grant({ refresh_token: undefined })), { code: 'refresh_missing' });
  const secret = ebay.grant(grant());
  for (const change of [{ active: 'true' }, { client_id: 'another-client' }, { sub: '' }, { sub: 'bad\nsubject' }, { username: null },
    { exp: '100' }, { scope: null }, { scope: 'bad\nscope' }, { token_type: 'mac' }, { aud: 'https://other.test' }, { aud: [EBAY_API, 1] }, { iss: 'https://other.test' }]) {
    ebay.inspectHandler = () => json(inspected(change));
    await assert.rejects(ebay.inspect(secret), { code: 'service_response' });
  }
  ebay.inspectHandler = () => json(inspected({ exp: Math.floor(Date.now() / 1000) - 1 }));
  await assert.rejects(ebay.inspect(secret), { code: 'reconnect_required' });
  await assert.rejects(ebay.token({ ...secret, client_id: 'other-client' }, { subject: '1001' }), { code: 'reconnect_required' });
  ebay.exchangeHandler = () => new Response('ebay-refresh-private', { status: 502 });
  await assert.rejects(ebay.exchange({ code: 'private' }), error => error.code === 'service_unavailable' && !error.message.includes('private'));
  ebay.exchangeHandler = () => json({ error: 'invalid_grant' }, 400);
  await assert.rejects(ebay.exchange({ code: 'used-code' }), { code: 'invalid_state' });
});

test('接続解除時にeBayへの取り消しを選べ、失敗した場合も解除結果を返す', async t => {
  const f = await ebayFixture(t), a = await f.connect(), b = await f.connect('work');
  assert.equal((await f.request('/v1/resources/' + a.id, { method: 'DELETE', data: { revoke: true } })).json.service_revoked, true);
  assert.equal((await f.request('/v1/resources/' + b.id, { method: 'DELETE', data: { revoke: false } })).json.service_revoked, null);
  const revokeCalls = f.ebay.calls.filter(call => call.url.endsWith('/revoke'));
  assert.equal(revokeCalls.length, 1);
  assert.equal(revokeCalls[0].url, EBAY_API + '/identity/v1/oauth2/token/revoke');
  assert.equal(revokeCalls[0].options.body.get('token'), 'ebay-refresh-personal');
  assert.equal(revokeCalls[0].options.body.get('token_type_hint'), 'refresh_token');
  const again = await f.connect();
  f.ebay.revokeHandler = () => json({ error: 'private-provider-error' }, 500);
  const failed = await f.request('/v1/resources/' + again.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(failed.json.service_revoked, false);
  assert.deepEqual(await f.connections(), []);
  for (const call of f.ebay.calls) {
    assert.equal(call.options.method, 'POST'); assert.equal(call.options.redirect, 'error'); assert.ok(call.options.signal);
    assert.equal(new URL(call.url).search, '');
  }
});

test('接続IDからeBay認証情報を更新し、CLI経由で子プロセスに渡す', async t => {
  const f = await ebayFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-ebay-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'key');
  await writeFile(keyPath, agent.token, { mode: 0o600 });
  const child = spawn(process.execPath, ['cli/runtime.mjs', 'exec', '--inputs', JSON.stringify([{ id: a.id }]), '--', process.execPath, '-e',
    'if(process.env.EBAY_ACCESS_TOKEN!=="ebay-access-personal-1"||process.env.EBAY_ACCOUNT_ID!=="1001"||process.env.EBAY_USERNAME!=="personal-seller"||process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("ebay-ready")'],
  { env: { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath } });
  let out = '', err = '';
  child.stdout.on('data', value => { out += value; }); child.stderr.on('data', value => { err += value; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(code, 0, err); assert.equal(out.trim(), 'ebay-ready');
  assert.doesNotMatch(out + err, /ebay-access-|ebay-refresh-/);
  assert.equal(f.ebay.refreshes, 1);
});
