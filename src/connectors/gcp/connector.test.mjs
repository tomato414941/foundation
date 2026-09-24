import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { GcpClient, GCP_SCOPES, CLOUD_PLATFORM_SCOPE } from './client.mjs';
import { gcpOauth, configuration } from './index.mjs';
import { gmailReadonly, configuration as gmailConfiguration } from '../gmail/index.mjs';
import { FakeGcp } from './fixture.mjs';
import { FakeGmail, fixture, json, USER_A } from '../../../test/helpers.mjs';

async function gcpFixture(t, gcp = new FakeGcp()) {
  const gmail = new FakeGmail(), f = await fixture(t, { gmail, connectors: [gcpOauth(gcp), gmailReadonly(gmail)] });
  async function start(input = {}) {
    const result = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gcp.oauth', ...input } });
    assert.equal(result.status, 200, result.text);
    return new URL(result.json.url);
  }
  async function connect(code = 'personal', input = {}) {
    const done = await f.callback(await start(input), code);
    assert.match(done.headers.get('location'), /connection=connected/);
    return (await connections()).find(item => item.subject === (code === 'work' ? '1002' : '1001'));
  }
  const connections = async () => (await f.request('/v1/state')).json.connections.filter(item => item.connector === 'gcp.oauth');
  return { ...f, gcp, start, connect, connections };
}

test('GCPの構成を読み込み、未設定なら接続を利用不可として返す', async t => {
  const env = { FOUNDATION_GCP_CLIENT_ID: 'id', FOUNDATION_GCP_CLIENT_SECRET: 'secret' };
  assert.deepEqual(configuration(env), { clientId: 'id', clientSecret: 'secret' });
  assert.deepEqual(gmailConfiguration(env), { clientId: '', clientSecret: '' });
  for (const incomplete of [{ clientId: 'id' }, { clientSecret: 'secret' }]) assert.throws(() => new GcpClient(incomplete), /Both Foundation GCP/);
  const f = await gcpFixture(t, new GcpClient());
  const catalog = await f.request('/v1/connectors');
  assert.equal(catalog.json.connectors.find(item => item.id === 'gcp.oauth').available, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { connector: 'gcp.oauth' } })).status, 503);
});

test('Google Cloudの同意をstate・PKCE・オフライン更新付きで要求する', async t => {
  const f = await gcpFixture(t), url = await f.start();
  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.deepEqual(url.searchParams.get('scope').split(' '), GCP_SCOPES);
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('include_granted_scopes'), 'false');
  assert.equal(url.searchParams.get('prompt'), 'consent select_account');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/gcp.oauth/callback');
  assert.ok(url.searchParams.get('state'));
  assert.equal(url.searchParams.has('client_secret'), false);
  assert.match((await f.callback(url, 'personal', { anonymous: true })).headers.get('location'), /connection=expired/);
  const valid = await f.start();
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /connection=connected/);
  const params = f.gcp.calls.find(call => call.url.endsWith('/token')).options.body;
  assert.equal(params.get('client_secret'), 'test-gcp-secret');
  assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), valid.searchParams.get('code_challenge'));
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /connection=expired/);
  assert.equal(f.gcp.exchanges, 1);
});

test('AIの依頼を完了し、接続の確認結果と短期トークンを分けて渡す', async t => {
  const f = await gcpFixture(t), agent = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { connector: 'gcp.oauth', purpose: 'Google Cloudの設定を確認します。' } });
  assert.equal(asked.status, 201);
  const a = await f.connect('personal', { request_id: asked.json.request.id });
  const done = await f.request('/v1/requests/' + asked.json.request.id, { token: agent.token });
  assert.equal(done.json.request.status, 'done');
  assert.equal(done.json.request.result.connection_id, a.id);
  const catalog = await f.request('/v1/connections', { token: agent.token });
  assert.equal(catalog.json.connections[0].label, 'personal@example.test');
  assert.deepEqual(catalog.json.connections[0].facts.scopes, GCP_SCOPES);
  assert.equal(catalog.json.connections[0].facts.iam_checked, false);
  assert.doesNotMatch(catalog.text, /gcp-access-|gcp-refresh-|test-gcp-secret/);
  const delivered = await f.deliver(a, { token: agent.token });
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(delivered.json.delivery.environment.CLOUDSDK_AUTH_ACCESS_TOKEN, 'gcp-access-personal-0');
  assert.equal(delivered.json.delivery.environment.GOOGLE_CLOUD_ACCOUNT_EMAIL, 'personal@example.test');
  assert.ok(Number(delivered.json.delivery.environment.GOOGLE_OAUTH_EXPIRES_AT) > Date.now());
  assert.doesNotMatch(delivered.text, /gcp-refresh-|test-gcp-secret/);
  assert.deepEqual((await f.request('/v1/state')).json.secrets, []);
});

test('複数アカウントをGoogleの固定IDで識別し、別の所有者から分離する', async t => {
  const f = await gcpFixture(t), a = await f.connect(), b = await f.connect('work'), agent = await f.issueKey();
  assert.notEqual(a.id, b.id);
  assert.equal(a.subject, '1001'); assert.equal(b.subject, '1002');
  assert.equal((await f.deliver(b, { token: agent.token })).json.delivery.environment.GOOGLE_CLOUD_ACCOUNT_EMAIL, 'work@example.test');
  const duplicate = await f.callback(await f.start(), 'personal');
  assert.match(duplicate.headers.get('location'), /connection=already_connected/);
  await f.login('second@example.test');
  const stranger = await f.issueKey();
  assert.deepEqual((await f.request('/v1/connections', { token: stranger.token })).json.connections, []);
  assert.equal((await f.deliver(a, { token: stranger.token })).status, 404);
  assert.equal((await f.request('/v1/connections/' + a.id, { method: 'DELETE', data: { revoke: false } })).status, 404);
});

test('再接続は同じGoogle IDで行い、メールアドレスの変更を反映する', async t => {
  const f = await gcpFixture(t), a = await f.connect();
  const url = await f.start({ connection_id: a.id });
  assert.equal(url.searchParams.get('login_hint'), '1001');
  assert.match((await f.callback(url, 'work')).headers.get('location'), /connection=wrong_account/);
  f.gcp.identityHandler = () => json({ sub: '1001', email: 'renamed@example.test', email_verified: true });
  f.gcp.exchangeHandler = () => json({ access_token: 'gcp-access-personal-new', scope: GCP_SCOPES.join(' '), expires_in: 3600 });
  const same = await f.connect('personal', { connection_id: a.id });
  assert.equal(same.id, a.id); assert.equal(same.label, 'renamed@example.test');
  const row = f.app.store.acquisition(USER_A, a.id);
  assert.equal(f.app.store.acquisitionState(row).private_state.refresh_token, 'gcp-refresh-personal');
});

test('権限の不足や追加をAIに返し、Googleが発行した認証情報を利用可能にする', async t => {
  const f = await gcpFixture(t), agent = await f.issueKey();
  const extra = 'https://www.googleapis.com/auth/drive.readonly';
  f.gcp.scopes = 'openid email ' + extra;
  const a = await f.connect();
  const result = await f.deliver(a, { token: agent.token });
  assert.equal(result.status, 200, result.text);
  assert.deepEqual(result.json.facts.missing_scopes, [CLOUD_PLATFORM_SCOPE]);
  assert.deepEqual(result.json.facts.additional_scopes, [extra]);
  f.expire(a.id);
  f.gcp.scopes = GCP_SCOPES.join(' ');
  const refreshed = await f.deliver(a, { token: agent.token });
  assert.equal(refreshed.status, 200);
  assert.deepEqual(refreshed.json.facts.missing_scopes, []);
  assert.deepEqual(refreshed.json.facts.additional_scopes, []);
  assert.deepEqual((await f.request('/v1/connections', { token: agent.token })).json.connections[0].facts.scopes, GCP_SCOPES);
});

test('メール情報が非公開でもGoogle IDで接続し、不足する権限をAIに返す', async t => {
  const f = await gcpFixture(t), agent = await f.issueKey();
  f.gcp.scopes = 'openid ' + CLOUD_PLATFORM_SCOPE;
  f.gcp.identityHandler = () => json({ sub: '1001' });
  const a = await f.connect();
  assert.equal(a.label, '1001');
  const result = await f.deliver(a, { token: agent.token });
  assert.equal(result.status, 200);
  assert.deepEqual(result.json.facts.missing_scopes, ['https://www.googleapis.com/auth/userinfo.email']);
  assert.equal(result.json.facts.email_verified, false);
  assert.equal(result.json.delivery.environment.GOOGLE_CLOUD_ACCOUNT_EMAIL, '');
});

test('有効期限内のトークンを再利用し、更新時は同時要求をまとめて回転したトークンを保存する', async t => {
  const f = await gcpFixture(t), a = await f.connect(), agent = await f.issueKey();
  await f.deliver(a, { token: agent.token });
  assert.equal(f.gcp.refreshes, 0);
  f.expire(a.id);
  f.gcp.refreshHandler = () => json({ access_token: 'gcp-access-personal-new', refresh_token: 'gcp-refresh-personal-rotated', expires_in: 3600 });
  const [one, two] = await Promise.all([f.deliver(a, { token: agent.token }), f.deliver(a, { token: agent.token })]);
  assert.equal(one.status, 200, one.text); assert.equal(two.status, 200, two.text);
  assert.deepEqual(one.json.delivery, two.json.delivery); assert.equal(f.gcp.refreshes, 1);
  const saved = await f.deliver(a, { token: agent.token });
  assert.equal(saved.status, 200);
  const current = f.app.store.acquisitionState(f.app.store.acquisition(USER_A, a.id));
  assert.equal(current.private_state.refresh_token, 'gcp-refresh-personal-rotated');
  assert.deepEqual(current.private_state.scopes, GCP_SCOPES);
});

test('アカウントが変わった更新は停止し、元の接続を再接続待ちにする', async t => {
  const f = await gcpFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  f.gcp.identityHandler = () => json({ sub: '1002', email: 'work@example.test', email_verified: true });
  const result = await f.deliver(a, { token: agent.token });
  assert.equal(result.json.error.code, 'account_changed');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
  assert.equal(f.app.store.acquisitionState(f.app.store.acquisition(USER_A, a.id)).private_state.access_token, 'gcp-access-personal-0');
});

test('Googleの一時的な障害は再試行可能にし、失効した許可は再接続待ちにする', async t => {
  const f = await gcpFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  for (const status of [403, 429, 500]) {
    f.gcp.refreshHandler = () => json({ error: 'private-provider-value', error_description: 'gcp-refresh-secret' }, status);
    const result = await f.deliver(a, { token: agent.token });
    assert.ok(result.status >= 500);
    assert.doesNotMatch(result.text, /private-provider|gcp-refresh/);
    assert.equal((await f.connections())[0].status, 'connected');
  }
  f.gcp.refreshHandler = () => json({ error: 'invalid_grant', error_description: 'private-provider-value' }, 400);
  assert.equal((await f.deliver(a, { token: agent.token })).json.error.code, 'reconnect_required');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('不正な認証応答を秘密値を含まないエラーで返す', async () => {
  const gcp = new FakeGcp(), valid = { access_token: 'a', refresh_token: 'r', scope: GCP_SCOPES.join(' '), expires_in: 3600 };
  for (const change of [{ access_token: '' }, { access_token: 'a\r\nb' }, { expires_in: '3600' }, { expires_in: -1 }, { expires_in: 86401 }, { token_type: 'mac' },
    { refresh_token: 'a\nb' }, { scope: null }, { scope: '' }, { scope: 'openid\nemail' }]) assert.throws(() => gcp.grant({ ...valid, ...change }), { code: 'service_response' });
  assert.throws(() => gcp.grant({ ...valid, refresh_token: undefined }), { code: 'refresh_missing' });
  for (const change of [{ sub: '' }, { sub: 'a\nb' }, { email: 'bad-address' }, { email_verified: 'true' }]) {
    gcp.identityHandler = () => json({ sub: '1001', email: 'personal@example.test', email_verified: true, ...change });
    await assert.rejects(gcp.identity('gcp-access-personal-0'), { code: 'service_response' });
  }
});

test('接続の解除ではGoogleへの取り消しを選べ、送信する秘密値はPOST本文に収める', async t => {
  const f = await gcpFixture(t), a = await f.connect(), b = await f.connect('work');
  assert.match(a.revocation_note, /他のGoogle接続/);
  const removed = await f.request('/v1/connections/' + a.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  const revoke = f.gcp.calls.find(call => call.url.endsWith('/revoke'));
  assert.equal(revoke.url, 'https://oauth2.googleapis.com/revoke');
  assert.equal(revoke.options.method, 'POST');
  assert.equal(revoke.options.body.get('token'), 'gcp-refresh-personal');
  assert.equal((await f.request('/v1/connections/' + b.id, { method: 'DELETE', data: { revoke: false } })).json.service_revoked, null);
  assert.equal(f.gcp.calls.filter(call => call.url.endsWith('/revoke')).length, 1);
  f.gcp.revokeHandler = () => json({ error: 'invalid_token' }, 400);
  await f.gcp.revoke({ refresh_token: 'already-gone' });
  for (const call of f.gcp.calls) { assert.equal(call.options.redirect, 'error'); assert.ok(call.options.signal); }
});

test('任意の名前に保存したGCP認証情報をCLI経由で子プロセスに渡す', async t => {
  const f = await gcpFixture(t), a = await f.connect(), agent = await f.issueKey();
  const name = 'a/aa=テスト';
  const saved = await f.request('/v1/functions/connection.credentials', { method: 'POST', token: agent.token,
    data: { connection_id: a.id, save: { CLOUDSDK_AUTH_ACCESS_TOKEN: name } } });
  assert.equal(saved.status, 200); assert.equal(saved.json.saved[0].name, name);
  assert.doesNotMatch(saved.text, /gcp-access-|gcp-refresh-/);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-gcp-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'key');
  await writeFile(keyPath, agent.token, { mode: 0o600 });
  const command = ['cli/runtime.mjs', 'exec', 'CLOUDSDK_AUTH_ACCESS_TOKEN=' + name, '--', process.execPath, '-e',
    'if(process.env.CLOUDSDK_AUTH_ACCESS_TOKEN!=="gcp-access-personal-0"||process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("gcp-ready")'];
  const child = spawn(process.execPath, command, { env: { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath } });
  let out = '', err = '';
  child.stdout.on('data', value => { out += value; }); child.stderr.on('data', value => { err += value; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(code, 0, err); assert.equal(out.trim(), 'gcp-ready');
  assert.doesNotMatch(out + err, /gcp-access-|gcp-refresh-/);
  assert.equal(f.gcp.refreshes, 0);
});
