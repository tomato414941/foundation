import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { GoogleClient, GOOGLE_BASE_SCOPES } from './client.mjs';
import { googleOauth, configuration } from './index.mjs';
import { FakeGoogle } from './fixture.mjs';
import { fixture, json, USER_A, entry } from '../../../test/helpers.mjs';

const CLOUD = 'https://www.googleapis.com/auth/cloud-platform', READONLY = 'https://www.googleapis.com/auth/gmail.readonly', SEND = 'https://www.googleapis.com/auth/gmail.send';
const with_ = (...scopes) => [...new Set([...GOOGLE_BASE_SCOPES, ...scopes])].sort();

async function googleFixture(t, google = new FakeGoogle()) {
  const f = await fixture(t, { google, services: [entry('google', { oauth: googleOauth(google) })] });
  async function connect(code = 'personal', input = {}) {
    const ids = new Set((await connections()).map(item => item.id));
    const result = await f.request('/v1/connections', { method: 'POST', data: { service: 'google', ...(input.request_id ? {} : { scopes: [CLOUD] }), ...input } });
    assert.equal(result.status, 200, result.text);
    const done = await f.callback(new URL(result.json.url), code);
    assert.match(done.headers.get('location'), /result=connected/, done.headers.get('location'));
    return (await connections()).find(item => input.connection_id ? item.id === input.connection_id : !ids.has(item.id));
  }
  const connections = async () => (await f.request('/v1/principals/me/resources?kind=connection')).json.resources.filter(item => item.service?.id === 'google');
  const secret = connection => f.app.connections.state(f.app.connections.held(USER_A, connection.id)).private_state;
  return { ...f, connect, connections, secret };
}

test('Googleの設定を読み込み、未設定なら接続を利用不可として返す', async t => {
  assert.deepEqual(configuration({ FOUNDATION_GOOGLE_CLIENT_ID: 'id', FOUNDATION_GOOGLE_CLIENT_SECRET: 'secret' }), { clientId: 'id', clientSecret: 'secret' });
  for (const incomplete of [{ clientId: 'id' }, { clientSecret: 'secret' }]) assert.throws(() => new GoogleClient(incomplete), /Both Foundation Google/);
  const f = await googleFixture(t, new GoogleClient());
  assert.equal((await f.request('/v1/services')).json.services.find(item => item.id === 'google').auth_schemes.oauth.available, false);
  assert.equal((await f.request('/v1/connections', { method: 'POST', data: { service: 'google' } })).status, 503);
});

test('Googleの同意を、頼まれた権限と本人確認の権限、state・PKCE・オフライン更新付きで一度だけ要求する', async t => {
  const f = await googleFixture(t), url = await f.start({ scopes: [CLOUD, READONLY] });
  assert.equal(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.deepEqual(url.searchParams.get('scope').split(' '), with_(CLOUD, READONLY));
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('prompt'), 'consent select_account');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('redirect_uri'), f.base + '/oauth/callback');
  assert.equal(url.searchParams.has('client_secret'), false);
  assert.match((await f.callback(url, 'personal', { anonymous: true })).headers.get('location'), /result=expired/);
  const valid = await f.start({ scopes: [CLOUD] });
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /result=connected/);
  const params = f.google.calls.find(call => call.url.endsWith('/token')).options.body;
  assert.equal(params.get('client_secret'), 'test-google-secret');
  assert.equal(createHash('sha256').update(params.get('code_verifier')).digest('base64url'), valid.searchParams.get('code_challenge'));
  assert.match((await f.callback(valid, 'personal')).headers.get('location'), /result=expired/);
  assert.equal(f.google.exchanges, 1);
});

test('AIが頼んだ権限で接続の依頼を完了し、確認結果と短期トークンを分けて渡す', async t => {
  const f = await googleFixture(t), agent = await f.issueKey();
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { authorization_details: [{ type: 'connection', service: 'google', scopes: [READONLY, SEND] }], binding_message: 'メールを読み、返信を送ります。' } });
  assert.equal(asked.status, 201, asked.text);
  assert.deepEqual(asked.json.request.authorization_details[0].scopes, [READONLY, SEND]);
  const a = await f.connect('personal', { request_id: asked.json.request.id });
  const done = await f.request('/v1/requests/' + asked.json.request.id, { token: agent.token });
  assert.equal(done.json.request.status, 'granted'); assert.equal(done.json.request.result.connection_id, a.id);
  const [listed] = (await f.request('/v1/principals/me/resources?kind=connection', { token: agent.token })).json.resources;
  assert.equal(listed.label, 'personal@example.test');
  assert.deepEqual(listed.facts.scopes, with_(READONLY, SEND));
  assert.deepEqual(listed.facts.requested_scopes, with_(READONLY, SEND));
  assert.deepEqual(listed.facts.missing_scopes, []);
  const delivered = await f.inject(a, { token: agent.token });
  assert.equal(delivered.status, 200, delivered.text);
  const environment = delivered.json.injection.environment;
  assert.equal(environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal');
  assert.equal(environment.CLOUDSDK_AUTH_ACCESS_TOKEN, 'google-access-personal');
  assert.equal(environment.GOOGLE_ACCOUNT_EMAIL, 'personal@example.test');
  assert.ok(Number(environment.GOOGLE_OAUTH_EXPIRES_AT) > Date.now());
  assert.doesNotMatch(delivered.text + JSON.stringify(listed), /refresh-personal|test-google-secret/);
});

test('つなぎ直しでは、同じアカウントで既存の権限に新しく頼んだ権限を足して要求する', async t => {
  const f = await googleFixture(t), a = await f.connect('personal', { scopes: [READONLY] });
  const url = await f.start({ connection_id: a.id, scopes: [SEND] });
  assert.equal(url.searchParams.get('login_hint'), 'personal@example.test');
  assert.deepEqual(url.searchParams.get('scope').split(' '), with_(READONLY, SEND));
  assert.match((await f.callback(url, 'work')).headers.get('location'), /result=wrong_account/);
  const same = await f.connect('personal', { connection_id: a.id, scopes: [SEND] });
  assert.equal(same.id, a.id);
  assert.deepEqual(same.facts.scopes, with_(READONLY, SEND));
});

test('複数アカウントをメールアドレスで区別し、別の所有者から分離する', async t => {
  const f = await googleFixture(t), a = await f.connect(), b = await f.connect('work'), agent = await f.issueKey();
  assert.notEqual(a.id, b.id);
  assert.equal(a.subject, 'personal@example.test'); assert.equal(b.facts.account_id, 'sub-work');
  assert.equal((await f.inject(b, { token: agent.token })).json.injection.environment.GOOGLE_ACCOUNT_EMAIL, 'work@example.test');
  await f.signin('second@example.test');
  const stranger = await f.issueKey();
  assert.deepEqual((await f.request('/v1/principals/me/resources?kind=connection', { token: stranger.token })).json.resources, []);
  assert.equal((await f.inject(a, { token: stranger.token })).status, 404);
  assert.equal((await f.request('/v1/resources/' + a.id, { method: 'DELETE', data: { revoke: false } })).status, 403);
});

test('頼んだ権限に対する不足と追加を、Googleが付与した権限に従って報告する', async t => {
  const f = await googleFixture(t), agent = await f.issueKey(), extra = 'https://www.googleapis.com/auth/drive.readonly';
  f.google.scopes = 'openid email ' + extra;
  const a = await f.connect('personal', { scopes: [CLOUD] });
  assert.equal((await f.inject(a, { token: agent.token })).status, 200);
  const facts = await f.connectionFacts(a, { token: agent.token });
  assert.deepEqual(facts.missing_scopes, [CLOUD]);
  assert.deepEqual(facts.additional_scopes, [extra]);
});

test('有効期限内のトークンを再利用し、更新時は同時要求をまとめて回転したトークンと省略された権限を保つ', async t => {
  const f = await googleFixture(t), a = await f.connect(), agent = await f.issueKey();
  await f.inject(a, { token: agent.token });
  assert.equal(f.google.refreshes, 0);
  f.expire(a.id);
  f.google.refreshHandler = () => json({ access_token: 'google-access-personal-9', refresh_token: 'refresh-personal-rotated', expires_in: 3600 });
  const [one, two] = await Promise.all([f.inject(a, { token: agent.token }), f.inject(a, { token: agent.token })]);
  assert.equal(one.status, 200, one.text); assert.deepEqual(one.json.injection, two.json.injection);
  assert.equal(f.google.refreshes, 1);
  assert.equal(f.secret(a).refresh_token, 'refresh-personal-rotated');
  assert.deepEqual(f.secret(a).scopes, with_(CLOUD));
});

test('更新でアカウントが変わった場合は渡さず、元の接続を再接続待ちにする', async t => {
  const f = await googleFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  f.google.userinfoHandler = () => json({ sub: 'sub-work', email: 'work@example.test', email_verified: true });
  const result = await f.inject(a, { token: agent.token });
  assert.equal(result.json.error.code, 'account_changed');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
  assert.doesNotMatch(result.text, /google-access-/);
});

test('Googleの一時的な障害は再試行可能にし、失効した許可は再接続待ちにする', async t => {
  const f = await googleFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  for (const status of [403, 429, 500]) {
    f.google.refreshHandler = () => json({ error: 'private-provider-value', error_description: 'refresh-secret' }, status);
    const result = await f.inject(a, { token: agent.token });
    assert.ok(result.status >= 500);
    assert.doesNotMatch(result.text, /private-provider|refresh-secret/);
    assert.equal((await f.connections())[0].status, 'usable');
  }
  f.google.refreshHandler = () => json({ error: 'invalid_grant', error_description: 'private-provider-value' }, 400);
  assert.equal((await f.inject(a, { token: agent.token })).json.error.code, 'reconnect_required');
  assert.equal((await f.connections())[0].status, 'reconnect_required');
});

test('不正な認証応答と本人確認の応答を、秘密値を含まないエラーで拒否する', async () => {
  const google = new FakeGoogle(), valid = { access_token: 'a', refresh_token: 'r', scope: 'openid email', expires_in: 3600 };
  for (const change of [{ access_token: '' }, { access_token: 'a\r\nb' }, { expires_in: '3600' }, { expires_in: -1 }, { expires_in: 86401 }, { token_type: 'mac' },
    { refresh_token: 'a\nb' }, { scope: null }, { scope: '' }, { scope: 'openid\nemail' }]) assert.throws(() => google.grant({ ...valid, ...change }), { code: 'service_response' });
  assert.throws(() => google.grant({ ...valid, refresh_token: undefined }), { code: 'refresh_missing' });
  for (const change of [{ sub: '' }, { sub: 'a\nb' }, { email: undefined }, { email: 'bad-address' }, { email_verified: 'true' }]) {
    google.userinfoHandler = () => json({ sub: 'sub-personal', email: 'personal@example.test', email_verified: true, ...change });
    await assert.rejects(google.identity('google-access-personal'), { code: 'service_response' });
  }
});

test('接続の解除ではGoogleへの取り消しを選べ、送信する秘密値はPOST本文に収める', async t => {
  const f = await googleFixture(t), a = await f.connect(), b = await f.connect('work');
  const removed = await f.request('/v1/resources/' + a.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  const revoke = f.google.calls.find(call => call.url.endsWith('/revoke'));
  assert.equal(revoke.url, 'https://oauth2.googleapis.com/revoke');
  assert.equal(revoke.options.method, 'POST');
  assert.equal(revoke.options.body.get('token'), 'refresh-personal');
  assert.equal((await f.request('/v1/resources/' + b.id, { method: 'DELETE', data: { revoke: false } })).json.service_revoked, null);
  f.google.revokeHandler = () => json({ error: 'invalid_token' }, 400);
  await f.google.revoke({ refresh_token: 'already-gone' });
  for (const call of f.google.calls) { assert.equal(call.options.redirect, 'error'); assert.ok(call.options.signal); }
});

test('接続IDからGoogleの認証情報を更新し、CLI経由で子プロセスに渡す', async t => {
  const f = await googleFixture(t), a = await f.connect(), agent = await f.issueKey();
  f.expire(a.id);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-google-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'key');
  await writeFile(keyPath, agent.token, { mode: 0o600 });
  const command = ['cli/runtime.mjs', 'exec', '--inputs', JSON.stringify([{ id: a.id }]), '--', process.execPath, '-e',
    'if(process.env.CLOUDSDK_AUTH_ACCESS_TOKEN!=="google-access-personal-1"||process.env.GOOGLE_ACCOUNT_EMAIL!=="personal@example.test"||process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2);console.log("google-ready")'];
  const child = spawn(process.execPath, command, { env: { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath } });
  let out = '', err = '';
  child.stdout.on('data', value => { out += value; }); child.stderr.on('data', value => { err += value; });
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
  assert.equal(code, 0, err); assert.equal(out.trim(), 'google-ready');
  assert.doesNotMatch(out + err, /google-access-|refresh-/);
  assert.equal(f.google.refreshes, 1);
});
