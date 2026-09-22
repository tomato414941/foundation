import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { EXPO_API, EXPO_TOKENS } from '../src/services/expo.mjs';
import { FakeExpo, expoFixture } from './expo-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const credential = (f, id, token) => f.request('/v1/credentials/' + id + '/deliver', { method: 'POST', anonymous: true, token, data: {} });
// A registration request comes from a key the owner has approved.
const createRequest = async (f, token) => { await f.approveKey(token); return (await f.request('/v1/access-requests', { method: 'POST', token, anonymous: true, data: { adapter: 'expo.token', purpose: 'アカウントの確認のみ。ビルドしません。' } })).json.request; };
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', chunk => out += chunk); child.stderr.on('data', chunk => err += chunk);
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});

test('Expo import is a discoverable token flow, validates identity without mutations and hides secrets from UI', async t => {
  const f = await expoFixture(t), account = await f.expoAccount();
  const state = await f.request('/api/state'), adapter = state.json.adapters.find(item => item.id === 'expo.token');
  assert.equal(adapter.register, 'paste');
  assert.equal(adapter.form.links[0].href, EXPO_TOKENS);
  assert.equal(adapter.can_reconnect, false); assert.equal(adapter.can_revoke, false);
  assert.match(adapter.access.description, /すべてのアカウント・組織/);
  assert.equal(account.label, 'fixture-expo-user');
  assert.equal(account.credential_type, 'api_key'); assert.equal(account.expires_at, null); assert.equal(account.expiry_known, false);
  assert.ok(!state.text.includes(f.expo.tokenValue()));
  assert.doesNotMatch(state.text, /"access_token":|refresh_token|session_secret/);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  assert.equal(f.expo.calls.length, 1);
  const call = f.expo.calls[0];
  assert.equal(call.url, EXPO_API); assert.equal(call.options.redirect, 'error');
  assert.deepEqual(Object.keys(call.options.headers).sort(), ['authorization', 'content-type']);
  assert.equal(call.options.headers.authorization, 'Bearer ' + f.expo.tokenValue());
  assert.doesNotMatch(call.options.body, /mutation|password|session_secret/);
});

test('Expo token import requires a human session and same-origin POST; bad tokens and wrong scopes never connect', async t => {
  const f = await expoFixture(t);
  assert.equal((await f.importExpo({}, { anonymous: true })).status, 401);
  assert.equal((await f.importExpo({}, { headers: { origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await f.importExpo({ token: 'password' })).json.error.code, 'invalid_credential');
  assert.equal((await f.importExpo({ token: 'a'.repeat(15) + '\r\n' + 'a'.repeat(15) })).json.error.code, 'invalid_values');
  assert.equal((await f.importExpo({ token: 'a'.repeat(1025) })).json.error.code, 'invalid_credential');
  assert.equal(f.expo.calls.length, 0);
  const invalid = await f.importExpo({ token: 'syntactically-valid-but-revoked' });
  assert.equal(invalid.json.error.code, 'reconnect_required');
  assert.doesNotMatch(invalid.text, /fixture secret|syntactically-valid/);
  assert.equal((await f.request('/api/state')).json.credentials.length, 0);
});

test('Expo supports Robot and SSO identities without pretending tokens are read-only or short-lived', async () => {
  const expo = new FakeExpo();
  expo.actor = { __typename: 'Robot', id: 'robot-1', firstName: 'limited-bot' };
  let result = await expo.importToken({ values: { token: expo.tokenValue() } });
  assert.equal(expo.facts(result.secret).label, 'limited-bot (Robot)');
  expo.actor = { __typename: 'SSOUser', id: 'sso-1', username: 'org-user' };
  result = await expo.importToken({ values: { token: expo.tokenValue() } });
  assert.equal(expo.facts(result.secret).label, 'org-user');
  assert.equal(result.secret.expires_at, null);
  assert.equal(result.secret.expiry_known, false);
});

test('Expo approval binds requesting runtime, retains explicit consent and prevents later delivery after revocation', async t => {
  const f = await expoFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url');
  assert.equal((await f.request('/v1/credentials', { token, anonymous: true })).status, 401, 'nothing before the key is approved');
  const row = await createRequest(f, token), account = await f.expoAccount({ accessRequestId: row.id });
  assert.equal((await f.request('/api/access-requests/' + row.id)).json.request.status, 'approved', 'registering completes the request');
  const listed = await f.request('/v1/credentials', { token });
  assert.deepEqual(listed.json.credentials[0].variables, ['EXPO_TOKEN']);
  assert.match(listed.json.credentials[0].delivery.revocation, /until the service expires or deletes them/);
  assert.ok(!listed.text.includes(f.expo.tokenValue()));
  const issued = await credential(f, account.id, token);
  assert.equal(issued.status, 200); assert.deepEqual(issued.json.delivery.environment, { EXPO_TOKEN: f.expo.tokenValue() });
  assert.equal(issued.json.expires_at, null); assert.equal(issued.json.expires_in, null);
  assert.equal(listed.json.credentials[0].api.base_url, EXPO_API);
  assert.equal(f.app.store.agents(USER_A)[0].issued_nonexpiring, 1);
  assert.equal(f.expo.calls.length, 2, 'identity is rechecked on delivery');
  await f.request('/api/agents/' + f.app.store.agents(USER_A)[0].id, { method: 'DELETE' });
  assert.equal((await credential(f, account.id, token)).status, 401);
});

test('Expo tokens stay encrypted and owner-separated; duplicate imports and silent replacement are rejected', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-expo-store-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite'), f = await expoFixture(t, { database });
  const account = await f.expoAccount(), agent = await f.agent();
  assert.ok(!(await readFile(database)).includes(Buffer.from(f.expo.tokenValue())));
  assert.ok(!f.app.store.credential(USER_A, account.id).secret.includes(f.expo.tokenValue()));
  assert.equal((await f.importExpo()).json.error.code, 'already_connected');
  assert.equal((await f.importExpo({ credentialId: account.id, token: f.expo.tokenValue('second') })).json.error.code, 'new_connection_required');
  await f.login('other@example.test');
  assert.equal((await f.request('/api/state')).json.credentials.length, 0);
  assert.equal((await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 404);
  const other = await f.expoAccount({ token: f.expo.tokenValue('second') }), otherAgent = await f.agent();
  assert.equal((await credential(f, account.id, otherAgent.token)).status, 403);
  assert.equal((await credential(f, other.id, agent.token)).status, 403);
});

for (const change of ['logout', 'cancel', 'expire', 'deny']) test('Expo does not save a token after in-flight ' + change, async t => {
  const f = await expoFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url'), row = await createRequest(f, token);
  let release, started;
  const waiting = new Promise(resolve => started = resolve);
  f.expo.identityHandler = async () => { started(); await new Promise(resolve => release = resolve); return json({ data: { meActor: f.expo.actor } }); };
  const pending = f.importExpo({ accessRequestId: row.id }); await waiting;
  if (change === 'logout') await f.request('/api/session', { method: 'DELETE' });
  if (change === 'cancel') await f.request('/v1/access-requests/current', { method: 'DELETE', token, data: {} });
  if (change === 'expire') f.app.store.db.prepare('UPDATE access_requests SET expires_at=0 WHERE id=?').run(row.id);
  if (change === 'deny') await f.request('/api/access-requests/' + row.id + '/deny', { method: 'POST', data: {} });
  release(); const result = await pending;
  assert.ok(result.status >= 400, result.text);
  assert.equal(f.app.store.credentials(USER_A).length, 0);
  assert.ok(!result.text.includes(f.expo.tokenValue()));
});

test('Revoked Expo token is not delivered and local disconnect never claims to revoke at Expo', async t => {
  const f = await expoFixture(t), account = await f.expoAccount(), agent = await f.agent();
  assert.equal((await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: true } })).json.error.code, 'manual_revocation_required');
  f.expo.identityHandler = () => json({ errors: [{ message: f.expo.tokenValue() }] }, 401);
  const result = await credential(f, account.id, agent.token);
  assert.equal(result.json.error.code, 'reconnect_required'); assert.ok(!result.text.includes(f.expo.tokenValue()));
  assert.equal(f.app.store.credential(USER_A, account.id).status, 'reconnect_required');
  assert.equal((await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: false } })).json.service_revoked, false);
  assert.equal((await credential(f, account.id, agent.token)).status, 403);
});

test('Expo withholds in-flight credentials after the key is revoked', async t => {
  const f = await expoFixture(t), account = await f.expoAccount(), agent = await f.agent();
  let release, started;
  const waiting = new Promise(resolve => started = resolve);
  f.expo.identityHandler = async () => { started(); await new Promise(resolve => release = resolve); return json({ data: { meActor: f.expo.actor } }); };
  const pending = credential(f, account.id, agent.token); await waiting;
  await f.request('/api/agents/' + agent.id, { method: 'DELETE' });
  release(); const result = await pending;
  assert.equal(result.status, 401); assert.ok(!result.text.includes(f.expo.tokenValue()));
});

for (const value of [null, {}, { data: { meActor: null } }, { data: { meActor: { id: 'one', __typename: 'User', username: '\n' } } }, { errors: 'secret error' }, { data: { meActor: { id: 'one', __typename: 'User', username: 'partial' } }, errors: [{ message: 'secret error' }] }]) {
  test('Expo rejects malformed, missing or partial identity: ' + JSON.stringify(value), async () => {
    const expo = new FakeExpo(); expo.identityHandler = () => json(value);
    await assert.rejects(expo.inspect(expo.tokenValue()), error => ['service_response', 'reconnect_required'].includes(error.code) && !error.message.includes('secret error'));
  });
}

test('CLI resumes Expo approval and injects EXPO_TOKEN only into selected command, without displaying it', async t => {
  const f = await expoFixture(t), account = await f.expoAccount();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-expo-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key'), EXPO_TOKEN: 'unrelated-existing-token', OPENROUTER_API_KEY: 'unrelated-key', GOOGLE_OAUTH_ACCESS_TOKEN: 'unrelated-google' };
  const start = await execute(['connect', '--name', 'dev-us のAI'], env);
  assert.equal(start.code, 0, start.err);
  const row = JSON.parse(start.out).request;
  assert.equal(row.kind, 'approve');
  assert.equal((await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code } })).status, 200);
  const run = await execute(['exec', account.id, '--', process.execPath, '-e', 'if(!process.env.EXPO_TOKEN || process.env.EXPO_TOKEN==="unrelated-existing-token" || process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2); console.log("expo-ready")'], env);
  assert.equal(run.code, 0, run.err); assert.equal(run.out.trim(), 'expo-ready');
  assert.ok(!(start.out + start.err + run.out + run.err).includes(f.expo.tokenValue()));
  assert.doesNotMatch(start.out + start.err + run.out + run.err, /fdn_/);
  const gmail = await f.credential();
  const other = await execute(['exec', gmail.id, '--', process.execPath, '-e', 'if(!process.env.GOOGLE_OAUTH_ACCESS_TOKEN) process.exit(2)'], env);
  assert.equal(other.code, 0, other.err);
});

test('Session login is off by default; stored sessions stop being delivered when it is disabled', async t => {
  const { ExpoClient, EXPO_SESSION_SCOPE } = await import('../src/services/expo.mjs');
  assert.equal(new ExpoClient().sessionLoginEnabled, false);
  const f = await expoFixture(t);
  const login = await f.request('/api/adapters/expo.login/connect', { method: 'POST', data: { username: 'u', password: 'p' } });
  assert.ok([400, 503].includes(login.status), login.text);
  assert.equal(f.app.store.credentials(USER_A).length, 0);
  const account = await f.expoAccount();
  const store = f.app.store, id = account.id, row = store.credential(USER_A, id);
  store.saveSecret(row, { ...store.secret(row), credential_type: 'expo_session', scopes: [EXPO_SESSION_SCOPE], details: { ...store.secret(row).details } });
  const check = await f.request('/api/credentials/' + id + '/check', { method: 'POST', data: {} });
  assert.equal(check.status, 409); assert.equal(check.json.error.code, 'reconnect_required');
  assert.equal(store.credential(row.owner_id, id).status, 'reconnect_required');
});
