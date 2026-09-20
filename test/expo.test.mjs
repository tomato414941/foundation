import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { EXPO_API, EXPO_TOKENS } from '../src/providers/expo.mjs';
import { FakeExpo, expoFixture } from './expo-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const credential = (f, id, token) => f.request('/v1/accounts/' + id + '/credentials', { method: 'POST', anonymous: true, token, data: {} });
const createRequest = async (f, token) => (await f.request('/v1/access-requests', { method: 'POST', token, data: { provider: 'expo', mode: 'access-token', name: 'dev-us のAI', purpose: 'アカウントの確認のみ。ビルドしません。' } })).json.request;
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', chunk => out += chunk); child.stderr.on('data', chunk => err += chunk);
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});

test('Expo import is a discoverable token flow, validates identity without mutations and hides secrets from UI', async t => {
  const f = await expoFixture(t), account = await f.expoAccount();
  const state = await f.request('/api/state'), provider = state.json.providers.find(item => item.id === 'expo');
  assert.equal(provider.connection_method, 'token');
  assert.equal(provider.token_setup.url, EXPO_TOKENS);
  assert.equal(provider.can_reconnect, false); assert.equal(provider.can_revoke, false);
  assert.match(provider.permissions[0].description, /すべてのアカウント・組織/);
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
  assert.equal((await f.importExpo({ mode: 'readonly' })).json.error.code, 'invalid_scope');
  assert.equal((await f.importExpo({ token: 'password' })).json.error.code, 'invalid_credential');
  assert.equal((await f.importExpo({ token: 'a'.repeat(30) + '\r\n' })).json.error.code, 'invalid_credential');
  assert.equal((await f.importExpo({ token: 'a'.repeat(1025) })).json.error.code, 'invalid_credential');
  assert.equal(f.expo.calls.length, 0);
  const invalid = await f.importExpo({ token: 'syntactically-valid-but-revoked' });
  assert.equal(invalid.json.error.code, 'reconnect_required');
  assert.doesNotMatch(invalid.text, /fixture secret|syntactically-valid/);
  assert.equal((await f.request('/api/state')).json.accounts.length, 0);
});

test('Expo supports Robot and SSO identities without pretending tokens are read-only or short-lived', async () => {
  const expo = new FakeExpo();
  expo.actor = { __typename: 'Robot', id: 'robot-1', firstName: 'limited-bot' };
  let result = await expo.importToken({ token: expo.tokenValue(), mode: 'access-token' });
  assert.equal(expo.accountInfo(result.credentials).label, 'limited-bot (Robot)');
  expo.actor = { __typename: 'SSOUser', id: 'sso-1', username: 'org-user' };
  result = await expo.importToken({ token: expo.tokenValue(), mode: 'access-token' });
  assert.equal(expo.accountInfo(result.credentials).label, 'org-user');
  assert.equal(result.credentials.expires_at, null);
  assert.equal(result.credentials.expiry_known, false);
});

test('Expo approval binds requesting runtime, retains explicit consent and prevents later delivery after revocation', async t => {
  const f = await expoFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url');
  const row = await createRequest(f, token), account = await f.expoAccount({ accessRequestId: row.id });
  assert.equal((await credential(f, account.id, token)).status, 401);
  assert.equal((await f.request('/v1/access-requests/current', { token })).json.request.status, 'pending');
  const approve = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: row.confirmation_code } });
  assert.equal(approve.status, 200);
  const listed = await f.request('/v1/accounts', { token });
  assert.equal(listed.json.accounts[0].authentication.type, 'api_key_bearer');
  assert.match(listed.json.accounts[0].authentication.revocation, /deletion on Expo/);
  assert.ok(!listed.text.includes(f.expo.tokenValue()));
  const issued = await credential(f, account.id, token);
  assert.equal(issued.status, 200); assert.equal(issued.json.access_token, f.expo.tokenValue());
  assert.equal(issued.json.expires_at, null); assert.equal(issued.json.expires_in, null);
  assert.equal(issued.json.api_base_url, EXPO_API);
  assert.equal(f.app.store.agents(USER_A)[0].issued_nonexpiring, 1);
  assert.equal(f.expo.calls.length, 2, 'identity is rechecked on delivery');
  await f.request('/api/agents/' + approve.json.request.agent_id, { method: 'DELETE' });
  assert.equal((await credential(f, account.id, token)).status, 401);
});

test('Expo tokens stay encrypted and owner-separated; duplicate imports and silent replacement are rejected', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-expo-store-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite'), f = await expoFixture(t, { database });
  const account = await f.expoAccount(), agent = await f.agent([account.id]);
  assert.ok(!(await readFile(database)).includes(Buffer.from(f.expo.tokenValue())));
  assert.ok(!f.app.store.account(USER_A, account.id).credentials.includes(f.expo.tokenValue()));
  assert.equal((await f.importExpo()).json.error.code, 'already_connected');
  assert.equal((await f.importExpo({ accountId: account.id, token: f.expo.tokenValue('second') })).json.error.code, 'new_connection_required');
  await f.login('other@example.test');
  assert.equal((await f.request('/api/state')).json.accounts.length, 0);
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 404);
  const other = await f.expoAccount({ token: f.expo.tokenValue('second') }), otherAgent = await f.agent([other.id]);
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
  assert.equal(f.app.store.accounts(USER_A).length, 0);
  assert.ok(!result.text.includes(f.expo.tokenValue()));
});

test('Revoked Expo token is not delivered and local disconnect never claims to revoke at Expo', async t => {
  const f = await expoFixture(t), account = await f.expoAccount(), agent = await f.agent([account.id]);
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: true } })).json.error.code, 'manual_revocation_required');
  f.expo.identityHandler = () => json({ errors: [{ message: f.expo.tokenValue() }] }, 401);
  const result = await credential(f, account.id, agent.token);
  assert.equal(result.json.error.code, 'reconnect_required'); assert.ok(!result.text.includes(f.expo.tokenValue()));
  assert.equal(f.app.store.account(USER_A, account.id).status, 'reconnect_required');
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: false } })).json.provider_revoked, false);
  assert.equal((await credential(f, account.id, agent.token)).status, 403);
});

test('Expo withholds in-flight credentials after permission removal', async t => {
  const f = await expoFixture(t), account = await f.expoAccount(), agent = await f.agent([account.id]);
  let release, started;
  const waiting = new Promise(resolve => started = resolve);
  f.expo.identityHandler = async () => { started(); await new Promise(resolve => release = resolve); return json({ data: { meActor: f.expo.actor } }); };
  const pending = credential(f, account.id, agent.token); await waiting;
  await f.request('/api/agents/' + agent.id + '/grants', { method: 'PUT', data: { accountIds: [] } });
  release(); const result = await pending;
  assert.equal(result.status, 403); assert.ok(!result.text.includes(f.expo.tokenValue()));
});

for (const value of [null, {}, { data: { meActor: null } }, { data: { meActor: { id: 'one', __typename: 'User', username: '\n' } } }, { errors: 'secret error' }, { data: { meActor: { id: 'one', __typename: 'User', username: 'partial' } }, errors: [{ message: 'secret error' }] }]) {
  test('Expo rejects malformed, missing or partial identity: ' + JSON.stringify(value), async () => {
    const expo = new FakeExpo(); expo.identityHandler = () => json(value);
    await assert.rejects(expo.inspect(expo.tokenValue()), error => ['provider_response', 'reconnect_required'].includes(error.code) && !error.message.includes('secret error'));
  });
}

test('CLI resumes Expo approval and injects EXPO_TOKEN only into selected command, without displaying it', async t => {
  const f = await expoFixture(t), account = await f.expoAccount();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-expo-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key'), EXPO_TOKEN: 'unrelated-existing-token', OPENROUTER_API_KEY: 'unrelated-key', GOOGLE_OAUTH_ACCESS_TOKEN: 'unrelated-google' };
  const start = await execute(['connect', '--provider', 'expo', '--name', 'dev-us のAI'], env);
  assert.equal(start.code, 0, start.err);
  const row = JSON.parse(start.out).request;
  assert.equal(row.provider, 'expo'); assert.equal(row.mode, 'access-token');
  await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: row.confirmation_code } });
  const run = await execute(['exec', account.id, '--', process.execPath, '-e', 'if(!process.env.EXPO_TOKEN || process.env.EXPO_TOKEN!==process.env.FOUNDATION_ACCESS_TOKEN || process.env.EXPO_TOKEN==="unrelated-existing-token" || process.env.FOUNDATION_PROVIDER!=="expo" || process.env.FOUNDATION_TOKEN_EXPIRES_AT!=="" || process.env.GOOGLE_OAUTH_ACCESS_TOKEN || process.env.OPENROUTER_API_KEY || process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2); console.log("expo-ready")'], env);
  assert.equal(run.code, 0, run.err); assert.equal(run.out.trim(), 'expo-ready');
  assert.ok(!(start.out + start.err + run.out + run.err).includes(f.expo.tokenValue()));
  assert.doesNotMatch(start.out + start.err + run.out + run.err, /fdn_/);
  const gmail = await f.account();
  const agent = f.app.store.agents(USER_A)[0];
  await f.request('/api/agents/' + agent.id + '/grants', { method: 'PUT', data: { accountIds: [account.id, gmail.id] } });
  const other = await execute(['exec', gmail.id, '--', process.execPath, '-e', 'if(process.env.EXPO_TOKEN || process.env.OPENROUTER_API_KEY || !process.env.GOOGLE_OAUTH_ACCESS_TOKEN) process.exit(2)'], env);
  assert.equal(other.code, 0, other.err);
});
