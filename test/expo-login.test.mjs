import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { expoLoginFixture, LOGIN_PASSWORD, LOGIN_OTP } from './expo-login-helper.mjs';
import { json, USER_A } from './helpers.mjs';
import { ACQUISITION_LIMIT } from '../src/store.mjs';

const credential = (f, prefix, token) => f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: [prefix + '/session'] } });
// A registration request for an Expo login, from a key the owner has approved.
async function requestAccess(f, extra = {}) {
  const token = 'fdn_' + randomBytes(32).toString('base64url');
  await f.approveKey(token);
  const created = await f.request('/v1/access-requests', { method: 'POST', token, data: { adapter: 'expo.login', purpose: '接続の確認のみ', ...extra } });
  assert.equal(created.status, 201, created.text);
  const row = created.json.request;
  return { token, row, input: { accessRequestId: row.id } };
}
const safeResponse = response => assert.doesNotMatch(response.text, /fixture-password|fixture-session|"password"\s*:|sessionSecret|"otp"\s*:\s*"123456"/);

test('Expo password login stores only an encrypted session, never password/OTP or a fabricated API key', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-expo-login-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite'), f = await expoLoginFixture(t, { database });
  const result = await f.loginExpo();
  assert.equal(result.status, 200, result.text); safeResponse(result);
  const acquisition = f.app.store.acquisition(USER_A, result.json.prefix), held = f.app.store.acquisitionState(acquisition);
  assert.equal(held.renewal.credential_type, 'expo_session'); assert.deepEqual(held.renewal.scopes, ['expo:session']);
  assert.equal(held.expires_at, null);
  assert.ok(f.expo.sessions.has(held.renewal.access_token));
  assert.ok(!JSON.stringify(held).includes(LOGIN_PASSWORD));
  const disk = await readFile(database);
  assert.ok(!disk.includes(Buffer.from(LOGIN_PASSWORD))); assert.ok(!disk.includes(Buffer.from(held.renewal.access_token)));
  const state = await f.request('/api/state'); safeResponse(state);
  assert.equal(state.json.acquisitions[0].label, 'fixture-user'); assert.equal(state.json.acquisitions[0].can_revoke, true);
  assert.deepEqual(state.json.entries.map(entry => [entry.path, entry.session]), [[acquisition.prefix + '/session', 'expo']]);
  assert.equal(f.app.store.agents(USER_A).length, 0, 'root connection alone never grants a runtime');
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.ok(f.expo.calls[0].url.endsWith('/auth/loginAsync'));
  assert.deepEqual(JSON.parse(f.expo.calls[0].options.body), { username: 'fixture-user', password: LOGIN_PASSWORD });
  assert.equal(f.expo.calls[1].options.headers['expo-session'], held.renewal.access_token);
  assert.equal(f.expo.calls[1].options.headers.authorization, undefined);
});

test('Logging in through a registration request completes it and delivers a typed session to the runtime', async t => {
  const f = await expoLoginFixture(t), { token, row, input } = await requestAccess(f);
  assert.equal(row.adapter.register, 'login'); assert.equal(row.confirmation_code, undefined);
  assert.deepEqual((await f.request('/v1/acquisitions', { token })).json.acquisitions, []);
  const result = await f.loginExpo(input); assert.equal(result.status, 200, result.text); safeResponse(result);
  assert.equal(result.json.request.status, 'approved');
  const listed = await f.request('/v1/entries', { token }); safeResponse(listed);
  assert.deepEqual(listed.json.entries.map(entry => [entry.env, entry.session]), [[null, 'expo']], 'the session reaches the command as Expo login state, not a variable');
  const issued = await credential(f, result.json.prefix, token);
  assert.equal(issued.status, 200, issued.text);
  assert.deepEqual(issued.json.delivery.environment, {}); assert.equal(issued.json.expires_at, null);
  assert.deepEqual(issued.json.delivery.expo_session.profile, { user_id: 'expo-fixture-user', username: 'fixture-user' });
  assert.equal(typeof issued.json.delivery.expo_session.secret, 'string');
  assert.doesNotMatch(issued.text, /fixture-password/);
});

test('Expo MFA keeps no server-side password challenge, grants nothing before valid OTP, redacts upstream metadata', async t => {
  const f = await expoLoginFixture(t), { input, token } = await requestAccess(f);
  const challenge = await f.loginExpo({ ...input, username: 'otp-user' });
  assert.equal(challenge.status, 202); safeResponse(challenge);
  assert.deepEqual(challenge.json, { challenge: { type: 'otp', delivery: 'authenticator' } });
  assert.equal(f.app.store.acquisitions(USER_A).length, 0);
  const wrong = await f.loginExpo({ ...input, username: 'otp-user', otp: '000000' });
  assert.equal(wrong.status, 400); safeResponse(wrong); assert.doesNotMatch(wrong.text, /000000/);
  const complete = await f.loginExpo({ ...input, username: 'otp-user', otp: LOGIN_OTP });
  assert.equal(complete.status, 200, complete.text); safeResponse(complete);
  assert.equal((await f.request('/v1/acquisitions', { token, anonymous: true })).json.acquisitions[0].prefix, complete.json.prefix);
  const stored = f.app.store.acquisitionState(f.app.store.acquisition(USER_A, complete.json.prefix));
  assert.ok(!JSON.stringify(stored).includes(LOGIN_PASSWORD)); assert.ok(!JSON.stringify(stored).includes(LOGIN_OTP));
  const sms = await f.loginExpo({ username: 'sms-user' });
  assert.deepEqual(sms.json, { challenge: { type: 'otp', delivery: 'sms' } });
});

test('Login cannot be invoked by an anonymous runtime, another origin, or a request for another adapter', async t => {
  const f = await expoLoginFixture(t), request = await requestAccess(f);
  assert.equal((await f.loginExpo(request.input, { anonymous: true, token: request.token })).status, 401);
  assert.equal((await f.loginExpo(request.input, { headers: { origin: 'https://attacker.example' } })).status, 403);
  const wrongAdapter = await requestAccess(f, { adapter: 'gmail.readonly' });
  assert.equal((await f.loginExpo(wrongAdapter.input)).json.error.code, 'scope_mismatch');
  assert.equal(f.expo.calls.length, 0);
  await f.loginExpo({ ...request.input, username: 'otp-user' });
  await f.login('other@example.test');
  const crossUser = await f.loginExpo(request.input); assert.equal(crossUser.status, 404); safeResponse(crossUser);
});

for (const kind of ['cancel', 'deny', 'expire', 'logout', 'switch-user']) test('In-flight Expo login is discarded and logged out on ' + kind, async t => {
  const f = await expoLoginFixture(t), { input, row, token } = await requestAccess(f);
  let release, started; const waiting = new Promise(resolve => started = resolve);
  f.expo.loginHandler = async () => { started(); await new Promise(resolve => release = resolve); };
  const pending = f.loginExpo(input); await waiting;
  if (kind === 'cancel') await f.request('/v1/access-requests/current', { method: 'DELETE', token, data: {} });
  if (kind === 'deny') await f.request('/api/access-requests/' + row.id + '/deny', { method: 'POST', data: {} });
  if (kind === 'expire') f.app.store.db.prepare('UPDATE access_requests SET expires_at=0 WHERE id=?').run(row.id);
  if (kind === 'logout') await f.request('/api/session', { method: 'DELETE' });
  if (kind === 'switch-user') await f.login('other@example.test');
  release(); const result = await pending;
  assert.ok(result.status >= 400, result.text); safeResponse(result);
  assert.equal(f.app.store.acquisitions(USER_A).length, 0);
  assert.equal(f.expo.sessions.size, 0);
  assert.equal(f.expo.calls.filter(call => call.url.endsWith('/auth/logout')).length, 1);
});

test('A registration that cannot be stored rolls back and logs out upstream; nested transactions preserve an outer transaction', async t => {
  const f = await expoLoginFixture(t), { input } = await requestAccess(f);
  for (let i = 0; i < ACQUISITION_LIMIT; i++) {
    f.app.store.saveAcquisition(USER_A, { prefix: 'filler/' + i, adapter: 'expo.login', subject: 'session:' + i, label: 'filler ' + i, state: { renewal: {}, facts: {}, expires_at: null } },
      [{ path: 'filler/' + i + '/value', content: Buffer.from('x'), media_type: 'text/plain', env: null, filename: null, session: null, readable: 0 }]);
  }
  const result = await f.loginExpo(input);
  assert.equal(result.status, 409, result.text); assert.equal(result.json.error.code, 'acquisition_limit'); safeResponse(result);
  assert.equal(f.app.store.acquisitions(USER_A).length, ACQUISITION_LIMIT); assert.equal(f.expo.sessions.size, 0);
  assert.equal(f.app.store.transactionDepth, 0);
  f.app.store.transaction(() => {
    assert.throws(() => f.app.store.transaction(() => { throw new Error('rollback nested only'); }));
    f.app.store.db.prepare('INSERT INTO metadata VALUES (?, ?)').run('nested-test', 'preserved');
  });
  assert.equal(f.app.store.db.prepare('SELECT value FROM metadata WHERE name=?').get('nested-test').value, 'preserved');
});

test('Closing the browser request during login discards and logs out the upstream session', async t => {
  const f = await expoLoginFixture(t), { input } = await requestAccess(f);
  let release, started, revoked;
  const began = new Promise(resolve => started = resolve), loggedOut = new Promise(resolve => revoked = resolve);
  f.expo.loginHandler = async () => { started(); await new Promise(resolve => release = resolve); };
  f.expo.logoutHandler = (_url, options) => { f.expo.sessions.delete(options.headers['expo-session']); revoked(); return json({ data: {} }); };
  const closed = new Promise(resolve => f.app.server.on('request', (req, res) => {
    if (req.url === '/api/adapters/expo.login/connect') res.once('close', resolve);
  }));
  const controller = new AbortController();
  const pending = fetch(f.base + '/api/adapters/expo.login/connect', { method: 'POST', signal: controller.signal,
    headers: { origin: f.base, cookie: f.cookie(), 'content-type': 'application/json' }, body: JSON.stringify({ ...input, name: 'Expo', username: 'fixture-user', password: LOGIN_PASSWORD }) });
  const aborted = assert.rejects(pending, { name: 'AbortError' });
  await began; controller.abort(); await aborted; await closed; release(); await loggedOut;
  assert.equal(f.expo.sessions.size, 0); assert.equal(f.app.store.acquisitions(USER_A).length, 0);
});

test('Concurrent login submissions cannot create two connections for one request', async t => {
  const f = await expoLoginFixture(t), { input } = await requestAccess(f);
  const release = []; let started;
  const began = new Promise(resolve => started = resolve);
  f.expo.loginHandler = async () => { await new Promise(resolve => { release.push(resolve); if (release.length === 2) started(); }); };
  const first = f.loginExpo(input), second = f.loginExpo(input);
  await began; release[0](); release[1]();
  const results = await Promise.all([first, second]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
  assert.equal(f.app.store.acquisitions(USER_A).length, 1); assert.equal(f.app.store.agents(USER_A).length, 1);
  assert.equal(f.expo.sessions.size, 1);
  assert.equal(f.expo.calls.filter(call => call.url.endsWith('/auth/logout')).length, 1);
});

test('Disconnect revokes only this Expo session and blocks issuance during an upstream logout failure', async t => {
  const f = await expoLoginFixture(t), { input, token } = await requestAccess(f), result = await f.loginExpo(input);
  const id = result.json.prefix;
  f.expo.logoutHandler = () => json({ errors: [{ message: 'private upstream body' }] }, 503);
  const failed = await f.request('/api/acquisitions/' + encodeURIComponent(id), { method: 'DELETE', data: { revoke: true } });
  assert.equal(failed.status, 200); assert.equal(failed.json.service_revoked, false);
  assert.doesNotMatch(failed.text, /private upstream/);
  assert.equal(f.app.store.acquisition(USER_A, id), undefined, 'it leaves Foundation whether or not Expo answered');
  assert.equal((await credential(f, id, token)).status, 404);
  // A session Foundation could log out is logged out.
  f.expo.logoutHandler = null;
  const second = await f.loginExpo((await requestAccess(f)).input);
  const removed = await f.request('/api/acquisitions/' + encodeURIComponent(second.json.prefix), { method: 'DELETE', data: { revoke: true } });
  assert.equal(removed.json.service_revoked, true);
  assert.equal(f.app.store.acquisition(USER_A, second.json.prefix), undefined);
});

test('Login is rate limited, transient errors redacted, and identity failure logs out the new session', async t => {
  const f = await expoLoginFixture(t);
  f.expo.loginHandler = () => json({ errors: [{ message: 'private body' }] }, 401);
  for (let index = 0; index < 10; index++) { const result = await f.loginExpo(); assert.equal(result.status, 400); assert.doesNotMatch(result.text, /private body/); }
  assert.equal((await f.loginExpo()).status, 429); assert.equal(f.expo.calls.length, 10);
  const second = await expoLoginFixture(t);
  second.expo.identityHandler = () => json({ data: { meActor: null } });
  assert.equal((await second.loginExpo()).status, 409);
  assert.equal(second.expo.sessions.size, 0);
});

test('EAS reads the isolated session; no EXPO_TOKEN, shared login overwrite, credential argv or disk copy', async t => {
  if (process.platform !== 'linux' || !existsSync('/usr/bin/bwrap')) { t.skip('Linux bubblewrap integration'); return; }
  let eas;
  try { eas = await realpath(execFileSync('which', ['eas'], { encoding: 'utf8' }).trim()); } catch { t.skip('Installed EAS CLI integration'); return; }
  const manager = join(dirname(dirname(eas)), 'build/user/SessionManager.js');
  const f = await expoLoginFixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-expo-runtime-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key'), EXPO_TOKEN: 'unrelated-token', EXPO_LOCAL: '1', EXPO_STAGING: '1' };
  const execute = args => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env }); let out = '', err = '';
    child.stdout.on('data', chunk => out += chunk); child.stderr.on('data', chunk => err += chunk); child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
  });
  const asked = JSON.parse((await execute(['connect'])).out).request;
  await f.request('/api/access-requests/' + asked.id + '/approve', { method: 'POST', data: { confirmationCode: asked.confirmation_code } });
  const created = await execute(['connect', '--adapter', 'expo.login', '--purpose', 'EAS のビルド']); assert.equal(created.code, 0, created.err);
  const row = JSON.parse(created.out).request; assert.equal(row.adapter.id, 'expo.login');
  const result = await f.loginExpo({ accessRequestId: row.id });
  const id = result.json.prefix + '/session';
  const fingerprint = async () => { try { return createHash('sha256').update(await readFile(join(homedir(), '.expo/state.json'))).digest('hex'); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } };
  const before = await fingerprint();
  const source = `const fs=require('node:fs'), path=require('node:path'), os=require('node:os'); const Manager=require(${JSON.stringify(manager)}).default; const state=new Manager({}).getSession(); if(!state.sessionSecret || state.username!=='fixture-user' || process.env.EXPO_TOKEN || process.env.EXPO_LOCAL || process.env.EXPO_STAGING)process.exit(2); const file=path.join(os.homedir(),'.expo/state.json'); if((fs.statSync(file).mode&0o777)!==0o600)process.exit(3); fs.writeFileSync(file,JSON.stringify({auth:{username:'private-overlay-only'}})); console.log('native-eas-ready');`;
  const run = await execute(['exec', id, '--', process.execPath, '-e', source]);
  assert.equal(run.code, 0, run.err); assert.equal(run.out.trim(), 'native-eas-ready');
  assert.equal(await fingerprint(), before, 'host login must remain byte-for-byte unchanged');
  assert.doesNotMatch(created.out + created.err + run.out + run.err, /fixture-password|fixture-session|fdn_/);
  await f.request('/api/acquisitions/' + encodeURIComponent(result.json.prefix), { method: 'DELETE', data: { revoke: true } });
  const rejected = await execute(['exec', id, '--', process.execPath, '-e', 'console.log("must-not-run")']);
  assert.equal(rejected.code, 1); assert.doesNotMatch(rejected.out, /must-not-run/);
});
