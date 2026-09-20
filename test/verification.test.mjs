import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cloudflareFixture, CLOUDFLARE_TOKEN, CLOUDFLARE_ACCOUNT } from './cloudflare-helper.mjs';
import { fixture, FakeGmail, KEY, USER_A, json } from './helpers.mjs';
import { ApiKeyProvider } from '../src/providers/apikey.mjs';
import { apikeyConnection, gmailConnection } from '../src/providers/catalog.mjs';
import { verification, verificationResult } from '../src/verification.mjs';
import { HttpError } from '../src/errors.mjs';
import { Store } from '../src/store.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
async function create(f, token = key(), extra = {}) {
  const result = await f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { name: 'dev-us', provider: 'cloudflare', mode: 'api-token', purpose: 'R2の一覧を確認', ...extra } });
  assert.equal(result.status, 201, result.text);
  return { token, row: result.json.request };
}
const status = async (f, token) => (await f.request('/v1/access-requests/current', { anonymous: true, token })).json.request;
const check = (report, name) => report.checks.find(item => item.check === name);
const approve = (f, row, accountId) => f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId, confirmationCode: row.confirmation_code } });
const credentials = (f, id, token) => f.request('/v1/accounts/' + id + '/credentials', { method: 'POST', anonymous: true, token, data: {} });
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', part => out += part); child.stderr.on('data', part => err += part);
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});

test('Failed import reaches only the requesting AI, stores no secret, and can be retried on the same request', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  const failed = await f.importCloudflare({ accessRequestId: row.id, token: 'invalid-token-with-valid-syntax' });
  assert.equal(failed.status, 409);
  const pending = await status(f, token);
  assert.equal(pending.status, 'pending');
  assert.equal(pending.verification.revision, 1);
  assert.equal(check(pending.verification, 'credential').code, 'reconnect_required');
  assert.equal(check(pending.verification, 'credential').http_status, 401);
  assert.equal(check(pending.verification, 'r2_bucket_list').status, 'unknown');
  assert.equal(f.app.store.accounts(USER_A).length, 0);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  const stored = JSON.stringify(f.app.store.db.prepare('SELECT * FROM access_requests').all());
  assert.doesNotMatch(stored, /invalid-token-with-valid-syntax|fixturetoken|test-bucket-do-not-store/);
  assert.equal((await f.request('/v1/access-requests/current', { token: key(), anonymous: true })).status, 410);
  const originalCookie = 'fdn_session=' + f.app.store.createSession(f.auth.value());
  await f.login('other@example.test');
  assert.equal((await f.request('/api/access-requests/' + row.id)).status, 404);
  assert.equal((await f.importCloudflare({ accessRequestId: row.id })).status, 404);
  const valid = await f.request('/api/connections/cloudflare/connect', { method: 'POST', headers: { cookie: originalCookie }, data: { name: 'Cloudflare', mode: 'api-token', token: CLOUDFLARE_TOKEN, fields: { account_id: CLOUDFLARE_ACCOUNT }, accessRequestId: row.id } });
  assert.equal(valid.status, 200, valid.text);
  const latest = await status(f, token);
  assert.equal(latest.id, row.id); assert.equal(latest.verification.revision, 2);
  assert.equal(check(latest.verification, 'credential').status, 'passed');
  assert.equal(check(latest.verification, 'permissions').status, 'unknown');
  assert.equal((await credentials(f, valid.json.account_id, token)).status, 401);
});

test('R2 failure permits explicit approval and delivery; the failed observation remains visible to the AI', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  f.cloudflare.handler = url => url.includes('/r2/') ? json({ success: false, errors: [{ message: CLOUDFLARE_TOKEN }] }, 403) : null;
  const imported = await f.importCloudflare({ accessRequestId: row.id });
  assert.equal(imported.status, 200);
  assert.equal(check(imported.json.verification, 'credential').status, 'passed');
  assert.equal(check(imported.json.verification, 'r2_bucket_list').http_status, 403);
  assert.equal((await credentials(f, imported.json.account_id, token)).status, 401);
  const result = await approve(f, row, imported.json.account_id);
  assert.equal(result.status, 200, result.text);
  assert.equal(check((await status(f, token)).verification, 'r2_bucket_list').status, 'failed');
  const issued = await credentials(f, imported.json.account_id, token);
  assert.equal(issued.status, 200);
  assert.equal(issued.json.access_token, CLOUDFLARE_TOKEN);
  assert.equal(check(issued.json.verification, 'r2_bucket_list').code, 'r2_unavailable');
  assert.ok(!JSON.stringify(issued.json.verification).includes(CLOUDFLARE_TOKEN));
});

test('Correcting an account ID before approval updates only this ungranted candidate', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  const first = await f.importCloudflare({ accessRequestId: row.id, fields: { account_id: 'f'.repeat(32) } });
  assert.equal(first.status, 200);
  assert.equal(check(first.json.verification, 'r2_bucket_list').status, 'failed');
  const second = await f.importCloudflare({ accessRequestId: row.id });
  assert.equal(second.status, 200, second.text); assert.equal(second.json.account_id, first.json.account_id);
  assert.equal(f.app.store.accounts(USER_A).length, 1);
  assert.equal(check((await status(f, token)).verification, 'r2_bucket_list').status, 'passed');
  const other = await f.agent([second.json.account_id]);
  const retry = await f.importCloudflare({ accessRequestId: row.id, fields: { account_id: 'e'.repeat(32) } });
  assert.equal(retry.status, 409);
  assert.equal((await credentials(f, second.json.account_id, other.token)).status, 200);
  assert.equal(f.app.store.secrets(f.app.store.account(USER_A, second.json.account_id)).details.account_id, CLOUDFLARE_ACCOUNT);
});

test('Verification output is a bounded allowlist, not upstream messages or input fields', () => {
  const secret = 'sensitive-credential-and-upstream-prompt';
  const error = new HttpError(502, 'provider_response', secret);
  assert.ok(!JSON.stringify(verificationResult(null, error)).includes(secret));
  const result = verification([{ check: secret, status: secret, code: secret, message: secret, token: secret, http_status: secret }]);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.equal(result.checks[0].status, 'unknown');
  assert.equal(verification(Array(100).fill({})).checks.length, 8);
  assert.equal(verification([null]).checks[0].status, 'unknown');
  assert.equal(verificationResult({ credentials: { verification: { checks: 'invalid' } } }).checks[0].status, 'unknown');
});

test('A provider outage is reported as unknown, not as proof of bad credentials', async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  f.cloudflare.handler = () => { throw new Error(CLOUDFLARE_TOKEN); };
  assert.equal((await f.importCloudflare({ accessRequestId: row.id })).status, 502);
  const pending = await status(f, token);
  assert.equal(check(pending.verification, 'credential').status, 'unknown');
  assert.equal(check(pending.verification, 'credential').code, 'provider_unavailable');
  assert.ok(!JSON.stringify(pending).includes(CLOUDFLARE_TOKEN));
  assert.equal(f.app.store.accounts(USER_A).length, 0);
});

test('Generic API keys report unverified, without pretending to verify the provider or permissions', async t => {
  const gmail = new FakeGmail(), f = await fixture(t, { gmail, integrations: [gmailConnection(gmail), apikeyConnection(new ApiKeyProvider())] });
  const details = { service: 'Example', site: 'https://example.test/keys', env: 'EXAMPLE_API_KEY' };
  const { row, token } = await create(f, key(), { provider: 'apikey', mode: 'key', details });
  const result = await f.request('/api/connections/apikey/connect', { method: 'POST', data: { name: 'Example', mode: 'key', token: 'example-private-key', accessRequestId: row.id } });
  assert.equal(result.status, 200, result.text);
  const pending = await status(f, token);
  assert.deepEqual(pending.verification.checks.map(item => item.status), ['unknown', 'unknown']);
  assert.doesNotMatch(JSON.stringify(pending), /example-private-key/);
});

test('OAuth failures also reach the AI and retry through the existing URL', async t => {
  const f = await fixture(t), { row, token } = await create(f, key(), { provider: 'gmail', mode: 'metadata' });
  const begin = async () => new URL((await f.request('/api/connections/gmail/connect', { method: 'POST', data: { name: 'Gmail', mode: 'metadata', accessRequestId: row.id } })).json.url);
  const failed = await f.callback(await begin(), 'personal-readonly');
  assert.match(failed.headers.get('location'), /connection=scope/);
  assert.equal((await status(f, token)).verification.checks[0].code, 'scope_mismatch');
  const succeeded = await f.callback(await begin(), 'personal-metadata');
  assert.match(succeeded.headers.get('location'), /connection=connected/);
  assert.equal((await status(f, token)).verification.revision, 2);
  assert.equal((await status(f, token)).verification.checks[0].status, 'passed');
});

for (const end of ['cancel', 'logout', 'newer']) test('A stale verification cannot publish results or create a connection after ' + end, { timeout: 8000 }, async t => {
  const f = await cloudflareFixture(t), { row, token } = await create(f);
  let release, entered;
  const ready = new Promise(resolve => entered = resolve);
  f.cloudflare.handler = async () => { entered(); await new Promise(resolve => release = resolve); return json({ success: false }, 401); };
  const first = f.importCloudflare({ accessRequestId: row.id });
  await Promise.race([ready, first.then(result => { throw new Error('Probe did not begin: ' + result.status); })]);
  try {
    if (end === 'cancel') await f.request('/v1/access-requests/current', { method: 'DELETE', token, anonymous: true, data: {} });
    if (end === 'logout') await f.request('/api/session', { method: 'DELETE' });
    if (end === 'newer') {
      f.cloudflare.handler = null;
      assert.equal((await f.importCloudflare({ accessRequestId: row.id })).status, 200);
    }
  } finally { release(); }
  assert.notEqual((await first).status, 200);
  const latest = await status(f, token);
  if (end === 'newer') { assert.equal(latest.verification.revision, 2); assert.equal(check(latest.verification, 'credential').status, 'passed'); }
  else { assert.equal(latest.verification, undefined); assert.equal(f.app.store.accounts(USER_A).length, 0); }
});

test('CLI wait returns verification without granting access and can wait for a later revision', { timeout: 12000 }, async t => {
  const f = await cloudflareFixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-verification-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const { row, token } = await create(f), keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  await f.importCloudflare({ accessRequestId: row.id, token: 'invalid-token-with-valid-syntax' });
  const observed = await execute(['wait', '--timeout', '1'], env);
  assert.equal(observed.code, 0, observed.err);
  const data = JSON.parse(observed.out);
  assert.equal(data.event, 'verification'); assert.equal(data.request.status, 'pending');
  assert.equal(data.request.verification.revision, 1);
  assert.equal((await execute(['accounts'], env)).code, 1);
  assert.equal((await execute(['wait', '--timeout', '1', '--after-verification', '1'], env)).code, 1);
  let polled;
  const firstPoll = new Promise(resolve => polled = resolve);
  const listener = req => { if (req.url === '/v1/access-requests/current') polled(); };
  f.app.server.on('request', listener);
  const waiting = execute(['wait', '--timeout', '7', '--after-verification', '1'], env);
  await firstPoll; f.app.server.off('request', listener);
  const imported = await f.importCloudflare({ accessRequestId: row.id });
  const next = await waiting;
  assert.equal(next.code, 0, next.err); assert.equal(JSON.parse(next.out).request.verification.revision, 2);
  await approve(f, row, imported.json.account_id);
  assert.equal(JSON.parse((await execute(['wait', '--timeout', '1', '--after-verification', '2'], env)).out).request.status, 'approved');
  f.cloudflare.handler = url => url.includes('/r2/') ? json({ success: false }, 403) : null;
  const run = await execute(['exec', imported.json.account_id, '--', process.execPath, '-e', 'if(!process.env.CLOUDFLARE_API_TOKEN)process.exit(2);console.log("native-ready")'], env);
  assert.equal(run.code, 0, run.err); assert.equal(run.out.trim(), 'native-ready');
  assert.equal(check(JSON.parse(run.err).verification, 'r2_bucket_list').status, 'failed');
  assert.ok(!run.err.includes(CLOUDFLARE_TOKEN));
  for (const bad of ['-1', '1.5', 'NaN', '9007199254740992']) assert.equal((await execute(['wait', '--after-verification', bad], env)).code, 1);
  assert.doesNotMatch(observed.out + observed.err + next.out + next.err, /fixturetoken|invalid-token-with-valid-syntax|fdn_/);
});

test('Schema upgrade preserves existing requests and grants; reports expire with requests', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-verification-migration-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite');
  const f = await cloudflareFixture(t, { database }), { row, token } = await create(f);
  const imported = await f.importCloudflare({ accessRequestId: row.id });
  await approve(f, row, imported.json.account_id);
  f.app.store.db.exec('ALTER TABLE access_requests DROP COLUMN verification; ALTER TABLE access_requests DROP COLUMN verification_revision; PRAGMA user_version=4;');
  const store = new Store(database, KEY);
  t.after(() => store.close());
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 5);
  assert.equal(store.authenticate(token).owner_id, USER_A);
  assert.equal(store.secrets(store.account(USER_A, imported.json.account_id)).access_token, CLOUDFLARE_TOKEN);
  const record = store.db.prepare('SELECT * FROM access_requests WHERE id=?').get(row.id);
  assert.equal(record.status, 'approved'); assert.equal(record.verification, null); assert.equal(record.verification_revision, 0);
  store.db.prepare('UPDATE access_requests SET expires_at=0, verification=? WHERE id=?').run(JSON.stringify(verification([{ check: 'connection', code: 'completed', status: 'passed' }])), row.id);
  store.sweep();
  assert.equal(store.db.prepare('SELECT count(*) n FROM access_requests').get().n, 0);
  assert.ok(store.authenticate(token));
});
