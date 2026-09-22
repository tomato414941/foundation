import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { CLOUDFLARE_API, CLOUDFLARE_TOKENS } from '../src/services/cloudflare.mjs';
import { GenericClient } from '../src/generic.mjs';
import { cloudflareFixture, FakeCloudflare, CLOUDFLARE_TOKEN, CLOUDFLARE_ACCOUNT } from './cloudflare-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const credential = (f, id, token) => f.request('/v1/accounts/' + id + '/credentials', { method: 'POST', anonymous: true, token, data: {} });
const createRequest = async (f, token) => (await f.request('/v1/access-requests', { method: 'POST', token, anonymous: true, data: { adapter: 'cloudflare.api-token', permission: 'api-token', name: 'dev-us', purpose: 'R2のバケット一覧を確認。変更は行わない。' } })).json.request;
const inspect = provider => provider.inspect(CLOUDFLARE_TOKEN, CLOUDFLARE_ACCOUNT);
const code = expected => error => error.code === expected;

test('Cloudflare verifies a user token and probes one R2 list page without keeping bucket data', async t => {
  const f = await cloudflareFixture(t), account = await f.cloudflareAccount({ fields: { account_id: CLOUDFLARE_ACCOUNT.toUpperCase() } });
  const state = await f.request('/api/state'), adapter = state.json.adapters.find(item => item.id === 'cloudflare.api-token');
  assert.equal(adapter.register, 'paste');
  assert.equal(adapter.form.links[0].href, CLOUDFLARE_TOKENS);
  assert.deepEqual(adapter.form.schema.map(field => field.id), ['account_id', 'token']);
  assert.equal(adapter.can_revoke, false);
  assert.equal(account.cloudflare_account_id, CLOUDFLARE_ACCOUNT);
  assert.equal(account.label, 'Cloudflare ' + CLOUDFLARE_ACCOUNT);
  assert.equal(account.expires_at, Date.parse(f.cloudflare.verification.expires_on));
  assert.equal(account.expiry_known, true);
  assert.equal(account.permission.id, 'api-token');
  assert.match(account.permission.restrictions, /全権限/);
  assert.ok(!state.text.includes(CLOUDFLARE_TOKEN));
  assert.doesNotMatch(state.text, /test-bucket-do-not-store|token_id|token_hash/);
  const saved = f.app.store.secrets(f.app.store.account(USER_A, account.id));
  assert.doesNotMatch(JSON.stringify(saved), /test-bucket-do-not-store/);
  assert.deepEqual(f.cloudflare.calls.map(call => call.url.slice(CLOUDFLARE_API.length)), ['/user/tokens/verify', '/accounts/' + CLOUDFLARE_ACCOUNT + '/r2/buckets?per_page=1']);
  assert.ok(f.cloudflare.calls.every(call => call.options.redirect === 'error' && call.options.method === 'GET' && call.options.headers.authorization === 'Bearer ' + CLOUDFLARE_TOKEN));
});

test('Cloudflare rejects invalid account IDs and token kinds before any network request', async () => {
  const provider = new FakeCloudflare();
  for (const id of [undefined, null, [], {}, 123, '', '../user', 'https://example.test', 'g'.repeat(32)]) {
    await assert.rejects(provider.inspect(CLOUDFLARE_TOKEN, id), code('invalid_account'));
  }
  for (const token of [null, {}, '', 'short', 'a'.repeat(257), 'a'.repeat(20) + '\n', 'cfk_' + 'a'.repeat(40), 'cfat_' + 'a'.repeat(40)]) {
    await assert.rejects(provider.inspect(token, CLOUDFLARE_ACCOUNT), code('invalid_credential'));
  }
  assert.equal(provider.calls.length, 0);
  await assert.rejects(provider.importToken({ values: { token: CLOUDFLARE_TOKEN, account_id: CLOUDFLARE_ACCOUNT }, permission: 'readonly' }), code('invalid_permission'));
});

test('Cloudflare accepts legacy user tokens, no expiry and empty bucket lists', async () => {
  const provider = new FakeCloudflare(), legacy = 'a'.repeat(40);
  provider.valid.add(legacy); provider.verification.expires_on = null; provider.buckets = [];
  const value = await provider.inspect(legacy, ' ' + CLOUDFLARE_ACCOUNT + ' ');
  assert.equal(value.expires_at, null); assert.equal(value.expiry_known, true);
  assert.equal(value.details.account_id, CLOUDFLARE_ACCOUNT);
});

test('Cloudflare rejects disabled, expired and not-yet-valid tokens before probing R2', async () => {
  for (const patch of [{ status: 'disabled' }, { status: 'expired' }, { expires_on: '2000-01-01T00:00:00Z' }, { not_before: '2099-01-01T00:00:00Z' }]) {
    const provider = new FakeCloudflare(); Object.assign(provider.verification, patch);
    await assert.rejects(inspect(provider), code('reconnect_required'));
    assert.equal(provider.calls.length, 1);
  }
  for (const patch of [{ status: 'unknown' }, { id: '../tokens' }, { expires_on: 'bad' }, { not_before: 1 }]) {
    const provider = new FakeCloudflare(); Object.assign(provider.verification, patch);
    await assert.rejects(inspect(provider), code('service_response'));
  }
});

test('Cloudflare handles invalid envelopes, provider failures and rate limits without exposing upstream errors', async () => {
  const provider = new FakeCloudflare();
  for (const [response, errorCode] of [
    [json({ success: false, errors: [{ message: CLOUDFLARE_TOKEN }] }), 'reconnect_required'],
    [json({ success: true, result: [] }), 'service_response'],
    [json({ result: provider.verification }), 'service_response'],
    [new Response('invalid-json'), 'service_response'],
    [json({ message: CLOUDFLARE_TOKEN }, 401), 'reconnect_required'],
    [json({ message: CLOUDFLARE_TOKEN }, 429), 'service_rate_limit'],
    [json({ message: CLOUDFLARE_TOKEN }, 500), 'service_unavailable'],
  ]) {
    provider.handler = () => response;
    await assert.rejects(inspect(provider), error => error.code === errorCode && !error.message.includes(CLOUDFLARE_TOKEN));
  }
  provider.handler = () => { throw new Error(CLOUDFLARE_TOKEN); };
  await assert.rejects(inspect(provider), error => error.code === 'service_unavailable' && !error.message.includes(CLOUDFLARE_TOKEN));
  provider.handler = url => url.includes('/r2/') ? json({ success: true, result: { buckets: [null] } }) : null;
  const unverified = await inspect(provider);
  assert.equal(unverified.verification.checks[1].code, 'service_response');
  assert.equal(unverified.verification.checks[1].status, 'unknown');
});

test('Cloudflare records R2 access failures without blocking registration of a valid token', async t => {
  const f = await cloudflareFixture(t);
  const bad = await f.importCloudflare({ fields: { account_id: 'f'.repeat(32) } });
  assert.equal(bad.status, 200); assert.equal(bad.json.verification.checks[1].code, 'r2_unavailable');
  assert.equal(f.app.store.accounts(USER_A).length, 1);
  assert.equal(f.app.store.agents(USER_A).length, 0);
  assert.equal((await f.importCloudflare({ fields: {} })).status, 400);
  assert.equal((await f.importCloudflare({ permission: 'admin' })).status, 400);
  assert.equal((await f.importCloudflare()).status, 409);
  const generic = new GenericClient();
  for (const env of ['CLOUDFLARE_API_TOKEN', 'CF_API_TOKEN']) assert.throws(() => generic.details({ service: 'Cloudflare', site: CLOUDFLARE_TOKENS, fields: [{ id: env }] }), /環境変数名/);
});

test('Cloudflare requires explicit approval, keeps tokens encrypted and stops delivery after revocation', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-cloudflare-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.db'), f = await cloudflareFixture(t, { database });
  const token = 'fdn_' + randomBytes(32).toString('base64url'), row = await createRequest(f, token);
  const account = await f.cloudflareAccount({ accessRequestId: row.id });
  assert.equal((await credential(f, account.id, token)).status, 401);
  const approved = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { accountId: account.id, confirmationCode: row.confirmation_code } });
  assert.equal(approved.status, 200, approved.text);
  const listed = await f.request('/v1/accounts', { token, anonymous: true });
  assert.equal(listed.json.accounts[0].token_env, 'CLOUDFLARE_API_TOKEN');
  assert.equal(listed.json.accounts[0].cloudflare_account_id, CLOUDFLARE_ACCOUNT);
  assert.ok(!listed.text.includes(CLOUDFLARE_TOKEN));
  const issued = await credential(f, account.id, token);
  assert.equal(issued.status, 200, issued.text);
  assert.equal(issued.json.access_token, CLOUDFLARE_TOKEN);
  assert.equal(issued.json.token_env, 'CLOUDFLARE_API_TOKEN');
  assert.equal(issued.json.api_base_url, CLOUDFLARE_API);
  f.app.store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  assert.ok(!(await readFile(database)).includes(Buffer.from(CLOUDFLARE_TOKEN)));
  f.cloudflare.valid.clear();
  const revoked = await credential(f, account.id, token);
  assert.equal(revoked.status, 409); assert.equal(revoked.json.error.code, 'reconnect_required');
  assert.equal((await f.request('/api/state')).json.accounts[0].status, 'reconnect_required');
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: true } })).json.error.code, 'manual_revocation_required');
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 200);
  assert.equal((await credential(f, account.id, token)).status, 403);
});

test('Cloudflare rechecks R2 access and token identity on delivery but does not invalidate on a network outage', async t => {
  const f = await cloudflareFixture(t), account = await f.cloudflareAccount(), agent = await f.agent();
  f.cloudflare.handler = () => { throw new Error('offline'); };
  assert.equal((await credential(f, account.id, agent.token)).status, 502);
  assert.equal((await f.request('/api/state')).json.accounts[0].status, 'connected');
  f.cloudflare.handler = null;
  const original = f.cloudflare.verification.id;
  f.cloudflare.verification.id = 'c'.repeat(32);
  assert.equal((await credential(f, account.id, agent.token)).json.error.code, 'service_response');
  f.cloudflare.verification.id = original;
  f.cloudflare.handler = url => url.includes('/r2/') ? json({ success: false }, 403) : null;
  const result = await credential(f, account.id, agent.token);
  assert.equal(result.status, 200);
  assert.equal(result.json.verification.checks[1].code, 'r2_unavailable');
  assert.equal((await f.request('/api/state')).json.accounts[0].status, 'connected');
});

test('Cloudflare cannot be imported across user sessions or after an approval request is cancelled', { timeout: 10_000 }, async t => {
  const f = await cloudflareFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url');
  const row = await createRequest(f, token);
  let release, entered;
  const ready = new Promise(resolve => { entered = resolve; });
  f.cloudflare.handler = async url => { if (url.endsWith('/verify')) { entered(); await new Promise(resolve => { release = resolve; }); } };
  const importing = f.importCloudflare({ accessRequestId: row.id });
  await Promise.race([ready, importing.then(result => { throw new Error('Verification ended before the probe: ' + result.status); })]);
  let cancelled;
  try { cancelled = await f.request('/v1/access-requests/current', { method: 'DELETE', anonymous: true, token, data: {} }); }
  finally { release(); }
  assert.equal(cancelled.status, 200, cancelled.text);
  assert.equal((await importing).status, 409);
  assert.equal(f.app.store.accounts(USER_A).length, 0);
  f.cloudflare.handler = null;
  const account = await f.cloudflareAccount(), agent = await f.agent();
  await f.login('other@example.test');
  assert.equal((await f.request('/api/state')).json.accounts.length, 0);
  assert.equal((await f.request('/api/accounts/' + account.id + '/check', { method: 'POST', data: {} })).status, 404);
  const otherAccount = await f.account('other'), other = await f.agent();
  assert.equal((await credential(f, account.id, other.token)).status, 403);
  assert.equal((await credential(f, account.id, agent.token)).status, 200);
});

test('Cloudflare import cannot recreate a connection after the user logs out during verification', { timeout: 10_000 }, async t => {
  const f = await cloudflareFixture(t);
  let release, entered;
  const ready = new Promise(resolve => { entered = resolve; });
  f.cloudflare.handler = async url => { if (url.endsWith('/verify')) { entered(); await new Promise(resolve => { release = resolve; }); } };
  const importing = f.importCloudflare();
  await Promise.race([ready, importing.then(result => { throw new Error('Verification ended before the probe: ' + result.status); })]);
  let logout;
  try { logout = await f.request('/api/session', { method: 'DELETE' }); }
  finally { release(); }
  assert.equal(logout.status, 200);
  assert.equal((await importing).status, 401);
  assert.equal(f.app.store.accounts(USER_A).length, 0);
});

test('Cloudflare native API credentials are injected into the child process without printing the token', async t => {
  const f = await cloudflareFixture(t), account = await f.cloudflareAccount(), agent = await f.agent();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-cloudflare-runtime-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const key = join(dir, 'runtime-key'); await writeFile(key, agent.token, { mode: 0o600 });
  const output = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['src/runtime.mjs', 'exec', account.id, '--', process.execPath, '-e',
      'if(!process.env.CLOUDFLARE_API_TOKEN?.startsWith("cfut_") || process.env.CLOUDFLARE_API_TOKEN!==process.env.FOUNDATION_ACCESS_TOKEN || process.env.FOUNDATION_API_BASE_URL!=="https://api.cloudflare.com/client/v4" || process.env.FOUNDATION_RUNTIME_KEY_FILE) process.exit(2); console.log("cloudflare-ready")'],
    { env: { ...process.env, FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: key } });
    let out = '', err = '';
    child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
    child.once('error', reject); child.once('exit', status => resolve({ status, out, err }));
  });
  assert.equal(output.status, 0, output.err);
  assert.equal(output.out.trim(), 'cloudflare-ready');
  assert.ok(!output.out.includes(CLOUDFLARE_TOKEN) && !output.err.includes(CLOUDFLARE_TOKEN));
});
