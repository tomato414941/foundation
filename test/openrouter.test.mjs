import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { OpenRouterClient, OPENROUTER_API } from '../src/services/openrouter.mjs';
import { FakeOpenRouter, openrouterFixture } from './openrouter-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', part => out += part); child.stderr.on('data', part => err += part);
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});
const credential = (f, id, token) => f.request('/v1/credentials/' + id + '/deliver', { method: 'POST', anonymous: true, token, data: {} });

test('OpenRouter authorization binds state in callback and uses S256 without application secrets', () => {
  const client = new OpenRouterClient();
  const url = new URL(client.authorize({ redirectUri: 'https://foundation.example/oauth/openrouter.oauth/callback', state: 'state-nonce', verifier: 'verifier' }));
  assert.equal(url.origin + url.pathname, 'https://openrouter.ai/auth');
  assert.equal(new URL(url.searchParams.get('callback_url')).searchParams.get('state'), 'state-nonce');
  assert.equal(url.searchParams.get('code_challenge'), createHash('sha256').update('verifier').digest('base64url'));
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('key_label'), 'Foundation');
  assert.ok(!url.href.includes('client_secret') && !url.href.includes('verifier'));
});

test('OpenRouter exchanges only PKCE code, preserves real expiry and zero budget, exposes no secrets in UI state', async t => {
  const f = await openrouterFixture(t);
  const url = await f.startOpenRouter();
  assert.equal((await f.callbackOpenRouter(url)).headers.get('location'), '/?connection=connected&adapter=openrouter.oauth');
  assert.match((await f.callbackOpenRouter(url)).headers.get('location'), /connection=expired/);
  const response = await f.request('/api/state');
  const account = response.json.credentials[0];
  assert.equal(account.adapter, 'openrouter.oauth');
  assert.equal(account.credential_type, 'api_key');
  assert.equal(account.key_info.limit, 0);
  assert.equal(account.expires_at, null);
  assert.match(account.label, /^キー [a-f0-9]{12}$/);
  assert.match(account.management_url, /^https:\/\/openrouter.ai\/keys\/[a-f0-9]{64}$/);
  assert.doesNotMatch(response.text, /sk-or-v1-|"access_token":|refresh_token|client_secret/);
  assert.equal(f.openrouter.calls.length, 2);
  const body = JSON.parse(f.openrouter.calls[0].options.body);
  assert.deepEqual(Object.keys(body).sort(), ['code', 'code_challenge_method', 'code_verifier']);
  assert.equal(createHash('sha256').update(body.code_verifier).digest('base64url'), url.searchParams.get('code_challenge'));
  assert.equal(f.openrouter.calls[1].url, OPENROUTER_API + '/key');
  assert.equal(f.app.store.agents(USER_A).length, 0, 'connecting alone grants no runtime');
});

test('OpenRouter callback cannot use another session, forged state, or a denied authorization', async t => {
  const f = await openrouterFixture(t);
  const url = await f.startOpenRouter();
  assert.match((await f.callbackOpenRouter(url, 'personal', { anonymous: true })).headers.get('location'), /connection=expired/);
  const target = new URL(url.searchParams.get('callback_url'));
  const denied = await f.request(target.pathname + target.search + '&error=access_denied');
  assert.match(denied.headers.get('location'), /connection=denied/);
  assert.equal(f.openrouter.calls.length, 0);
  const forged = await f.request('/oauth/openrouter.oauth/callback?state=' + 'x'.repeat(43) + '&code=personal');
  assert.match(forged.headers.get('location'), /connection=expired/);
  assert.equal(f.openrouter.calls.length, 0);
});

test('API key is delivered only to an approved key; revocation metadata never promises short expiry', async t => {
  const f = await openrouterFixture(t), token = 'fdn_' + randomBytes(32).toString('base64url');
  assert.equal((await f.request('/v1/credentials', { token, anonymous: true })).status, 401, 'nothing before the key is approved');
  await f.approveKey(token);
  const created = await f.request('/v1/access-requests', { method: 'POST', token, data: { adapter: 'openrouter.oauth', purpose: 'キー情報を確認。モデルは実行しない。' } });
  const row = created.json.request;
  assert.equal(row.adapter.can_revoke, false);
  assert.match(row.adapter.access.restrictions, /読み取り専用のキーではありません/);
  const callback = await f.callbackOpenRouter(await f.startOpenRouter({ accessRequestId: row.id }));
  assert.equal(callback.headers.get('location'), '/connect/' + row.id + '?connection=connected');
  const account = (await f.request('/api/state')).json.credentials[0];
  assert.equal((await f.request('/api/access-requests/' + row.id)).json.request.status, 'approved', 'registering completes the request');
  const listed = await f.request('/v1/credentials', { token });
  assert.deepEqual(listed.json.credentials[0].variables, ['OPENROUTER_API_KEY']);
  assert.match(listed.json.credentials[0].delivery.revocation, /Keys already delivered/);
  assert.doesNotMatch(listed.text, /sk-or-v1-/);
  const issued = await credential(f, account.id, token);
  assert.equal(issued.status, 200, issued.text);
  assert.deepEqual(issued.json.delivery.environment, { OPENROUTER_API_KEY: f.openrouter.key() });
  assert.equal(issued.json.expires_at, null);
  assert.equal(issued.json.expires_in, null);
  assert.equal(f.app.store.agents(USER_A)[0].issued_nonexpiring, 1);
  await f.request('/api/agents/' + f.app.store.agents(USER_A)[0].id, { method: 'DELETE' });
  assert.equal((await credential(f, account.id, token)).status, 401);
});

test('OpenRouter keys are owner-separated, cannot silently replace connections, and remain encrypted on disk', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'foundation-openrouter-storage-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const database = join(dir, 'state.sqlite'), f = await openrouterFixture(t, { database });
  const account = await f.openrouterAccount(), agent = await f.agent();
  assert.ok(!(await readFile(database)).includes(Buffer.from(f.openrouter.key())));
  const replacement = await f.request('/api/adapters/openrouter.oauth/connect', { method: 'POST', data: { credentialId: account.id, name: 'replacement' } });
  assert.equal(replacement.json.error.code, 'new_connection_required');
  await f.login('other@example.test');
  assert.equal((await f.request('/api/state')).json.credentials.length, 0);
  assert.equal((await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 404);
  const own = await f.openrouterAccount('other'), other = await f.agent();
  assert.equal((await credential(f, account.id, other.token)).status, 403);
  assert.equal((await credential(f, own.id, agent.token)).status, 403);
});

test('Local disconnect never pretends to delete OpenRouter key or calls a management endpoint', async t => {
  const f = await openrouterFixture(t), account = await f.openrouterAccount(), agent = await f.agent();
  const refused = await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(refused.json.error.code, 'manual_revocation_required');
  assert.equal((await credential(f, account.id, agent.token)).status, 200);
  const removed = await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: false } });
  assert.equal(removed.json.service_revoked, false);
  assert.equal((await credential(f, account.id, agent.token)).status, 403);
  assert.equal(f.app.store.credential(USER_A, account.id), undefined);
  assert.ok(f.openrouter.calls.every(call => ['/auth/keys', '/key'].some(path => call.url === OPENROUTER_API + path)));
});

test('Provider expiry, revocation and budget updates are checked before every API key delivery', async t => {
  const f = await openrouterFixture(t);
  f.openrouter.info.expires_at = new Date(Date.now() + 86_400_000).toISOString();
  const account = await f.openrouterAccount(), agent = await f.agent();
  f.openrouter.info.limit = 10; f.openrouter.info.limit_remaining = 8; f.openrouter.info.limit_reset = 'monthly';
  let issued = await credential(f, account.id, agent.token);
  assert.equal(issued.json.expires_at, Date.parse(f.openrouter.info.expires_at));
  assert.ok(issued.json.expires_in > 80_000, 'not replaced with a fictitious short lifetime');
  assert.equal(issued.json.key_info.limit, 10);
  assert.equal(f.app.store.agents(USER_A)[0].issued_nonexpiring, 0);
  f.openrouter.keyHandler = () => json({ error: 'secret upstream response' }, 401);
  issued = await credential(f, account.id, agent.token);
  assert.equal(issued.json.error.code, 'reconnect_required');
  assert.doesNotMatch(issued.text, /secret upstream|sk-or-v1-/);
  assert.equal(f.app.store.credential(USER_A, account.id).status, 'reconnect_required');
});

test('OpenRouter in-flight key is withheld after the key is revoked', async t => {
  const f = await openrouterFixture(t), account = await f.openrouterAccount(), agent = await f.agent();
  let release, started;
  const waiting = new Promise(resolve => started = resolve);
  f.openrouter.keyHandler = async () => { started(); await new Promise(resolve => release = resolve); return json({ data: f.openrouter.info }); };
  const pending = credential(f, account.id, agent.token);
  await waiting;
  await f.request('/api/agents/' + agent.id, { method: 'DELETE' });
  release();
  const result = await pending;
  assert.equal(result.status, 401);
  assert.doesNotMatch(result.text, /sk-or-v1-/);
});

for (const [name, change] of [
  ['management key', { is_management_key: true }], ['legacy management key', { is_provisioning_key: true }],
  ['invalid expiry', { expires_at: 'not-a-date' }], ['expired key', { expires_at: '2000-01-01T00:00:00Z' }],
  ['invalid limit', { limit: 'unlimited' }], ['negative limit', { limit: -1 }], ['unknown limit reset', { limit_reset: 'surprise' }],
]) test('OpenRouter rejects ' + name, async () => {
  const client = new FakeOpenRouter(); Object.assign(client.info, change);
  await assert.rejects(client.exchange({ code: 'personal', verifier: 'secret-verifier' }));
});

test('OpenRouter accepts explicit unlimited and zero budgets without changing them', async () => {
  const client = new FakeOpenRouter();
  client.info.limit = null; client.info.limit_remaining = null;
  const result = await client.exchange({ code: 'personal', verifier: 'verifier' });
  assert.equal(result.secret.details.limit, null);
  assert.equal(client.calls.length, 2);
  client.info.limit = 0; client.info.limit_remaining = 0;
  assert.equal((await client.inspect(client.key())).details.limit, 0);
});

test('CLI asks for approval, then injects the OpenRouter key only into the child process, and is refused after the key is revoked', async t => {
  const f = await openrouterFixture(t), account = await f.openrouterAccount();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-openrouter-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key') };
  const start = await execute(['connect', '--name', 'dev-us'], env);
  assert.equal(start.code, 0, start.err);
  const row = JSON.parse(start.out).request;
  assert.equal(row.kind, 'approve');
  const approved = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code } });
  assert.equal(approved.status, 200);
  const run = await execute(['exec', account.id, '--', process.execPath, '-e', 'if(!process.env.OPENROUTER_API_KEY || process.env.GOOGLE_OAUTH_ACCESS_TOKEN || process.env.FOUNDATION_RUNTIME_KEY_FILE)process.exit(2); console.log("authenticated")'], env);
  assert.equal(run.code, 0, run.err); assert.equal(run.out.trim(), 'authenticated');
  assert.doesNotMatch(start.out + start.err + run.out + run.err, /sk-or-v1-|fdn_/);
  await f.request('/api/agents/' + approved.json.request.agent_id, { method: 'DELETE' });
  assert.equal((await execute(['exec', account.id, '--', process.execPath, '-e', 'process.exit(0)'], env)).code, 1);
});
