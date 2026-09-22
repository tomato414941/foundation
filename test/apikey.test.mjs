import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, FakeGmail, USER_A } from './helpers.mjs';
import { apikeyConnection, gmailConnection } from '../src/providers/catalog.mjs';
import { ApiKeyProvider } from '../src/providers/apikey.mjs';
import { validEnvName, validRequestedEnvName } from '../src/env-name.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const claim = { service: 'Anthropic', site: 'https://console.anthropic.com/settings/keys', env: 'ANTHROPIC_API_KEY' };
const secret = 'sk-ant-fixture-' + randomBytes(16).toString('hex');
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});
async function apikeyFixture(t) {
  const gmail = new FakeGmail();
  return fixture(t, { gmail, integrations: [apikeyConnection(new ApiKeyProvider()), gmailConnection(gmail)] });
}
const create = (f, token, details = claim, extra = {}) => f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { provider: 'apikey', mode: 'key', name: 'dev-us のAI', purpose: 'Claude APIでの要約', details, ...extra } });

test('Environment variable names cannot hijack the child process or borrow built-in provider names', () => {
  for (const name of ['ANTHROPIC_API_KEY', 'STRIPE_SECRET_KEY', 'X']) assert.ok(validRequestedEnvName(name), name);
  for (const name of ['PATH', 'HOME', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'NODE_OPTIONS', 'FOUNDATION_ACCESS_TOKEN', 'lower', '1ABC', 'A-B', '', undefined, 'A'.repeat(65)]) assert.equal(validEnvName(name), false, String(name));
  for (const name of ['OPENROUTER_API_KEY', 'EXPO_TOKEN', 'GOOGLE_OAUTH_ACCESS_TOKEN']) { assert.ok(validEnvName(name), name); assert.equal(validRequestedEnvName(name), false, name); }
});

test('A runtime declares service, key page and variable; the declaration is validated and shown, never trusted as a scope', async t => {
  const f = await apikeyFixture(t), token = key();
  for (const [details, code] of [[null, 'invalid_details'], [{ ...claim, service: '' }, 'invalid_service'], [{ ...claim, service: '<b>x</b>' }, 'invalid_service'], [{ ...claim, site: 'http://example.com/keys' }, 'invalid_site'], [{ ...claim, site: 'https://user:pw@example.com/' }, 'invalid_site'], [{ ...claim, site: 'https://localhost/keys' }, 'invalid_site'], [{ ...claim, env: 'PATH' }, 'invalid_env'], [{ ...claim, env: 'OPENROUTER_API_KEY' }, 'invalid_env'], [{ ...claim, env: 'anthropic_api_key' }, 'invalid_env']]) {
    const response = await create(f, token, details);
    assert.equal(response.status, 400, JSON.stringify(details)); assert.equal(response.json.error.code, code, JSON.stringify(details));
  }
  const created = await create(f, token);
  assert.equal(created.status, 201, created.text);
  const row = created.json.request;
  assert.deepEqual(row.details, claim);
  assert.deepEqual(row.service.request_fields.map(field => field.id), ['service', 'site', 'env']);
  assert.equal(row.service.api.base_url, '');
  // Same declaration reuses the pending request; a different one conflicts.
  assert.equal((await create(f, token)).json.request.id, row.id);
  assert.equal((await create(f, token, { ...claim, env: 'OTHER_KEY' })).status, 409);
  const page = await f.request('/api/access-requests/' + row.id);
  assert.deepEqual(page.json.request.details, claim);
  assert.equal(page.json.request.confirmation_code, undefined);
  return { f, token, row };
});

test('The user pastes the key; it is bound to the declaration, delivered under the declared variable, and never verified or claimed as scoped', async t => {
  const f = await apikeyFixture(t), token = key();
  const row = (await create(f, token)).json.request;
  // Import through the request: details come from the request, not the browser.
  const bad = await f.request('/api/connections/apikey/connect', { method: 'POST', data: { name: 'Anthropic', mode: 'key', token: 'with space', accessRequestId: row.id } });
  assert.equal(bad.status, 400); assert.equal(bad.json.error.code, 'invalid_credential');
  const imported = await f.request('/api/connections/apikey/connect', { method: 'POST', data: { name: 'Anthropic', mode: 'key', token: secret, accessRequestId: row.id, details: { ...claim, env: 'IGNORED_NAME' } } });
  assert.equal(imported.status, 200, imported.text);
  const state = (await f.request('/api/state')).json, account = state.accounts.find(item => item.id === imported.json.account_id);
  assert.equal(account.verified, false);
  assert.deepEqual(account.details, claim);
  assert.deepEqual(account.scopes, ['apikey', 'service:anthropic', 'env:ANTHROPIC_API_KEY']);
  assert.equal(account.management_url, claim.site);
  assert.doesNotMatch(JSON.stringify(state), new RegExp(secret));
  assert.equal(account.permission.id, 'key');
  // Duplicate key content is rejected; the same key cannot be registered twice.
  assert.equal((await f.request('/api/connections/apikey/connect', { method: 'POST', data: { name: 'Anthropic', mode: 'key', token: secret, details: claim } })).status, 409);
  // A key for another service registered outside the request is an ordinary second connection.
  const other = await f.request('/api/connections/apikey/connect', { method: 'POST', data: { name: 'Stripe', mode: 'key', token: 'sk_live_fixture_' + randomBytes(8).toString('hex'), details: { service: 'Stripe', site: 'https://dashboard.stripe.com/apikeys', env: 'STRIPE_SECRET_KEY' } } });
  assert.equal(other.status, 200, other.text);
  const approved = await f.request('/api/access-requests/' + row.id + '/approve', { method: 'POST', data: { confirmationCode: row.confirmation_code } });
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.request.account.label, 'Anthropic キー …' + account.email.split(':')[1].slice(0, 8));
  // Runtime side: listing names the variable; exec sets it and nothing else leaks.
  const listed = await f.request('/v1/accounts', { token, anonymous: true });
  assert.deepEqual(listed.json.accounts.map(item => item.token_env).sort(), ['ANTHROPIC_API_KEY', 'STRIPE_SECRET_KEY']);
  assert.equal(listed.json.accounts.find(item => item.id === account.id).authentication.type, 'api_key_bearer');
  assert.doesNotMatch(listed.text, new RegExp(secret));
  const issued = await f.request('/v1/accounts/' + account.id + '/credentials', { method: 'POST', token, anonymous: true, data: {} });
  assert.equal(issued.status, 200, issued.text);
  assert.equal(issued.json.access_token, secret);
  assert.equal(issued.json.token_env, 'ANTHROPIC_API_KEY');
  assert.equal(issued.json.expires_at, null);
  assert.equal(issued.json.scope, 'apikey service:anthropic env:ANTHROPIC_API_KEY');
  const dir = await mkdtemp(join(tmpdir(), 'foundation-apikey-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  const { writeFile } = await import('node:fs/promises'); await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const run = await execute(['exec', account.id, '--', process.execPath, '-e', `if(process.env.ANTHROPIC_API_KEY!==${JSON.stringify(secret)}||process.env.FOUNDATION_ACCESS_TOKEN!==process.env.ANTHROPIC_API_KEY||process.env.FOUNDATION_PROVIDER!=='apikey'||process.env.FOUNDATION_TOKEN_EXPIRES_AT!==''||process.env.FOUNDATION_API_BASE_URL!=='')process.exit(2);console.log('ready')`], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'ready');
  // Disconnect cannot revoke at the service; delivery stops locally.
  const revoke = await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(revoke.status, 409); assert.equal(revoke.json.error.code, 'manual_revocation_required');
  assert.equal((await f.request('/api/accounts/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 200);
  assert.equal((await f.request('/v1/accounts/' + account.id + '/credentials', { method: 'POST', token, anonymous: true, data: {} })).status, 403);
  assert.equal(f.app.store.accounts(USER_A).length, 1);
});

test('The CLI builds a key request from its own declaration and refuses reserved variable names before contacting Foundation', async t => {
  const f = await apikeyFixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-apikey-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key') };
  const reserved = await execute(['connect', '--service', 'Anthropic', '--site', claim.site, '--env', 'LD_PRELOAD'], env);
  assert.equal(reserved.code, 1); assert.match(reserved.err, /reserved/);
  const partial = await execute(['connect', '--service', 'Anthropic'], env);
  assert.equal(partial.code, 1); assert.match(partial.err, /--site/);
  const connected = await execute(['connect', '--service', 'Anthropic', '--site', claim.site, '--env', claim.env, '--purpose', 'Claude APIでの要約'], env);
  assert.equal(connected.code, 0, connected.err);
  const row = JSON.parse(connected.out).request;
  assert.equal(row.provider, 'apikey'); assert.equal(row.mode, 'key');
  assert.deepEqual(row.details, claim);
  assert.match(row.verification_uri, /\/connect\//);
});
