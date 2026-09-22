import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, FakeGmail, USER_A } from './helpers.mjs';
import { Adapters, generic, gmailReadonly, gmailMetadata } from '../src/adapters.mjs';
import { GenericClient } from '../src/generic.mjs';
import { validEnvName } from '../src/env-name.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const claim = { service: 'Anthropic', site: 'https://console.anthropic.com/settings/keys', fields: [{ id: 'ANTHROPIC_API_KEY', label: 'APIキー', kind: 'line' }] };
const field = id => ({ ...claim, fields: [{ id, label: id, kind: 'line' }] });
const secret = 'sk-ant-fixture-' + randomBytes(16).toString('hex');
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});
async function apikeyFixture(t) {
  const gmail = new FakeGmail();
  return fixture(t, { gmail, adapters: [generic(new GenericClient()), gmailReadonly(gmail), gmailMetadata(gmail)] });
}
const create = (f, token, details = claim, extra = {}) => f.request('/v1/access-requests', { method: 'POST', anonymous: true, token, data: { adapter: 'generic', purpose: 'Claude APIでの要約', details, ...extra } });

test('The generic client rejects credentials in a site, a local site and a lowercase name', () => {
  const client = new GenericClient(), code = details => { try { client.details(details); } catch (error) { return error.code; } };
  assert.equal(code({ ...claim, site: 'https://user:pw@example.com/' }), 'invalid_site');
  assert.equal(code({ ...claim, site: 'https://localhost/keys' }), 'invalid_site');
  assert.equal(code({ ...claim, service: '<b>x</b>' }), 'invalid_service');
  assert.equal(code(field('anthropic_api_key')), 'invalid_env');
});

test('Declared names cannot hijack the child process or take a variable another adapter delivers', () => {
  for (const name of ['ANTHROPIC_API_KEY', 'STRIPE_SECRET_KEY', 'X', 'GOOGLE_OAUTH_ACCESS_TOKEN']) assert.ok(validEnvName(name), name);
  for (const name of ['PATH', 'HOME', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'NODE_OPTIONS', 'FOUNDATION_CREDENTIAL_IDS', 'lower', '1ABC', 'A-B', '', undefined, 'A'.repeat(65)]) assert.equal(validEnvName(name), false, String(name));
  const gmail = new FakeGmail(), adapters = new Adapters([gmailReadonly(gmail), gmailMetadata(gmail), generic(new GenericClient())]);
  const code = name => { try { adapters.details('generic', field(name)); } catch (error) { return error.code; } };
  for (const name of ['GOOGLE_OAUTH_ACCESS_TOKEN', 'GMAIL_ACCOUNT_EMAIL']) assert.equal(code(name), 'invalid_env', name);
  assert.equal(code('ANTHROPIC_API_KEY'), undefined);
});

test('A runtime declares the service, the key page and the fields; the declaration is validated and shown, never trusted as a scope', async t => {
  const f = await apikeyFixture(t), token = key();
  await f.approveKey(token);
  for (const [details, code] of [[null, 'invalid_details'], [{ ...claim, service: '' }, 'invalid_service'], [{ ...claim, site: 'http://example.com/keys' }, 'invalid_site'],
    [field('PATH'), 'invalid_env'], [field('GOOGLE_OAUTH_ACCESS_TOKEN'), 'invalid_env'], [{ ...claim, fields: [] }, 'invalid_fields'], [{ ...claim, fields: [...claim.fields, ...claim.fields] }, 'invalid_fields'], [{ ...claim, fields: [{ id: 'A_KEY', kind: 'file' }] }, 'invalid_fields']]) {
    const response = await create(f, token, details);
    assert.equal(response.status, 400, JSON.stringify(details)); assert.equal(response.json.error.code, code, JSON.stringify(details));
  }
  const created = await create(f, token);
  assert.equal(created.status, 201, created.text);
  const row = created.json.request;
  assert.deepEqual(row.details, claim);
  assert.equal(row.adapter.id, 'generic'); assert.equal(row.adapter.service.name, 'Anthropic'); assert.equal(row.adapter.label, 'Anthropicのキーを登録');
  assert.deepEqual(row.adapter.form.schema.map(item => [item.id, item.label, item.kind, item.secret]), [['ANTHROPIC_API_KEY', 'APIキー', 'line', true]]);
  assert.deepEqual(row.adapter.form.links, [{ label: claim.site, href: claim.site, declared: true }]);
  // Same declaration reuses the pending request; a different one conflicts.
  assert.equal((await create(f, token)).json.request.id, row.id);
  assert.equal((await create(f, token, field('OTHER_KEY'))).status, 409);
  const page = await f.request('/api/access-requests/' + row.id);
  assert.deepEqual(page.json.request.details, claim);
  assert.equal(page.json.request.confirmation_code, undefined);
});

test('The owner pastes each declared value; each reaches the command under its own name, unverified', async t => {
  const f = await apikeyFixture(t), token = key();
  await f.approveKey(token);
  const row = (await create(f, token)).json.request;
  const register = (values, extra = {}) => f.request('/api/adapters/generic/connect', { method: 'POST', data: { name: 'Anthropic', values, accessRequestId: row.id, ...extra } });
  // Values are taken for the request's declared fields only; what the browser sends as a declaration is ignored.
  const bad = await register({ ANTHROPIC_API_KEY: 'with space' });
  assert.equal(bad.status, 400); assert.equal(bad.json.error.code, 'invalid_values');
  const imported = await register({ ANTHROPIC_API_KEY: secret, IGNORED_NAME: 'x' }, { details: field('IGNORED_NAME') });
  assert.equal(imported.status, 200, imported.text);
  const state = (await f.request('/api/state')).json, account = state.credentials.find(item => item.id === imported.json.credential_id);
  assert.equal(account.verified, false);
  assert.deepEqual(account.details, { service: 'Anthropic', site: claim.site, fields: ['ANTHROPIC_API_KEY'] });
  assert.equal(account.service, 'Anthropic'); assert.deepEqual(account.variables, ['ANTHROPIC_API_KEY']);
  assert.equal(account.management_url, claim.site);
  assert.doesNotMatch(JSON.stringify(state), new RegExp(secret));
  assert.equal(account.access.name, 'キーの権限で利用');
  const done = (await f.request('/api/access-requests/' + row.id)).json.request;
  assert.equal(done.status, 'approved', 'registering completes the request');
  assert.equal(done.credential.label, 'Anthropic キー …' + account.subject.split(':')[1].slice(0, 8));
  // Two values from one registration: both reach the command, each under its declared name.
  const twilio = { service: 'Twilio', site: 'https://console.twilio.com/', fields: [{ id: 'TWILIO_ACCOUNT_SID', label: 'Account SID', kind: 'line' }, { id: 'TWILIO_AUTH_TOKEN', label: 'Auth Token', kind: 'line' }] };
  const second = (await create(f, token, twilio)).json.request;
  const pair = await f.request('/api/adapters/generic/connect', { method: 'POST', data: { name: 'Twilio', values: { TWILIO_ACCOUNT_SID: 'AC123', TWILIO_AUTH_TOKEN: 'twilio-secret' }, accessRequestId: second.id } });
  assert.equal(pair.status, 200, pair.text);
  assert.equal((await f.request('/api/access-requests/' + second.id)).json.request.status, 'approved', 'an approved key completes by registering');
  const listed = await f.request('/v1/credentials', { token, anonymous: true });
  assert.deepEqual(listed.json.credentials.map(item => item.variables), [['ANTHROPIC_API_KEY'], ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN']]);
  assert.doesNotMatch(listed.text, new RegExp(secret + '|twilio-secret'));
  const issued = await f.request('/v1/credentials/' + account.id + '/deliver', { method: 'POST', token, anonymous: true, data: {} });
  assert.deepEqual(issued.json.delivery.environment, { ANTHROPIC_API_KEY: secret }); assert.equal(issued.json.expires_at, null);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-apikey-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  const { writeFile } = await import('node:fs/promises'); await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const run = await execute(['exec', account.id, pair.json.credential_id, '--', process.execPath, '-e', `if(process.env.ANTHROPIC_API_KEY!==${JSON.stringify(secret)}||process.env.TWILIO_ACCOUNT_SID!=='AC123'||process.env.TWILIO_AUTH_TOKEN!=='twilio-secret')process.exit(2);console.log('ready')`], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'ready');
  // Removing it cannot revoke at the service; delivery stops locally.
  const revoke = await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: true } });
  assert.equal(revoke.status, 409); assert.equal(revoke.json.error.code, 'manual_revocation_required');
  assert.equal((await f.request('/api/credentials/' + account.id, { method: 'DELETE', data: { revoke: false } })).status, 200);
  assert.equal((await f.request('/v1/credentials/' + account.id + '/deliver', { method: 'POST', token, anonymous: true, data: {} })).status, 403);
});

test('The CLI builds a generic request from --field declarations and refuses reserved names before contacting Foundation', async t => {
  const f = await apikeyFixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-apikey-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: join(dir, 'runtime-key') };
  const asked = JSON.parse((await execute(['connect'], env)).out).request;
  assert.equal((await f.request('/api/access-requests/' + asked.id + '/approve', { method: 'POST', data: { confirmationCode: asked.confirmation_code } })).status, 200);
  const reserved = await execute(['connect', '--service', 'Anthropic', '--site', claim.site, '--field', 'LD_PRELOAD'], env);
  assert.equal(reserved.code, 1); assert.match(reserved.err, /reserved/);
  const partial = await execute(['connect', '--service', 'Anthropic'], env);
  assert.equal(partial.code, 1); assert.match(partial.err, /--site/);
  const connected = await execute(['connect', '--service', 'Anthropic', '--site', claim.site, '--field', 'ANTHROPIC_API_KEY=APIキー', '--multiline-field', 'ANTHROPIC_CONFIG', '--purpose', 'Claude APIでの要約'], env);
  assert.equal(connected.code, 0, connected.err);
  const row = JSON.parse(connected.out).request;
  assert.equal(row.adapter.id, 'generic');
  assert.deepEqual(row.details.fields, [{ id: 'ANTHROPIC_API_KEY', label: 'APIキー', kind: 'line' }, { id: 'ANTHROPIC_CONFIG', label: 'ANTHROPIC_CONFIG', kind: 'multiline' }]);
  assert.match(row.verification_uri, /\/connect\//);
});
