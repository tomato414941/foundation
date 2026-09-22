import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { APPLE_KEYS } from '../src/providers/apple.mjs';
import { appleFixture, APPLE_P8, APPLE_FIELDS } from './apple-helper.mjs';
import { json, USER_A } from './helpers.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const credential = (f, id, token) => f.request('/v1/accounts/' + id + '/credentials', { method: 'POST', anonymous: true, token, data: {} });
const execute = (args, env) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env } });
  let out = '', err = '';
  child.stdout.on('data', part => out += part); child.stderr.on('data', part => err += part);
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});
async function grant(f, ids) {
  const runtime = await f.agent();
  const dir = await mkdtemp(join(tmpdir(), 'foundation-apple-test-'));
  const keyPath = join(dir, 'runtime-key'); await writeFile(keyPath, runtime.token, { mode: 0o600 });
  return { dir, env: { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath, XDG_RUNTIME_DIR: dir }, runtime };
}

test('Apple import signs a JWT with the .p8, confirms it with one read, and shows team and key without exposing the key', async t => {
  const f = await appleFixture(t), account = await f.appleAccount();
  const state = await f.request('/api/state'), provider = state.json.providers.find(item => item.id === 'apple');
  assert.equal(provider.connection_method, 'token'); assert.equal(provider.token_setup.multiline, true);
  assert.deepEqual(provider.token_setup.fields.map(field => field.id), ['key_id', 'issuer_id', 'team_id', 'team_type']);
  assert.equal(provider.token_setup.links[0].href, APPLE_KEYS);
  assert.equal(account.label, 'Team TEAM123456 / Key ABC1234567'); assert.equal(provider.name, 'Apple');
  assert.equal(account.credential_type, 'private_key'); assert.equal(account.expires_at, null);
  assert.deepEqual(account.apple, APPLE_FIELDS);
  assert.ok(!state.text.includes('PRIVATE KEY'));
  assert.equal(f.apple.calls.length, 1);
  assert.match(f.apple.calls[0].url, /\/apps\?limit=1/);
});

test('Apple rejects wrong identifiers, non-P-256 keys, malformed keys and keys Apple refuses, storing nothing', async t => {
  const f = await appleFixture(t);
  const rejects = (fn, message) => assert.throws(fn, error => error.status === 400 && message.test(error.message));
  for (const [fields, message] of [[{ ...APPLE_FIELDS, key_id: 'short' }, /Key ID/], [{ ...APPLE_FIELDS, issuer_id: 'nope' }, /Issuer ID/], [{ ...APPLE_FIELDS, team_id: 'x' }, /Team ID/], [{ ...APPLE_FIELDS, team_type: 'PERSONAL' }, /チーム種別/], [null, /入力/]]) rejects(() => f.apple.fields(fields), message);
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  for (const pem of [rsa, 'not a key', APPLE_P8.replace('PRIVATE KEY-----\n', 'PRIVATE KEY-----\nAAAA'), '']) rejects(() => f.apple.privateKey(pem), /p8|P-256/);
  assert.equal(f.apple.calls.length, 0, 'format checks never contact Apple');
  const wrongFields = await f.importApple({ fields: { ...APPLE_FIELDS, key_id: 'short' } });
  assert.equal(wrongFields.status, 400); assert.equal(wrongFields.json.error.code, 'invalid_account');
  assert.equal((await f.importApple({ mode: 'session' })).status, 400);
  // A key Apple no longer accepts: valid PEM, wrong key id for the signature.
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ type: 'pkcs8', format: 'pem' });
  const refused = await f.importApple({ token: other });
  assert.equal(refused.status, 409); assert.equal(refused.json.error.code, 'reconnect_required');
  f.apple.handler = () => json({ errors: [] }, 403);
  assert.equal((await f.importApple()).json.error.code, 'reconnect_required');
  f.apple.handler = () => json({}, 429);
  assert.equal((await f.importApple()).status, 503);
  f.apple.handler = () => json({ nope: true });
  assert.equal((await f.importApple()).json.error.code, 'provider_response');
  f.apple.handler = null;
  assert.equal(f.app.store.accounts(USER_A).length, 0);
  assert.equal((await f.importApple()).status, 200);
  assert.equal((await f.importApple()).status, 409, 'same key twice');
});

test('The runtime receives the .p8 as a file that exists only while the command runs, alongside the identifiers and another connection', async t => {
  const f = await appleFixture(t), apple = await f.appleAccount(), gmail = await f.account();
  const { dir, env } = await grant(f, [apple.id, gmail.id]); t.after(() => rm(dir, { recursive: true, force: true }));
  const issued = await credential(f, apple.id, (await f.request('/api/state')).json.agents && null);
  assert.equal(issued.status, 401, 'anonymous issuance still requires a key');
  const probe = ['-e', `
    const fs = require('node:fs'); const p = process.env.EXPO_ASC_API_KEY_PATH;
    const stat = fs.statSync(p); const pem = fs.readFileSync(p, 'utf8');
    if ((stat.mode & 0o777) !== 0o600 || !pem.startsWith('-----BEGIN PRIVATE KEY-----')) process.exit(2);
    if (process.env.EXPO_ASC_KEY_ID !== 'ABC1234567' || process.env.EXPO_APPLE_TEAM_TYPE !== 'INDIVIDUAL' || !process.env.GOOGLE_OAUTH_ACCESS_TOKEN) process.exit(3);
    if (process.env.FOUNDATION_ACCESS_TOKEN !== '' || process.env.FOUNDATION_PROVIDER !== 'apple' || process.env.FOUNDATION_ACCOUNT_IDS.split(',').length !== 2) process.exit(4);
    console.log(p);`];
  const run = await execute(['exec', apple.id, gmail.id, '--', process.execPath, ...probe], env);
  assert.equal(run.code, 0, run.err + run.out);
  const path = run.out.trim();
  assert.ok(path.startsWith(dir), 'secret file lives under XDG_RUNTIME_DIR');
  assert.match(path, /AuthKey_ABC1234567\.p8$/);
  assert.deepEqual((await readdir(dir)).filter(name => name.startsWith('foundation-')), [], 'secret directory removed after exit');
  assert.ok(!run.out.includes('PRIVATE KEY') && !run.err.includes('PRIVATE KEY'));
  // Two connections that would set the same variable are refused before anything runs.
  const second = await f.account('second');
  const both = await grant(f, [gmail.id, second.id]); t.after(() => rm(both.dir, { recursive: true, force: true }));
  const clash = await execute(['exec', gmail.id, second.id, '--', process.execPath, '-e', 'console.log("must-not-run")'], both.env);
  assert.equal(clash.code, 1); assert.match(clash.err, /GOOGLE_OAUTH_ACCESS_TOKEN/); assert.doesNotMatch(clash.out, /must-not-run/);
  const dup = await execute(['exec', gmail.id, gmail.id, '--', process.execPath, '-e', '1'], both.env);
  assert.equal(dup.code, 1); assert.match(dup.err, /Invalid command/);
  // Revoking one of the grants stops the combined command as a whole.
  await f.request('/api/agents/' + both.runtime.id + '/grants', { method: 'PUT', data: { accountIds: [gmail.id] } });
  const partial = await execute(['exec', gmail.id, second.id, '--', process.execPath, '-e', 'console.log("must-not-run")'], both.env);
  assert.equal(partial.code, 1); assert.doesNotMatch(partial.out, /must-not-run/);
});

test('A key Apple stops accepting marks the connection for reconnection on next use', async t => {
  const f = await appleFixture(t), apple = await f.appleAccount();
  const runtime = await f.agent();
  assert.equal((await credential(f, apple.id, runtime.token)).status, 200);
  f.apple.handler = () => json({ errors: [] }, 401);
  const revoked = await credential(f, apple.id, runtime.token);
  assert.equal(revoked.status, 409); assert.equal(revoked.json.error.code, 'reconnect_required');
  assert.equal((await f.request('/api/state')).json.accounts[0].status, 'reconnect_required');
  assert.equal((await f.request('/api/accounts/' + apple.id, { method: 'DELETE', data: { revoke: true } })).json.error.code, 'manual_revocation_required');
});
