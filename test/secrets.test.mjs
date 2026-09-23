import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, USER_B } from './helpers.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const secret = 'ghp_entry-fixture-' + randomBytes(12).toString('hex');
const run = (args, env, input) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  const out = [], err = [];
  child.stdout.on('data', part => out.push(part)); child.stderr.on('data', part => err.push(part));
  child.stdin.end(input ?? '');
  child.once('error', reject);
  child.once('exit', code => resolve({ code, out: Buffer.concat(out), err: Buffer.concat(err).toString() }));
});
async function keyed(t) {
  const f = await fixture(t), token = key();
  await f.approveKey(token);
  return { f, token };
}
const put = (f, token, path, content, query = {}, type = 'text/plain') =>
  f.request('/v1/secrets/' + path + (Object.keys(query).length ? '?' + new URLSearchParams(query) : ''), { method: 'PUT', token, anonymous: true, raw: content, type });

test('What is kept is bytes at a path, and the name a command receives them under comes from that path', async t => {
  const { f, token } = await keyed(t);
  const kept = await put(f, token, 'github/gh-token', secret, { secret: 'true' });
  assert.equal(kept.status, 200, kept.text);
  assert.deepEqual({ ...kept.json.secret, created_at: 0, updated_at: 0 },
    { path: 'github/gh-token', size: secret.length, session: null, readable: false, version: 1, kept_by: 'dev-us', created_at: 0, updated_at: 0 });
  assert.doesNotMatch(kept.text, new RegExp(secret), 'writing never echoes the bytes back');

  const listed = await f.request('/v1/secrets', { token, anonymous: true });
  assert.deepEqual(listed.json.secrets.map(row => row.path), ['github/gh-token']);
  assert.doesNotMatch(listed.text, new RegExp(secret), 'listing tells what is kept, never the bytes');

  // Written as a secret, so the key that wrote it cannot read it back.
  const refused = await f.request('/v1/secrets/github/gh-token', { token, anonymous: true });
  assert.equal(refused.status, 403);
  assert.equal(refused.json.error.code, 'write_only');

  const delivered = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['github/gh-token'] } });
  assert.deepEqual(delivered.json.delivery, { environment: { GH_TOKEN: secret }, files: [] });
});

test('Bytes with no delivery are kept and read back as they were written', async t => {
  const { f, token } = await keyed(t);
  const state = JSON.stringify({ step: 'レビュー待ち', pull_request: 42 });
  assert.equal((await put(f, token, 'release/2026-09-23', state, {}, 'application/json')).status, 200);
  const read = await f.request('/v1/secrets/release/2026-09-23', { token, anonymous: true });
  assert.equal(read.status, 200);
  assert.equal(read.text, state);
  // The path gives no usable variable name, so handing it over needs one to be said.
  const asked = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['release/2026-09-23'] } });
  assert.equal(asked.status, 400);
  assert.equal(asked.json.error.code, 'no_variable');
  const named = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: [{ path: 'release/2026-09-23', as: 'RELEASE_STATE' }] } });
  assert.deepEqual(named.json.delivery.environment, { RELEASE_STATE: state });
});

test('Bytes that cannot be an environment variable can still be delivered as a file', async t => {
  const { f, token } = await keyed(t);
  const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n';
  const stored = await put(f, token, 'apple/key', pem, { secret: 'true' });
  assert.equal(stored.status, 200, stored.text);
  const refused = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: [{ path: 'apple/key', as: 'APPLE_KEY' }] } });
  assert.equal(refused.status, 400);
  assert.equal(refused.json.error.code, 'invalid_value');
  const delivered = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true,
    data: { paths: [{ path: 'apple/key', as: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey.p8' }] } });
  assert.deepEqual(delivered.json.delivery.environment, {});
  assert.deepEqual(delivered.json.delivery.files, [{ env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey.p8', content: Buffer.from(pem).toString('base64'), encoding: 'base64' }]);
});

test('Paths are checked when writing, names when handing over; nothing else about the bytes is', async t => {
  const { f, token } = await keyed(t);
  const code = async (path, query = {}, type = 'text/plain') => (await put(f, token, path, 'x', query, type)).json.error?.code;
  assert.equal(await code('-leading/segment'), 'invalid_path');
  assert.equal(await code('a/b/c/d/e/f/g/h/i'), 'invalid_path');
  assert.equal((await put(f, token, 'a/b', 'x')).status, 200);
  const handing = async as => (await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: [{ path: 'a/b', as }] } })).json.error?.code;
  assert.equal(await handing('lower'), 'invalid_env');
  assert.equal(await handing('PATH'), 'invalid_env');
  const badFile = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: [{ path: 'a/b', as: 'A_KEY', filename: '../escape' }] } });
  assert.equal(badFile.json.error.code, 'invalid_filename');
  // Anything at all may be kept, as long as Foundation is not asked to make it a variable.
  assert.equal((await put(f, token, 'raw/bytes', '\u0000\u0001 binary �', {}, 'application/octet-stream')).status, 200);
});

test('Writing the same path again replaces what is there', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'github/gh-token', 'first', { secret: 'true' });
  await put(f, token, 'github/gh-token', 'second');
  assert.equal((await f.request('/v1/secrets', { token, anonymous: true })).json.secrets.length, 1);
  const delivered = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['github/gh-token'] } });
  assert.deepEqual(delivered.json.delivery.environment, { GH_TOKEN: 'second' });
  assert.equal((await f.request('/v1/secrets/github/gh-token', { token, anonymous: true })).text, 'second', 'no longer a secret either');
});

test('A write can refuse to overwrite what it has not seen, so two at once cannot lose each other\'s work', async t => {
  const { f, token } = await keyed(t);
  const first = await put(f, token, 'release/expo-v3', '{"step":"started"}', {}, 'application/json');
  assert.equal(first.json.secret.version, 1);

  // Two conversations read the same thing; the first to write wins and the second is told, rather than silently losing it.
  const one = await put(f, token, 'release/expo-v3', '{"step":"reminded"}', { if_version: '1' }, 'application/json');
  assert.equal(one.status, 200, one.text);
  assert.equal(one.json.secret.version, 2);
  const two = await put(f, token, 'release/expo-v3', '{"step":"released"}', { if_version: '1' }, 'application/json');
  assert.equal(two.status, 409);
  assert.equal(two.json.error.code, 'version_conflict');
  assert.equal((await f.request('/v1/secrets/release/expo-v3', { token, anonymous: true })).text, '{"step":"reminded"}');

  // Reading again and retrying works; writing with no version at all still overwrites.
  const retried = await put(f, token, 'release/expo-v3', '{"step":"released"}', { if_version: '2' }, 'application/json');
  assert.equal(retried.status, 200, retried.text);
  assert.equal((await put(f, token, 'release/expo-v3', 'plain')).status, 200);
  // A path that is not there yet is version 0, so a writer can insist on creating it.
  assert.equal((await put(f, token, 'release/new', 'x', { if_version: '1' })).json.error.code, 'version_conflict');
  assert.equal((await put(f, token, 'release/new', 'x', { if_version: '0' })).status, 200);
});

test('Delivering several at once refuses two that want the same variable', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'work/gh-token', 'one');
  await put(f, token, 'personal/gh-token', 'two');
  const clash = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['work/gh-token', 'personal/gh-token'] } });
  assert.equal(clash.status, 409);
  assert.equal(clash.json.error.code, 'name_conflict');
  const apart = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true,
    data: { paths: ['work/gh-token', { path: 'personal/gh-token', as: 'PERSONAL_GH_TOKEN' }] } });
  assert.deepEqual(apart.json.delivery.environment, { GH_TOKEN: 'one', PERSONAL_GH_TOKEN: 'two' }, 'saying a different name is enough');
});

test('Listing narrows by path prefix, and each owner reaches only their own', async t => {
  const { f, token } = await keyed(t);
  for (const path of ['github/token', 'github/user', 'release/expo-v3']) await put(f, token, path, 'x');
  const narrowed = await f.request('/v1/secrets?prefix=github', { token, anonymous: true });
  assert.deepEqual(narrowed.json.secrets.map(row => row.path), ['github/token', 'github/user']);

  await f.login('other@example.test');
  const other = key();
  await f.approveKey(other, 'other-machine');
  assert.deepEqual((await f.request('/v1/secrets', { token: other, anonymous: true })).json.secrets, []);
  assert.equal((await f.request('/v1/secrets/github/token', { token: other, anonymous: true })).status, 404);
  assert.equal(f.app.store.secrets(USER_B).length, 0);

  const dropped = await f.request('/v1/secrets/github/token', { method: 'DELETE', token, anonymous: true, data: {} });
  assert.equal(dropped.status, 200);
  assert.equal((await f.request('/v1/secrets/github/token', { token, anonymous: true })).status, 404);
});

test('What is kept is bounded, so one owner cannot fill the disk', async t => {
  const { f, token } = await keyed(t);
  const big = await put(f, token, 'big/one', 'a'.repeat(1024 * 1024 + 1));
  assert.equal(big.status, 413);
  assert.equal(big.json.error.code, 'too_large');
  assert.equal((await put(f, token, 'long/value', 'a'.repeat(20_000))).status, 200);
  const asVariable = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['long/value'] } });
  assert.equal(asVariable.status, 413);
  assert.equal(asVariable.json.error.code, 'value_too_large');
  const asFile = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: [{ path: 'long/value', as: 'LONG_VALUE', filename: 'value.txt' }] } });
  assert.equal(asFile.status, 200, 'the same bytes are fine when they become a file');
});

test('The owner reads and removes anything kept, including what the key may not read back', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'github/token', secret, { env: 'GH_TOKEN', secret: 'true' });
  const state = await f.request('/api/state');
  assert.deepEqual(state.json.secrets.map(row => row.path), ['github/token']);
  assert.doesNotMatch(state.text, new RegExp(secret));
  const read = await f.request('/api/secrets/github%2Ftoken');
  assert.equal(read.status, 200);
  assert.equal(read.text, secret, 'the owner sees what they are keeping');
  assert.equal((await f.request('/api/secrets/github%2Ftoken', { method: 'DELETE', data: {} })).status, 200);
  assert.deepEqual((await f.request('/v1/secrets', { token, anonymous: true })).json.secrets, []);
});

test('The runtime hands what is kept to a command, as bytes and as a file, and nothing else', async t => {
  const { f, token } = await keyed(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-entries-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };

  await put(f, token, 'github/gh-token', secret, { secret: 'true' });
  const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n';
  await put(f, token, 'apple/key', pem, { secret: 'true' }, 'application/octet-stream');

  const script = `const fs=require('fs');if(process.env.GH_TOKEN!==${JSON.stringify(secret)})process.exit(2);if(fs.readFileSync(process.env.APPLE_KEY_PATH,'utf8')!==${JSON.stringify(pem)})process.exit(3);if(!process.env.APPLE_KEY_PATH.endsWith('AuthKey.p8'))process.exit(4);if(process.env.FOUNDATION_PATHS!=='github/gh-token,apple/key')process.exit(5);console.log('ready')`;
  const used = await run(['exec', 'github/gh-token', 'APPLE_KEY_PATH=apple/key:AuthKey.p8', '--', process.execPath, '-e', script], env);
  assert.equal(used.code, 0, used.err);
  assert.equal(used.out.toString().trim(), 'ready');
  assert.doesNotMatch(used.out.toString() + used.err, new RegExp(secret));

  // The file it wrote exists only while the command runs.
  const where = await run(['exec', 'APPLE_KEY_PATH=apple/key:AuthKey.p8', '--', process.execPath, '-e', 'console.log(process.env.APPLE_KEY_PATH)'], env);
  assert.equal(where.code, 0, where.err);
  const { access } = await import('node:fs/promises');
  await assert.rejects(access(where.out.toString().trim()));

  // Nothing else is a command: everything the agent can do for itself is left to it.
  const refused = await run(['list'], env);
  assert.equal(refused.code, 1);
  assert.match(refused.err, /connect .* exec/);
});

test('Storage needs an approved key, and the guide describes the API an agent calls itself', async t => {
  const f = await fixture(t), token = key();
  assert.equal((await f.request('/v1/secrets', { token, anonymous: true })).status, 401);
  const guide = (await run(['--help'], {})).out.toString();
  assert.match(guide, /PUT \/v1\/secrets\/<path>/);
  assert.match(guide, /POST \/v1\/deliver/);
  assert.match(guide, /Nothing here needs a shell/);
  assert.match(guide, /foundation exec \[<NAME>/, 'and the one thing that does need one');
});

test('An agent that cannot make a secret of its own is issued one, once', async t => {
  const f = await fixture(t);
  const asked = await f.request('/v1/access-requests', { method: 'POST', anonymous: true, data: { name: 'an agent with no randomness' } });
  assert.equal(asked.status, 201, asked.text);
  assert.match(asked.json.key, /^fdn_[A-Za-z0-9_-]{43}$/);
  // It is the key: approving the request approves it, and it works from then on.
  await f.request('/api/access-requests/' + asked.json.request.id + '/approve', { method: 'POST', data: { confirmationCode: asked.json.request.confirmation_code } });
  assert.equal((await f.request('/v1/me', { token: asked.json.key, anonymous: true })).status, 200);
  const again = await f.request('/v1/access-requests/current', { token: asked.json.key, anonymous: true });
  assert.equal(again.json.request.key, undefined, 'never handed out a second time');
});
