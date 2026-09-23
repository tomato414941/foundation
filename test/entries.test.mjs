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
  f.request('/v1/entries/' + path + (Object.keys(query).length ? '?' + new URLSearchParams(query) : ''), { method: 'PUT', token, anonymous: true, raw: content, type });

test('What is kept is bytes at a path, and how they reach a command is settled when they are written', async t => {
  const { f, token } = await keyed(t);
  const kept = await put(f, token, 'github/token', secret, { env: 'GH_TOKEN', secret: 'true' });
  assert.equal(kept.status, 200, kept.text);
  assert.deepEqual({ ...kept.json.entry, created_at: 0, updated_at: 0 },
    { path: 'github/token', media_type: 'text/plain', size: secret.length, env: 'GH_TOKEN', filename: null, session: null, readable: false, version: 1, kept_by: 'dev-us', created_at: 0, updated_at: 0 });
  assert.doesNotMatch(kept.text, new RegExp(secret), 'writing never echoes the bytes back');

  const listed = await f.request('/v1/entries', { token, anonymous: true });
  assert.deepEqual(listed.json.entries.map(row => row.path), ['github/token']);
  assert.doesNotMatch(listed.text, new RegExp(secret), 'listing tells what is kept, never the bytes');

  // Written as a secret, so the key that wrote it cannot read it back.
  const refused = await f.request('/v1/entries/github/token', { token, anonymous: true });
  assert.equal(refused.status, 403);
  assert.equal(refused.json.error.code, 'write_only');

  const delivered = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['github/token'] } });
  assert.deepEqual(delivered.json.delivery, { environment: { GH_TOKEN: secret }, files: [] });
});

test('Bytes with no delivery are kept and read back as they were written', async t => {
  const { f, token } = await keyed(t);
  const state = JSON.stringify({ step: 'レビュー待ち', pull_request: 42 });
  assert.equal((await put(f, token, 'release/expo-v3', state, {}, 'application/json')).status, 200);
  const read = await f.request('/v1/entries/release/expo-v3', { token, anonymous: true });
  assert.equal(read.status, 200);
  assert.equal(read.headers.get('content-type'), 'application/json');
  assert.equal(read.text, state);
  // Nothing was told about delivering it, so it cannot be handed to a command.
  const asked = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['release/expo-v3'] } });
  assert.equal(asked.status, 409);
  assert.equal(asked.json.error.code, 'not_delivered');
});

test('Bytes that cannot be an environment variable can still be delivered as a file', async t => {
  const { f, token } = await keyed(t);
  const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n';
  const refused = await put(f, token, 'apple/key', pem, { env: 'APPLE_KEY' });
  assert.equal(refused.status, 400);
  assert.equal(refused.json.error.code, 'invalid_value');
  const stored = await put(f, token, 'apple/key', pem, { env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey.p8', secret: 'true' });
  assert.equal(stored.status, 200, stored.text);
  const delivered = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['apple/key'] } });
  assert.deepEqual(delivered.json.delivery.environment, {});
  assert.deepEqual(delivered.json.delivery.files, [{ env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey.p8', content: Buffer.from(pem).toString('base64'), encoding: 'base64' }]);
});

test('Paths, media types and delivery names are checked; nothing else about the bytes is', async t => {
  const { f, token } = await keyed(t);
  const code = async (path, query = {}, type = 'text/plain') => (await put(f, token, path, 'x', query, type)).json.error?.code;
  assert.equal(await code('-leading/segment'), 'invalid_path');
  assert.equal(await code('a/b/c/d/e/f/g/h/i'), 'invalid_path');
  assert.equal(await code('a/b', {}, 'not a media type'), 'invalid_media_type');
  assert.equal(await code('a/b', { env: 'lower' }), 'invalid_env');
  assert.equal(await code('a/b', { env: 'PATH' }), 'invalid_env');
  assert.equal(await code('a/b', { env: 'GOOGLE_OAUTH_ACCESS_TOKEN' }), 'invalid_env', 'a name an adapter already delivers');
  assert.equal(await code('a/b', { filename: 'AuthKey.p8' }), 'invalid_delivery', 'a file with nothing to hold its path');
  assert.equal(await code('a/b', { env: 'A_KEY', filename: '../escape' }), 'invalid_filename');
  // Anything at all may be kept, as long as Foundation is not asked to make it a variable.
  assert.equal((await put(f, token, 'raw/bytes', '\u0000\u0001 binary �', {}, 'application/octet-stream')).status, 200);
});

test('Writing the same path again replaces both the bytes and how they are delivered', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'github/token', 'first', { env: 'GH_TOKEN' });
  await put(f, token, 'github/token', 'second', { env: 'GITHUB_TOKEN' });
  assert.equal((await f.request('/v1/entries', { token, anonymous: true })).json.entries.length, 1);
  const delivered = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['github/token'] } });
  assert.deepEqual(delivered.json.delivery.environment, { GITHUB_TOKEN: 'second' });
  assert.equal((await f.request('/v1/entries/github/token', { token, anonymous: true })).text, 'second', 'no longer a secret either');
});

test('A write can refuse to overwrite what it has not seen, so two at once cannot lose each other\'s work', async t => {
  const { f, token } = await keyed(t);
  const first = await put(f, token, 'release/expo-v3', '{"step":"started"}', {}, 'application/json');
  assert.equal(first.json.entry.version, 1);

  // Two conversations read the same thing; the first to write wins and the second is told, rather than silently losing it.
  const one = await put(f, token, 'release/expo-v3', '{"step":"reminded"}', { if_version: '1' }, 'application/json');
  assert.equal(one.status, 200, one.text);
  assert.equal(one.json.entry.version, 2);
  const two = await put(f, token, 'release/expo-v3', '{"step":"released"}', { if_version: '1' }, 'application/json');
  assert.equal(two.status, 409);
  assert.equal(two.json.error.code, 'version_conflict');
  assert.equal((await f.request('/v1/entries/release/expo-v3', { token, anonymous: true })).text, '{"step":"reminded"}');

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
  await put(f, token, 'work/token', 'one', { env: 'GH_TOKEN' });
  await put(f, token, 'personal/token', 'two', { env: 'GH_TOKEN' });
  const clash = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['work/token', 'personal/token'] } });
  assert.equal(clash.status, 409);
  assert.equal(clash.json.error.code, 'name_conflict');
  const one = await f.request('/v1/deliver', { method: 'POST', token, anonymous: true, data: { paths: ['work/token'] } });
  assert.deepEqual(one.json.delivery.environment, { GH_TOKEN: 'one' }, 'the same variable name in two places is fine until both are asked for');
});

test('Listing narrows by path prefix, and each owner reaches only their own', async t => {
  const { f, token } = await keyed(t);
  for (const path of ['github/token', 'github/user', 'release/expo-v3']) await put(f, token, path, 'x');
  const narrowed = await f.request('/v1/entries?prefix=github', { token, anonymous: true });
  assert.deepEqual(narrowed.json.entries.map(row => row.path), ['github/token', 'github/user']);

  await f.login('other@example.test');
  const other = key();
  await f.approveKey(other, 'other-machine');
  assert.deepEqual((await f.request('/v1/entries', { token: other, anonymous: true })).json.entries, []);
  assert.equal((await f.request('/v1/entries/github/token', { token: other, anonymous: true })).status, 404);
  assert.equal(f.app.store.entries(USER_B).length, 0);

  const dropped = await f.request('/v1/entries/github/token', { method: 'DELETE', token, anonymous: true, data: {} });
  assert.equal(dropped.status, 200);
  assert.equal((await f.request('/v1/entries/github/token', { token, anonymous: true })).status, 404);
});

test('What is kept is bounded, so one owner cannot fill the disk', async t => {
  const { f, token } = await keyed(t);
  const big = await put(f, token, 'big/one', 'a'.repeat(1024 * 1024 + 1));
  assert.equal(big.status, 413);
  assert.equal(big.json.error.code, 'too_large');
  const longValue = await put(f, token, 'long/value', 'a'.repeat(20_000), { env: 'A_KEY' });
  assert.equal(longValue.status, 413);
  assert.equal(longValue.json.error.code, 'value_too_large');
  assert.equal((await put(f, token, 'long/value', 'a'.repeat(20_000))).status, 200, 'the same bytes are fine when nothing must become a variable');
});

test('The owner reads and removes anything kept, including what the key may not read back', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'github/token', secret, { env: 'GH_TOKEN', secret: 'true' });
  const state = await f.request('/api/state');
  assert.deepEqual(state.json.entries.map(row => row.path), ['github/token']);
  assert.doesNotMatch(state.text, new RegExp(secret));
  const read = await f.request('/api/entries/github%2Ftoken');
  assert.equal(read.status, 200);
  assert.equal(read.text, secret, 'the owner sees what they are keeping');
  assert.equal((await f.request('/api/entries/github%2Ftoken', { method: 'DELETE', data: {} })).status, 200);
  assert.deepEqual((await f.request('/v1/entries', { token, anonymous: true })).json.entries, []);
});

test('The CLI keeps bytes, hands them to a command, reads them back and drops them', async t => {
  const { f, token } = await keyed(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-entries-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };

  const kept = await run(['put', 'github/token', '--env', 'GH_TOKEN', '--secret', '--type', 'text/plain'], env, secret);
  assert.equal(kept.code, 0, kept.err);
  assert.equal(JSON.parse(kept.out.toString()).entry.env, 'GH_TOKEN');
  assert.doesNotMatch(kept.out.toString(), new RegExp(secret), 'the bytes are never printed');

  const pem = Buffer.from('-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n');
  await writeFile(join(dir, 'key.p8'), pem);
  const file = await run(['put', 'apple/key', '--file', 'AuthKey.p8', '--env', 'APPLE_KEY_PATH', '--secret', '--from', join(dir, 'key.p8')], env);
  assert.equal(file.code, 0, file.err);

  const script = `const fs=require('fs');if(process.env.GH_TOKEN!==${JSON.stringify(secret)})process.exit(2);if(fs.readFileSync(process.env.APPLE_KEY_PATH,'utf8')!==${JSON.stringify(pem.toString())})process.exit(3);if(!process.env.APPLE_KEY_PATH.endsWith('AuthKey.p8'))process.exit(4);console.log('ready')`;
  const used = await run(['exec', 'github/token', 'apple/key', '--', process.execPath, '-e', script], env);
  assert.equal(used.code, 0, used.err);
  assert.equal(used.out.toString().trim(), 'ready');

  const listed = await run(['list', 'github'], env);
  assert.deepEqual(JSON.parse(listed.out.toString()).entries.map(row => row.path), ['github/token']);

  await run(['put', 'release/expo-v3', '--type', 'application/json'], env, '{"step":"awaiting"}');
  const got = await run(['get', 'release/expo-v3'], env);
  assert.equal(got.out.toString(), '{"step":"awaiting"}');
  const saved = await run(['get', 'release/expo-v3', '--out', join(dir, 'state.json')], env);
  assert.equal(saved.code, 0, saved.err);
  assert.equal(await readFile(join(dir, 'state.json'), 'utf8'), '{"step":"awaiting"}');

  const readSecret = await run(['get', 'github/token'], env);
  assert.equal(readSecret.code, 1);
  assert.match(readSecret.err, /write_only/);

  assert.equal((await run(['drop', 'release/expo-v3'], env)).code, 0);
  assert.deepEqual(JSON.parse((await run(['list'], env)).out.toString()).entries.map(row => row.path), ['apple/key', 'github/token']);
});

test('Storage needs an approved key, and the guide tells an agent it is there', async t => {
  const f = await fixture(t), token = key();
  assert.equal((await f.request('/v1/entries', { token, anonymous: true })).status, 401);
  const guide = await run(['--help'], {});
  assert.match(guide.out.toString(), /foundation put <path> \[--env NAME\]/);
  assert.match(guide.out.toString(), /foundation exec <path>/);
});
