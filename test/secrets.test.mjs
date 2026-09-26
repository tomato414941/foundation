import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, USER_A, USER_B } from './helpers.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const secret = 'ghp_entry-fixture-' + randomBytes(12).toString('hex');
const run = (args, env, input) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['cli/runtime.mjs', ...args], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
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
const put = (f, token, name, content, query = {}, type = 'text/plain') =>
  f.request('/v1/holdings?' + new URLSearchParams({ ...query, kind: 'secret', name }), { method: 'PUT', token, anonymous: true, raw: content, type });

test('Stored names and caller-selected environment variables are independent', async t => {
  const { f, token } = await keyed(t);
  const kept = await put(f, token, 'github/gh-token', secret);
  assert.equal(kept.status, 200, kept.text);
  assert.match(kept.json.holding.id, /^[0-9a-f-]{36}$/, 'a held thing has an id of its own');
  assert.deepEqual({ ...kept.json.holding, id: undefined, created_at: 0, updated_at: 0 },
    { id: undefined, kind: 'secret', name: 'github/gh-token', size: secret.length, type: null, holder_id: USER_A, created_at: 0, updated_at: 0 });
  assert.doesNotMatch(kept.text, new RegExp(secret), 'writing never echoes the bytes back');

  const listed = await f.request('/v1/holdings?kind=secret', { token, anonymous: true });
  assert.deepEqual(listed.json.holdings.map(row => row.name), ['github/gh-token']);
  assert.doesNotMatch(listed.text, new RegExp(secret), 'listing tells what is kept, never the bytes');

  // What the key kept it may read back, along the line drawn for it; the holder can take that line away.
  assert.equal((await f.read('secret', 'github/gh-token', { token, anonymous: true })).status, 200);
  const keyId = (await f.request('/v1/principals/me', { token, anonymous: true })).json.principal.id;
  assert.equal((await f.request('/v1/relations', { method: 'DELETE', data: { subject: keyId, relation: 'editor', object_type: 'holding', object_id: kept.json.holding.id } })).status, 200);
  const refused = await f.read('secret', 'github/gh-token', { token, anonymous: true });
  assert.equal(refused.status, 403);
  assert.equal(refused.json.error.code, 'forbidden');

  const delivered = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'github/gh-token', as: 'GH_TOKEN' }] } });
  assert.deepEqual(delivered.json.delivery, { environment: { GH_TOKEN: secret }, files: [] });
});

test('Bytes with no delivery are kept and read back as they were written', async t => {
  const { f, token } = await keyed(t);
  const state = JSON.stringify({ step: 'レビュー待ち', pull_request: 42 });
  assert.equal((await put(f, token, 'release/2026-09-23', state, {}, 'application/json')).status, 200);
  const read = await f.read('secret', 'release/2026-09-23', { token, anonymous: true });
  assert.equal(read.status, 200);
  assert.equal(read.text, state);
  // Delivery needs an explicit destination variable regardless of the saved name.
  const asked = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: ['release/2026-09-23'] } });
  assert.equal(asked.status, 400);
  assert.equal(asked.json.error.code, 'no_variable');
  const named = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'release/2026-09-23', as: 'RELEASE_STATE' }] } });
  assert.deepEqual(named.json.delivery.environment, { RELEASE_STATE: state });
});

test('Bytes that cannot be an environment variable can still be delivered as a file', async t => {
  const { f, token } = await keyed(t);
  const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n';
  const stored = await put(f, token, 'apple/key', pem, { secret: 'true' });
  assert.equal(stored.status, 200, stored.text);
  const refused = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'apple/key', as: 'APPLE_KEY' }] } });
  assert.equal(refused.status, 400);
  assert.equal(refused.json.error.code, 'invalid_value');
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true,
    data: { names: [{ name: 'apple/key', as: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey.p8' }] } });
  assert.deepEqual(delivered.json.delivery.environment, {});
  assert.deepEqual(delivered.json.delivery.files, [{ env: 'EXPO_ASC_API_KEY_PATH', filename: 'AuthKey.p8', content: Buffer.from(pem).toString('base64'), encoding: 'base64' }]);
});

test('Stored names accept literal text, while delivery destinations are validated', async t => {
  const { f, token } = await keyed(t);
  const code = async (path, query = {}, type = 'text/plain') => (await put(f, token, path, 'x', query, type)).json.error?.code;
  assert.equal(await code(''), 'invalid_name');
  assert.equal(await code('a\nb'), 'invalid_name');
  assert.equal(await code('a'.repeat(201)), 'invalid_name');
  assert.equal((await put(f, token, '-leading/segment', 'x')).status, 200);
  assert.equal((await put(f, token, 'a/b/c/d/e/f/g/h/i', 'x')).status, 200);
  assert.equal((await put(f, token, 'a/b', 'x')).status, 200);
  const handing = async as => (await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'a/b', as }] } })).json.error?.code;
  assert.equal(await handing('lower'), 'invalid_env');
  assert.equal(await handing('PATH'), 'invalid_env');
  const badFile = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'a/b', as: 'A_KEY', filename: '../escape' }] } });
  assert.equal(badFile.json.error.code, 'invalid_filename');
  // Anything at all may be kept, as long as Foundation is not asked to make it a variable.
  assert.equal((await put(f, token, 'raw/bytes', '\u0000\u0001 binary �', {}, 'application/octet-stream')).status, 200);
});

test('Writing the same name again replaces what is there', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'github/gh-token', 'first', { secret: 'true' });
  await put(f, token, 'github/gh-token', 'second');
  assert.equal((await f.request('/v1/holdings?kind=secret', { token, anonymous: true })).json.holdings.length, 1);
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'github/gh-token', as: 'GH_TOKEN' }] } });
  assert.deepEqual(delivered.json.delivery.environment, { GH_TOKEN: 'second' });
  assert.equal((await f.read('secret', 'github/gh-token', { token, anonymous: true })).text, 'second', 'no longer a secret either');
});

test('Delivering several at once refuses two that want the same variable', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'work/gh-token', 'one');
  await put(f, token, 'personal/gh-token', 'two');
  const clash = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'work/gh-token', as: 'GH_TOKEN' }, { name: 'personal/gh-token', as: 'GH_TOKEN' }] } });
  assert.equal(clash.status, 409);
  assert.equal(clash.json.error.code, 'name_conflict');
  const apart = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true,
    data: { names: [{ name: 'work/gh-token', as: 'GH_TOKEN' }, { name: 'personal/gh-token', as: 'PERSONAL_GH_TOKEN' }] } });
  assert.deepEqual(apart.json.delivery.environment, { GH_TOKEN: 'one', PERSONAL_GH_TOKEN: 'two' }, 'saying a different name is enough');
});

test('Listing narrows by a literal name prefix, and each owner reaches only their own', async t => {
  const { f, token } = await keyed(t);
  for (const path of ['github/token', 'github/user', 'release/expo-v3']) await put(f, token, path, 'x');
  const narrowed = await f.request('/v1/holdings?kind=secret&prefix=github', { token, anonymous: true });
  assert.deepEqual(narrowed.json.holdings.map(row => row.name), ['github/token', 'github/user']);

  await f.login('other@example.test');
  const other = key();
  await f.approveKey(other, 'other-machine');
  assert.deepEqual((await f.request('/v1/holdings?kind=secret', { token: other, anonymous: true })).json.holdings, []);
  assert.equal((await f.read('secret', 'github/token', { token: other, anonymous: true })).status, 404);
  assert.equal(f.app.secrets.list(USER_B).length, 0);

  const dropped = await f.drop('secret', 'github/token', { token, anonymous: true });
  assert.equal(dropped.status, 200);
  assert.equal((await f.read('secret', 'github/token', { token, anonymous: true })).status, 404);
});

test('What is kept is bounded, so one owner cannot fill the disk', async t => {
  const { f, token } = await keyed(t);
  const big = await put(f, token, 'big/one', 'a'.repeat(1024 * 1024 + 1));
  assert.equal(big.status, 413);
  assert.equal(big.json.error.code, 'too_large');
  assert.equal((await put(f, token, 'long/value', 'a'.repeat(20_000))).status, 200);
  const asVariable = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'long/value', as: 'VALUE' }] } });
  assert.equal(asVariable.status, 413);
  assert.equal(asVariable.json.error.code, 'value_too_large');
  const asFile = await f.request('/v1/deliveries', { method: 'POST', token, anonymous: true, data: { names: [{ name: 'long/value', as: 'LONG_VALUE', filename: 'value.txt' }] } });
  assert.equal(asFile.status, 200, 'the same bytes are fine when they become a file');
});

test('The owner reads and removes anything kept, including what the key may not read back', async t => {
  const { f, token } = await keyed(t);
  await put(f, token, 'github/token', secret, { env: 'GH_TOKEN', secret: 'true' });
  const state = await f.request('/v1/overview');
  assert.deepEqual(state.json.secrets.map(row => row.name), ['github/token']);
  assert.doesNotMatch(state.text, new RegExp(secret));
  const read = await f.read('secret', 'github/token');
  assert.equal(read.status, 200);
  assert.equal(read.text, secret, 'the owner sees what they are keeping');
  assert.equal((await f.drop('secret', 'github/token')).status, 200);
  assert.deepEqual((await f.request('/v1/holdings?kind=secret', { token, anonymous: true })).json.holdings, []);
});

test('The owner edits the value they opened while preserving its name and the lines onto it', async t => {
  const { f, token } = await keyed(t);
  for (const privateValue of [true, false]) {
    const name = privateValue ? 'private value' : 'readable value';
    const path = '/v1/holdings?' + new URLSearchParams({ kind: 'secret', name });
    // Kept by the owner, no line reaches it; kept by the key, the key is on a line to it.
    if (privateValue) await f.request(path, { method: 'PUT', raw: 'original', type: 'text/plain' }); else await put(f, token, name, 'original');
    const content = '/v1/holdings/' + (await f.lookup('secret', name)).json.holding.id + '/content';
    const opened = await f.request(content);
    const etag = opened.headers.get('etag');
    assert.ok(etag);
    assert.equal((await f.request(content)).headers.get('etag'), etag);
    const value = '  {\n  "token": "new value"\n}\n';
    const saved = await f.request(path, { method: 'PUT', raw: value, headers: { 'if-match': etag } });
    assert.equal(saved.status, 200, saved.text);
    assert.equal(saved.json.holding.name, name);
    assert.notEqual(saved.headers.get('etag'), etag);
    const updated = await f.request(content);
    assert.equal(updated.text, value);
    assert.equal(updated.headers.get('etag'), saved.headers.get('etag'));
    const keyRead = await f.read('secret', name, { token, anonymous: true });
    assert.equal(keyRead.status, privateValue ? 403 : 200);
  }
});

test('A stale editor preserves a newer value and its permissions', async t => {
  const { f, token } = await keyed(t);
  const path = '/v1/holdings?kind=secret&name=shared';
  await put(f, token, 'shared', 'original');
  const opened = await f.read('secret', 'shared');
  await put(f, token, 'shared', 'newer value');
  const saved = await f.request(path, { method: 'PUT', raw: 'stale draft', headers: { 'if-match': opened.headers.get('etag') } });
  assert.equal(saved.status, 412, saved.text);
  assert.equal(saved.json.error.code, 'secret_changed');
  assert.equal((await f.read('secret', 'shared')).text, 'newer value');
});

test('A stale editor respects renames, deletion, recreation, and owner boundaries', async t => {
  const { f, token } = await keyed(t);
  const path = '/v1/holdings?kind=secret&name=original';
  await put(f, token, 'original', 'first');
  const etag = (await f.read('secret', 'original')).headers.get('etag');
  const save = () => f.request(path, { method: 'PUT', raw: 'draft', headers: { 'if-match': etag } });
  const rename = async (from, to) => f.request('/v1/holdings/' + (await f.lookup('secret', from)).json.holding.id, { method: 'PATCH', data: { name: to } });
  await rename('original', 'renamed');
  assert.equal((await save()).status, 412);
  assert.deepEqual((await f.request('/v1/overview')).json.secrets.map(row => row.name), ['renamed']);
  await rename('renamed', 'original');
  await f.drop('secret', 'original');
  assert.equal((await save()).status, 412);
  await put(f, token, 'original', 'recreated');
  assert.equal((await save()).status, 412);
  assert.equal((await f.read('secret', 'original')).text, 'recreated');
  const current = (await f.read('secret', 'original')).headers.get('etag');
  await f.login('other@example.test');
  assert.equal((await f.read('secret', 'original')).status, 404);
  assert.equal((await f.request(path, { method: 'PUT', raw: 'other owner', headers: { 'if-match': current } })).status, 412);
  assert.deepEqual((await f.request('/v1/overview')).json.secrets, []);
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

  const script = `const fs=require('fs');if(process.env.GH_TOKEN!==${JSON.stringify(secret)})process.exit(2);if(fs.readFileSync(process.env.APPLE_KEY_PATH,'utf8')!==${JSON.stringify(pem)})process.exit(3);if(!process.env.APPLE_KEY_PATH.endsWith('AuthKey.p8'))process.exit(4);if(process.env.FOUNDATION_NAMES!==JSON.stringify(['github/gh-token','apple/key']))process.exit(5);console.log('ready')`;
  const used = await run(['exec', '--inputs', JSON.stringify([{ name: 'github/gh-token', as: 'GH_TOKEN' }, { name: 'apple/key', as: 'APPLE_KEY_PATH', filename: 'AuthKey.p8' }]), '--', process.execPath, '-e', script], env);
  assert.equal(used.code, 0, used.err);
  assert.equal(used.out.toString().trim(), 'ready');
  assert.doesNotMatch(used.out.toString() + used.err, new RegExp(secret));

  // The file it wrote exists only while the command runs.
  const where = await run(['exec', '--inputs', JSON.stringify([{ name: 'apple/key', as: 'APPLE_KEY_PATH', filename: 'AuthKey.p8' }]), '--', process.execPath, '-e', 'console.log(process.env.APPLE_KEY_PATH)'], env);
  assert.equal(where.code, 0, where.err);
  const { access } = await import('node:fs/promises');
  await assert.rejects(access(where.out.toString().trim()));

  // A command that cannot start still leaves no delivered files on disk.
  const failed = await run(['exec', '--inputs', JSON.stringify([{ name: 'apple/key', as: 'KEY_FILE', filename: 'AuthKey.p8' }]), '--', join(dir, 'no-such-command')], { ...env, XDG_RUNTIME_DIR: dir });
  assert.equal(failed.code, 1);
  assert.deepEqual(await readdir(dir), ['runtime-key']);

  const duplicate = await run(['exec', '--inputs', JSON.stringify([
    { name: 'apple/key', as: 'FIRST_FILE', filename: 'same.p8' },
    { name: 'apple/key', as: 'SECOND_FILE', filename: 'same.p8' },
  ]), '--', process.execPath, '-e', 'console.log("must-not-run")'], { ...env, XDG_RUNTIME_DIR: dir });
  assert.equal(duplicate.code, 1); assert.match(duplicate.err, /filename_conflict/);
  assert.equal(duplicate.out.length, 0); assert.deepEqual(await readdir(dir), ['runtime-key']);

  // Nothing else is a command: everything the agent can do for itself is left to it.
  const refused = await run(['list'], env);
  assert.equal(refused.code, 1);
  assert.match(refused.err, /connect .* exec/);
});

test('保存には承認済みキーを要求し、ガイドに保存と受け渡しのAPIを示す', async t => {
  const f = await fixture(t), token = key();
  assert.equal((await f.request('/v1/holdings?kind=secret', { token, anonymous: true })).status, 401);
  const guide = (await run(['guide'], {})).out.toString();
  assert.match(guide, /PUT \/v1\/holdings\?kind=secret&name=<name>/);
  assert.match(guide, /POST \/v1\/deliveries/);
  assert.match(guide, /Nothing here needs a shell/);
  assert.match(guide, /foundation exec <ENV>/, 'and the one thing that does need one');
});

test('An agent that cannot make a secret of its own is issued one, once', async t => {
  const f = await fixture(t);
  const asked = await f.request('/v1/requests', { method: 'POST', anonymous: true, data: { kind: 'actor', input: { name: 'an agent with no randomness' } } });
  assert.equal(asked.status, 201, asked.text);
  assert.match(asked.json.key, /^fdn_[A-Za-z0-9_-]{43}$/);
  // It is the key: approving the request approves it, and it works from then on.
  await f.request('/v1/requests/' + asked.json.request.id + '/done', { method: 'POST', data: { confirmation_code: asked.json.request.confirmation_code } });
  assert.equal((await f.request('/v1/principals/me', { token: asked.json.key, anonymous: true })).status, 200);
  const again = await f.request('/v1/principals/me', { token: asked.json.key, anonymous: true });
  assert.equal(again.json.key, undefined, 'never handed out a second time');
});

test('閲覧を許された相手は、その保有者の値だけを読み、別の保有者が同じ名前で持つ値は読めない', async t => {
  const f = await fixture(t);
  const kept = await f.request('/v1/holdings?kind=secret&name=shared', { method: 'PUT', raw: 'a-value' });
  const made = await f.request('/v1/principals', { method: 'POST', data: { name: 'reader', credential: 'key' } });
  assert.equal(made.status, 201, made.text);
  const granted = await f.request('/v1/relations', { method: 'POST', data: { subject: made.json.principal.id, relation: 'viewer', object_type: 'holding', object_id: kept.json.holding.id } });
  assert.equal(granted.status, 201, granted.text);
  await f.login('other@example.test');
  await f.request('/v1/holdings?kind=secret&name=shared', { method: 'PUT', raw: 'b-value' });
  const allowed = await f.request('/v1/holdings/' + kept.json.holding.id + '/content', { token: made.json.token, anonymous: true });
  assert.equal(allowed.status, 200, allowed.text); assert.equal(allowed.text, 'a-value');
  const refused = await f.request('/v1/holdings/' + (await f.lookup('secret', 'shared')).json.holding.id + '/content', { token: made.json.token, anonymous: true });
  assert.equal(refused.status, 403, refused.text);
});

test('編集を許された相手はその値を書き換え、値を消すと線は消え、名前を変えると線はついていく', async t => {
  const f = await fixture(t);
  const kept = await f.request('/v1/holdings?kind=secret&name=doc', { method: 'PUT', raw: 'v1' });
  const made = await f.request('/v1/principals', { method: 'POST', data: { name: 'editor', credential: 'key' } });
  const token = made.json.token, id = made.json.principal.id;
  assert.equal((await f.request('/v1/relations', { method: 'POST', data: { subject: id, relation: 'editor', object_type: 'holding', object_id: kept.json.holding.id } })).status, 201);
  const written = await f.request('/v1/holdings?kind=secret&name=doc&as=' + USER_A, { method: 'PUT', raw: 'v2', token, anonymous: true });
  assert.equal(written.status, 200, written.text);
  assert.equal((await f.read('secret', 'doc')).text, 'v2');
  assert.equal((await f.request('/v1/holdings/' + kept.json.holding.id, { method: 'PATCH', data: { name: 'moved' } })).status, 200);
  assert.equal((await f.request('/v1/holdings/' + kept.json.holding.id + '/content', { token, anonymous: true })).status, 200, 'the line follows the thing');
  await f.drop('secret', 'moved');
  const fresh = await f.request('/v1/holdings?kind=secret&name=moved', { method: 'PUT', raw: 'fresh' });
  assert.equal((await f.request('/v1/holdings/' + fresh.json.holding.id + '/content', { token, anonymous: true })).status, 403, 'a new thing by the old name starts with no lines');
  const owner = await f.request('/v1/relations', { method: 'POST', data: { subject: id, relation: 'owner', object_type: 'principal', object_id: USER_A } });
  assert.equal(owner.status, 400, 'ownership is not drawn by hand');
});
