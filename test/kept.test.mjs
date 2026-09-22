import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, USER_B } from './helpers.mjs';

const key = () => 'fdn_' + randomBytes(32).toString('base64url');
const secret = 'ghp_kept-fixture-' + randomBytes(12).toString('hex');
const execute = (args, env, input) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ['src/runtime.mjs', ...args], { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '', err = '';
  child.stdout.on('data', part => { out += part; }); child.stderr.on('data', part => { err += part; });
  child.stdin.end(input ?? '');
  child.once('error', reject); child.once('exit', code => resolve({ code, out, err }));
});
async function keyFixture(t) {
  const f = await fixture(t), token = key();
  await f.approveKey(token);
  return { f, token };
}
const keep = (f, token, data) => f.request('/v1/vault', { method: 'POST', anonymous: true, token, data });

test('A key keeps values with no service behind them, and a command receives them under the names it chose', async t => {
  const { f, token } = await keyFixture(t);
  const kept = await keep(f, token, { service: 'GitHub', values: { GH_TOKEN: secret, GITHUB_TOKEN: secret } });
  assert.equal(kept.status, 201, kept.text);
  assert.deepEqual(kept.json.value.names, ['GH_TOKEN', 'GITHUB_TOKEN']);
  assert.equal(kept.json.value.service, 'GitHub');
  assert.equal(kept.json.value.kept_by, 'dev-us');
  assert.doesNotMatch(kept.text, new RegExp(secret), 'keeping a value never echoes it back');

  const listed = await f.request('/v1/vault', { token, anonymous: true });
  assert.deepEqual(listed.json.values.map(row => row.service), ['GitHub']);
  assert.doesNotMatch(listed.text, new RegExp(secret), 'listing tells the names, never the values');

  const delivered = await f.request('/v1/credentials/' + kept.json.value.id + '/deliver', { method: 'POST', token, anonymous: true, data: {} });
  assert.equal(delivered.status, 200, delivered.text);
  assert.deepEqual(delivered.json.delivery.environment, { GH_TOKEN: secret, GITHUB_TOKEN: secret });
  assert.equal(delivered.json.expires_at, null);

  const dir = await mkdtemp(join(tmpdir(), 'foundation-kept-test-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };
  const run = await execute(['exec', kept.json.value.id, '--', process.execPath, '-e', `if(process.env.GH_TOKEN!==${JSON.stringify(secret)})process.exit(2);console.log('ready')`], env);
  assert.equal(run.code, 0, run.err);
  assert.equal(run.out.trim(), 'ready');

  const replaced = await f.request('/v1/vault/' + kept.json.value.id, { method: 'PUT', token, anonymous: true, data: { values: { GH_TOKEN: 'ghp_second' } } });
  assert.equal(replaced.status, 200, replaced.text);
  assert.deepEqual(replaced.json.value.names, ['GH_TOKEN']);
  const again = await f.request('/v1/credentials/' + kept.json.value.id + '/deliver', { method: 'POST', token, anonymous: true, data: {} });
  assert.deepEqual(again.json.delivery.environment, { GH_TOKEN: 'ghp_second' });

  const forgotten = await f.request('/v1/vault/' + kept.json.value.id, { method: 'DELETE', token, anonymous: true, data: {} });
  assert.equal(forgotten.status, 200);
  assert.deepEqual((await f.request('/v1/vault', { token, anonymous: true })).json.values, []);
  assert.equal((await f.request('/v1/credentials/' + kept.json.value.id + '/deliver', { method: 'POST', token, anonymous: true, data: {} })).status, 403);
});

test('Kept values take only names a command can read, and never a name an adapter already delivers', async t => {
  const { f, token } = await keyFixture(t);
  const code = async values => (await keep(f, token, { service: 'GitHub', values })).json.error.code;
  assert.equal(await code({ 'lower': 'x' }), 'invalid_env');
  assert.equal(await code({ PATH: 'x' }), 'invalid_env');
  assert.equal(await code({ GOOGLE_OAUTH_ACCESS_TOKEN: 'x' }), 'invalid_env');
  assert.equal(await code({}), 'invalid_values');
  assert.equal(await code({ GH_TOKEN: 'with\nnewline' }), 'invalid_values');
  assert.equal(await code({ GH_TOKEN: '' }), 'invalid_values');
  assert.equal((await keep(f, token, { service: '', values: { GH_TOKEN: 'x' } })).json.error.code, 'invalid_service');
});

test('A key writes a document and reads it back whole, and each owner sees only their own', async t => {
  const { f, token } = await keyFixture(t);
  const state = { step: 'awaiting-review', pull_request: 42, notes: ['ビルドは通った'] };
  const written = await f.request('/v1/documents/release/expo-v3', { method: 'PUT', token, anonymous: true, data: { body: state } });
  assert.equal(written.status, 200, written.text);
  assert.equal(written.json.document.name, 'expo-v3');

  const read = await f.request('/v1/documents/release/expo-v3', { token, anonymous: true });
  assert.deepEqual(read.json.document.body, state);
  assert.equal(read.json.document.kept_by, 'dev-us');

  const updated = await f.request('/v1/documents/release/expo-v3', { method: 'PUT', token, anonymous: true, data: { body: { ...state, step: 'released' } } });
  assert.equal(updated.status, 200);
  assert.equal((await f.request('/v1/documents/release/expo-v3', { token, anonymous: true })).json.document.body.step, 'released');
  assert.equal((await f.request('/v1/documents', { token, anonymous: true })).json.documents.length, 1, 'writing the same name again replaces it');

  await f.request('/v1/documents/notes/todo', { method: 'PUT', token, anonymous: true, data: { body: { next: 'ドメインを決める' } } });
  assert.deepEqual((await f.request('/v1/documents?collection=release', { token, anonymous: true })).json.documents.map(row => row.name), ['expo-v3']);

  // Another owner's key reaches nothing of this one's.
  await f.login('other@example.test');
  const otherToken = key();
  await f.approveKey(otherToken, 'other-machine');
  assert.equal((await f.request('/v1/documents/release/expo-v3', { token: otherToken, anonymous: true })).status, 404);
  assert.deepEqual((await f.request('/v1/vault', { token: otherToken, anonymous: true })).json.values, []);
  assert.equal(f.app.store.documents(USER_B).length, 0);

  const erased = await f.request('/v1/documents/release/expo-v3', { method: 'DELETE', token, anonymous: true, data: {} });
  assert.equal(erased.status, 200);
  assert.equal((await f.request('/v1/documents/release/expo-v3', { token, anonymous: true })).status, 404);
});

test('Documents are named plainly, and refuse a body too large to hold', async t => {
  const { f, token } = await keyFixture(t);
  for (const path of ['/v1/documents/../etc/passwd', '/v1/documents/release/' + 'a'.repeat(65), '/v1/documents/-release/name']) {
    const response = await f.request(path, { method: 'PUT', token, anonymous: true, data: { body: {} } });
    assert.equal(response.status === 404 || response.json.error.code === 'invalid_document', true, path + ' -> ' + response.status);
  }
  const big = await f.request('/v1/documents/release/big', { method: 'PUT', token, anonymous: true, data: { body: { text: 'a'.repeat(263_000) } } });
  assert.equal(big.status, 413);
  assert.equal(big.json.error.code, 'document_too_large');
  // Far beyond what a document can hold, the request itself is refused before it is read.
  const huge = await f.request('/v1/documents/release/big', { method: 'PUT', token, anonymous: true, data: { body: { text: 'a'.repeat(400_000) } } });
  assert.equal(huge.status, 413);
  assert.equal(huge.json.error.code, 'body_too_large');
  assert.equal((await f.request('/v1/documents', { token, anonymous: true })).json.documents.length, 0, 'neither one was kept');
});

test('The CLI keeps a value, writes a document and reads it back', async t => {
  const { f, token } = await keyFixture(t);
  const dir = await mkdtemp(join(tmpdir(), 'foundation-kept-cli-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'runtime-key');
  await writeFile(keyPath, token, { mode: 0o600 });
  const env = { FOUNDATION_URL: f.base, FOUNDATION_RUNTIME_KEY_FILE: keyPath };

  const kept = await execute(['keep', '--service', 'GitHub', '--value', 'GH_TOKEN=' + secret], env);
  assert.equal(kept.code, 0, kept.err);
  assert.deepEqual(JSON.parse(kept.out).value.names, ['GH_TOKEN']);
  assert.doesNotMatch(kept.out, new RegExp(secret));
  const listed = await execute(['values'], env);
  assert.equal(JSON.parse(listed.out).values[0].service, 'GitHub');

  const badName = await execute(['keep', '--service', 'GitHub', '--value', 'lower=x'], env);
  assert.equal(badName.code, 1);
  assert.match(badName.err, /environment variable name/);

  const wrote = await execute(['write', 'release/expo-v3'], env, JSON.stringify({ step: 'awaiting-review' }));
  assert.equal(wrote.code, 0, wrote.err);
  const read = await execute(['read', 'release/expo-v3'], env);
  assert.equal(JSON.parse(read.out).document.body.step, 'awaiting-review');
  const notJson = await execute(['write', 'release/expo-v3'], env, 'not json');
  assert.equal(notJson.code, 1);
  assert.match(notJson.err, /JSON/);
  const erased = await execute(['erase', 'release/expo-v3'], env);
  assert.equal(erased.code, 0, erased.err);
  assert.deepEqual(JSON.parse((await execute(['documents'], env)).out).documents, []);
});

test('Storage needs an approved key and nothing else', async t => {
  const f = await fixture(t), token = key();
  for (const [path, method] of [['/v1/vault', 'GET'], ['/v1/documents', 'GET']]) {
    assert.equal((await f.request(path, { method, token, anonymous: true })).status, 401, path);
  }
  const guide = await execute(['--help'], {});
  assert.match(guide.out, /foundation keep --service <service>/);
  assert.match(guide.out, /foundation write <collection>\/<name>/);
});
