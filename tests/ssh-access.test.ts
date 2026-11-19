import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { fingerprintOf } from '../server/ssh-access.js';
import { newSSHKey } from '../cli/src/ssh-keys.js';
import { sshKeyText } from '../shared/ssh.js';
import type { InjectOptions } from 'fastify';

const publicKey = () => {
  const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const field = (value: Buffer) => { const length = Buffer.alloc(4); length.writeUInt32BE(value.length); return Buffer.concat([length, value]); };
  return 'ssh-ed25519 ' + Buffer.concat([field(Buffer.from('ssh-ed25519')), field(Buffer.from(jwk.x!, 'base64url'))]).toString('base64');
};
const fingerprint = (key: string) => fingerprintOf(sshKeyText(key).key);

async function setup() {
  const f = await fixture();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const app = await buildApp(context);
  const call = (person: { token: string }, method: InjectOptions['method'], url: string, payload?: object) =>
    app.inject({ method, url, headers: { authorization: 'Bearer ' + person.token }, ...(payload === undefined ? {} : { payload }) });
  async function close() { await app.close(); await f.close(); }
  return { f, app, call, close };
}
async function registered(s: Awaited<ReturnType<typeof setup>>, owner: { token: string; principal: { id: string } }, suffix = '') {
  const key = (await s.call(owner, 'POST', '/api/principals/' + owner.principal.id + '/ssh-keys',
    { name: 'Laptop' + suffix, publicKey: publicKey() + ' laptop', purpose: 'Deploys' })).json();
  const host = (await s.call(owner, 'POST', '/api/principals/' + owner.principal.id + '/ssh-hosts',
    { name: 'Build server' + suffix, address: 'build.example.test' })).json();
  return { key, host };
}

test('SSH公開鍵と接続先と記録をread権限のある主体にだけ見せる', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner'), other = await s.f.person('Other');
  const { key, host } = await registered(s, owner);
  assert.equal(key.kind, 'ssh_key');
  assert.equal(key.data.fingerprint, fingerprint(key.data.publicKey));
  assert.equal(key.data.privateKeyId, null);
  assert.deepEqual(host.data, { address: 'build.example.test', port: 22 });
  const granted = await s.call(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' });
  assert.equal(granted.statusCode, 201, granted.body);
  for (const url of ['/api/resources/' + key.id, '/api/resources/' + host.id])
    assert.notEqual((await s.call(other, 'GET', url)).statusCode, 200);
  assert.deepEqual((await s.call(other, 'GET', '/api/ssh-access')).json().items, []);

  const shared = await s.call(owner, 'POST', '/api/relations', { subjectId: other.principal.id, relation: 'reader', objectId: host.id });
  assert.equal(shared.statusCode, 200, shared.body);
  const [seen] = (await s.call(other, 'GET', '/api/ssh-access')).json().items;
  assert.equal(seen.account, 'deploy');
  assert.deepEqual(seen.host, { name: 'Build server', address: 'build.example.test', port: 22 });
  assert.equal(seen.key, null);
  assert.equal((await s.call(owner, 'POST', '/api/relations', { subjectId: other.principal.id, relation: 'reader', objectId: key.id })).statusCode, 200);
  assert.equal((await s.call(other, 'GET', '/api/ssh-access')).json().items[0].key.fingerprint, key.data.fingerprint);
});

test('接続先を管理する主体が、SSH鍵でログインするアカウントを記録し、鍵を使う主体もその記録を消せる', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner'), user = await s.f.person('Key user'), other = await s.f.person('Other');
  const { key, host } = await registered(s, owner);
  assert.equal((await s.call(other, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' })).statusCode, 403);
  const granted = (await s.call(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' })).json();
  assert.equal(granted.account, 'deploy');
  assert.equal(granted.grantedBy, owner.principal.id);
  assert.deepEqual(granted.key, { name: 'Laptop', ownerId: owner.principal.id, fingerprint: key.data.fingerprint });

  // Another registration of the same public key is not recorded for the same account a second time.
  const copy = (await s.call(owner, 'POST', '/api/principals/' + owner.principal.id + '/ssh-keys',
    { name: 'Laptop copy', publicKey: key.data.publicKey })).json();
  const duplicate = await s.call(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: copy.id, account: 'deploy' });
  assert.equal(duplicate.statusCode, 409);
  assert.equal(duplicate.json().error.code, 'ssh_key_duplicate');

  assert.equal((await s.call(other, 'DELETE', '/api/ssh-access/' + granted.id)).statusCode, 403);
  assert.equal((await s.call(owner, 'POST', '/api/relations', { subjectId: user.principal.id, relation: 'user', objectId: key.id })).statusCode, 200);
  const removed = await s.call(user, 'DELETE', '/api/ssh-access/' + granted.id);
  assert.equal(removed.statusCode, 200, removed.body);
  assert.deepEqual((await s.call(owner, 'GET', '/api/ssh-access')).json().items, []);
  assert.equal((await s.call(owner, 'DELETE', '/api/ssh-access/' + granted.id)).statusCode, 404);
});

test('記録が残る接続先や鍵も削除でき、その記録も消える', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const first = await registered(s, owner), second = await registered(s, owner, ' 2');
  for (const { key, host } of [first, second]) {
    const granted = await s.call(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' });
    assert.equal(granted.statusCode, 201, granted.body);
  }
  assert.equal((await s.call(owner, 'DELETE', '/api/resources/' + first.host.id)).statusCode, 200);
  assert.equal((await s.call(owner, 'DELETE', '/api/resources/' + second.key.id)).statusCode, 200);
  assert.deepEqual((await s.call(owner, 'GET', '/api/ssh-access')).json().items, []);
  const changed = await s.call(owner, 'PUT', '/api/ssh-hosts/' + second.host.id, { version: second.host.version, address: 'build-2.example.test', port: 2222 });
  assert.equal(changed.statusCode, 200, changed.body);
  assert.deepEqual(changed.json().data, { address: 'build-2.example.test', port: 2222 });
});

async function cliSetup(t: test.TestContext) {
  const reserved = createServer();
  await new Promise<void>(done => reserved.listen(0, '127.0.0.1', done));
  const port = (reserved.address() as { port: number }).port;
  await new Promise<void>(done => reserved.close(() => done()));
  const f = await fixture({ FOUNDATION_ORIGIN: 'http://127.0.0.1:' + port });
  const app = await buildApp(await createContext(f.config, { db: f.db, mailer: f.mailer }));
  const origin = await app.listen({ host: '127.0.0.1', port });
  const directory = await mkdtemp(join(tmpdir(), 'foundation-ssh-cli-'));
  t.after(async () => { await app.close(); await f.close(); await rm(directory, { recursive: true, force: true }); });
  const environment: NodeJS.ProcessEnv = { ...process.env, XDG_CONFIG_HOME: directory };
  for (const name of Object.keys(environment)) if (name.startsWith('FOUNDATION_') || name === 'SSH_AUTH_SOCK') delete environment[name];
  const run = (args: string[], input = '') => new Promise<{ code: number | null; stdout: string; stderr: string }>((done, reject) => {
    const child = spawn(process.execPath, [resolve('cli/dist/cli.mjs'), ...args], { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.end(input);
    let stdout = '', stderr = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', code => done({ code, stdout, stderr }));
  });
  const json = async (args: string[]) => {
    const result = await run(args);
    assert.equal(result.code, 0, result.stderr + result.stdout);
    return JSON.parse(result.stdout);
  };
  assert.equal((await run(['init', '--name', 'Operator', '--origin', origin])).code, 0);
  return { f, run, json, directory };
}

test('CLIはローカルで作ったSSH秘密鍵を結果とは別のファイルに保存し、登録した公開鍵と一致させる', async t => {
  const c = await cliSetup(t);
  const keyFile = join(c.directory, 'keys', 'laptop'), result = join(c.directory, 'result.json');
  const derived = (file: string) => new Promise<string>((done, reject) => {
    const child = spawn('ssh-keygen', ['-y', '-P', '', '-f', file], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.once('error', reject);
    child.once('close', code => code === 0 ? done(stdout.trim().split(' ').slice(0, 2).join(' ')) : reject(new Error('ssh-keygen ' + code)));
  });
  const created = await c.run(['ssh-key', 'create', 'Laptop', '--private-key-output', keyFile, '--output', result]);
  assert.equal(created.code, 0, created.stderr);
  const key = JSON.parse(await readFile(result, 'utf8'));
  assert.equal(key.data.privateKeyId, null);
  assert.equal(await derived(keyFile), key.data.publicKey);

  // Replacing the key file writes the new private key there, and the result goes only to its own file.
  const replaced = await c.run(['ssh-key', 'create', 'Replacement', '--private-key-output', keyFile, '--force', '--output', result]);
  assert.equal(replaced.code, 0, replaced.stderr);
  const replacement = JSON.parse(await readFile(result, 'utf8'));
  assert.equal(await derived(keyFile), replacement.data.publicKey);
  assert.notEqual(replacement.data.publicKey, key.data.publicKey);

  const same = await c.run(['ssh-key', 'create', 'Same', '--private-key-output', keyFile, '--output', keyFile, '--force']);
  assert.equal(same.code, 1);
  assert.match(same.stderr, /different files/);
  assert.equal(await derived(keyFile), replacement.data.publicKey);
  const keys = await c.json(['api', 'GET', '/api/principals/' + key.ownerId + '/resources?kind=ssh_key']);
  assert.deepEqual(keys.items.map((item: { name: string }) => item.name).sort(), ['Laptop', 'Replacement']);
});

test('CLIはSSH鍵の登録に失敗したとき、新しく作った秘密鍵の変数だけを片付ける', async t => {
  const c = await cliSetup(t);
  const purpose = 'x'.repeat(501);
  const failed = await c.run(['ssh-key', 'create', 'Automation', '--store', '--purpose', purpose]);
  assert.equal(failed.code, 1);
  const status = await c.json(['status']);
  const variables = async () => (await c.json(['api', 'GET', '/api/principals/' + status.principal.id + '/resources?kind=variable'])).items
    .map((item: { name: string }) => item.name);
  assert.deepEqual(await variables(), []);
  const keyFile = join(c.directory, 'unregistered');
  assert.equal((await c.run(['ssh-key', 'create', 'Local', '--private-key-output', keyFile, '--purpose', purpose])).code, 1);
  await assert.rejects(readFile(keyFile));

  // A variable of that name already there is neither replaced nor removed.
  assert.equal((await c.run(['keep', 'Automation', '--stdin'], 'kept value')).code, 0);
  assert.equal((await c.run(['ssh-key', 'create', 'Automation', '--store'])).code, 1);
  assert.deepEqual(await variables(), ['Automation']);
  const [kept] = (await c.json(['api', 'GET', '/api/principals/' + status.principal.id + '/resources?kind=variable'])).items;
  assert.equal((await c.run(['read', kept.id])).stdout, 'kept value');
});

test('CLIは秘密鍵を読み込めないとき、待ち続けずに後片付けしてエラーで終わる', async t => {
  const c = await cliSetup(t);
  const kept = await c.run(['keep', 'not-a-key', '--stdin'], 'not an SSH private key');
  assert.equal(kept.code, 0, kept.stderr);
  const variable = JSON.parse(kept.stdout);
  const key = await c.json(['api', 'POST', '/api/principals/' + variable.ownerId + '/ssh-keys', '--body',
    JSON.stringify({ name: 'Broken', publicKey: publicKey(), privateKeyId: variable.id })]);
  const started = Date.now();
  const result = await c.run(['ssh-key', 'agent', key.id, '--', 'true']);
  assert.equal(result.code, 1);
  assert.match(result.stderr, /could not be loaded into an SSH agent/);
  assert.ok(Date.now() - started < 30_000);
});

test('SSH鍵が使う秘密鍵の変数は、使っている鍵を示して削除を断る', async t => {
  const c = await cliSetup(t);
  const variable = JSON.parse((await c.run(['keep', 'automation-key', '--stdin'], newSSHKey().privateKey)).stdout);
  const key = await c.json(['api', 'POST', '/api/principals/' + variable.ownerId + '/ssh-keys', '--body',
    JSON.stringify({ name: 'Automation', publicKey: publicKey(), privateKeyId: variable.id })]);
  const refused = await c.run(['api', 'DELETE', '/api/resources/' + variable.id]);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, new RegExp('in_use: .*Automation \\(ssh_key ' + key.id + '\\)'));
  assert.equal((await c.run(['api', 'DELETE', '/api/resources/' + key.id])).code, 0);
  assert.equal((await c.run(['api', 'DELETE', '/api/resources/' + variable.id])).code, 0);
});

// Why: an SSH key is named by its label in Foundation, which its owner may change; the private key kept for it is
// sealed and is not rewritten on a rename. Intent: the agent lists the key by the name it has when it is used.
test('SSH鍵の名前を変えると、ssh-add -l に新しい名前が出る', async t => {
  const c = await cliSetup(t);
  const key = await c.json(['ssh-key', 'create', 'First name', '--store']);
  const renamed = await c.json(['api', 'PATCH', '/api/resources/' + key.id, '--body', JSON.stringify({ version: key.version, name: 'Second name' })]);
  assert.equal(renamed.name, 'Second name');
  const listed = await c.run(['ssh-key', 'agent', key.id, '--', 'ssh-add', '-l']);
  assert.equal(listed.code, 0, listed.stderr);
  assert.match(listed.stdout, / Second name \(ED25519\)\n$/);
});

// Why: keys kept before their comment was left empty hold the name they were made with, and their sealed private key
// is not rewritten to change it. Intent: such a key, of each type OpenSSH makes, is listed by its current name too.
test('名前を中に持つ秘密鍵も、書き換えずに ssh-add -l へ今の名前で出す', async t => {
  const c = await cliSetup(t);
  for (const type of ['ed25519', 'ecdsa', 'rsa']) {
    const file = join(c.directory, type);
    await new Promise<void>((done, reject) => spawn('ssh-keygen', ['-q', '-t', type, '-N', '', '-C', 'name made with', '-f', file], { stdio: 'ignore' })
      .once('error', reject).once('close', code => code === 0 ? done() : reject(new Error('ssh-keygen ' + code))));
    const key = await c.json(['ssh-key', 'add', 'Current ' + type, '--private-key', file]);
    const listed = await c.run(['ssh-key', 'agent', key.id, '--', 'ssh-add', '-l']);
    assert.equal(listed.code, 0, listed.stderr);
    assert.match(listed.stdout, new RegExp(' Current ' + type + ' \\([A-Z0-9-]+\\)\n$'), type);
    assert.equal((await c.run(['read', key.data.privateKeyId])).stdout, await readFile(file, 'utf8'), type);
  }
});

test('CLIは保存された秘密鍵が選んだSSH鍵の公開鍵と一致しないとき、その鍵を使わない', async t => {
  const c = await cliSetup(t);
  const kept = JSON.parse((await c.run(['keep', 'another-key', '--stdin'], newSSHKey().privateKey)).stdout);
  const key = await c.json(['api', 'POST', '/api/principals/' + kept.ownerId + '/ssh-keys', '--body',
    JSON.stringify({ name: 'Mismatched', publicKey: publicKey(), privateKeyId: kept.id })]);
  const result = await c.run(['ssh-key', 'agent', key.id, '--', 'node', '-e', 'process.stdout.write("ran")']);
  assert.equal(result.code, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /does not match the public key of this SSH key/);
});
