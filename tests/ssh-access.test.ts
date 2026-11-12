import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fixture } from './support.js';
import { confirmedCall } from './confirmation-support.js';
import { sshServer } from './ssh-support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { fingerprintOf, SSHPlan } from '../shared/ssh-access.js';
import { applyPlan, newSSHKey } from '../cli/src/ssh-access.js';
import { sshKeyText } from '../shared/ssh.js';
import type { IdentityKeys } from '../shared/authority.js';
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
  const call = (person: { token: string }, method: InjectOptions['method'], url: string, payload?: object, confirmation?: string) =>
    app.inject({ method, url, headers: { authorization: 'Bearer ' + person.token, ...(confirmation ? { 'foundation-confirmation': confirmation } : {}) },
      ...(payload === undefined ? {} : { payload }) });
  // Sends a change confirmed by signing with the person's keys, as the CLI does.
  const confirmed = (person: { token: string; keys: IdentityKeys }, method: InjectOptions['method'], url: string, payload?: object) =>
    confirmedCall(app, person.keys, { method, url, headers: { authorization: 'Bearer ' + person.token }, ...(payload === undefined ? {} : { payload }) });
  // Confirms one change and returns the confirmation, to send with another.
  async function confirmation(person: { token: string; keys: IdentityKeys }, refused: { json(): { error: { details: { operation: unknown } } } }) {
    const { signConfirmation } = await import('../shared/confirmations.js');
    const view = (await call(person, 'POST', '/api/confirmations', { operation: refused.json().error.details.operation })).json();
    const proved = await call(person, 'POST', '/api/confirmations/' + view.id + '/proof',
      { method: 'signature', signature: await signConfirmation(view, person.keys.signing) });
    assert.equal(proved.statusCode, 200, proved.body);
    return view.id as string;
  }
  async function close() { await app.close(); await f.close(); }
  return { f, app, call, confirmed, confirmation, close };
}
async function registered(s: Awaited<ReturnType<typeof setup>>, owner: { token: string; principal: { id: string } }) {
  const key = (await s.call(owner, 'POST', '/api/principals/' + owner.principal.id + '/ssh-keys',
    { name: 'Laptop', publicKey: publicKey() + ' laptop', purpose: 'Deploys' })).json();
  const host = (await s.call(owner, 'POST', '/api/principals/' + owner.principal.id + '/ssh-hosts',
    { name: 'Build server', address: 'build.example.test', hostKeys: [publicKey()] })).json();
  return { key, host };
}

test('SSH公開鍵と接続先をread権限のある主体にだけ見せる', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner'), other = await s.f.person('Other');
  const { key, host } = await registered(s, owner);
  assert.equal(key.kind, 'ssh_key');
  assert.equal(key.data.fingerprint, fingerprint(key.data.publicKey));
  assert.equal(key.data.privateKeyId, null);
  const granted = await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' });
  assert.equal(granted.statusCode, 201, granted.body);
  for (const url of ['/api/resources/' + key.id, '/api/resources/' + host.id, '/api/ssh-hosts/' + host.id + '/accounts'])
    assert.notEqual((await s.call(other, 'GET', url)).statusCode, 200);
  assert.deepEqual((await s.call(other, 'GET', '/api/ssh-access')).json().items, []);
  assert.equal((await s.call(other, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).statusCode, 403);

  const shared = await s.call(owner, 'POST', '/api/relations', { subjectId: other.principal.id, relation: 'reader', objectId: host.id });
  assert.equal(shared.statusCode, 200, shared.body);
  const [seen] = (await s.call(other, 'GET', '/api/ssh-access')).json().items;
  assert.equal(seen.account, 'deploy');
  assert.deepEqual(seen.host, { name: 'Build server', address: 'build.example.test', port: 22 });
  assert.equal(seen.key, null);
  assert.equal(seen.status, 'pending');
  assert.equal((await s.call(other, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).statusCode, 403);
  assert.equal((await s.call(owner, 'POST', '/api/relations', { subjectId: other.principal.id, relation: 'reader', objectId: key.id })).statusCode, 200);
  assert.equal((await s.call(other, 'GET', '/api/ssh-access')).json().items[0].key.fingerprint, key.data.fingerprint);
});

test('SSHの許可・取消し・鍵の失効・接続先の変更をトークンだけでは受け付けない', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  const grant = { hostId: host.id, keyId: key.id, account: 'deploy' };
  const refused = await s.call(owner, 'POST', '/api/ssh-access', grant);
  assert.equal(refused.statusCode, 403);
  assert.equal(refused.json().error.code, 'confirmation_required');
  assert.deepEqual(refused.json().error.details.methods, ['signature']);
  assert.deepEqual((await s.call(owner, 'GET', '/api/ssh-access')).json().items, []);
  const authorization = (await s.confirmed(owner, 'POST', '/api/ssh-access', grant)).json();

  const changes: Array<[InjectOptions['method'], string, object | undefined]> = [
    ['DELETE', '/api/ssh-access/' + authorization.id, undefined],
    ['POST', '/api/ssh-keys/' + key.id + '/revoke', {}],
    ['PUT', '/api/ssh-hosts/' + host.id, { version: host.version, address: 'other.example.test' }],
    ['PUT', '/api/ssh-hosts/' + host.id, { version: host.version, authorizedKeysFile: '/etc/ssh/keys/%u' }],
    ['PUT', '/api/ssh-hosts/' + host.id, { version: host.version, hostKeys: [publicKey()] }],
  ];
  for (const [method, url, payload] of changes) {
    const response = await s.call(owner, method, url, payload);
    assert.equal(response.statusCode, 403, url);
    assert.equal(response.json().error.code, 'confirmation_required');
  }
  assert.equal((await s.call(owner, 'GET', '/api/ssh-access')).json().items[0].desired, 'present');
  assert.equal((await s.call(owner, 'GET', '/api/resources/' + key.id)).json().data.revokedAt, null);
  assert.equal((await s.call(owner, 'GET', '/api/resources/' + host.id)).json().data.address, 'build.example.test');

  const revoked = await s.confirmed(owner, 'DELETE', '/api/ssh-access/' + authorization.id);
  assert.equal(revoked.statusCode, 200, revoked.body);
  assert.equal(revoked.json().desired, 'absent');
  const moved = await s.confirmed(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, address: 'other.example.test' });
  assert.equal(moved.statusCode, 200, moved.body);
  const keyRevoked = await s.confirmed(owner, 'POST', '/api/ssh-keys/' + key.id + '/revoke', {});
  assert.equal(keyRevoked.statusCode, 200, keyRevoked.body);
  assert.ok(keyRevoked.json().data.revokedAt);
  const again = await s.confirmed(owner, 'POST', '/api/ssh-access', grant);
  assert.equal(again.json().error.code, 'ssh_key_revoked');
});

test('確認した内容と異なるSSHの許可や接続先の変更を受け付けない', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  const confirmedGrant = await s.confirmation(owner, await s.call(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' }));
  for (const swapped of [{ account: 'root' }, { expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, { from: '10.0.0.0/8' }]) {
    const response = await s.call(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy', ...swapped }, confirmedGrant);
    assert.equal(response.statusCode, 403);
    assert.equal(response.json().error.code, 'confirmation_invalid');
  }
  const hostKeys = [publicKey()];
  const confirmedKeys = await s.confirmation(owner, await s.call(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, hostKeys }));
  for (const swapped of [{ address: 'attacker.example.test' }, { port: 2222 }, { authorizedKeysFile: '/etc/ssh/keys/%u' }]) {
    const response = await s.call(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, hostKeys, ...swapped }, confirmedKeys);
    assert.equal(response.statusCode, 403);
    assert.equal(response.json().error.code, 'confirmation_invalid');
  }
  const view = (await s.call(owner, 'GET', '/api/resources/' + host.id)).json();
  assert.deepEqual([view.data.address, view.data.port, view.data.authorizedKeysFile, view.version], ['build.example.test', 22, '.ssh/authorized_keys', 1]);
  const applied = await s.call(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, hostKeys }, confirmedKeys);
  assert.equal(applied.statusCode, 200, applied.body);
  assert.deepEqual(applied.json().data.hostKeys, hostKeys);
});

test('計画の元が変わった後の古い報告を受け付けない', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  const plan = async () => (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json();
  const report = (generation: number) => s.call(owner, 'POST', '/api/ssh-hosts/' + host.id + '/reports',
    { account: 'deploy', generation, outcome: 'verified', managed: [], unmanaged: [] });
  const authorization = (await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' })).json();
  let current = await plan();
  const second = (await s.call(owner, 'POST', '/api/principals/' + owner.principal.id + '/ssh-keys', { name: 'Second', publicKey: publicKey() })).json();
  await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: second.id, account: 'deploy' });
  assert.equal((await report(current.accounts[0].generation)).json().error.code, 'ssh_report_stale');
  current = await plan();
  assert.equal(current.accounts[0].lines.length, 2);
  await s.confirmed(owner, 'DELETE', '/api/ssh-access/' + authorization.id);
  assert.equal((await report(current.accounts[0].generation)).json().error.code, 'ssh_report_stale');
  current = await plan();
  const rotated = await s.confirmed(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, hostKeys: [...host.data.hostKeys, publicKey()] });
  assert.equal(rotated.statusCode, 200, rotated.body);
  assert.equal((await report(current.accounts[0].generation)).json().error.code, 'ssh_report_stale');
  current = await plan();
  await s.confirmed(owner, 'POST', '/api/ssh-keys/' + second.id + '/revoke', {});
  assert.equal((await report(current.accounts[0].generation)).json().error.code, 'ssh_report_stale');
  current = await plan();
  assert.deepEqual(current.accounts[0].lines, []);
  const accepted = await report(current.accounts[0].generation);
  assert.equal(accepted.statusCode, 200, accepted.body);
  assert.equal((await report(current.accounts[0].generation)).json().error.code, 'ssh_report_stale');
});

test('許可が残る間は書込み先ファイルの変更や全ホスト鍵の差し替えを受け付けず、アドレスの変更では観測を保つ', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' });
  const [account] = (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json().accounts;
  await s.call(owner, 'POST', '/api/ssh-hosts/' + host.id + '/reports',
    { account: 'deploy', generation: account.generation, outcome: 'verified', managed: account.lines, unmanaged: [] });
  for (const change of [{ authorizedKeysFile: '.ssh/other_keys' }, { hostKeys: [publicKey()] },
    { address: 'elsewhere.example.test', hostKeys: [publicKey()] }]) {
    const refused = await s.confirmed(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, ...change });
    assert.equal(refused.statusCode, 409, refused.body);
    assert.equal(refused.json().error.code, 'ssh_access_remaining');
  }
  const moved = await s.confirmed(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, address: '192.0.2.10', port: 2222 });
  assert.equal(moved.statusCode, 200, moved.body);
  const [item] = (await s.call(owner, 'GET', '/api/ssh-access?hostId=' + host.id)).json().items;
  assert.equal(item.status, 'applied');
  assert.deepEqual(item.host, { name: 'Build server', address: '192.0.2.10', port: 2222 });
});

test('まだ反映されていない無期限の許可がある間は、鍵・接続先・主体の削除と書込み先の変更を受け付けない', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' });
  const [account] = (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json().accounts;
  const reported = await s.call(owner, 'POST', '/api/ssh-hosts/' + host.id + '/reports',
    { account: 'deploy', generation: account.generation, outcome: 'verified', managed: [], unmanaged: [] });
  assert.equal(reported.statusCode, 200, reported.body);
  const [item] = (await s.call(owner, 'GET', '/api/ssh-access')).json().items;
  assert.deepEqual([item.desired, item.expiresAt, item.observed, item.unmanaged, item.status], ['present', null, 'absent', false, 'pending']);
  for (const response of [
    await s.call(owner, 'DELETE', '/api/resources/' + key.id),
    await s.call(owner, 'DELETE', '/api/resources/' + host.id),
    await s.call(owner, 'DELETE', '/api/principals/' + owner.principal.id),
    await s.confirmed(owner, 'PUT', '/api/ssh-hosts/' + host.id, { version: host.version, authorizedKeysFile: '.ssh/other_keys' }),
  ]) {
    assert.equal(response.statusCode, 409, response.body);
    assert.equal(response.json().error.code, 'ssh_access_remaining');
  }
  assert.equal((await s.call(owner, 'GET', '/api/ssh-access')).json().items.length, 1);
});

test('取り消した鍵が管理外の行に残る間は削除済みとせず、再照合を続ける', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  const authorization = (await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' })).json();
  const report = async (managed: string[], unmanaged: string[]) => {
    const [account] = (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json().accounts;
    const response = await s.call(owner, 'POST', '/api/ssh-hosts/' + host.id + '/reports',
      { account: 'deploy', generation: account.generation, outcome: 'verified', managed, unmanaged });
    assert.equal(response.statusCode, 200, response.body);
    return (await s.call(owner, 'GET', '/api/ssh-access?hostId=' + host.id)).json().items[0];
  };
  const [line] = (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json().accounts[0].lines;
  assert.equal((await report([line], [])).status, 'applied');
  await s.confirmed(owner, 'DELETE', '/api/ssh-access/' + authorization.id);
  assert.equal((await report([line], [])).status, 'pending');
  const remaining = await report([], [key.data.fingerprint]);
  assert.equal(remaining.status, 'remains_unmanaged');
  assert.equal(remaining.unmanaged, true);
  const accounts = (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/accounts')).json().items;
  assert.deepEqual(accounts[0].unmanaged, [{ fingerprint: key.data.fingerprint, keyId: key.id }]);
  assert.equal((await s.confirmed(owner, 'POST', '/api/ssh-keys/' + key.id + '/revoke', {})).statusCode, 200);
  assert.equal((await s.call(owner, 'DELETE', '/api/resources/' + key.id)).json().error.code, 'ssh_access_remaining');
  assert.equal((await report([], [])).status, 'removed');
  // An account once let into stays followed, so a key let in again outside the managed lines is found by a check.
  assert.equal((await report([], [key.data.fingerprint])).status, 'remains_unmanaged');
  assert.equal((await report([], [])).status, 'removed');
  assert.equal((await s.call(owner, 'DELETE', '/api/resources/' + host.id)).statusCode, 200);
  assert.equal((await s.call(owner, 'GET', '/api/ssh-access')).json().items.length, 0);
});

test('取り消した許可がサーバーで確かめられないまま残る接続先は、本人の確認があれば許可ごと削除する', async t => {
  const s = await setup(); t.after(s.close);
  const owner = await s.f.person('Owner');
  const { key, host } = await registered(s, owner);
  const authorization = (await s.confirmed(owner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' })).json();
  await s.confirmed(owner, 'DELETE', '/api/ssh-access/' + authorization.id);
  const [account] = (await s.call(owner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json().accounts;
  await s.call(owner, 'POST', '/api/ssh-hosts/' + host.id + '/reports',
    { account: 'deploy', generation: account.generation, outcome: 'verified', managed: [], unmanaged: [key.data.fingerprint] });
  assert.equal((await s.call(owner, 'GET', '/api/ssh-access')).json().items[0].status, 'remains_unmanaged');

  const refused = await s.call(owner, 'DELETE', '/api/resources/' + host.id);
  assert.equal(refused.statusCode, 403, refused.body);
  assert.equal(refused.json().error.code, 'confirmation_required');
  assert.deepEqual(refused.json().error.details.operation, { action: 'ssh.hostDelete', principalId: owner.principal.id, hostId: host.id });
  assert.equal((await s.call(owner, 'GET', '/api/ssh-access')).json().items.length, 1);
  const deleted = await s.confirmed(owner, 'DELETE', '/api/resources/' + host.id);
  assert.equal(deleted.statusCode, 200, deleted.body);
  assert.equal((await s.call(owner, 'GET', '/api/resources/' + host.id)).statusCode, 404);
  assert.deepEqual((await s.call(owner, 'GET', '/api/ssh-access')).json().items, []);
  assert.equal((await s.call(owner, 'DELETE', '/api/resources/' + key.id)).statusCode, 200);
});

test('鍵の持ち主と接続先の持ち主のどちらも、サーバーに残りうる許可がある間は主体を削除できない', async t => {
  const s = await setup(); t.after(s.close);
  const keyOwner = await s.f.person('Key owner'), hostOwner = await s.f.person('Host owner');
  const key = (await s.call(keyOwner, 'POST', '/api/principals/' + keyOwner.principal.id + '/ssh-keys', { name: 'Laptop', publicKey: publicKey() })).json();
  const host = (await s.call(hostOwner, 'POST', '/api/principals/' + hostOwner.principal.id + '/ssh-hosts',
    { name: 'Build server', address: 'build.example.test', hostKeys: [publicKey()] })).json();
  assert.equal((await s.call(keyOwner, 'POST', '/api/relations', { subjectId: hostOwner.principal.id, relation: 'reader', objectId: key.id })).statusCode, 200);
  const authorization = (await s.confirmed(hostOwner, 'POST', '/api/ssh-access', { hostId: host.id, keyId: key.id, account: 'deploy' })).json();
  // Reports the account as holding exactly the lines of the current plan, as a client does after applying it.
  const applied = async () => {
    const [account] = (await s.call(hostOwner, 'GET', '/api/ssh-hosts/' + host.id + '/plan')).json().accounts;
    const response = await s.call(hostOwner, 'POST', '/api/ssh-hosts/' + host.id + '/reports',
      { account: 'deploy', generation: account.generation, outcome: 'verified', managed: account.lines, unmanaged: [] });
    assert.equal(response.statusCode, 200, response.body);
  };
  await applied();
  assert.equal((await s.call(hostOwner, 'GET', '/api/ssh-access')).json().items[0].status, 'applied');
  const remove = (person: { token: string; principal: { id: string } }) => s.call(person, 'DELETE', '/api/principals/' + person.principal.id);
  for (const person of [keyOwner, hostOwner]) {
    const refused = await remove(person);
    assert.equal(refused.statusCode, 409, refused.body);
    assert.equal(refused.json().error.code, 'ssh_access_remaining');
  }
  // Taken out here but not yet shown gone on the server, it is still followed.
  await s.confirmed(hostOwner, 'DELETE', '/api/ssh-access/' + authorization.id);
  assert.equal((await remove(keyOwner)).json().error.code, 'ssh_access_remaining');
  const [item] = (await s.call(hostOwner, 'GET', '/api/ssh-access')).json().items;
  assert.equal(item.status, 'pending');
  assert.equal(item.key.fingerprint, key.data.fingerprint);

  await applied();
  assert.equal((await s.call(hostOwner, 'GET', '/api/ssh-access')).json().items[0].status, 'removed');
  assert.equal((await remove(keyOwner)).statusCode, 200);
  assert.deepEqual((await s.call(hostOwner, 'GET', '/api/ssh-access')).json().items, []);
  assert.equal((await remove(hostOwner)).statusCode, 200);
});

// The CLI, against a Foundation server listening on a local port.
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

test('CLIで公開鍵を管理区画へ反映し、管理外の行を残したまま読み直して記録する', async t => {
  const server = await sshServer(t), c = await cliSetup(t);
  const identity = join(c.directory, 'operator-key');
  await writeFile(identity, server.keys.privateKey, { mode: 0o600 });
  const outside = '# kept by hand\n' + server.keys.publicKey.trim() + ' operator\n';
  await writeFile(server.authorizedKeys, outside, { mode: 0o600 });
  const host = await c.json(['ssh-host', 'add', 'Test server', '--address', '127.0.0.1', '--port', String(server.port),
    '--host-key', server.keys.hostPublicKey, '--authorized-keys-file', server.authorizedKeys]);
  const laptop = await c.json(['ssh-key', 'add', 'Laptop', '--public-key', publicKey() + ' laptop']);
  const stored = await c.json(['ssh-key', 'create', 'Stored', '--store', '--purpose', 'Automation']);
  assert.ok(stored.data.privateKeyId);
  const grants = [];
  for (const key of [laptop, stored])
    grants.push(await c.json(['ssh-access', 'grant', '--host', host.id, '--ssh-key', key.id, '--account', server.username]));

  const applied = await c.json(['ssh-access', 'apply', host.id, '--identity', identity]);
  assert.deepEqual(applied.accounts, [{ account: server.username, outcome: 'verified' }]);
  const content = await readFile(server.authorizedKeys, 'utf8');
  assert.ok(content.startsWith(outside));
  assert.match(content, new RegExp('# BEGIN FOUNDATION SSH ACCESS ' + host.id + ' \\d+\n'));
  for (const grant of grants) assert.match(content, new RegExp(' foundation:' + grant.id + '\n'));
  const listed = await c.json(['ssh-access', 'list', '--host', host.id]);
  assert.deepEqual(listed.items.map((item: { status: string }) => item.status), ['applied', 'applied']);

  // The stored private key signs in through an agent of its own, without being written to a file. Only that key is
  // offered, never the user's own keys.
  const storedPublic = join(c.directory, 'stored.pub');
  await writeFile(storedPublic, stored.data.publicKey + '\n');
  const signIn = () => c.run(['ssh-key', 'agent', stored.id, '--', 'ssh', '-F', '/dev/null', '-p', String(server.port),
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', storedPublic, '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null', '-o', 'LogLevel=ERROR', server.username + '@127.0.0.1', 'printf signed-in']);
  const signedIn = await signIn();
  assert.equal(signedIn.code, 0, signedIn.stderr);
  assert.equal(signedIn.stdout, 'signed-in');

  // Taking a key out while the same key was also added by hand leaves it let in, and says so.
  const laptopLine = content.split('\n').find(line => line.endsWith('foundation:' + grants[0].id))!;
  await writeFile(server.authorizedKeys, (await readFile(server.authorizedKeys, 'utf8')) + laptopLine.replace(/ foundation:.*/, ' by-hand') + '\n');
  await c.json(['ssh-access', 'revoke', grants[0].id]);
  assert.equal((await c.json(['ssh-access', 'apply', host.id, '--ssh-key', stored.id])).accounts[0].outcome, 'verified');
  const after = await readFile(server.authorizedKeys, 'utf8');
  assert.doesNotMatch(after, new RegExp('foundation:' + grants[0].id));
  assert.match(after, / by-hand\n/);
  let statuses = (await c.json(['ssh-access', 'list', '--host', host.id])).items.map((item: { status: string }) => item.status);
  assert.deepEqual(statuses, ['remains_unmanaged', 'applied']);

  await writeFile(server.authorizedKeys, after.split('\n').filter(line => !line.endsWith(' by-hand')).join('\n'));
  const checked = await c.json(['ssh-access', 'check', host.id, '--identity', identity]);
  assert.equal(checked.accounts[0].outcome, 'verified');
  statuses = (await c.json(['ssh-access', 'list', '--host', host.id])).items.map((item: { status: string }) => item.status);
  assert.deepEqual(statuses, ['removed', 'applied']);

  // Once its authorization is taken out and applied, the server refuses the stored key.
  await c.json(['ssh-access', 'revoke', grants[1].id]);
  assert.equal((await c.json(['ssh-access', 'apply', host.id, '--identity', identity])).accounts[0].outcome, 'verified');
  const refused = await signIn();
  assert.equal(refused.code, 255);
  assert.match(refused.stderr, /Permission denied/);
  statuses = (await c.json(['ssh-access', 'list', '--host', host.id])).items.map((item: { status: string }) => item.status);
  assert.deepEqual(statuses, ['removed', 'removed']);
});

test('古い計画を持つクライアントは、別のクライアントが反映した新しい取消しを書き戻さない', async t => {
  const server = await sshServer(t), c = await cliSetup(t);
  const identity = join(c.directory, 'operator-key');
  await writeFile(identity, server.keys.privateKey, { mode: 0o600 });
  await writeFile(server.authorizedKeys, server.keys.publicKey, { mode: 0o600 });
  const host = await c.json(['ssh-host', 'add', 'Test server', '--address', '127.0.0.1', '--port', String(server.port),
    '--host-key', server.keys.hostPublicKey, '--authorized-keys-file', server.authorizedKeys]);
  const key = await c.json(['ssh-key', 'add', 'Laptop', '--public-key', publicKey()]);
  const grant = await c.json(['ssh-access', 'grant', '--host', host.id, '--ssh-key', key.id, '--account', server.username]);
  assert.equal((await c.json(['ssh-access', 'apply', host.id, '--identity', identity])).accounts[0].outcome, 'verified');
  // One client reads the plan that still lets the key in; the key is then taken out, and another client applies that.
  const old = SSHPlan.parse(await c.json(['api', 'GET', '/api/ssh-hosts/' + host.id + '/plan']));
  assert.equal(old.accounts[0]!.lines.length, 1);
  await c.json(['ssh-access', 'revoke', grant.id]);
  assert.equal((await c.json(['ssh-access', 'apply', host.id, '--identity', identity])).accounts[0].outcome, 'verified');
  const applied = await readFile(server.authorizedKeys, 'utf8');
  assert.doesNotMatch(applied, /foundation:/);
  assert.match(applied, new RegExp('# BEGIN FOUNDATION SSH ACCESS ' + host.id + ' \\d+\n# END FOUNDATION SSH ACCESS ' + host.id + '\n'));
  // The older plan finds the newer one applied, even with no key left, and writes nothing.
  const [late] = await applyPlan(old, { identity }, false);
  assert.equal(late!.outcome, 'conflict');
  assert.equal(await readFile(server.authorizedKeys, 'utf8'), applied);
  assert.equal((await c.json(['ssh-access', 'list', '--host', host.id])).items[0].status, 'removed');
});

test('一度も反映しないまま取り消した許可も、空の計画の反映で版を残し、古い計画では書き戻さない', async t => {
  const server = await sshServer(t), c = await cliSetup(t);
  const identity = join(c.directory, 'operator-key');
  await writeFile(identity, server.keys.privateKey, { mode: 0o600 });
  await writeFile(server.authorizedKeys, server.keys.publicKey, { mode: 0o600 });
  const host = await c.json(['ssh-host', 'add', 'Test server', '--address', '127.0.0.1', '--port', String(server.port),
    '--host-key', server.keys.hostPublicKey, '--authorized-keys-file', server.authorizedKeys]);
  const key = await c.json(['ssh-key', 'add', 'Laptop', '--public-key', publicKey()]);
  const grant = await c.json(['ssh-access', 'grant', '--host', host.id, '--ssh-key', key.id, '--account', server.username]);
  // One client reads the plan letting the key in but applies nothing yet; the key is taken out, and another client
  // applies the plan that is now empty.
  const old = SSHPlan.parse(await c.json(['api', 'GET', '/api/ssh-hosts/' + host.id + '/plan']));
  assert.equal(old.accounts[0]!.lines.length, 1);
  await c.json(['ssh-access', 'revoke', grant.id]);
  assert.equal((await c.json(['ssh-access', 'apply', host.id, '--identity', identity])).accounts[0].outcome, 'verified');
  const applied = await readFile(server.authorizedKeys, 'utf8');
  assert.equal(applied, server.keys.publicKey.trim() + '\n# BEGIN FOUNDATION SSH ACCESS ' + host.id + ' ' + (old.accounts[0]!.generation + 1) +
    '\n# END FOUNDATION SSH ACCESS ' + host.id + '\n');
  const [late] = await applyPlan(old, { identity }, false);
  assert.equal(late!.outcome, 'conflict');
  assert.equal(await readFile(server.authorizedKeys, 'utf8'), applied);
  assert.equal((await c.json(['ssh-access', 'list', '--host', host.id])).items[0].status, 'removed');
});

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

test('CLIは接続できない接続先・ホスト鍵の違う接続先・競合中のファイルを未反映として記録する', async t => {
  const server = await sshServer(t), c = await cliSetup(t);
  const identity = join(c.directory, 'operator-key');
  await writeFile(identity, server.keys.privateKey, { mode: 0o600 });
  await writeFile(server.authorizedKeys, server.keys.publicKey, { mode: 0o600 });
  const key = await c.json(['ssh-key', 'add', 'Laptop', '--public-key', publicKey()]);
  const add = (name: string, port: number, hostKey: string) => c.json(['ssh-host', 'add', name, '--address', '127.0.0.1',
    '--port', String(port), '--host-key', hostKey, '--authorized-keys-file', server.authorizedKeys]);
  const attempt = async (hostId: string) => {
    await c.json(['ssh-access', 'grant', '--host', hostId, '--ssh-key', key.id, '--account', server.username]);
    const result = await c.run(['ssh-access', 'apply', hostId, '--identity', identity]);
    assert.equal(result.code, 1, result.stderr);
    const [item] = (await c.json(['ssh-access', 'list', '--host', hostId])).items;
    assert.equal(item.status, 'pending');
    return item.attempt.outcome;
  };
  const closed = createServer();
  await new Promise<void>(done => closed.listen(0, '127.0.0.1', done));
  const closedPort = (closed.address() as { port: number }).port;
  await new Promise<void>(done => closed.close(() => done()));
  assert.equal(await attempt((await add('Closed', closedPort, server.keys.hostPublicKey)).id), 'unreachable');
  assert.equal(await attempt((await add('Impostor', server.port, publicKey())).id), 'host_key_mismatch');
  const locked = await add('Locked', server.port, server.keys.hostPublicKey);
  await mkdir(join(server.directory, '.foundation-ssh-access.lock'));
  assert.equal(await attempt(locked.id), 'conflict');
  assert.equal(await readFile(server.authorizedKeys, 'utf8'), server.keys.publicKey);
  await rm(join(server.directory, '.foundation-ssh-access.lock'), { recursive: true });

  // A file whose managed lines for the host only end is reported and left as it is.
  const brokenFile = join(server.directory, 'broken_keys');
  const broken = await c.json(['ssh-host', 'add', 'Broken', '--address', '127.0.0.1', '--port', String(server.port),
    '--host-key', server.keys.hostPublicKey, '--authorized-keys-file', brokenFile]);
  const content = 'ssh-ed25519 AAAA by-hand\n# END FOUNDATION SSH ACCESS ' + broken.id + '\n';
  await writeFile(brokenFile, content, { mode: 0o600 });
  assert.equal(await attempt(broken.id), 'invalid_file');
  assert.equal(await readFile(brokenFile, 'utf8'), content);
});
