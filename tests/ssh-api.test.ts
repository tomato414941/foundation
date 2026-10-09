import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { SSHView, sshKeyBytes } from '../shared/ssh.js';
import { bindKeys, newIdentityKeys, signBinding } from '../shared/authority.js';
import { signEnvironment } from '../shared/execution.js';
import { Operations } from '../shared/custody.js';
import { DomainError } from '../server/errors.js';

function publicKey() {
  const field = (value: Buffer) => {
    const length = Buffer.alloc(4); length.writeUInt32BE(value.length);
    return Buffer.concat([length, value]);
  };
  return 'ssh-ed25519 ' + Buffer.concat([field(Buffer.from('ssh-ed25519')), field(randomBytes(32))]).toString('base64');
}
async function setup(t: TestContext, range = 2) {
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included', FLY_SSH_HOST: 'ssh.foundation.test',
    FOUNDATION_INCLUDED_ENVIRONMENTS: '10',
    FLY_SSH_PORT_MIN: '24000', FLY_SSH_PORT_MAX: String(23999 + range) });
  t.after(f.close);
  const owner = await f.person(), other = await f.person('Other principal'), runner = new MemoryRunner();
  const c = await createContext(f.config, { db: f.db, runner }), app = await buildApp(c);
  t.after(() => app.close());
  const headers = { authorization: 'Bearer ' + owner.token };
  const keys = [publicKey()];
  const row = await c.environments.create(owner.actor, owner.actor.id,
    EnvironmentInput.parse({ lifetime: { idleSeconds: 60, maxSeconds: 600 }, ssh: { authorizedKeys: keys } }));
  return { f, c, app, owner, other, runner, headers, keys, row };
}
async function register(s: Awaited<ReturnType<typeof setup>>) {
  await s.c.environments.tick();
  const bootstrap = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(
    s.runner.machines.get(s.row.id)!.environment.FOUNDATION_EXECUTOR_BOOTSTRAP!, 'base64url').toString()));
  const keys = await newIdentityKeys(), binding = bindKeys(bootstrap.executorId, keys);
  const token = 'fk_' + randomBytes(32).toString('base64url');
  await s.c.environments.enroll(s.row.id, { bootstrap: bootstrap.bootstrap, binding: await signBinding(binding, keys), token });
  const actor = (await s.c.authentication.authenticate(token))!;
  await s.c.delegation.register(actor, await signEnvironment({ format: 3, id: s.row.id,
    origin: s.f.config.origin, ownerId: s.owner.actor.id, name: bootstrap.name, executor: binding,
    operatorId: actor.id, driver: 'managed', capabilities: [Operations.command],
    isolation: 'container', commandImage: bootstrap.commandImage, revision: 1 }, keys));
  return { actor, headers: { authorization: 'Bearer ' + token }, hostKey: publicKey() };
}

test('公開鍵を登録した環境の接続情報を返し、鍵の変更を実行環境へ届けて反映状態を示す', async t => {
  const s = await setup(t), { app, headers, row, keys } = s;
  const url = '/api/environments/' + row.id + '/ssh';
  assert.equal((await app.inject({ url: '/api/session', headers })).json().features.ssh, true);
  const starting = SSHView.parse((await app.inject({ url, headers })).json());
  assert.equal(starting.state, 'starting');
  assert.equal(starting.host, 'ssh.foundation.test');
  assert.equal(starting.port, 24000);
  assert.equal(starting.username, 'root');
  assert.equal(starting.workingDirectory, '/workspace');
  assert.deepEqual(starting.authorizedKeys, keys);
  const executor = await register(s);
  assert.equal(s.runner.machines.get(row.id)!.environment.FOUNDATION_SSH_PORT, '24000');
  const beat = (appliedRevision: number) => app.inject({ method: 'POST', url: url + '/heartbeat', headers: executor.headers,
    payload: { hostKey: executor.hostKey, appliedRevision, activeSessions: 0 } });
  const initial = await beat(0);
  assert.equal(initial.statusCode, 200, initial.body);
  assert.deepEqual(initial.json().configuration, { authorizedKeys: keys, port: starting.port, revision: 1 });
  await beat(1);
  const ready = SSHView.parse((await app.inject({ url, headers })).json());
  assert.equal(ready.state, 'ready');
  assert.equal(ready.hostKey, executor.hostKey);
  assert.equal(ready.fingerprint, 'SHA256:' + createHash('sha256').update(sshKeyBytes(executor.hostKey)!).digest('base64').replace(/=+$/, ''));
  const replacement = publicKey();
  const update = await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [replacement], revision: ready.revision } });
  assert.equal(update.statusCode, 200, update.body);
  assert.equal(update.json().state, 'configuring');
  assert.equal((await beat(1)).json().configuration.revision, 2);
  assert.deepEqual((await beat(1)).json().configuration.authorizedKeys, [replacement]);
  await beat(2);
  assert.equal((await app.inject({ url, headers })).json().state, 'ready');
  const conflict = await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: keys, revision: 1 } });
  assert.equal(conflict.statusCode, 409);
  const disable = await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [], revision: 2 } });
  assert.equal(disable.statusCode, 200, disable.body);
  await beat(3);
  assert.equal((await app.inject({ url, headers })).json().state, 'disabled');
});

test('編集権限のあるプリンシパルがSSH鍵を設定し、登録した実行環境だけがホスト鍵を報告する', async t => {
  const s = await setup(t), executor = await register(s), { app, row, c, owner, other } = s;
  const url = '/api/environments/' + row.id + '/ssh', headers = { authorization: 'Bearer ' + other.token };
  assert.equal((await app.inject({ url, headers })).statusCode, 403);
  for (const relation of ['reader', 'runner'])
    await c.relations.draw(owner.actor, { subjectId: other.actor.id, relation, objectId: row.id });
  assert.equal((await app.inject({ url, headers })).statusCode, 200);
  assert.equal((await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [publicKey()] } })).statusCode, 403);
  assert.equal((await app.inject({ method: 'POST', url: url + '/heartbeat', headers: s.headers,
    payload: { hostKey: executor.hostKey, appliedRevision: 1, activeSessions: 0 } })).statusCode, 403);
  const heartbeat = { hostKey: executor.hostKey, appliedRevision: 1, activeSessions: 0 };
  assert.equal((await app.inject({ method: 'POST', url: url + '/heartbeat', headers: executor.headers, payload: heartbeat })).statusCode, 200);
  const changed = await app.inject({ method: 'POST', url: url + '/heartbeat', headers: executor.headers,
    payload: { ...heartbeat, hostKey: publicKey() } });
  assert.equal(changed.statusCode, 409);
  assert.equal(changed.json().error.code, 'ssh_host_key_changed');
  const malformed = await app.inject({ method: 'PUT', url, headers: s.headers, payload: { authorizedKeys: ['not a public key'] } });
  assert.equal(malformed.statusCode, 400);
});

test('SSH接続中はアイドル停止を延期し、接続終了後にアイドル停止する', async t => {
  const s = await setup(t), executor = await register(s);
  await s.c.environments.sshHeartbeat(executor.actor, s.row.id, { hostKey: executor.hostKey, appliedRevision: 1, activeSessions: 1 });
  await s.f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb((now()-interval '2 minutes')::text)) WHERE id=$1", [s.row.id]);
  await s.c.environments.tick();
  assert.equal((await s.c.resources.get(s.row.id)).data.state, 'running');
  await s.c.environments.sshHeartbeat(executor.actor, s.row.id, { hostKey: executor.hostKey, appliedRevision: 1, activeSessions: 0 });
  await s.f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [s.row.id]);
  await s.c.environments.tick();
  assert.equal((await s.c.environments.ssh(s.owner.actor, s.row.id))!.state, 'stopped');
  assert.equal(s.runner.machines.size, 0);
});

test('SSH接続中も最長稼働時間を適用して環境を停止する', async t => {
  const s = await setup(t), executor = await register(s);
  await s.c.environments.sshHeartbeat(executor.actor, s.row.id, { hostKey: executor.hostKey, appliedRevision: 1, activeSessions: 1 });
  await s.f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb((now()-interval '11 minutes')::text)) WHERE id=$1", [s.row.id]);
  await s.f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [s.row.id]);
  await s.c.environments.tick();
  assert.equal((await s.c.environments.ssh(s.owner.actor, s.row.id))!.state, 'stopped');
  assert.equal(s.runner.machines.size, 0);
});

test('同時作成した環境へ別々のSSHポートを割り当て、停止を完了したポートを再利用する', async t => {
  const s = await setup(t, 3);
  const options = EnvironmentInput.parse({ lifetime: { idleSeconds: 60, maxSeconds: 600 } });
  const rows = await Promise.all([0, 1].map(() => s.c.environments.create(s.owner.actor, s.owner.actor.id, options)));
  const ports = await Promise.all([s.row, ...rows].map(row => s.c.environments.ssh(s.owner.actor, row.id)));
  assert.deepEqual(ports.map(value => value!.port).sort(), [24000, 24001, 24002]);
  await assert.rejects(s.c.environments.create(s.owner.actor, s.owner.actor.id, options), { code: 'ssh_capacity' });
  await register(s);
  const stop = s.runner.stop.bind(s.runner);
  let failed = false;
  t.mock.method(s.runner, 'stop', async (id: string) => {
    if (!failed) { failed = true; throw new DomainError(502, 'runner_unavailable', 'Provider unavailable'); }
    return stop(id);
  });
  await s.c.environments.remove(s.owner.actor, await s.c.resources.get(s.row.id));
  await s.c.environments.tick();
  await assert.rejects(s.c.environments.create(s.owner.actor, s.owner.actor.id, options), { code: 'ssh_capacity' });
  await s.c.environments.remove(s.owner.actor, await s.c.resources.get(s.row.id));
  await s.c.environments.tick();
  const next = await s.c.environments.create(s.owner.actor, s.owner.actor.id, options);
  assert.equal((await s.c.environments.ssh(s.owner.actor, next.id))!.port, 24000);
});
