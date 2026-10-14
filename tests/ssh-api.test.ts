import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { SSHView, sshKeyBytes } from '../shared/ssh.js';

function publicKey() {
  const field = (value: Buffer) => {
    const length = Buffer.alloc(4); length.writeUInt32BE(value.length);
    return Buffer.concat([length, value]);
  };
  return 'ssh-ed25519 ' + Buffer.concat([field(Buffer.from('ssh-ed25519')), field(randomBytes(32))]).toString('base64');
}
async function setup(t: TestContext) {
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included', FOUNDATION_INCLUDED_ENVIRONMENTS: '10' });
  t.after(f.close);
  const owner = await f.person(), other = await f.person('Other principal'), runner = new MemoryRunner();
  const c = await createContext(f.config, { db: f.db, runner, ssh: runner.ssh }), app = await buildApp(c);
  t.after(() => app.close());
  const headers = { authorization: 'Bearer ' + owner.token };
  const keys = [publicKey()];
  const row = await c.environments.create(owner.actor, owner.actor.id,
    EnvironmentInput.parse({ lifetime: { idleSeconds: 60, maxSeconds: 600 }, ssh: { authorizedKeys: keys } }));
  return { f, c, app, owner, other, runner, headers, keys, row };
}
async function register(s: Awaited<ReturnType<typeof setup>>) {
  await s.c.environments.tick();

}

test('公開鍵を登録した環境の接続情報を返し、鍵の変更を実行環境へ届けて反映状態を示す', async t => {
  const s = await setup(t), { app, headers, row, keys } = s;
  const url = '/api/environments/' + row.id + '/ssh';
  assert.equal((await app.inject({ url: '/api/session', headers })).json().features.ssh, true);
  const starting = SSHView.parse((await app.inject({ url, headers })).json());
  assert.equal(starting.state, 'starting');
  assert.equal(starting.host, null);
  assert.equal(starting.port, 22);
  assert.equal(starting.username, 'ubuntu');
  assert.equal(starting.workingDirectory, '/home/ubuntu');
  assert.deepEqual(starting.authorizedKeys, keys);
  await register(s);
  assert.equal((await s.c.environments.ssh(s.owner.actor, row.id))!.host, row.id + '.ssh.foundation.test');
  const hostKey = s.runner.machines.get(row.id)!.ssh.keys.hostPublicKey;
  const ready = SSHView.parse((await app.inject({ url, headers })).json());
  assert.equal(ready.state, 'ready');
  assert.equal(ready.hostKey, hostKey);
  assert.equal(ready.fingerprint, 'SHA256:' + createHash('sha256').update(sshKeyBytes(hostKey)!).digest('base64').replace(/=+$/, ''));
  const replacement = publicKey();
  const update = await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [replacement], revision: ready.revision } });
  assert.equal(update.statusCode, 200, update.body);
  assert.equal(update.json().state, 'configuring');
  await s.c.environments.syncSSH(row.id);
  assert.equal((await app.inject({ url, headers })).json().state, 'ready');
  const conflict = await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: keys, revision: 1 } });
  assert.equal(conflict.statusCode, 409);
  const disable = await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [], revision: 2 } });
  assert.equal(disable.statusCode, 200, disable.body);
  await s.c.environments.syncSSH(row.id);
  assert.equal((await app.inject({ url, headers })).json().state, 'disabled');
});

test('編集権限のあるプリンシパルがSSH鍵を設定する', async t => {
  const s = await setup(t), { app, row, c, owner, other } = s;
  await register(s);
  const url = '/api/environments/' + row.id + '/ssh', headers = { authorization: 'Bearer ' + other.token };
  assert.equal((await app.inject({ url, headers })).statusCode, 403);
  for (const relation of ['reader', 'runner'])
    await c.relations.draw(owner.actor, { subjectId: other.actor.id, relation, objectId: row.id });
  assert.equal((await app.inject({ url, headers })).statusCode, 200);
  assert.equal((await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [publicKey()] } })).statusCode, 403);
  await c.relations.draw(owner.actor, { subjectId: other.actor.id, relation: 'editor', objectId: row.id });
  assert.equal((await app.inject({ method: 'PUT', url, headers, payload: { authorizedKeys: [publicKey()] } })).statusCode, 200);
  const malformed = await app.inject({ method: 'PUT', url, headers: s.headers, payload: { authorizedKeys: ['not a public key'] } });
  assert.equal(malformed.statusCode, 400);
});

test('SSH接続中はアイドル停止を延期し、接続終了後にアイドル停止する', async t => {
  const s = await setup(t);
  await register(s);
  s.runner.ssh.sessions.set(s.row.id, 1);
  await s.f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb((now()-interval '2 minutes')::text)) WHERE id=$1", [s.row.id]);
  await s.c.environments.tick();
  assert.equal((await s.c.resources.get(s.row.id)).data.state, 'running');
  s.runner.ssh.sessions.set(s.row.id, 0);
  await s.f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb((now()-interval '2 minutes')::text)) WHERE id=$1", [s.row.id]);
  await s.f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [s.row.id]);
  await s.c.environments.tick();
  assert.equal((await s.c.environments.ssh(s.owner.actor, s.row.id))!.state, 'stopped');
  assert.equal(s.runner.machines.get(s.row.id)!.state, 'stopped');
});

test('SSH接続中も最長稼働時間を適用して環境を停止する', async t => {
  const s = await setup(t);
  await register(s);
  s.runner.ssh.sessions.set(s.row.id, 1);
  await s.f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb((now()-interval '11 minutes')::text)) WHERE id=$1", [s.row.id]);
  await s.f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [s.row.id]);
  await s.c.environments.tick();
  assert.equal((await s.c.environments.ssh(s.owner.actor, s.row.id))!.state, 'stopped');
  assert.equal(s.runner.machines.get(s.row.id)!.state, 'stopped');
});

test('同じ所有者の環境を同時に作成し、それぞれのSSH接続情報を返す', async t => {
  const s = await setup(t);
  const options = EnvironmentInput.parse({ lifetime: { idleSeconds: 60, maxSeconds: 600 } });
  const rows = await Promise.all([0, 1].map(() => s.c.environments.create(s.owner.actor, s.owner.actor.id, options)));
  for (const row of [s.row, ...rows]) {
    await s.f.db.pool.query('UPDATE environment_jobs SET retry_at=now()');
    await s.c.environments.tick();
  }
  const connections = await Promise.all([s.row, ...rows].map(row => s.c.environments.ssh(s.owner.actor, row.id)));
  assert.equal(new Set(connections.map(value => value!.host)).size, 3);
  assert.deepEqual(connections.map(value => value!.port), [22, 22, 22]);
});
