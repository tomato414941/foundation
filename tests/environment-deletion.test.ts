import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { delegatedFixture } from './delegation-support.js';
import { MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { DomainError } from '../server/errors.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { bindKeys, hash, newIdentityKeys, signBinding } from '../shared/authority.js';
import { makeReceipt, readReceipt, signEnvironment } from '../shared/execution.js';
import { Operations, prepareRun } from '../shared/custody.js';

async function setup(t: TestContext) {
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included' });
  const runner = new MemoryRunner(), owner = await f.person(), outsider = await f.person('Outsider');
  const c = await createContext(f.config, { db: f.db, runner });
  t.after(f.close);
  const row = await c.environments.create(owner.actor, owner.actor.id, EnvironmentInput.parse({}));
  return { f, c, runner, owner, outsider, row };
}
async function register(s: Awaited<ReturnType<typeof setup>>) {
  await s.c.environments.tick();
  const bootstrap = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(
    s.runner.machines.get(s.row.id)!.environment.FOUNDATION_EXECUTOR_BOOTSTRAP!, 'base64url').toString()));
  const keys = await newIdentityKeys(), binding = bindKeys(bootstrap.executorId, keys);
  const token = 'fk_' + randomBytes(32).toString('base64url');
  await s.c.environments.enroll(s.row.id, { bootstrap: bootstrap.bootstrap, binding: await signBinding(binding, keys), token });
  const actor = (await s.c.authentication.authenticate(token))!;
  const registration = await signEnvironment({ format: 3, id: s.row.id,
    origin: s.f.config.origin, ownerId: s.owner.actor.id, name: bootstrap.name, executor: binding,
    operatorId: actor.id, driver: 'managed', capabilities: [Operations.command],
    isolation: 'container', commandImage: bootstrap.commandImage, revision: 1 }, keys);
  await s.c.delegation.register(actor, registration);
  return { token, actor, keys, binding, registration };
}

test('稼働中の環境の削除を一度受け付け、停止とディスク削除を完了して結果を返す', async t => {
  const s = await setup(t), { c, f, owner, outsider, row, runner } = s;
  const { token: executorToken } = await register(s);
  const app = await buildApp(c);
  t.after(() => app.close());
  const headers = { authorization: 'Bearer ' + owner.token };
  const denied = await app.inject({ method: 'DELETE', url: '/api/resources/' + row.id,
    headers: { authorization: 'Bearer ' + outsider.token } });
  assert.equal(denied.statusCode, 403);
  const requests = await Promise.all([0, 1].map(() => app.inject({ method: 'DELETE', url: '/api/resources/' + row.id, headers })));
  for (const response of requests) {
    assert.equal(response.statusCode, 202, response.body);
    assert.deepEqual(response.json(), { state: 'pending', error: null });
  }
  const view = await c.resources.view(owner.actor, await c.resources.get(row.id));
  assert.equal(view.kind, 'environment');
  if (view.kind === 'environment') assert.deepEqual(view.data.deletion, { state: 'pending', error: null });
  assert.equal(await c.authentication.authenticate(executorToken), null);
  assert.equal((await f.audit.list(owner.actor.id)).items.filter(item => item.action === 'environment.delete_requested').length, 1);
  assert.equal((await app.inject({ method: 'GET', url: '/api/resources/' + row.id + '/deletion', headers })).json().state, 'pending');
  await c.environments.tick();
  assert.equal(runner.machines.size, 0);
  assert.equal(runner.volumes.size, 0);
  assert.equal((await app.inject({ method: 'GET', url: '/api/resources/' + row.id, headers })).statusCode, 404);
  assert.deepEqual((await app.inject({ method: 'GET', url: '/api/resources/' + row.id + '/deletion', headers })).json(),
    { state: 'complete', error: null });
  assert.equal((await app.inject({ method: 'GET', url: '/api/resources/' + row.id + '/deletion',
    headers: { authorization: 'Bearer ' + outsider.token } })).statusCode, 403);
  assert.equal((await f.audit.list(owner.actor.id)).items.filter(item => item.action === 'resource.delete').length, 1);
});

for (const phase of ['stop', 'removeVolume'] as const) test(
  `${phase === 'stop' ? '停止' : 'ディスク削除'}の失敗理由を保存し、再試行で削除を完了して使用量を一度記録する`, async t => {
    const s = await setup(t), { c, f, owner, row, runner } = s;
    await register(s);
    let failOnce = true;
    const original = runner[phase].bind(runner);
    t.mock.method(runner, phase, async (id: string) => {
      if (failOnce) { failOnce = false; throw new DomainError(502, 'runner_unavailable', 'Provider unavailable'); }
      return original(id);
    });
    await c.environments.remove(owner.actor, await c.resources.get(row.id));
    await c.environments.tick();
    const error = phase === 'stop' ? 'environment_stop_failed' : 'environment_disk_delete_failed';
    assert.deepEqual(await c.environments.deletion(owner.actor, row.id), { state: 'failed', error });
    const restarted = await createContext(f.config, { db: f.db, runner });
    assert.deepEqual((await restarted.resources.get(row.id)).data.deletion, { state: 'failed', error });
    await restarted.environments.remove(owner.actor, await restarted.resources.get(row.id));
    await restarted.environments.tick();
    assert.deepEqual(await restarted.environments.deletion(owner.actor, row.id), { state: 'complete', error: null });
    assert.equal(runner.machines.size, 0);
    assert.equal(runner.volumes.size, 0);
    const usage = await f.db.all("SELECT * FROM billing_events WHERE reference=$1", ['environment:' + row.id]);
    assert.equal(usage.length, 1);
  });

test('起動処理中に削除を受け付け、起動の完了後に同じ環境を停止して削除する', async t => {
  const { c, f, owner, row, runner } = await setup(t);
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const start = runner.start.bind(runner);
  t.mock.method(runner, 'start', async (...args: Parameters<typeof start>) => {
    entered();
    await gate;
    return start(...args);
  });
  const provisioning = c.environments.tick();
  await ready;
  try {
    await c.environments.remove(owner.actor, await c.resources.get(row.id));
    assert.equal(await c.environments.tick(), false);
  } finally { release(); await provisioning; }
  assert.equal(runner.machines.size, 1);
  await f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [row.id]);
  const restarted = await createContext(f.config, { db: f.db, runner });
  await restarted.environments.tick();
  assert.deepEqual(await restarted.environments.deletion(owner.actor, row.id), { state: 'complete', error: null });
  assert.equal(runner.machines.size, 0);
  assert.equal(runner.volumes.size, 0);
});

test('接続した端末の環境登録を削除し、端末の身元を引き続き利用する', async t => {
  const f = await delegatedFixture();
  t.after(f.close);
  const runner = new MemoryRunner();
  const c = await createContext({ ...f.config, FOUNDATION_BILLING_MODE: 'included' }, { db: f.db, runner });
  const row = await c.resources.get(f.environment.manifest.id);
  await c.environments.remove(f.owner.actor, row);
  await c.environments.tick();
  assert.equal((await c.environments.deletion(f.owner.actor, row.id)).state, 'complete');
  assert.equal((await c.authentication.authenticate(f.executor.token))!.id, f.executor.actor.id);
});

test('起動中に作成されたディスクを見つけ、起動が失敗しても削除を完了する', async t => {
  const { c, f, owner, row, runner } = await setup(t);
  let entered!: () => void, release!: () => void;
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  t.mock.method(runner, 'start', async () => {
    runner.volumes.add('vol_' + row.id.replaceAll('-', ''));
    entered(); await gate;
    throw new DomainError(502, 'runner_unavailable', 'Machine creation failed');
  });
  const provisioning = c.environments.tick();
  await ready;
  try { await c.environments.remove(owner.actor, await c.resources.get(row.id)); }
  finally { release(); await provisioning; }
  await f.db.pool.query('UPDATE environment_jobs SET retry_at=now() WHERE resource_id=$1', [row.id]);
  await c.environments.tick();
  assert.equal((await c.environments.deletion(owner.actor, row.id)).state, 'complete');
  assert.equal(runner.volumes.size, 0);
});

async function commandRequest(s: Awaited<ReturnType<typeof setup>>, executor: Awaited<ReturnType<typeof register>>,
  principal: typeof s.owner, ownerId = s.owner.actor.id) {
  const operation = { kind: 'command', command: ['node', '-e', "process.stdout.write('principal-result')"],
    inputs: [], environment: {}, files: {}, stdin: '', timeoutSeconds: 10 };
  const intent = { format: 2 as const, id: crypto.randomUUID(), origin: s.f.config.origin, ownerId,
    actor: principal.binding, environmentId: s.row.id, executor: executor.binding,
    environmentDigest: await hash(executor.registration.manifest), operation: Operations.command,
    functionDigest: null, operationDigest: await hash(operation), sources: [], resultRecipients: [principal.binding],
    createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString() };
  return { intent, request: await prepareRun(intent, operation, principal.keys) };
}

test('鍵が未登録の所有者の実行環境を作成し、所有者の権限で使用する', async t => {
  const s = await setup(t);
  await s.c.environments.remove(s.owner.actor, s.row);
  await s.c.environments.tick();
  const principal = await s.c.principals.create('Principal without keys');
  const row = await s.c.environments.create({ id: principal.id }, principal.id, EnvironmentInput.parse({}));
  assert.equal(row.owner_id, principal.id);
  const view = await s.c.resources.view({ id: principal.id }, row);
  assert.ok(view.permissions.includes('execute'));
  const executor = await register({ ...s, row, owner: { ...s.owner, actor: { id: principal.id } } });
  assert.equal((await s.c.resources.get(row.id)).data.state, 'running');
  assert.equal(executor.registration.manifest.ownerId, principal.id);
});

test('所有者と関連プリンシパルの実行依頼を受け付け、結果を依頼元へ返す', async t => {
  const s = await setup(t), { f, c, owner, row } = s;
  const principal = await f.person('Related principal');
  await f.relations.draw(owner.actor, { subjectId: principal.actor.id, relation: 'agent', objectId: owner.actor.id });
  const executor = await register(s);
  for (const caller of [owner, principal]) {
    const { intent, request } = await commandRequest(s, executor, caller);
    const task = await c.delegation.submit(caller.actor, request);
    assert.equal(task.state, 'queued');
    const claim = (await c.delegation.claim(executor.actor, row.id))!;
    await c.delegation.dispatch(executor.actor, task.id, claim.lease);
    const receipt = await makeReceipt(intent, 'succeeded', { ok: true,
      result: { exitCode: 0, stdout: 'principal-result', stderr: '' }, error: null }, executor.keys);
    const finished = await c.delegation.finish(executor.actor, claim.lease, receipt);
    assert.equal(finished.state, 'succeeded');
    assert.equal((await readReceipt(finished.receipt!, intent, caller.binding.id, caller.keys)).result?.stdout, 'principal-result');
  }
});

test('プリンシパルへの共有を登録更新後も保持し、権限の解除を待機中の実行にも反映する', async t => {
  const s = await setup(t), { c, owner, outsider, row } = s;
  let executor = await register(s);
  const denied = await commandRequest(s, executor, outsider, outsider.actor.id);
  await assert.rejects(c.delegation.submit(outsider.actor, denied.request), { code: 'forbidden' });
  for (const relation of ['reader', 'runner'])
    await c.relations.draw(owner.actor, { subjectId: outsider.actor.id, relation, objectId: row.id });
  const registration = await signEnvironment({ ...executor.registration.manifest, revision: 2 }, executor.keys);
  await c.delegation.register(executor.actor, registration);
  executor = { ...executor, registration };
  const permissions = (await c.resources.view(outsider.actor, await c.resources.get(row.id))).permissions;
  assert.ok(permissions.includes('execute'));
  const { request } = await commandRequest(s, executor, outsider, outsider.actor.id);
  const task = await c.delegation.submit(outsider.actor, request);
  assert.equal(task.state, 'queued');
  for (const relation of ['reader', 'runner'])
    await c.relations.erase(owner.actor, { subjectId: outsider.actor.id, relation, objectId: row.id });
  assert.equal(await c.delegation.claim(executor.actor, row.id), null);
  const failed = await c.delegation.get(outsider.actor, task.id);
  assert.equal(failed.state, 'failed');
  assert.equal(failed.error, 'authorization_changed');
  const revoked = await commandRequest(s, executor, outsider, outsider.actor.id);
  await assert.rejects(c.delegation.submit(outsider.actor, revoked.request), { code: 'forbidden' });
});
