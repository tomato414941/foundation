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
  const registration = await signEnvironment({ format: 2, id: s.row.id,
    origin: s.f.config.origin, ownerId: s.owner.actor.id, name: bootstrap.name, executor: binding,
    operatorId: actor.id, driver: 'managed', callers: bootstrap.callers, capabilities: [Operations.command],
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

test('自分のAIを環境の利用者に指定し、そのAIの実行依頼と結果を受け付ける', async t => {
  const s = await setup(t), { f, c, owner } = s;
  const ai = await f.person('My own AI'), other = await f.person('Other AI');
  await f.principals.relate(owner.actor, ai.actor.id, 'agent', owner.actor.id);
  await f.principals.relate(owner.actor, other.actor.id, 'agent', owner.actor.id);
  const callers = await c.environments.callers(owner.actor, owner.actor.id);
  assert.ok(callers.some(caller => caller.id === ai.actor.id && caller.name === 'My own AI'));
  await assert.rejects(c.environments.callers(s.outsider.actor, owner.actor.id), { code: 'forbidden' });
  await c.environments.remove(owner.actor, s.row);
  await c.environments.tick();
  const row = await c.environments.create(owner.actor, owner.actor.id,
    EnvironmentInput.parse({ callerIds: [owner.actor.id, ai.actor.id] }));
  const executor = await register({ ...s, row });
  const operation = { kind: 'command', command: ['node', '-e', "process.stdout.write('from-my-ai')"],
    inputs: [], environment: {}, files: {}, stdin: '', timeoutSeconds: 10 };
  const intent = { format: 2 as const, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    actor: ai.binding, environmentId: row.id, executor: executor.binding,
    environmentDigest: await hash(executor.registration.manifest), operation: Operations.command,
    functionDigest: null, operationDigest: await hash(operation), sources: [], resultRecipients: [ai.binding],
    createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString() };
  const task = await c.delegation.submit(ai.actor, await prepareRun(intent, operation, ai.keys));
  assert.equal(task.state, 'queued');
  const unselected = { ...intent, id: crypto.randomUUID(), actor: other.binding, resultRecipients: [other.binding] };
  await assert.rejects(c.delegation.submit(other.actor, await prepareRun(unselected, operation, other.keys)));
  const claim = (await c.delegation.claim(executor.actor, row.id))!;
  await c.delegation.dispatch(executor.actor, task.id, claim.lease);
  const receipt = await makeReceipt(intent, 'succeeded', { ok: true,
    result: { exitCode: 0, stdout: 'from-my-ai', stderr: '' }, error: null }, executor.keys);
  const finished = await c.delegation.finish(executor.actor, claim.lease, receipt);
  assert.equal(finished.state, 'succeeded');
  assert.equal((await readReceipt(finished.receipt!, intent, ai.binding.id, ai.keys)).result?.stdout, 'from-my-ai');
});
