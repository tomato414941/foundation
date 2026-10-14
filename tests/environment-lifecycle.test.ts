import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fixture } from './support.js';
import { MemoryRunner } from './fakes.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { EnvironmentInput } from '../shared/contracts.js';
import { EnvironmentBootstrap } from '../shared/protocol.js';
import { bindKeys, newIdentityKeys, signBinding } from '../shared/authority.js';
import { signEnvironment } from '../shared/runtime-protocol.js';
import { Operations } from '../shared/custody.js';

async function setup(t: TestContext) {
  const f = await fixture({ FOUNDATION_BILLING_MODE: 'included', FOUNDATION_INCLUDED_COMPUTE_SECONDS: '1000000000' });
  t.after(f.close);
  const runner = new MemoryRunner(), owner = await f.person(), outsider = await f.person('Outsider');
  const c = await createContext(f.config, { db: f.db, runner });
  await c.billing.limits(owner.actor, owner.actor.id, 1073741824, 1000000000);
  async function create(input = {}) {
    const row = await c.environments.create(owner.actor, owner.actor.id, EnvironmentInput.parse(input));
    await c.environments.tick();
    const bootstrap = EnvironmentBootstrap.parse(JSON.parse(Buffer.from(
      runner.machines.get(row.id)!.environment.FOUNDATION_EXECUTOR_BOOTSTRAP!, 'base64url').toString()));
    const keys = await newIdentityKeys(), binding = bindKeys(bootstrap.executorId, keys);
    const token = 'fk_' + randomBytes(32).toString('base64url');
    const enrollment = { bootstrap: bootstrap.bootstrap, binding: await signBinding(binding, keys), token };
    await c.environments.enroll(row.id, enrollment);
    const actor = (await c.authentication.authenticate(token))!;
    const registration = await signEnvironment({ format: 3, id: row.id, origin: f.config.origin,
      ownerId: owner.actor.id, name: row.name, executor: binding, operatorId: actor.id,
      driver: 'managed', capabilities: [Operations.command], isolation: 'process',
      functionImage: bootstrap.functionImage, revision: 1 }, keys);
    await c.delegation.register(actor, registration);
    return { row, token, actor, registration, enrollment };
  }
  return { f, c, runner, owner, outsider, create };
}

test('時間制限を指定しない環境を操作のない数日間も稼働させ、指定した期限では停止する', async t => {
  const { f, c, owner, create } = await setup(t);
  const unlimited = await create(), limited = await create({ lifetime: { maxSeconds: 3 * 86400 } });
  assert.deepEqual(unlimited.row.data.lifetime, { idleSeconds: null, maxSeconds: null });
  const since = new Date(Math.floor(Date.now() / 1000) * 1000 - 4 * 86400000).toISOString();
  for (const { row } of [unlimited, limited]) await f.db.pool.query(
    "UPDATE resources SET data=data||jsonb_build_object('startedAt',$2::text,'lastActiveAt',$2::text) WHERE id=$1", [row.id, since]);
  await c.environments.tick();
  assert.equal((await c.resources.get(unlimited.row.id)).data.state, 'running');
  const stopped = await c.resources.view(owner.actor, await c.resources.get(limited.row.id));
  assert.equal(stopped.kind, 'environment');
  if (stopped.kind === 'environment') {
    assert.equal(stopped.data.state, 'stopped');
    assert.equal(stopped.data.stopReason, 'timeout');
    assert.equal(stopped.data.error, null);
  }
});

test('APIから同じ環境を再起動し、所有者の権限・保存した身元・SSHホスト鍵を引き継ぐ', async t => {
  const { f, c, runner, owner, outsider, create } = await setup(t), environment = await create();
  const { row, token, actor, registration } = environment;
  const app = await buildApp(c);
  t.after(() => app.close());
  const headers = { authorization: 'Bearer ' + owner.token };
  const hostKey = 'ssh-ed25519 ' + Buffer.concat([
    Buffer.from('0000000b7373682d6564323535313900000020', 'hex'), randomBytes(32),
  ]).toString('base64');
  await c.environments.sshHeartbeat(actor, row.id, { hostKey, appliedRevision: 1, activeSessions: 1 });
  const original = await c.environments.ssh(owner.actor, row.id);
  const volume = await runner.findVolume(row.id);
  assert.equal((await app.inject({ method: 'POST', url: '/api/resources/' + row.id + '/stop', headers, payload: {} })).statusCode, 200);
  await c.environments.tick();
  assert.equal(await c.authentication.authenticate(token), null);
  assert.equal((await app.inject({ method: 'POST', url: '/api/resources/' + row.id + '/start',
    headers: { authorization: 'Bearer ' + outsider.token }, payload: {} })).statusCode, 403);
  const responses = await Promise.all([0, 1].map(() => app.inject({ method: 'POST',
    url: '/api/resources/' + row.id + '/start', headers, payload: {} })));
  for (const response of responses) {
    assert.equal(response.statusCode, 200, response.body);
    assert.equal(response.json().data.state, 'starting');
  }
  await c.environments.tick();
  const resumedActor = (await c.authentication.authenticate(token))!;
  await c.delegation.register(resumedActor, registration);
  await c.environments.sshHeartbeat(resumedActor, row.id, { hostKey, appliedRevision: 1, activeSessions: 0 });
  const resumed = await c.resources.get(row.id), ssh = await c.environments.ssh(owner.actor, row.id);
  assert.equal(resumed.data.state, 'running');
  assert.equal(resumed.data.executorId, row.data.executorId);
  assert.equal(resumed.owner_id, owner.actor.id);
  assert.equal(resumed.data.stopReason, null);
  assert.equal(await runner.findVolume(row.id), volume);
  assert.equal(ssh!.fingerprint, original!.fingerprint);
  assert.notEqual(ssh!.host, original!.host);
  await c.delegation.heartbeat(resumedActor, row.id);
  assert.equal((await f.audit.list(owner.actor.id)).items.filter(event => event.action === 'environment.start').length, 1);
});

test('同時稼働の環境の使用量をサイズに応じて合算し、利用枠に達した環境を停止する', async t => {
  const { f, c, owner, create } = await setup(t);
  const small = await create(), medium = await create({ size: 'medium' });
  await c.billing.limits(owner.actor, owner.actor.id, 1073741824, 300);
  await f.db.pool.query(
    "UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb((date_trunc('second',now())-interval '2 minutes')::text)) WHERE id=ANY($1::uuid[])",
    [[small.row.id, medium.row.id]]);
  const usage = await c.billing.usage(owner.actor.id);
  assert.ok(usage.computeSeconds >= 360 && usage.computeSeconds < 375, String(usage.computeSeconds));
  await c.environments.tick();
  await c.environments.tick();
  for (const { row } of [small, medium]) {
    const environment = await c.resources.get(row.id);
    assert.equal(environment.data.state, 'stopped');
    assert.equal(environment.data.stopReason, 'quota');
  }
  await assert.rejects(c.environments.start(owner.actor, await c.resources.get(small.row.id)), { code: 'compute_limit' });
  await c.billing.limits(owner.actor, owner.actor.id, 1073741824, 10000);
  assert.equal((await c.environments.start(owner.actor, await c.resources.get(small.row.id))).data.state, 'starting');
});

test('所有者が再起動した環境を保存済みの身元で再登録する', async t => {
  const { c, owner, create } = await setup(t), { row, actor, token, registration, enrollment } = await create();
  await c.authentication.removeCredential(actor, actor.id, actor.credentialId!);
  await c.environments.stop(owner.actor, await c.resources.get(row.id));
  await c.environments.tick();
  await c.environments.start(owner.actor, await c.resources.get(row.id));
  await c.environments.tick();
  await assert.rejects(c.environments.enroll(row.id, { ...enrollment, bootstrap: randomBytes(32).toString('base64url') }), { code: 'bootstrap_expired' });
  await c.environments.enroll(row.id, enrollment);
  const resumed = (await c.authentication.authenticate(token))!;
  await c.delegation.register(resumed, registration);
  assert.equal(resumed.id, actor.id);
  assert.equal((await c.resources.get(row.id)).data.state, 'running');
});

test('稼働中の使用量を月ごとに計上し、並行計測とワーカー再開でも重複して加算しない', async t => {
  const { f, c, runner, owner, create } = await setup(t), { row } = await create({ size: 'medium' });
  const boundary = new Date();
  boundary.setUTCDate(1); boundary.setUTCHours(0, 0, 0, 0);
  const started = new Date(boundary.getTime() - 120000);
  await f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb($2::text)) WHERE id=$1", [row.id, started.toISOString()]);
  await Promise.all([c.billing.measureCompute(), c.billing.measureCompute()]);
  const previous = await f.db.one<{ seconds: string }>(
    "SELECT sum(amount) AS seconds FROM billing_events WHERE principal_id=$1 AND meter='compute' AND created_at<$2", [owner.actor.id, boundary]);
  assert.equal(Number(previous!.seconds), 240);
  const usage = await c.billing.usage(owner.actor.id);
  const expected = Math.floor((Date.now() - boundary.getTime()) / 1000) * 2;
  assert.ok(Math.abs(usage.computeSeconds - expected) <= 2, `${usage.computeSeconds} / ${expected}`);
  const restarted = await createContext(f.config, { db: f.db, runner });
  const before = await f.db.one<{ amount: string }>('SELECT sum(amount) AS amount FROM billing_events WHERE principal_id=$1', [owner.actor.id]);
  await restarted.billing.measureCompute();
  const after = await f.db.one<{ amount: string }>('SELECT sum(amount) AS amount FROM billing_events WHERE principal_id=$1', [owner.actor.id]);
  assert.equal(after!.amount, before!.amount);
});

test('停止中の時間を使用量に含めず、次の起動から計測を再開する', async t => {
  const { f, c, owner, create } = await setup(t), { row, actor, registration } = await create();
  await f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb((date_trunc('second',now())-interval '2 minutes')::text)) WHERE id=$1", [row.id]);
  await c.environments.stop(owner.actor, await c.resources.get(row.id));
  await c.environments.tick();
  const stoppedUsage = (await c.billing.usage(owner.actor.id)).computeSeconds;
  await f.db.pool.query("UPDATE environment_jobs SET metered_at=now()-interval '1 day' WHERE resource_id=$1", [row.id]);
  assert.equal((await c.billing.usage(owner.actor.id)).computeSeconds, stoppedUsage);
  await c.environments.start(owner.actor, await c.resources.get(row.id));
  await c.environments.tick();
  await c.delegation.register(actor, registration);
  const resumedUsage = (await c.billing.usage(owner.actor.id)).computeSeconds;
  assert.ok(resumedUsage >= stoppedUsage && resumedUsage < stoppedUsage + 5, String(resumedUsage));
});

test('複数の起動処理が待機中でも利用枠に達した稼働中の環境を停止する', async t => {
  const { f, c, runner, owner, create } = await setup(t), { row } = await create();
  await c.billing.limits(owner.actor, owner.actor.id, 1073741824, 100);
  await c.environments.create(owner.actor, owner.actor.id, EnvironmentInput.parse({}));
  await c.environments.create(owner.actor, owner.actor.id, EnvironmentInput.parse({}));
  let release!: () => void, entered!: () => void, starts = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const ready = new Promise<void>(resolve => { entered = resolve; });
  const start = runner.start.bind(runner);
  t.mock.method(runner, 'start', async (...args: Parameters<typeof start>) => {
    if (++starts === 2) entered();
    await gate;
    return start(...args);
  });
  const provisioning = Promise.all([c.environments.tick(), c.environments.tick()]);
  try {
    await ready;
    await f.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{startedAt}',to_jsonb((date_trunc('second',now())-interval '2 minutes')::text)) WHERE id=$1", [row.id]);
    await c.environments.tick(true);
    assert.equal((await c.resources.get(row.id)).data.state, 'stopped');
    assert.equal(runner.machines.get(row.id)!.state, 'stopped');
  } finally { release(); await provisioning; }
});
