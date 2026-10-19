import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { FunctionDefinition } from '../shared/contracts.js';
import { FunctionClient } from '../shared/function-client.js';
import { FunctionConfigure } from '../shared/executions.js';
import { hash } from '../shared/authority.js';
import { Operations, authorizeUse } from '../shared/custody.js';
import { signEnvironment } from '../shared/runtime-protocol.js';
import { FunctionBroker, FunctionExecutor } from '../runtime/functions.js';
import { Executor } from '../runtime/executor.js';
import { HttpBroker } from '../runtime/broker.js';
import { CommandProcess } from '../runtime/command.js';
import { Connections } from '../runtime/connections.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
const program = (sourceId?: string) => FunctionDefinition.parse({
  program: { kind: 'command', command: ['node', '-e', 'console.log(JSON.stringify({configured:!!process.env.TOKEN}))'],
    inputs: sourceId ? [{ name: 'TOKEN', source: { id: sourceId } }] : [] }, result: 'json',
});
async function save(f: Fixture, sourceId?: string) {
  return f.functions.save({ ownerId: f.owner.actor.id, name: 'Independent function', definition: program(sourceId) });
}
async function removeEnvironment(f: Fixture) {
  await f.context.environments.remove(f.owner.actor, await f.resources.get(f.environment.manifest.id));
  await f.context.environments.tick();
  assert.equal((await f.context.environments.deletion(f.owner.actor, f.environment.manifest.id)).state, 'complete');
}
async function anotherEnvironment(f: Fixture) {
  const identity = await f.personWithKeys('Replacement executor');
  await f.relations.draw(f.owner.actor, { subjectId: identity.actor.id, relation: 'delegate', objectId: f.owner.actor.id });
  const environment = await signEnvironment({ ...f.environment.manifest, id: crypto.randomUUID(), name: 'Replacement environment',
    executor: identity.binding, operatorId: identity.actor.id }, identity.keys);
  await f.context.delegation.register(identity.actor, environment);
  await f.client.trust.rememberBinding(identity.binding);
  const broker = new HttpBroker(f.api(identity.token)), journal = new MemoryJournal();
  const extension = new Connections(identity.binding, identity.keys, broker.connections(), journal, f.transport);
  const executor = new Executor(environment, identity.keys, broker, journal, f.transport,
    new CommandProcess({ isolation: 'process' }), extension);
  return { environment, executor: new FunctionExecutor(executor, new FunctionBroker(f.api(identity.token)), journal) };
}

test('計算資源がなくても関数を作成・更新・共有し、実行先を後から設定する', async t => {
  const f = await flowFixture(); t.after(f.close);
  await removeEnvironment(f);
  const fn = await save(f);
  assert.deepEqual((await f.functions.get(fn.id)).data, program());
  assert.equal((await f.functions.settings(fn.id)).state, 'unconfigured');
  const updated = await f.functions.save({ ownerId: fn.ownerId, name: 'Saved without compute', definition: program(),
    resourceId: fn.id, version: fn.version });
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const caller = new FunctionClient(f.api(f.stranger.token));
  assert.equal((await caller.get(fn.id)).name, updated.name);
  await assert.rejects(caller.invoke(fn.id), { code: 'function_not_configured' });
  const replacement = await anotherEnvironment(f);
  await f.functions.configure(fn.id, { environmentId: replacement.environment.manifest.id });
  const call = await caller.invoke(fn.id); await replacement.executor.tick();
  assert.deepEqual((await caller.result(call.id)).results[0], { configured: false });
  assert.equal((await f.functions.get(fn.id)).version, updated.version);
});

test('環境の停止後も関数を編集し、環境を削除しても定義と共有を保持して別環境で実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, f.resource.id);
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  await f.context.delegation.stop(f.owner.actor, f.environment.manifest.id);
  assert.equal((await f.functions.settings(fn.id)).state, 'unavailable');
  const definition = { ...program(f.resource.id), description: 'Still available after environment removal' };
  const updated = await f.functions.save({ ownerId: fn.ownerId, name: fn.name, definition, resourceId: fn.id, version: fn.version });
  await removeEnvironment(f);
  assert.deepEqual(await f.functions.get(fn.id), updated);
  assert.equal((await f.functions.settings(fn.id)).state, 'unconfigured');
  const replacement = await anotherEnvironment(f);
  await f.functions.configure(fn.id, { environmentId: replacement.environment.manifest.id });
  const caller = new FunctionClient(f.api(f.stranger.token)), call = await caller.invoke(fn.id);
  await replacement.executor.tick();
  assert.equal((await caller.result(call.id)).state, 'succeeded');
  assert.deepEqual((await caller.result(call.id)).results[0], { configured: true });
  assert.equal((await f.functions.get(fn.id)).version, updated.version);
});

test('実行先の変更を承認し、以前の待機中の呼び出しを止めて新しい実行先だけへ入力を許可する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, f.resource.id);
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  const queued = await f.functions.invoke(fn.id), replacement = await anotherEnvironment(f);
  const settings = await f.functions.configure(fn.id, { environmentId: replacement.environment.manifest.id });
  assert.equal(settings.version, 2);
  assert.deepEqual(await f.functions.get(fn.id), fn);
  assert.equal(await f.functionExecutor.tick(), false);
  assert.equal((await f.functions.result(queued.id)).state, 'failed');
  const content = (await f.client.read(f.resource.id)).content;
  await assert.rejects(authorizeUse(content, { ...f.intent, operation: Operations.function, functionId: fn.id,
    functionDigest: await hash(program(f.resource.id)), sources: [{ id: content.policy.id,
      policyDigest: await hash(content.policy), materialRevision: content.materialRevision }] }));
  const call = await f.functions.invoke(fn.id); await replacement.executor.tick();
  assert.deepEqual((await f.functions.result(call.id)).results[0], { configured: true });
});

test('実行設定を解除して入力の利用許可を撤回し、関数を再設定して同じ定義を実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, f.resource.id);
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  const settings = await f.functions.configure(fn.id, { environmentId: null });
  assert.equal(settings.state, 'unconfigured');
  assert.equal(settings.version, 2);
  await assert.rejects(f.functions.invoke(fn.id), { code: 'function_not_configured' });
  await assert.rejects(authorizeUse((await f.client.read(f.resource.id)).content, { ...f.intent,
    operation: Operations.function, functionId: fn.id, functionDigest: await hash(program(f.resource.id)) }));
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  assert.deepEqual(await f.functions.get(fn.id), fn);
  const call = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
  assert.equal((await f.functions.result(call.id)).state, 'succeeded');
});

test('実行設定の競合を検出して承認済みの設定を保持し、呼び出す権限と設定する権限を分ける', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, f.resource.id);
  const input = FunctionConfigure.parse({ functionId: fn.id, functionVersion: fn.version, version: 0,
    environmentId: f.environment.manifest.id });
  const authorization = await f.functions.prepareSettings(input);
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  const { functionId, ...body } = input;
  await assert.rejects(f.client.api.json('/api/functions/' + functionId + '/execution-settings', {
    method: 'PUT', body: { ...body, authorization } }), { code: 'changed' });
  assert.equal((await f.functions.settings(fn.id)).version, 1);
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  await assert.rejects(f.api(f.stranger.token).json('/api/functions/' + fn.id + '/execution-settings'), { code: 'forbidden' });
  const caller = new FunctionClient(f.api(f.stranger.token)), call = await caller.invoke(fn.id);
  await f.functionExecutor.tick();
  assert.deepEqual((await caller.result(call.id)).results[0], { configured: true });
});

test('関数の名前を変更しても承認済みの処理と実行設定を使って呼び出す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, f.resource.id);
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  await f.resources.rename(f.owner.actor, await f.resources.get(fn.id), 'Renamed function');
  assert.equal((await f.functions.get(fn.id)).name, 'Renamed function');
  const call = await f.functions.invoke(fn.id); await f.functionExecutor.tick();
  assert.deepEqual((await f.functions.result(call.id)).results[0], { configured: true });
});

test('承認された実行設定の署名を確認し、改ざんされた設定を実行前に拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const fn = await save(f, f.resource.id);
  await f.functions.configure(fn.id, { environmentId: f.environment.manifest.id });
  const call = await f.functions.invoke(fn.id), broker = new FunctionBroker(f.api(f.executorIdentity.token));
  const claim = broker.claim.bind(broker);
  broker.claim = async id => {
    const value = await claim(id);
    if (value) value.settings.inputAccess.expiresAt = new Date(Date.now() + 100_000).toISOString();
    return value;
  };
  await new FunctionExecutor(f.functionExecutor.executor, broker, f.journal).tick();
  const result = await f.functions.result(call.id);
  assert.equal(result.state, 'failed');
  assert.equal(result.error?.code, 'invalid_function');
});

test('保存済みの処理と共有を保持して独立した定義へ移行し、再承認後に実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const row = await f.resources.insert(f.owner.actor.id, 'function', 'Existing function', {
    ...program(), environmentId: f.environment.manifest.id, inputAccess: { expiresAt: null },
    publication: { format: 1 },
  }, { references: [f.environment.manifest.id] });
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: row.id });
  await f.db.pool.query("DELETE FROM schema_migrations WHERE name='001-foundation-schema'");
  await f.db.migrate();
  const current = await f.functions.get(row.id);
  assert.deepEqual(current.data, program());
  assert.equal((await new FunctionClient(f.api(f.stranger.token)).get(row.id)).name, row.name);
  await f.functions.save({ ownerId: current.ownerId, name: current.name, definition: program(), resourceId: row.id, version: current.version });
  await f.functions.configure(row.id, { environmentId: f.environment.manifest.id });
  const call = await f.functions.invoke(row.id); await f.functionExecutor.tick();
  assert.equal((await f.functions.result(call.id)).state, 'succeeded');
  await removeEnvironment(f);
  assert.deepEqual((await f.functions.get(row.id)).data, program());
});
