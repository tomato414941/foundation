import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { EnvironmentResource, Resource, listOf } from '../shared/contracts.js';

test('一覧と詳細と共有一覧で通信断と再接続を示し、明示的な停止を反映する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const id = f.environment.manifest.id, owner = f.api(f.owner.token), executor = f.api(f.executorIdentity.token);
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'reader', objectId: id });
  const views = async (connected: boolean, state = 'running') => {
    const detail = await owner.json('/api/resources/' + id, {}, EnvironmentResource);
    const owned = await owner.json('/api/principals/' + f.owner.actor.id + '/resources?kind=environment', {}, listOf(Resource));
    const shared = await f.api(f.stranger.token).json('/api/resources/shared', {}, listOf(Resource));
    for (const item of [detail, ...owned.items, ...shared.items]) {
      assert.equal(item.id, id);
      assert.equal(item.kind, 'environment');
      if (item.kind !== 'environment') throw new Error('Expected an execution environment.');
      assert.equal(item.data.connected, connected);
      assert.equal(item.data.state, state);
    }
    assert.equal(owned.items.length, 1);
    assert.equal(shared.items.length, 1);
  };
  await views(true);
  await f.db.pool.query("UPDATE executor_environments SET heartbeat_at=now()-interval '2 minutes' WHERE resource_id=$1", [id]);
  await views(false);
  await executor.json('/api/environments/' + id + '/claim', { method: 'POST', body: {} });
  await views(true);
  await owner.json('/api/resources/' + id + '/stop', { method: 'POST', body: {} });
  await views(false, 'stopped');
});

test('長い処理の実行権の更新を生存確認に反映する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const id = f.environment.manifest.id, executor = f.api(f.executorIdentity.token);
  await f.context.delegation.submit(f.owner.actor, f.request);
  const claim = (await f.context.delegation.claim(f.executorIdentity.actor, id))!;
  await f.context.delegation.dispatch(f.executorIdentity.actor, f.intent.id, claim.lease);
  await f.db.pool.query("UPDATE executor_environments SET heartbeat_at=now()-interval '2 minutes' WHERE resource_id=$1", [id]);
  const renewed = await executor.json('/api/runtime/runs/' + f.intent.id + '/renew', {
    method: 'POST', body: { lease: claim.lease },
  });
  assert.deepEqual(renewed, { active: true });
  const resource = await f.api(f.owner.token).json('/api/resources/' + id, {}, EnvironmentResource);
  assert.equal(resource.data.connected, true);
  assert.equal((await f.context.delegation.get(f.owner.actor, f.intent.id)).state, 'running');
});

test('応答が戻った実行環境でコマンドを受け付ける', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const id = f.environment.manifest.id, owner = f.api(f.owner.token), executor = f.api(f.executorIdentity.token);
  await executor.json('/api/environments/' + id + '/processes/registration', {
    method: 'PUT', body: { workingDirectory: f.config.dataDirectory },
  });
  const command = () => owner.json('/api/environments/' + id + '/processes', {
    method: 'POST', body: { command: ['node', '-e', 'console.log("ok")'] },
  });
  await f.db.pool.query("UPDATE executor_environments SET heartbeat_at=now()-interval '2 minutes' WHERE resource_id=$1", [id]);
  await assert.rejects(command, { code: 'environment_unavailable' });
  await executor.json('/api/environments/' + id + '/heartbeat', { method: 'POST', body: {} });
  assert.equal((await command() as { state: string }).state, 'queued');
});
