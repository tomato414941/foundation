import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { HttpRequest } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
async function inspect(f: Fixture, connectionId: string, url = 'https://api.cloudrift.ai/api/v1/auth/me') {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: HttpRequest.parse({ connectionId, url, method: 'POST' }), save: {},
  });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  return { task: completed, result: await f.client.result(completed) };
}

test('CloudRiftのAPIキーを暗号化して保存し、同じ接続を更新して管理APIを使用する', async t => {
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://api.cloudrift.ai/api/v1/auth/me');
    assert.equal(request.method, 'POST');
    return jsonResponse({ user: { id: 'test-user' } });
  }); t.after(f.close);
  const key = 'cloudrift_initial_test_key';
  const original = await f.saveConnection({ methodId: 'cloudrift:api_key', name: 'CloudRift compute', fields: { token: key } });
  if (original.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(original.data.services, [{ id: 'cloudrift', name: 'CloudRift' }]);
  const encrypted = await f.client.read(original.id);
  assert.equal(JSON.stringify({ original, content: encrypted.content }).includes(key), false);
  const used = await inspect(f, original.id);
  assert.equal(used.task.state, 'succeeded', JSON.stringify(used.result));
  const updated = await f.saveConnection({ methodId: 'cloudrift:api_key', connectionId: original.id,
    name: original.name, fields: { token: 'cloudrift_updated_test_key' } });
  assert.equal(updated.id, original.id);
  assert.equal(updated.name, original.name);
  const reused = await inspect(f, updated.id);
  assert.equal(reused.task.state, 'succeeded', JSON.stringify(reused.result));
  assert.deepEqual(f.requests.map(request => request.headers?.Authorization),
    ['Bearer cloudrift_initial_test_key', 'Bearer cloudrift_updated_test_key']);
});

test('CloudRiftのHTTP接続でAPIキーの送信先を管理APIのホストに限定する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'cloudrift:api_key', fields: { token: 'cloudrift_private_test_key' } });
  for (const url of ['https://other.example/api/v1/auth/me', 'https://api.cloudrift.ai.other.example/api/v1/auth/me']) {
    const { task, result } = await inspect(f, connection.id, url);
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
  }
  assert.equal(f.requests.length, 0);
});
