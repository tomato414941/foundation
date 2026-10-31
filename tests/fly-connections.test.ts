import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { HttpRequest } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
async function send(f: Fixture, connectionId: string, url: string) {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: HttpRequest.parse({ connectionId, url, method: 'GET' }), save: {},
  });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  return { task: completed, result: await f.client.result(completed) };
}

test('Flyのトークンを暗号化して保存し、選んだ接続だけを更新してMachines APIを使用する', async t => {
  const f = await flowFixture(() => jsonResponse({ apps: [] })); t.after(f.close);
  const tokens = ['FlyV1 fm2_first_token,fm2_discharge', 'FlyV1 fm2_second_token'];
  const connections = [];
  for (const token of tokens) {
    const saved = await f.saveConnection({ methodId: 'fly:token', name: 'Fly.io', fields: { token } });
    if (saved.kind !== 'connection') throw new Error('Expected a saved connection.');
    assert.deepEqual(saved.data.services, [{ id: 'fly', name: 'Fly.io' }]);
    const encrypted = await f.client.read(saved.id);
    assert.equal(JSON.stringify({ saved, content: encrypted.content }).includes(token), false);
    connections.push(saved);
  }
  assert.notEqual(connections[0]!.id, connections[1]!.id);
  const updated = await f.saveConnection({ methodId: 'fly:token', connectionId: connections[0]!.id,
    name: connections[0]!.name, fields: { token: 'FlyV1 fm2_updated_token' } });
  assert.equal(updated.id, connections[0]!.id);
  for (const connection of connections) {
    const { task, result } = await send(f, connection.id, 'https://api.machines.dev/v1/apps');
    assert.equal(task.state, 'succeeded', JSON.stringify(result));
  }
  assert.deepEqual(f.requests.map(request => request.headers?.Authorization),
    ['Bearer FlyV1 fm2_updated_token', 'Bearer FlyV1 fm2_second_token']);
});

test('FlyのHTTP接続でトークンの送信先をMachines APIのホストに限定する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'fly:token', fields: { token: 'FlyV1 fm2_private_token' } });
  for (const url of ['https://other.example/v1/apps', 'https://api.machines.dev.other.example/v1/apps']) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
  }
  assert.equal(f.requests.length, 0);
});
