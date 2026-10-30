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

test('Prime IntellectのAPIキーを暗号化して保存し、GPUの空きを読むAPIを呼び出す', async t => {
  const f = await flowFixture(() => jsonResponse({}));
  t.after(f.close);
  const token = 'private-prime-test-key';
  const connection = await f.saveConnection({ methodId: 'prime:token', fields: { token } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, [{ id: 'prime', name: 'Prime Intellect' }]);
  const stored = await f.client.read(connection.id);
  assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
  const url = 'https://api.primeintellect.ai/api/v1/availability/gpu-summary';
  const { task, result } = await send(f, connection.id, url);
  assert.equal(task.state, 'succeeded', JSON.stringify(result));
  assert.equal(f.requests.at(-1)?.url, url);
  assert.equal(f.requests.at(-1)?.headers?.Authorization, 'Bearer ' + token);
});

test('Prime IntellectのAPIキーの送信先をPrime IntellectのAPIのホストに限定する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'prime:token', fields: { token: 'private-prime-key' } });
  for (const url of ['https://other.example/api/v1/pods', 'https://api.primeintellect.ai.other.example/api/v1/pods']) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
  }
  assert.equal(f.requests.length, 0);
});

test('Prime IntellectのAPIキーとAPIの場所を、コマンドに環境変数で渡す', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'prime:token', fields: { token: 'private-prime-key' } });
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'command', timeoutSeconds: 10, command: [process.execPath, '-e',
      'const assert=require("node:assert/strict");assert.equal(process.env.PRIME_API_KEY,"private-prime-key");' +
      'assert.equal(process.env.PRIME_API_BASE_URL,"https://api.primeintellect.ai");console.log("Prime credentials delivered");'],
    inputs: ['PRIME_API_KEY', 'PRIME_API_BASE_URL'].map(name => ({ name, source: { id: connection.id, output: name } })),
  });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true, JSON.stringify(result));
  assert.match(JSON.stringify(result), /Prime credentials delivered/);
});
