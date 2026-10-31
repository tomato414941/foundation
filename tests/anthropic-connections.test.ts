import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { HttpRequest } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;

async function send(f: Fixture, connectionId: string, url: string) {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: HttpRequest.parse({ connectionId, url, method: 'GET',
      headers: { 'anthropic-version': '2023-06-01' } }), save: {},
  });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  return { task: completed, result: await f.client.result(completed) };
}

test('Anthropicの通常キーとAdminキーを暗号化して保存し、選んだ接続でAPIを呼び出す', async t => {
  const f = await flowFixture(() => jsonResponse({ data: [] })); t.after(f.close);
  for (const [method, field, paths] of [
    ['api_key', 'token', ['/models']],
    ['admin_key', 'adminKey', ['/organizations/usage_report/messages', '/organizations/cost_report']],
  ] as const) {
    const key = 'private-anthropic-' + method;
    const saved = await f.saveConnection({ methodId: 'anthropic:' + method, fields: { [field]: key } });
    assert.equal(saved.kind, 'connection');
    if (saved.kind !== 'connection') throw new Error('Expected a saved connection.');
    assert.deepEqual(saved.data.services, [{ id: 'anthropic', name: 'Anthropic' }]);
    const encrypted = await f.client.read(saved.id);
    assert.equal(JSON.stringify({ saved, content: encrypted.content }).includes(key), false);
    for (const path of paths) {
      const { task, result } = await send(f, saved.id, 'https://api.anthropic.com/v1' + path);
      assert.equal(task.state, 'succeeded', JSON.stringify(result));
      assert.equal(f.requests.at(-1)?.headers['x-api-key'], key);
      assert.equal(f.requests.at(-1)?.headers['anthropic-version'], '2023-06-01');
    }
  }
});

test('Anthropicのキーをコマンドに環境変数で渡し、更新した接続のキーを使用する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const inputs = [];
  for (const [method, field, output] of [
    ['api_key', 'token', 'ANTHROPIC_API_KEY'], ['admin_key', 'adminKey', 'ANTHROPIC_ADMIN_KEY'],
  ] as const) {
    const original = await f.saveConnection({ methodId: 'anthropic:' + method, fields: { [field]: 'old-key' } });
    const updated = await f.saveConnection({ methodId: 'anthropic:' + method, connectionId: original.id,
      fields: { [field]: 'updated-' + method } });
    assert.equal(updated.id, original.id);
    inputs.push({ name: output, source: { id: updated.id, output } });
  }
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'command', timeoutSeconds: 10, inputs, command: [process.execPath, '-e',
      'const assert=require("node:assert/strict");assert.equal(process.env.ANTHROPIC_API_KEY,"updated-api_key");' +
      'assert.equal(process.env.ANTHROPIC_ADMIN_KEY,"updated-admin_key");console.log("Anthropic credentials delivered");'],
  });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true, JSON.stringify(result));
  assert.match(JSON.stringify(result), /Anthropic credentials delivered/);
});

test('Anthropicの接続から送るキーの送信先をAnthropicのAPIホストに限定する', async t => {
  const f = await flowFixture(); t.after(f.close);
  for (const [method, field] of [['api_key', 'token'], ['admin_key', 'adminKey']] as const) {
    const connection = await f.saveConnection({ methodId: 'anthropic:' + method, fields: { [field]: 'private-key' } });
    for (const url of ['https://other.example/v1/messages', 'https://api.anthropic.com.other.example/v1/messages']) {
      const { task, result } = await send(f, connection.id, url);
      assert.equal(task.state, 'failed');
      assert.equal(result?.error?.code, 'invalid_destination');
    }
  }
  assert.equal(f.requests.length, 0);
});
