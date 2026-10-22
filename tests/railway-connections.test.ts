import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { HttpRequest } from '../shared/contracts.js';
import { Task } from '../shared/runtime-protocol.js';
import type { HttpRequestInput } from '../shared/contracts.js';

const endpoint = 'https://backboard.railway.com/graphql/v2';
const methods = [
  { id: 'railway:token', field: 'token', output: 'RAILWAY_API_TOKEN', header: 'Authorization', prefix: 'Bearer ' },
  { id: 'railway:project-token', field: 'projectToken', output: 'RAILWAY_TOKEN', header: 'Project-Access-Token', prefix: '' },
] as const;
type Fixture = Awaited<ReturnType<typeof flowFixture>>;

async function send(f: Fixture, connectionId: string, request: Partial<HttpRequestInput> = {}) {
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'http', request: HttpRequest.parse({ connectionId, method: 'POST',
      json: { query: '{ __typename }' }, ...request }), save: {},
  });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  return { task: completed, result: await f.client.result(completed) };
}

test('Railwayのトークンだけを暗号化して登録し、対応する認証でGraphQL APIを呼び出す', async t => {
  for (const method of methods) await t.test(method.id, async t => {
    const f = await flowFixture(() => jsonResponse({ data: { __typename: 'Query' } }));
    t.after(f.close);
    const token = 'private-railway-test-token';
    const connection = await f.saveConnection({ methodId: method.id, fields: { [method.field]: token } });
    assert.equal(connection.kind, 'connection');
    if (connection.kind !== 'connection') return;
    assert.deepEqual(connection.data.services, [{ id: 'railway', name: 'Railway' }]);
    const stored = await f.client.read(connection.id);
    assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
    const { task, result } = await send(f, connection.id);
    assert.equal(task.state, 'succeeded', JSON.stringify(result));
    assert.equal(result?.ok, true);
    assert.equal(f.requests[0]?.url, endpoint);
    assert.equal(f.requests[0]?.method, 'POST');
    assert.equal(f.requests[0]?.headers?.[method.header], method.prefix + token);
    assert.deepEqual(JSON.parse(f.requests[0]!.body as string), { query: '{ __typename }' });
  });
});

test('Railwayの認証情報を送信できるホストを固定する', async t => {
  for (const method of methods) await t.test(method.id, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const connection = await f.saveConnection({ methodId: method.id,
      fields: { [method.field]: 'private-railway-token' } });
    const { task, result } = await send(f, connection.id, { url: 'https://other.example/graphql/v2' });
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
    assert.equal(f.requests.length, 0);
  });
});

test('Railwayの同じ接続を再接続し、更新したトークンでAPIを呼び出す', async t => {
  for (const method of methods) await t.test(method.id, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const first = await f.saveConnection({ methodId: method.id, fields: { [method.field]: 'first-token' } });
    const updated = await f.saveConnection({ methodId: method.id, connectionId: first.id,
      fields: { [method.field]: 'updated-token' } });
    assert.equal(updated.id, first.id);
    assert.equal((await send(f, updated.id)).result?.ok, true);
    assert.equal(f.requests[0]?.headers?.[method.header], method.prefix + 'updated-token');
  });
});

test('Railway CLI用のトークンとAPIのURLを実行環境へ渡す', async t => {
  for (const method of methods) await t.test(method.id, async t => {
    const f = await flowFixture();
    t.after(f.close);
    const connection = await f.saveConnection({ methodId: method.id, fields: { [method.field]: 'cli-test-token' } });
    const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
      kind: 'command', command: [process.execPath, '-e',
        'const assert=require("node:assert/strict");assert.equal(process.env.' + method.output + ',"cli-test-token");' +
        'assert.equal(process.env.RAILWAY_API_URL,' + JSON.stringify(endpoint) + ');console.log("Railway credentials delivered");'],
      inputs: [method.output, 'RAILWAY_API_URL'].map(name => ({ name, source: { id: connection.id, output: name } })),
      timeoutSeconds: 10,
    });
    await f.executor.tick();
    const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
    assert.equal(result?.ok, true);
    assert.match(JSON.stringify(result), /Railway credentials delivered/);
  });
});
