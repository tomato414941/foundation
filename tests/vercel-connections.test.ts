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

test('Vercelのトークンを暗号化して保存し、アカウントとチームのAPIを呼び出す', async t => {
  const f = await flowFixture(() => jsonResponse({ projects: [], pagination: { next: null } }));
  t.after(f.close);
  const token = 'private-vercel-test-token';
  const service = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'vercel')!;
  assert.equal(service.name, 'Vercel');
  assert.equal(service.methods.token!.availability, 'ready');
  const connection = await f.saveConnection({ methodId: service.methods.token!.id, fields: { token } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, [{ id: 'vercel', name: 'Vercel' }]);
  const stored = await f.client.read(connection.id);
  assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
  for (const url of [
    'https://api.vercel.com/v10/projects?limit=20',
    'https://api.vercel.com/v6/deployments?teamId=team_example&limit=20',
  ]) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'succeeded', JSON.stringify(result));
    assert.deepEqual(result?.result, { status: 200, headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ projects: [], pagination: { next: null } }) });
    assert.equal(f.requests.at(-1)?.url, url);
    assert.equal(f.requests.at(-1)?.method, 'GET');
    assert.equal(f.requests.at(-1)?.headers?.Authorization, 'Bearer ' + token);
  }
});

test('Vercelの認証情報の送信先をVercel APIのホストに限定する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'vercel:token', fields: { token: 'private-vercel-token' } });
  for (const url of ['https://other.example/v10/projects', 'https://api.vercel.com.other.example/v10/projects']) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
  }
  assert.equal(f.requests.length, 0);
});

test('Vercelの同じ接続を再接続し、更新したトークンをHTTP処理とコマンドで使う', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const first = await f.saveConnection({ methodId: 'vercel:token', fields: { token: 'first-vercel-token' } });
  const updated = await f.saveConnection({ methodId: 'vercel:token', connectionId: first.id,
    fields: { token: 'updated-vercel-token' } });
  assert.equal(updated.id, first.id);
  assert.equal((await send(f, updated.id, 'https://api.vercel.com/v10/projects')).result?.ok, true);
  assert.equal(f.requests.at(-1)?.headers?.Authorization, 'Bearer updated-vercel-token');
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'command', command: [process.execPath, '-e',
      'const assert=require("node:assert/strict");assert.equal(process.env.VERCEL_TOKEN,"updated-vercel-token");' +
      'assert.equal(process.env.VERCEL_API_URL,"https://api.vercel.com");console.log("Vercel credentials delivered");'],
    inputs: ['VERCEL_TOKEN', 'VERCEL_API_URL'].map(name => ({ name, source: { id: updated.id, output: name } })),
    timeoutSeconds: 10,
  });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true);
  assert.match(JSON.stringify(result), /Vercel credentials delivered/);
});
