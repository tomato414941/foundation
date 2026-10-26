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

test('TailscaleのAPIアクセストークンを暗号化して保存し、tailnetのAPIを呼び出す', async t => {
  const f = await flowFixture(() => jsonResponse({ devices: [] }));
  t.after(f.close);
  const token = 'tskey-api-private-test-token';
  const service = (await f.context.catalog.list(f.owner.actor)).find(item => item.id === 'tailscale')!;
  assert.equal(service.name, 'Tailscale');
  assert.equal(service.methods['api-access-token']!.availability, 'ready');
  const connection = await f.saveConnection({ methodId: service.methods['api-access-token']!.id, fields: { token } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, [{ id: 'tailscale', name: 'Tailscale' }]);
  const stored = await f.client.read(connection.id);
  assert.equal(JSON.stringify({ connection, content: stored.content }).includes(token), false);
  for (const url of [
    'https://api.tailscale.com/api/v2/tailnet/-/devices',
    'https://api.tailscale.com/api/v2/tailnet/-/acl',
  ]) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'succeeded', JSON.stringify(result));
    assert.deepEqual(result?.result, { status: 200, headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ devices: [] }) });
    assert.equal(f.requests.at(-1)?.url, url);
    assert.equal(f.requests.at(-1)?.method, 'GET');
    assert.equal(f.requests.at(-1)?.headers?.Authorization, 'Bearer ' + token);
  }
});

test('TailscaleのAPIアクセストークン以外の鍵を受け付けない', async t => {
  const f = await flowFixture();
  t.after(f.close);
  for (const token of ['tskey-auth-private-test-key', 'tskey-client-private-test-secret']) {
    await assert.rejects(f.saveConnection({ methodId: 'tailscale:api-access-token', fields: { token } }));
  }
});

test('Tailscaleの認証情報の送信先をTailscale APIのホストに限定する', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'tailscale:api-access-token',
    fields: { token: 'tskey-api-private-test-token' } });
  for (const url of ['https://other.example/api/v2/tailnet/-/devices', 'https://api.tailscale.com.other.example/api/v2/tailnet/-/devices']) {
    const { task, result } = await send(f, connection.id, url);
    assert.equal(task.state, 'failed');
    assert.equal(result?.error?.code, 'invalid_destination');
  }
  assert.equal(f.requests.length, 0);
});

test('Tailscaleの同じ接続を再接続し、更新したトークンをHTTP処理とコマンドで使う', async t => {
  const f = await flowFixture();
  t.after(f.close);
  const first = await f.saveConnection({ methodId: 'tailscale:api-access-token',
    fields: { token: 'tskey-api-first-test-token' } });
  const updated = await f.saveConnection({ methodId: 'tailscale:api-access-token', connectionId: first.id,
    fields: { token: 'tskey-api-updated-test-token' } });
  assert.equal(updated.id, first.id);
  assert.equal((await send(f, updated.id, 'https://api.tailscale.com/api/v2/tailnet/-/devices')).result?.ok, true);
  assert.equal(f.requests.at(-1)?.headers?.Authorization, 'Bearer tskey-api-updated-test-token');
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, {
    kind: 'command', command: [process.execPath, '-e',
      'const assert=require("node:assert/strict");assert.equal(process.env.TAILSCALE_API_KEY,"tskey-api-updated-test-token");' +
      'assert.equal(process.env.TAILSCALE_BASE_URL,"https://api.tailscale.com");console.log("Tailscale credentials delivered");'],
    inputs: ['TAILSCALE_API_KEY', 'TAILSCALE_BASE_URL'].map(name => ({ name, source: { id: updated.id, output: name } })),
    timeoutSeconds: 10,
  });
  await f.executor.tick();
  const result = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.equal(result?.ok, true);
  assert.match(JSON.stringify(result), /Tailscale credentials delivered/);
});
