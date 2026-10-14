import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { HttpRequest, FunctionDefinition } from '../shared/contracts.js';
import type { HttpRequestInput } from '../shared/contracts.js';
import { Task, signEnvironment } from '../shared/runtime-protocol.js';
import { CustodyClient } from '../shared/client.js';
import { FunctionClient } from '../shared/function-client.js';
import { JournalTrust } from '../runtime/trust.js';
import { Operations } from '../shared/custody.js';

type Fixture = Awaited<ReturnType<typeof flowFixture>>;
const endpoint = 'https://receiver.example/webhook/private-url-token';
async function run(f: Fixture, request: Partial<HttpRequestInput>) {
  const started = await f.operations.execute({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
    environmentId: f.environment.manifest.id, operation: { kind: 'http', request: HttpRequest.parse(request) } } });
  assert.ok('kind' in started && started.kind === 'run');
  await f.executor.tick();
  const task = await f.client.api.json('/api/runtime/runs/' + started.task.id, {}, Task);
  return { task, result: await f.client.result(task) };
}

for (const scenario of [
  { method: 'http:bearer', fields: { token: 'private-bearer-token' }, authorization: 'Bearer private-bearer-token' },
  { method: 'http:basic', fields: { username: 'example-user', password: 'private-password' },
    authorization: 'Basic ' + Buffer.from('example-user:private-password').toString('base64') },
  { method: 'http:header', fields: { headerName: 'X-Custom-Key', key: 'private-header-key' }, header: 'private-header-key' },
  { method: 'http:query', fields: { parameterName: 'credential', key: 'private-query-key' }, query: 'private-query-key' },
  { method: 'http:url', fields: {} },
]) test(scenario.method + 'をサービスに関連付けず保存し、接続のURLと認証を使ってHTTP送信する', async t => {
  const f = await flowFixture(() => jsonResponse({ accepted: true })); t.after(f.close);
  const connection = await f.saveConnection({ name: 'My endpoint', methodId: scenario.method,
    fields: { url: endpoint, ...scenario.fields } });
  assert.equal(connection.kind, 'connection');
  if (connection.kind !== 'connection') return;
  assert.deepEqual(connection.data.services, []);
  assert.equal(connection.name, 'My endpoint');
  const stored = await f.client.read(connection.id);
  for (const value of [endpoint, ...Object.entries(scenario.fields).filter(([name]) => !['headerName', 'parameterName'].includes(name)).map(([, value]) => value)]) {
    assert.equal(JSON.stringify(connection).includes(value), false);
    assert.equal(JSON.stringify(stored.content).includes(value), false);
  }
  const { task, result } = await run(f, { connectionId: connection.id, method: 'POST', json: { message: 'Run this task' } });
  assert.equal(task.state, 'succeeded', JSON.stringify(result));
  assert.equal(result?.ok, true);
  assert.deepEqual(JSON.parse(f.requests[0]!.body as string), { message: 'Run this task' });
  const request = f.requests[0]!;
  if ('authorization' in scenario) assert.equal(request.headers?.Authorization, scenario.authorization);
  if ('header' in scenario) assert.equal(request.headers?.['X-Custom-Key'], scenario.header);
  if ('query' in scenario) assert.equal(new URL(request.url).searchParams.get('credential'), scenario.query);
  else assert.equal(request.url, endpoint);
});

test('別の端末から同じ接続を選び、認証値を手入力せずHTTP送信する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'device-shared-token' } });
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding);
  const client = new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, trust);
  const task = await client.submit(f.owner.actor.id, f.environment.manifest.id,
    { kind: 'http', request: HttpRequest.parse({ connectionId: connection.id }), save: {} });
  await f.executor.tick();
  assert.equal((await client.result(await client.api.json('/api/runtime/runs/' + task.id, {}, Task)))?.ok, true);
  assert.equal(f.requests[0]?.headers?.Authorization, 'Bearer device-shared-token');
});

test('関数の実行権限だけを持つ利用者がHTTP接続を使った処理の結果を受け取る', async t => {
  const f = await flowFixture(() => jsonResponse({ accepted: true })); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'function-private-token' } });
  const definition = FunctionDefinition.parse({ environmentId: f.environment.manifest.id,
    program: { kind: 'http', request: { connectionId: connection.id, method: 'POST', json: { message: '{{message}}', enabled: '{{enabled}}' } } },
    parameters: [{ name: 'message', label: 'Message' }, { name: 'enabled', label: 'Enabled', type: 'boolean' }] });
  const fn = await f.functions.save({ ownerId: f.owner.actor.id, name: 'Send message', definition });
  await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'runner', objectId: fn.id });
  const functions = new FunctionClient(f.api(f.stranger.token));
  const invocation = await functions.invoke(fn.id, { message: 'Hello', enabled: false });
  await f.functionExecutor.tick();
  const result = await functions.result(invocation.id);
  assert.equal(result.state, 'succeeded', JSON.stringify(result));
  assert.deepEqual(result.results[0], { status: 200, headers: { 'content-type': 'application/json' }, body: { accepted: true } });
  assert.deepEqual(JSON.parse(f.requests[0]!.body as string), { message: 'Hello', enabled: false });
  const denied = await f.app.inject({ method: 'GET', url: '/api/custody/' + connection.id,
    headers: { authorization: 'Bearer ' + f.stranger.token } });
  assert.equal(denied.statusCode, 403);
});

test('接続の送信先と同じホストでパスを変えてHTTP送信する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'scoped-token' } });
  const { result } = await run(f, { connectionId: connection.id, url: 'https://receiver.example/other/path' });
  assert.equal(result?.ok, true);
  assert.equal(f.requests[0]?.url, 'https://receiver.example/other/path');
});

test('接続の認証を別のホストへ送ろうとすると送信前に拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'scoped-token' } });
  const { task, result } = await run(f, { connectionId: connection.id, url: 'https://other.example/receive' });
  assert.equal(task.state, 'failed');
  assert.equal(result?.error?.code, 'invalid_destination');
  assert.equal(f.requests.length, 0);
});

test('保存したURLを復号してから、許可された送信先に一致することを確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'restricted-token' } });
  const previous = await f.client.read(connection.id);
  const grant = { actor: f.owner.binding, executor: f.executor.binding, operations: [Operations.http],
    origins: ['https://receiver.example'], functionDigests: [], callerProgram: true, expiresAt: new Date(Date.now() + 86_400_000).toISOString() };
  const policy = { ...previous.content.policy, revision: previous.content.policy.revision + 1, grants: [grant] };
  await f.client.save(connection.name, await f.client.reveal(connection.id), policy,
    { previous, metadata: previous.content.metadata });
  assert.equal((await run(f, { connectionId: connection.id })).result?.ok, true);
  const current = await f.client.read(connection.id);
  await f.client.save(connection.name, await f.client.reveal(connection.id),
    { ...current.content.policy, revision: current.content.policy.revision + 1, grants: [{ ...grant, origins: ['https://other.example'] }] },
    { previous: current, metadata: current.content.metadata });
  const { task } = await run(f, { connectionId: connection.id });
  assert.equal(task.state, 'failed');
  assert.equal(f.requests.length, 1);
});

test('プライベートアドレスへのHTTP接続を送信前に拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: 'https://127.0.0.1/private', token: 'private-target-token' } });
  const { task, result } = await run(f, { connectionId: connection.id });
  assert.equal(task.state, 'failed');
  assert.equal(result?.error?.code, 'private_destination');
  assert.equal(f.requests.length, 0);
});

test('認証ヘッダーの二重指定を確定した入力エラーとして返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'conflicting-token' } });
  const { task, result } = await run(f, { connectionId: connection.id, headers: { authorization: 'manual-token' } });
  assert.equal(task.state, 'failed');
  assert.equal(result?.error?.code, 'invalid_authentication');
  assert.equal(f.requests.length, 0);
});

test('通常のHTTP実行結果に返された認証値と秘密URLをマスクする', async t => {
  const f = await flowFixture(request => jsonResponse({ url: request.url, authorization: request.headers?.Authorization })); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:basic', fields: { url: endpoint, username: 'private-user', password: 'private-password' } });
  const { result } = await run(f, { connectionId: connection.id });
  assert.equal(result?.ok, true);
  assert.ok(JSON.stringify(result).includes('[redacted]'));
  for (const value of [endpoint, 'private-user', 'private-password', Buffer.from('private-user:private-password').toString('base64')])
    assert.equal(JSON.stringify(result).includes(value), false);
});

test('HTTP接続を扱える実行環境を選ぶよう、送信の受付前に案内する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connection = await f.saveConnection({ methodId: 'http:bearer', fields: { url: endpoint, token: 'new-runtime-token' } });
  const { httpVersion: _version, ...manifest } = f.environment.manifest;
  const registration = await signEnvironment({ ...manifest, revision: manifest.revision + 1 }, f.executor.keys);
  await f.context.delegation.register(f.executorIdentity.actor, registration);
  await assert.rejects(run(f, { connectionId: connection.id }), /Update this execution environment/);
});
