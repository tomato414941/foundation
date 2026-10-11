import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { flowFixture, jsonResponse } from './flow-support.js';
import { ApprovalRequest, Resource, listOf } from '../shared/contracts.js';
import { OperationDescription, OperationExecution } from '../shared/operations.js';
import { OperationClient } from '../shared/operation-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { Task } from '../shared/execution.js';
import { decode } from '../shared/encryption.js';
import { DomainError } from '../server/errors.js';
import type { JsonApi } from '../shared/client.js';
import { CustodyClient, SubmissionPending } from '../shared/client.js';

test('定義した操作を通常のAPIと承認依頼から同じ利用者の権限で実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  f.context.operations.define('message.format', z.object({ text: z.string() }).strict(), ['文章を確認する', 'Review text'],
    async (actor, input) => ({ text: input.text, actorId: actor.id }));
  const catalog = await f.client.api.json('/api/operations', {}, listOf(OperationDescription));
  assert.equal(catalog.items.find(item => item.name === 'message.format')?.title.ja, '文章を確認する');
  const direct = await f.client.api.json('/api/operations/message.format', { method: 'POST', body: { text: 'Hello' } });
  assert.deepEqual(direct, { text: 'Hello', actorId: f.owner.actor.id });
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'message.format', input: { text: 'Hello' } }] } }, ApprovalRequest);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(answer.state, 'approved'); assert.deepEqual(answer.results[0], direct);
});

test('通常の画面と依頼の変数保存が鍵を持つ利用者の暗号化処理を使い、入力後に同じ実行を続ける', async t => {
  const f = await flowFixture(); t.after(f.close);
  const operations = new OperationClient(f.client, f.connections), sender = f.api(f.stranger.token);
  const ordinary = await operations.execute({ name: 'variable.save', input: { ownerId: f.owner.actor.id,
    name: 'Ordinary', environmentIds: [] } }, { value: 'ordinary-secret' });
  assert.equal('kind' in ordinary && ordinary.kind, 'saved');
  if (!('kind' in ordinary) || ordinary.kind !== 'saved') throw new Error('Expected a variable.');
  assert.equal(decode(await f.client.reveal(ordinary.resource.id)), 'ordinary-secret');
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'principal.create', input: { ownerId: '$approver', name: 'Prepared group' } },
    { name: 'variable.save', input: { ownerId: '$approver', name: 'Requested value', value: '', environmentIds: [] },
      inputs: [{ pointer: '/value', label: 'Access token', secret: true }] },
    { name: 'principal.rename', input: { id: '$approver', name: 'Finished owner' } },
  ] } }, ApprovalRequest);
  const pending = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(pending.state, 'running'); assert.equal(pending.waiting?.index, 1);
  const first = (pending.results[0] as { id: string }).id;
  const result = await operations.continue(asked.id, { value: 'owner-only-secret' });
  assert.equal('kind' in result && result.kind, 'saved');
  if (!('kind' in result) || result.kind !== 'saved') throw new Error('Expected a saved value.');
  assert.equal(decode(await f.client.reveal(result.resource.id)), 'owner-only-secret');
  const completed = await sender.json('/api/requests/' + asked.id, {}, ApprovalRequest);
  assert.equal(completed.state, 'approved'); assert.equal((completed.results[0] as { id: string }).id, first);
  assert.equal((completed.results[2] as { name: string }).name, 'Finished owner');
  const execution = await f.client.api.json('/api/operation-executions/' + asked.id, {}, OperationExecution);
  assert.equal(execution.state, 'succeeded'); assert.equal(execution.id, asked.id);
  const row = await f.context.db.one<{ snapshot: string }>('SELECT snapshot FROM operation_executions WHERE id=$1', [asked.id]);
  assert.ok(row?.snapshot);
  const snapshot = await f.context.vault.decrypt(row.snapshot, 'operation-execution:' + asked.id);
  assert.equal(JSON.stringify(snapshot).includes('owner-only-secret'), false);
  const resource = await f.client.api.json('/api/resources/' + result.resource.id, {}, Resource);
  assert.deepEqual(resource.data, result.resource.data);
});

test('OVHのIDとSecretを接続時に暗号化して保存し、別のクライアントから依頼内の接続を再開する', async t => {
  const f = await flowFixture(request => request.url.includes('/oauth2/token')
    ? jsonResponse({ access_token: 'ovh-access-token', token_type: 'Bearer', expires_in: 3600 }) : jsonResponse({ ok: true }));
  t.after(f.close);
  const sender = f.api(f.stranger.token), connections = new ConnectionClient(f.client, new RemoteFlowStore(f.client));
  const operations = new OperationClient(f.client, connections);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'connection.connect', input: { ownerId: '$approver', methodId: 'ovh:client_credentials', name: 'OVH account' } },
  ] } }, ApprovalRequest);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {
    configuration: [{ environmentId: f.environment.manifest.id, clientId: 'ovh-service-account' }],
  } }, ApprovalRequest);
  assert.equal(answer.waiting?.invocation.input.clientId, 'ovh-service-account');
  const start = await operations.continue(asked.id, { clientSecret: 'ovh-service-secret' });
  if (!('flow' in start)) throw new Error('Expected a connection flow.');
  const saved = await f.client.api.json('/api/operation-executions/' + asked.id, {}, OperationExecution);
  assert.deepEqual(saved.waiting?.continuation, { kind: 'connection', id: start.flow.id });
  const fresh = new ConnectionClient(f.client, new RemoteFlowStore(f.client));
  await f.executor.tick();
  assert.equal((await fresh.progress(start.flow.id)).kind, 'review');
  await fresh.accept(start.flow.id); await f.executor.tick();
  const completed = await fresh.progress(start.flow.id);
  assert.equal(completed.kind, 'connected');
  assert.equal((await sender.json('/api/requests/' + asked.id, {}, ApprovalRequest)).state, 'approved');
  const tokenCall = f.requests.find(request => request.url.includes('/oauth2/token'))!;
  assert.ok(String(tokenCall.body).includes('client_secret=ovh-service-secret'));
  assert.ok(String(tokenCall.body).includes('client_id=ovh-service-account'));
  await assert.rejects(sender.json('/api/operation-continuations/' + start.flow.id), { code: 'forbidden' });
});

test('承認したHTTP操作と署名した実行を結び付け、実行先が復号後に差し替えを拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const operations = new OperationClient(f.client, f.connections), sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'run.execute', input: { ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id,
      operation: { kind: 'http', request: { url: 'https://api.example.com/reviewed', method: 'GET' } } } }] } }, ApprovalRequest);
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  const plan = await operations.plan(asked.id);
  const prepared = await f.client.prepare(f.owner.actor.id, f.environment.manifest.id, { kind: 'http', request: {
    url: 'https://api.example.com/changed', method: 'DELETE', headers: {}, bindings: [],
  }, save: {} }, { approval: plan.approval, operationContext: { id: asked.id, index: plan.index, invocation: plan.invocation } });
  await f.client.api.json('/api/operation-executions/' + asked.id + '/continuation', { method: 'PUT',
    body: { index: plan.index, continuation: { kind: 'run', id: prepared.intent.id } } });
  const task = await f.client.submitPrepared(prepared);
  await f.executor.tick();
  const failed = await f.client.api.json('/api/executions/' + task.id, {}, Task);
  assert.equal(failed.state, 'failed');
  const result = await f.client.result(failed);
  assert.equal(result?.ok, false); assert.deepEqual(result?.error && typeof result.error === 'object' && 'code' in result.error
    ? result.error.code : null, 'invalid_execution');
  assert.equal((await f.client.api.json('/api/operation-executions/' + asked.id, {}, OperationExecution)).state, 'failed');
});

test('HTTPの秘密情報を封をしたまま再開し、同じ実行先の処理と完了通知を一度だけ反映する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const operations = new OperationClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client)));
  const execution = await operations.start({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
    environmentId: f.environment.manifest.id, operation: { kind: 'http', request: {
      url: 'https://api.example.com/private', method: 'POST', headers: { authorization: 'Bearer private-http-token' }, body: 'private-http-body',
    } } } });
  assert.equal(execution.wait, 'input');
  assert.equal(JSON.stringify(execution).includes('private-http-token'), false);
  assert.equal(JSON.stringify(execution).includes('private-http-body'), false);
  const first = await operations.continue(execution.id);
  if (!('kind' in first) || first.kind !== 'run') throw new Error('Expected a run.');
  const plan = await operations.plan(execution.id);
  const extra = await f.client.prepare(f.owner.actor.id, f.environment.manifest.id, { kind: 'http', request: {
    url: 'https://api.example.com/private', method: 'POST', headers: {}, bindings: [],
  }, save: {} }, { operationContext: { id: execution.id, index: plan.index, invocation: plan.invocation } });
  await assert.rejects(f.client.submitPrepared(extra), { code: 'operation_changed' });
  const fresh = new OperationClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client)));
  const resumed = await fresh.continue(execution.id);
  assert.equal('kind' in resumed && resumed.kind === 'run' && resumed.task.id, first.task.id);
  await f.executor.tick();
  const completed = await fresh.continue(execution.id);
  assert.equal('state' in completed && completed.state, 'succeeded');
  assert.equal((await operations.complete(execution.id, 0, { runId: first.task.id })).state, 'succeeded');
  assert.equal(f.requests.length, 1); assert.equal(f.requests[0]?.headers.authorization, 'Bearer private-http-token');
  const row = await f.context.db.one<{ snapshot: string }>('SELECT snapshot FROM operation_executions WHERE id=$1', [execution.id]);
  const snapshot = await f.context.vault.decrypt(row!.snapshot, 'operation-execution:' + execution.id);
  assert.equal(JSON.stringify(snapshot).includes('private-http-token'), false);
});

test('途中の操作をやり直す際に、保存した進捗から続けて完了済みの処理を一度だけ反映する', async t => {
  const f = await flowFixture(); t.after(f.close);
  let first = 0, second = 0;
  const input = z.object({}).strict();
  f.context.operations.define('counter.first', input, ['準備する', 'Prepare'], async () => ({ count: ++first }));
  f.context.operations.define('counter.second', input, ['完了する', 'Finish'], async () => {
    if (++second === 1) throw new DomainError(400, 'temporarily_unavailable', 'Try again.');
    return { count: second };
  });
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'counter.first', input: {} }, { name: 'counter.second', input: {} }] } }, ApprovalRequest);
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { code: 'temporarily_unavailable' });
  assert.equal((await f.client.api.json('/api/requests/' + asked.id, {}, ApprovalRequest)).state, 'pending');
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(answer.state, 'approved'); assert.equal(first, 1); assert.equal(second, 2);
  assert.deepEqual(answer.results, [{ count: 1 }, { count: 2 }]);
});

test('送信の応答を失っても保存した署名付き実行を別のクライアントで再送し、同じ処理として実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  let loseResponse = true;
  const api: JsonApi = { async json(path, options = {}, schema) {
    const result = await f.client.api.json(path, options, schema);
    if (path === '/api/executions' && options.method === 'POST' && loseResponse) {
      loseResponse = false; throw new Error('Connection closed after submission.');
    }
    return result;
  } };
  const custody = new CustodyClient(api, f.config.origin, f.owner.binding, f.owner.keys, f.client.trust);
  const operations = new OperationClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody)));
  const execution = await operations.start({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
    environmentId: f.environment.manifest.id, operation: { kind: 'http', request: { url: 'https://api.example.com/retry', method: 'GET' } } } });
  await assert.rejects(operations.continue(execution.id), SubmissionPending);
  const fresh = new OperationClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client)));
  const resumed = await fresh.continue(execution.id);
  assert.equal('kind' in resumed && resumed.kind, 'run');
  await f.executor.tick();
  assert.equal((await f.client.api.json('/api/operation-executions/' + execution.id, {}, OperationExecution)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});

test('承認後に実行開始が中断しても、承認済みの同じ実行を保存した権限で再開する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'principal.create', input: { ownerId: '$approver', name: 'Resumed group' } }] } }, ApprovalRequest);
  const start = f.context.operationExecutions.start.bind(f.context.operationExecutions);
  f.context.operationExecutions.start = async () => { throw new Error('Process stopped after recording approval.'); };
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { status: 500 });
  f.context.operationExecutions.start = start;
  const resumed = await f.client.api.json('/api/requests/' + asked.id, {}, ApprovalRequest);
  assert.equal(resumed.state, 'approved');
  assert.equal((await f.client.api.json('/api/operation-executions/' + asked.id, {}, OperationExecution)).actorId, f.owner.actor.id);
  const groups = await f.context.db.all('SELECT id FROM principals WHERE owner_id=$1 AND name=$2', [f.owner.actor.id, 'Resumed group']);
  assert.equal(groups.length, 1); assert.equal((resumed.results[0] as { id: string }).id, groups[0]!.id);
});

test('処理後の進捗保存に失敗すると結果を要確認とし、同じ処理を自動で繰り返すことを防ぐ', async t => {
  const f = await flowFixture(); t.after(f.close);
  let effects = 0, loseCheckpoint = false;
  const transaction = f.context.db.transaction.bind(f.context.db);
  f.context.db.transaction = async run => {
    if (loseCheckpoint) { loseCheckpoint = false; throw new Error('Connection lost while saving progress.'); }
    return transaction(run);
  };
  f.context.operations.define('counter.commit', z.object({}).strict(), ['保存する', 'Save'], async () => {
    effects++; loseCheckpoint = true; return { count: effects };
  });
  await assert.rejects(f.client.api.json('/api/operation-executions', { method: 'POST', body: { name: 'counter.commit', input: {} } }), { status: 500 });
  const row = await f.context.db.one<{ id: string }>('SELECT id FROM operation_executions WHERE actor_id=$1 ORDER BY created_at DESC LIMIT 1', [f.owner.actor.id]);
  assert.ok(row);
  const recovered = await f.client.api.json('/api/operation-executions/' + row.id, {}, OperationExecution);
  assert.equal(recovered.state, 'uncertain');
  assert.equal((await f.client.api.json('/api/operation-executions/' + row.id, {}, OperationExecution)).state, 'uncertain');
  assert.equal(effects, 1);
});

test('前のログインを終了しても同じ本人の新しいログインで入力待ちの実行を続ける', async t => {
  const f = await flowFixture(); t.after(f.close);
  const login = async () => {
    const session = await f.context.authentication.session(f.owner.actor.id, f.owner.actor.credentialId);
    const api: JsonApi = { async json(path, options = {}, schema) {
      const response = await f.app.inject({ method: (options.method ?? 'GET') as 'GET', url: path,
        headers: { cookie: 'foundation_session=' + session.token, origin: f.config.origin },
        ...(options.body === undefined ? {} : { payload: options.body as object }) });
      const value = response.json();
      if (response.statusCode >= 400) throw new DomainError(response.statusCode, value.error.code, value.error.message);
      return schema ? schema.parse(value) : value;
    } };
    const custody = new CustodyClient(api, f.config.origin, f.owner.binding, f.owner.keys, f.client.trust);
    return { session, operations: new OperationClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody))) };
  };
  const first = await login(), execution = await first.operations.start({ name: 'variable.save',
    input: { ownerId: f.owner.actor.id, name: 'Continued after login', environmentIds: [] } });
  await f.context.authentication.signout(first.session.actor);
  const fresh = await login(), completed = await fresh.operations.continue(execution.id, { value: 'continued-private-value' });
  assert.equal('kind' in completed && completed.kind, 'saved');
  if (!('kind' in completed) || completed.kind !== 'saved') throw new Error('Expected a saved value.');
  assert.equal(decode(await f.client.reveal(completed.resource.id)), 'continued-private-value');
});

test('接続を取り消すと入力待ちの実行と待機中の処理を取り消した状態で保存する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connections = new ConnectionClient(f.client, new RemoteFlowStore(f.client)), operations = new OperationClient(f.client, connections);
  const execution = await operations.start({ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
    environmentId: f.environment.manifest.id, methodId: 'render:token', name: 'Cancelled connection' } });
  const started = await operations.continue(execution.id, { fields: { token: 'private-render-token' } });
  if (!('flow' in started)) throw new Error('Expected a connection.');
  assert.equal((await connections.cancel(started.flow.id)).kind, 'cancelled');
  assert.equal((await f.client.api.json('/api/executions/' + started.flow.taskId, {}, Task)).state, 'cancelled');
  const resumed = await operations.continue(execution.id);
  assert.equal('state' in resumed && resumed.state, 'cancelled');
  assert.equal(await f.executor.tick(), false);
});
