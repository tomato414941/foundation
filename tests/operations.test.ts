import { AppMaterial, ConnectionMaterial } from '../shared/connections.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { flowFixture, jsonResponse } from './flow-support.js';
import { ApprovalRequest, Resource, listOf } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import { DefinitionDescription, Execution } from '../shared/executions.js';
import { ExecutionClient } from '../shared/execution-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { Task } from '../shared/runtime-protocol.js';
import { decode, encode } from '../shared/encryption.js';
import { canonical } from '../shared/authority.js';
import { ContentTypes } from '../shared/custody.js';
import { ConnectionMaterial, connectionLabels, connectionMetadata } from '../shared/connections.js';
import { DomainError } from '../server/errors.js';
import type { JsonApi } from '../shared/client.js';
import { CustodyClient, SubmissionPending } from '../shared/client.js';

test('定義した操作を通常のAPIと承認依頼から同じ利用者の権限で実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  f.context.definitions.define('message.format', z.object({ text: z.string() }).strict(), ['文章を確認する', 'Review text'],
    async (actor, input) => ({ text: input.text, actorId: actor.id }));
  const catalog = await f.client.api.json('/api/definitions', {}, listOf(DefinitionDescription));
  assert.equal(catalog.items.find(item => item.name === 'message.format')?.title.ja, '文章を確認する');
  const direct = await f.client.api.json('/api/definitions/message.format/executions', { method: 'POST', body: { text: 'Hello' } }, Execution);
  assert.deepEqual(direct.results[0], { text: 'Hello', actorId: f.owner.actor.id });
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'message.format', input: { text: 'Hello' } }] } }, ApprovalRequest);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(answer.state, 'accepted');
  const completed = await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.deepEqual(completed.results[0], direct.results[0]);
});

test('通常の画面と依頼の変数保存が鍵を持つ利用者の暗号化処理を使い、入力後に同じ実行を続ける', async t => {
  const f = await flowFixture(); t.after(f.close);
  const operations = new ExecutionClient(f.client, f.connections), sender = f.api(f.stranger.token);
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
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  const pending = await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(pending.state, 'waiting'); assert.equal(pending.waiting?.index, 1);
  const first = (pending.results[0] as { id: string }).id;
  const result = await operations.continue(asked.executionId, { value: 'owner-only-secret' });
  assert.equal('kind' in result && result.kind, 'saved');
  if (!('kind' in result) || result.kind !== 'saved') throw new Error('Expected a saved value.');
  assert.equal(decode(await f.client.reveal(result.resource.id)), 'owner-only-secret');
  const completed = await sender.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded'); assert.equal((completed.results[0] as { id: string }).id, first);
  assert.equal((completed.results[2] as { name: string }).name, 'Finished owner');
  const execution = await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(execution.state, 'succeeded'); assert.equal(execution.id, asked.executionId);
  const row = await f.context.db.one<{ snapshot: string }>('SELECT snapshot FROM executions WHERE id=$1', [asked.executionId]);
  assert.ok(row?.snapshot);
  const snapshot = await f.context.vault.decrypt(row.snapshot, 'operation-execution:' + asked.executionId);
  assert.equal(JSON.stringify(snapshot).includes('owner-only-secret'), false);
  const resource = await f.client.api.json('/api/resources/' + result.resource.id, {}, Resource);
  assert.deepEqual(resource.data, result.resource.data);
});

test('依頼でOVHのIDとSecretを暗号化して保存し、同じ実行に結果を記録する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'connection.connect', input: { ownerId: '$approver', methodId: 'ovh:client_credentials', fields: { apiRegion: 'eu' }, name: 'OVH account' } },
  ] } }, ApprovalRequest);
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {
    configuration: [{ clientId: 'ovh-service-account' }],
  } }, ApprovalRequest);
  const saved = await f.operations.continue(asked.executionId, { clientSecret: 'ovh-service-secret' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected saved credentials.');
  const material = ConnectionMaterial.parse(JSON.parse(decode(await f.client.reveal(saved.resource.id))));
  const app = AppMaterial.parse(JSON.parse(decode(await f.client.reveal(material.appId!))));
  assert.equal(app.clientId, 'ovh-service-account'); assert.equal(app.clientSecret, 'ovh-service-secret');
  const completed = await sender.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded'); assert.equal((completed.results[0] as { id: string }).id, saved.resource.id);
  await assert.rejects(sender.json('/api/resources/' + saved.resource.id + '/custody'), { code: 'forbidden' });
});

test('準備した接続設定を維持して不足する設定を補い、秘密の値を暗号化して保存する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const handler = new ExecutionClient(f.client, f.connections);
  const execution = await f.client.api.json('/api/executions', { method: 'POST', body: { operations: [
    { name: 'connection.connect', input: { ownerId: f.owner.actor.id, methodId: 'zendesk:token',
      name: 'Support account', fields: { subdomain: 'workspace' } } },
  ] } }, Execution);
  await handler.configure(execution.id, { fields: { email: 'owner@example.com' } });
  const configured = await f.client.api.json('/api/executions/' + execution.id, {}, Execution);
  assert.deepEqual(configured.waiting?.invocation.input.fields, { subdomain: 'workspace', email: 'owner@example.com' });
  await assert.rejects(handler.configure(execution.id, { fields: { subdomain: 'other' } }), { code: 'operation_changed' });
  await assert.rejects(handler.configure(execution.id, { fields: { token: 'private-token' } }), { code: 'encrypted_input_required' });
  const altered = ConnectionMaterial.parse({ format: 2, methodId: 'zendesk:token', method: await f.method('zendesk:token'),
    generation: crypto.randomUUID(), appId: null, appGeneration: null,
    fields: { subdomain: 'other', email: 'owner@example.com', token: 'private-token' } });
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.tokenSet);
  await assert.rejects(f.client.save('Support account', encode(canonical(altered)), policy, {
    metadata: await connectionMetadata(altered), labels: connectionLabels(altered),
    commit: async write => {
      const completed = await handler.complete(execution.id, 0, write as unknown as JsonValue);
      return f.client.api.json('/api/resources/' + (completed.results[0] as { id: string }).id, {}, Resource);
    },
  }), { code: 'operation_changed' });
  const result = await handler.continue(execution.id, { fields: { token: 'private-token' } });
  if (!('kind' in result) || result.kind !== 'saved' || result.resource.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(result.resource.data.fields, { subdomain: 'workspace', email: 'owner@example.com' });
  const saved = await f.client.api.json('/api/executions/' + execution.id, {}, Execution);
  assert.equal(saved.state, 'succeeded');
  const material = JSON.parse(decode(await f.client.reveal(result.resource.id)));
  assert.equal(material.fields.token, 'private-token');
});

test('承認したHTTP操作と署名した実行を結び付け、実行先が復号後に差し替えを拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const operations = new ExecutionClient(f.client, f.connections), sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'run.execute', input: { ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id,
      operation: { kind: 'http', request: { url: 'https://api.example.com/reviewed', method: 'GET' } } } }] } }, ApprovalRequest);
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  const plan = await operations.plan(asked.executionId);
  const prepared = await f.client.prepare(f.owner.actor.id, f.environment.manifest.id, { kind: 'http', request: {
    url: 'https://api.example.com/changed', method: 'DELETE', headers: {}, bindings: [],
  }, save: {} }, { approval: plan.approval, operationContext: { id: asked.executionId, index: plan.index, invocation: plan.invocation } });
  await f.client.api.json('/api/executions/' + asked.executionId + '/continuation', { method: 'PUT',
    body: { index: plan.index, continuation: { kind: 'run', id: prepared.intent.id } } });
  const task = await f.client.submitPrepared(prepared);
  await f.executor.tick();
  const failed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.equal(failed.state, 'failed');
  const result = await f.client.result(failed);
  assert.equal(result?.ok, false); assert.deepEqual(result?.error && typeof result.error === 'object' && 'code' in result.error
    ? result.error.code : null, 'invalid_execution');
  assert.equal((await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution)).state, 'failed');
});

test('HTTPの秘密情報を封をしたまま再開し、同じ実行先の処理と完了通知を一度だけ反映する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const operations = new ExecutionClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client)));
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
  const fresh = new ExecutionClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client)));
  const resumed = await fresh.continue(execution.id);
  assert.equal('kind' in resumed && resumed.kind === 'run' && resumed.task.id, first.task.id);
  await f.executor.tick();
  const completed = await fresh.continue(execution.id);
  assert.equal('state' in completed && completed.state, 'succeeded');
  assert.equal((await operations.complete(execution.id, 0, { runId: first.task.id })).state, 'succeeded');
  assert.equal(f.requests.length, 1); assert.equal(f.requests[0]?.headers.authorization, 'Bearer private-http-token');
  const row = await f.context.db.one<{ snapshot: string }>('SELECT snapshot FROM executions WHERE id=$1', [execution.id]);
  const snapshot = await f.context.vault.decrypt(row!.snapshot, 'operation-execution:' + execution.id);
  assert.equal(JSON.stringify(snapshot).includes('private-http-token'), false);
});

test('途中の操作をやり直す際に、保存した進捗から続けて完了済みの処理を一度だけ反映する', async t => {
  const f = await flowFixture(); t.after(f.close);
  let first = 0, second = 0;
  const input = z.object({}).strict();
  f.context.definitions.define('counter.first', input, ['準備する', 'Prepare'], async () => ({ count: ++first }));
  f.context.definitions.define('counter.second', input, ['完了する', 'Finish'], async () => {
    if (++second === 1) throw new DomainError(400, 'temporarily_unavailable', 'Try again.');
    return { count: second };
  });
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'counter.first', input: {} }, { name: 'counter.second', input: {} }] } }, ApprovalRequest);
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { code: 'temporarily_unavailable' });
  assert.equal((await f.client.api.json('/api/requests/' + asked.id, {}, ApprovalRequest)).state, 'accepted');
  const answer = await f.client.api.json('/api/executions/' + asked.executionId + '/resume', { method: 'POST', body: {} }, Execution);
  assert.equal(answer.state, 'succeeded'); assert.equal(first, 1); assert.equal(second, 2);
  assert.deepEqual(answer.results, [{ count: 1 }, { count: 2 }]);
});

test('送信の応答を失っても保存した署名付き実行を別のクライアントで再送し、同じ処理として実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  let loseResponse = true;
  const api: JsonApi = { async json(path, options = {}, schema) {
    const result = await f.client.api.json(path, options, schema);
    if (path === '/api/runtime/runs' && options.method === 'POST' && loseResponse) {
      loseResponse = false; throw new Error('Connection closed after submission.');
    }
    return result;
  } };
  const custody = new CustodyClient(api, f.config.origin, f.owner.binding, f.owner.keys, f.client.trust);
  const operations = new ExecutionClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody)));
  const execution = await operations.start({ name: 'run.execute', input: { ownerId: f.owner.actor.id,
    environmentId: f.environment.manifest.id, operation: { kind: 'http', request: { url: 'https://api.example.com/retry', method: 'GET' } } } });
  await assert.rejects(operations.continue(execution.id), SubmissionPending);
  const fresh = new ExecutionClient(f.client, new ConnectionClient(f.client, new RemoteFlowStore(f.client)));
  const resumed = await fresh.continue(execution.id);
  assert.equal('kind' in resumed && resumed.kind, 'run');
  await f.executor.tick();
  assert.equal((await f.client.api.json('/api/executions/' + execution.id, {}, Execution)).state, 'succeeded');
  assert.equal(f.requests.length, 1);
});

test('承認後に実行開始が中断しても、承認済みの同じ実行を保存した権限で再開する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'principal.create', input: { ownerId: '$approver', name: 'Resumed group' } }] } }, ApprovalRequest);
  const start = f.context.executions.start.bind(f.context.executions);
  f.context.executions.start = async () => { throw new Error('Process stopped after recording approval.'); };
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { status: 500 });
  f.context.executions.start = start;
  const resumed = await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(resumed.state, 'succeeded');
  assert.equal((await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution)).actorId, f.owner.actor.id);
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
  f.context.definitions.define('counter.commit', z.object({}).strict(), ['保存する', 'Save'], async () => {
    effects++; loseCheckpoint = true; return { count: effects };
  });
  await assert.rejects(f.client.api.json('/api/executions', { method: 'POST', body: { operations: [{ name: 'counter.commit', input: {} }] } }), { status: 500 });
  const row = await f.context.db.one<{ id: string }>('SELECT id FROM executions WHERE actor_id=$1 ORDER BY created_at DESC LIMIT 1', [f.owner.actor.id]);
  assert.ok(row);
  const recovered = await f.client.api.json('/api/executions/' + row.id, {}, Execution);
  assert.equal(recovered.state, 'uncertain');
  assert.equal((await f.client.api.json('/api/executions/' + row.id, {}, Execution)).state, 'uncertain');
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
    return { session, operations: new ExecutionClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody))) };
  };
  const first = await login(), execution = await first.operations.start({ name: 'variable.save',
    input: { ownerId: f.owner.actor.id, name: 'Continued after login', environmentIds: [] } });
  await f.context.authentication.signout(first.session.actor);
  const fresh = await login(), completed = await fresh.operations.continue(execution.id, { value: 'continued-private-value' });
  assert.equal('kind' in completed && completed.kind, 'saved');
  if (!('kind' in completed) || completed.kind !== 'saved') throw new Error('Expected a saved value.');
  assert.equal(decode(await f.client.reveal(completed.resource.id)), 'continued-private-value');
});

test('認可待ちの接続を取り消すと実行を取り消した状態で保存する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connections = new ConnectionClient(f.client, new RemoteFlowStore(f.client)), operations = new ExecutionClient(f.client, connections);
  const execution = await operations.start({ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
    methodId: 'openrouter:oauth', name: 'Cancelled connection' } });
  const started = await operations.continue(execution.id);
  if (!('flow' in started)) throw new Error('Expected a connection.');
  assert.equal((await connections.cancel(started.flow.id)).kind, 'cancelled');
  const resumed = await operations.continue(execution.id);
  assert.equal('state' in resumed && resumed.state, 'cancelled');
  assert.equal(await f.executor.tick(), false);
});

test('同じプリンシパルの許可済み操作を応答待ちにせず実行し、結果と継続URLを返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const execution = await f.client.api.json('/api/executions', { method: 'POST', body: { operations: [
    { name: 'principal.create', input: { ownerId: f.owner.actor.id, name: 'Direct operation' } },
  ] } }, Execution);
  assert.equal(execution.state, 'succeeded'); assert.deepEqual(execution.requests, []);
  assert.equal(execution.creator.id, f.owner.actor.id); assert.equal(execution.actorId, f.owner.actor.id);
  assert.equal(new URL(execution.url).pathname, '/executions/' + execution.id);
  assert.equal((execution.results[0] as { name: string }).name, 'Direct operation');
  const fetched = await f.client.api.json('/api/executions/' + execution.id, {}, Execution);
  assert.deepEqual(fetched.results, execution.results);
});

test('異なるプリンシパルが準備したOVH接続を操作のURLから再開し、指定した権限で保存する', async t => {
  const f = await flowFixture(request => request.url.includes('/oauth2/token')
    ? jsonResponse({ access_token: 'direct-ovh-token', token_type: 'Bearer', expires_in: 3600 }) : jsonResponse({ ok: true }));
  t.after(f.close);
  const creator = f.api(f.stranger.token), connections = new ConnectionClient(f.client, new RemoteFlowStore(f.client));
  const handler = new ExecutionClient(f.client, connections);
  const execution = await creator.json('/api/executions', { method: 'POST', body: {
    responderId: f.owner.actor.id, message: 'Connect OVHcloud', operations: [{ name: 'connection.connect',
      input: { ownerId: '$approver', methodId: 'ovh:client_credentials', fields: { apiRegion: 'ca' }, name: 'Direct OVH' } }],
  } }, Execution);
  assert.equal(execution.wait, 'approval'); assert.equal(execution.creator.id, f.stranger.actor.id);
  assert.equal((await f.client.api.json('/api/requests/' + execution.requests[0], {}, ApprovalRequest)).to?.id, f.owner.actor.id);
  await assert.rejects(creator.json('/api/executions/' + execution.id + '/respond', { method: 'POST', body: {} }), { code: 'forbidden' });
  const responded = await f.client.api.json('/api/executions/' + execution.id + '/respond', { method: 'POST',
    body: { configuration: [{ clientId: 'direct-ovh-client' }] } }, Execution);
  assert.equal(responded.actorId, f.owner.actor.id); assert.equal(responded.wait, 'input');
  assert.deepEqual(responded.waiting?.invocation.input.fields, { apiRegion: 'ca' });
  await assert.rejects(handler.continue(execution.id, { clientSecret: 'direct-ovh-secret', fields: { apiRegion: 'eu' } }),
    { code: 'operation_changed' });
  const savedConnection = await handler.continue(execution.id, { clientSecret: 'direct-ovh-secret' });
  assert.equal('kind' in savedConnection && savedConnection.kind, 'saved');
  const completed = await creator.json('/api/executions/' + execution.id, {}, Execution);
  assert.equal(completed.state, 'succeeded'); assert.equal(completed.id, execution.id);
  const resourceId = (completed.results[0] as { id: string }).id;
  const connection = await f.client.api.json('/api/resources/' + resourceId, {}, Resource);
  assert.equal(connection.kind, 'connection');
  if (connection.kind === 'connection') assert.deepEqual(connection.data.fields, { apiRegion: 'ca' });
  await assert.rejects(creator.json('/api/resources/' + resourceId + '/custody'), { code: 'forbidden' });
  const saved = await f.context.db.one<{ snapshot: string }>('SELECT snapshot FROM executions WHERE id=$1', [execution.id]);
  assert.ok(saved);
  assert.equal(JSON.stringify(await f.context.vault.decrypt(saved.snapshot, 'operation-execution:' + execution.id)).includes('direct-ovh-secret'), false);
});

test('共通の操作から関数を公開して実行し、関数の終了後に準備済みの操作をバックグラウンドで続ける', async t => {
  const f = await flowFixture(() => jsonResponse({ message: 'function result' })); t.after(f.close);
  const publication = await f.operations.execute({ name: 'function.save', input: { ownerId: f.owner.actor.id,
    name: 'Operation function', definition: {
      program: { kind: 'http', request: { url: 'https://api.example.com/function', method: 'GET' } }, parameters: [], result: 'json', description: '' } } });
  if (!('kind' in publication) || publication.kind !== 'saved') throw new Error('Expected a published function.');
  await f.operations.execute({ name: 'function.configure', input: { functionId: publication.resource.id,
    functionVersion: publication.resource.version, version: 0, environmentId: f.environment.manifest.id, inputAccess: { expiresAt: null } } });
  const execution = await f.client.api.json('/api/executions', { method: 'POST', body: { operations: [
    { name: 'function.invoke', input: { functionId: publication.resource.id, arguments: {} } },
    { name: 'principal.rename', input: { id: f.owner.actor.id, name: 'Background completion' } },
  ] } }, Execution);
  assert.equal(execution.state, 'running'); assert.equal(execution.wait, 'execution');
  const repeated = await f.client.api.json('/api/executions/' + execution.id, {}, Execution);
  assert.equal(repeated.steps[0]!.runs[0]!.id, execution.steps[0]!.runs[0]!.id);
  await f.functionExecutor.tick();
  await f.context.executions.recoverAll();
  assert.equal((await f.context.principals.get(f.owner.actor.id)).name, 'Background completion');
  const completed = await f.client.api.json('/api/executions/' + execution.id, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.results[0], { status: 200, headers: { 'content-type': 'application/json' }, body: { message: 'function result' } });
  assert.equal(f.requests.filter(request => request.url === 'https://api.example.com/function').length, 1);
  const cancelled = await f.client.api.json('/api/executions', { method: 'POST', body: { operations: [
    { name: 'function.invoke', input: { functionId: publication.resource.id, arguments: {} } },
  ] } }, Execution);
  assert.equal((await f.client.api.json('/api/executions/' + cancelled.id + '/cancel', { method: 'POST', body: {} }, Execution)).state, 'cancelled');
  assert.equal((await f.functions.result(cancelled.id)).state, 'cancelled');
});

test('期限を過ぎた操作の入力や実行を拒否し、完了した操作を再読み込みして結果を確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const execution = await f.operations.start({ name: 'variable.save', input: { ownerId: f.owner.actor.id, name: 'Expired input', environmentIds: [] } });
  await f.context.db.pool.query("UPDATE executions SET expires_at=now()-interval '1 second' WHERE id=$1", [execution.id]);
  const expired = await f.client.api.json('/api/executions/' + execution.id, {}, Execution);
  assert.equal(expired.state, 'cancelled');
  await assert.rejects(f.operations.plan(execution.id), { code: 'execution_expired' });
});

test('連続する操作で必要な相手ごとに同意を確認し、すでに済んだ移転を一度だけ反映する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const recipient = await f.person('Second recipient');
  const first = await f.resources.insert(f.owner.actor.id, 'object', 'First handoff', { size: 0, contentType: 'text/plain' });
  const second = await f.resources.insert(f.owner.actor.id, 'object', 'Second handoff', { size: 0, contentType: 'text/plain' });
  const execution = await f.client.api.json('/api/executions', { method: 'POST', body: { operations: [
    { name: 'resource.transfer', input: { id: first.id, to: f.stranger.actor.id, version: first.version } },
    { name: 'resource.transfer', input: { id: second.id, to: recipient.actor.id, version: second.version } },
  ] } }, Execution);
  assert.equal(execution.wait, 'approval'); assert.equal((await f.client.api.json('/api/requests/' + execution.requests[0], {}, ApprovalRequest)).to?.id, f.stranger.actor.id);
  const agreed = await f.api(f.stranger.token).json('/api/executions/' + execution.id + '/respond', { method: 'POST', body: {} }, Execution);
  assert.equal(agreed.wait, 'approval'); assert.equal(agreed.index, 1);
  assert.equal((await f.api(f.stranger.token).json('/api/requests/' + agreed.requests.at(-1), {}, ApprovalRequest)).to?.id, recipient.actor.id);
  assert.equal((await f.resources.get(first.id)).owner_id, f.stranger.actor.id);
  assert.equal((await f.resources.get(second.id)).owner_id, f.owner.actor.id);
  const completed = await f.api(recipient.token).json('/api/executions/' + execution.id + '/respond', { method: 'POST', body: {} }, Execution);
  assert.equal(completed.state, 'succeeded'); assert.equal((await f.resources.get(second.id)).owner_id, recipient.actor.id);
  assert.deepEqual((await f.api(f.stranger.token).json('/api/executions/' + execution.id, {}, Execution)).results, completed.results);
});

test('同じIDで送信した操作を一度だけ実行し、異なる入力によるIDの再利用を拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const id = crypto.randomUUID(), body = { id, operations: [{ name: 'principal.create', input: { ownerId: f.owner.actor.id, name: 'Idempotent group' } }] };
  const first = await f.client.api.json('/api/executions', { method: 'POST', body }, Execution);
  const repeated = await f.client.api.json('/api/executions', { method: 'POST', body }, Execution);
  assert.equal(first.id, id); assert.equal(repeated.id, id); assert.deepEqual(repeated.results, first.results);
  const groups = await f.context.db.all('SELECT id FROM principals WHERE owner_id=$1 AND name=$2', [f.owner.actor.id, 'Idempotent group']);
  assert.equal(groups.length, 1);
  await assert.rejects(f.client.api.json('/api/executions', { method: 'POST', body: { ...body,
    operations: [{ name: 'principal.create', input: { ownerId: f.owner.actor.id, name: 'Changed group' } }] } }), { code: 'execution_conflict' });
});

type FlowFixture = Awaited<ReturnType<typeof flowFixture>>;
async function connectOAuth(f: FlowFixture, methodId: string) {
  const app = await f.saveApp(methodId);
  const start = await f.authorize({ methodId, appId: app.id });
  const authorization = await f.tick(start.flow.id);
  if (authorization.kind !== 'authorize') throw new Error('Expected browser authorization.');
  const state = new URL(authorization.url).searchParams.get('state')!;
  await f.connections.complete(start.flow.id, new URLSearchParams({ code: 'approved-code', state }).toString());
  const connection = await f.saved(start.flow.id);
  if (connection.kind !== 'connection') throw new Error('Expected a connection.');
  return connection;
}
async function disconnect(f: FlowFixture, connectionId: string, run = true) {
  const revocation = await f.operations.execute({ name: 'connection.revoke', input: { ownerId: f.owner.actor.id,
    environmentId: f.environment.manifest.id, connectionId } });
  if (!('kind' in revocation) || revocation.kind !== 'run') throw new Error('Expected a revocation run.');
  if (run) await f.executor.tick();
  return { task: revocation.task, executionId: revocation.task.intent.operationContext!.id };
}
const githubToken = (request: { url: string }) => request.url === 'https://github.com/login/oauth/access_token'
  ? jsonResponse({ access_token: 'github-access', token_type: 'bearer', scope: 'repo' }) : null;

test('GitHubの接続を解除すると、そのトークンだけをサービス側で取り消して接続を削除する', async t => {
  const f = await flowFixture(request => githubToken(request) ?? { status: 204, headers: {}, body: new Uint8Array() });
  t.after(f.close);
  const connection = await connectOAuth(f, 'github:oauth');
  assert.equal(connection.data.revocable, true);
  const { task, executionId } = await disconnect(f, connection.id);
  const completed = await f.client.api.json('/api/executions/' + executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  const run = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.deepEqual(run?.result, { kind: 'disconnected', id: connection.id, revoked: true });
  const revocations = f.requests.filter(request => request.url.startsWith('https://api.github.com/applications/'));
  assert.deepEqual(revocations.map(request => [request.method, request.url]),
    [['DELETE', 'https://api.github.com/applications/application-id/token']]);
  await assert.rejects(f.client.api.json('/api/resources/' + connection.id), { code: 'not_found' });
});

test('サービス側での取り消しに失敗しても、解除した接続を削除して結果を記録する', async t => {
  const f = await flowFixture(request => githubToken(request) ?? { status: 500, headers: {}, body: new Uint8Array() });
  t.after(f.close);
  const connection = await connectOAuth(f, 'github:oauth');
  const { task, executionId } = await disconnect(f, connection.id);
  const completed = await f.client.api.json('/api/executions/' + executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.results, [{ kind: 'run', id: task.id, state: 'failed' }]);
  await assert.rejects(f.client.api.json('/api/resources/' + connection.id), { code: 'not_found' });
});

test('そのトークンだけを取り消せない方式の接続は、サービスに取り消しを求めずに解除する', async t => {
  const f = await flowFixture(request => request.url.endsWith('/token')
    ? jsonResponse({ access_token: 'google-access', refresh_token: 'google-refresh', token_type: 'Bearer', expires_in: 3600 })
    : jsonResponse({ ok: true }));
  t.after(f.close);
  const connection = await connectOAuth(f, 'google:oauth');
  assert.equal(connection.data.revocable, false);
  const sent = f.requests.length;
  const { task, executionId } = await disconnect(f, connection.id);
  assert.equal((await f.client.api.json('/api/executions/' + executionId, {}, Execution)).state, 'succeeded');
  const run = await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  assert.deepEqual(run?.result, { kind: 'disconnected', id: connection.id, revoked: false });
  assert.equal(f.requests.length, sent);
  await assert.rejects(f.client.api.json('/api/resources/' + connection.id), { code: 'not_found' });
});

test('解除の実行を取り消すと、サービスに要求を送らずに接続を残す', async t => {
  const f = await flowFixture(request => githubToken(request) ?? { status: 204, headers: {}, body: new Uint8Array() });
  t.after(f.close);
  const connection = await connectOAuth(f, 'github:oauth');
  const { executionId } = await disconnect(f, connection.id, false);
  await f.client.api.json('/api/executions/' + executionId + '/cancel', { method: 'POST', body: {} });
  await f.executor.tick();
  assert.equal((await f.client.api.json('/api/executions/' + executionId, {}, Execution)).state, 'cancelled');
  assert.equal(f.requests.filter(request => request.url.startsWith('https://api.github.com/applications/')).length, 0);
  assert.equal((await f.client.api.json('/api/resources/' + connection.id, {}, Resource)).id, connection.id);
});
