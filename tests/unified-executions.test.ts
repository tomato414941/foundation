import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { JournalTrust } from '../runtime/trust.js';
import { CustodyClient } from '../shared/client.js';
import { ExecutionClient } from '../shared/execution-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { ApprovalRequest, Resource, listOf } from '../shared/contracts.js';
import { Execution } from '../shared/executions.js';
import { Task } from '../shared/runtime-protocol.js';
import { decode } from '../shared/encryption.js';

test('実行環境を持たない所有者がHFトークンを暗号化して登録し、一件の実行から結果を確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const custody = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys,
    new JournalTrust(new MemoryJournal()));
  const client = new ExecutionClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody)));
  const token = 'hf_locally_encrypted_registration';
  const saved = await client.execute({ name: 'connection.connect', input: { ownerId: f.stranger.actor.id,
    methodId: 'huggingface:token', name: 'Hugging Face' } }, { fields: { token } });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
  assert.equal(saved.resource.ownerId, f.stranger.actor.id);
  const material = JSON.parse(decode(await custody.reveal(saved.resource.id)));
  assert.equal(material.fields.token, token);
  const history = await custody.api.json('/api/principals/' + f.stranger.actor.id + '/executions', {}, listOf(Execution));
  assert.equal(history.items.length, 1);
  assert.equal(history.items[0]!.state, 'succeeded');
  assert.equal((history.items[0]!.results[0] as { id: string }).id, saved.resource.id);
  assert.equal(JSON.stringify(history).includes(token), false);
  assert.equal((await custody.api.json('/api/requests', {}, listOf(ApprovalRequest))).items.length, 0);
});

test('依頼の承諾と処理の完了を分け、依頼が参照する実行を入力後も同じIDで続ける', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'variable.save', input: { ownerId: f.owner.actor.id, name: 'Approved input', value: '' },
      inputs: [{ pointer: '/value', label: 'Value', secret: true }] }] } }, ApprovalRequest);
  assert.notEqual(asked.id, asked.executionId);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(answer.state, 'accepted');
  assert.equal((await f.client.api.json('/api/executions/' + asked.executionId, {}, Execution)).wait, 'input');
  await f.operations.continue(asked.executionId, { value: 'sealed-after-consent' });
  const completed = await f.api(f.stranger.token).json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.requests, [asked.id]);
  assert.equal((await f.client.api.json('/api/requests/' + asked.id, {}, ApprovalRequest)).state, 'accepted');
});

test('入力待ちの実行へ後から依頼を送り、受信者の入力で元の実行を完了する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const execution = await sender.json('/api/executions', { method: 'POST', body: { operations: [
    { name: 'variable.save', input: { ownerId: f.owner.actor.id, name: 'Shared workflow' } },
  ] } }, Execution);
  const asked = await sender.json('/api/requests', { method: 'POST', body: {
    executionId: execution.id, to: f.owner.actor.id, message: 'Please provide the value.' } }, ApprovalRequest);
  assert.equal(asked.executionId, execution.id);
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  await f.operations.continue(execution.id, { value: 'new-recipient-input' });
  const completed = await sender.json('/api/executions/' + execution.id, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.requests, [asked.id]);
});

test('接続の所有者がAIに使用を許可し、AI自身の権限と実行先でHF APIを呼び出す', async t => {
  const token = 'hf_authorized_agent_token';
  const f = await flowFixture(request => {
    assert.equal(request.url, 'https://huggingface.co/api/whoami-v2');
    assert.equal(request.headers.authorization, 'Bearer ' + token);
    return jsonResponse({ name: 'model-owner' });
  }); t.after(f.close);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding);
  const human = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys, trust);
  const client = new ExecutionClient(human, new ConnectionClient(human, new RemoteFlowStore(human)));
  const saved = await client.execute({ name: 'connection.connect', input: { ownerId: f.stranger.actor.id,
    methodId: 'huggingface:token', name: 'Hugging Face' } }, { fields: { token } });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
  const agentTrust = new JournalTrust(new MemoryJournal());
  await agentTrust.rememberBinding(f.stranger.binding);
  const agent = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys, agentTrust);
  await assert.rejects(agent.read(saved.resource.id), { code: 'forbidden' });
  const permission = await client.execute({ name: 'connection.authorize', input: { ownerId: f.stranger.actor.id,
    connectionId: saved.resource.id, version: saved.resource.version, users: [f.executorIdentity.actor.id] } });
  assert.equal('kind' in permission && permission.kind, 'saved');
  const visible = await agent.read(saved.resource.id);
  assert.equal(visible.content.policy.ownerId, f.stranger.actor.id);
  assert.ok(visible.content.policy.grants.some(grant => 'actor' in grant && grant.actor.principalId === f.executorIdentity.actor.id));
  const jobs = new ExecutionClient(agent, new ConnectionClient(agent, new RemoteFlowStore(agent)));
  const started = await jobs.execute({ name: 'run.execute', input: { ownerId: f.executorIdentity.actor.id,
    environmentId: f.environment.manifest.id, operation: { kind: 'http', request: {
      url: 'https://huggingface.co/api/whoami-v2', method: 'GET', headers: {}, bindings: [
        { pointer: '/headers/authorization', parts: ['Bearer ', { id: saved.resource.id, output: 'HF_TOKEN' }] },
      ],
    } } } });
  if (!('kind' in started) || started.kind !== 'run') throw new Error('Expected a run.');
  const executionId = started.task.intent.operationContext!.id;
  assert.equal((await agent.api.json('/api/executions/' + executionId, {}, Execution)).state, 'running');
  await f.executor.tick();
  const completed = await agent.api.json('/api/executions/' + executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.steps[0]!.runs, [{ kind: 'run', id: started.task.id }]);
  const result = await agent.result(await agent.api.json('/api/runtime/runs/' + started.task.id, {}, Task));
  assert.equal(result?.ok, true);
  assert.equal((await human.api.json('/api/resources/' + saved.resource.id, {}, Resource)).ownerId, f.stranger.actor.id);
});
