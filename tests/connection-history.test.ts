import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture, jsonResponse } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { JournalTrust } from '../runtime/trust.js';
import { CustodyClient } from '../shared/client.js';
import { OperationClient } from '../shared/operation-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { Resource, listOf } from '../shared/contracts.js';
import { OperationView, RequestView } from '../shared/operations.js';
import { HttpBroker } from '../runtime/broker.js';
import { Connections } from '../runtime/connections.js';
import { openInputs } from '../runtime/inputs.js';
import { decode } from '../shared/encryption.js';

test('持ち主がHFトークンを手元で暗号化して接続し、履歴の一件の操作から結果を確かめる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const custody = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys,
    new JournalTrust(new MemoryJournal()));
  const client = new OperationClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody)));
  const token = 'hf_locally_encrypted_registration';
  const saved = await client.perform({ name: 'connection.connect', input: { ownerId: f.stranger.actor.id,
    methodId: 'huggingface:token', name: 'Hugging Face' } }, { fields: { token } });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
  assert.equal(saved.resource.ownerId, f.stranger.actor.id);
  const material = JSON.parse(decode(await custody.reveal(saved.resource.id)));
  assert.equal(material.fields.token, token);
  const history = await custody.api.json('/api/principals/' + f.stranger.actor.id + '/operations', {}, listOf(OperationView));
  assert.equal(history.items.length, 1);
  assert.equal(history.items[0]!.id, saved.operationId); assert.equal(history.items[0]!.state, 'succeeded');
  assert.equal((history.items[0]!.result as { id: string }).id, saved.resource.id);
  assert.equal(JSON.stringify(history).includes(token), false);
  assert.equal((await custody.api.json('/api/requests', {}, listOf(RequestView))).items.length, 0);
});

test('接続の所有者がAIに使用を許可し、AIが自分の鍵で開いたHFのトークンを手元のコマンドへ渡す', async t => {
  const token = 'hf_authorized_agent_token';
  const f = await flowFixture(() => jsonResponse({ name: 'model-owner' })); t.after(f.close);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.delegate.binding);
  const human = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys, trust);
  const client = new OperationClient(human, new ConnectionClient(human, new RemoteFlowStore(human)));
  const saved = await client.perform({ name: 'connection.connect', input: { ownerId: f.stranger.actor.id,
    methodId: 'huggingface:token', name: 'Hugging Face' } }, { fields: { token } });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected a saved connection.');
  const agentTrust = new JournalTrust(new MemoryJournal());
  await agentTrust.rememberBinding(f.stranger.binding);
  const agent = new CustodyClient(f.api(f.delegate.token), f.config.origin, f.delegate.binding, f.delegate.keys, agentTrust);
  await assert.rejects(agent.read(saved.resource.id), { code: 'forbidden' });
  const permission = await client.perform({ name: 'connection.authorize', input: { ownerId: f.stranger.actor.id,
    connectionId: saved.resource.id, version: saved.resource.version, users: [f.delegate.actor.id] } });
  assert.equal('kind' in permission && permission.kind, 'saved');
  const visible = await agent.read(saved.resource.id);
  assert.equal(visible.content.policy.ownerId, f.stranger.actor.id);
  assert.ok(visible.content.policy.readers.some(reader => reader.principalId === f.delegate.actor.id));
  const own = new Connections(f.delegate.binding, f.delegate.keys, new HttpBroker(f.api(f.delegate.token)).connections(),
    new MemoryJournal(), f.transport);
  const used = await openInputs(agent, own, [{ name: 'HF_TOKEN', source: { id: saved.resource.id, output: 'HF_TOKEN' } }]);
  assert.equal(used.environment.HF_TOKEN, token);
  assert.equal((await human.api.json('/api/resources/' + saved.resource.id, {}, Resource)).ownerId, f.stranger.actor.id);
});
