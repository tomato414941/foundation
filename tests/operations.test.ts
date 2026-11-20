import { AppMaterial } from '../shared/connections.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import { flowFixture, jsonResponse } from './flow-support.js';
import { Resource, listOf } from '../shared/contracts.js';
import type { JsonValue } from '../shared/contracts.js';
import { OperationKind, OperationView, RequestView } from '../shared/operations.js';
import { OperationClient } from '../shared/operation-client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import { RemoteFlowStore } from '../shared/operation-continuations.js';
import { decode } from '../shared/encryption.js';
import { ConnectionMaterial, connectionLabels, connectionMetadata, sealedConnection } from '../shared/connections.js';
import { DomainError } from '../server/errors.js';
import type { JsonApi } from '../shared/client.js';
import { CustodyClient } from '../shared/client.js';

const made = (value: unknown) => OperationView.parse(value);

test('定義した操作を、持ち主はそのまま行い、ほかの人の依頼では承認したあと同じ持ち主の権限で行う', async t => {
  const f = await flowFixture(); t.after(f.close);
  f.context.definitions.define('message.format', z.object({ text: z.string() }).strict(), ['文章を確認する', 'Review text'],
    async (actor, input) => ({ text: input.text, actorId: actor.id }));
  const kinds = await f.client.api.json('/api/operation-kinds', {}, listOf(OperationKind));
  assert.equal(kinds.items.find(item => item.name === 'message.format')?.title.ja, '文章を確認する');
  const direct = made(await f.client.api.json('/api/operations', { method: 'POST', body: { name: 'message.format', input: { text: 'Hello' } } }));
  assert.equal(direct.state, 'succeeded'); assert.equal(direct.request, null);
  assert.deepEqual(direct.result, { text: 'Hello', actorId: f.owner.actor.id });
  assert.equal(new URL(direct.url).pathname, '/operations/' + direct.id);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'message.format', input: { text: 'Hello' } }] } }, RequestView);
  assert.equal(asked.state, 'pending'); assert.deepEqual(asked.performed, []);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.equal(answer.state, 'approved');
  const requested = await sender.json('/api/operations/' + answer.performed[0]!.id, {}, OperationView);
  assert.deepEqual(requested.result, direct.result); assert.deepEqual(requested.request, { id: asked.id, position: 0 });
  const history = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/operations', {}, listOf(OperationView));
  assert.deepEqual(history.items.map(item => item.id).filter(id => [direct.id, requested.id].includes(id)), [requested.id, direct.id]);
});

test('鍵で封じる変数の保存を、持ち主の端末はそのまま行い、依頼では承認のあと手元で封じてから後ろの操作を続ける', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const ordinary = await f.operations.perform({ name: 'variable.save', input: { ownerId: f.owner.actor.id,
    name: 'Ordinary' } }, { value: 'ordinary-secret' });
  if (!('kind' in ordinary) || ordinary.kind !== 'saved') throw new Error('Expected a variable.');
  assert.equal(decode(await f.client.reveal(ordinary.resource.id)), 'ordinary-secret');
  assert.equal((await f.operations.get(ordinary.operationId)).state, 'succeeded');
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'principal.create', input: { ownerId: '$approver', name: 'Prepared group' } },
    { name: 'variable.save', input: { ownerId: '$approver', name: 'Requested value', value: '' },
      inputs: [{ pointer: '/value', label: 'Access token', secret: true }] },
    { name: 'principal.rename', input: { id: '$approver', name: 'Finished owner' } },
  ] } }, RequestView);
  const approved = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.deepEqual(approved.performed.map(item => item.state), ['succeeded', 'stopped', 'stopped']);
  await assert.rejects(f.client.api.json('/api/operations/' + approved.performed[2]!.id + '/perform', { method: 'POST', body: {} }),
    { code: 'operation_waiting' });
  const result = await f.operations.continue(approved.performed[1]!.id, { value: 'owner-only-secret' });
  if (!('kind' in result) || result.kind !== 'saved') throw new Error('Expected a saved value.');
  assert.equal(decode(await f.client.reveal(result.resource.id)), 'owner-only-secret');
  const completed = await sender.json('/api/requests/' + asked.id, {}, RequestView);
  assert.deepEqual(completed.performed.map(item => item.state), ['succeeded', 'succeeded', 'succeeded']);
  const renamed = await sender.json('/api/operations/' + completed.performed[2]!.id, {}, OperationView);
  assert.equal((renamed.result as { name: string }).name, 'Finished owner');
  for (const { id } of completed.performed) {
    const row = await f.context.db.one<{ record: string }>('SELECT record FROM operations WHERE id=$1', [id]);
    assert.equal(JSON.stringify(await f.context.vault.decrypt(row!.record, 'operation:' + id)).includes('owner-only-secret'), false);
  }
});

test('依頼でOVHのIDとSecretを暗号化して保存し、アプリの保存を持ち主の操作として行ってから接続を記録する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'connection.connect', input: { ownerId: '$approver', methodId: 'ovh:client_credentials', fields: { apiRegion: 'eu' }, name: 'OVH account' } },
  ] } }, RequestView);
  await assert.rejects(sender.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { code: 'forbidden' });
  const approved = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {
    configuration: [{ clientId: 'ovh-service-account' }],
  } }, RequestView);
  const connect = approved.performed[0]!.id;
  await assert.rejects(f.operations.continue(connect, { clientSecret: 'ovh-service-secret', fields: { apiRegion: 'ca' } }),
    { code: 'operation_changed' });
  const saved = await f.operations.continue(connect, { clientSecret: 'ovh-service-secret' });
  if (!('kind' in saved) || saved.kind !== 'saved') throw new Error('Expected saved credentials.');
  const material = await f.client.connection(saved.resource.id);
  const app = AppMaterial.parse(JSON.parse(decode(await f.client.reveal(material.appId!))));
  assert.equal(app.clientId, 'ovh-service-account'); assert.equal(app.clientSecret, 'ovh-service-secret');
  const completed = await sender.json('/api/operations/' + connect, {}, OperationView);
  assert.equal(completed.state, 'succeeded'); assert.equal((completed.result as { id: string }).id, saved.resource.id);
  assert.equal(completed.input.appId, material.appId);
  const history = await f.client.api.json('/api/operations', {}, listOf(OperationView));
  const application = history.items.find(item => item.name === 'app.save');
  assert.equal(application?.request, null); assert.equal((application?.result as { id: string }).id, material.appId);
  await assert.rejects(sender.json('/api/resources/' + saved.resource.id + '/custody'), { code: 'forbidden' });
  for (const id of [connect, application!.id]) {
    const row = await f.context.db.one<{ record: string }>('SELECT record FROM operations WHERE id=$1', [id]);
    assert.equal(JSON.stringify(await f.context.vault.decrypt(row!.record, 'operation:' + id)).includes('ovh-service-secret'), false);
  }
});

test('依頼された接続の設定を保ったまま足りない設定を補い、秘密の値は手元で暗号化して保存する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'connection.connect', input: { ownerId: f.owner.actor.id, methodId: 'zendesk:token',
      name: 'Support account', fields: { subdomain: 'workspace' } } },
  ] } }, RequestView);
  const id = (await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView)).performed[0]!.id;
  const plan = { id, name: 'connection.connect', input: (await f.operations.get(id)).input, held: true, continuation: null };
  const configured = await f.operations.configure(plan, { fields: { email: 'owner@example.com' } });
  assert.deepEqual(configured.input.fields, { subdomain: 'workspace', email: 'owner@example.com' });
  await assert.rejects(f.operations.configure(plan, { fields: { subdomain: 'other' } }), { code: 'operation_changed' });
  await assert.rejects(f.operations.configure(plan, { fields: { token: 'private-token' } }), { code: 'encrypted_input_required' });
  const altered = ConnectionMaterial.parse({ format: 3, methodId: 'zendesk:token', method: await f.method('zendesk:token'),
    generation: crypto.randomUUID(), appId: null, appGeneration: null,
    fields: { subdomain: 'other', email: 'owner@example.com', token: 'private-token' } });
  await assert.rejects(f.client.save({ id: crypto.randomUUID(), ownerId: f.owner.actor.id, kind: 'connection' }, 'Support account',
    sealedConnection(altered), {
    metadata: await connectionMetadata(altered), labels: connectionLabels(altered),
    commit: async write => {
      const committed = await f.operations.commit(configured, write as unknown as JsonValue);
      return f.client.api.json('/api/resources/' + (committed.result as { id: string }).id, {}, Resource);
    },
  }), { code: 'operation_changed' });
  assert.equal((await f.operations.get(id)).state, 'failed');
  const result = await f.operations.continue(id, { fields: { token: 'private-token' } });
  if (!('kind' in result) || result.kind !== 'saved' || result.resource.kind !== 'connection') throw new Error('Expected a saved connection.');
  assert.deepEqual(result.resource.data.fields, { subdomain: 'workspace', email: 'owner@example.com' });
  assert.equal((await f.operations.get(id)).state, 'succeeded');
  assert.equal(JSON.parse(decode(await f.client.reveal(result.resource.id))).fields.token, 'private-token');
});

test('承認した依頼の操作が失敗すると、依頼は承認のまま後ろの操作を止め、失敗した操作をやり直すと後ろも続けて行う', async t => {
  const f = await flowFixture(); t.after(f.close);
  let first = 0, second = 0, third = 0;
  const input = z.object({}).strict();
  f.context.definitions.define('counter.first', input, ['準備する', 'Prepare'], async () => ({ count: ++first }));
  f.context.definitions.define('counter.second', input, ['確かめる', 'Check'], async () => {
    if (++second === 1) throw new DomainError(400, 'temporarily_unavailable', 'Try again.');
    return { count: second };
  });
  f.context.definitions.define('counter.third', input, ['完了する', 'Finish'], async () => ({ count: ++third }));
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'counter.first', input: {} }, { name: 'counter.second', input: {} }, { name: 'counter.third', input: {} }] } }, RequestView);
  const approved = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.equal(approved.state, 'approved');
  assert.deepEqual(approved.performed.map(item => item.state), ['succeeded', 'failed', 'stopped']);
  const failed = await f.client.api.json('/api/operations/' + approved.performed[1]!.id, {}, OperationView);
  assert.deepEqual(failed.error, { code: 'temporarily_unavailable', message: 'Try again.' });
  assert.equal(failed.canPerform, true);
  assert.equal((await sender.json('/api/operations/' + approved.performed[1]!.id, {}, OperationView)).canPerform, false);
  await assert.rejects(sender.json('/api/operations/' + approved.performed[1]!.id + '/perform', { method: 'POST', body: {} }), { code: 'forbidden' });
  await assert.rejects(f.client.api.json('/api/operations/' + approved.performed[2]!.id + '/perform', { method: 'POST', body: {} }),
    { code: 'operation_waiting' });
  assert.equal(third, 0);
  const retried = made(await f.client.api.json('/api/operations/' + approved.performed[1]!.id + '/perform', { method: 'POST', body: {} }));
  assert.equal(retried.state, 'succeeded');
  const completed = await sender.json('/api/requests/' + asked.id, {}, RequestView);
  assert.equal(completed.state, 'approved');
  assert.deepEqual(completed.performed.map(item => item.state), ['succeeded', 'succeeded', 'succeeded']);
  assert.deepEqual([first, second, third], [1, 2, 1]);
});

test('失敗の後ろで止まった操作を持ち主がやめると、その後ろもまとめて取りやめになる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const input = z.object({}).strict();
  f.context.definitions.define('counter.fail', input, ['確かめる', 'Check'], async () => {
    throw new DomainError(400, 'temporarily_unavailable', 'Try again.');
  });
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'counter.fail', input: {} },
    { name: 'principal.create', input: { ownerId: '$approver', name: 'Never made' } },
    { name: 'principal.create', input: { ownerId: '$approver', name: 'Never made either' } }] } }, RequestView);
  const approved = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  const stopped = made(await f.client.api.json('/api/operations/' + approved.performed[1]!.id + '/cancel', { method: 'POST', body: {} }));
  assert.equal(stopped.state, 'cancelled');
  const ended = await f.client.api.json('/api/requests/' + asked.id, {}, RequestView);
  assert.deepEqual(ended.performed.map(item => item.state), ['failed', 'cancelled', 'cancelled']);
  await assert.rejects(f.client.api.json('/api/operations/' + approved.performed[2]!.id + '/perform', { method: 'POST', body: {} }),
    { code: 'operation_changed' });
  assert.equal((await f.context.db.all("SELECT id FROM principals WHERE name LIKE 'Never made%'")).length, 0);
});

test('承認のあと操作を始める前に処理が止まっても、止まったままの操作を承認した権限で続けて行う', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'principal.create', input: { ownerId: '$approver', name: 'Resumed group' } }] } }, RequestView);
  const advance = f.context.operations.advance.bind(f.context.operations);
  f.context.operations.advance = async () => { throw new Error('Process stopped after recording approval.'); };
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { status: 500 });
  f.context.operations.advance = advance;
  const approved = await f.client.api.json('/api/requests/' + asked.id, {}, RequestView);
  assert.equal(approved.state, 'approved'); assert.deepEqual(approved.performed.map(item => item.state), ['stopped']);
  await f.context.operations.advanceAll();
  const resumed = await f.client.api.json('/api/operations/' + approved.performed[0]!.id, {}, OperationView);
  assert.equal(resumed.state, 'succeeded'); assert.equal(resumed.actor.id, f.owner.actor.id);
  const groups = await f.context.db.all('SELECT id FROM principals WHERE owner_id=$1 AND name=$2', [f.owner.actor.id, 'Resumed group']);
  assert.equal(groups.length, 1); assert.equal((resumed.result as { id: string }).id, groups[0]!.id);
});

test('行ったあとの記録を保存できなかった操作は結果不明とし、同じ処理を自動では繰り返さない', async t => {
  const f = await flowFixture(); t.after(f.close);
  let effects = 0, loseRecord = false;
  const encrypt = f.context.vault.encrypt.bind(f.context.vault);
  f.context.vault.encrypt = async (value, purpose) => {
    if (loseRecord) { loseRecord = false; throw new Error('Connection lost while saving the result.'); }
    return encrypt(value, purpose);
  };
  f.context.definitions.define('counter.commit', z.object({}).strict(), ['保存する', 'Save'], async () => {
    effects++; loseRecord = true; return { count: effects };
  });
  const id = crypto.randomUUID();
  await assert.rejects(f.client.api.json('/api/operations', { method: 'POST', body: { id, name: 'counter.commit', input: {} } }), { status: 500 });
  const recovered = await f.client.api.json('/api/operations/' + id, {}, OperationView);
  assert.equal(recovered.state, 'uncertain'); assert.equal(recovered.error?.code, 'operation_uncertain');
  assert.equal(recovered.canPerform, false);
  await assert.rejects(f.client.api.json('/api/operations/' + id + '/perform', { method: 'POST', body: {} }), { code: 'operation_uncertain' });
  assert.equal(effects, 1);
});

test('前のサインインを終えても、同じ本人の新しいサインインで止まっている操作を続けて行う', async t => {
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
    const custody = new CustodyClient(api, f.config.origin, f.owner.actor.id, f.owner.keys);
    return { session, api, operations: new OperationClient(custody, new ConnectionClient(custody, new RemoteFlowStore(custody))) };
  };
  const asked = await f.api(f.stranger.token).json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id, operations: [
    { name: 'variable.save', input: { ownerId: f.owner.actor.id, name: 'Continued after sign-in' } }] } }, RequestView);
  const first = await login();
  const approved = await first.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  await f.context.authentication.signout(first.session.actor);
  const fresh = await login(), completed = await fresh.operations.continue(approved.performed[0]!.id, { value: 'continued-private-value' });
  if (!('kind' in completed) || completed.kind !== 'saved') throw new Error('Expected a saved value.');
  assert.equal(decode(await f.client.reveal(completed.resource.id)), 'continued-private-value');
});

test('サービスでの許可を待つ接続をやめると、操作は取りやめとして残る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const connections = new ConnectionClient(f.client, new RemoteFlowStore(f.client)), operations = new OperationClient(f.client, connections);
  const started = await operations.perform({ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
    methodId: 'openrouter:oauth', name: 'Cancelled connection' } });
  if (!('flow' in started)) throw new Error('Expected a connection.');
  const waiting = await operations.get(started.flow.operationId);
  assert.equal(waiting.state, 'in_progress'); assert.equal(waiting.continuation?.id, started.flow.id);
  assert.equal((await connections.cancel(started.flow.id)).kind, 'cancelled');
  const ended = await operations.continue(started.flow.operationId);
  assert.equal('state' in ended && ended.state, 'cancelled');
});

test('相手の同意が要る譲渡は相手への依頼になり、相手が承認すると一度だけ行われる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const item = await f.resources.insert(f.owner.actor.id, 'object', 'Handoff', { size: 0, contentType: 'text/plain' });
  const asked = RequestView.parse(await f.client.api.json('/api/operations', { method: 'POST', body: { name: 'resource.transfer',
    input: { id: item.id, to: f.stranger.actor.id, version: item.version } } }));
  assert.equal(asked.to?.id, f.stranger.actor.id); assert.equal(asked.proposal?.kind, 'transfer');
  assert.equal((await f.resources.get(item.id)).owner_id, f.owner.actor.id);
  const recipient = f.api(f.stranger.token);
  const approved = await recipient.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.deepEqual(approved.performed.map(entry => entry.state), ['succeeded']);
  assert.equal((await f.resources.get(item.id)).owner_id, f.stranger.actor.id);
  const transfer = await f.client.api.json('/api/operations/' + approved.performed[0]!.id, {}, OperationView);
  assert.equal(transfer.actor.id, f.owner.actor.id);
  await assert.rejects(recipient.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { code: 'request_answered' });
});

test('同じIDで送った操作は一度だけ行い、違う入力でのIDの使い回しを拒む', async t => {
  const f = await flowFixture(); t.after(f.close);
  const id = crypto.randomUUID(), body = { id, name: 'principal.create', input: { ownerId: f.owner.actor.id, name: 'Idempotent group' } };
  const first = made(await f.client.api.json('/api/operations', { method: 'POST', body }));
  const repeated = made(await f.client.api.json('/api/operations', { method: 'POST', body }));
  assert.equal(first.id, id); assert.equal(repeated.id, id); assert.deepEqual(repeated.result, first.result);
  const groups = await f.context.db.all('SELECT id FROM principals WHERE owner_id=$1 AND name=$2', [f.owner.actor.id, 'Idempotent group']);
  assert.equal(groups.length, 1);
  await assert.rejects(f.client.api.json('/api/operations', { method: 'POST', body: { ...body,
    input: { ownerId: f.owner.actor.id, name: 'Changed group' } } }), { code: 'operation_conflict' });
});

test('HTTPで送られた変更も操作として行い、相手の同意が要るときは依頼を返す', async t => {
  const f = await flowFixture(() => jsonResponse({ ok: true })); t.after(f.close);
  const item = await f.resources.insert(f.owner.actor.id, 'object', 'Endpoint handoff', { size: 0, contentType: 'text/plain' });
  const response = await f.app.inject({ method: 'POST', url: '/api/resources/' + item.id + '/transfer',
    headers: { authorization: 'Bearer ' + f.owner.token }, payload: { to: f.stranger.actor.id, version: item.version } });
  assert.equal(response.statusCode, 202, response.body);
  const asked = RequestView.parse(response.json());
  assert.equal(asked.state, 'pending'); assert.equal(asked.from.id, f.owner.actor.id);
  const renamed = await f.app.inject({ method: 'PATCH', url: '/api/principals/' + f.owner.actor.id,
    headers: { authorization: 'Bearer ' + f.owner.token }, payload: { name: 'Renamed through HTTP' } });
  assert.equal(renamed.statusCode, 200, renamed.body);
  const history = await f.client.api.json('/api/operations', {}, listOf(OperationView));
  assert.equal(history.items[0]?.name, 'principal.rename'); assert.equal(history.items[0]?.state, 'succeeded');
});
