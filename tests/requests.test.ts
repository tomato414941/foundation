import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { principal } from '../server/authorization.js';
import { flowFixture } from './flow-support.js';
import { OperationView, RequestView } from '../shared/operations.js';

test('確認コードで端末を引き受け、承認者の権限で利用を委任する', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const person = await f.person('Person'),
    device = await f.person('Device'),
    headers = { authorization: 'Bearer ' + device.token };
  const request = await app.inject({
    method: 'POST',
    url: '/api/requests',
    headers,
    payload: {
      operation: {
        name: 'relation.draw',
        input: { relation: 'delegate', objectId: '$approver', subjectId: device.actor.id },
      },
    },
  });
  assert.equal(request.statusCode, 201, request.body);
  const pending = request.json();
  assert.match(pending.code, /^[A-Z2-9]{8}$/);
  const wrong = await app.inject({
    method: 'POST',
    url: '/api/requests/' + pending.id + '/approve',
    headers: { authorization: 'Bearer ' + person.token },
    payload: { code: 'WRONG' },
  });
  assert.equal(wrong.statusCode, 400, wrong.body);
  const answer = await app.inject({
    method: 'POST',
    url: '/api/requests/' + pending.id + '/approve',
    headers: { authorization: 'Bearer ' + person.token },
    payload: { code: pending.code },
  });
  assert.equal(answer.statusCode, 200, answer.body);
  assert.equal(answer.json().state, 'approved');
  assert.equal(answer.json().performed.state, 'succeeded');
  assert.equal(await context.authorization.holds(device.actor.id, principal(person.actor.id), 'use'), true);
  assert.equal(await context.authorization.can(person.actor, principal(device.actor.id), 'manage_credentials'), true);
  const polled = await app.inject({ url: '/api/requests/' + pending.id, headers });
  assert.equal(polled.json().state, 'approved');
});

test('依頼の承認後にトークンを手元で暗号化して保存し、依頼した側も行われた操作の結果を確かめる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operation: { name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: 'github:token', name: 'Requested connection' } } } }, RequestView);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.equal(answer.state, 'approved'); assert.equal(answer.performed?.state, 'stopped');
  const started = await f.operations.continue(answer.performed!.id, { fields: { token: 'owner-provided-key' } });
  if (!('kind' in started) || started.kind !== 'saved') throw new Error('Expected a saved connection.');
  const made = await sender.json('/api/operations/' + answer.performed!.id, {}, OperationView);
  assert.equal(made.state, 'succeeded'); assert.equal(made.requestId, asked.id);
  assert.equal((made.result as { id: string }).id, started.resource.id);
  assert.equal(JSON.stringify(made).includes('owner-provided-key'), false);
});

test('依頼を取り下げると、承認も操作もされないまま取り下げとして残る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operation: { name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: 'render:token', name: 'Requested' } } } }, RequestView);
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/withdraw', { method: 'POST', body: {} }), { code: 'forbidden' });
  const withdrawn = await sender.json('/api/requests/' + asked.id + '/withdraw', { method: 'POST', body: {} }, RequestView);
  assert.equal(withdrawn.state, 'withdrawn'); assert.equal(withdrawn.canWithdraw, false);
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { code: 'request_answered' });
  assert.equal((await f.client.api.json('/api/requests/' + asked.id, {}, RequestView)).performed, null);
});

test('断った依頼と期限が切れた依頼は承認できず、操作も行われない', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const ask = (name: string) => sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operation: { name: 'principal.create', input: { ownerId: '$approver', name } } } }, RequestView);
  const declined = await ask('Declined group'), expired = await ask('Expired group');
  assert.equal((await f.client.api.json('/api/requests/' + declined.id + '/decline', { method: 'POST', body: {} }, RequestView)).state, 'declined');
  await f.context.db.pool.query("UPDATE requests SET expires_at=now()-interval '1 second' WHERE id=$1", [expired.id]);
  assert.equal((await sender.json('/api/requests/' + expired.id, {}, RequestView)).state, 'expired');
  for (const request of [declined, expired])
    await assert.rejects(f.client.api.json('/api/requests/' + request.id + '/approve', { method: 'POST', body: {} }), { code: 'request_answered' });
  const groups = await f.context.db.all("SELECT id FROM principals WHERE name IN ('Declined group','Expired group')");
  assert.equal(groups.length, 0);
});

test('承認する操作の名前を日本語と英語で返す', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const person = await f.person('Person'),
    device = await f.person('Device'),
    headers = { authorization: 'Bearer ' + device.token };
  const ask = async (operation: object, to?: string) => {
    const response = await app.inject({ method: 'POST', url: '/api/requests', headers,
      payload: { ...(to ? { to } : {}), operation } });
    assert.equal(response.statusCode, 201, response.body);
    return RequestView.parse(response.json()).operation.title;
  };
  assert.deepEqual(await ask({ name: 'relation.draw', input: { relation: 'delegate', objectId: '$approver', subjectId: device.actor.id } }),
    { ja: '権限を委任する', en: 'Delegate access' });
  const target = '00000000-0000-4000-8000-000000000001';
  assert.deepEqual(await Promise.all([
    { name: 'relation.draw', input: { relation: 'reader', objectId: target, subjectId: device.actor.id } },
    { name: 'principal.rename', input: { id: device.actor.id, name: 'renamed' } },
    { name: 'resource.delete', input: { id: target } },
    { name: 'connection.connect', input: { ownerId: '$approver', methodId: 'github:token' } },
  ].map(operation => ask(operation, person.actor.id))), [
    { ja: '権限を渡す', en: 'Give a permission' },
    { ja: 'プリンシパルを変更する', en: 'Change a principal' },
    { ja: '項目を削除する', en: 'Delete an item' },
    { ja: 'サービスに接続する', en: 'Connect a service' },
  ]);
});

test('今はない操作を頼んだ依頼も、その操作の名前を示して一覧と詳細に出す', async t => {
  const f = await fixture(), context = await createContext(f.config, { db: f.db, mailer: f.mailer }), app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const sender = await f.person('Sender'), receiver = await f.person('Receiver');
  const call = (who: { token: string }, method: 'GET' | 'POST', url: string, payload?: object) =>
    app.inject({ method, url, headers: { authorization: 'Bearer ' + who.token }, ...(payload ? { payload } : {}) });
  const asked = await call(sender, 'POST', '/api/requests', { to: receiver.actor.id,
    operation: { name: 'principal.create', input: { ownerId: '$approver', name: 'Project' } } });
  assert.equal(asked.statusCode, 201, asked.body);
  context.definitions.definitions.delete('principal.create');
  const listed = await call(receiver, 'GET', '/api/requests');
  assert.equal(listed.statusCode, 200, listed.body);
  const shown = listed.json().items.find((item: { id: string }) => item.id === asked.json().id);
  assert.deepEqual(shown.operation.title, { ja: 'principal.create', en: 'principal.create' });
  const opened = await call(receiver, 'GET', '/api/requests/' + asked.json().id);
  assert.equal(opened.statusCode, 200, opened.body);
  assert.equal(opened.json().operation.name, 'principal.create');
});

test('同じ依頼を同時に送っても一件になり、承認者が入力した値で一度だけ実行する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token), receiver = f.client.api;
  const body = { id: crypto.randomUUID(), to: f.owner.actor.id, operation: {
    name: 'principal.create', input: { name: '', ownerId: '$approver' }, inputs: [{ pointer: '/name', label: 'Name' }] } };
  const send = () => sender.json('/api/requests', { method: 'POST', body }, RequestView);
  const [first, retry] = await Promise.all([send(), send()]);
  assert.equal(first.id, retry.id);
  await assert.rejects(sender.json('/api/requests', { method: 'POST', body: { ...body, message: 'Different request' } }), { code: 'request_conflict' });
  const path = '/api/requests/' + first.id + '/approve';
  await assert.rejects(receiver.json(path, { method: 'POST', body: { values: { '/ownerId': f.stranger.actor.id } } }), { code: 'unexpected_input' });
  const approve = () => receiver.json(path, { method: 'POST', body: { values: { '/name': 'Approved project' } } }, RequestView);
  const outcomes = await Promise.allSettled([approve(), approve()]);
  assert.equal(outcomes.filter(outcome => outcome.status === 'fulfilled').length, 1);
  const rejected = outcomes.find(outcome => outcome.status === 'rejected');
  assert.equal(rejected?.reason.code, 'request_answered');
  const approved = await send();
  assert.equal(approved.state, 'approved');
  const made = await receiver.json('/api/operations/' + approved.performed!.id, {}, OperationView);
  assert.equal(made.state, 'succeeded');
  assert.equal((made.result as { name: string }).name, 'Approved project');
  assert.equal((await f.db.all('SELECT id FROM principals WHERE name=$1', ['Approved project'])).length, 1);
});
