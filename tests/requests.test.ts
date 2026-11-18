import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { confirmedCall } from './confirmation-support.js';
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
  const request = await confirmedCall(app, device.keys, {
    method: 'POST',
    url: '/api/requests',
    headers,
    payload: {
      operations: [
        {
          name: 'relation.draw',
          input: { relation: 'delegate', objectId: '$approver', subjectId: device.actor.id },
        },
      ],
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
  assert.deepEqual(answer.json().performed.map((made: { state: string }) => made.state), ['succeeded']);
  assert.equal(await context.authorization.holds(device.actor.id, principal(person.actor.id), 'use'), true);
  assert.equal(await context.authorization.can(person.actor, principal(device.actor.id), 'manage_credentials'), true);
  const polled = await app.inject({ url: '/api/requests/' + pending.id, headers });
  assert.equal(polled.json().state, 'approved');
});

test('依頼専用リンクでその依頼を承認し、通常のAPI操作を拒否する', async (t) => {
  const f = await fixture(),
    context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => {
    await app.close();
    await f.close();
  });
  const owner = await f.person('Owner'),
    sender = await f.person('Sender');
  const asked = await app.inject({
    method: 'POST',
    url: '/api/requests',
    headers: { authorization: 'Bearer ' + sender.token },
    payload: {
      to: owner.actor.id,
      operations: [
        { name: 'principal.create', input: { name: '', ownerId: owner.actor.id },
          inputs: [{ pointer: '/name', label: 'Group name' }] },
      ],
    },
  });
  assert.equal(asked.statusCode, 201, asked.body);
  const link = await context.requests.link(owner.actor, asked.json().id),
    secret = new URLSearchParams(new URL(link.url).hash.slice(1)).get('token')!;
  const redeemed = await app.inject({
    method: 'POST',
    url: '/api/requests/' + asked.json().id + '/redeem',
    payload: { token: secret },
  });
  assert.equal(redeemed.statusCode, 200, redeemed.body);
  const ordinary = await f.authentication.session(sender.actor.id, sender.credential.id);
  const cookie = redeemed.cookies.find((value) => value.name === 'foundation_request')!,
    headers = {
      cookie: 'foundation_session=' + ordinary.token + '; ' + cookie.name + '=' + cookie.value,
      origin: f.config.origin,
    };
  const session = await app.inject({ url: '/api/session', headers });
  assert.equal(session.json().requestId, asked.json().id);
  assert.equal(session.json().principal.id, owner.actor.id);
  const direct = await app.inject({
    method: 'PATCH',
    url: '/api/principals/' + owner.actor.id,
    headers,
    payload: { name: 'Unrelated change' },
  });
  assert.equal(direct.statusCode, 403, direct.body);
  const answer = await app.inject({
    method: 'POST',
    url: '/api/requests/' + asked.json().id + '/approve',
    headers,
    payload: { values: [{ '/name': 'New group' }] },
  });
  assert.equal(answer.statusCode, 200, answer.body);
  assert.equal(answer.json().state, 'approved');
  const made = await app.inject({ url: '/api/operations/' + answer.json().performed[0].id, headers });
  assert.equal(made.statusCode, 200, made.body);
  assert.equal(made.json().result.name, 'New group'); assert.equal(made.json().canPerform, false);
  const performing = await app.inject({ method: 'POST', url: '/api/operations/' + answer.json().performed[0].id + '/perform', headers, payload: {} });
  assert.equal(performing.statusCode, 403, performing.body);
  const repeated = await app.inject({
    method: 'POST',
    url: '/api/requests/' + asked.json().id + '/redeem',
    payload: { token: secret },
  });
  assert.equal(repeated.statusCode, 400, repeated.body);
});

test('依頼の承認後にトークンを手元で暗号化して保存し、依頼した側も行われた操作の結果を確かめる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: 'github:token', name: 'Requested connection' } }] } }, RequestView);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.equal(answer.state, 'approved'); assert.equal(answer.performed[0]?.state, 'stopped');
  const started = await f.operations.continue(answer.performed[0]!.id, { fields: { token: 'owner-provided-key' } });
  if (!('kind' in started) || started.kind !== 'saved') throw new Error('Expected a saved connection.');
  const made = await sender.json('/api/operations/' + answer.performed[0]!.id, {}, OperationView);
  assert.equal(made.state, 'succeeded'); assert.deepEqual(made.request, { id: asked.id, position: 0 });
  assert.equal((made.result as { id: string }).id, started.resource.id);
  assert.equal(JSON.stringify(made).includes('owner-provided-key'), false);
});

test('依頼を取り下げると、承認も操作もされないまま取り下げとして残る', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: 'render:token', name: 'Requested' } }] } }, RequestView);
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/withdraw', { method: 'POST', body: {} }), { code: 'forbidden' });
  const withdrawn = await sender.json('/api/requests/' + asked.id + '/withdraw', { method: 'POST', body: {} }, RequestView);
  assert.equal(withdrawn.state, 'withdrawn'); assert.equal(withdrawn.canWithdraw, false);
  await assert.rejects(f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }), { code: 'request_answered' });
  assert.deepEqual((await f.client.api.json('/api/requests/' + asked.id, {}, RequestView)).performed, []);
});

test('断った依頼と期限が切れた依頼は承認できず、操作も行われない', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const ask = (name: string) => sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'principal.create', input: { ownerId: '$approver', name } }] } }, RequestView);
  const declined = await ask('Declined group'), expired = await ask('Expired group');
  assert.equal((await f.client.api.json('/api/requests/' + declined.id + '/decline', { method: 'POST', body: {} }, RequestView)).state, 'declined');
  await f.context.db.pool.query("UPDATE requests SET expires_at=now()-interval '1 second' WHERE id=$1", [expired.id]);
  assert.equal((await sender.json('/api/requests/' + expired.id, {}, RequestView)).state, 'expired');
  for (const request of [declined, expired])
    await assert.rejects(f.client.api.json('/api/requests/' + request.id + '/approve', { method: 'POST', body: {} }), { code: 'request_answered' });
  const groups = await f.context.db.all("SELECT id FROM principals WHERE name IN ('Declined group','Expired group')");
  assert.equal(groups.length, 0);
});

test('依頼の各操作は、承認する人が読む名前を日本語と英語で持ち、呼び出しの形は見せずに済む', async (t) => {
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
  const ask = async (operations: unknown[], to?: string) => {
    const response = await confirmedCall(app, device.keys, { method: 'POST', url: '/api/requests', headers,
      payload: { ...(to ? { to } : {}), operations } });
    assert.equal(response.statusCode, 201, response.body);
    return RequestView.parse(response.json()).operations.map(operation => operation.title);
  };
  assert.deepEqual(await ask([{ name: 'relation.draw', input: { relation: 'delegate', objectId: '$approver', subjectId: device.actor.id } }]),
    [{ ja: '権限を委任する', en: 'Delegate access' }]);
  const target = '00000000-0000-4000-8000-000000000001';
  assert.deepEqual(await ask([
    { name: 'relation.draw', input: { relation: 'reader', objectId: target, subjectId: device.actor.id } },
    { name: 'principal.rename', input: { id: device.actor.id, name: 'renamed' } },
    { name: 'resource.delete', input: { id: target } },
    { name: 'connection.connect', input: { ownerId: '$approver', methodId: 'github:token' } },
  ], person.actor.id), [
    { ja: '権限を渡す', en: 'Give a permission' },
    { ja: 'プリンシパルを変更する', en: 'Change a principal' },
    { ja: '項目を削除する', en: 'Delete an item' },
    { ja: 'サービスに接続する', en: 'Connect a service' },
  ]);
});
