import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { principal } from '../server/authorization.js';
import { ApprovalRequest } from '../shared/contracts.js';
import { flowFixture } from './flow-support.js';
import { Execution } from '../shared/executions.js';

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
  assert.equal(answer.json().state, 'accepted');
  assert.equal(await context.authorization.holds(device.actor.id, principal(person.actor.id), 'use'), true);
  assert.equal(await context.authorization.can(person.actor, principal(device.actor.id), 'manage_credentials'), true);
  const polled = await app.inject({ url: '/api/requests/' + pending.id, headers });
  assert.equal(polled.json().state, 'accepted');
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
  assert.equal(answer.json().state, 'accepted');
  const execution = await app.inject({ url: '/api/executions/' + asked.json().executionId, headers });
  assert.equal(execution.json().results[0].name, 'New group');
  const repeated = await app.inject({
    method: 'POST',
    url: '/api/requests/' + asked.json().id + '/redeem',
    payload: { token: secret },
  });
  assert.equal(repeated.statusCode, 400, repeated.body);
});

test('実行環境の更新待機中と再開後も接続依頼と実行先を確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const environmentId = f.environment.manifest.id, sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'connection.connect', input: {
      ownerId: f.owner.actor.id, methodId: 'huggingface:token', environmentId,
    } }] } }, ApprovalRequest);
  for (const paused of [true, false]) {
    await f.context.delegation.maintenance({ id: f.executor.binding.principalId }, environmentId, paused);
    const request = await f.client.api.json('/api/requests/' + asked.id, {}, ApprovalRequest);
    assert.equal(request.canRespond, true);
    assert.equal(request.state, 'pending');
    const headers = { authorization: 'Bearer ' + f.owner.token };
    const environment = await f.app.inject({ url: '/api/resources/' + environmentId, headers });
    assert.equal(environment.statusCode, 200, environment.body);
    assert.equal(environment.json().data.executorId, f.executor.binding.principalId);
    assert.equal(environment.json().data.state, 'running');
    const available = await f.app.inject({
      url: '/api/principals/' + f.owner.actor.id + '/resources?kind=environment&limit=200', headers,
    });
    assert.equal(available.statusCode, 200, available.body);
    assert.ok(available.json().items.some((item: { id: string }) => item.id === environmentId));
  }
});

test('依頼の承諾後にトークンを暗号化して保存し、実行から作成結果を確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: 'github:token', name: 'Requested connection' } }] } }, ApprovalRequest);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(answer.state, 'accepted');
  const started = await f.operations.continue(asked.executionId, { fields: { token: 'owner-provided-key' } });
  if (!('kind' in started) || started.kind !== 'saved') throw new Error('Expected a saved connection.');
  const completed = await sender.json('/api/executions/' + asked.executionId, {}, Execution);
  assert.equal(completed.state, 'succeeded');
  assert.equal((completed.results[0] as { id: string }).id, started.resource.id);
});

test('依頼を取り消すと入力待ちの実行を取り消し、その実行の再開を拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ name: 'connection.connect', input: { ownerId: f.owner.actor.id,
      methodId: 'render:token', name: 'Requested' } }] } }, ApprovalRequest);
  assert.equal((await sender.json('/api/requests/' + asked.id + '/cancel', { method: 'POST', body: {} }, ApprovalRequest)).state, 'cancelled');
  const resumed = await f.operations.continue(asked.executionId, { fields: { token: 'provided-key' } });
  assert.equal('state' in resumed && resumed.state, 'cancelled');
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
    const response = await app.inject({ method: 'POST', url: '/api/requests', headers, payload: { ...(to ? { to } : {}), operations } });
    assert.equal(response.statusCode, 201, response.body);
    const request = ApprovalRequest.parse(response.json());
    const execution = await app.inject({ url: '/api/executions/' + request.executionId, headers });
    assert.equal(execution.statusCode, 200, execution.body);
    return Execution.parse(execution.json()).operations.map(operation => operation.title);
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
