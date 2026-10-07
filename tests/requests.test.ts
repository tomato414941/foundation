import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { ApprovalRequest } from '../shared/contracts.js';
import { flowFixture } from './flow-support.js';

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
          method: 'POST',
          path: '/api/relations',
          body: { relation: 'agent', principalId: '$approver', subjectId: device.actor.id },
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
  assert.equal(await context.authorization.uses(device.actor.id, person.actor.id), true);
  assert.equal(await context.authorization.principal(person.actor, device.actor.id, 'credentials'), true);
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
        { method: 'POST', path: '/api/principals', body: { name: 'New group', ownerId: owner.actor.id } },
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
    payload: {},
  });
  assert.equal(answer.statusCode, 200, answer.body);
  assert.equal(answer.json().state, 'approved');
  const repeated = await app.inject({
    method: 'POST',
    url: '/api/requests/' + asked.json().id + '/redeem',
    payload: { token: secret },
  });
  assert.equal(repeated.statusCode, 400, repeated.body);
});

test('接続の承認後に実行先で秘密を受け取り、暗号化した接続の作成結果を依頼元へ返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ method: 'CONNECT', path: '/api/connections', body: {
      ownerId: f.owner.actor.id, methodId: 'github:token', environmentId: f.environment.manifest.id,
    } }] } }, ApprovalRequest);
  const answer = await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  assert.equal(answer.state, 'running');
  assert.equal(new URL(answer.continueUrl!).searchParams.get('approval'), asked.id);
  const started = await f.connections.start({ ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id,
    methodId: 'github:token', method: await f.method('github:token'), name: 'Requested connection',
    fields: { token: 'owner-provided-key' }, approvalId: asked.id });
  assert.equal((await f.tick(started.flow.id)).kind, 'review');
  const connection = await f.accept(started.flow.id);
  const completed = await sender.json('/api/requests/' + asked.id, {}, ApprovalRequest);
  assert.equal(completed.state, 'approved');
  assert.equal((completed.results[0] as { id: string }).id, connection.id);
  assert.equal((await f.http(connection.id, 'GH_TOKEN'))?.ok, true);
  assert.equal(f.requests.at(-1)!.headers.authorization, 'Bearer owner-provided-key');
  assert.equal((await f.connections.progress(started.flow.id)).kind, 'connected');
});

test('承認依頼の取り消しで待機中の接続を止め、その依頼による再開を拒否する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const sender = f.api(f.stranger.token);
  const asked = await sender.json('/api/requests', { method: 'POST', body: { to: f.owner.actor.id,
    operations: [{ method: 'CONNECT', path: '/api/connections', body: {
      ownerId: f.owner.actor.id, methodId: 'render:token',
    } }] } }, ApprovalRequest);
  await f.client.api.json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, ApprovalRequest);
  const input = { ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id,
    methodId: 'render:token', method: await f.method('render:token'), name: 'Requested',
    fields: { token: 'provided-key' }, approvalId: asked.id };
  const started = await f.connections.start(input);
  assert.equal((await sender.json('/api/requests/' + asked.id + '/cancel', { method: 'POST', body: {} }, ApprovalRequest)).state, 'cancelled');
  const progress = await f.tick(started.flow.id);
  assert.equal(progress.kind, 'failed');
  if (progress.kind === 'failed') assert.equal(progress.task.state, 'cancelled');
  await assert.rejects(f.connections.start(input), { code: 'request_answered' });
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
    return ApprovalRequest.parse(response.json()).operations.map((operation) => operation.title);
  };
  assert.deepEqual(await ask([{ method: 'POST', path: '/api/relations', body: { relation: 'agent', principalId: '$approver', subjectId: device.actor.id } }]),
    [{ ja: 'アクセスを許可する', en: 'Allow access' }]);
  const target = '00000000-0000-4000-8000-000000000001';
  assert.deepEqual(await ask([
    { method: 'POST', path: '/api/relations', body: { relation: 'viewer', principalId: target, subjectId: device.actor.id } },
    { method: 'PATCH', path: '/api/principals/' + device.actor.id, body: { name: 'renamed' } },
    { method: 'DELETE', path: '/api/resources/' + target },
    { method: 'CONNECT', path: '/api/connections', body: { ownerId: '$approver', methodId: 'github-token' } },
  ], person.actor.id), [
    { ja: '関係を結ぶ', en: 'Add a relation' },
    { ja: 'プリンシパルを変更する', en: 'Change a principal' },
    { ja: '項目を削除する', en: 'Delete an item' },
    { ja: 'サービスに接続する', en: 'Connect a service' },
  ]);
});
