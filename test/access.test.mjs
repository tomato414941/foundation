import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fixture, USER_A, USER_B } from './helpers.mjs';

const revoke = (f, id, { as = 'me', ...options } = {}) => f.request(`/v1/principals/${as}/access/${id}`, { method: 'DELETE', data: {}, ...options });
async function ask(f, agent, to, kind = 'store') {
  const input = kind === 'store' ? { fields: [{ name: 'requested', label: '値', readable: true }] } : { service: 'google' };
  const result = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { authorization_details: [{ type: { actor: 'relation', store: 'secret', connect: 'connection', app: 'app' }[kind], ...(kind === 'actor' ? { relation: 'agent' } : input) }], to } });
  assert.equal(result.status, 201, result.text);
  return result.json.request;
}

test('アクセス許可と個別の閲覧・編集権限を取り消し、相手と保存データを維持する', async t => {
  const f = await fixture(t), agent = await f.issueKey(), other = await f.issueKey('other');
  const given = await f.keep('secret', 'private', 'owner-value');
  const written = await f.keep('secret', 'written', 'actor-value', { token: agent.token });
  f.app.principals.relate(agent.id, 'viewer', 'resource', given.json.resource.id);
  f.app.principals.relate(other.id, 'viewer', 'resource', given.json.resource.id);
  await f.handEnvelope(given.json.resource.id, { token: agent.token });
  await f.handEnvelope(given.json.resource.id, { token: other.token });
  await f.keep('secret', 'own', 'own-value', { token: agent.token, as: agent.id });
  const second = await f.request('/v1/principals/' + agent.id + '/credentials', { method: 'POST', data: { kind: 'key' } });
  assert.equal(second.status, 201);
  assert.equal((await f.read('secret', 'private', { token: agent.token })).text, 'owner-value');
  assert.equal((await revoke(f, agent.id)).status, 200);
  for (const token of [agent.token, second.json.token]) {
    const me = await f.request('/v1/principals/me', { token });
    assert.equal(me.status, 200); assert.equal(me.json.principal.id, agent.id);
    assert.deepEqual(me.json.principal.acts_for, []);
    assert.equal(me.json.principal.keys.length, 2);
    assert.equal((await f.request('/v1/principals/' + USER_A + '/resources?kind=connection', { token })).status, 403);
    for (const saved of [given, written]) {
      assert.equal((await f.request(`/v1/resources/${saved.json.resource.id}/content`, { token })).status, 403);
      assert.equal((await f.request(`/v1/resources/${saved.json.resource.id}/content`, { token, method: 'PUT', raw: 'changed' })).status, 403);
    }
    const delivered = await f.request('/v1/principals/' + USER_A + '/injections', { method: 'POST', token, data: { names: [{ name: 'private', as: 'VALUE' }] } });
    assert.equal(delivered.status, 403);
    assert.equal((await f.read('secret', 'own', { token, as: agent.id })).text, 'own-value');
  }
  assert.equal((await f.read('secret', 'private')).text, 'owner-value');
  assert.equal((await f.read('secret', 'written')).text, 'actor-value');
  assert.equal((await f.read('secret', 'private', { token: other.token })).text, 'owner-value');
  assert.equal((await revoke(f, agent.id)).status, 200, '取り消しを再送しても完了する');
});

test('自分宛ての未完了依頼を取り消し、他のアカウントの権限・依頼・共有を維持する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const pendingA = await ask(f, agent, USER_A), connectA = await ask(f, agent, USER_A, 'connect');
  const completed = await f.request('/v1/requests/' + pendingA.id + '/grant', { method: 'POST', data: { entries: [{ name: 'kept', content: 'value' }] } });
  assert.equal(completed.status, 200);
  const nextA = await ask(f, agent, USER_A);
  await f.signin('other@example.test');
  const approval = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { authorization_details: [{ type: 'relation', relation: 'agent' }], to: USER_B } });
  assert.equal(approval.status, 201);
  assert.equal((await f.request(`/v1/requests/${approval.json.request.id}/grant`, { method: 'POST', data: { user_code: approval.json.request.user_code } })).status, 200);
  const privateB = await f.keep('secret', 'private-b', 'other-value');
  f.app.principals.relate(agent.id, 'viewer', 'resource', privateB.json.resource.id);
  await f.handEnvelope(privateB.json.resource.id, { token: agent.token });
  const pendingB = await ask(f, agent, USER_B);
  await f.signin();
  assert.equal((await revoke(f, agent.id)).status, 200);
  const me = (await f.request('/v1/principals/me', { token: agent.token })).json;
  assert.deepEqual(me.principal.acts_for, [USER_B]);
  assert.equal((await f.read('secret', 'private-b', { token: agent.token, as: USER_B })).text, 'other-value');
  for (const request of [nextA, connectA]) {
    const current = (await f.request('/v1/requests/' + request.id, { token: agent.token })).json.request;
    assert.equal(current.status, 'cancelled'); assert.equal(current.reason, 'access_revoked');
    assert.equal((await f.request('/v1/requests/' + request.id + '/grant', { method: 'POST', data: { entries: [{ name: 'later', content: 'value' }] } })).status, 409);
  }
  assert.equal((await f.request('/v1/requests/' + pendingA.id, { token: agent.token })).json.request.status, 'granted');
  assert.equal((await f.request('/v1/requests/' + pendingB.id, { token: agent.token })).json.request.status, 'pending');
  await f.signin('other@example.test');
  assert.equal((await f.request('/v1/requests/' + pendingB.id + '/grant', { method: 'POST', data: { entries: [{ name: 'requested', content: 'b-value' }] } })).status, 200);
});

test('保有者が自分への許可だけを取り消し、相手の所有権を持たなくても停止する', async t => {
  const f = await fixture(t), agent = await f.issueKey(), stranger = await f.become('stranger');
  assert.equal((await revoke(f, agent.id, { token: stranger.token, as: USER_A })).status, 401);
  assert.equal((await revoke(f, agent.id, { token: agent.token, as: USER_A })).status, 403);
  assert.equal((await revoke(f, USER_A)).status, 400);
  assert.equal((await f.request('/v1/principals/' + USER_A + '/resources?kind=connection', { token: agent.token })).status, 200);
  f.app.principals.unrelate(USER_A, 'owner', 'principal', agent.id);
  assert.equal((await revoke(f, agent.id)).status, 200);
  assert.equal((await f.request('/v1/principals/me', { token: agent.token })).status, 200);
  assert.equal((await f.request('/v1/principals/' + USER_A + '/resources?kind=connection', { token: agent.token })).status, 401);
});

test('取り消した相手を同じキーで再承認し、以後に追加したデータも利用する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  await revoke(f, agent.id);
  const asked = await f.request('/v1/requests', { method: 'POST', token: agent.token, data: { authorization_details: [{ type: 'relation', relation: 'agent' }], binding_message: '作業の再開' } });
  assert.equal(asked.status, 201);
  assert.equal((await f.request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: { user_code: asked.json.request.user_code } })).status, 200);
  await f.keep('secret', 'later', 'later-value');
  const delivered = await f.request('/v1/principals/' + USER_A + '/injections', { method: 'POST', token: agent.token, data: { names: [{ name: 'later', as: 'VALUE' }] } });
  assert.equal(delivered.status, 200); assert.equal(delivered.json.injection.environment.VALUE, 'later-value');
});

test('オブジェクトへの個別共有も取り消し、進行中の取得を止めて保有者のデータを維持する', async t => {
  const bytes = new Map();
  let began, release;
  const started = new Promise(resolve => began = resolve);
  let paused = false;
  const space = { enabled: true,
    async put(prefix, id, content, contentType) { bytes.set(id, { content, contentType }); },
    async get(prefix, id) { if (paused) { began(); await new Promise(resolve => release = resolve); } return bytes.get(id); },
  };
  const f = await fixture(t, { space }), agent = await f.issueKey();
  const saved = await f.keep('object', 'private.txt', 'object-value', { token: agent.token });
  assert.equal(saved.status, 200);
  paused = true;
  const reading = f.request(`/v1/resources/${saved.json.resource.id}/content`, { token: agent.token });
  await started;
  await revoke(f, agent.id);
  release(); paused = false;
  assert.equal((await reading).status, 401);
  assert.equal((await f.request(`/v1/resources/${saved.json.resource.id}/content`, { token: agent.token })).status, 403);
  assert.equal((await f.read('object', 'private.txt')).text, 'object-value');
});

test('個別のキーを失効させても他のキーから同じアクセス許可を利用する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const second = await f.request('/v1/principals/' + agent.id + '/credentials', { method: 'POST', data: { kind: 'key' } });
  assert.equal((await f.request('/v1/principals/' + agent.id + '/credentials/' + agent.key_id, { method: 'DELETE', data: {} })).status, 200);
  assert.equal((await f.request('/v1/principals/me', { token: agent.token })).status, 401);
  const result = await f.request('/v1/principals/me', { token: second.json.token });
  assert.equal(result.status, 200); assert.deepEqual(result.json.principal.acts_for, [USER_A]);
  assert.equal((await f.request('/v1/principals/' + USER_A + '/resources?kind=connection', { token: second.json.token })).status, 200);
});

test('認証情報の更新中にアクセスを取り消すと受け渡しを止め、保有者は接続を利用し続ける', async t => {
  const f = await fixture(t), agent = await f.issueKey(), connection = await f.connection();
  f.expire(connection.id);
  let began, release;
  const started = new Promise(resolve => began = resolve);
  f.google.refreshHandler = () => { began(); return new Promise(resolve => release = resolve); };
  const delivering = f.inject(connection, { token: agent.token });
  await started;
  await revoke(f, agent.id);
  release();
  assert.equal((await delivering).status, 401);
  assert.equal((await f.inject(connection)).status, 200);
  assert.equal((await f.request('/v1/principals/me', { token: agent.token })).status, 200);
});

test('アップロード中にアクセスを取り消すと保存を拒否し、元の値を維持する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  await f.keep('secret', 'value', 'original');
  const started = new Promise(resolve => f.app.server.once('request', req => req.once('readable', resolve)));
  let upload;
  const completed = new Promise((resolve, reject) => {
    upload = httpRequest(f.base + '/v1/principals/' + USER_A + '/resources?kind=secret&name=value', { method: 'PUT', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + agent.token } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() })); res.on('error', reject);
    });
    upload.on('error', reject);
  });
  t.after(() => upload.destroy());
  upload.write('{"plain":"cmVwbGFjZW1lbnQt'); await started;
  assert.equal((await revoke(f, agent.id)).status, 200);
  upload.end('dmFsdWU"}');
  assert.equal((await completed).status, 401);
  assert.equal((await f.read('secret', 'value')).text, 'original');
});

test('接続認証の完了前にアクセスを取り消すと、取消済みの依頼として完了を拒否する', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const asked = await ask(f, agent, USER_A, 'connect');
  const started = await f.request('/v1/principals/me/connections', { method: 'POST', data: { service: 'google', request_id: asked.id } });
  assert.equal(started.status, 200);
  let began, release;
  const exchanging = new Promise(resolve => began = resolve);
  f.google.exchangeHandler = () => { began(); return new Promise(resolve => release = resolve); };
  const returning = f.callback(new URL(started.json.url));
  await exchanging;
  await revoke(f, agent.id);
  release();
  const callback = await returning;
  assert.match(callback.headers.get('location'), /result=failed/);
  assert.equal((await f.request('/v1/requests/' + asked.id)).json.request.status, 'cancelled');
  assert.deepEqual((await f.request('/v1/principals/me/resources?kind=connection')).json.resources, []);
});
