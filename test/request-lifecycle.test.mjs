import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fixture, USER_A } from './helpers.mjs';
import { requestResultView } from '../web/request-view.js';

async function ask(f, token, kind, input) {
  const answer = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: { actor: 'relation', store: 'secret', connect: 'connection', app: 'app' }[kind], ...(kind === 'actor' ? { relation: 'agent' } : input) }] } });
  assert.equal(answer.status, 201, answer.text);
  return answer.json.request;
}

test('依頼の種類と内容を保存し、同じ依頼を二度出しても一つとして扱う', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'connect', { service: 'google' });
  const again = await f.request('/v1/requests', { method: 'POST', token: key.token, data: { authorization_details: [{ type: 'connection', service: 'google' }] } });
  assert.equal(again.json.request.id, request.id);
  assert.deepEqual(request.authorization_details, [{ type: 'connection', service: 'google', auth_scheme: 'oauth' }]);
  for (const data of [
    { authorization_details: [{ type: 'other' }] }, { authorization_details: [{ type: 'connection', fields: [] }] },
    { authorization_details: [{ type: 'secret', service: 'google' }] }, { service: 'google' },
  ]) assert.equal((await f.request('/v1/requests', { method: 'POST', token: key.token, data })).status, 400);
});

test('接続の失効・削除後も依頼の完了と結果を維持する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'connect', { service: 'google' });
  const start = await f.request('/v1/principals/me/connections', { method: 'POST', data: { service: 'google', request_id: request.id } });
  await f.callback(new URL(start.json.url));
  const read = async () => (await f.request('/v1/requests/' + request.id, { token: key.token })).json.request;
  const done = await read(), id = done.result.connection_id;
  assert.equal(done.status, 'granted');
  f.app.connections.reconnectRequired(f.app.connections.held(USER_A, id));
  assert.equal((await f.request('/v1/principals/me/resources?kind=connection', { token: key.token })).json.resources[0].status, 'reconnect_required');
  for (const remove of [false, true]) {
    if (remove) await f.request('/v1/resources/' + id, { method: 'DELETE', data: { revoke: false } });
    const current = await read();
    assert.equal(current.status, 'granted');
    assert.deepEqual(current.result, done.result);
    assert.equal((await f.request('/v1/requests?status=granted', { token: key.token })).json.requests[0].status, 'granted');
  }
  f.app.services.catalog.delete('google');
  assert.deepEqual((await read()).result, done.result);
});

test('保存値の名前変更や削除後も依頼には完了時の保存名を返す', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'store', { fields: [{ name: 'first', label: 'トークン' }] });
  const complete = await f.request('/v1/requests/' + request.id + '/grant', { method: 'POST', data: { entries: [{ name: 'first', content: 'fixture-secret' }] } });
  assert.equal(complete.status, 200);
  await f.request('/v1/principals/me/resources?kind=secret&name=first', { method: 'PATCH', data: { name: 'renamed' } });
  await f.request('/v1/principals/me/resources?kind=secret&name=renamed', { method: 'DELETE', data: {} });
  const done = (await f.request('/v1/requests/' + request.id, { token: key.token })).json.request;
  assert.equal(done.status, 'granted');
  assert.deepEqual(done.result, { names: ['first'], replaced: [] });
});

test('キー失効時に未完了の依頼を取り消し、同じトークンの再承認後も以前の依頼へのアクセスを拒否する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const doneRequest = await ask(f, key.token, 'store', { fields: [{ name: 'kept', label: 'トークン' }] });
  await f.request('/v1/requests/' + doneRequest.id + '/grant', { method: 'POST', data: { entries: [{ name: 'kept', content: 'fixture-secret' }] } });
  const pending = await ask(f, key.token, 'connect', { service: 'google' });
  await f.request('/v1/principals/' + key.id, { method: 'DELETE', data: {} });
  const cancelled = (await f.request('/v1/requests/' + pending.id)).json.request;
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(cancelled.reason, 'requester_revoked');
  const done = (await f.request('/v1/requests/' + doneRequest.id)).json.request;
  assert.equal(done.status, 'granted');
  assert.deepEqual(done.result, { names: ['kept'], replaced: [] });
  assert.equal((await f.request('/v1/requests/' + doneRequest.id, { token: key.token })).status, 401);
  assert.equal((await f.request('/v1/requests', { token: key.token })).status, 401);
  const again = await f.approveKey('再承認');
  assert.equal((await f.request('/v1/requests/' + doneRequest.id, { token: again.token })).status, 404);
  assert.deepEqual((await f.request('/v1/requests', { token: again.token })).json.requests.map(row => row.authorization_details[0].relation), ['agent'], 'a newly approved machine is a new principal, with only its own asking behind it');
  assert.equal((await f.request('/v1/principals/me/resources?kind=secret', { token: again.token })).json.resources[0].name, 'kept');
});

test('承認依頼の完了結果を保ち、失効キーの認証を拒否する', async t => {
  const f = await fixture(t);
  const approval = await f.approveKey(), token = approval.token;
  const approved = (await f.request('/v1/requests/' + approval.id)).json.request;
  assert.equal(approved.authorization_details[0].relation, 'agent');
  assert.equal(approved.status, 'granted');
  await f.request('/v1/principals/' + approved.from, { method: 'DELETE', data: {} });
  assert.deepEqual((await f.request('/v1/requests/' + approval.id)).json.request, approved);
  assert.equal((await f.request('/v1/principals/me', { token })).status, 401);
});

test('APIの認証成功をキーの最終利用として記録する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const mine = async () => (await f.request('/v1/principals/' + key.id)).json.principal.keys[0];
  // Issued and used once already: the machine published its key with it.
  const first = (await mine()).last_used_at;
  assert.ok(first);
  await new Promise(resolve => setTimeout(resolve, 5));
  const before = Date.now();
  assert.equal((await f.request('/v1/principals/me/resources?kind=connection', { token: key.token })).status, 200);
  const current = await mine();
  assert.ok(Date.parse(current.last_used_at) >= before);
  assert.ok(Date.parse(current.last_used_at) > Date.parse(first));
  assert.ok(Date.parse(current.last_used_at) <= Date.now());
  assert.equal((await mine()).last_used_at, current.last_used_at);
});

for (const identity of ['キー', 'セッション']) test(`アップロード中に${identity}が失効した場合は保存を拒否して元の値を維持する`, async t => {
  const f = await fixture(t), key = await f.issueKey();
  await f.request('/v1/principals/me/resources?kind=secret&name=value', { method: 'PUT', raw: 'original' });
  const started = new Promise(resolve => f.app.server.once('request', req => req.once('readable', resolve)));
  let upload;
  const completed = new Promise((resolve, reject) => {
    upload = httpRequest(f.base + '/v1/principals/me/resources?kind=secret&name=value', { method: 'PUT', headers: {
      'content-type': 'application/json',
      ...(identity === 'キー' ? { authorization: 'Bearer ' + key.token } : { cookie: f.cookie(), origin: f.base }),
    } }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }));
      res.on('error', reject);
    });
    upload.on('error', reject);
  });
  t.after(() => upload.destroy());
  upload.write('{"plain":"cmVwbGFjZW1lbnQt');
  await started;
  if (identity === 'キー') await f.request('/v1/principals/' + key.id, { method: 'DELETE', data: {} });
  else await f.request('/v1/session', { method: 'DELETE' });
  upload.end('dmFsdWU"}');
  const result = await completed;
  assert.equal(result.status, 401, result.text);
  assert.equal(f.app.secrets.open(f.app.secrets.at(USER_A, 'value')).toString(), 'original');
});

test('保存と依頼完了を一緒に確定し、失敗した場合は再試行可能にする', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'store', { fields: [{ name: 'value', label: '値' }] });
  const original = f.app.requests.done;
  f.app.requests.done = () => { throw new Error('fixture completion failure'); };
  const entry = { name: 'value', ...await f.sealed('fixture-value', {}) };
  assert.throws(() => f.app.requestActions.save(request.id, USER_A, [entry]), /fixture completion failure/);
  assert.equal(f.app.requests.get(request.id).status, 'pending');
  assert.deepEqual(f.app.secrets.list(USER_A), []);
  f.app.requests.done = original;
  assert.deepEqual(f.app.requestActions.save(request.id, USER_A, [entry]), { names: ['value'], replaced: [] });
  assert.equal(f.app.secrets.open(f.app.secrets.at(USER_A, 'value')).toString(), 'fixture-value');
});

test('依頼の種類に合った完了表示と移動先を返す', () => {
  for (const [type, title, href, label] of [['connection', '接続しました', '/services', 'サービス'], ['secret', '登録しました', '/secrets', 'シークレット'], ['relation', '許可しました', '/principals', 'プリンシパル']]) {
    const view = requestResultView({ authorization_details: [{ type }], status: 'granted' });
    assert.equal(view.title, title); assert.equal(view.href, href); assert.equal(view.completed, true);
    assert.equal(view.label, label);
  }
  const unknown = requestResultView({ authorization_details: [{ type: '__proto__' }], status: 'granted' });
  assert.equal(unknown.title, '依頼を確認できません');
  assert.equal(unknown.href, '/');
});
