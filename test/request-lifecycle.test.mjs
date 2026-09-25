import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { fixture, USER_A } from './helpers.mjs';
import { requestResultView } from '../web/request-view.js';

async function ask(f, token, kind, input) {
  const answer = await f.request('/v1/requests', { method: 'POST', token, data: { kind, input } });
  assert.equal(answer.status, 201, answer.text);
  return answer.json.request;
}

test('明示した依頼の種類と内容を保存し、従来の入力形式も同じ依頼として扱う', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'connect', { connector: 'gmail.readonly' });
  const legacy = await f.request('/v1/requests', { method: 'POST', token: key.token, data: { connector: 'gmail.readonly' } });
  assert.equal(legacy.json.request.id, request.id);
  assert.equal(request.kind, 'connect');
  assert.deepEqual(request.input, { connector: 'gmail.readonly' });
  for (const data of [
    { kind: 'other', input: {} }, { kind: 'connect', input: { fields: [] } },
    { kind: 'store', input: { connector: 'gmail.readonly' } },
    { kind: 'connect', input: { connector: 'gmail.readonly' }, store: { name: 'x', label: 'x' } },
  ]) assert.equal((await f.request('/v1/requests', { method: 'POST', token: key.token, data })).status, 400);
});

test('接続の失効・削除後も依頼の完了と結果を維持する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'connect', { connector: 'gmail.readonly' });
  const start = await f.request('/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly', request_id: request.id } });
  await f.callback(new URL(start.json.url));
  const read = async () => (await f.request('/v1/requests/' + request.id, { token: key.token })).json.request;
  const done = await read(), id = done.result.connection_id;
  assert.equal(done.status, 'done');
  f.app.connections.reconnectRequired(f.app.connections.get(USER_A, id));
  assert.equal((await f.request('/v1/connections', { token: key.token })).json.connections[0].status, 'reconnect_required');
  for (const remove of [false, true]) {
    if (remove) await f.request('/v1/connections/' + id, { method: 'DELETE', data: { revoke: false } });
    const current = await read();
    assert.equal(current.status, 'done');
    assert.deepEqual(current.result, done.result);
    assert.equal((await f.request('/v1/requests?status=done', { token: key.token })).json.requests[0].status, 'done');
  }
  f.app.connections.connectors.connectors.delete('gmail.readonly');
  assert.deepEqual((await read()).result, done.result);
});

test('保存値の名前変更や削除後も依頼には完了時の保存名を返す', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'store', { fields: [{ name: 'first', label: 'トークン' }] });
  const complete = await f.request('/v1/requests/' + request.id + '/done', { method: 'POST', data: { entries: [{ name: 'first', content: 'fixture-secret' }] } });
  assert.equal(complete.status, 200);
  await f.request('/v1/secrets?name=first', { method: 'PATCH', data: { name: 'renamed' } });
  await f.request('/v1/secrets?name=renamed', { method: 'DELETE', data: {} });
  const done = (await f.request('/v1/requests/' + request.id, { token: key.token })).json.request;
  assert.equal(done.status, 'done');
  assert.deepEqual(done.result, { names: ['first'] });
});

test('キー失効時に未完了の依頼を取り消し、同じトークンの再承認後も以前の依頼へのアクセスを拒否する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const doneRequest = await ask(f, key.token, 'store', { fields: [{ name: 'kept', label: 'トークン' }] });
  await f.request('/v1/requests/' + doneRequest.id + '/done', { method: 'POST', data: { entries: [{ name: 'kept', content: 'fixture-secret' }] } });
  const pending = await ask(f, key.token, 'connect', { connector: 'gmail.readonly' });
  await f.request('/v1/keys/' + key.id, { method: 'DELETE' });
  const cancelled = (await f.request('/v1/requests/' + pending.id)).json.request;
  assert.equal(cancelled.status, 'cancelled');
  assert.equal(cancelled.reason, 'requester_revoked');
  const done = (await f.request('/v1/requests/' + doneRequest.id)).json.request;
  assert.equal(done.status, 'done');
  assert.deepEqual(done.result, { names: ['kept'] });
  assert.equal((await f.request('/v1/requests/' + doneRequest.id, { token: key.token })).status, 401);
  assert.equal((await f.request('/v1/requests', { token: key.token })).status, 401);
  await f.approveKey(key.token, '再承認');
  assert.equal((await f.request('/v1/requests/' + doneRequest.id, { token: key.token })).status, 404);
  assert.deepEqual((await f.request('/v1/requests', { token: key.token })).json.requests, []);
  assert.equal((await f.request('/v1/secrets', { token: key.token })).json.secrets[0].name, 'kept');
});

test('承認依頼の完了結果を保ち、失効キーの認証を拒否する', async t => {
  const f = await fixture(t), token = 'fdn_' + 'a'.repeat(43);
  const approval = await f.approveKey(token);
  const approved = (await f.request('/v1/key-requests/' + approval.id)).json.request;
  assert.equal(approved.kind, 'approve');
  assert.equal(approved.status, 'done');
  await f.request('/v1/keys/' + approved.result.key_id, { method: 'DELETE' });
  assert.deepEqual((await f.request('/v1/key-requests/' + approval.id)).json.request, approved);
  assert.equal((await f.request('/v1/keys/current', { token })).status, 401);
});

test('APIの認証成功をキーの最終利用として記録する', async t => {
  const f = await fixture(t), key = await f.issueKey();
  assert.equal(key.last_used_at, null);
  const before = Date.now();
  assert.equal((await f.request('/v1/connections', { token: key.token })).status, 200);
  const current = (await f.request('/v1/keys')).json.keys[0];
  assert.ok(Date.parse(current.last_used_at) >= before);
  assert.ok(Date.parse(current.last_used_at) <= Date.now());
  assert.equal((await f.request('/v1/keys')).json.keys[0].last_used_at, current.last_used_at);
});

for (const identity of ['キー', 'セッション']) test(`アップロード中に${identity}が失効した場合は保存を拒否して元の値を維持する`, async t => {
  const f = await fixture(t), key = await f.issueKey();
  await f.request('/v1/secrets?name=value', { method: 'PUT', raw: 'original' });
  const started = new Promise(resolve => f.app.server.once('request', req => req.once('readable', resolve)));
  let upload;
  const completed = new Promise((resolve, reject) => {
    upload = httpRequest(f.base + '/v1/secrets?name=value', { method: 'PUT', headers: {
      'content-type': 'application/octet-stream',
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
  upload.write('replacement-');
  await started;
  if (identity === 'キー') await f.request('/v1/keys/' + key.id, { method: 'DELETE' });
  else await f.request('/v1/session', { method: 'DELETE' });
  upload.end('value');
  const result = await completed;
  assert.equal(result.status, 401, result.text);
  assert.equal(f.app.secrets.content(f.app.secrets.at(USER_A, 'value')).toString(), 'original');
});

test('保存と依頼完了を一緒に確定し、失敗した場合は再試行可能にする', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const request = await ask(f, key.token, 'store', { fields: [{ name: 'value', label: '値' }] });
  const original = f.app.requests.done;
  f.app.requests.done = () => { throw new Error('fixture completion failure'); };
  assert.throws(() => f.app.requestActions.save(request.id, USER_A, [{ name: 'value', content: 'fixture-value' }]), /fixture completion failure/);
  assert.equal(f.app.requests.get(request.id).status, 'pending');
  assert.deepEqual(f.app.secrets.list(USER_A), []);
  f.app.requests.done = original;
  assert.deepEqual(f.app.requestActions.save(request.id, USER_A, [{ name: 'value', content: 'fixture-value' }]), { names: ['value'] });
  assert.equal(f.app.secrets.content(f.app.secrets.at(USER_A, 'value')).toString(), 'fixture-value');
});

test('依頼の種類に合った完了表示と移動先を返す', () => {
  for (const [kind, title, href] of [['connect', '接続しました', '/connections'], ['store', '保存しました', '/secrets'], ['approve', '承認しました', '/keys']]) {
    const view = requestResultView({ kind, status: 'done' });
    assert.equal(view.title, title); assert.equal(view.href, href); assert.equal(view.completed, true);
  }
  const unknown = requestResultView({ kind: '__proto__', status: 'done' });
  assert.equal(unknown.title, '依頼を確認できません');
  assert.equal(unknown.href, '/');
});
