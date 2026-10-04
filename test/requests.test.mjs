import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A } from './helpers.mjs';

// A request is calls of the API, as the one asked would make them. Answering makes them, as that one, in order.
const grant = (f, row, data = {}, options = {}) => f.request('/v1/requests/' + row.id + '/grant', { method: 'POST', data, ...options });
const ask = (f, token, data) => f.request('/v1/requests', { method: 'POST', anonymous: true, token, data });
const status = (f, id) => f.app.store.db.prepare('SELECT status FROM requests WHERE id=?').get(id)?.status;
const keeping = (name, extra = {}) => ({ method: 'PUT', path: '/v1/principals/me/resources?kind=secret&name=' + name, inputs: [{ at: '', label: 'APIキー', kind: 'sealed', ...extra }] });

test('知らない相手は、開いた人の代理にしてもらうことだけを頼め、確認コードで答えた人が持ち主になる', async t => {
  const f = await fixture(t, { signin: false });
  const key = await f.become('laptop のAI');
  const asked = await ask(f, key.token, { operations: [f.takingOn(key.id)], binding_message: 'メールを読むため' });
  assert.equal(asked.status, 201, asked.text);
  const row = asked.json.request;
  assert.equal(row.to, null); assert.equal(row.requester_name, 'laptop のAI');
  assert.match(row.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
  assert.equal(row.verification_uri, f.base + '/requests/' + row.id);
  assert.deepEqual(row.results, [null]);
  assert.equal(row.operations[0].operation_id, 'addRelation');
  for (const other of [{ method: 'DELETE', path: '/v1/principals/me', body: {} }, { ...f.takingOn(key.id), body: { relation: 'viewer', object_type: 'principal', object_id: 'me' } }]) {
    const refused = await ask(f, key.token, { operations: [other] });
    assert.equal(refused.json.error.code, 'invalid_operations', 'nobody knows it yet: it may ask only to act for whoever answers');
  }
  assert.equal((await ask(f, key.token, { to: USER_A, operations: [f.takingOn(key.id)] })).json.error.code, 'unknown_requester');
  assert.equal((await ask(f, key.token, { operations: [f.takingOn(key.id)], binding_message: 'メールを読むため' })).json.request.id, row.id, 'asking again for the same is the same request');

  await f.signin();
  const page = await f.request('/v1/requests/' + row.id);
  assert.equal(page.json.request.user_code, undefined, 'the one asked never receives the code: they type what the asker shows');
  assert.equal(page.json.request.names[key.id].name, 'laptop のAI');
  for (const wrong of ['', 'ZZZZ-ZZZZ']) assert.equal((await grant(f, row, { user_code: wrong })).json.error.code, 'confirmation_required');
  const granted = await grant(f, row, { user_code: ' ' + row.user_code.toLowerCase().replace('-', '') + ' ' });
  assert.equal(granted.status, 200, granted.text);
  assert.equal(granted.json.request.status, 'granted');
  assert.equal(granted.json.request.results[0].status, 201);
  assert.ok(f.app.principals.actsFor(key.id).includes(USER_A));
  assert.deepEqual(f.app.principals.ownersOf(key.id), [USER_A]);
  assert.equal((await grant(f, row, { user_code: row.user_code })).status, 409);

  const second = await f.become('other');
  const locked = (await ask(f, second.token, { operations: [f.takingOn(second.id)] })).json.request;
  for (let attempt = 1; attempt <= 4; attempt++) assert.equal((await grant(f, locked, { user_code: '0000-0000' })).json.error.code, 'confirmation_required');
  assert.equal((await grant(f, locked, { user_code: '0000-0000' })).json.error.code, 'confirmation_locked');
  assert.equal(status(f, locked.id), 'denied');
});

test('知られた相手は、持ち主にどの API 操作でも頼め、持ち主が許可するとその人として実行され、結果が依頼元に返る', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const other = await f.issueKey('old laptop');
  const credential = f.app.principals.keys(other.id)[0];
  const asked = await ask(f, agent.token, { to: USER_A, operations: [{ method: 'PATCH', path: '/v1/principals/' + other.id, body: { name: 'retired' } }, { method: 'DELETE', path: '/v1/principals/' + other.id + '/credentials/' + credential.id, body: {} }], binding_message: '使っていない鍵を片付ける' });
  assert.equal(asked.status, 201, asked.text);
  const row = asked.json.request;
  assert.equal(row.to, USER_A);
  assert.equal(row.user_code, undefined);
  assert.deepEqual(row.operations.map(call => call.operation_id), ['renamePrincipal', 'removeCredential']);
  assert.equal((await f.request('/v1/principals/' + other.id + '/credentials/' + credential.id, { method: 'DELETE', data: {}, token: agent.token, anonymous: true })).status, 403, 'what it asks for, it may not do itself');

  const granted = await grant(f, row);
  assert.equal(granted.status, 200, granted.text);
  assert.equal(granted.json.request.status, 'granted');
  assert.deepEqual(granted.json.request.results.map(result => result.status), [200, 200]);
  assert.equal(granted.json.request.results[0].body.principal.name, 'retired');
  assert.equal(f.app.principals.keys(other.id).length, 0);
  const read = await f.request('/v1/requests/' + row.id, { token: agent.token, anonymous: true });
  assert.equal(read.json.request.results[0].body.principal.name, 'retired', 'what each call answered is the asker\'s to read');
});

test('持ち主が入れる値は、依頼が場所を空けておき、封をしたシークレットはその人の端末で封じられて保管される', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const asked = await ask(f, agent.token, { to: USER_A, operations: [keeping('openai-key', { site: 'https://platform.openai.com/api-keys' }), {
    method: 'PUT', path: '/v1/principals/me/resources?kind=app&name=' + encodeURIComponent('仕事用'), body: { service: 'google' },
    inputs: [{ at: '/client_id', label: 'クライアントID' }, { at: '/client_secret', label: 'クライアントシークレット', kind: 'hidden' }] }] });
  assert.equal(asked.status, 201, asked.text);
  const row = asked.json.request;
  const page = (await f.request('/v1/requests/' + row.id)).json.request;
  assert.ok(page.recipients.some(one => one.principal_id === USER_A), 'the one asked seals for those who may open it');
  assert.equal((await grant(f, row, { values: [{}, {}] })).json.error.code, 'input_required');
  const granted = await grant(f, row, { values: [{ '': 'sk-kept-value' }, { '/client_id': 'work-app-id', '/client_secret': 'work-app-secret' }] });
  assert.equal(granted.status, 200, granted.text);
  assert.equal(granted.json.request.status, 'granted');
  assert.equal((await f.read('secret', 'openai-key')).text, 'sk-kept-value');
  assert.doesNotMatch(JSON.stringify(f.app.store.db.prepare('SELECT * FROM requests').all()), /sk-kept-value|work-app-secret/, 'what the one asked typed is never kept with the request');
  const injected = await f.request('/v1/principals/' + USER_A + '/injections', { method: 'POST', token: agent.token, anonymous: true, data: { names: [{ name: 'openai-key', as: 'OPENAI_API_KEY' }] } });
  assert.equal(injected.json.injection.environment.OPENAI_API_KEY, 'sk-kept-value');
});

test('頼めない操作と、形の合わない操作は、依頼を作る時点で断る', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  for (const [call, code] of [
    [{ method: 'POST', path: '/v1/requests', body: {} }, 'operation_unavailable'],
    [{ method: 'POST', path: '/v1/principals/me/links', body: { request_id: 'x' } }, 'operation_unavailable'],
    [{ method: 'POST', path: '/v1/principals/me/payment', body: {} }, 'operation_unavailable'],
    [{ method: 'GET', path: '/v1/nowhere' }, 'operation_unavailable'],
    [{ method: 'PATCH', path: '/v1/principals/me', body: { name: 42 } }, 'invalid_name'],
    [{ method: 'PUT', path: '/v1/principals/me/resources?kind=secret&name=x', inputs: [{ at: 'value', label: 'x' }] }, 'invalid_operations'],
    [{ method: 'PATCH', path: '/v1/principals/me', body: { name: 'x' }, inputs: [{ at: '', label: 'x' }] }, 'invalid_operations'],
  ]) {
    const refused = await ask(f, agent.token, { operations: [call] });
    assert.equal(refused.status >= 400, true, call.path);
    assert.equal(refused.json.error.code, code, call.method + ' ' + call.path);
  }
  assert.equal((await ask(f, agent.token, { operations: Array(9).fill({ method: 'GET', path: '/v1/principals/me' }) })).json.error.code, 'invalid_operations');
});

test('実行できなかった操作で止まり、持ち主の権限を超えることはできず、続きから答え直せる', async t => {
  const f = await fixture(t), agent = await f.issueKey(), stranger = await f.become('stranger');
  const asked = (await ask(f, agent.token, { to: USER_A, operations: [{ method: 'PATCH', path: '/v1/principals/me', body: { name: '新しい名前' } }, { method: 'DELETE', path: '/v1/principals/' + stranger.id, body: {} }] })).json.request;
  const stopped = await grant(f, asked);
  assert.equal(stopped.status, 403, 'a call runs with the rights of the one answering, no more');
  const row = (await f.request('/v1/requests/' + asked.id)).json.request;
  assert.equal(row.status, 'pending'); assert.equal(row.results[0].status, 200); assert.equal(row.results[1], null);
  assert.ok(f.app.principals.get(stranger.id));
  const events = (await f.request('/v1/requests/' + asked.id, { token: agent.token, anonymous: true })).json.request.events;
  assert.equal(events.find(one => one.event === 'call_failed')?.code, 'forbidden', 'the asker learns why, without what was typed');
  assert.equal((await f.request('/v1/requests/' + asked.id + '/deny', { method: 'POST', data: {} })).json.request.status, 'denied');
});

test('サービスへの接続を頼むと、持ち主は同意の画面へ進み、戻ってきたときに依頼が答えられる', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const asked = (await ask(f, agent.token, { to: USER_A, operations: [{ method: 'POST', path: '/v1/principals/me/connections', body: { service: 'google', scopes: ['https://www.googleapis.com/auth/gmail.readonly'] } }] })).json.request;
  const begun = await grant(f, asked);
  assert.equal(begun.status, 200, begun.text);
  assert.equal(begun.json.request.status, 'pending');
  const consent = new URL(begun.json.continue.url);
  assert.ok(consent.searchParams.get('scope').split(' ').includes('https://www.googleapis.com/auth/gmail.readonly'));
  const back = await f.callback(consent, 'personal');
  assert.equal(back.headers.get('location'), '/requests/' + asked.id + '?result=connected', back.text);
  const done = (await f.request('/v1/requests/' + asked.id, { token: agent.token, anonymous: true })).json.request;
  assert.equal(done.status, 'granted');
  assert.equal(done.results[0].body.connection.subject, 'personal@example.test');
});

const naming = n => ({ method: 'PATCH', path: '/v1/principals/me', body: { name: 'name ' + n } });
test('依頼の期限と手順は依頼元が決め、Foundation はその範囲を守る', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const long = (await ask(f, agent.token, { to: USER_A, operations: [naming(0)], valid_minutes: 120, steps: [' 一つめ ', '二つめ'] })).json.request;
  assert.equal(long.expires_at - long.created_at, 120 * 60_000);
  assert.deepEqual(long.steps, ['一つめ', '二つめ']);
  for (const bad of [0, 1441, 1.5]) assert.equal((await ask(f, agent.token, { operations: [naming(1)], valid_minutes: bad })).json.error.code, 'invalid_validity');
  for (const bad of [['改行\nあり'], ['x'.repeat(501)], Array(21).fill('多すぎる')]) assert.equal((await ask(f, agent.token, { operations: [naming(1)], steps: bad })).json.error.code, 'invalid_steps');
});

test('同時に開ける依頼は10件までで、依頼元は間隔をあけて確認し、取り消せる', async t => {
  const f = await fixture(t, { requestInterval: 5 }), agent = await f.issueKey();
  const call = naming;
  const long = (await ask(f, agent.token, { to: USER_A, operations: [call(0)] })).json.request;
  const look = () => f.request('/v1/requests/' + long.id, { token: agent.token, anonymous: true });
  assert.equal((await look()).status, 200);
  assert.equal((await look()).json.error.code, 'slow_down');
  for (let n = 1; n < 10; n++) assert.equal((await ask(f, agent.token, { operations: [call(n)] })).status, 201);
  assert.equal((await ask(f, agent.token, { operations: [call(10)] })).json.error.code, 'too_many_pending');
  assert.equal((await f.request('/v1/requests/' + long.id, { method: 'DELETE', token: agent.token, anonymous: true, data: {} })).json.request.status, 'cancelled');
});

test('依頼のリンクを渡された人は、サインインせずにその依頼だけに答えられる', async t => {
  const f = await fixture(t), agent = await f.issueKey();
  const row = (await ask(f, agent.token, { to: USER_A, operations: [keeping('handed')] })).json.request;
  const issued = await f.request('/v1/principals/me/links', { method: 'POST', data: { request_id: row.id } });
  assert.equal(issued.status, 201, issued.text);
  const link = new URL(issued.json.url).hash.slice('#link='.length);
  const exchanged = await f.request('/v1/links/exchange', { method: 'POST', anonymous: true, data: { link, request_id: row.id } });
  assert.equal(exchanged.status, 200, exchanged.text);
  const cookie = exchanged.headers.get('set-cookie').split(';')[0];
  const shown = await f.request('/v1/requests/' + row.id, { anonymous: true, headers: { cookie } });
  assert.equal(shown.status, 200, shown.text);
  assert.ok(shown.json.request.recipients.length);
  assert.equal((await f.request('/v1/principals/me/resources?kind=secret', { anonymous: true, headers: { cookie } })).status, 401, 'the link reaches its request and nothing else');
  const answered = await grant(f, row, { values: [{ '': 'from the link' }] }, { anonymous: true, headers: { cookie } });
  assert.equal(answered.status, 200, answered.text);
  assert.equal((await f.read('secret', 'handed')).text, 'from the link');
});
