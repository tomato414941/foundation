import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A, json } from './helpers.mjs';
import { SECRET_COUNT_MAX } from '../src/secrets.mjs';

const route = name => '/v1/holdings?kind=secret&name=' + encodeURIComponent(name);
const own = name => '/v1/holdings?kind=secret&name=' + encodeURIComponent(name);
const invoke = (f, token, connection, save) => f.request('/v1/functions/connection.credentials', {
  method: 'POST', token, data: { connection_id: connection.id, ...(save === undefined ? {} : { save }) },
});

test('Every accepted name round-trips literally through HTTP, including Unicode, separators and dot segments', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const names = ['safdgaae', 'a/aa/aaa', '.', '..', '/', 'a//b', 'a/../b', ' 空白 ', '値🔑', 'NAME', 'name', 'x,y=z:1', 'a?b#c%', '{{a}}', '雪'.repeat(200)];
  for (const [index, name] of names.entries()) {
    const content = 'value-' + index;
    const put = await f.request(route(name), { method: 'PUT', token, raw: content });
    assert.equal(put.status, 200, put.text); assert.equal(put.json.holding.name, name);
    assert.equal((await f.read('secret', name, { token })).text, content);
    assert.equal((await f.read('secret', name)).text, content);
  }
  assert.deepEqual(new Set((await f.request('/v1/holdings?kind=secret', { token })).json.holdings.map(row => row.name)), new Set(names));
  const renamed = await f.request('/v1/holdings/' + (await f.lookup('secret', '..')).json.holding.id, { method: 'PATCH', data: { name: ' ../新しい名=, ' } });
  assert.equal(renamed.status, 200); assert.equal(renamed.json.holding.name, ' ../新しい名=, ');
  assert.equal((await f.read('secret', ' ../新しい名=, ', { token })).text, 'value-3');
  assert.equal((await f.drop('secret', ' ../新しい名=, ', { token })).status, 200);
  assert.equal((await f.read('secret', ' ../新しい名=, ', { token })).status, 404);
});

test('Name prefix filtering uses literal, case-sensitive text rather than wildcard or directory semantics', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const names = ['a', 'a_', 'a_2', 'a%', 'ab', 'ab/c', 'A_', 'a/?'];
  for (const name of names) await f.request(route(name), { method: 'PUT', token, raw: 'x' });
  for (const [prefix, expected] of [['a_', ['a_', 'a_2']], ['a%', ['a%']], ['A', ['A_']], ['ab', ['ab', 'ab/c']]]) {
    const listed = await f.request('/v1/holdings?kind=secret&prefix=' + encodeURIComponent(prefix), { token });
    assert.deepEqual(listed.json.holdings.map(row => row.name), expected);
  }
});

test('The function catalog is authenticated and describes explicit inputs and optional saved outputs', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  assert.equal((await f.request('/v1/functions', { anonymous: true })).status, 401);
  const catalog = await f.request('/v1/functions', { token });
  assert.deepEqual(catalog.json.functions.map(fn => fn.id), ['http.request', 'connection.credentials']);
  for (const fn of catalog.json.functions) {
    assert.ok(fn.input && fn.output && fn.save);
    assert.equal(fn.endpoint, '/v1/functions/' + fn.id);
  }
  for (const connection_id of [undefined, null, {}, [], 1, '']) {
    const invalid = await f.request('/v1/functions/connection.credentials', { method: 'POST', token, data: { connection_id } });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.json.error.code, 'invalid_connection');
  }
});

test('Explicit credential outputs can be saved, renamed and delivered without linking the values to the connection', async t => {
  const f = await fixture(t), personal = await f.credential(), work = await f.credential('work'), { token } = await f.issueKey();
  const snapshot = 'safdgaae', unrelated = 'gmail/personal-example-test/google-oauth-access-token';
  await f.request(route(unrelated), { method: 'PUT', token, raw: 'unrelated value' });
  const saved = await invoke(f, token, personal, { GOOGLE_OAUTH_ACCESS_TOKEN: snapshot });
  assert.equal(saved.status, 200, saved.text);
  assert.deepEqual(saved.json.saved.map(row => row.name), [snapshot]);
  assert.ok(saved.json.expires_in > 3500);
  assert.doesNotMatch(saved.text, /google-access|refresh-personal/);
  assert.equal((await f.read('secret', snapshot, { token })).status, 403);
  f.expire(personal.id);
  const calls = f.gmail.calls.length;
  const delivered = await f.request('/v1/deliveries', { method: 'POST', token, data: { names: [{ name: snapshot, as: 'CHOSEN_TOKEN' }] } });
  assert.deepEqual(delivered.json.delivery.environment, { CHOSEN_TOKEN: 'google-access-personal-readonly' });
  assert.equal(delivered.json.expires_at, null);
  assert.equal((await f.read('secret', snapshot)).text, 'google-access-personal-readonly');
  assert.equal(f.gmail.calls.length, calls, 'reads deliver the stored snapshot, with no provider invocation');
  assert.equal((await f.request('/v1/holdings/' + (await f.lookup('secret', snapshot)).json.holding.id, { method: 'PATCH', data: { name: 'a/aa/aaa' } })).status, 200);
  const oldCiphertext = f.app.secrets.find(USER_A, 'a/aa/aaa').content;
  assert.equal((await invoke(f, token, personal)).status, 200);
  assert.ok(f.gmail.calls.length > calls, 'the explicit function renews an expired credential');
  assert.equal(f.app.secrets.find(USER_A, 'a/aa/aaa').content, oldCiphertext);
  assert.equal((await f.read('secret', unrelated, { token })).text, 'unrelated value');
  const removed = await f.request('/v1/connections/' + personal.id, { method: 'DELETE', data: { revoke: false } });
  assert.equal(removed.status, 200);
  assert.equal((await f.read('secret', 'a/aa/aaa')).text, 'google-access-personal-readonly');
  assert.equal((await invoke(f, token, work)).json.delivery.environment.GMAIL_ACCOUNT_EMAIL, 'work@example.test');
  assert.equal((await invoke(f, token, personal)).status, 404);
});

test('Selected output names are validated before provider calls; a failed batch leaves all saved values unchanged', async t => {
  const f = await fixture(t), connection = await f.credential(), { token } = await f.issueKey();
  f.expire(connection.id);
  const calls = f.gmail.calls.length;
  for (const save of [null, [], {}, { MISSING: 'x' }, { GOOGLE_OAUTH_ACCESS_TOKEN: '' }, { GOOGLE_OAUTH_ACCESS_TOKEN: 'same', GMAIL_ACCOUNT_EMAIL: 'same' }]) {
    const refused = await invoke(f, token, connection, save);
    assert.equal(refused.status, 400, refused.text);
  }
  assert.equal(f.gmail.calls.length, calls);
  for (let index = 0; index < SECRET_COUNT_MAX - 1; index++) {
    f.app.secrets.put(USER_A, { name: 'kept-' + index, content: Buffer.from('existing') });
  }
  f.gmail.refreshHandler = () => json({ access_token: 'google-access-personal-readonly', refresh_token: 'rotated-fixture-refresh-token', expires_in: 3600 });
  const refused = await invoke(f, token, connection, { GOOGLE_OAUTH_ACCESS_TOKEN: 'new-one', GMAIL_ACCOUNT_EMAIL: 'new-two' });
  assert.equal(refused.json.error.code, 'secret_limit');
  const kept = f.app.secrets.list(USER_A);
  assert.equal(kept.length, SECRET_COUNT_MAX - 1);
  assert.ok(kept.every(row => row.name.startsWith('kept-')));
  const updated = f.app.connections.state(f.app.connections.get(USER_A, connection.id));
  assert.equal(updated.private_state.refresh_token, 'rotated-fixture-refresh-token', 'private renewal state survives a failed snapshot save');
  assert.ok(updated.expires_at > Date.now());
});

for (const change of ['key', 'connection', 'reconnect']) test('An in-flight credential save cannot publish after changing the ' + change, async t => {
  const f = await fixture(t), connection = await f.credential(), key = await f.issueKey();
  f.expire(connection.id);
  let began, release;
  const started = new Promise(resolve => began = resolve);
  f.gmail.refreshHandler = () => { began(); return new Promise(resolve => release = resolve); };
  const pending = invoke(f, key.token, connection, { GOOGLE_OAUTH_ACCESS_TOKEN: 'result' });
  await started;
  if (change === 'key') await f.request('/v1/principals/' + key.id, { method: 'DELETE', data: {} });
  if (change === 'connection') await f.request('/v1/connections/' + connection.id, { method: 'DELETE', data: { revoke: false } });
  if (change === 'reconnect') await f.callback(await f.start({ connection_id: connection.id }));
  release();
  const result = await pending;
  assert.ok([401, 409].includes(result.status), result.text);
  assert.deepEqual(f.app.secrets.list(USER_A), []);
  assert.doesNotMatch(result.text, /google-access|refresh-personal/);
});

test('A storage request preserves comma and punctuation names in its completion result', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const names = ['one, two', '{{value}}', '__proto__'];
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { store: names.map(name => ({ name, label: name })), purpose: '値の保存' } });
  assert.equal(asked.status, 201, asked.text);
  const complete = await f.request('/v1/requests/' + asked.json.request.id + '/done', { method: 'POST', data: { entries: names.map(name => ({ name, content: 'value-' + name })) } });
  assert.equal(complete.status, 200, complete.text);
  const done = await f.request('/v1/requests/' + asked.json.request.id, { token });
  assert.deepEqual(done.json.request.result.names, names);
  for (const name of names) assert.equal((await f.read('secret', name)).text, 'value-' + name);
});
