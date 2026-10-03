import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A, json } from './helpers.mjs';

const route = name => '/v1/principals/me/resources?kind=secret&name=' + encodeURIComponent(name);
const own = name => '/v1/principals/me/resources?kind=secret&name=' + encodeURIComponent(name);

test('Every accepted name round-trips literally through HTTP, including Unicode, separators and dot segments', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const names = ['safdgaae', 'a/aa/aaa', '.', '..', '/', 'a//b', 'a/../b', ' 空白 ', '値🔑', 'NAME', 'name', 'x,y=z:1', 'a?b#c%', '{{a}}', '雪'.repeat(200)];
  for (const [index, name] of names.entries()) {
    const content = 'value-' + index;
    const put = await f.request(route(name), { method: 'PUT', token, raw: content });
    assert.equal(put.status, 200, put.text); assert.equal(put.json.resource.name, name);
    assert.equal((await f.read('secret', name, { token })).text, content);
    assert.equal((await f.read('secret', name)).text, content);
  }
  assert.deepEqual(new Set((await f.request('/v1/principals/me/resources?kind=secret', { token })).json.resources.map(row => row.name)), new Set(names));
  const renamed = await f.request('/v1/resources/' + (await f.lookup('secret', '..')).json.resource.id, { method: 'PATCH', data: { name: ' ../新しい名=, ' } });
  assert.equal(renamed.status, 200); assert.equal(renamed.json.resource.name, ' ../新しい名=, ');
  assert.equal((await f.read('secret', ' ../新しい名=, ', { token })).text, 'value-3');
  assert.equal((await f.drop('secret', ' ../新しい名=, ', { token })).status, 200);
  assert.equal((await f.read('secret', ' ../新しい名=, ', { token })).status, 404);
});

test('Name prefix filtering uses literal, case-sensitive text rather than wildcard or directory semantics', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const names = ['a', 'a_', 'a_2', 'a%', 'ab', 'ab/c', 'A_', 'a/?'];
  for (const name of names) await f.request(route(name), { method: 'PUT', token, raw: 'x' });
  for (const [prefix, expected] of [['a_', ['a_', 'a_2']], ['a%', ['a%']], ['A', ['A_']], ['ab', ['ab', 'ab/c']]]) {
    const listed = await f.request('/v1/principals/me/resources?kind=secret&prefix=' + encodeURIComponent(prefix), { token });
    assert.deepEqual(listed.json.resources.map(row => row.name), expected);
  }
});

test('The function catalog is authenticated and describes explicit inputs and optional saved outputs', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  assert.equal((await f.request('/v1/functions', { anonymous: true })).status, 401);
  const catalog = await f.request('/v1/functions', { token });
  assert.deepEqual(catalog.json.functions.map(fn => fn.id), ['http.request']);
  for (const fn of catalog.json.functions) {
    assert.ok(fn.input && fn.output && fn.save);
    assert.equal(fn.endpoint, '/v1/functions/' + fn.id);
  }
});

test('A storage request preserves comma and punctuation names in its completion result', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  const names = ['one, two', '{{value}}', '__proto__'];
  const asked = await f.request('/v1/requests', { method: 'POST', token, data: { authorization_details: [{ type: 'secret', fields: names.map(name => ({ name, label: name })) }], binding_message: '値の保存' } });
  assert.equal(asked.status, 201, asked.text);
  const complete = await f.request('/v1/requests/' + asked.json.request.id + '/grant', { method: 'POST', data: { entries: names.map(name => ({ name, content: 'value-' + name })) } });
  assert.equal(complete.status, 200, complete.text);
  const done = await f.request('/v1/requests/' + asked.json.request.id, { token });
  assert.deepEqual(done.json.request.result.names, names);
  for (const name of names) assert.equal((await f.read('secret', name)).text, 'value-' + name);
});
