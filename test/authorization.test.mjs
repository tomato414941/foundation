import test from 'node:test';
import assert from 'node:assert/strict';
import { allowed, rules } from '../src/authorization.mjs';
import { fixture } from './helpers.mjs';

test('答えは subject・action・resource から decision だけを返し、規則は一覧できる', () => {
  assert.deepEqual(allowed({ subject: { type: 'owner', id: 'u' }, action: { name: 'read' }, resource: { type: 'export' } }), { decision: true });
  assert.deepEqual(allowed({ subject: { type: 'key', id: 'k' }, action: { name: 'read' }, resource: { type: 'export' } }), { decision: false });
  assert.deepEqual(allowed({ subject: { type: 'key', id: 'k' }, action: { name: 'create' }, resource: { type: 'delivery' } }), { decision: true });
  assert.deepEqual(allowed({ subject: { type: 'owner', id: 'u' }, action: { name: 'create' }, resource: { type: 'delivery' } }), { decision: false });
  assert.deepEqual(allowed({ subject: { type: 'linked', id: 'u' }, action: { name: 'done' }, resource: { type: 'request', id: 'r' } }), { decision: true });
  assert.deepEqual(allowed({ subject: { type: 'linked', id: 'u' }, action: { name: 'list' }, resource: { type: 'secret' } }), { decision: false });
  assert.deepEqual(allowed({ subject: { type: 'nobody' }, action: { name: 'read' }, resource: { type: 'state' } }), { decision: false });
  assert.deepEqual(allowed({}), { decision: false });
  const listed = rules();
  assert.ok(listed.some(rule => rule.resource === 'secret' && rule.action === 'rename' && rule.subjects.join() === 'owner'));
  assert.ok(listed.every(rule => rule.subjects.every(door => ['owner', 'linked', 'key', 'app'].includes(door))));
});

test('ルートは同じ問いを立て、許されない主体には 403、依頼だけを渡された利用者には 401 で答える', async t => {
  const f = await fixture(t), { token } = await f.issueKey();
  for (const [path, options] of [['/v1/state', {}], ['/v1/keys', {}], ['/v1/apps', {}], ['/v1/export', {}],
    ['/v1/secrets?name=x', { method: 'PATCH', data: { name: 'y' } }], ['/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly' } }]]) {
    const refused = await f.request(path, { ...options, token, anonymous: true });
    assert.equal(refused.status, 403, path + ' ' + refused.text); assert.equal(refused.json.error.code, 'forbidden');
  }
  for (const [path, options] of [['/v1/deliveries', { method: 'POST', data: { names: [] } }], ['/v1/functions', {}],
    ['/v1/functions/http.request', { method: 'POST', data: { url: 'https://example.test/' } }]]) {
    const refused = await f.request(path, options);
    assert.equal(refused.status, 403, path + ' ' + refused.text); assert.equal(refused.json.error.code, 'forbidden');
  }
  assert.equal((await f.request('/v1/secrets', { token, anonymous: true })).status, 200, 'what both may do still works');
  assert.equal((await f.request('/v1/secrets')).status, 200);
});
