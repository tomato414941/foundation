import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/store.mjs';
import { Principals } from '../src/principals.mjs';
import { Authorization, rules } from '../src/authorization.mjs';
import { fixture, KEY, USER_A } from './helpers.mjs';

test('答えは subject・action・resource から decision だけを返し、根拠は関係にある', () => {
  const store = new Store(':memory:', KEY), principals = new Principals(store), authorization = new Authorization(principals);
  const person = principals.ensure('person'), key = principals.create(person.id, { name: 'key' }), other = principals.ensure('other');
  principals.relate(key.id, 'actor', 'principal', person.id);
  const ask = (subject, name, resource) => authorization.allowed({ subject, action: { name }, resource }).decision;
  const me = { id: person.id, credential: { kind: 'session' } }, actor = { id: key.id, credential: { kind: 'key' } }, stranger = { id: other.id, credential: { kind: 'key' } };
  assert.equal(ask(me, 'read', { type: 'secret', id: 'x', holder: person.id }), true, 'the holder');
  assert.equal(ask(actor, 'list', { type: 'secret', holder: person.id }), true, 'one who acts for the holder reaches their things');
  assert.equal(ask(actor, 'read', { type: 'secret', id: 'x', holder: person.id }), false, 'but reads a value only along a line to it');
  assert.equal(ask(stranger, 'read', { type: 'secret', id: 'x', holder: person.id }), false, 'nobody else');
  assert.equal(ask(actor, 'rename', { type: 'secret', id: 'x', holder: person.id }), false, 'renaming is the holder\'s alone');
  principals.relate(other.id, 'viewer', 'holding', 'x');
  assert.equal(ask(stranger, 'read', { type: 'secret', id: 'x', holder: person.id }), true, 'a line drawn onto the thing itself');
  assert.equal(ask(stranger, 'read', { type: 'secret', id: 'y', holder: person.id }), false, 'and only that thing');
  assert.equal(ask(stranger, 'write', { type: 'secret', id: 'x', holder: person.id }), false);
  assert.equal(ask(me, 'remove', { type: 'principal', id: key.id }), true, 'the owner');
  assert.equal(ask(actor, 'remove', { type: 'principal', id: key.id }), false, 'not oneself');
  assert.equal(ask(actor, 'rename', { type: 'principal', id: key.id }), true, 'oneself, for a name');
  assert.equal(ask(actor, 'create', { type: 'connection', holder: person.id }), false, 'a browser is needed for a service\'s consent screen');
  assert.equal(ask(me, 'create', { type: 'connection', holder: person.id }), true);
  const linked = { id: person.id, credential: { kind: 'link', scope: 'request:r1' } };
  assert.equal(ask(linked, 'done', { type: 'request', id: 'r1', holder: person.id }), true, 'the one request a link reaches');
  assert.equal(ask(linked, 'read', { type: 'request', id: 'r2', holder: person.id }), false);
  assert.equal(ask(linked, 'list', { type: 'secret', holder: person.id }), false, 'and nothing else');
  assert.deepEqual(authorization.allowed({}), { decision: false });
  assert.ok(rules().some(rule => rule.resource === 'secret' && rule.action === 'rename' && rule.grounds.join() === 'self'));
  store.close();
});

test('ルートは同じ問いを立て、許されない主体には 403、依頼だけを渡された利用者には 401 で答える', async t => {
  const f = await fixture(t), key = await f.issueKey();
  for (const [path, options] of [['/v1/overview', {}], ['/v1/export', {}],
    ['/v1/secrets?name=x', { method: 'PATCH', data: { name: 'y' } }], ['/v1/connections', { method: 'POST', data: { connector: 'gmail.readonly' } }]]) {
    const refused = await f.request(path, { ...options, token: key.token, anonymous: true });
    assert.equal(refused.status, 403, path + ' ' + refused.text); assert.equal(refused.json.error.code, 'forbidden');
  }
  assert.equal((await f.request('/v1/secrets', { token: key.token, anonymous: true })).status, 200, 'what both may do still works');
  assert.equal((await f.request('/v1/secrets')).status, 200);
  assert.equal((await f.request('/v1/functions')).status, 200, 'the holder may do what those acting for them may');
  assert.equal((await f.request('/v1/principals/' + key.id, { method: 'DELETE', token: key.token, anonymous: true, data: {} })).status, 403, 'nobody removes what they do not own');
  const stranger = await f.request('/v1/principals/' + USER_A, { token: key.token, anonymous: true });
  assert.equal(stranger.status, 403);
});
