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
  const me = { id: person.id, via: { kind: 'session' } }, actor = { id: key.id, via: { kind: 'key' } }, stranger = { id: other.id, via: { kind: 'key' } };
  assert.equal(ask(me, 'content', { type: 'credential', id: 'x', holder: person.id }), true, 'the holder');
  assert.equal(ask(actor, 'list', { type: 'credential', holder: person.id }), true, 'one who acts for the holder reaches their things');
  assert.equal(ask(actor, 'read', { type: 'credential', id: 'x', holder: person.id }), true, 'and sees what each is');
  assert.equal(ask(actor, 'content', { type: 'credential', id: 'x', holder: person.id }), false, 'but reads what one holds only along a line to it');
  assert.equal(ask(stranger, 'content', { type: 'credential', id: 'x', holder: person.id }), false, 'nobody else');
  assert.equal(ask(actor, 'rename', { type: 'credential', id: 'x', holder: person.id }), false, 'renaming is the holder\'s alone');
  principals.relate(other.id, 'viewer', 'resource', 'x');
  assert.equal(ask(stranger, 'content', { type: 'credential', id: 'x', holder: person.id }), true, 'a line drawn onto the thing itself');
  assert.equal(ask(stranger, 'content', { type: 'credential', id: 'y', holder: person.id }), false, 'and only that thing');
  assert.equal(ask(stranger, 'write', { type: 'credential', id: 'x', holder: person.id }), false);
  assert.equal(ask(me, 'remove', { type: 'principal', id: key.id }), true, 'the owner');
  assert.equal(ask(actor, 'remove', { type: 'principal', id: key.id }), false, 'not oneself');
  assert.equal(ask(actor, 'rename', { type: 'principal', id: key.id }), true, 'oneself, for a name');
  assert.equal(ask(actor, 'connect', { type: 'credential', holder: person.id }), false, 'connecting is the holder\'s unless given');
  assert.equal(ask(me, 'connect', { type: 'credential', holder: person.id }), true);
  const linked = { id: person.id, via: { kind: 'link', request: 'r1' } };
  assert.equal(ask(linked, 'done', { type: 'request', id: 'r1', holder: person.id }), true, 'the one request a link reaches');
  assert.equal(ask(linked, 'read', { type: 'request', id: 'r2', holder: person.id }), false);
  assert.equal(ask(linked, 'list', { type: 'credential', holder: person.id }), false, 'and nothing else');
  assert.deepEqual(authorization.allowed({}), { decision: false });
  assert.ok(rules().some(rule => rule.resource === 'credential' && rule.action === 'rename' && rule.grounds.join() === 'self'));
  store.close();
});

test('ルートは同じ問いを立て、許されない主体には 403、依頼だけを渡された利用者には 401 で答える', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const kept = await f.keep('credential', 'x', 'value');
  for (const [path, options] of [['/v1/overview', {}], ['/v1/export', {}],
    ['/v1/resources/' + kept.json.resource.id, { method: 'PATCH', data: { name: 'y' } }], ['/v1/credentials', { method: 'POST', data: { service: 'google' } }]]) {
    const refused = await f.request(path, { ...options, token: key.token, anonymous: true });
    assert.equal(refused.status, 403, path + ' ' + refused.text); assert.equal(refused.json.error.code, 'forbidden');
  }
  assert.equal((await f.request('/v1/resources?kind=credential', { token: key.token, anonymous: true })).status, 200, 'what both may do still works');
  assert.equal((await f.request('/v1/resources?kind=credential')).status, 200);
  assert.equal((await f.request('/v1/functions')).status, 200, 'the holder may do what those acting for them may');
  assert.equal((await f.request('/v1/principals/' + key.id, { method: 'DELETE', token: key.token, anonymous: true, data: {} })).status, 403, 'nobody removes what they do not own');
  const stranger = await f.request('/v1/principals/' + USER_A, { token: key.token, anonymous: true });
  assert.equal(stranger.status, 403);
});

test('持ち主は一つの操作を API から渡し、渡された相手は鍵からその操作をする', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const connected = await f.credential();
  const disconnect = (token) => f.request('/v1/resources/' + connected.id, { method: 'DELETE', data: { revoke: false }, ...(token ? { token, anonymous: true } : {}) });
  assert.equal((await disconnect(key.token)).status, 403, '渡される前は解除できない');
  const given = await f.request('/v1/permissions', { method: 'POST', data: { subject: key.id, action: 'credential.disconnect', object_type: 'resource', object_id: connected.id } });
  assert.equal(given.status, 201, given.text);
  const listed = await f.request('/v1/permissions', { token: key.token, anonymous: true });
  assert.deepEqual(listed.json.permissions.map(row => [row.action, row.object_id]), [['credential.disconnect', connected.id]]);
  const done = await disconnect(key.token);
  assert.equal(done.status, 200, done.text);
  assert.equal((await f.request('/v1/resources?kind=credential')).json.resources.some(item => item.id === connected.id), false);
});

test('持ち物全体に渡した操作は、その持ち主のどの接続にも届き、外すと届かなくなる', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const first = await f.credential('personal'), second = await f.credential('work');
  const scope = { subject: key.id, action: 'credential.disconnect', object_type: 'principal', object_id: USER_A };
  assert.equal((await f.request('/v1/permissions', { method: 'POST', data: scope })).status, 201);
  assert.equal((await f.request('/v1/resources/' + first.id, { method: 'DELETE', data: { revoke: false }, token: key.token, anonymous: true })).status, 200);
  assert.equal((await f.request('/v1/permissions', { method: 'DELETE', data: scope })).status, 200);
  assert.equal((await f.request('/v1/resources/' + second.id, { method: 'DELETE', data: { revoke: false }, token: key.token, anonymous: true })).status, 403);
});

test('自分が持たない操作や、線を引けない相手の持ち物には、権限を渡せない', async t => {
  const f = await fixture(t), key = await f.issueKey(), other = await f.issueKey('other');
  const connected = await f.credential();
  const give = (token, data) => f.request('/v1/permissions', { method: 'POST', data, token, anonymous: true });
  assert.equal((await give(key.token, { subject: other.id, action: 'credential.disconnect', object_type: 'principal', object_id: USER_A })).status, 403, '代わりに動く者は持ち主の持ち物全体に線を引けない');
  assert.equal((await give(key.token, { subject: other.id, action: 'credential.disconnect', object_type: 'resource', object_id: connected.id })).status, 403, '共有できない物にも渡せない');
  assert.equal((await f.request('/v1/permissions', { method: 'POST', data: { subject: key.id, action: 'credential.nothing', object_type: 'resource', object_id: connected.id } })).status, 400, 'ない操作は渡せない');
  assert.equal((await f.request('/v1/permissions', { method: 'POST', data: { subject: key.id, action: 'object.read', object_type: 'resource', object_id: connected.id } })).status, 400, '種類の違う物には渡せない');
});

test('来かたによらず、同じ関係なら同じ答えを返す', () => {
  const store = new Store(':memory:', KEY), principals = new Principals(store), authorization = new Authorization(principals);
  const person = principals.ensure('person');
  const ask = (via, name, resource) => authorization.allowed({ subject: { id: person.id, via: { kind: via } }, action: { name }, resource }).decision;
  for (const [name, resource] of [['connect', { type: 'credential', holder: person.id }], ['disconnect', { type: 'credential', id: 'x', holder: person.id }], ['read', { type: 'export', holder: person.id }]]) {
    assert.equal(ask('key', name, resource), ask('session', name, resource), name);
    assert.equal(ask('key', name, resource), true, name);
  }
  store.close();
});
