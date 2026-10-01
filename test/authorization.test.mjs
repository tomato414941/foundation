import test from 'node:test';
import assert from 'node:assert/strict';
import { Store } from '../src/store.mjs';
import { Principals } from '../src/principals.mjs';
import { Resources } from '../src/resources.mjs';
import { Authorization, rules } from '../src/authorization.mjs';
import { fixture, KEY, USER_A } from './helpers.mjs';

test('答えは subject・action・resource から decision だけを返し、根拠は関係にある', () => {
  const store = new Store(':memory:', KEY), principals = new Principals(store), authorization = new Authorization(principals, new Resources(store));
  const person = principals.ensure('person'), key = principals.create(person.id, { name: 'key' }), other = principals.ensure('other');
  principals.relate(key.id, 'agent', 'principal', person.id);
  const ask = (subject, name, resource) => authorization.allowed({ subject, action: { name }, resource }).decision;
  const me = { id: person.id, via: { kind: 'session' } }, actor = { id: key.id, via: { kind: 'key' } }, stranger = { id: other.id, via: { kind: 'key' } };
  assert.equal(ask(me, 'content', { type: 'secret', id: 'x', holder: person.id }), true, 'the holder');
  assert.equal(ask(actor, 'list', { type: 'secret', holder: person.id }), true, 'one who acts for the holder reaches their things');
  assert.equal(ask(actor, 'read', { type: 'secret', id: 'x', holder: person.id }), true, 'and sees what each is');
  assert.equal(ask(actor, 'content', { type: 'secret', id: 'x', holder: person.id }), false, 'but reads what one holds only along a line to it');
  assert.equal(ask(stranger, 'content', { type: 'secret', id: 'x', holder: person.id }), false, 'nobody else');
  assert.equal(ask(actor, 'rename', { type: 'secret', id: 'x', holder: person.id }), false, 'renaming is the holder\'s alone');
  principals.relate(other.id, 'viewer', 'resource', 'x');
  assert.equal(ask(stranger, 'content', { type: 'secret', id: 'x', holder: person.id }), true, 'a line drawn onto the thing itself');
  assert.equal(ask(stranger, 'content', { type: 'secret', id: 'y', holder: person.id }), false, 'and only that thing');
  assert.equal(ask(stranger, 'write', { type: 'secret', id: 'x', holder: person.id }), false);
  assert.equal(ask(me, 'remove', { type: 'principal', id: key.id }), true, 'the owner');
  assert.equal(ask(actor, 'remove', { type: 'principal', id: key.id }), false, 'not oneself');
  assert.equal(ask(actor, 'rename', { type: 'principal', id: key.id }), true, 'oneself, for a name');
  assert.equal(ask(actor, 'connect', { type: 'connection', holder: person.id }), false, 'connecting is the holder\'s unless given');
  assert.equal(ask(me, 'connect', { type: 'connection', holder: person.id }), true);
  assert.deepEqual(authorization.allowed({}), { decision: false });
  assert.ok(rules().some(rule => rule.resource === 'connection' && rule.action === 'rename'), 'every permission is readable');
  store.close();
});

test('ルートは同じ問いを立て、許されない主体には 403、依頼だけを渡された利用者には 401 で答える', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const kept = await f.keep('secret', 'x', 'value');
  for (const [path, options] of [['/v1/overview', {}], ['/v1/export', {}],
    ['/v1/resources/' + kept.json.resource.id, { method: 'PATCH', data: { name: 'y' } }], ['/v1/connections', { method: 'POST', data: { service: 'google' } }]]) {
    const refused = await f.request(path, { ...options, token: key.token, anonymous: true });
    assert.equal(refused.status, 403, path + ' ' + refused.text); assert.equal(refused.json.error.code, 'forbidden');
  }
  assert.equal((await f.request('/v1/resources?kind=connection', { token: key.token, anonymous: true })).status, 200, 'what both may do still works');
  assert.equal((await f.request('/v1/resources?kind=connection')).status, 200);
  assert.equal((await f.request('/v1/functions')).status, 200, 'the holder may do what those acting for them may');
  assert.equal((await f.request('/v1/principals/' + key.id, { method: 'DELETE', token: key.token, anonymous: true, data: {} })).status, 403, 'nobody removes what they do not own');
  const stranger = await f.request('/v1/principals/' + USER_A, { token: key.token, anonymous: true });
  assert.equal(stranger.status, 403);
});

test('持ち主は一つの操作を関係として渡し、渡された相手は鍵からその操作をする', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const connected = await f.connection();
  const disconnect = token => f.request('/v1/resources/' + connected.id, { method: 'DELETE', data: { revoke: false }, token, anonymous: true });
  assert.equal((await disconnect(key.token)).status, 403, '渡される前は解除できない');
  const given = await f.request('/v1/relations', { method: 'POST', data: { subject: key.id, relation: 'disconnect_grant', object_type: 'resource', object_id: connected.id } });
  assert.equal(given.status, 201, given.text);
  const listed = await f.request('/v1/relations', { token: key.token, anonymous: true });
  assert.ok(listed.json.relations.some(row => row.relation === 'disconnect_grant' && row.object_id === connected.id), '役割と同じ一覧に載る');
  const done = await disconnect(key.token);
  assert.equal(done.status, 200, done.text);
  assert.equal((await f.request('/v1/resources?kind=connection')).json.resources.some(item => item.id === connected.id), false);
});

test('一つの操作は、その物にだけ渡せる。持ち主そのものには引けない', async t => {
  const f = await fixture(t), key = await f.issueKey();
  const first = await f.connection('personal');
  const onto = { subject: key.id, relation: 'disconnect_grant', object_type: 'principal', object_id: USER_A };
  assert.equal((await f.request('/v1/relations', { method: 'POST', data: onto })).status, 400, '持ち主には、その操作の関係がない');
  assert.equal((await f.request('/v1/resources/' + first.id, { method: 'DELETE', data: { revoke: false }, token: key.token, anonymous: true })).status, 403);
});

test('自分がその場所でできないことを含む関係は引けず、所有は引けない', async t => {
  const f = await fixture(t), key = await f.issueKey(), other = await f.issueKey('other');
  const connected = (await f.keep('secret', 'private value', 'value')).json.resource;
  const draw = (token, data) => f.request('/v1/relations', { method: 'POST', data, token, anonymous: true });
  assert.equal((await draw(key.token, { subject: other.id, relation: 'agent', object_type: 'principal', object_id: USER_A })).status, 403, '代わりに動く者は持ち主に線を引けない');
  assert.equal((await draw(key.token, { subject: other.id, relation: 'viewer', object_type: 'resource', object_id: connected.id })).status, 403, '共有できない物にも引けない');
  const owner = (data) => f.request('/v1/relations', { method: 'POST', data });
  assert.equal((await owner({ subject: key.id, relation: 'nothing_grant', object_type: 'resource', object_id: connected.id })).status, 400, 'ない操作');
  assert.equal((await owner({ subject: key.id, relation: 'link_grant', object_type: 'resource', object_id: connected.id })).status, 400, '種類の違う物の操作');
  assert.equal((await owner({ subject: key.id, relation: 'owner', object_type: 'principal', object_id: other.id })).status, 400, '所有は作るか承認するときだけ');
  assert.equal((await owner({ subject: key.id, relation: 'viewer', object_type: 'principal', object_id: other.id })).status, 400, '役割の置き場所');
  const shared = await owner({ subject: key.id, relation: 'share', object_type: 'resource', object_id: connected.id });
  assert.equal(shared.status, 400);
  assert.equal((await owner({ subject: key.id, relation: 'share_grant', object_type: 'resource', object_id: connected.id })).status, 201, '共有する権利も渡せる');
  assert.equal((await draw(key.token, { subject: other.id, relation: 'viewer', object_type: 'resource', object_id: connected.id })).status, 403, 'それでも自分が読めない中身を含む役割は渡せない');
});

test('来かたによらず、同じ関係なら同じ答えを返す', () => {
  const store = new Store(':memory:', KEY), principals = new Principals(store), authorization = new Authorization(principals, new Resources(store));
  const person = principals.ensure('person');
  const ask = (via, name, resource) => authorization.allowed({ subject: { id: person.id, via: { kind: via } }, action: { name }, resource }).decision;
  for (const [name, resource] of [['connect', { type: 'connection', holder: person.id }], ['disconnect', { type: 'connection', id: 'x', holder: person.id }], ['export', { type: 'principal', id: person.id }]]) {
    assert.equal(ask('key', name, resource), ask('session', name, resource), name);
    assert.equal(ask('key', name, resource), true, name);
  }
  store.close();
});

test('所有者は所有する相手を管理するが、その持ち物には届かない', () => {
  const store = new Store(':memory:', KEY), principals = new Principals(store), authorization = new Authorization(principals, new Resources(store));
  const person = principals.ensure('person'), ai = principals.create(person.id, { name: 'ai' });
  const ask = (name, resource) => authorization.allowed({ subject: { id: person.id, via: { kind: 'key' } }, action: { name }, resource }).decision;
  assert.equal(ask('issue-key', { type: 'principal', id: ai.id }), true);
  assert.equal(ask('remove', { type: 'principal', id: ai.id }), true);
  assert.equal(ask('content', { type: 'connection', id: 'x', holder: ai.id }), false);
  principals.relate(person.id, 'agent', 'principal', ai.id);
  assert.equal(ask('list', { type: 'connection', holder: ai.id }), true, '届かせるには代理の関係を別に引く');
  store.close();
});
