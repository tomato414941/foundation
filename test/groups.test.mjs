import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A, USER_B } from './helpers.mjs';
import { seal, open } from '../cli/envelope.mjs';

const b64 = buffer => Buffer.from(buffer).toString('base64url');

test('集団として作った相手には、作った者がその者として立ち、集団の持ち物を見て使い、他の人も立てる', async t => {
  const f = await fixture(t);
  const made = await f.request('/v1/principals', { method: 'POST', data: { name: '経理チーム', member: true } });
  assert.equal(made.status, 201, made.text);
  const group = made.json.principal;
  assert.deepEqual(group.members, [USER_A]); assert.deepEqual(group.owners, [USER_A]); assert.deepEqual(group.keys, []);
  const machine = await f.request('/v1/principals', { method: 'POST', data: { name: 'box', key: true } });
  assert.deepEqual(machine.json.principal.members, [], 'one with a key of its own stands for itself');
  assert.deepEqual((await f.request('/v1/principals', { method: 'POST', data: { alias: 'user-1' } })).json.principal.members, [], 'one made for someone else to come in as is nobody\'s to stand as');
  // The group keeps a secret; its member sees it, since it is sealed for those who stand as the group.
  const kept = await f.keep('secret', 'budget', 'q4-budget', { as: group.id });
  assert.equal(kept.status, 200, kept.text);
  assert.equal(kept.json.resource.owner_id, group.id);
  assert.ok(kept.json.resource.recipients.includes(USER_A));
  assert.equal((await f.read('secret', 'budget', { as: group.id })).text, 'q4-budget');
  // Another person: nothing, until made a member by one who stands as the group; then the secret, once handed its key.
  const other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const theirs = { token: other.json.token, anonymous: true };
  assert.equal((await f.request('/v1/principals/' + group.id + '/resources?kind=secret', theirs)).status, 403);
  assert.equal((await f.request('/v1/principals/' + other.json.principal.id + '/relations', { method: 'POST', token: other.json.token, anonymous: true, data: { relation: 'member', object_type: 'principal', object_id: group.id } })).status, 403, 'not by oneself');
  const drawn = await f.request('/v1/principals/' + other.json.principal.id + '/relations', { method: 'POST', data: { relation: 'member', object_type: 'principal', object_id: group.id } });
  assert.equal(drawn.status, 201, drawn.text);
  assert.deepEqual((await f.request('/v1/principals/' + group.id)).json.principal.members.sort(), [USER_A, other.json.principal.id].sort());
  const shown = await f.request('/v1/resources/' + kept.json.resource.id + '/content', theirs);
  assert.equal(shown.status, 200); assert.equal(shown.json.envelope, null, 'allowed, not yet handed the key');
  const mine = await f.keyOf({}), theirKey = await f.keyOf(theirs);
  const contentKey = open(Buffer.from((await f.request('/v1/resources/' + kept.json.resource.id + '/content')).json.envelope, 'base64url'), mine.privateKey);
  assert.equal((await f.request('/v1/resources/' + kept.json.resource.id + '/envelopes/' + other.json.principal.id, { method: 'PUT', data: { wrapped: b64(seal(contentKey, theirKey.publicKey)) } })).status, 200);
  assert.equal((await f.read('secret', 'budget', { ...theirs, as: group.id })).text, 'q4-budget');
  // What the group keeps from now on is sealed for both members.
  const next = await f.keep('secret', 'forecast', 'q1', { as: group.id });
  assert.ok([USER_A, other.json.principal.id].every(id => next.json.resource.recipients.includes(id)));
  // Foundation made the group's agent by a member: the group's secrets are injected.
  assert.equal((await f.request('/v1/principals/' + f.app.keys.agentId + '/relations', { method: 'POST', data: { relation: 'agent', object_type: 'principal', object_id: group.id } })).status, 201);
  const third = await f.keep('secret', 'ledger', 'rows', { as: group.id });
  assert.ok(third.json.resource.recipients.includes(f.app.keys.agentId));
  assert.deepEqual((await f.request('/v1/principals/' + group.id + '/injections', { method: 'POST', data: { names: [{ name: 'ledger', as: 'LEDGER' }] } })).json.injection.environment, { LEDGER: 'rows' });
  // Owning a group manages it; standing as it decides for it. USER_B, owning nothing here, reaches nothing.
  await f.signin('other@example.test');
  assert.equal((await f.request('/v1/principals/' + group.id + '/resources?kind=secret')).status, 403);
  assert.equal(f.app.authorization.can(USER_B, 'decide', 'principal', { id: group.id }), false);
  assert.equal(f.app.authorization.can(USER_A, 'decide', 'principal', { id: group.id }), true);
  assert.equal(f.app.authorization.can(USER_A, 'remove', 'principal', { id: group.id }), true, 'as its owner');
});

test('プリンシパルの線は、本人とオーナーとメンバーにだけ、両方の向きで、相手の名前つきで、区切って見える', async t => {
  const f = await fixture(t);
  const machine = await f.issueKey('machine'), stranger = await f.become('stranger');
  const lines = async (id, query = '', options = {}) => f.request('/v1/principals/' + id + '/relations' + query, options);
  // The owner's own: the machine it owns and that acts for it, and Foundation's principal made its agent at sign-in.
  const mine = await lines('me');
  assert.equal(mine.status, 200, mine.text);
  const seen = mine.json.relations.map(line => [line.direction, line.relation, line.principal?.name]);
  assert.ok(seen.some(([direction, relation, name]) => direction === 'from' && relation === 'owner' && name === 'machine'), 'what it owns');
  assert.ok(seen.some(([direction, relation, name]) => direction === 'to' && relation === 'agent' && name === 'machine'), 'who acts for it');
  assert.ok(seen.some(([direction, relation, name]) => direction === 'to' && relation === 'agent' && name === 'Foundation Agent'));
  assert.deepEqual(Object.keys(mine.json.relations.find(line => line.principal?.name === 'machine').principal).sort(), ['id', 'name'], 'the other end by id and name, no more');
  assert.deepEqual((await lines('me', '?relation=owner&direction=from')).json.relations.map(line => line.principal.name), ['machine']);
  assert.deepEqual((await lines('me', '?principal=' + machine.id)).json.relations.map(line => [line.direction, line.relation]).sort(), [['from', 'owner'], ['to', 'agent']], 'the lines between it and one other');
  // A line onto a thing names the thing.
  const kept = (await f.keep('secret', 'shown', 'value')).json.resource;
  assert.equal((await f.request('/v1/principals/' + machine.id + '/relations', { method: 'POST', data: { relation: 'viewer', object_type: 'resource', object_id: kept.id } })).status, 201);
  const theirs = await lines(machine.id, '?relation=viewer');
  assert.deepEqual(theirs.json.relations.map(line => [line.direction, line.resource.kind, line.resource.name]), [['from', 'secret', 'shown']], 'the owner reads the lines of what it owns');
  // A page at a time.
  const first = await lines('me', '?limit=1');
  assert.equal(first.json.relations.length, 1); assert.ok(first.json.next);
  const rest = await lines('me', '?limit=200&after=' + first.json.next);
  assert.equal(rest.json.next, null);
  assert.equal(first.json.relations.length + rest.json.relations.length, mine.json.relations.length);
  assert.equal((await lines('me', '?limit=0')).status, 400);
  // Nobody else is told whom a principal is joined to: not a stranger, not one who acts for it, not one it acts for.
  assert.equal((await lines(USER_A, '', { token: stranger.token, anonymous: true })).status, 401);
  assert.equal((await lines(USER_A, '', { token: machine.token, anonymous: true })).status, 403, 'acting for it is not reading its lines');
  const group = (await f.request('/v1/principals', { method: 'POST', data: { name: 'team', member: true } })).json.principal;
  assert.equal((await lines(group.id)).status, 200, 'a member reads the group\'s');
  // The principal the server acts as is found by a name, by anyone.
  const agent = await f.request('/v1/principals/agent', { token: stranger.token, anonymous: true });
  assert.equal(agent.status, 200, agent.text);
  assert.deepEqual([agent.json.principal.id, agent.json.principal.name], [f.app.keys.agentId, 'Foundation Agent']);
});
