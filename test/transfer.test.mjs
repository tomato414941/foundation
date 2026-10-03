import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, USER_A, USER_B, entry, FakeGoogle } from './helpers.mjs';
import { googleOauth } from '../src/adapters/google/index.mjs';
import { cloudflareOauth } from '../src/adapters/cloudflare/index.mjs';
import { FakeCloudflare } from '../src/adapters/cloudflare/fixture.mjs';
import { seal, open } from '../cli/envelope.mjs';

const b64 = buffer => Buffer.from(buffer).toString('base64url');
const give = (f, id, data, options = {}) => f.request('/v1/resources/' + id + '/transfer', { method: 'POST', data, ...options });

test('持ち主は秘密を相手に渡し、封筒をつけるか Foundation に作らせ、自分の封筒は線とともになくなる', async t => {
  const f = await fixture(t), other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const theirs = { token: other.json.token, anonymous: true }, key = await f.keyOf(theirs);
  const kept = await f.keep('secret', 'handed', 'hand-me');
  // The giver opens its own envelope and seals the key for the new owner, as a client does.
  const mine = await f.request('/v1/resources/' + kept.json.resource.id + '/content');
  const contentKey = open(Buffer.from(mine.json.envelope, 'base64url'), (await f.keyOf({})).privateKey);
  const given = await give(f, kept.json.resource.id, { to: other.json.principal.id, envelope: b64(seal(contentKey, key.publicKey)) });
  assert.equal(given.status, 200, given.text);
  assert.equal(given.json.resource.owner_id, other.json.principal.id);
  assert.deepEqual(given.json.resource.recipients.sort(), [f.app.keys.agentId, other.json.principal.id].sort(), 'the new owner has an envelope; the giver no longer');
  assert.equal((await f.read('secret', 'handed', theirs)).text, 'hand-me');
  assert.equal((await f.request('/v1/resources/' + kept.json.resource.id + '/content')).status, 403, 'the giver has no line to it');
  assert.deepEqual((await f.request('/v1/principals/me/resources?kind=secret')).json.resources, []);
  // Without an envelope from the giver, Foundation makes one from its own, for a new owner with a key.
  const second = await f.keep('secret', 'second', 'two');
  const handed = await give(f, second.json.resource.id, { to: other.json.principal.id });
  assert.equal(handed.status, 200, handed.text);
  assert.equal((await f.read('secret', 'second', theirs)).text, 'two');
  const log = (await f.request('/v1/principals/me/audit-log')).json.entries.filter(row => row.action === 'resource.transferred');
  assert.equal(log.length, 2); assert.deepEqual(log[0].detail, { from: USER_A, to: other.json.principal.id });
});

test('渡せるのは持ち主と、渡す操作を渡された相手だけで、同じ名前のものを持つ相手には渡せない', async t => {
  const f = await fixture(t), agent = await f.issueKey(), other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const kept = await f.keep('secret', 'thing', 'v');
  assert.equal((await give(f, kept.json.resource.id, { to: other.json.principal.id }, { token: agent.token })).status, 403, 'an agent uses, it does not give away');
  assert.equal((await give(f, kept.json.resource.id, { to: USER_A })).json.error.code, 'invalid_transfer');
  assert.equal((await give(f, kept.json.resource.id, { to: 'no-such' })).status, 404);
  await f.request('/v1/principals/me/resources?kind=secret&name=thing', { method: 'PUT', raw: 'theirs', token: other.json.token, anonymous: true });
  assert.equal((await give(f, kept.json.resource.id, { to: other.json.principal.id })).json.error.code, 'name_taken');
  f.app.principals.relate(agent.id, 'transfer_grant', 'resource', kept.json.resource.id);
  const byGrant = await give(f, kept.json.resource.id, { to: agent.id }, { token: agent.token });
  assert.equal(byGrant.status, 200, byGrant.text);
  assert.equal(byGrant.json.resource.owner_id, agent.id);
});

test('接続とアプリは新しい持ち主の名前で封じ直され、そのまま使える', async t => {
  const f = await fixture(t, { services: [entry('google', { oauth: googleOauth(new FakeGoogle()) }), entry('cloudflare', { oauth: cloudflareOauth(new FakeCloudflare()) })] });
  const connection = await f.connection(), other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const theirs = { token: other.json.token, anonymous: true, as: other.json.principal.id };
  const moved = await give(f, connection.id, { to: other.json.principal.id });
  assert.equal(moved.status, 200, moved.text);
  assert.equal(f.app.connections.get(connection.id).owner_id, other.json.principal.id);
  assert.equal(f.app.connections.state(f.app.connections.get(connection.id)).private_state.refresh_token !== undefined, true, 'opens under the new name');
  const delivered = await f.inject(connection, theirs);
  assert.equal(delivered.status, 200, delivered.text);
  assert.equal(delivered.json.injection.environment.GOOGLE_OAUTH_ACCESS_TOKEN, 'google-access-personal');
  assert.equal((await f.inject(connection)).status, 404, 'no longer the giver\'s');
  const app = await f.request('/v1/principals/me/resources?kind=app&name=mine', { method: 'PUT', data: { service: 'cloudflare', client_id: 'id-1', client_secret: 'secret-1' } });
  assert.equal(app.status, 200, app.text);
  const appMoved = await give(f, app.json.resource.id, { to: other.json.principal.id });
  assert.equal(appMoved.status, 200, appMoved.text);
  assert.equal(f.app.apps.clientValues(f.app.apps.get(app.json.resource.id)).clientSecret, 'secret-1', 'its secret opens under the new name');
});

test('サービスは参照するものがなければ渡せ、オブジェクトは相手の枠に入れば渡せ、エンバイロメントは渡せない', async t => {
  const f = await fixture(t), other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const service = await f.request('/v1/principals/me/resources?kind=service&name=Notes', { method: 'PUT', data: { name: 'Notes' } });
  assert.equal(service.status, 200, service.text);
  // Something of the owner's referring to it keeps it where it is.
  f.app.resources.insert('conn-1', USER_A, 'connection', 'Notes');
  f.app.store.db.prepare("INSERT INTO connections (resource_id,service,auth_scheme,subject,status,generation,state) VALUES ('conn-1',?,'token',NULL,'usable',1,'x')").run(service.json.resource.id);
  assert.equal((await give(f, service.json.resource.id, { to: other.json.principal.id })).json.error.code, 'service_in_use');
  f.app.resources.remove(f.app.resources.get('conn-1'));
  assert.equal((await give(f, service.json.resource.id, { to: other.json.principal.id })).status, 200);
  assert.equal(f.app.services.row(service.json.resource.id).owner_id, other.json.principal.id);
  const object = await f.request('/v1/principals/me/resources?kind=object&name=file.txt', { method: 'PUT', raw: Buffer.from('bytes'), type: 'text/plain' });
  if (object.status === 200) {
    assert.equal((await give(f, object.json.resource.id, { to: other.json.principal.id })).status, 200);
    assert.equal(f.app.resources.get(object.json.resource.id).owner_id, other.json.principal.id);
  }
  f.app.resources.insert('11111111-1111-4111-8111-111111111111', USER_A, 'environment', 'box');
  f.app.store.db.prepare("INSERT INTO environments (resource_id,size,lifetime,idle_seconds,max_seconds,identity,runner,machine,status,started_at,last_active_at,expires_at) VALUES ('11111111-1111-4111-8111-111111111111','s','idle',60,600,NULL,'local',NULL,'ready',1,1,9999999999999)").run();
  assert.equal((await give(f, '11111111-1111-4111-8111-111111111111', { to: other.json.principal.id })).status, 405);
});

test('持ち主は持っている相手を別の相手に渡し、別名は消え、その相手の線と鍵はそのまま残る', async t => {
  const f = await fixture(t), machine = await f.issueKey('box'), other = await f.request('/v1/principals', { method: 'POST', data: { name: 'other', key: true } });
  const aliased = await f.request('/v1/principals', { method: 'POST', data: { alias: 'ext-1' } });
  assert.equal((await f.request('/v1/principals/' + machine.id + '/transfer', { method: 'POST', token: machine.token, anonymous: true, data: { to: other.json.principal.id } })).status, 403, 'not by itself');
  assert.equal((await f.request('/v1/principals/' + machine.id + '/transfer', { method: 'POST', data: { to: USER_A } })).json.error.code, 'invalid_transfer');
  const moved = await f.request('/v1/principals/' + machine.id + '/transfer', { method: 'POST', data: { to: other.json.principal.id } });
  assert.equal(moved.status, 200, moved.text);
  assert.deepEqual(moved.json.principal.owners, [other.json.principal.id]);
  assert.deepEqual(moved.json.principal.acts_for, [USER_A], 'it still acts for whom it acted for');
  assert.deepEqual((await f.request('/v1/principals/me/relations?relation=owner&direction=from')).json.relations.map(row => row.principal.id).sort(), [other.json.principal.id, aliased.json.principal.id].sort(), 'no longer among what the giver owns');
  assert.deepEqual((await f.request('/v1/principals/me/relations?relation=owner&direction=from', { token: other.json.token, anonymous: true })).json.relations.map(row => row.principal.id), [machine.id]);
  const withAlias = await f.request('/v1/principals/' + aliased.json.principal.id + '/transfer', { method: 'POST', data: { to: other.json.principal.id } });
  assert.equal(withAlias.status, 200, withAlias.text);
  assert.equal(f.app.principals.aliasOf(USER_A, aliased.json.principal.id), null);
  assert.equal(f.app.principals.aliasOf(other.json.principal.id, aliased.json.principal.id), null, 'an alias was the old owner\'s word');
  assert.equal((await f.request('/v1/principals/' + machine.id + '/transfer', { method: 'POST', data: { to: USER_B } })).status, 403, 'no longer the owner');
});
