import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { principal } from '../server/authorization.js';
import { AccessPolicy, ContentTypes, protect } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';

test('代理は持ち主の物を使えるが決められず、一つだけ渡された操作はその物でだけできる', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), ai = await f.person('Agent'), friend = await f.person('Friend');
  await f.relations.draw(owner.actor, { subjectId: ai.actor.id, relation: 'agent', objectId: owner.actor.id });
  const file = await f.resources.insert(owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  const other = await f.resources.insert(owner.actor.id, 'object', 'notes.txt', { size: 0, contentType: 'text/plain' });
  assert.equal(await f.authorization.holds(ai.actor.id, file, 'use'), true);
  assert.equal(await f.authorization.holds(ai.actor.id, file, 'update'), true);
  assert.equal(await f.authorization.holds(ai.actor.id, file, 'share'), false);
  assert.equal(await f.authorization.holds(ai.actor.id, file, 'rename'), false);
  assert.equal(await f.authorization.holds(owner.actor.id, file, 'rename'), true);
  await f.relations.draw(owner.actor, { subjectId: friend.actor.id, relation: 'reader', objectId: file.id });
  assert.equal(await f.authorization.holds(friend.actor.id, file, 'read'), true);
  assert.equal(await f.authorization.holds(friend.actor.id, file, 'update'), false);
  assert.equal(await f.authorization.holds(friend.actor.id, other, 'read'), false);
  assert.deepEqual((await f.resources.view(friend.actor, file)).permissions, ['read']);
});

test('持ち主としてふるまえる者と一員だけがプリンシパルを決め、持ち主だけが譲り、本人か持ち主が消せる', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), member = await f.person('Member'), ai = await f.person('Agent');
  const team = await f.principals.create('Team', null, owner.actor.id);
  await f.relations.draw(owner.actor, { subjectId: member.actor.id, relation: 'member', objectId: team.id });
  await f.relations.draw(owner.actor, { subjectId: ai.actor.id, relation: 'agent', objectId: team.id });
  const view = await f.principals.view(owner.actor, await f.principals.get(team.id));
  assert.deepEqual(view.owner, { id: owner.actor.id, name: 'Owner' });
  assert.ok(view.permissions.includes('transfer') && view.permissions.includes('manage_credentials'));
  const asMember = await f.principals.view(member.actor, await f.principals.get(team.id));
  assert.ok(asMember.permissions.includes('manage_billing'));
  assert.ok(!asMember.permissions.includes('transfer') && !asMember.permissions.includes('delete'));
  const asAgent = await f.principals.view(ai.actor, await f.principals.get(team.id));
  assert.deepEqual(asAgent.permissions, ['read', 'use', 'execute']);
  assert.ok(asAgent.createKinds.includes('variable') && !asAgent.createKinds.includes('connection'));
  assert.equal(await f.authorization.holds(team.id, principal(team.id), 'delete'), true);
});

test('共有だけを渡された相手は、自分をメンバーや代理にできず、持たない操作も渡せない', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), helper = await f.person('Helper'), other = await f.person('Other');
  await f.relations.draw(owner.actor, { subjectId: helper.actor.id, relation: 'sharer', objectId: owner.actor.id });
  for (const relation of ['member', 'agent', 'reader'])
    await assert.rejects(f.relations.draw(helper.actor, { subjectId: helper.actor.id, relation, objectId: owner.actor.id }),
      { code: 'forbidden' });
  await f.relations.draw(helper.actor, { subjectId: other.actor.id, relation: 'sharer', objectId: owner.actor.id });
  assert.equal(await f.authorization.holds(other.actor.id, principal(owner.actor.id), 'share'), true);
  assert.equal(await f.authorization.holds(other.actor.id, principal(owner.actor.id), 'stands'), false);
});

test('支払いの線は支払う側が引き、払われる側からは引けない', async (t) => {
  const f = await fixture(), c = await createContext(f.config, { db: f.db, mailer: f.mailer });
  t.after(f.close);
  const owner = await f.person('Owner'), sponsor = await f.person('Sponsor');
  const bot = await f.principals.create('Bot', null, owner.actor.id);
  const line = { subjectId: sponsor.actor.id, relation: 'payer', objectId: bot.id };
  await assert.rejects(f.relations.draw(owner.actor, line), { code: 'forbidden' });
  assert.equal(await c.billing.payer(bot.id), owner.actor.id);
  await f.relations.draw(sponsor.actor, line);
  assert.equal(await c.billing.payer(bot.id), sponsor.actor.id);
  await assert.rejects(f.relations.draw(owner.actor, { subjectId: bot.id, relation: 'payer', objectId: sponsor.actor.id }),
    { code: 'relation_cycle' });
});

test('主体は自分に引かれた線を外せ、対象で共有できる人も外せる', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), ai = await f.person('Agent'), stranger = await f.person('Stranger');
  const line = { subjectId: ai.actor.id, relation: 'agent', objectId: owner.actor.id };
  await f.relations.draw(owner.actor, line);
  await assert.rejects(f.relations.erase(stranger.actor, line), { code: 'forbidden' });
  await f.relations.erase(ai.actor, line);
  assert.equal(await f.authorization.holds(ai.actor.id, principal(owner.actor.id), 'use'), false);
  await f.relations.draw(owner.actor, line);
  await f.relations.erase(owner.actor, line);
  assert.equal(await f.authorization.holds(ai.actor.id, principal(owner.actor.id), 'use'), false);
});

test('鍵で守られた項目の役割は署名した方針から書かれ、線としては引けない', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), editor = await f.person('Editor'), viewer = await f.person('Viewer');
  const policy = AccessPolicy.parse({ format: 2, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    contentType: ContentTypes.value, revision: 1, authorities: [owner.binding, editor.binding],
    readers: [owner.binding, editor.binding], grants: [], observers: [viewer.actor.id] });
  const row = await f.custody.put(owner.actor, { name: 'Token', content: await protect(encode('value'), policy, 1, owner.binding, owner.keys) });
  assert.equal(await f.authorization.holds(editor.actor.id, row, 'reveal'), true);
  assert.equal(await f.authorization.holds(editor.actor.id, row, 'update'), true);
  assert.equal(await f.authorization.holds(viewer.actor.id, row, 'read'), true);
  assert.equal(await f.authorization.holds(viewer.actor.id, row, 'reveal'), false);
  await assert.rejects(f.relations.draw(owner.actor, { subjectId: viewer.actor.id, relation: 'revealer', objectId: row.id }),
    { code: 'rekey_required' });
});

test('線を「主体は対象の関係」として、対象からも主体からも一覧する', async (t) => {
  const f = await fixture(), context = await createContext(f.config, { db: f.db, mailer: f.mailer }),
    app = await buildApp(context);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), ai = await f.person('Agent');
  const drawn = await app.inject({ method: 'POST', url: '/api/relations', headers: { authorization: 'Bearer ' + owner.token },
    payload: { subjectId: ai.actor.id, relation: 'agent', objectId: owner.actor.id } });
  assert.equal(drawn.statusCode, 200, drawn.body);
  const onto = await app.inject({ url: '/api/relations?object=' + owner.actor.id, headers: { authorization: 'Bearer ' + owner.token } });
  assert.deepEqual(onto.json().items.map(({ createdAt: _, ...line }: { createdAt: string }) => line), [{
    subjectId: ai.actor.id, subjectName: 'Agent', relation: 'agent', objectId: owner.actor.id, objectName: 'Owner', objectType: 'principal',
  }]);
  const from = await app.inject({ url: '/api/relations?subject=' + ai.actor.id, headers: { authorization: 'Bearer ' + ai.token } });
  assert.deepEqual(from.json().items.map((line: { objectId: string }) => line.objectId), [owner.actor.id]);
  assert.equal((await app.inject({ url: '/api/relations?subject=' + ai.actor.id, headers: { authorization: 'Bearer ' + owner.token } })).statusCode, 403);
  assert.equal((await app.inject({ url: '/api/relations', headers: { authorization: 'Bearer ' + owner.token } })).statusCode, 400);
});
