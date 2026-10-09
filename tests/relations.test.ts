import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { principal } from '../server/authorization.js';
import { AgreementNeeded } from '../server/relations.js';
import { MemoryPayments } from './fakes.js';
import { AccessPolicy, ContentTypes, protect, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';

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

// The application over a fixture, and a way to call it as one of its people.
async function served(f: Awaited<ReturnType<typeof fixture>>) {
  const app = await buildApp(await createContext(f.config, { db: f.db, mailer: f.mailer }));
  const call = (who: { token: string }, url: string, payload: object = {}, method: 'POST' | 'PUT' = 'POST') =>
    app.inject({ method, url, headers: { authorization: 'Bearer ' + who.token }, payload });
  return { app, call };
}

test('支払元の線は、払う側と払ってもらう側の両方で支払いを管理できる人なら、その場で引ける', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), sponsor = await f.person('Sponsor');
  const bot = await f.principals.create('Bot', null, owner.actor.id);
  await f.relations.draw(sponsor.actor, { subjectId: owner.actor.id, relation: 'billing_manager', objectId: sponsor.actor.id });
  await f.relations.draw(owner.actor, { subjectId: sponsor.actor.id, relation: 'payer', objectId: bot.id });
  assert.equal(await f.billing.payer(bot.id), sponsor.actor.id);
  await assert.rejects(f.relations.draw(owner.actor, { subjectId: bot.id, relation: 'payer', objectId: sponsor.actor.id }),
    { code: 'relation_cycle' });
});

test('片方の側しか持たない人が支払元の線を引くと、もう片方への依頼になり、承認されたときに引かれる', async (t) => {
  const f = await fixture(), { app, call } = await served(f);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), sponsor = await f.person('Sponsor');
  const bot = await f.principals.create('Bot', null, owner.actor.id);
  const line = { subjectId: sponsor.actor.id, relation: 'payer', objectId: bot.id };
  const asked = await call(owner, '/api/relations', line);
  assert.equal(asked.statusCode, 202, asked.body);
  assert.deepEqual(asked.json().to, { id: sponsor.actor.id, name: 'Sponsor' });
  assert.deepEqual(asked.json().proposal, { kind: 'line', subject: { id: sponsor.actor.id, name: 'Sponsor' },
    relation: 'payer', object: { id: bot.id, name: 'Bot' } });
  assert.equal(await f.billing.payer(bot.id), owner.actor.id);
  assert.equal((await call(sponsor, '/api/requests/' + asked.json().id + '/approve')).json().state, 'approved');
  assert.equal(await f.billing.payer(bot.id), sponsor.actor.id);
  await f.relations.erase(owner.actor, line);
  const offered = await call(sponsor, '/api/relations', line);
  assert.equal(offered.statusCode, 202, offered.body);
  assert.deepEqual(offered.json().to, { id: bot.id, name: 'Bot' });
  assert.equal((await call(owner, '/api/requests/' + offered.json().id + '/approve')).json().state, 'approved');
  assert.equal(await f.billing.payer(bot.id), sponsor.actor.id);
});

test('共有を管理するだけの人は、相手を支払元にできず、相手に頼むことしかできない', async (t) => {
  const f = await fixture(), { app, call } = await served(f);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), helper = await f.person('Helper');
  await f.relations.draw(owner.actor, { subjectId: helper.actor.id, relation: 'sharer', objectId: owner.actor.id });
  const bot = await f.principals.create('Helper bot', null, helper.actor.id);
  const asked = await call(helper, '/api/relations', { subjectId: owner.actor.id, relation: 'payer', objectId: bot.id });
  assert.equal(asked.statusCode, 202, asked.body);
  assert.equal(asked.json().to.id, owner.actor.id);
  assert.equal((await call(owner, '/api/requests/' + asked.json().id + '/decline')).json().state, 'declined');
  assert.equal(await f.billing.payer(bot.id), helper.actor.id);
});

test('AI は持ち主が払うお金で支払元になれず、AI に頼まれた支払いは持ち主に届く', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), stranger = await f.person('Stranger');
  const ai = await f.principals.create('AI', null, owner.actor.id);
  const bot = await f.principals.create('Stranger bot', null, stranger.actor.id);
  const line = { subjectId: ai.id, relation: 'payer', objectId: bot.id };
  await assert.rejects(f.relations.draw({ id: ai.id }, line), { code: 'forbidden' });
  await assert.rejects(f.relations.draw(stranger.actor, line),
    (error) => error instanceof AgreementNeeded && error.to === owner.actor.id);
  assert.equal(await f.billing.payer(bot.id), stranger.actor.id);
});

test('支払元の線は、どちらかの側で支払いを管理できる人が外せる', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Owner'), sponsor = await f.person('Sponsor'),
    accountant = await f.person('Accountant'), helper = await f.person('Helper');
  const bot = await f.principals.create('Bot', null, owner.actor.id);
  await f.relations.draw(sponsor.actor, { subjectId: owner.actor.id, relation: 'billing_manager', objectId: sponsor.actor.id });
  await f.relations.draw(owner.actor, { subjectId: accountant.actor.id, relation: 'billing_manager', objectId: bot.id });
  await f.relations.draw(owner.actor, { subjectId: helper.actor.id, relation: 'sharer', objectId: bot.id });
  const line = { subjectId: sponsor.actor.id, relation: 'payer', objectId: bot.id };
  await f.relations.draw(owner.actor, line);
  await assert.rejects(f.relations.erase(helper.actor, line), { code: 'forbidden' });
  await f.relations.erase(sponsor.actor, line);
  assert.equal(await f.billing.payer(bot.id), owner.actor.id);
  await f.relations.draw(owner.actor, line);
  await f.relations.erase(accountant.actor, line);
  assert.equal(await f.billing.payer(bot.id), owner.actor.id);
});

test('お金を払う人に支払い方法がなければ、支払元の線を引かない', async (t) => {
  const f = await fixture({}, new MemoryPayments());
  t.after(f.close);
  const owner = await f.person('Owner'), sponsor = await f.person('Sponsor');
  const bot = await f.principals.create('Bot', null, owner.actor.id);
  await f.relations.draw(sponsor.actor, { subjectId: owner.actor.id, relation: 'billing_manager', objectId: sponsor.actor.id });
  const line = { subjectId: sponsor.actor.id, relation: 'payer', objectId: bot.id };
  await assert.rejects(f.relations.draw(owner.actor, line), { code: 'payment_required' });
  await f.db.pool.query("INSERT INTO payment_accounts(principal_id,customer_id,status) VALUES($1,'customer-sponsor','active')",
    [sponsor.actor.id]);
  await f.relations.draw(owner.actor, line);
  assert.equal(await f.billing.payer(bot.id), sponsor.actor.id);
});

test('持ち主を移すと、受け取る側でも作れる人ならその場で移り、そうでなければ受け取る側が承認したときに移る', async (t) => {
  const f = await fixture(), { app, call } = await served(f);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), other = await f.person('Other');
  const team = await f.principals.create('Team', null, owner.actor.id), bot = await f.principals.create('Bot', null, owner.actor.id);
  const file = await f.resources.insert(owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  assert.equal((await call(owner, '/api/resources/' + file.id + '/transfer', { to: team.id })).statusCode, 200);
  assert.equal((await f.resources.get(file.id)).owner_id, team.id);
  await assert.rejects(f.relations.transfer(other.actor, file.id, other.actor.id), { code: 'forbidden' });
  const asked = await call(owner, '/api/resources/' + file.id + '/transfer', { to: other.actor.id });
  assert.equal(asked.statusCode, 202, asked.body);
  assert.deepEqual(asked.json().proposal, { kind: 'transfer', item: { id: file.id, name: 'report.txt' },
    to: { id: other.actor.id, name: 'Other' } });
  assert.equal((await f.resources.get(file.id)).owner_id, team.id);
  assert.equal((await call(other, '/api/requests/' + asked.json().id + '/approve')).json().state, 'approved');
  assert.equal((await f.resources.get(file.id)).owner_id, other.actor.id);
  const passed = await call(owner, '/api/principals/' + bot.id + '/transfer', { to: other.actor.id });
  assert.equal(passed.statusCode, 202, passed.body);
  assert.equal((await f.principals.get(bot.id)).owner_id, owner.actor.id);
  assert.equal((await call(other, '/api/requests/' + passed.json().id + '/approve')).json().state, 'approved');
  assert.equal((await f.principals.get(bot.id)).owner_id, other.actor.id);
});

test('承認までに頼んだ人が譲る権限を失っていると、承認されても移さない', async (t) => {
  const f = await fixture(), { app, call } = await served(f);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), helper = await f.person('Helper'), other = await f.person('Other');
  const file = await f.resources.insert(owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  const role = { subjectId: helper.actor.id, relation: 'transferrer', objectId: file.id };
  await f.relations.draw(owner.actor, role);
  const asked = await call(helper, '/api/resources/' + file.id + '/transfer', { to: other.actor.id });
  assert.equal(asked.statusCode, 202, asked.body);
  await f.relations.erase(owner.actor, role);
  assert.equal((await call(other, '/api/requests/' + asked.json().id + '/approve')).statusCode, 403);
  assert.equal((await f.resources.get(file.id)).owner_id, owner.actor.id);
});

test('依頼を出した鍵が取り消されると、その依頼はなくなる', async (t) => {
  const f = await fixture(), { app, call } = await served(f);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), other = await f.person('Other');
  const file = await f.resources.insert(owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  const second = await f.authentication.issueKey(owner.actor.id, 'Second key');
  const asked = await call(second, '/api/resources/' + file.id + '/transfer', { to: other.actor.id });
  assert.equal(asked.statusCode, 202, asked.body);
  await f.authentication.removeCredential(owner.actor, owner.actor.id, second.credential.id);
  assert.equal((await call(other, '/api/requests/' + asked.json().id + '/approve')).statusCode, 404);
  assert.equal((await f.resources.get(file.id)).owner_id, owner.actor.id);
});

test('鍵で守られた項目は、新しい持ち主向けに封をした内容が、受け取る側の承認で保存される', async (t) => {
  const f = await fixture(), { app, call } = await served(f);
  t.after(async () => { await app.close(); await f.close(); });
  const owner = await f.person('Owner'), other = await f.person('Other');
  const policy = AccessPolicy.parse({ format: 2, id: crypto.randomUUID(), origin: f.config.origin, ownerId: owner.actor.id,
    contentType: ContentTypes.value, revision: 1, authorities: [owner.binding], readers: [owner.binding], grants: [] });
  const first = await protect(encode('kept value'), policy, 1, owner.binding, owner.keys);
  const row = await f.custody.put(owner.actor, { name: 'Token', content: first });
  const passed = await protect(encode('kept value'), { ...policy, ownerId: other.actor.id, revision: 2,
    authorities: [other.binding], readers: [other.binding] }, 2, owner.binding, owner.keys, undefined, first);
  const asked = await call(owner, '/api/resources/' + row.id + '/custody', { name: row.name, version: row.version, content: passed }, 'PUT');
  assert.equal(asked.statusCode, 202, asked.body);
  assert.deepEqual(asked.json().proposal, { kind: 'transfer', item: { id: row.id, name: 'Token' }, to: { id: other.actor.id, name: 'Other' } });
  assert.equal((await f.resources.get(row.id)).owner_id, owner.actor.id);
  const approvedResponse = await call(other, '/api/requests/' + asked.json().id + '/approve');
  assert.equal(approvedResponse.json().state, 'approved', approvedResponse.body);
  assert.equal((await f.resources.get(row.id)).owner_id, other.actor.id);
  assert.equal(decode(await reveal((await f.custody.read(other.actor, row.id)).content, other.binding, other.keys.encryption)), 'kept value');
});
