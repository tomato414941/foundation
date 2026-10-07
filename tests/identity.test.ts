import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { seal, open, encode, decode, wrap, unwrap } from '../shared/encryption.js';
import { AccessPolicy, protect, reveal, continuesPolicy } from '../shared/custody.js';

test('メンバー追加と所有者変更で配下の秘密を再暗号化し、新しい相手が開けるようにする', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), member = await f.person('Member'), next = await f.person('New owner');
  const project = await f.principals.create('Project', null, owner.actor.id);
  const child = await f.principals.create('Nested project', null, project.id);
  const bytes = encode('shared project secret'), id = randomUUID();
  const initial = await protect(bytes, AccessPolicy.parse({ format: 1, id, origin: f.config.origin,
    ownerId: child.id, kind: 'secret', revision: 1, authorities: [owner.binding], readers: [owner.binding], grants: [] }),
    1, owner.binding, owner.keys);
  await f.custody.put(owner.actor, { name: 'Project secret', content: initial });
  await assert.rejects(f.principals.relate(owner.actor, member.actor.id, 'member', project.id), { code: 'rekey_required' });
  const updates = async (subject: string, relation: 'member' | 'owner') => {
    const plan = await f.principals.keySharing.plan(owner.actor, project.id, subject, relation);
    return Object.fromEntries(await Promise.all(plan.items.map(async item => [item.id, {
      version: item.version, content: await protect(bytes, item.policy, item.content.materialRevision + 1,
        owner.binding, owner.keys, item.content.metadata, item.content),
    }])));
  };
  await f.principals.relate(owner.actor, member.actor.id, 'member', project.id, await updates(member.actor.id, 'member'));
  const shared = (await f.custody.read(member.actor, id)).content;
  assert.equal(decode(await reveal(shared, member.binding, member.keys.encryption)), decode(bytes));
  const transferred = await updates(next.actor.id, 'owner');
  await f.resources.rename(owner.actor, await f.resources.get(id), 'Renamed secret');
  await assert.rejects(f.principals.transfer(owner.actor, project.id, next.actor.id, transferred), { code: 'changed' });
  transferred[id]!.version = (await f.resources.get(id)).version;
  await f.principals.transfer(owner.actor, project.id, next.actor.id, transferred);
  const result = (await f.custody.read(next.actor, id)).content;
  assert.equal(continuesPolicy(shared.policy, result), true);
  assert.equal(decode(await reveal(result, next.binding, next.keys.encryption)), decode(bytes));
  assert.equal(decode(await reveal(result, member.binding, member.keys.encryption)), decode(bytes));
  await assert.rejects(f.custody.read(owner.actor, id), { code: 'forbidden' });
  const updated = await protect(encode('new value'), result.policy, result.materialRevision + 1,
    next.binding, next.keys, undefined, result);
  await f.custody.put(next.actor, { name: 'Renamed secret', content: updated, version: (await f.resources.get(id)).version });
  assert.equal(decode(await reveal((await f.custody.read(next.actor, id)).content, next.binding, next.keys.encryption)), 'new value');
});

test('シークレットを新しい所有者へ移し、宛先の鍵と編集権限を引き継ぐ', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Before'), next = await f.person('After'), id = randomUUID();
  const policy = AccessPolicy.parse({ format: 1, id, origin: f.config.origin, ownerId: owner.actor.id,
    kind: 'secret', revision: 1, authorities: [owner.binding], readers: [owner.binding], grants: [] });
  const initial = await protect(encode('transfer-value'), policy, 1, owner.binding, owner.keys);
  const row = await f.custody.put(owner.actor, { name: 'Transferred secret', content: initial });
  const content = await protect(encode('transfer-value'), { ...policy, ownerId: next.actor.id,
    revision: 2, authorities: [next.binding], readers: [next.binding] }, 2, owner.binding, owner.keys, undefined, initial);
  await f.custody.put(owner.actor, { name: row.name, version: row.version, content });
  assert.equal((await f.resources.get(id)).owner_id, next.actor.id);
  assert.equal(decode(await reveal((await f.custody.read(next.actor, id)).content, next.binding, next.keys.encryption)), 'transfer-value');
  await assert.rejects(f.custody.read(owner.actor, id), { code: 'forbidden' });
});

test('機械が自分の鍵で登録し、自分のプリンシパルとして認証する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person('Machine');
  assert.equal(owner.actor.id, owner.principal.id);
  assert.equal((await f.principals.get(owner.actor.id)).name, 'Machine');
  const session = await f.authentication.session(owner.actor.id, owner.credential.id);
  assert.equal((await f.authentication.authenticate(session.token))?.id, owner.actor.id);
  await f.db.pool.query('DELETE FROM credentials WHERE id=$1', [owner.credential.id]);
  assert.equal(await f.authentication.authenticate(owner.token), null);
  assert.equal(await f.authentication.authenticate(session.token), null);
});

test('メンバーを外すと宛先と編集権限を更新し、残る所有者が秘密を使い続ける', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person(), member = await f.person('Member');
  const project = await f.principals.create('Project', null, owner.actor.id);
  await f.principals.relate(owner.actor, member.actor.id, 'member', project.id);
  const policy = AccessPolicy.parse({ format: 1, id: randomUUID(), origin: f.config.origin,
    ownerId: project.id, kind: 'secret', revision: 1, authorities: [owner.binding, member.binding], readers: [owner.binding, member.binding], grants: [] });
  const bytes = encode('private value'), content = await protect(bytes, policy, 1, owner.binding, owner.keys);
  const row = await f.custody.put(owner.actor, { name: 'Credential', content });
  const plan = await f.principals.keySharing.plan(owner.actor, project.id, member.actor.id, 'member', f.db.pool, true);
  const update = plan.items[0]!;
  await f.principals.unrelate(owner.actor, member.actor.id, 'member', project.id, { [row.id]: { version: row.version,
    content: await protect(bytes, update.policy, 2, owner.binding, owner.keys, content.metadata, content) } });
  const current = (await f.custody.read(owner.actor, row.id)).content;
  assert.equal(decode(await reveal(current, owner.binding, owner.keys.encryption)), 'private value');
  await assert.rejects(f.custody.read(member.actor, row.id), { code: 'forbidden' });
});

test('公開鍵で暗号化したシークレットを宛先の秘密鍵で開く', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person(),
    stranger = await f.person('Stranger');
  const value = await seal(
    encode('correct secret'),
    [{ id: owner.actor.id, publicKey: owner.keys.publicKey }],
    'item',
  );
  assert.equal(decode(await open(value, owner.keys.privateKey, owner.actor.id, 'item')), 'correct secret');
  await assert.rejects(open(value, stranger.keys.privateKey, owner.actor.id, 'item'));
  await assert.rejects(open(value, owner.keys.privateKey, owner.actor.id, 'different item'));
  const prf = crypto.getRandomValues(new Uint8Array(32));
  assert.deepEqual(
    await unwrap(await wrap(owner.keys.privateKey, prf, owner.actor.id), prf, owner.actor.id),
    owner.keys.privateKey,
  );
});

test('所有と所属の循環を拒否し、所有するプリンシパルの権限を継承する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person();
  const child = await f.principals.create('Child', null, owner.actor.id);
  const grandchild = await f.principals.create('Grandchild', null, child.id);
  assert.equal(await f.authorization.principal(owner.actor, grandchild.id, 'credentials'), true);
  await assert.rejects(f.principals.relate(owner.actor, child.id, 'member', owner.actor.id), {
    code: 'relation_cycle',
  });
  await assert.rejects(f.principals.transfer(owner.actor, child.id, grandchild.id), {
    code: 'relation_cycle',
  });
});

test('メールの確認リンクでサインインし、同じリンクの再使用を拒否する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  await f.authentication.beginEmail('person@example.test', 'browser');
  const link = new URL(f.mailer.sent[0]!.link),
    values = new URLSearchParams(link.hash.slice(1));
  const result = await f.authentication.verifyEmail(values.get('challenge')!, values.get('token')!);
  assert.ok('token' in result);
  assert.ok(await f.authentication.authenticate(result.token));
  await assert.rejects(f.authentication.verifyEmail(values.get('challenge')!, values.get('token')!), {
    code: 'invalid_link',
  });
});

test('同時に編集された項目を上書きせず、最新の値を保持する', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person();
  const resource = await f.resources.insert(owner.actor.id, 'service', 'Service', {});
  await f.resources.update(resource, { name: 'Latest' });
  await assert.rejects(f.resources.update(resource, { name: 'Stale' }), { code: 'changed' });
  assert.equal((await f.resources.get(resource.id)).name, 'Latest');
});
