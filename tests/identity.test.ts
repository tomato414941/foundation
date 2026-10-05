import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { seal, open, encode, decode, wrap, unwrap } from '../shared/encryption.js';

test('シークレットを新しい所有者へ移し、宛先の鍵と権限を更新する', async t => {
  const f=await fixture();t.after(f.close);
  const owner=await f.person('Before'),next=await f.person('After'),id=randomUUID();
  const original=await seal(encode('transfer-value'),[{id:owner.actor.id,publicKey:owner.keys.publicKey}],'resource:'+id);
  const row=await f.resources.createSecret(owner.actor,owner.actor.id,{kind:'secret',id,name:'Transferred secret',sealed:original,bytes:14,allowUse:false});
  const sealed=await seal(encode('transfer-value'),[{id:next.actor.id,publicKey:next.keys.publicKey}],'resource:'+id);
  await f.resources.transfer(owner.actor,row,next.actor.id,sealed);
  const transferred=await f.resources.get(id),content=await f.resources.secretContent(next.actor,id);
  assert.equal(transferred.owner_id,next.actor.id);assert.deepEqual(transferred.data.recipients,[next.actor.id]);
  assert.equal(decode(await open(content.sealed,next.keys.privateKey,next.actor.id,content.context)),'transfer-value');
  await assert.rejects(()=>f.resources.secretContent(owner.actor,id),{code:'forbidden'});
});

test('機械が自分の鍵で登録し、自分のプリンシパルとして認証する', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Machine');
  assert.equal(owner.actor.id, owner.principal.id);
  assert.equal((await f.principals.get(owner.actor.id)).name, 'Machine');
  const session = await f.authentication.session(owner.actor.id, owner.credential.id);
  assert.equal((await f.authentication.authenticate(session.token))?.id, owner.actor.id);
  await f.db.pool.query('DELETE FROM credentials WHERE id=$1', [owner.credential.id]);
  assert.equal(await f.authentication.authenticate(owner.token), null);
  assert.equal(await f.authentication.authenticate(session.token), null);
});

test('所有者がエージェントに利用を委任し、解除すると利用を拒否する', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person(), agent = await f.person('Agent'), stranger = await f.person('Stranger');
  await f.principals.relate(owner.actor, agent.actor.id, 'agent', owner.actor.id);
  const id = randomUUID(), content = encode('private value');
  const sealed = await seal(content, [{ id: owner.actor.id, publicKey: owner.keys.publicKey }, { id: f.identity.id, publicKey: f.identity.publicKey }], 'resource:' + id);
  const secret = await f.resources.createSecret(owner.actor, owner.actor.id, { kind: 'secret', id, name: 'api-token', sealed, bytes: content.length, allowUse: true });
  assert.equal(await f.authorization.resource(agent.actor, secret, 'use'), true);
  assert.equal(await f.authorization.resource(agent.actor, secret, 'reveal'), false);
  assert.equal(await f.authorization.resource(stranger.actor, secret, 'use'), false);
  assert.equal(decode(await f.identity.open(sealed, 'resource:' + id)), 'private value');
  await f.principals.revoke(owner.actor, owner.actor.id, agent.actor.id);
  assert.equal(await f.authorization.resource(agent.actor, secret, 'use'), false);
});

test('公開鍵で暗号化したシークレットを宛先の秘密鍵で開く', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person(), stranger = await f.person('Stranger');
  const value = await seal(encode('correct secret'), [{ id: owner.actor.id, publicKey: owner.keys.publicKey }], 'item');
  assert.equal(decode(await open(value, owner.keys.privateKey, owner.actor.id, 'item')), 'correct secret');
  await assert.rejects(open(value, stranger.keys.privateKey, owner.actor.id, 'item'));
  await assert.rejects(open(value, owner.keys.privateKey, owner.actor.id, 'different item'));
  const prf = crypto.getRandomValues(new Uint8Array(32));
  assert.deepEqual(await unwrap(await wrap(owner.keys.privateKey, prf, owner.actor.id), prf, owner.actor.id), owner.keys.privateKey);
});

test('所有と所属の循環を拒否し、所有するプリンシパルの権限を継承する', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person();
  const child = await f.principals.create('Child', null, owner.actor.id);
  const grandchild = await f.principals.create('Grandchild', null, child.id);
  assert.equal(await f.authorization.principal(owner.actor, grandchild.id, 'credentials'), true);
  await assert.rejects(f.principals.relate(owner.actor, child.id, 'member', owner.actor.id), { code: 'relation_cycle' });
  await assert.rejects(f.principals.transfer(owner.actor, child.id, grandchild.id), { code: 'relation_cycle' });
});

test('メールの確認リンクでサインインし、同じリンクの再使用を拒否する', async t => {
  const f = await fixture(); t.after(f.close);
  await f.authentication.beginEmail('person@example.test', 'browser');
  const link = new URL(f.mailer.sent[0]!.link), values = new URLSearchParams(link.hash.slice(1));
  const result = await f.authentication.verifyEmail(values.get('challenge')!, values.get('token')!);
  assert.ok('token' in result);
  assert.ok(await f.authentication.authenticate(result.token));
  await assert.rejects(f.authentication.verifyEmail(values.get('challenge')!, values.get('token')!), { code: 'invalid_link' });
});

test('同時に編集された項目を上書きせず、最新の値を保持する', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person();
  const resource = await f.resources.insert(owner.actor.id, 'service', 'Service', {});
  await f.resources.update(resource, { name: 'Latest' });
  await assert.rejects(f.resources.update(resource, { name: 'Stale' }), { code: 'changed' });
  assert.equal((await f.resources.get(resource.id)).name, 'Latest');
});
