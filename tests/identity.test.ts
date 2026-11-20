import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { principal } from '../server/authorization.js';
import { AgreementNeeded } from '../server/relations.js';
import { seal, open, encode, decode, wrap, unwrap } from '../shared/encryption.js';
import { openItem, sealItem } from '../shared/custody.js';

test('メンバーを加えると加えた人が配下の変数を包み、持ち主を変えると新しい持ち主に包み直して移す', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), member = await f.person('Member'), next = await f.person('New owner');
  const project = await f.principals.create('Project', null, owner.actor.id);
  const child = await f.principals.create('Nested project', null, project.id);
  const row = await f.keep(owner.actor, child.id, 'Project variable', 'shared project value');
  await f.relations.draw(owner.actor, { subjectId: member.actor.id, relation: 'member', objectId: project.id });
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), [{ id: row.id }]);
  const before = await f.custody.read(owner.actor, row.id), bytes = await openItem(before.content, owner.keys.privateKey, owner.keys.publicKey);
  await f.custody.put(owner.actor, { id: row.id, name: 'Project variable', kind: 'variable', ownerId: child.id, version: before.version,
    content: await sealItem(bytes, await f.custody.recipients(await f.resources.get(row.id)), 2, before.content.metadata) });
  assert.equal(decode(await openItem((await f.custody.read(member.actor, row.id)).content, member.keys.privateKey, member.keys.publicKey)),
    'shared project value');
  // Passing the project on seals what it holds, below it too, for whoever acts as it then: the new owner and the member.
  const plan = await f.principals.keySharing.plan(owner.actor, project.id, next.actor.id);
  assert.deepEqual(plan.items.map(item => item.id), [row.id]);
  assert.deepEqual(plan.items[0]!.recipients.map(recipient => recipient.id).sort(), [member.actor.id, next.actor.id].sort());
  const sealing = async () => Object.fromEntries(await Promise.all(plan.items.map(async item => {
    const current = await f.custody.read(owner.actor, item.id);
    return [item.id, { version: current.version, content: await sealItem(await openItem(current.content, owner.keys.privateKey,
      owner.keys.publicKey), item.recipients, current.content.revision + 1, current.content.metadata) }];
  })));
  const transferred = await sealing();
  await f.resources.rename(owner.actor, await f.resources.get(row.id), 'Renamed variable');
  const agreed = { ...owner.actor, agreedBy: next.actor.id };
  await assert.rejects(f.relations.transfer(agreed, project.id, next.actor.id, transferred), { code: 'changed' });
  await f.relations.transfer(agreed, project.id, next.actor.id, await sealing());
  for (const person of [next, member])
    assert.equal(decode(await openItem((await f.custody.read(person.actor, row.id)).content, person.keys.privateKey, person.keys.publicKey)),
      'shared project value');
  await assert.rejects(f.custody.read(owner.actor, row.id), { code: 'forbidden' });
});

test('変数は新しい所有者が受け取りに同意したときに、その所有者向けに包んで移す', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Before'), next = await f.person('After');
  const row = await f.keep(owner.actor, owner.actor.id, 'Transferred variable', 'transfer-value');
  const content = await sealItem(encode('transfer-value'), await f.custody.ownerRecipients(next.actor.id), 2, { bytes: 14 });
  const write = { id: row.id, name: row.name, kind: 'variable' as const, ownerId: next.actor.id, version: row.version, content };
  await assert.rejects(f.custody.transfer(owner.actor, next.actor.id, write),
    (error) => error instanceof AgreementNeeded && error.to === next.actor.id);
  assert.equal((await f.resources.get(row.id)).owner_id, owner.actor.id);
  await f.custody.transfer({ ...owner.actor, agreedBy: next.actor.id }, next.actor.id, write);
  assert.equal((await f.resources.get(row.id)).owner_id, next.actor.id);
  assert.equal(decode(await openItem((await f.custody.read(next.actor, row.id)).content, next.keys.privateKey, next.keys.publicKey)),
    'transfer-value');
  await assert.rejects(f.custody.read(owner.actor, row.id), { code: 'forbidden' });
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

test('メンバーを外すとまだ包んである変数も渡さなくなり、所有者は次の値をメンバー抜きで包む', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person(), member = await f.person('Member');
  const project = await f.principals.create('Project', null, owner.actor.id);
  const membership = { subjectId: member.actor.id, relation: 'member', objectId: project.id };
  await f.relations.draw(owner.actor, membership);
  const row = await f.keep(owner.actor, project.id, 'Credential', 'private value');
  await f.relations.erase(owner.actor, membership);
  await assert.rejects(f.custody.read(member.actor, row.id), { code: 'forbidden' });
  const recipients = await f.custody.recipients(await f.resources.get(row.id));
  assert.deepEqual(recipients.map(recipient => recipient.id), [owner.actor.id]);
  await f.custody.put(owner.actor, { id: row.id, name: 'Credential', kind: 'variable', ownerId: project.id, version: row.version,
    content: await sealItem(encode('next value'), recipients, 2, { bytes: 10 }) });
  assert.equal(decode(await openItem((await f.custody.read(owner.actor, row.id)).content, owner.keys.privateKey, owner.keys.publicKey)),
    'next value');
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), []);
});

test('公開鍵で暗号化した値を宛先の秘密鍵で開く', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const owner = await f.person(),
    stranger = await f.person('Stranger');
  const value = await seal(
    encode('correct value'),
    [{ id: owner.actor.id, publicKey: owner.keys.publicKey }],
    'item',
  );
  assert.equal(decode(await open(value, owner.keys.privateKey, owner.actor.id, 'item')), 'correct value');
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
  assert.equal(await f.authorization.can(owner.actor, principal(grandchild.id), 'manage_credentials'), true);
  await assert.rejects(f.relations.draw(owner.actor, { subjectId: child.id, relation: 'member', objectId: owner.actor.id }), {
    code: 'relation_cycle',
  });
  await assert.rejects(f.relations.transfer(owner.actor, child.id, grandchild.id), {
    code: 'relation_cycle',
  });
});

test('登録のないメールアドレスは確認後に作成を求め、作成したアカウントでサインインする', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const link = async () => {
    await f.authentication.beginEmail('person@example.test', 'browser');
    const values = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
    return [values.get('challenge')!, values.get('token')!] as const;
  };
  const [challenge, secret] = await link();
  const verified = await f.authentication.verifyEmail(challenge, secret);
  assert.ok('registrationProof' in verified);
  if (!('registrationProof' in verified)) return;
  assert.equal(verified.email, 'person@example.test');
  await assert.rejects(f.authentication.verifyEmail(challenge, secret), { code: 'invalid_link' });
  const registered = await f.authentication.registerEmail(verified.registrationProof, 'Person');
  assert.equal((await f.authentication.authenticate(registered.token))?.id, registered.actor.id);
  assert.equal((await f.principals.get(registered.actor.id)).name, 'Person');
  await assert.rejects(f.authentication.registerEmail(verified.registrationProof), { code: 'invalid_proof' });
  await f.db.pool.query("UPDATE challenges SET created_at=now()-interval '2 minutes'");
  const signedIn = await f.authentication.verifyEmail(...(await link()));
  assert.ok('token' in signedIn);
  if (!('token' in signedIn)) return;
  assert.equal(signedIn.actor.id, registered.actor.id);
});

test('作成の確認中に同じアドレスが登録されたら、二つ目のアカウントを作らない', async (t) => {
  const f = await fixture();
  t.after(f.close);
  const proofs = [];
  for (const browser of ['first', 'second']) {
    await f.db.pool.query("UPDATE challenges SET created_at=now()-interval '2 minutes'");
    await f.authentication.beginEmail('twice@example.test', browser);
    const values = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
    const verified = await f.authentication.verifyEmail(values.get('challenge')!, values.get('token')!);
    assert.ok('registrationProof' in verified);
    if ('registrationProof' in verified) proofs.push(verified.registrationProof);
  }
  await f.authentication.registerEmail(proofs[0]!);
  await assert.rejects(f.authentication.registerEmail(proofs[1]!), { code: 'email_in_use' });
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
