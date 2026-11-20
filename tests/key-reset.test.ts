import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './support.js';
import { addPasskey, softwarePasskey } from './passkey-support.js';
import type { Actor } from '../server/authorization.js';
import { decode, encode, newIdentityKeys, publicPart, wrap } from '../shared/encryption.js';
import type { IdentityKeysValue } from '../shared/encryption.js';
import { openItem, sealItem, sealedFor } from '../shared/custody.js';

type Fixture = Awaited<ReturnType<typeof fixture>>;

// A person signed in with a passkey, as on the page that sets up a device.
async function signedIn(f: Fixture, name = 'Owner') {
  const person = await f.person(name), passkey = await addPasskey(f.db, person.actor.id, f.config.origin);
  const { actor } = await f.authentication.session(person.actor.id, passkey.id);
  return { ...person, actor, passkey };
}
// The new key, wrapped for the passkey registered with the reset.
async function completion(person: Awaited<ReturnType<typeof signedIn>>, keys: IdentityKeysValue) {
  return { publicKey: publicPart(keys.encryption),
    wrappedKey: await wrap(keys, crypto.getRandomValues(new Uint8Array(32)), person.actor.id) };
}
// Seven days have passed since the request.
async function wait(f: Fixture, principalId: string) {
  await f.db.pool.query("UPDATE challenges SET data=data||jsonb_build_object('readyAt',$2::text) WHERE kind='key-reset' AND principal_id=$1",
    [principalId, new Date(Date.now() - 1000).toISOString()]);
}
// Registers the passkey that will hold the new keys with the ready reset, as the browser does.
async function register(f: Fixture, actor: Actor, principalId: string) {
  const passkey = softwarePasskey(f.config.origin);
  const { options } = await f.keyResets.passkeyOptions(actor, principalId, 'New passkey');
  await f.keyResets.registerPasskey(actor, principalId, passkey.register(options));
  return passkey;
}
// Completes the reset with new keys held by a new passkey, as the browser does.
async function reset(f: Fixture, person: Awaited<ReturnType<typeof signedIn>>) {
  const keys = await newIdentityKeys(), input = await completion(person, keys);
  await register(f, person.actor, person.actor.id);
  await f.keyResets.complete(person.actor, person.actor.id, input);
  return { publicKey: input.publicKey, privateKey: keys.encryption };
}
const passkeys = async (f: Fixture, principalId: string) => (await f.db.all<{ identifier: string; wrapped: boolean }>(
  "SELECT identifier,private_wrap IS NOT NULL AS wrapped FROM credentials WHERE principal_id=$1 AND kind='passkey' ORDER BY created_at",
  [principalId]));

test('秘密鍵をなくしたプリンシパルは、申請から7日たつと申請したサインインで新しいパスキーを登録し、確定と同時に新しい鍵とともに使えるようにする', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f);
  await f.db.pool.query("UPDATE credentials SET private_wrap='earlier' WHERE principal_id=$1", [person.actor.id]);
  const requested = await f.keyResets.request(person.actor, person.actor.id);
  assert.ok(Date.parse(requested.readyAt) - Date.parse(requested.requestedAt) >= 7 * 86_400_000 - 1000);
  assert.deepEqual(await f.keyResets.request(person.actor, person.actor.id), requested);
  const keys = await newIdentityKeys(), input = await completion(person, keys);
  await assert.rejects(register(f, person.actor, person.actor.id), { code: 'key_reset_waiting' });
  await wait(f, person.actor.id);
  await assert.rejects(f.keyResets.complete(person.actor, person.actor.id, input), { code: 'passkey_required' });
  const passkey = await register(f, person.actor, person.actor.id);
  assert.equal((await passkeys(f, person.actor.id)).length, 1);
  await f.keyResets.complete(person.actor, person.actor.id, input);
  assert.deepEqual((await f.principals.get(person.actor.id)).public_key, publicPart(keys.encryption));
  assert.deepEqual((await passkeys(f, person.actor.id)).map(row => row.wrapped), [false, true]);
  assert.equal((await passkeys(f, person.actor.id))[1]!.identifier, passkey.identifier);
  assert.equal((await f.db.one<{ count: string }>('SELECT count(*) FROM credentials WHERE principal_id=$1 AND private_wrap IS NOT NULL',
    [person.actor.id]))!.count, '1');
  assert.equal(await f.keyResets.get(person.actor.id), null);
});

test('準備できた作り直しでも、申請していない別のサインインは新しいパスキーを登録できない', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f);
  await f.keyResets.request(person.actor, person.actor.id);
  await wait(f, person.actor.id);
  const other = (await f.authentication.authenticate((await f.authentication.issueKey(person.actor.id, 'Other key')).token))!;
  await assert.rejects(register(f, other, person.actor.id), { code: 'forbidden' });
  await register(f, person.actor, person.actor.id);
  await assert.rejects(f.keyResets.complete(other, person.actor.id, await completion(person, await newIdentityKeys())), { code: 'forbidden' });
});

test('作り直しの申請を取り消すと、登録しておいた新しいパスキーも使えるようにならず、7日たっても作り直さない', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f), other = await f.person('Other');
  await f.keyResets.request(person.actor, person.actor.id);
  await wait(f, person.actor.id);
  await register(f, person.actor, person.actor.id);
  await assert.rejects(f.keyResets.cancel(other.actor, person.actor.id), { code: 'forbidden' });
  const { actor: device } = await f.authentication.session(person.actor.id);
  await f.keyResets.cancel(device, person.actor.id);
  assert.equal(await f.keyResets.get(person.actor.id), null);
  await assert.rejects(f.keyResets.complete(person.actor, person.actor.id, await completion(person, await newIdentityKeys())),
    { code: 'key_reset_waiting' });
  assert.equal((await passkeys(f, person.actor.id)).length, 1);
  assert.deepEqual((await f.principals.get(person.actor.id)).public_key, person.keys.publicKey);
});

test('作り直す前の鍵向けに包んだ変数は開けず、新しい鍵向けに値を入れ直す', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f), other = await f.person('Other');
  const row = await f.keep(person.actor, person.actor.id, 'Token', 'lost value');
  await f.keyResets.request(person.actor, person.actor.id);
  await wait(f, person.actor.id);
  const next = await reset(f, person);
  const sealed = await f.custody.read(person.actor, row.id);
  assert.equal(await sealedFor(sealed.content, next.publicKey), false);
  assert.deepEqual(await f.custody.ownerRecipients(person.actor.id), [{ id: person.actor.id, name: 'Owner', publicKey: next.publicKey }]);
  await assert.rejects(f.custody.put(other.actor, { id: row.id, name: 'Token', kind: 'variable', ownerId: person.actor.id,
    version: row.version, content: await sealItem(encode('taken'), [other.keys], 2, { bytes: 5 }) }), { code: 'forbidden' });
  await f.custody.put(person.actor, { id: row.id, name: 'Token', kind: 'variable', ownerId: person.actor.id, version: row.version,
    content: await sealItem(encode('entered again'), [next], 2, { bytes: 13 }) });
  const current = (await f.custody.read(person.actor, row.id)).content;
  assert.equal(decode(await openItem(current, next.privateKey, next.publicKey)), 'entered again');
});

test('共有した相手が鍵を作り直すと、所有者が包み直す項目に挙げる', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), friend = await signedIn(f, 'Friend');
  const row = await f.keep(owner.actor, owner.actor.id, 'Shared', 'shared value');
  await f.relations.draw(owner.actor, { subjectId: friend.actor.id, relation: 'revealer', objectId: row.id });
  const current = await f.custody.read(owner.actor, row.id);
  await f.custody.put(owner.actor, { id: row.id, name: 'Shared', kind: 'variable', ownerId: owner.actor.id, version: current.version,
    content: await sealItem(encode('shared value'), [owner.keys, friend.keys], 2, { bytes: 12 }) });
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), []);
  await f.keyResets.request(friend.actor, friend.actor.id);
  await wait(f, friend.actor.id);
  await reset(f, friend);
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), [{ id: row.id }]);
});
