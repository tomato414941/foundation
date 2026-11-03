import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { addPasskey, softwarePasskey } from './passkey-support.js';
import type { Actor } from '../server/authorization.js';
import { bindKeys, newIdentityKeys, publicPart, signBinding } from '../shared/authority.js';
import type { IdentityKeys } from '../shared/authority.js';
import { decode, encode, wrap } from '../shared/encryption.js';
import { AccessPolicy, ContentTypes, protect, reveal } from '../shared/custody.js';

type Fixture = Awaited<ReturnType<typeof fixture>>;

// A person signed in with a passkey, as on the page that sets up a device.
async function signedIn(f: Fixture, name = 'Owner') {
  const person = await f.person(name), passkey = await addPasskey(f.db, person.actor.id, f.config.origin);
  const { actor } = await f.authentication.session(person.actor.id, passkey.id);
  return { ...person, actor, passkey };
}
// The new keys, wrapped for the passkey registered with the reset.
async function completion(person: Awaited<ReturnType<typeof signedIn>>, keys: IdentityKeys) {
  return { binding: await signBinding(bindKeys(person.actor.id, keys), keys),
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
  return { binding: input.binding.binding, keys };
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
  assert.deepEqual((await f.bindings.current(person.actor.id)).binding, input.binding.binding);
  assert.deepEqual((await passkeys(f, person.actor.id)).map(row => row.wrapped), [false, true]);
  assert.equal((await passkeys(f, person.actor.id))[1]!.identifier, passkey.identifier);
  assert.equal((await f.db.one<{ count: string }>('SELECT count(*) FROM credentials WHERE principal_id=$1 AND private_wrap IS NOT NULL',
    [person.actor.id]))!.count, '1');
  assert.equal(await f.keyResets.get(person.actor.id), null);
});

test('準備できた作り直しでも、申請していない別のサインインは新しいパスキーを登録できず、通常のパスキー追加は確認を求める', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f);
  await f.keyResets.request(person.actor, person.actor.id);
  await wait(f, person.actor.id);
  const other = (await f.authentication.authenticate((await f.authentication.issueKey(person.actor.id, 'Other key')).token))!;
  await assert.rejects(register(f, other, person.actor.id), { code: 'forbidden' });
  await register(f, person.actor, person.actor.id);
  await assert.rejects(f.keyResets.complete(other, person.actor.id, await completion(person, await newIdentityKeys())), { code: 'forbidden' });
  const passkey = softwarePasskey(f.config.origin);
  const started = await f.authentication.passkeyOptions('browser', { intent: 'register', name: 'Extra', principalId: person.actor.id }, other);
  await assert.rejects(f.authentication.verifyPasskey('browser', { challengeId: started.challengeId,
    credential: passkey.register(started.options) }, other), { code: 'confirmation_required' });
  assert.equal((await passkeys(f, person.actor.id)).length, 1);
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

test('作り直す前の秘密鍵で暗号化した変数に、新しい公開鍵で値を入れ直す', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f), other = await f.person('Other'), id = randomUUID();
  const before = AccessPolicy.parse({ format: 2, id, origin: f.config.origin, ownerId: person.actor.id,
    contentType: ContentTypes.value, revision: 1, authorities: [person.binding], readers: [person.binding], grants: [] });
  const row = await f.custody.put(person.actor, { name: 'Token', content: await protect(encode('lost value'), before, 1, person.binding, person.keys) });
  await f.keyResets.request(person.actor, person.actor.id);
  await wait(f, person.actor.id);
  const next = await reset(f, person);
  const sealed = await f.custody.read(person.actor, id);
  assert.deepEqual(sealed.content.policy.readers.map(reader => reader.id), [person.binding.id]);
  const policy = { ...before, revision: 2, authorities: [next.binding], readers: [next.binding] };
  const content = await protect(encode('entered again'), policy, 2, next.binding, next.keys);
  const stranger = AccessPolicy.parse({ ...policy, authorities: [other.binding], readers: [other.binding] });
  await assert.rejects(f.custody.put(other.actor, { name: 'Token', version: row.version,
    content: await protect(encode('taken'), stranger, 2, other.binding, other.keys) }), { code: 'forbidden' });
  await f.custody.put(person.actor, { name: 'Token', version: row.version, content });
  const current = (await f.custody.read(person.actor, id)).content;
  assert.equal(decode(await reveal(current, next.binding, next.keys.encryption)), 'entered again');
});

test('共有した相手が公開鍵を作り直すと、所有者が暗号化し直す項目に挙げる', async t => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), friend = await signedIn(f, 'Friend'), id = randomUUID();
  await f.custody.put(owner.actor, { name: 'Shared', content: await protect(encode('shared value'), AccessPolicy.parse({
    format: 2, id, origin: f.config.origin, ownerId: owner.actor.id, contentType: ContentTypes.value, revision: 1,
    authorities: [owner.binding], readers: [owner.binding, friend.binding], grants: [] }), 1, owner.binding, owner.keys) });
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), []);
  await f.keyResets.request(friend.actor, friend.actor.id);
  await wait(f, friend.actor.id);
  await reset(f, friend);
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), [{ id, reason: 'recipients', remove: [] }]);
});
