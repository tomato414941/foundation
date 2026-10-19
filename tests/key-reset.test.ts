import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { bindKeys, newIdentityKeys, publicPart, signBinding } from '../shared/authority.js';
import { decode, encode, wrap } from '../shared/encryption.js';
import { AccessPolicy, ContentTypes, protect, reveal } from '../shared/custody.js';

type Fixture = Awaited<ReturnType<typeof fixture>>;

// A person signed in with a passkey, as on the page that sets up a device.
async function signedIn(f: Fixture, name = 'Owner') {
  const person = await f.person(name), passkey = randomUUID();
  await f.db.pool.query("INSERT INTO credentials(id,principal_id,kind,name,identifier) VALUES($1,$2,'passkey','New passkey',$3)",
    [passkey, person.actor.id, randomUUID()]);
  const { actor } = await f.authentication.session(person.actor.id, passkey);
  return { ...person, actor, passkey };
}
// Seven days have passed since the request.
async function wait(f: Fixture, principalId: string) {
  await f.db.pool.query("UPDATE challenges SET data=jsonb_build_object('readyAt',$2::text) WHERE kind='key-reset' AND principal_id=$1",
    [principalId, new Date(Date.now() - 1000).toISOString()]);
}
// Completes the reset with new keys and publishes them, as the browser does.
async function reset(f: Fixture, person: Awaited<ReturnType<typeof signedIn>>) {
  const keys = await newIdentityKeys(), prf = crypto.getRandomValues(new Uint8Array(32));
  await f.keyResets.complete(person.actor, person.actor.id,
    { publicKey: publicPart(keys.encryption), wrappedKey: await wrap(keys, prf, person.actor.id) });
  const binding = bindKeys(person.actor.id, keys);
  await f.bindings.publish(person.actor, await signBinding(binding, keys));
  return { binding, keys };
}

test('秘密鍵をなくしたプリンシパルは、申請から7日たつと公開鍵と秘密鍵を作り直す', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f);
  await f.db.pool.query("UPDATE credentials SET private_wrap='earlier' WHERE principal_id=$1", [person.actor.id]);
  const requested = await f.keyResets.request(person.actor, person.actor.id);
  assert.ok(Date.parse(requested.readyAt) - Date.parse(requested.requestedAt) >= 7 * 86_400_000 - 1000);
  assert.deepEqual(await f.keyResets.request(person.actor, person.actor.id), requested);
  const keys = await newIdentityKeys(), wrappedKey = await wrap(keys, crypto.getRandomValues(new Uint8Array(32)), person.actor.id);
  await assert.rejects(f.keyResets.complete(person.actor, person.actor.id, { publicKey: publicPart(keys.encryption), wrappedKey }),
    { code: 'key_reset_waiting' });
  await wait(f, person.actor.id);
  const { actor: email } = await f.authentication.session(person.actor.id);
  await assert.rejects(f.keyResets.complete(email, person.actor.id, { publicKey: publicPart(keys.encryption), wrappedKey }),
    { code: 'forbidden' });
  await f.keyResets.complete(person.actor, person.actor.id, { publicKey: publicPart(keys.encryption), wrappedKey });
  assert.deepEqual((await f.principals.get(person.actor.id)).public_key, publicPart(keys.encryption));
  await assert.rejects(f.bindings.current(person.actor.id), { code: 'key_binding_required' });
  assert.deepEqual((await f.db.all<{ id: string }>('SELECT id FROM credentials WHERE principal_id=$1 AND private_wrap IS NOT NULL',
    [person.actor.id])).map(row => row.id), [person.passkey]);
  assert.equal(await f.keyResets.get(person.actor.id), null);
  await f.bindings.publish(person.actor, await signBinding(bindKeys(person.actor.id, keys), keys));
  assert.equal((await f.bindings.current(person.actor.id)).binding.generation, 1);
});

test('作り直しの申請を取り消すと、7日たっても作り直さない', async t => {
  const f = await fixture(); t.after(f.close);
  const person = await signedIn(f), other = await f.person('Other');
  await f.keyResets.request(person.actor, person.actor.id);
  await assert.rejects(f.keyResets.cancel(other.actor, person.actor.id), { code: 'forbidden' });
  const { actor: device } = await f.authentication.session(person.actor.id);
  await f.keyResets.cancel(device, person.actor.id);
  assert.equal(await f.keyResets.get(person.actor.id), null);
  await wait(f, person.actor.id);
  const keys = await newIdentityKeys();
  await assert.rejects(f.keyResets.complete(person.actor, person.actor.id, { publicKey: publicPart(keys.encryption),
    wrappedKey: await wrap(keys, crypto.getRandomValues(new Uint8Array(32)), person.actor.id) }), { code: 'key_reset_waiting' });
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
