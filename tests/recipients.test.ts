import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { fixture } from './support.js';
import { openItem, sealItem, sealedFor } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import type { Actor } from '../server/authorization.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import type { JWK } from 'jose';

type Fixture = Awaited<ReturnType<typeof fixture>>;
type Keys = { publicKey: PublicEncryptionKey; privateKey: JWK };
// What a device does for an item someone may open that is not sealed for them yet: it opens the item and seals it again
// for everyone Foundation lists.
async function reseal(f: Fixture, actor: Actor, keys: Keys, id: string) {
  const current = await f.custody.read(actor, id), row = await f.resources.get(id);
  const bytes = await openItem(current.content, keys.privateKey, keys.publicKey);
  return f.custody.put(actor, { id, name: row.name, kind: current.kind, ownerId: row.owner_id, version: current.version,
    content: await sealItem(bytes, await f.custody.recipients(row), current.content.revision + 1, current.content.metadata) });
}
async function opened(f: Fixture, actor: Actor, keys: Keys, id: string) {
  return decode(await openItem((await f.custody.read(actor, id)).content, keys.privateKey, keys.publicKey));
}

test('本番が示す開ける人に包んだ内容だけを保存し、示した人と違う相手に包んだ内容は断る', async (t) => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), ai = await f.person('AI'), stranger = await f.person('Stranger');
  await f.relations.draw(owner.actor, { subjectId: ai.actor.id, relation: 'delegate', objectId: owner.actor.id });
  assert.deepEqual((await f.custody.ownerRecipients(owner.actor.id)).map(recipient => recipient.id).sort(),
    [owner.actor.id, ai.actor.id].sort());
  const id = randomUUID();
  const write = async (people: Keys[]) => ({ id, name: 'Token', kind: 'variable' as const, ownerId: owner.actor.id,
    content: await sealItem(encode('value'), people, 1, { bytes: 5 }) });
  await assert.rejects(f.custody.put(owner.actor, await write([owner.keys])), { code: 'recipients_changed' });
  await assert.rejects(f.custody.put(owner.actor, await write([owner.keys, ai.keys, stranger.keys])), { code: 'recipients_changed' });
  const twice = await write([owner.keys, ai.keys]);
  const [first, second] = twice.content.sealed.recipients;
  twice.content.sealed.recipients = [first!, { ...second!, header: { ...second!.header, kid: first!.header.kid } }];
  await assert.rejects(f.custody.put(owner.actor, twice), { code: 'recipients_changed' });
  await f.custody.put(owner.actor, await write([owner.keys, ai.keys]));
  assert.equal(await opened(f, ai.actor, ai.keys, id), 'value');
  await assert.rejects(f.custody.read(stranger.actor, id), { code: 'forbidden' });
});

test('委任先を加えると、まだ包んでいない項目を挙げ、加えた人の端末が包むと委任先が開ける', async (t) => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), ai = await f.person('AI');
  const saved = await f.keep(owner.actor, owner.actor.id, 'Token', 'owner value');
  await f.relations.draw(owner.actor, { subjectId: ai.actor.id, relation: 'delegate', objectId: owner.actor.id });
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), [{ id: saved.id }]);
  assert.equal(await sealedFor((await f.custody.read(ai.actor, saved.id)).content, ai.keys.publicKey), false);
  await reseal(f, owner.actor, owner.keys, saved.id);
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), []);
  assert.equal(await opened(f, ai.actor, ai.keys, saved.id), 'owner value');
});

test('項目一つを開ける線を引くと、その相手に包むまで挙げ、包むと開け、線を外すと渡さない', async (t) => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), friend = await f.person('Friend');
  const saved = await f.keep(owner.actor, owner.actor.id, 'Token', 'shared value');
  const line = { subjectId: friend.actor.id, relation: 'revealer', objectId: saved.id };
  await f.relations.draw(owner.actor, line);
  assert.deepEqual(await f.custody.pending(owner.actor, owner.actor.id), [{ id: saved.id }]);
  await reseal(f, owner.actor, owner.keys, saved.id);
  assert.equal(await opened(f, friend.actor, friend.keys, saved.id), 'shared value');
  await f.relations.erase(owner.actor, line);
  await assert.rejects(f.custody.read(friend.actor, saved.id), { code: 'forbidden' });
  assert.equal(await opened(f, owner.actor, owner.keys, saved.id), 'shared value');
});

test('編集を許された相手は内容を開いて新しい値を保存できるが、ほかの人への共有はできない', async (t) => {
  const f = await fixture(); t.after(f.close);
  const owner = await f.person('Owner'), editor = await f.person('Editor'), other = await f.person('Other');
  const saved = await f.keep(owner.actor, owner.actor.id, 'Token', 'first');
  await f.relations.draw(owner.actor, { subjectId: editor.actor.id, relation: 'editor', objectId: saved.id });
  await reseal(f, owner.actor, owner.keys, saved.id);
  assert.equal(await opened(f, editor.actor, editor.keys, saved.id), 'first');
  const current = await f.custody.read(editor.actor, saved.id), row = await f.resources.get(saved.id);
  await f.custody.put(editor.actor, { id: saved.id, name: 'Token', kind: 'variable', ownerId: owner.actor.id, version: current.version,
    content: await sealItem(encode('second'), await f.custody.recipients(row), current.content.revision + 1, { bytes: 6 }) });
  assert.equal(await opened(f, owner.actor, owner.keys, saved.id), 'second');
  await assert.rejects(f.relations.draw(editor.actor, { subjectId: other.actor.id, relation: 'revealer', objectId: saved.id }),
    { code: 'forbidden' });
});
