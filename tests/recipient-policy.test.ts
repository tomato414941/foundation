import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient } from '../shared/client.js';
import type { RecipientAccess } from '../shared/client.js';
import { bindKeys, fingerprint, newIdentityKeys, signBinding } from '../shared/authority.js';
import { ContentTypes, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { JournalTrust } from '../runtime/trust.js';

test('代理は未検証の相手を知らせて保存し、自分で鍵を検証してから既存の項目を暗号化し直す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const peer = await f.person('Peer delegate');
  await f.relations.draw(f.owner.actor, { subjectId: peer.actor.id, relation: 'delegate', objectId: f.owner.actor.id });
  await f.client.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const notices: RecipientAccess[] = [];
  const writer = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys,
    new JournalTrust(new MemoryJournal()), notice => notices.push(notice));
  await writer.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  const saved = await writer.save('Verified peers', encode('shared value'), await writer.policy(f.owner.actor.id, ContentTypes.value));
  assert.equal(decode(await writer.reveal(saved.id)), 'shared value');
  assert.deepEqual(notices, [{ id: saved.id, name: 'Verified peers', excluded: [
    { id: peer.actor.id, name: 'Peer delegate', code: 'identity_untrusted' }] }]);
  await assert.rejects(f.custody.read(peer.actor, saved.id), { code: 'forbidden' });
  await writer.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const updated = await writer.reprotectPending();
  assert.ok(updated.done.includes(saved.id));
  assert.deepEqual(updated.failed, []);
  assert.equal(decode(await reveal((await f.custody.read(peer.actor, saved.id)).content, peer.binding, peer.keys.encryption)), 'shared value');
  assert.deepEqual(notices.findLast(notice => notice.id === saved.id)?.excluded, []);
});

test('代理が変数を更新すると新しく許可された信頼済みの代理にも暗号化し、既存の利用許可を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const peer = await f.person('Later delegate');
  const writer = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys,
    new JournalTrust(new MemoryJournal()));
  await writer.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  const saved = await writer.save('Changing peers', encode('first value'), await writer.policy(f.owner.actor.id, ContentTypes.value));
  const previous = await writer.read(saved.id);
  await f.relations.draw(f.owner.actor, { subjectId: peer.actor.id, relation: 'delegate', objectId: f.owner.actor.id });
  await writer.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const policy = await writer.refreshRecipients(previous.content.policy);
  assert.deepEqual(policy.grants, previous.content.policy.grants);
  await writer.save('Changing peers', encode('next value'), policy, { previous });
  assert.equal(decode(await reveal((await f.custody.read(peer.actor, saved.id)).content, peer.binding, peer.keys.encryption)), 'next value');
});

test('更新する代理が未検証の鍵は以前の暗号化先からも外し、検証後に同じ項目を開けるようにする', async t => {
  const f = await flowFixture(); t.after(f.close);
  const peer = await f.person('Existing delegate');
  await f.relations.draw(f.owner.actor, { subjectId: peer.actor.id, relation: 'delegate', objectId: f.owner.actor.id });
  await f.client.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const saved = await f.client.save('Existing peers', encode('before update'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  const notices: RecipientAccess[] = [];
  const writer = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys,
    new JournalTrust(new MemoryJournal()), notice => notices.push(notice));
  await writer.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  const previous = await writer.read(saved.id);
  await writer.save('Existing peers', encode('after update'), await writer.refreshRecipients(previous.content.policy), { previous });
  assert.equal(decode(await writer.reveal(saved.id)), 'after update');
  assert.equal(notices[0]?.excluded[0]?.id, peer.actor.id);
  await assert.rejects(f.custody.read(peer.actor, saved.id), { code: 'forbidden' });
  await writer.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  await writer.reprotectPending();
  assert.equal(decode(await reveal((await f.custody.read(peer.actor, saved.id)).content, peer.binding, peer.keys.encryption)), 'after update');
});

test('代理が自分で信頼した相手でも持ち主の代理ではなければ共有の許可を求める', async t => {
  const f = await flowFixture(); t.after(f.close);
  const writer = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys,
    new JournalTrust(new MemoryJournal()));
  await writer.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  await writer.trustIdentity(f.stranger.actor.id, await fingerprint(f.stranger.binding));
  const policy = await writer.policy(f.owner.actor.id, ContentTypes.value);
  const saved = await writer.save('Owned value', encode('first value'), policy);
  const previous = await writer.read(saved.id);
  const shared = { ...previous.content.policy, revision: previous.content.policy.revision + 1,
    readers: [...previous.content.policy.readers, f.stranger.binding] };
  await assert.rejects(writer.save('Owned value', encode('unauthorized change'), shared, { previous }), { code: 'forbidden' });
  await assert.rejects(writer.save('Outside share', encode('outside value'), { ...policy, id: crypto.randomUUID(),
    readers: [...policy.readers, f.stranger.binding] }), { code: 'forbidden' });
  assert.equal(decode(await writer.reveal(saved.id)), 'first value');
});

test('代理が暗号化先を選び直すときも持ち主と明示的な共有先を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  await f.client.trustIdentity(f.stranger.actor.id, await fingerprint(f.stranger.binding));
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value);
  const saved = await f.client.save('Explicit readers', encode('shared explicitly'), {
    ...policy, readers: [...policy.readers, f.stranger.binding] });
  const writer = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys,
    new JournalTrust(new MemoryJournal()));
  await writer.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  const previous = await writer.read(saved.id);
  const next = { ...previous.content.policy, revision: previous.content.policy.revision + 1 };
  await assert.rejects(writer.save('Explicit readers', encode('removed explicit reader'), {
    ...next, readers: next.readers.filter(reader => reader.principalId !== f.stranger.actor.id) }, { previous }), { code: 'forbidden' });
  await assert.rejects(writer.save('Explicit readers', encode('removed owner'), {
    ...next, readers: next.readers.filter(reader => reader.principalId !== f.owner.actor.id),
    authorities: next.authorities.filter(authority => authority.principalId !== f.owner.actor.id) }, { previous }), { code: 'missing_recipient' });
  assert.equal(decode(await writer.reveal(saved.id)), 'shared explicitly');
});

test('サーバーが信頼済みの代理の別の鍵を返すとその代理を外して保存し鍵の変更を知らせる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const peer = await f.person('Changed delegate');
  await f.relations.draw(f.owner.actor, { subjectId: peer.actor.id, relation: 'delegate', objectId: f.owner.actor.id });
  await f.client.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const keys = await newIdentityKeys(), substituted = await signBinding(bindKeys(peer.actor.id, keys), keys);
  const api = { async json<T>(...args: Parameters<typeof f.client.api.json<T>>): Promise<T> {
    const result = await f.client.api.json<T>(...args);
    if (args[0].endsWith('/bound-delegates')) return { items: [{ name: 'Changed delegate', ...substituted }], next: null } as T;
    return result;
  } };
  const notices: RecipientAccess[] = [];
  const client = new CustodyClient(api, f.config.origin, f.owner.binding, f.owner.keys, f.client.trust, notice => notices.push(notice));
  const saved = await client.save('Changed keys', encode('saved safely'), await client.policy(f.owner.actor.id, ContentTypes.value));
  assert.equal(decode(await client.reveal(saved.id)), 'saved safely');
  assert.deepEqual(notices[0]?.excluded, [{ id: peer.actor.id, name: 'Changed delegate', code: 'identity_changed' }]);
  await assert.rejects(f.custody.read(peer.actor, saved.id), { code: 'forbidden' });
});
