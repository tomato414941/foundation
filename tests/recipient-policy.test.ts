import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient, RecipientVerificationRequired } from '../shared/client.js';
import { bindKeys, fingerprint, newIdentityKeys, signBinding } from '../shared/authority.js';
import { ContentTypes, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { JournalTrust } from '../runtime/trust.js';

test('代理は持ち主が検証した鍵を引き継がず、自分で全員の鍵を検証してから暗号化する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const peer = await f.person('Peer delegate');
  await f.relations.draw(f.owner.actor, { subjectId: peer.actor.id, relation: 'delegate', objectId: f.owner.actor.id });
  await f.client.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const writer = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin, f.executor.binding, f.executor.keys,
    new JournalTrust(new MemoryJournal()));
  await writer.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  await assert.rejects(writer.policy(f.owner.actor.id, ContentTypes.value), error => {
    assert.ok(error instanceof RecipientVerificationRequired);
    assert.deepEqual(error.recipients, [{ id: peer.actor.id, name: 'Peer delegate', code: 'identity_untrusted' }]);
    return true;
  });
  await writer.trustIdentity(peer.actor.id, await fingerprint(peer.binding));
  const saved = await writer.save('Verified peers', encode('shared value'), await writer.policy(f.owner.actor.id, ContentTypes.value));
  assert.equal(decode(await reveal((await f.custody.read(peer.actor, saved.id)).content, peer.binding, peer.keys.encryption)), 'shared value');
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
  const current = await writer.read(saved.id);
  await assert.rejects(writer.save('Changing peers', encode('excluded peer'), { ...current.content.policy,
    revision: current.content.policy.revision + 1, readers: current.content.policy.readers.filter(reader => reader.principalId !== peer.actor.id),
    authorities: current.content.policy.authorities.filter(authority => authority.principalId !== peer.actor.id) }, { previous: current }),
  { code: 'forbidden' });
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

test('サーバーが信頼済みの代理の別の鍵を返すと変更を知らせて暗号化を止める', async t => {
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
  const client = new CustodyClient(api, f.config.origin, f.owner.binding, f.owner.keys, f.client.trust);
  await assert.rejects(client.policy(f.owner.actor.id, ContentTypes.value), error => {
    assert.ok(error instanceof RecipientVerificationRequired);
    assert.deepEqual(error.recipients, [{ id: peer.actor.id, name: 'Changed delegate', code: 'identity_changed' }]);
    return true;
  });
});
