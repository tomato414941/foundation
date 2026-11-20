import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { openItem, sealItem } from '../shared/custody.js';
import type { SealedItemValue } from '../shared/custody.js';
import type { JsonValue } from '../shared/contracts.js';
import { decode, encode } from '../shared/encryption.js';

async function setup() {
  const f = await delegatedFixture();
  const metadata = { state: 'ready', methodId: 'provider:oauth', methodKind: 'oauth', generation: crypto.randomUUID(),
    appId: null, accountId: 'account-1', accountVerified: true,
    scopes: ['read'], scopesStatus: 'reported', outputs: ['ACCESS_TOKEN'] };
  const resource = await f.keep(f.owner.actor, f.owner.actor.id, 'Connection', 'old-refresh-token', 'connection', metadata);
  const content = (await f.custody.read(f.owner.actor, resource.id)).content;
  // A device renewing the connection seals the new tokens for everyone who may open it now.
  const renewed = async (source: SealedItemValue, value: string, changes: Record<string, JsonValue> = {}) =>
    sealItem(encode(value), await f.custody.recipients(await f.resources.get(resource.id)), source.revision + 1,
      { ...source.metadata, ...changes });
  return { ...f, connection: { content, resource }, renewed, operations: new ConnectionOperations(f.custody) };
}

test('接続の更新を一つの読み手が取得し、更新した暗号文を一度だけ確定する', async () => {
  const f = await setup();
  try {
    const id = crypto.randomUUID(), source = f.connection.content, resourceId = f.connection.resource.id;
    const results = await Promise.allSettled([
      f.operations.prepare(f.delegate.actor, id, resourceId, 1),
      f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 1),
    ]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const operation = (results.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<Awaited<ReturnType<typeof f.operations.prepare>>>).value;
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    const content = await f.renewed(source, 'rotated-refresh-token');
    assert.deepEqual(await f.operations.commit(f.delegate.actor, operation.id, operation.fence, content), content);
    assert.deepEqual(await f.operations.commit(f.delegate.actor, operation.id, operation.fence, content), content);
    const current = await f.custody.read(f.owner.actor, resourceId);
    assert.equal(current.content.revision, 2);
    assert.equal(decode(await openItem(current.content, f.owner.keys.privateKey, f.owner.keys.publicKey)), 'rotated-refresh-token');
  } finally { await f.close(); }
});

test('更新した暗号文が開けるはずの相手と食い違うと確定せず、今の相手に包み直すと確定する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content, resourceId = f.connection.resource.id;
    const operation = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 1);
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    const stale = await f.renewed(source, 'rotated-refresh-token');
    await f.relations.draw(f.owner.actor, { subjectId: f.stranger.actor.id, relation: 'revealer', objectId: resourceId });
    await assert.rejects(f.operations.commit(f.delegate.actor, operation.id, operation.fence, stale), { code: 'recipients_changed' });
    await f.operations.commit(f.delegate.actor, operation.id, operation.fence, await f.renewed(source, 'rotated-refresh-token'));
    const shared = await f.custody.read(f.stranger.actor, resourceId);
    assert.equal(decode(await openItem(shared.content, f.stranger.keys.privateKey, f.stranger.keys.publicKey)), 'rotated-refresh-token');
  } finally { await f.close(); }
});

test('更新応答が不明な接続を停止し、保存済みの更新結果で復旧する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content, resourceId = f.connection.resource.id;
    const operation = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 1);
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    await f.operations.uncertain(f.delegate.actor, operation.id, operation.fence);
    await assert.rejects(f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 1), { code: 'connection_uncertain' });
    await assert.rejects(f.operations.abort(f.delegate.actor, operation.id, operation.fence), { code: 'connection_uncertain' });
    await f.operations.commit(f.delegate.actor, operation.id, operation.fence, await f.renewed(source, 'durably-recorded-token'));
    assert.equal((await f.resources.get(resourceId)).data.state, 'ready');
    assert.equal(await f.operations.state(f.delegate.actor, resourceId), null);
  } finally { await f.close(); }
});

test('接続の更新中は値の保存と削除を待たせ、更新で変わった権限もそのまま確定する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content, resourceId = f.connection.resource.id;
    const operation = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 1);
    await assert.rejects(f.custody.put(f.owner.actor, { id: resourceId, name: 'Connection', kind: 'connection', ownerId: f.owner.actor.id,
      version: f.connection.resource.version, content: await f.renewed(source, 'replacement') }), { code: 'connection_busy' });
    await assert.rejects(f.resources.delete(f.owner.actor, f.connection.resource), { code: 'connection_busy' });
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    await f.operations.commit(f.delegate.actor, operation.id, operation.fence,
      await f.renewed(source, 'broader-token', { scopes: ['read', 'write'] }));
    assert.deepEqual((await f.resources.get(resourceId)).data.scopes, ['read', 'write']);
  } finally { await f.close(); }
});

test('結果が不明な古い更新を新しく承認した接続に置き換え、新世代の更新を開始する', async () => {
  const f = await setup();
  try {
    const previous = f.connection.content, resourceId = f.connection.resource.id;
    const pending = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 1);
    await f.operations.dispatch(f.delegate.actor, pending.id, pending.fence);
    await f.operations.uncertain(f.delegate.actor, pending.id, pending.fence);
    await f.custody.put(f.owner.actor, { id: resourceId, name: 'Connection', kind: 'connection', ownerId: f.owner.actor.id,
      version: (await f.resources.get(resourceId)).version,
      content: await f.renewed(previous, 'new-authorization', { generation: crypto.randomUUID() }) });
    assert.equal((await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), resourceId, 2)).state, 'prepared');
    const late = await f.renewed(previous, 'old-authorization');
    await assert.rejects(f.operations.commit(f.delegate.actor, pending.id, pending.fence, late), { code: 'invalid_operation' });
  } finally { await f.close(); }
});
