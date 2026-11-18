import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { ContentTypes, protect, renewContent, reveal } from '../shared/custody.js';
import type { CustodyPolicy } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';

async function setup() {
  const f = await delegatedFixture();
  const policy: CustodyPolicy = { ...f.policy, id: crypto.randomUUID(), contentType: ContentTypes.tokenSet };
  const metadata = { state: 'ready', methodId: 'provider:oauth', methodKind: 'oauth', generation: crypto.randomUUID(),
    appId: null, accountId: 'account-1', accountVerified: true,
    scopes: ['read'], scopesStatus: 'reported', outputs: ['ACCESS_TOKEN'] };
  const content = await protect(encode('old-refresh-token'), policy, 1, f.owner.binding, f.owner.keys, metadata);
  const resource = await f.custody.put(f.owner.actor, { name: 'Connection', content, labels: { account: 'Account' } });
  return { ...f, connection: { policy, content, resource }, operations: new ConnectionOperations(f.custody) };
}

test('接続の更新を一つの読み手が取得し、更新した暗号文を一度だけ確定する', async () => {
  const f = await setup();
  try {
    const id = crypto.randomUUID(), source = f.connection.content;
    const results = await Promise.allSettled([
      f.operations.prepare(f.delegate.actor, id, source.policy.id, 1),
      f.operations.prepare(f.delegate.actor, crypto.randomUUID(), source.policy.id, 1),
    ]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const operation = (results.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<Awaited<ReturnType<typeof f.operations.prepare>>>).value;
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    const content = await renewContent(source, encode('rotated-refresh-token'), f.delegate.binding, f.delegate.keys);
    assert.deepEqual(await f.operations.commit(f.delegate.actor, operation.id, operation.fence, content), content);
    assert.deepEqual(await f.operations.commit(f.delegate.actor, operation.id, operation.fence, content), content);
    const current = await f.custody.read(f.owner.actor, source.policy.id);
    assert.equal(current.content.materialRevision, 2);
    assert.equal(decode(await reveal(current.content, f.owner.binding, f.owner.keys.encryption)), 'rotated-refresh-token');
  } finally { await f.close(); }
});

test('更新応答が不明な接続を停止し、保存済みの更新結果で復旧する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content;
    const operation = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), source.policy.id, 1);
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    await f.operations.uncertain(f.delegate.actor, operation.id, operation.fence);
    await assert.rejects(f.operations.prepare(f.delegate.actor, crypto.randomUUID(), source.policy.id, 1), { code: 'connection_uncertain' });
    await assert.rejects(f.operations.abort(f.delegate.actor, operation.id, operation.fence), { code: 'connection_uncertain' });
    const recovered = await renewContent(source, encode('durably-recorded-token'), f.delegate.binding, f.delegate.keys);
    await f.operations.commit(f.delegate.actor, operation.id, operation.fence, recovered);
    assert.equal((await f.resources.get(source.policy.id)).data.state, 'ready');
    assert.equal(await f.operations.state(f.delegate.actor, source.policy.id), null);
  } finally { await f.close(); }
});

test('接続の更新中は読み手の変更と削除を待たせ、更新で変わった権限もそのまま確定する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content;
    const operation = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), source.policy.id, 1);
    const changed = await protect(encode('replacement'), { ...source.policy, revision: 2, observers: [f.stranger.actor.id] }, 2,
      f.owner.binding, f.owner.keys, source.metadata);
    await assert.rejects(f.custody.put(f.owner.actor, { name: 'Connection', content: changed,
      version: f.connection.resource.version }), { code: 'connection_busy' });
    await assert.rejects(f.resources.delete(f.owner.actor, f.connection.resource), { code: 'connection_busy' });
    await f.operations.dispatch(f.delegate.actor, operation.id, operation.fence);
    const broadened = await renewContent(source, encode('broader-token'), f.delegate.binding, f.delegate.keys,
      { ...source.metadata, scopes: ['read', 'write'] });
    await f.operations.commit(f.delegate.actor, operation.id, operation.fence, broadened);
    assert.deepEqual((await f.resources.get(source.policy.id)).data.scopes, ['read', 'write']);
  } finally { await f.close(); }
});

test('結果が不明な古い更新を新しく承認した接続に置き換え、新世代の更新を開始する', async () => {
  const f = await setup();
  try {
    const previous = f.connection.content;
    const pending = await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), previous.policy.id, 1);
    await f.operations.dispatch(f.delegate.actor, pending.id, pending.fence);
    await f.operations.uncertain(f.delegate.actor, pending.id, pending.fence);
    const replacement = await protect(encode('new-authorization'), previous.policy, 2, f.owner.binding, f.owner.keys,
      { ...previous.metadata, generation: crypto.randomUUID() });
    await f.custody.put(f.owner.actor, { name: 'Connection', content: replacement,
      version: (await f.resources.get(previous.policy.id)).version });
    assert.equal((await f.operations.prepare(f.delegate.actor, crypto.randomUUID(), previous.policy.id, 2)).state, 'prepared');
    const late = await renewContent(previous, encode('old-authorization'), f.delegate.binding, f.delegate.keys);
    await assert.rejects(f.operations.commit(f.delegate.actor, pending.id, pending.fence, late), { code: 'invalid_operation' });
  } finally { await f.close(); }
});

