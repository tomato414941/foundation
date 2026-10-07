import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture } from './delegation-support.js';
import { ConnectionOperations } from '../server/connection-operations.js';
import { approvePolicy, prepareRun, produceContent, protect, renewContent, reveal, matchesPin } from '../shared/custody.js';
import type { CustodyPolicy } from '../shared/custody.js';
import { hash } from '../shared/authority.js';
import { decode, encode } from '../shared/encryption.js';

async function setup() {
  const f = await delegatedFixture();
  const policy: CustodyPolicy = { ...f.policy, id: crypto.randomUUID(), kind: 'connection',
    grants: [{ ...f.policy.grants[0]!, operations: ['http', 'refresh'] }] };
  const metadata = { state: 'ready', authorizationDigest: await hash({ account: 'account-1', scopes: ['read'] }) };
  const content = await protect(encode('old-refresh-token'), policy, 1, f.owner.binding, f.owner.keys, metadata);
  const resource = await f.custody.put(f.owner.actor, { name: 'Connection', content });
  return { ...f, connection: { policy, content, resource }, operations: new ConnectionOperations(f.custody) };
}

test('接続更新を一つの実行先が取得し、更新した暗号文を一度だけ確定する', async () => {
  const f = await setup();
  try {
    const id = crypto.randomUUID(), source = f.connection.content;
    const results = await Promise.allSettled([
      f.operations.prepare(f.executor.actor, id, source.policy.id, 1),
      f.operations.prepare(f.executor.actor, crypto.randomUUID(), source.policy.id, 1),
    ]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const operation = (results.find(result => result.status === 'fulfilled') as PromiseFulfilledResult<Awaited<ReturnType<typeof f.operations.prepare>>>).value;
    await f.operations.dispatch(f.executor.actor, operation.id, operation.fence);
    const content = await renewContent(source, encode('rotated-refresh-token'), f.executor.binding, f.executor.keys);
    assert.deepEqual(await f.operations.commit(f.executor.actor, operation.id, operation.fence, content), content);
    assert.deepEqual(await f.operations.commit(f.executor.actor, operation.id, operation.fence, content), content);
    const current = await f.custody.read(f.owner.actor, source.policy.id);
    assert.equal(current.content.materialRevision, 2);
    assert.equal(decode(await reveal(current.content, f.owner.binding, f.owner.keys.encryption)), 'rotated-refresh-token');
    assert.equal(await matchesPin(content, { id: source.policy.id, kind: 'connection', policyDigest: await hash(source.policy),
      materialRevision: 1, authorizationDigest: String(source.metadata.authorizationDigest) }), true);
  } finally { await f.close(); }
});

test('更新応答が不明な接続を停止し、保存済みの更新結果で復旧する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content;
    const operation = await f.operations.prepare(f.executor.actor, crypto.randomUUID(), source.policy.id, 1);
    await f.operations.dispatch(f.executor.actor, operation.id, operation.fence);
    await f.operations.uncertain(f.executor.actor, operation.id, operation.fence);
    await assert.rejects(f.operations.prepare(f.executor.actor, crypto.randomUUID(), source.policy.id, 1), { code: 'connection_uncertain' });
    await assert.rejects(f.operations.abort(f.executor.actor, operation.id, operation.fence), { code: 'connection_uncertain' });
    const recovered = await renewContent(source, encode('durably-recorded-token'), f.executor.binding, f.executor.keys);
    await f.operations.commit(f.executor.actor, operation.id, operation.fence, recovered);
    assert.equal((await f.resources.get(source.policy.id)).data.state, 'ready');
    assert.equal(await f.operations.state(f.executor.actor, source.policy.id), null);
  } finally { await f.close(); }
});

test('接続更新中は宛先の変更を待ち、承認した接続先と権限を維持する', async () => {
  const f = await setup();
  try {
    const source = f.connection.content;
    const operation = await f.operations.prepare(f.executor.actor, crypto.randomUUID(), source.policy.id, 1);
    const changed = await protect(encode('replacement'), { ...source.policy, revision: 2, grants: [] }, 2,
      f.owner.binding, f.owner.keys, source.metadata);
    await assert.rejects(f.custody.put(f.owner.actor, { name: 'Connection', content: changed,
      version: f.connection.resource.version }), { code: 'connection_busy' });
    await f.operations.dispatch(f.executor.actor, operation.id, operation.fence);
    const broadened = await renewContent(source, encode('other-account-token'), f.executor.binding, f.executor.keys,
      { ...source.metadata, authorizationDigest: await hash({ account: 'another-account' }) });
    await assert.rejects(f.operations.commit(f.executor.actor, operation.id, operation.fence, broadened), { code: 'changed' });
  } finally { await f.close(); }
});

test('所有者が承認した出力先へ実行結果を暗号化して保存する', async () => {
  const f = await delegatedFixture();
  try {
    const policy = { ...f.policy, id: crypto.randomUUID(), grants: [], producers: [{
      executor: f.executor.binding, runId: f.intent.id, expiresAt: f.intent.expiresAt, materialRevision: 1,
    }] };
    const approval = await approvePolicy(policy, f.owner.binding, f.owner.keys);
    await f.delegation.submit(f.owner.actor, await prepareRun(f.intent, f.operation, f.owner.keys));
    const claim = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
    await f.delegation.dispatch(f.executor.actor, f.intent.id, claim.lease);
    const content = await produceContent(encode('output'), approval, f.intent.id, f.executor.binding,
      f.executor.keys, { bytes: 6 });
    const saved = await f.custody.putProduced(f.executor.actor, { name: 'Output', content });
    assert.equal(saved.id, policy.id);
    assert.equal(decode(await reveal((await f.custody.read(f.owner.actor, saved.id)).content,
      f.owner.binding, f.owner.keys.encryption)), 'output');
    assert.equal((await f.custody.putProduced(f.executor.actor, { name: 'Output', content })).id, saved.id);
    await assert.rejects(produceContent(encode('output'), approval, crypto.randomUUID(), f.executor.binding,
      f.executor.keys, { bytes: 6 }));
  } finally { await f.close(); }
});
