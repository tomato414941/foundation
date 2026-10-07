import test from 'node:test';
import assert from 'node:assert/strict';
import { delegatedFixture as setup } from './delegation-support.js';
import { bindKeys, newIdentityKeys, signBinding } from '../shared/authority.js';
import { openRun, prepareRun, protect, reveal } from '../shared/custody.js';
import { makeReceipt, readReceipt } from '../shared/execution.js';
import { decode, encode } from '../shared/encryption.js';

test('公開鍵を本人の署名に結び付け、同じ鍵の登録を再送する', async () => {
  const f = await setup();
  try {
    const published = await f.bindings.current(f.owner.actor.id);
    assert.deepEqual(published.binding, f.owner.binding);
    assert.deepEqual(await f.bindings.publish(f.owner.actor, published), published);
    await assert.rejects(f.bindings.publish(f.stranger.actor, published), { code: 'forbidden' });
    const replacementKeys = await newIdentityKeys();
    const replacement = bindKeys(f.owner.actor.id, replacementKeys);
    await assert.rejects(f.bindings.publish(f.owner.actor, await signBinding(replacement, replacementKeys)),
      { code: 'key_binding_changed' });
  } finally { await f.close(); }
});

test('所有者と指定した実行先へ暗号化データを配り、権限変更を署名して保存する', async () => {
  const f = await setup();
  try {
    const read = await f.custody.read(f.owner.actor, f.policy.id);
    assert.equal(decode(await reveal(read.content, f.owner.binding, f.owner.keys.encryption)), 'confidential-value');
    assert.deepEqual((await f.custody.read(f.executor.actor, f.policy.id)).content, read.content);
    await assert.rejects(f.custody.read(f.stranger.actor, f.policy.id), { code: 'forbidden' });
    const policy = { ...f.policy, revision: 2, grants: [] };
    const next = await protect(encode('new-value'), policy, 2, f.owner.binding, f.owner.keys);
    await f.custody.put(f.owner.actor, { name: 'Credential', content: next, data: { bytes: 9 }, version: f.resource.version });
    await assert.rejects(f.custody.read(f.executor.actor, f.policy.id), { code: 'forbidden' });
    await assert.rejects(f.custody.put(f.owner.actor, { name: 'Credential', content: next,
      data: { bytes: 9 }, version: f.resource.version }), { code: 'changed' });
  } finally { await f.close(); }
});

test('暗号化された依頼を指定先が一度取得し、暗号化した結果を依頼者へ返す', async () => {
  const f = await setup();
  try {
    const submitted = await f.delegation.submit(f.owner.actor, f.request);
    assert.equal(submitted.state, 'queued');
    assert.equal((await f.delegation.submit(f.owner.actor, f.request)).id, submitted.id);
    await assert.rejects(f.delegation.claim(f.stranger.actor, f.environment.manifest.id), { code: 'forbidden' });
    const claims = await Promise.all([f.delegation.claim(f.executor.actor, f.environment.manifest.id),
      f.delegation.claim(f.executor.actor, f.environment.manifest.id)]);
    assert.equal(claims.filter(Boolean).length, 1);
    const claim = claims.find(Boolean)!;
    assert.deepEqual((await openRun(claim.request, f.executor.binding, f.executor.keys)).operation, f.operation);
    await assert.rejects(openRun(claim.request, f.stranger.binding, f.stranger.keys));
    await f.delegation.dispatch(f.executor.actor, submitted.id, claim.lease);
    const receipt = await makeReceipt(f.intent, 'succeeded', { ok: true, result: 'private-result', error: null }, f.executor.keys);
    const completed = await f.delegation.finish(f.executor.actor, claim.lease, receipt);
    assert.equal(completed.state, 'succeeded');
    assert.equal((await readReceipt(completed.receipt!, f.intent, f.owner.binding.id, f.owner.keys)).result, 'private-result');
    await assert.rejects(readReceipt(completed.receipt!, f.intent, f.stranger.binding.id, f.stranger.keys));
    assert.deepEqual(await f.delegation.finish(f.executor.actor, claim.lease, receipt), completed);
  } finally { await f.close(); }
});

test('外部操作前に失われた実行権を引き継ぎ、古い実行権による開始を拒否する', async () => {
  const f = await setup();
  try {
    await f.delegation.submit(f.owner.actor, f.request);
    const before = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
    await f.db.pool.query("UPDATE execution_tasks SET lease_until=now()-interval '1 second' WHERE id=$1", [f.intent.id]);
    await f.delegation.recover();
    const after = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
    assert.notEqual(after.lease, before.lease);
    await assert.rejects(f.delegation.dispatch(f.executor.actor, f.intent.id, before.lease), { code: 'lease_lost' });
    await f.delegation.dispatch(f.executor.actor, f.intent.id, after.lease);
    assert.deepEqual(await f.delegation.renew(f.executor.actor, f.intent.id, after.lease), { active: true });
  } finally { await f.close(); }
});

test('外部操作中の通信断を未確定として記録し、同じ実行先の記録から結果を確定する', async () => {
  const f = await setup();
  try {
    await f.delegation.submit(f.owner.actor, f.request);
    const claim = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
    await f.delegation.dispatch(f.executor.actor, f.intent.id, claim.lease);
    await f.db.pool.query("UPDATE execution_tasks SET lease_until=now()-interval '1 second' WHERE id=$1", [f.intent.id]);
    await f.delegation.recover();
    assert.equal((await f.delegation.get(f.owner.actor, f.intent.id)).state, 'uncertain');
    assert.equal(await f.delegation.claim(f.executor.actor, f.environment.manifest.id), null);
    const receipt = await makeReceipt(f.intent, 'succeeded', { ok: true, result: { created: true }, error: null }, f.executor.keys);
    assert.equal((await f.delegation.finish(f.executor.actor, claim.lease, receipt)).state, 'succeeded');
  } finally { await f.close(); }
});

test('待機中の依頼を取り消し、開始後の取り消しは結果の確認待ちとして示す', async () => {
  const f = await setup();
  try {
    await f.delegation.submit(f.owner.actor, f.request);
    assert.equal((await f.delegation.cancel(f.owner.actor, f.intent.id)).state, 'cancelled');
    const intent = { ...f.intent, id: crypto.randomUUID() };
    await f.delegation.submit(f.owner.actor, await prepareRun(intent, f.operation, f.owner.keys));
    const claim = (await f.delegation.claim(f.executor.actor, f.environment.manifest.id))!;
    await f.delegation.dispatch(f.executor.actor, intent.id, claim.lease);
    assert.equal((await f.delegation.cancel(f.owner.actor, intent.id)).state, 'uncertain');
    assert.deepEqual(await f.delegation.renew(f.executor.actor, intent.id, claim.lease), { active: false });
  } finally { await f.close(); }
});

test('権限が変わった依頼を開始前に止め、停止した実行先への依頼を拒否する', async () => {
  const f = await setup();
  try {
    await f.delegation.submit(f.owner.actor, f.request);
    const content = await protect(encode('value'), { ...f.policy, revision: 2, grants: [] },
      2, f.owner.binding, f.owner.keys);
    await f.custody.put(f.owner.actor, { name: 'Credential', content, data: { bytes: 5 }, version: f.resource.version });
    assert.equal(await f.delegation.claim(f.executor.actor, f.environment.manifest.id), null);
    assert.equal((await f.delegation.get(f.owner.actor, f.intent.id)).state, 'failed');
    await f.delegation.stop(f.owner.actor, f.environment.manifest.id);
    await assert.rejects(f.delegation.heartbeat(f.executor.actor, f.environment.manifest.id), { code: 'environment_stopped' });
  } finally { await f.close(); }
});
