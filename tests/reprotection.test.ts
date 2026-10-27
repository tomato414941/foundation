import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { ContentTypes, Operations, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';

const minutes = (count: number) => new Date(Date.now() + count * 60_000).toISOString();

test('委任先が64件の項目を開けるように暗号化し直す間の進捗を通知する', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const delegate = await f.person('Progress delegate');
  await f.client.trust.rememberBinding(delegate.binding);
  const saved = await Promise.all(Array.from({ length: 63 }, async (_, index) => f.client.save('Progress ' + index,
    encode('value ' + index), await f.client.policy(f.owner.actor.id, ContentTypes.value))));
  await f.client.api.json('/api/relations', { method: 'POST', body: {
    subjectId: delegate.actor.id, relation: 'delegate', objectId: f.owner.actor.id } });

  const progress: Array<{ completed: number; total: number }> = [];
  const result = await f.client.reprotectPending(value => progress.push(value));
  assert.equal(progress.length, 65);
  assert.deepEqual(progress[0], { completed: 0, total: 64 });
  assert.deepEqual(progress[12], { completed: 12, total: 64 });
  assert.deepEqual(progress[64], { completed: 64, total: 64 });
  assert.deepEqual(result, { done: [f.resource.id, ...saved.map(item => item.id)].sort(), failed: [] });
  assert.deepEqual(await f.client.pendingProtection(), []);
  const shared = await f.custody.read(delegate.actor, saved[62]!.id);
  assert.equal(decode(await reveal(shared.content, delegate.binding, delegate.keys.encryption)), 'value 62');
});

test('期限の切れた許可が残る項目を待ち行列に示し、所有者の端末がその許可を外して封じ直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const save = async (name: string, value: string, expiresAt: string) => f.client.save(name, encode(value),
    await f.client.policy(f.owner.actor.id, ContentTypes.value, [f.environment], { expiresAt }));
  const expired = await save('Expired token', 'kept after expiry', minutes(-1));
  const current = await save('Current token', 'still granted', minutes(60));

  assert.deepEqual(await f.client.pendingProtection(), [{ id: expired.id, reason: 'grantExpired', remove: [] }]);
  assert.deepEqual(await f.client.reprotectPending(), { done: [expired.id], failed: [] });
  assert.deepEqual(await f.client.pendingProtection(), []);

  const { content } = await f.client.read(expired.id);
  assert.deepEqual(content.policy.grants, []);
  assert.equal(content.policy.revision, 2);
  assert.equal(content.materialRevision, 2);
  assert.deepEqual(content.sealed.recipients.map(recipient => recipient.header.kid).sort(), [f.owner.binding.id, f.executor.binding.id].sort());
  assert.equal(decode(await reveal(content, f.owner.binding, f.owner.keys.encryption)), 'kept after expiry');
  assert.deepEqual((await f.resources.get(expired.id)).data.executors, []);
  assert.equal((await f.client.read(current.id)).content.policy.grants.length, 1);
});

test('実行結果の書き込みを待つ項目は、その書き込みの期限まで封じ直さない', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value, [f.environment], { expiresAt: minutes(-1) });
  policy.producers = [{ executor: f.environment.manifest.executor, runId: crypto.randomUUID(), expiresAt: minutes(60), materialRevision: 2 }];
  const saved = await f.client.save('Run output', encode('before the run'), policy);

  assert.deepEqual(await f.client.reprotectPending(), { done: [], failed: [] });
  assert.deepEqual(await f.client.pendingProtection(), [{ id: saved.id, reason: 'grantExpired', remove: [] }]);
  assert.equal((await f.client.read(saved.id)).content.policy.revision, 1);
});

test('値を保存し直すとき、ほかの人が受けた許可のうち期限の切れたものを引き継がない', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const grant = (expiresAt: string) => ({ actor: f.stranger.binding, executor: f.environment.manifest.executor,
    operations: [Operations.command], functionDigests: [], origins: [], callerProgram: true, expiresAt });
  const previous = { ...await f.client.policy(f.owner.actor.id, ContentTypes.value), grants: [grant(minutes(-1)), grant(minutes(60))] };

  const next = await f.client.policy(f.owner.actor.id, ContentTypes.value, [], { previous });
  assert.deepEqual(next.grants, [previous.grants[1]]);
  assert.equal(next.revision, previous.revision + 1);
});

test('持ち主の端末は未検証の委任先を明示し、全員の鍵を検証してから項目を暗号化し直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent'), other = await f.person('Other');
  const saved = await f.client.save('Token', encode('owner value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  for (const agent of [ai, other])
    await f.db.pool.query("INSERT INTO relations(subject_id,relation,principal_id) VALUES($1,'delegate',$2)", [agent.actor.id, f.owner.actor.id]);

  const items = [saved.id, f.resource.id].sort();
  assert.deepEqual(await f.client.pendingProtection(), items.map(id => ({ id, reason: 'recipients', remove: [] })));
  const pending = await f.client.reprotectPending();
  assert.deepEqual(pending.done, []);
  assert.deepEqual(pending.failed.map(item => item.id), items);
  for (const item of pending.failed) {
    assert.equal(item.code, 'recipient_verification_required');
    assert.deepEqual(item.verification?.map(recipient => recipient.id).sort(), [ai.actor.id, other.actor.id].sort());
  }
  await assert.rejects(f.custody.read(ai.actor, saved.id), { code: 'forbidden' });
  await f.client.trust.rememberBinding(ai.binding);
  const remaining = await f.client.reprotectPending();
  assert.deepEqual(remaining.done, []);
  for (const item of remaining.failed) assert.deepEqual(item.verification, [
    { id: other.actor.id, name: 'Other', code: 'identity_untrusted' }]);
  await f.client.trust.rememberBinding(other.binding);
  assert.deepEqual(await f.client.reprotectPending(), { done: items, failed: [] });
  const shared = await f.custody.read(ai.actor, saved.id);
  assert.equal(decode(await reveal(shared.content, ai.binding, ai.keys.encryption)), 'owner value');
  assert.equal(decode(await reveal((await f.custody.read(other.actor, saved.id)).content, other.binding, other.keys.encryption)), 'owner value');
  const later = await f.client.save('Later', encode('later value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  assert.deepEqual((await f.custody.get(later.id)).policy.readers.map(reader => reader.principalId).sort(),
    [f.owner.actor.id, f.executor.binding.principalId, ai.actor.id, other.actor.id].sort());
});

test('委任先の線を外すと、まだ封じてある項目も委任先に渡さなくなり、持ち主の端末が委任先抜きで封じ直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent');
  await f.client.trust.rememberBinding(ai.binding);
  const saved = await f.client.save('Token', encode('owner value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  const line = { subjectId: ai.actor.id, relation: 'delegate', objectId: f.owner.actor.id };
  await f.client.api.json('/api/relations', { method: 'POST', body: line });
  await f.client.reprotectPending();
  assert.equal(decode(await reveal((await f.custody.read(ai.actor, saved.id)).content, ai.binding, ai.keys.encryption)), 'owner value');

  await f.client.api.json('/api/relations', { method: 'DELETE', body: line });
  await assert.rejects(f.custody.read(ai.actor, saved.id), { code: 'forbidden' });
  assert.deepEqual((await f.client.pendingProtection()).find(item => item.id === saved.id), { id: saved.id, reason: 'recipients', remove: [ai.actor.id] });
  assert.deepEqual((await f.client.reprotectPending()).failed, []);
  const { content } = await f.client.read(saved.id);
  assert.equal(content.policy.readers.some(reader => reader.principalId === ai.actor.id), false);
  assert.equal(content.policy.authorities.some(authority => authority.principalId === ai.actor.id), false);
  assert.equal(decode(await reveal(content, f.owner.binding, f.owner.keys.encryption)), 'owner value');
  assert.deepEqual(await f.client.pendingProtection(), []);
});

test('トークン更新中の項目があっても委任先の線を引け、持ち主の端末はほかの項目を封じ直してその項目を理由とともに残す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent');
  await f.client.trust.rememberBinding(ai.binding);
  const busy = await f.client.save('Busy token', encode('busy value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  await f.db.pool.query("INSERT INTO connection_operations(id,resource_id,executor_id,expected_revision,state) VALUES($1,$2,$3,1,'in_flight')",
    [crypto.randomUUID(), busy.id, f.owner.actor.id]);
  await f.client.api.json('/api/relations', { method: 'POST', body: { subjectId: ai.actor.id, relation: 'delegate', objectId: f.owner.actor.id } });

  const progress: Array<{ completed: number; total: number }> = [];
  assert.deepEqual(await f.client.reprotectPending(value => progress.push(value)),
    { done: [f.resource.id], failed: [{ id: busy.id, code: 'connection_busy' }] });
  assert.deepEqual(progress, [{ completed: 0, total: 2 }, { completed: 1, total: 2 }, { completed: 2, total: 2 }]);
  assert.equal(decode(await reveal((await f.custody.read(ai.actor, f.resource.id)).content, ai.binding, ai.keys.encryption)).length > 0, true);
  await assert.rejects(f.custody.read(ai.actor, busy.id), { code: 'forbidden' });
  assert.deepEqual((await f.client.pendingProtection()).map(item => item.id), [busy.id]);
});
