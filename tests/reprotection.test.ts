import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { ContentTypes, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { Resource, listOf } from '../shared/contracts.js';

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

test('持ち主の端末は未検証の代理を知らせ、検証済みの代理が項目を開けるように暗号化し直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent'), other = await f.person('Other');
  const saved = await f.client.save('Token', encode('owner value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  for (const agent of [ai, other])
    await f.db.pool.query("INSERT INTO relations(subject_id,relation,principal_id) VALUES($1,'delegate',$2)", [agent.actor.id, f.owner.actor.id]);

  const items = [saved.id, f.resource.id].sort();
  assert.deepEqual(await f.client.pendingProtection(), items.map(id => ({ id, remove: [] })));
  const pending = await f.client.reprotectPending();
  assert.deepEqual(pending.done, []);
  assert.deepEqual(pending.failed.map(item => item.id), items);
  for (const item of pending.failed) {
    assert.equal(item.code, 'recipient_excluded');
    assert.deepEqual(item.verification?.map(recipient => recipient.id).sort(), [ai.actor.id, other.actor.id].sort());
  }
  await assert.rejects(f.custody.read(ai.actor, saved.id), { code: 'forbidden' });
  await f.client.trust.rememberBinding(ai.binding);
  const remaining = await f.client.reprotectPending();
  assert.deepEqual(remaining.done, items);
  const shared = await f.custody.read(ai.actor, saved.id);
  assert.equal(decode(await reveal(shared.content, ai.binding, ai.keys.encryption)), 'owner value');
  for (const item of remaining.failed) assert.deepEqual(item.verification, [
    { id: other.actor.id, name: 'Other', code: 'identity_untrusted' }]);
  await f.client.trust.rememberBinding(other.binding);
  assert.deepEqual(await f.client.reprotectPending(), { done: items, failed: [] });
  assert.equal(decode(await reveal((await f.custody.read(other.actor, saved.id)).content, other.binding, other.keys.encryption)), 'owner value');
  const later = await f.client.save('Later', encode('later value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  assert.deepEqual((await f.custody.get(later.id)).policy.readers.map(reader => reader.principalId).sort(),
    [f.owner.actor.id, f.delegate.binding.principalId, ai.actor.id, other.actor.id].sort());
});

test('委任先の線を外すと、まだ封じてある項目も委任先に渡さなくなる', async (t) => {
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
  assert.equal(decode(await f.client.reveal(saved.id)), 'owner value');
});

test('トークン更新中の項目があっても委任先の線を引け、持ち主の端末はほかの項目を封じ直してその項目を理由とともに残す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent');
  await f.client.trust.rememberBinding(ai.binding);
  const busy = await f.client.save('Busy token', encode('busy value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  await f.db.pool.query("INSERT INTO connection_operations(id,resource_id,renewer_id,expected_revision,state) VALUES($1,$2,$3,1,'in_flight')",
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

test('以前の形のまま残った項目は、開こうとすると理由を示して断り、一覧・封じ直し・削除は止めない', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent');
  await f.client.trust.rememberBinding(ai.binding);
  const earlier = await f.saveConnection({ methodId: 'cloudrift:api_key', name: 'Earlier account', fields: { token: 'earlier-token' } });
  // What production keeps of an item that no device sealed again in the current form.
  await f.db.pool.query("UPDATE resource_custody SET content=jsonb_set(content,'{policy,format}','2') WHERE resource_id=$1", [earlier.id]);
  for (const read of [() => f.client.read(earlier.id), () => f.custody.read(f.owner.actor, earlier.id)])
    await assert.rejects(read(), { code: 'content_outdated' });
  const listed = await f.client.api.json('/api/principals/' + f.owner.actor.id + '/resources?kind=connection', {}, listOf(Resource));
  assert.deepEqual(listed.items.map(item => item.id), [earlier.id]);

  await f.client.api.json('/api/relations', { method: 'POST', body: { subjectId: ai.actor.id, relation: 'delegate', objectId: f.owner.actor.id } });
  assert.deepEqual(await f.client.pendingProtection(), [{ id: f.resource.id, remove: [] }]);
  assert.deepEqual(await f.client.reprotectPending(), { done: [f.resource.id], failed: [] });
  assert.equal(decode(await reveal((await f.custody.read(ai.actor, f.resource.id)).content, ai.binding, ai.keys.encryption)).length > 0, true);

  await f.client.api.json('/api/resources/' + earlier.id, { method: 'DELETE' });
  await assert.rejects(f.client.api.json('/api/resources/' + earlier.id, {}, Resource), { status: 404 });
});
