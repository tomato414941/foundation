import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { openItem } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';

test('委任先が64件の項目を開けるように包み直す間の進捗を知らせる', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const delegate = await f.personWithKeys('Progress delegate');
  const saved = await Promise.all(Array.from({ length: 63 }, (_, index) => f.client.save({ id: crypto.randomUUID(),
    ownerId: f.owner.actor.id, kind: 'variable' }, 'Progress ' + index, encode('value ' + index))));
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
  assert.equal(decode(await openItem(shared.content, delegate.keys.privateKey, delegate.keys.publicKey)), 'value 62');
});

test('委任先の線を外すと、まだ包んである項目も委任先に渡さなくなる', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.personWithKeys('Agent');
  const saved = await f.client.save({ id: crypto.randomUUID(), ownerId: f.owner.actor.id, kind: 'variable' }, 'Token', encode('owner value'));
  const line = { subjectId: ai.actor.id, relation: 'delegate', objectId: f.owner.actor.id };
  await f.client.api.json('/api/relations', { method: 'POST', body: line });
  await f.client.reprotectPending();
  assert.equal(decode(await openItem((await f.custody.read(ai.actor, saved.id)).content, ai.keys.privateKey, ai.keys.publicKey)), 'owner value');

  await f.client.api.json('/api/relations', { method: 'DELETE', body: line });
  await assert.rejects(f.custody.read(ai.actor, saved.id), { code: 'forbidden' });
  assert.equal(decode(await f.client.reveal(saved.id)), 'owner value');
});

test('トークン更新中の項目があっても委任先の線を引け、持ち主の端末はほかの項目を包んでその項目を理由とともに残す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.personWithKeys('Agent');
  const busy = await f.saveConnection({ methodId: 'cloudrift:api_key', name: 'Busy account', fields: { token: 'busy-token' } });
  await f.db.pool.query("INSERT INTO connection_operations(id,resource_id,renewer_id,expected_revision,state) VALUES($1,$2,$3,1,'in_flight')",
    [crypto.randomUUID(), busy.id, f.owner.actor.id]);
  await f.client.api.json('/api/relations', { method: 'POST', body: { subjectId: ai.actor.id, relation: 'delegate', objectId: f.owner.actor.id } });

  const progress: Array<{ completed: number; total: number }> = [];
  assert.deepEqual(await f.client.reprotectPending(value => progress.push(value)),
    { done: [f.resource.id], failed: [{ id: busy.id, code: 'connection_busy' }] });
  assert.deepEqual(progress, [{ completed: 0, total: 2 }, { completed: 1, total: 2 }, { completed: 2, total: 2 }]);
  assert.equal(decode(await openItem((await f.custody.read(ai.actor, f.resource.id)).content, ai.keys.privateKey, ai.keys.publicKey)),
    'confidential-value');
  assert.deepEqual((await f.client.pendingProtection()).map(item => item.id), [busy.id]);
});
