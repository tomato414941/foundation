import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { ContentTypes, Operations, reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';

const minutes = (count: number) => new Date(Date.now() + count * 60_000).toISOString();

test('期限の切れた許可が残る項目を待ち行列に示し、所有者の端末がその許可を外して封じ直す', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const save = async (name: string, value: string, expiresAt: string) => f.client.save(name, encode(value),
    await f.client.policy(f.owner.actor.id, ContentTypes.value, [f.environment], { expiresAt }));
  const expired = await save('Expired token', 'kept after expiry', minutes(-1));
  const current = await save('Current token', 'still granted', minutes(60));

  assert.deepEqual(await f.client.pendingProtection(), [{ id: expired.id, reason: 'grantExpired' }]);
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
  assert.deepEqual(await f.client.pendingProtection(), [{ id: saved.id, reason: 'grantExpired' }]);
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

test('持ち主の端末は鍵を確かめた代理にだけ持ち主の項目を封じ直し、確かめていない代理がいても項目を作れる', async (t) => {
  const f = await flowFixture();
  t.after(f.close);
  const ai = await f.person('Agent'), other = await f.person('Other');
  const saved = await f.client.save('Token', encode('owner value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  for (const agent of [ai, other])
    await f.db.pool.query("INSERT INTO relations(subject_id,relation,principal_id) VALUES($1,'agent',$2)", [agent.actor.id, f.owner.actor.id]);

  const items = [saved.id, f.resource.id].sort();
  assert.deepEqual(await f.client.pendingProtection(), items.map(id => ({ id, reason: 'recipients' })));
  assert.deepEqual(await f.client.reprotectPending(), { done: [], failed: [] });
  await assert.rejects(f.custody.read(ai.actor, saved.id), { code: 'forbidden' });
  await f.client.trust.rememberBinding(ai.binding);
  assert.deepEqual(await f.client.reprotectPending(), { done: items, failed: [] });
  const shared = await f.custody.read(ai.actor, saved.id);
  assert.equal(decode(await reveal(shared.content, ai.binding, ai.keys.encryption)), 'owner value');
  await assert.rejects(f.custody.read(other.actor, saved.id), { code: 'forbidden' });
  const later = await f.client.save('Later', encode('later value'), await f.client.policy(f.owner.actor.id, ContentTypes.value));
  assert.deepEqual((await f.custody.get(later.id)).policy.readers.map(reader => reader.principalId).sort(),
    [f.owner.actor.id, f.executor.binding.principalId, ai.actor.id].sort());
});
