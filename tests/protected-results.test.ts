import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient } from '../shared/client.js';
import { JournalTrust } from '../runtime/trust.js';
import { Executor } from '../runtime/executor.js';
import { ContentTypes, protect } from '../shared/custody.js';
import { Task, receiptHeader, signEnvironment } from '../shared/runtime-protocol.js';
import { canonical, hash, sign } from '../shared/authority.js';
import { decode, encode } from '../shared/encryption.js';
import { ProtectedRead } from '../shared/protocol.js';
import { Accounts } from '../server/accounts.js';

async function setup() {
  const f = await flowFixture();
  const environment = await signEnvironment({ ...f.environment.manifest, resultVersion: 1,
    revision: f.environment.manifest.revision + 1 }, f.executor.keys);
  await f.context.delegation.register(f.executorIdentity.actor, environment);
  const executor = new Executor(environment, f.executor.keys, f.executor.broker, f.executor.journal,
    f.executor.transport, f.executor.commands, f.executor.extension);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.owner.binding);
  await trust.rememberBinding(f.executorIdentity.binding);
  const viewer = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys, trust);
  return { ...f, executor, viewer };
}

test('所有するAIが開始した実行結果を、所有者が自分の鍵で読む', async t => {
  const f = await setup(); t.after(f.close);
  await f.db.pool.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [f.executorIdentity.actor.id, f.owner.actor.id]);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.owner.binding);
  const agent = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin,
    f.executorIdentity.binding, f.executorIdentity.keys, trust);
  const task = await agent.submit(f.executorIdentity.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['node', '-e', 'console.log("owned-agent-result")'], inputs: [], timeoutSeconds: 5 });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.equal(completed.state, 'succeeded');
  assert.equal((await f.client.result(completed))?.result?.stdout, 'owned-agent-result\n');
  assert.equal((await agent.result(completed))?.result?.stdout, 'owned-agent-result\n');
  const stored = await f.context.custody.read(f.owner.actor, task.id);
  assert.equal(stored.content.policy.contentType, ContentTypes.executionResult);
  assert.equal(JSON.stringify(stored).includes('owned-agent-result'), false);
});

test('メンバーの追加と解除を、所有者の端末が秘密変数と実行結果へ一緒に封じ直して反映する', async t => {
  const f = await setup(); t.after(f.close);
  await f.client.trust.rememberBinding(f.stranger.binding);
  const secret = await f.client.save('Shared secret', encode('protected-team-value'),
    await f.client.policy(f.owner.actor.id, ContentTypes.value));
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['node', '-e', 'console.log("protected-team-result")'], inputs: [], timeoutSeconds: 5 });
  await f.executor.tick();
  const original = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.ok(original.receipt && 'content' in original.receipt);
  const header = receiptHeader(original.receipt), signature = original.receipt.signature;
  const line = { subjectId: f.stranger.actor.id, relation: 'member' as const, objectId: f.owner.actor.id };
  await f.client.api.json('/api/relations', { method: 'POST', body: line });
  const added = await f.client.reprotectPending();
  assert.ok(added.done.includes(secret.id) && added.done.includes(task.id), JSON.stringify(added));
  const shared = await f.viewer.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.equal((await f.viewer.result(shared))?.result?.stdout, 'protected-team-result\n');
  assert.equal(decode(await f.viewer.reveal(secret.id)), 'protected-team-value');
  assert.ok(shared.receipt && 'content' in shared.receipt);
  assert.deepEqual(receiptHeader(shared.receipt), header);
  assert.equal(shared.receipt.signature, signature);
  await f.client.api.json('/api/relations', { method: 'DELETE', body: line });
  await assert.rejects(f.viewer.read(task.id), { code: 'forbidden' });
  await assert.rejects(f.viewer.read(secret.id), { code: 'forbidden' });
  const removed = await f.client.reprotectPending();
  assert.ok(removed.done.includes(secret.id) && removed.done.includes(task.id), JSON.stringify(removed));
  for (const id of [secret.id, task.id])
    assert.equal((await f.client.read(id)).content.policy.readers.some(reader => reader.principalId === f.stranger.actor.id), false);
  const current = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.equal((await f.client.result(current))?.result?.stdout, 'protected-team-result\n');
  await f.context.delegation.finish(f.executorIdentity.actor, 'already-delivered', original.receipt);
});

test('閲覧者の鍵で署名された偽の実行依頼と、結果本文の差し替えを検証する', async t => {
  const f = await setup(); t.after(f.close);
  await f.context.relations.draw(f.owner.actor,
    { subjectId: f.stranger.actor.id, relation: 'reader', objectId: f.owner.actor.id });
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['node', '-e', 'console.log("verified-result")'], inputs: [], timeoutSeconds: 5 });
  await f.executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  await assert.rejects(f.viewer.result(completed), { code: 'not_recipient' });
  const forged = await sign({ intent: completed.intent, sealed: {} }, f.stranger.keys.signing, 'run');
  await assert.rejects(f.client.result({ ...completed, requestSignature: forged }));
  assert.ok(completed.receipt && 'content' in completed.receipt);
  const receipt = structuredClone(completed.receipt);
  const text = receipt.content.sealed.ciphertext;
  receipt.content.sealed.ciphertext = (text[0] === 'A' ? 'B' : 'A') + text.slice(1);
  await assert.rejects(f.client.result({ ...completed, receipt }));
  const wrong = { ...completed.intent, ownerId: f.stranger.actor.id };
  await assert.rejects(f.client.result({ ...completed, intent: wrong }));
  assert.notEqual(await hash(receipt), await hash(completed.receipt));
  const current = await f.client.read(task.id);
  const payload = JSON.parse(decode(await f.client.reveal(task.id)));
  payload.result.result.stdout = 'tampered-result\n';
  const content = await protect(encode(canonical(payload)), current.content.policy,
    current.content.materialRevision + 1, f.owner.binding, f.owner.keys, current.content.metadata, current.content);
  await f.client.api.json('/api/custody/' + task.id, { method: 'PUT', body: {
    name: 'Execution result', version: current.version, content,
  } }, ProtectedRead);
  await assert.rejects(f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task)));
});

test('元の実行者が既存結果を共有し、元の署名と完了日時を保持する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.owner.binding);
  const agent = new CustodyClient(f.api(f.executorIdentity.token), f.config.origin,
    f.executorIdentity.binding, f.executorIdentity.keys, trust);
  const task = await agent.submit(f.executorIdentity.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['node', '-e', 'console.log("legacy-result")'], inputs: [], timeoutSeconds: 5 });
  await f.executor.tick();
  const previous = await agent.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.ok(previous.receipt && 'sealed' in previous.receipt);
  await f.db.pool.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [f.executorIdentity.actor.id, f.owner.actor.id]);
  const shared = await agent.shareLegacyResult(previous);
  assert.ok(shared.receipt && 'content' in shared.receipt);
  assert.equal(canonical(shared.receipt.previous), canonical(previous.receipt));
  assert.equal(shared.finishedAt, previous.finishedAt);
  assert.equal((await f.client.result(shared))?.result?.stdout, 'legacy-result\n');
  const stored = await f.client.api.json('/api/custody/' + task.id, {}, ProtectedRead);
  assert.equal(stored.content.policy.ownerId, f.executorIdentity.actor.id);
});

test('開始期限内に動き始めた処理の結果を、期限後も記録して読む', async t => {
  const f = await setup(); t.after(f.close);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const executor = new Executor(f.executor.environment, f.executor.keys, f.executor.broker, f.executor.journal,
    f.executor.transport, { async execute() {
      t.mock.timers.tick(7_200_000);
      return { stdout: 'completed-after-deadline', stderr: '', exitCode: 0, signal: null, timedOut: false, truncated: false };
    } });
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['long-task'], inputs: [], timeoutSeconds: 5 });
  await executor.tick();
  const completed = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.equal(completed.state, 'succeeded');
  assert.equal((await f.client.result(completed))?.result?.stdout, 'completed-after-deadline');
});

test('アカウントの統合で秘密変数と結果を引き継ぎ、署名付きの結果を新しい鍵で読む', async t => {
  const f = await setup(); t.after(f.close);
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id,
    { kind: 'command', command: ['node', '-e', 'console.log("merged-result")'], inputs: [], timeoutSeconds: 5 });
  await f.executor.tick();
  const original = await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.ok(original.receipt && 'content' in original.receipt);
  await f.context.delegation.stop(f.owner.actor, f.environment.manifest.id);
  const accounts = new Accounts(f.context);
  await f.context.authentication.beginEmail('result-merge@example.com', 'browser', '/account', 'en', f.owner.actor, f.owner.actor.id);
  let parameters = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  await f.context.authentication.verifyEmail(parameters.get('challenge')!, parameters.get('token')!);
  await f.context.authentication.beginEmail('result-merge@example.com', 'browser', '/account', 'en', f.stranger.actor,
    undefined, f.stranger.actor.id);
  parameters = new URLSearchParams(new URL(f.mailer.sent.at(-1)!.link).hash.slice(1));
  const verified = await f.context.authentication.verifyEmail(parameters.get('challenge')!, parameters.get('token')!);
  assert.ok('mergeProof' in verified);
  const plan = await accounts.plan(f.stranger.actor, verified.mergeProof);
  const contents: Record<string, { version: number; content: typeof plan.protectedItems[number]['content'] }> = {};
  for (const item of plan.protectedItems) {
    const policy = { ...item.content.policy, ownerId: f.stranger.actor.id, revision: item.content.policy.revision + 1,
      readers: [f.stranger.binding], authorities: [f.stranger.binding], grants: [], producers: [] };
    contents[item.id] = { version: item.version, content: await protect(await f.client.reveal(item.id), policy,
      item.content.materialRevision + 1, f.owner.binding, f.owner.keys, item.content.metadata, item.content) };
  }
  await accounts.merge(f.stranger.actor, verified.mergeProof, contents);
  const current = await f.viewer.api.json('/api/runtime/runs/' + task.id, {}, Task);
  assert.equal(current.ownerId, f.stranger.actor.id);
  assert.equal((await f.viewer.result(current))?.result?.stdout, 'merged-result\n');
  assert.ok(current.receipt && 'content' in current.receipt);
  assert.deepEqual(receiptHeader(current.receipt), receiptHeader(original.receipt));
  const exported: string[] = [];
  for await (const row of accounts.export(f.stranger.actor, f.stranger.actor.id)) exported.push(row);
  assert.ok(exported.some(row => JSON.parse(row).type === 'execution-result'));
});

test('保護データの識別子を一意に保ち、既存の秘密と実行結果を維持する', async t => {
  const f = await setup(); t.after(f.close);
  const operation = { kind: 'command' as const, command: ['node', '-e', 'console.log("unique-result")'],
    inputs: [], timeoutSeconds: 5 };
  await assert.rejects(f.client.submit(f.owner.actor.id, f.environment.manifest.id, operation, { id: f.resource.id }),
    { code: 'id_in_use' });
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
  const task = await f.client.submit(f.owner.actor.id, f.environment.manifest.id, operation);
  await f.executor.tick();
  const policy = await f.client.policy(f.owner.actor.id, ContentTypes.value, [], { id: task.id });
  await assert.rejects(f.client.save('Another item', encode('another-value'), policy), { code: 'id_in_use' });
  assert.equal((await f.client.result(await f.client.api.json('/api/runtime/runs/' + task.id, {}, Task)))?.result?.stdout,
    'unique-result\n');
});
