import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { MemoryJournal } from './delegation-support.js';
import { CustodyClient, IdentityVerificationRequired } from '../shared/client.js';
import type { RecipientAccess } from '../shared/client.js';
import { bindKeys, fingerprint, hash, newIdentityKeys, sign, signBinding, verifyBinding } from '../shared/authority.js';
import { reveal } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { Execution } from '../shared/executions.js';
import { TransferRecipients } from '../shared/protocol.js';
import { JournalTrust } from '../runtime/trust.js';

test('暗号化した項目を渡すAPIは公開鍵の取得と手元での再暗号化と送信の手順を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const path = '/api/resources/' + f.resource.id + '/transfer';
  const response = await f.app.inject({ method: 'POST', url: path,
    headers: { authorization: 'Bearer ' + f.owner.token }, payload: { to: f.stranger.actor.id } });
  assert.equal(response.statusCode, 409, response.body);
  const { error } = response.json();
  assert.equal(error.code, 'rekey_required');
  assert.match(error.message, new RegExp('foundation transfer ' + f.resource.id + ' --to ' + f.stranger.actor.id));
  assert.deepEqual(error.details.submit, { method: 'POST', path, fields: ['to', 'version', 'content'] });
  const current = await f.api(f.owner.token).json(error.details.content.path);
  assert.deepEqual(current, await f.custody.read(f.owner.actor, f.resource.id));
  const recipients = await f.api(f.owner.token).json(error.details.recipients.path, {}, TransferRecipients);
  assert.deepEqual(recipients.required.map(item => item.binding), [f.stranger.binding]);
  for (const { name: _name, ...binding } of recipients.required) await verifyBinding(binding);
});

test('未検証の相手へ渡すときは検証するプリンシパルを知らせて持ち主と内容を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  await assert.rejects(f.client.transfer(f.resource.id, f.stranger.actor.id), error => {
    assert.ok(error instanceof IdentityVerificationRequired);
    assert.deepEqual(error.recipient, { id: f.stranger.actor.id, name: 'Other', code: 'identity_untrusted' });
    return true;
  });
  assert.equal((await f.resources.get(f.resource.id)).owner_id, f.owner.actor.id);
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

test('受け取り先の鍵が変わったら検証へ案内し新しい鍵を検証すると渡せるようにする', async t => {
  const f = await flowFixture(); t.after(f.close);
  await f.client.trustIdentity(f.stranger.actor.id, await fingerprint(f.stranger.binding));
  const keys = await newIdentityKeys(), binding = { ...bindKeys(f.stranger.actor.id, keys),
    generation: f.stranger.binding.generation + 1, previous: await hash(f.stranger.binding) };
  await f.bindings.publish(f.stranger.actor, await signBinding(binding, keys),
    await sign(binding, f.stranger.keys.signing, 'key-replacement'));
  await assert.rejects(f.client.transfer(f.resource.id, f.stranger.actor.id), error => {
    assert.ok(error instanceof IdentityVerificationRequired);
    assert.deepEqual(error.recipient, { id: f.stranger.actor.id, name: 'Other', code: 'identity_changed' });
    return true;
  });
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
  await f.client.trustIdentity(f.stranger.actor.id, await fingerprint(binding));
  const execution = Execution.parse(await f.client.transfer(f.resource.id, f.stranger.actor.id));
  await f.api(f.stranger.token).json('/api/requests/' + execution.requests[0] + '/approve', { method: 'POST', body: {} });
  const received = await f.custody.read(f.stranger.actor, f.resource.id);
  assert.equal(decode(await reveal(received.content, binding, keys.encryption)), 'confidential-value');
});

test('変数と接続を一回の操作で暗号化し直し受け取り側の承認後に所有者と利用権限を移す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const unknown = await f.person('Unverified delegate'), notices: RecipientAccess[] = [];
  await f.relations.draw(f.stranger.actor, { subjectId: f.executorIdentity.actor.id, relation: 'delegate', objectId: f.stranger.actor.id });
  await f.relations.draw(f.stranger.actor, { subjectId: unknown.actor.id, relation: 'delegate', objectId: f.stranger.actor.id });
  const client = new CustodyClient(f.api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys,
    new JournalTrust(new MemoryJournal()), notice => notices.push(notice));
  await client.trustIdentity(f.stranger.actor.id, await fingerprint(f.stranger.binding));
  await client.trustIdentity(f.executorIdentity.actor.id, await fingerprint(f.executorIdentity.binding));
  const connection = await f.saveConnection({ methodId: 'tailscale:api-access-token', name: 'Network connection',
    fields: { token: 'tskey-api-transfer-test' } });
  for (const resource of [f.resource, connection]) {
    const previous = await client.read(resource.id), bytes = await client.reveal(resource.id);
    const execution = Execution.parse(await client.transfer(resource.id, f.stranger.actor.id));
    assert.equal(execution.wait, 'approval');
    assert.equal((await f.resources.get(resource.id)).owner_id, f.owner.actor.id);
    assert.deepEqual(await f.custody.read(f.owner.actor, resource.id), { content: previous.content, version: previous.version });
    await assert.rejects(f.custody.read(f.stranger.actor, resource.id), { code: 'forbidden' });
    assert.deepEqual(notices.at(-1), { id: execution.id, name: resource.name, operation: 'transfer', excluded: [
      { id: unknown.actor.id, name: 'Unverified delegate', code: 'identity_untrusted' }] });
    const approval = await f.api(f.stranger.token).json<{ state: string }>(
      '/api/requests/' + execution.requests[0] + '/approve', { method: 'POST', body: {} });
    assert.equal(approval.state, 'accepted');
    const transferred = await f.custody.read(f.stranger.actor, resource.id);
    assert.equal((await f.resources.get(resource.id)).owner_id, f.stranger.actor.id);
    assert.deepEqual(await reveal(transferred.content, f.stranger.binding, f.stranger.keys.encryption), bytes);
    assert.deepEqual(transferred.content.metadata, previous.content.metadata);
    assert.deepEqual(transferred.content.policy.grants, []);
    assert.deepEqual(transferred.content.policy.authorities.map(binding => binding.principalId).sort(),
      [f.stranger.actor.id, f.executorIdentity.actor.id].sort());
    await assert.rejects(f.custody.read(f.owner.actor, resource.id), { code: 'forbidden' });
    assert.deepEqual(await reveal((await f.custody.read(f.executorIdentity.actor, resource.id)).content,
      f.executorIdentity.binding, f.executorIdentity.keys.encryption), bytes);
    await assert.rejects(f.custody.read(unknown.actor, resource.id), { code: 'forbidden' });
  }
  const receiver = new CustodyClient(f.api(f.stranger.token), f.config.origin, f.stranger.binding, f.stranger.keys,
    new JournalTrust(new MemoryJournal()));
  await receiver.trustIdentity(f.owner.actor.id, await fingerprint(f.owner.binding));
  await receiver.trustIdentity(f.executorIdentity.actor.id, await fingerprint(f.executorIdentity.binding));
  await receiver.trustIdentity(unknown.actor.id, await fingerprint(unknown.binding));
  const updated = await receiver.reprotectPending();
  assert.deepEqual(updated.failed, []);
  for (const resource of [f.resource, connection]) {
    assert.ok(updated.done.includes(resource.id));
    assert.deepEqual(await reveal((await f.custody.read(unknown.actor, resource.id)).content, unknown.binding, unknown.keys.encryption),
      await receiver.reveal(resource.id));
  }
});

test('受け取り承認までに項目が更新されたら現在の持ち主と新しい値を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  await f.client.trustIdentity(f.stranger.actor.id, await fingerprint(f.stranger.binding));
  const execution = Execution.parse(await f.client.transfer(f.resource.id, f.stranger.actor.id));
  const previous = await f.client.read(f.resource.id);
  await f.client.save(f.resource.name, encode('updated while awaiting acceptance'), previous.content.policy, { previous });
  await assert.rejects(f.api(f.stranger.token).json('/api/requests/' + execution.requests[0] + '/approve', { method: 'POST', body: {} }),
    { code: 'changed' });
  assert.equal((await f.resources.get(f.resource.id)).owner_id, f.owner.actor.id);
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'updated while awaiting acceptance');
});

test('署名済みの譲渡内容と指定した受け取り先が一致していることを確認する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const previous = await f.client.read(f.resource.id);
  await assert.rejects(f.api(f.owner.token).json('/api/resources/' + f.resource.id + '/transfer', { method: 'POST',
    body: { to: f.stranger.actor.id, version: previous.version, content: previous.content } }), { code: 'wrong_content' });
  await assert.rejects(f.api(f.owner.token).json('/api/resources/' + f.resource.id + '/transfer', { method: 'POST',
    body: { to: f.stranger.actor.id, content: previous.content } }), { code: 'invalid_input' });
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});
