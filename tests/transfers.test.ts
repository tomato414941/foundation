import test from 'node:test';
import assert from 'node:assert/strict';
import { flowFixture } from './flow-support.js';
import { CustodyClient, transferResource } from '../shared/client.js';
import { openItem, sealItem } from '../shared/custody.js';
import { decode, encode, newIdentityKeys, publicPart } from '../shared/encryption.js';
import { OperationView, RequestView } from '../shared/operations.js';
import { Recipient, Resource, listOf } from '../shared/contracts.js';
import type { Database } from '../server/database.js';

const transfer = (client: CustodyClient, id: string, to: string) => transferResource(client.api, id, to, () => client);
// Gives the principal a new key, as a key reset does once its waiting period has passed.
async function resetKeys(db: Database, principalId: string) {
  const keys = await newIdentityKeys(), publicKey = publicPart(keys.encryption);
  await db.pool.query('UPDATE principals SET public_key=$2 WHERE id=$1', [principalId, JSON.stringify(publicKey)]);
  return { publicKey, privateKey: keys.encryption };
}

test('鍵で守られた項目を渡すAPIは、今の内容と受け取り先で開ける人と、手元で包んで送る手順を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const path = '/api/resources/' + f.resource.id + '/transfer';
  const response = await f.app.inject({ method: 'POST', url: path,
    headers: { authorization: 'Bearer ' + f.owner.token }, payload: { to: f.stranger.actor.id, version: f.resource.version } });
  assert.equal(response.statusCode, 409, response.body);
  const { error } = response.json();
  assert.equal(error.code, 'rekey_required');
  assert.deepEqual(error.details.submit, { method: 'POST', path, fields: ['to', 'version', 'content'] });
  const current = await f.api(f.owner.token).json(error.details.content.path);
  assert.deepEqual(current, await f.custody.read(f.owner.actor, f.resource.id));
  const recipients = await f.api(f.owner.token).json(error.details.recipients.path, {}, listOf(Recipient));
  assert.deepEqual(recipients.items, [{ id: f.stranger.actor.id, name: 'Other', publicKey: f.stranger.keys.publicKey }]);
});

test('受け取り先が鍵を作り直したあとは、新しい鍵向けに包んで渡す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const renewed = await resetKeys(f.db, f.stranger.actor.id);
  const asked = RequestView.parse(await transfer(f.client, f.resource.id, f.stranger.actor.id));
  await f.api(f.stranger.token).json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} });
  const received = await f.custody.read(f.stranger.actor, f.resource.id);
  assert.equal(decode(await openItem(received.content, renewed.privateKey, renewed.publicKey)), 'confidential-value');
});

test('変数と接続とアプリを受け取り先で開ける人向けに包み直し、受け取り側の承認後に所有者を移す', async t => {
  const f = await flowFixture(); t.after(f.close);
  await f.relations.draw(f.stranger.actor, { subjectId: f.delegate.actor.id, relation: 'delegate', objectId: f.stranger.actor.id });
  const connection = await f.saveConnection({ methodId: 'tailscale:api-access-token', name: 'Network connection',
    fields: { token: 'tskey-api-transfer-test' } });
  const app = await f.saveApp('github:oauth');
  for (const resource of [f.resource, connection, app]) {
    const previous = await f.client.read(resource.id), bytes = await f.client.reveal(resource.id);
    const asked = RequestView.parse(await transfer(f.client, resource.id, f.stranger.actor.id));
    assert.equal(asked.state, 'pending'); assert.equal(asked.proposal?.kind, 'transfer');
    assert.equal((await f.resources.get(resource.id)).owner_id, f.owner.actor.id);
    assert.deepEqual(await f.custody.read(f.owner.actor, resource.id), previous);
    await assert.rejects(f.custody.read(f.stranger.actor, resource.id), { code: 'forbidden' });
    const approval = await f.api(f.stranger.token).json<{ state: string }>(
      '/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} });
    assert.equal(approval.state, 'approved');
    const transferred = await f.custody.read(f.stranger.actor, resource.id);
    assert.equal((await f.resources.get(resource.id)).owner_id, f.stranger.actor.id);
    assert.deepEqual(await openItem(transferred.content, f.stranger.keys.privateKey, f.stranger.keys.publicKey), bytes);
    assert.deepEqual(transferred.content.metadata, previous.content.metadata);
    await assert.rejects(f.custody.read(f.owner.actor, resource.id), { code: 'forbidden' });
    assert.deepEqual(await openItem((await f.custody.read(f.delegate.actor, resource.id)).content,
      f.delegate.keys.privateKey, f.delegate.keys.publicKey), bytes);
  }
});

// The request stays approved, and its transfer stops short, for its requester to look at.
async function failedTransfer(f: Awaited<ReturnType<typeof flowFixture>>, id: string, code: string) {
  const approved = await f.api(f.stranger.token).json('/api/requests/' + id + '/approve', { method: 'POST', body: {} }, RequestView);
  assert.equal(approved.state, 'approved');
  const made = await f.client.api.json('/api/operations/' + approved.performed[0]!.id, {}, OperationView);
  assert.equal(made.state, 'failed'); assert.equal(made.error?.code, code);
}

test('受け取り承認までに項目が更新されたら譲渡を行わず、現在の持ち主と新しい値を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = RequestView.parse(await transfer(f.client, f.resource.id, f.stranger.actor.id));
  const previous = await f.client.read(f.resource.id);
  await f.client.save({ id: f.resource.id, ownerId: f.owner.actor.id, kind: 'variable' }, f.resource.name,
    encode('updated while awaiting acceptance'), { previous });
  await failedTransfer(f, asked.id, 'changed');
  assert.equal((await f.resources.get(f.resource.id)).owner_id, f.owner.actor.id);
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'updated while awaiting acceptance');
});

test('渡す内容が受け取り先で開ける人向けに包まれていて、版を指定していることを確かめる', async t => {
  const f = await flowFixture(); t.after(f.close);
  const previous = await f.client.read(f.resource.id);
  const resealed = await sealItem(encode('confidential-value'), [f.owner.keys], previous.content.revision + 1, previous.content.metadata);
  await assert.rejects(f.api(f.owner.token).json('/api/resources/' + f.resource.id + '/transfer', { method: 'POST',
    body: { to: f.stranger.actor.id, version: previous.version, content: resealed } }), { code: 'recipients_changed' });
  await assert.rejects(f.api(f.owner.token).json('/api/resources/' + f.resource.id + '/transfer', { method: 'POST',
    body: { to: f.stranger.actor.id, content: previous.content } }), { code: 'invalid_input' });
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

test('暗号化していない項目は秘密鍵を開かずに譲渡を依頼し承認後の項目を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const file = await f.resources.insert(f.owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  const asked = RequestView.parse(await transferResource(f.api(f.owner.token), file.id, f.stranger.actor.id,
    () => { throw new Error('This device has no private keys.'); }));
  assert.equal(asked.state, 'pending');
  assert.equal((await f.resources.get(file.id)).owner_id, f.owner.actor.id);
  const approved = await f.api(f.stranger.token).json('/api/requests/' + asked.id + '/approve', { method: 'POST', body: {} }, RequestView);
  const completed = await f.api(f.stranger.token).json('/api/operations/' + approved.performed[0]!.id, {}, OperationView);
  const received = Resource.parse(completed.result);
  assert.equal(received.id, file.id);
  assert.equal(received.ownerId, f.stranger.actor.id);
  assert.equal(received.version, file.version + 1);
  assert.deepEqual(received.data, file.data);
});

test('受け取る権限をすでに持つ相手への譲渡は暗号化の有無によらず更新後の項目を返す', async t => {
  const f = await flowFixture(); t.after(f.close);
  const recipient = await f.principals.create('Owned recipient', null, f.owner.actor.id);
  const file = await f.resources.insert(f.owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  for (const item of [f.resource, file]) {
    const received = Resource.parse(await transfer(f.client, item.id, recipient.id));
    assert.equal(received.id, item.id);
    assert.equal(received.ownerId, recipient.id);
    assert.equal(received.version, item.version + 1);
  }
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

test('暗号化していない項目も現在の版を指定して渡し古い版の依頼では現在の値を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const file = await f.resources.insert(f.owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  const path = '/api/resources/' + file.id + '/transfer';
  await assert.rejects(f.api(f.owner.token).json(path, { method: 'POST', body: { to: f.stranger.actor.id } }),
    { code: 'invalid_input' });
  const changed = await f.resources.rename(f.owner.actor, file, 'revised.txt');
  await assert.rejects(f.api(f.owner.token).json(path, { method: 'POST', body: { to: f.stranger.actor.id, version: file.version } }),
    { code: 'changed' });
  assert.equal((await f.resources.get(file.id)).name, changed.name);
  assert.equal((await f.resources.get(file.id)).owner_id, f.owner.actor.id);
});

test('暗号化していない項目を承認待ちの間に更新したら譲渡を行わず、更新後の値を現在の所有者に保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const file = await f.resources.insert(f.owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
  const asked = RequestView.parse(await transfer(f.client, file.id, f.stranger.actor.id));
  const changed = await f.resources.rename(f.owner.actor, file, 'revised.txt');
  await failedTransfer(f, asked.id, 'changed');
  const current = await f.resources.get(file.id);
  assert.equal(current.owner_id, f.owner.actor.id);
  assert.equal(current.name, changed.name);
  assert.equal(current.version, changed.version);
});

test('内容を保存すると現在の所有者を保ち値を更新する', async t => {
  const f = await flowFixture(); t.after(f.close);
  const previous = await f.client.read(f.resource.id);
  const content = await sealItem(encode('confidential-value'), [f.stranger.keys], previous.content.revision + 1, previous.content.metadata);
  await assert.rejects(f.api(f.owner.token).json('/api/resources/' + f.resource.id + '/custody', { method: 'PUT', body: {
    id: f.resource.id, name: f.resource.name, kind: 'variable', ownerId: f.stranger.actor.id, version: previous.version, content } }),
    { code: 'transfer_required' });
  await f.client.save({ id: f.resource.id, ownerId: f.owner.actor.id, kind: 'variable' }, f.resource.name,
    encode('updated by its owner'), { previous });
  assert.equal((await f.resources.get(f.resource.id)).owner_id, f.owner.actor.id);
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'updated by its owner');
});

test('承認待ちの間に受け取り先の公開鍵が変わったら譲渡を行わず、現在の所有者が引き続き内容を読めるようにする', async t => {
  const f = await flowFixture(); t.after(f.close);
  const asked = RequestView.parse(await transfer(f.client, f.resource.id, f.stranger.actor.id));
  await resetKeys(f.db, f.stranger.actor.id);
  await failedTransfer(f, asked.id, 'recipients_changed');
  assert.equal((await f.resources.get(f.resource.id)).owner_id, f.owner.actor.id);
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

test('譲渡を依頼したキーが承認前に取り消されたら現在の所有者と内容を保つ', async t => {
  const f = await flowFixture(); t.after(f.close);
  const credential = await f.authentication.issueKey(f.owner.actor.id, 'Transfer device');
  const client = new CustodyClient(f.api(credential.token), f.config.origin, f.owner.actor.id, f.owner.keys);
  const asked = RequestView.parse(await transfer(client, f.resource.id, f.stranger.actor.id));
  await f.authentication.removeCredential(f.owner.actor, f.owner.actor.id, credential.credential.id);
  const approval = await f.app.inject({ method: 'POST', url: '/api/requests/' + asked.id + '/approve',
    headers: { authorization: 'Bearer ' + f.stranger.token }, payload: {} });
  assert.equal(approval.statusCode, 401, approval.body);
  assert.equal((await f.client.api.json('/api/requests/' + asked.id, {}, RequestView)).state, 'pending');
  assert.equal((await f.resources.get(f.resource.id)).owner_id, f.owner.actor.id);
  assert.equal(decode(await f.client.reveal(f.resource.id)), 'confidential-value');
});

for (const kind of ['variable', 'object'] as const) for (const action of ['decline', 'withdraw'] as const)
  test(kind + 'の譲渡の依頼を' + (action === 'decline' ? '断る' : '取り下げる') + 'と現在の所有者と内容を保つ', async t => {
    const f = await flowFixture(); t.after(f.close);
    const item = kind === 'variable' ? f.resource
      : await f.resources.insert(f.owner.actor.id, 'object', 'report.txt', { size: 0, contentType: 'text/plain' });
    const asked = RequestView.parse(await transfer(f.client, item.id, f.stranger.actor.id));
    const stopped = await f.api(action === 'decline' ? f.stranger.token : f.owner.token).json(
      '/api/requests/' + asked.id + '/' + action, { method: 'POST', body: {} }, RequestView);
    assert.equal(stopped.state, action === 'decline' ? 'declined' : 'withdrawn');
    await assert.rejects(f.api(f.stranger.token).json('/api/requests/' + asked.id + '/approve',
      { method: 'POST', body: {} }), { code: 'request_answered' });
    const current = await f.resources.get(item.id);
    assert.equal(current.owner_id, f.owner.actor.id);
    assert.equal(current.version, item.version);
    if (kind === 'variable') assert.equal(decode(await f.client.reveal(item.id)), 'confidential-value');
    else assert.deepEqual(current.data, item.data);
  });
