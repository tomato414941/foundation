import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bindKeys, canonical, fingerprint, hash, newIdentityKeys, sign, signBinding, verify, verifyBinding,
} from '../shared/authority.js';
import { AccessPolicy, ContentTypes, Operations, permittedOperations, authorizeUse, openRun, prepareRun, protect, renewContent, reveal, useContent, verifyContent, verifyRun } from '../shared/custody.js';
import type { CustodyPolicy, ExecutionIntent } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';

async function identity() {
  const keys = await newIdentityKeys();
  return { keys, binding: bindKeys(crypto.randomUUID(), keys) };
}
async function setup() {
  const [owner, executor, caller, stranger] = await Promise.all([
    identity(), identity(), identity(), identity(),
  ]);
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  const policy = AccessPolicy.parse({
    format: 2, origin: 'https://foundation.test', id: crypto.randomUUID(),
    ownerId: owner.binding.principalId, contentType: ContentTypes.value, revision: 1,
    authorities: [owner.binding], readers: [owner.binding],
    grants: [{ actor: caller.binding, executor: executor.binding, operations: [Operations.http],
      callerProgram: true, origins: ['https://service.example'], expiresAt }],
  });
  const operation = { kind: 'http', request: { method: 'GET', url: 'https://service.example/items' } };
  const intent: ExecutionIntent = {
    format: 2, id: crypto.randomUUID(), origin: policy.origin, ownerId: policy.ownerId,
    actor: caller.binding, environmentId: crypto.randomUUID(), executor: executor.binding,
    environmentDigest: await hash({ environment: 'test' }),
    operation: Operations.http, functionDigest: null, operationDigest: await hash(operation),
    sources: [{ id: policy.id, policyDigest: await hash(policy), materialRevision: 1 }],
    resultRecipients: [caller.binding], createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  };
  return { owner, executor, caller, stranger, policy, operation, intent };
}

test('JSONの順序によらず同じ内容に署名し、用途と署名者を確認する', async () => {
  const { keys, binding } = await identity();
  const value = { z: '日本語', a: [1e30, 4.50, 0.002, null, true] };
  assert.equal(canonical(value), '{"a":[1e+30,4.5,0.002,null,true],"z":"日本語"}');
  const signature = await sign(value, keys.signing, 'test');
  await verify({ a: value.a, z: value.z }, signature, binding.signing, 'test');
  await assert.rejects(verify(value, signature, binding.signing, 'another-purpose'));
  await assert.rejects(verify({ ...value, z: 'changed' }, signature, binding.signing, 'test'));
  const other = await identity();
  await assert.rejects(verify(value, signature, other.binding.signing, 'test'));
  for (const input of [undefined, NaN, Infinity, '\ud800', { invalid: undefined }, new Date(), Array(2)])
    assert.throws(() => canonical(input));
});

test('暗号化鍵と署名鍵を個別に生成し、公開する鍵の組を署名で確認する', async () => {
  const { keys, binding } = await identity();
  assert.notEqual(await fingerprint(keys.encryption), await fingerprint(keys.signing));
  const signed = await signBinding(binding, keys);
  assert.deepEqual(await verifyBinding(signed), binding);
  await assert.rejects(verifyBinding({ ...signed, binding: { ...binding, principalId: crypto.randomUUID() } }));
  await assert.rejects(signBinding({ ...binding, signing: binding.encryption }, keys));
  const other = await identity();
  await assert.rejects(signBinding(binding, other.keys));
});

test('所有者は内容を読み、許可された実行先は指定した依頼者の処理に秘密を使う', async () => {
  const { owner, executor, caller, stranger, policy, intent, operation } = await setup();
  const content = await protect(encode('sensitive-value'), policy, 1, owner.binding, owner.keys);
  assert.equal(decode(await reveal(content, owner.binding, owner.keys.encryption)), 'sensitive-value');
  await assert.rejects(reveal(content, caller.binding, caller.keys.encryption));
  await assert.rejects(reveal(content, executor.binding, executor.keys.encryption));
  await assert.rejects(reveal(content, stranger.binding, stranger.keys.encryption));
  const request = await prepareRun(intent, operation, caller.keys);
  const verified = await openRun(request, executor.binding, executor.keys);
  assert.deepEqual(verified.operation, operation);
  assert.equal(decode(await useContent(content, verified.intent, executor.keys, {
    destination: operation.request.url,
  })), 'sensitive-value');
});

test('権限、内容、宛先、版を検証してから暗号化データを開く', async () => {
  const { owner, policy, stranger } = await setup();
  const content = await protect(encode('secret'), policy, 1, owner.binding, owner.keys);
  await assert.rejects(verifyContent({ ...content, materialRevision: 2 }));
  await assert.rejects(verifyContent({ ...content, policy: { ...policy, readers: [stranger.binding] } }));
  await assert.rejects(verifyContent({ ...content, sealed: { ...content.sealed,
    ciphertext: content.sealed.ciphertext.slice(0, -1) + '!' } }));
  await assert.rejects(protect(encode('value'), policy, 1, stranger.binding, stranger.keys));
  const changedKeys = { ...owner.keys, signing: stranger.keys.signing };
  await assert.rejects(protect(encode('value'), policy, 1, owner.binding, changedKeys));
});

test('実行依頼を署名者、実行先、入力、結果の宛先、有効期限へ結び付ける', async () => {
  const { caller, executor, stranger, intent, operation } = await setup();
  const run = await prepareRun(intent, operation, caller.keys);
  await verifyRun(run);
  await assert.rejects(verifyRun({ ...run, intent: { ...intent, resultRecipients: [stranger.binding] } }));
  await assert.rejects(verifyRun({ ...run, intent: { ...intent, environmentId: crypto.randomUUID() } }));
  await assert.rejects(verifyRun({ ...run, intent: { ...intent, executor: stranger.binding } }));
  await assert.rejects(openRun(run, stranger.binding, stranger.keys));
  await assert.rejects(openRun(run, executor.binding, stranger.keys));
  await assert.rejects(prepareRun(intent, { ...operation, extra: true }, caller.keys));
  await assert.rejects(verifyRun(run, Date.parse(intent.expiresAt) + 1));
  const tooLong = { ...intent, expiresAt: new Date(Date.now() + 172_800_000).toISOString() };
  await assert.rejects(verifyRun(await prepareRun(tooLong, operation, caller.keys)));
});

test('大きな実行入力を暗号化して復元し、送信形式の上限を超える入力は準備時に知らせる', async () => {
  const { caller, executor, intent, operation } = await setup();
  const large = { ...operation, request: { ...operation.request, body: 'x'.repeat(1_000_000) } };
  const request = await prepareRun({ ...intent, operationDigest: await hash(large) }, large, caller.keys);
  assert.deepEqual((await openRun(request, executor.binding, executor.keys)).operation, large);
  const oversized = { ...large, request: { ...large.request, body: '\0'.repeat(300_000) } };
  await assert.rejects(prepareRun({ ...intent, operationDigest: await hash(oversized) }, oversized, caller.keys));
});

test('一つの委任に含まれる依頼者、実行先、操作、送信先の条件をすべて照合する', async () => {
  const { owner, policy, intent, stranger } = await setup();
  const grant = policy.grants[0]!;
  const split: CustodyPolicy = { ...policy, grants: [
    { ...grant, origins: ['https://first.example'], operations: [Operations.http] },
    { ...grant, origins: ['https://service.example'], operations: [Operations.command] },
  ] };
  const content = await protect(encode('value'), split, 1, owner.binding, owner.keys);
  const pinned = { ...intent, sources: [{ ...intent.sources[0]!, policyDigest: await hash(split) }] };
  await assert.rejects(authorizeUse(content, pinned, { destination: 'https://service.example/items' }));
  await authorizeUse(content, pinned, { destination: 'https://first.example/items' });
  await assert.rejects(authorizeUse(content, { ...pinned, actor: stranger.binding }, {
    destination: 'https://first.example/items',
  }));
  await assert.rejects(authorizeUse(content, pinned, { destination: 'https://first.example/items',
    now: Date.parse(grant.expiresAt) + 1 }));
});

test('指定した関数の内容を照合し、任意のプログラムを動かす委任は明示して受け付ける', async () => {
  const { owner, policy, intent } = await setup();
  const functionDigest = await hash({ url: 'https://service.example/me', method: 'GET' });
  const functions: CustodyPolicy = { ...policy, grants: [{ ...policy.grants[0]!, operations: [Operations.function],
    callerProgram: false, functionDigests: [functionDigest] }] };
  const content = await protect(encode('value'), functions, 1, owner.binding, owner.keys);
  const pinned: ExecutionIntent = { ...intent, operation: Operations.function, functionDigest,
    sources: [{ ...intent.sources[0]!, policyDigest: await hash(functions) }] };
  await authorizeUse(content, pinned, { destination: 'https://service.example/me' });
  await assert.rejects(authorizeUse(content, { ...pinned, functionDigest: await hash({ changed: true }) }, {
    destination: 'https://service.example/me',
  }));
  await assert.rejects(protect(encode('value'), { ...policy,
    grants: [{ ...policy.grants[0]!, callerProgram: false }] }, 1, owner.binding, owner.keys));
});

test('変数、接続情報、OAuthアプリに同じ宛先指定と暗号化を適用し、型を差し替えた内容を拒否する', async () => {
  const { owner, policy } = await setup();
  for (const contentType of Object.values(ContentTypes)) {
    const value = contentType === ContentTypes.value ? 'value' : JSON.stringify({ accessToken: 'value', clientSecret: 'value' });
    const operations = permittedOperations(contentType).filter(operation => operation !== Operations.function);
    const typed = { ...policy, contentType, grants: policy.grants.map(grant => ({ ...grant, operations })) };
    const content = await protect(encode(value), typed, 1, owner.binding, owner.keys);
    assert.equal(decode(await reveal(content, owner.binding, owner.keys.encryption)), value);
    await assert.rejects(verifyContent({ ...content, policy: { ...content.policy,
      contentType: contentType === ContentTypes.value ? ContentTypes.tokenSet : ContentTypes.value } }));
  }
});

test('内容の型が扱わない操作を許可するポリシーを拒否する', async () => {
  const { owner, policy } = await setup();
  await assert.rejects(protect(encode('value'), { ...policy, grants: policy.grants.map(grant =>
    ({ ...grant, operations: [...grant.operations, Operations.refresh] })) }, 1, owner.binding, owner.keys),
  /operations this kind of content supports/);
  await assert.rejects(protect(encode('value'), { ...policy, contentType: ContentTypes.clientCredential }, 1,
    owner.binding, owner.keys), /operations this kind of content supports/);
});

test('上限サイズの内容を100人へ暗号化し、所有者と共有相手の鍵で読み出す', async () => {
  const recipients = await Promise.all(Array.from({ length: 100 }, () => identity()));
  const owner = recipients[0]!, last = recipients.at(-1)!;
  const policy = AccessPolicy.parse({ format: 2, origin: 'https://foundation.test', id: crypto.randomUUID(),
    ownerId: owner.binding.principalId, contentType: ContentTypes.value, revision: 1,
    authorities: recipients.map(recipient => recipient.binding), readers: recipients.map(recipient => recipient.binding),
    grants: [],
  });
  const bytes = new Uint8Array(1_000_000).fill(171);
  const content = await protect(bytes, policy, 1, owner.binding, owner.keys);
  assert.deepEqual(await reveal(content, owner.binding, owner.keys.encryption), bytes);
  assert.deepEqual(await reveal(content, last.binding, last.keys.encryption), bytes);
});

test('許可した実行先が接続を更新し、所有者が署名した権限と宛先を保持する', async () => {
  const { owner, executor, stranger, policy } = await setup();
  const connection: CustodyPolicy = { ...policy, contentType: ContentTypes.tokenSet, grants: [
    { ...policy.grants[0]!, operations: [Operations.http, Operations.refresh] },
  ] };
  const content = await protect(encode('old-token'), connection, 1, owner.binding, owner.keys);
  const renewed = await renewContent(content, encode('new-token'), executor.binding, executor.keys);
  assert.equal(renewed.materialRevision, 2);
  assert.equal(renewed.authorization, content.authorization);
  assert.deepEqual(renewed.policy, content.policy);
  assert.equal(decode(await reveal(renewed, owner.binding, owner.keys.encryption)), 'new-token');
  await assert.rejects(renewContent(content, encode('value'), stranger.binding, stranger.keys));
  const { signature: _signature, ...tampered } = { ...renewed, policy: {
    ...renewed.policy, grants: [{ ...connection.grants[0]!, actor: stranger.binding }],
  } };
  await assert.rejects(verifyContent({ ...tampered, signature: await sign(tampered, executor.keys.signing, 'resource') }));
});
