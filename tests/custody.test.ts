import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bindKeys, canonical, newIdentityKeys, sign, signBinding, thumbprint, verify, verifyBinding,
} from '../shared/authority.js';
import { AccessPolicy, ContentTypes, protect, renewContent, reveal, verifyContent } from '../shared/custody.js';
import type { CustodyPolicy } from '../shared/custody.js';
import { decode, encode } from '../shared/encryption.js';
import { ClientFailure, CustodyClient } from '../shared/client.js';
import type { JsonApi } from '../shared/client.js';
import { JournalTrust } from '../runtime/trust.js';
import { MemoryJournal } from './delegation-support.js';

async function identity() {
  const keys = await newIdentityKeys();
  return { keys, binding: bindKeys(crypto.randomUUID(), keys) };
}
async function setup() {
  const [owner, reader, stranger] = await Promise.all([identity(), identity(), identity()]);
  const policy = AccessPolicy.parse({
    format: 3, origin: 'https://foundation.test', id: crypto.randomUUID(),
    ownerId: owner.binding.principalId, contentType: ContentTypes.value, revision: 1,
    authorities: [owner.binding], readers: [owner.binding, reader.binding],
  });
  return { owner, reader, stranger, policy };
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
  assert.notEqual(await thumbprint(keys.encryption), await thumbprint(keys.signing));
  const signed = await signBinding(binding, keys);
  assert.deepEqual(await verifyBinding(signed), binding);
  await assert.rejects(verifyBinding({ ...signed, binding: { ...binding, principalId: crypto.randomUUID() } }));
  await assert.rejects(signBinding({ ...binding, signing: binding.encryption }, keys));
  const other = await identity();
  await assert.rejects(signBinding(binding, other.keys));
});

test('所有者と読み手は内容を開き、読み手でない者は開けない', async () => {
  const { owner, reader, stranger, policy } = await setup();
  const content = await protect(encode('sensitive-value'), policy, 1, owner.binding, owner.keys);
  assert.equal(decode(await reveal(content, owner.binding, owner.keys.encryption)), 'sensitive-value');
  assert.equal(decode(await reveal(content, reader.binding, reader.keys.encryption)), 'sensitive-value');
  await assert.rejects(reveal(content, stranger.binding, stranger.keys.encryption));
  await assert.rejects(protect(encode('value'), policy, 2, reader.binding, reader.keys, undefined, content));
});

test('権限、内容、宛先、版を検証してから暗号化データを開く', async () => {
  const { owner, policy, stranger } = await setup();
  const content = await protect(encode('value'), policy, 1, owner.binding, owner.keys);
  await assert.rejects(verifyContent({ ...content, materialRevision: 2 }));
  await assert.rejects(verifyContent({ ...content, policy: { ...policy, readers: [stranger.binding] } }));
  await assert.rejects(verifyContent({ ...content, sealed: { ...content.sealed,
    ciphertext: content.sealed.ciphertext.slice(0, -1) + '!' } }));
  await assert.rejects(protect(encode('value'), policy, 1, stranger.binding, stranger.keys));
  const changedKeys = { ...owner.keys, signing: stranger.keys.signing };
  await assert.rejects(protect(encode('value'), policy, 1, owner.binding, changedKeys));
});

test('端末が前に確認したより古い内容を返されると、食い違いとして止める', async () => {
  const { owner, policy } = await setup();
  const first = await protect(encode('first'), policy, 1, owner.binding, owner.keys);
  const second = await protect(encode('second'), policy, 2, owner.binding, owner.keys, undefined, first);
  let served = second;
  const api: JsonApi = { async json(_path, _options, schema) { return schema!.parse({ content: served, version: 1 }); } };
  const client = new CustodyClient(api, policy.origin, owner.binding, owner.keys, new JournalTrust(new MemoryJournal()));
  assert.equal(decode(await client.reveal(policy.id)), 'second');
  served = first;
  await assert.rejects(client.reveal(policy.id), error => error instanceof ClientFailure && error.code === 'content_conflict');
});

test('変数、接続情報、OAuthアプリに同じ宛先指定と暗号化を適用し、型を差し替えた内容を拒否する', async () => {
  const { owner, policy } = await setup();
  for (const contentType of Object.values(ContentTypes)) {
    const value = contentType === ContentTypes.value ? 'value' : JSON.stringify({ accessToken: 'value', clientSecret: 'value' });
    const content = await protect(encode(value), { ...policy, contentType }, 1, owner.binding, owner.keys);
    assert.equal(decode(await reveal(content, owner.binding, owner.keys.encryption)), value);
    await assert.rejects(verifyContent({ ...content, policy: { ...content.policy,
      contentType: contentType === ContentTypes.value ? ContentTypes.tokenSet : ContentTypes.value } }));
  }
});

test('上限サイズの内容を100人へ暗号化し、所有者と共有相手の鍵で読み出す', async () => {
  const recipients = await Promise.all(Array.from({ length: 100 }, () => identity()));
  const owner = recipients[0]!, last = recipients.at(-1)!;
  const policy = AccessPolicy.parse({ format: 3, origin: 'https://foundation.test', id: crypto.randomUUID(),
    ownerId: owner.binding.principalId, contentType: ContentTypes.value, revision: 1,
    authorities: recipients.map(recipient => recipient.binding), readers: recipients.map(recipient => recipient.binding),
  });
  const bytes = new Uint8Array(1_000_000).fill(171);
  const content = await protect(bytes, policy, 1, owner.binding, owner.keys);
  assert.deepEqual(await reveal(content, owner.binding, owner.keys.encryption), bytes);
  assert.deepEqual(await reveal(content, last.binding, last.keys.encryption), bytes);
});

test('読み手が接続を更新し、所有者が署名した読み手と宛先を保ち、読み手でない者は更新できない', async () => {
  const { owner, reader, stranger, policy } = await setup();
  const connection: CustodyPolicy = { ...policy, contentType: ContentTypes.tokenSet };
  const content = await protect(encode('old-token'), connection, 1, owner.binding, owner.keys);
  const renewed = await renewContent(content, encode('new-token'), reader.binding, reader.keys);
  assert.equal(renewed.materialRevision, 2);
  assert.equal(renewed.authorization, content.authorization);
  assert.deepEqual(renewed.policy, content.policy);
  assert.equal(decode(await reveal(renewed, owner.binding, owner.keys.encryption)), 'new-token');
  await assert.rejects(renewContent(content, encode('value'), stranger.binding, stranger.keys));
  const variable = await protect(encode('value'), policy, 1, owner.binding, owner.keys);
  await assert.rejects(renewContent(variable, encode('changed'), reader.binding, reader.keys));
  const { signature: _signature, ...tampered } = { ...renewed, policy: { ...renewed.policy, readers: [...renewed.policy.readers, stranger.binding] } };
  await assert.rejects(verifyContent({ ...tampered, signature: await sign(tampered, reader.keys.signing, 'resource') }));
});
