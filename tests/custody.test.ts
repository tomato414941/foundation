import test from 'node:test';
import assert from 'node:assert/strict';
import { openItem, sealItem, sealedFor } from '../shared/custody.js';
import { decode, encode, newIdentityKeys, publicPart, thumbprint } from '../shared/encryption.js';

async function identity() {
  const keys = await newIdentityKeys();
  return { privateKey: keys.encryption, publicKey: publicPart(keys.encryption) };
}

test('包んだ相手それぞれの秘密鍵で開け、包んでいない相手の鍵では開けない', async () => {
  const [owner, reader, stranger] = await Promise.all([identity(), identity(), identity()]);
  const item = await sealItem(encode('sensitive-value'), [owner, reader], 1, { bytes: 15 });
  assert.equal(decode(await openItem(item, owner.privateKey, owner.publicKey)), 'sensitive-value');
  assert.equal(decode(await openItem(item, reader.privateKey, reader.publicKey)), 'sensitive-value');
  assert.equal(await sealedFor(item, stranger.publicKey), false);
  await assert.rejects(openItem(item, stranger.privateKey, stranger.publicKey));
});

test('包んだ相手を、それぞれの公開鍵の指紋で名指す', async () => {
  const [owner, reader] = await Promise.all([identity(), identity()]);
  const item = await sealItem(encode('value'), [owner, reader], 3, { bytes: 5 });
  assert.deepEqual(item.sealed.recipients.map(recipient => recipient.header.kid).sort(),
    (await Promise.all([owner, reader].map(person => thumbprint(person.publicKey)))).sort());
  assert.equal(item.revision, 3);
  assert.deepEqual(item.metadata, { bytes: 5 });
});

test('上限サイズの内容を100人へ包み、最初と最後の相手の鍵で開く', async () => {
  const recipients = await Promise.all(Array.from({ length: 100 }, () => identity()));
  const bytes = new Uint8Array(1_000_000).fill(171);
  const item = await sealItem(bytes, recipients, 1, { bytes: bytes.byteLength });
  assert.deepEqual(await openItem(item, recipients[0]!.privateKey, recipients[0]!.publicKey), bytes);
  assert.deepEqual(await openItem(item, recipients.at(-1)!.privateKey, recipients.at(-1)!.publicKey), bytes);
  await assert.rejects(sealItem(new Uint8Array(1_000_001), recipients.slice(0, 1), 1, {}));
});
