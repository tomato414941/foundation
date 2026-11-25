import test from 'node:test';
import assert from 'node:assert/strict';
import { openExportLine, openItem, sealItem, sealedFor } from '../shared/custody.js';
import { decode, encode, newIdentityKeys, publicPart, thumbprint } from '../shared/encryption.js';
import { CustodyClient } from '../shared/client.js';
import type { JsonApi } from '../shared/client.js';

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

test('書き出しの行のうち、端末の鍵で開ける値を開いて中身に置き換え、開けない値は包んだまま残して名指す', async () => {
  const [owner, stranger] = await Promise.all([identity(), identity()]);
  const opened = await sealItem(encode('値-1'), [owner], 1, {}), kept = await sealItem(encode('other'), [stranger], 1, {});
  const header = JSON.stringify({ format: 'foundation', version: 5 }),
    relations = JSON.stringify({ type: 'relations', items: [] }),
    file = JSON.stringify({ type: 'resource', resource: { id: 'file', kind: 'object' }, content: 'AQI=' });
  assert.deepEqual(await Promise.all([header, relations, file].map(line => openExportLine(line, owner))),
    [header, relations, file].map(line => ({ line })));
  const variable = await openExportLine(JSON.stringify({ type: 'resource', resource: { id: 'variable', kind: 'variable' }, custody: opened }), owner);
  assert.deepEqual(JSON.parse(variable.line), { type: 'resource', resource: { id: 'variable', kind: 'variable' },
    content: Buffer.from('値-1').toString('base64') });
  assert.equal(variable.sealed, undefined);
  const sealedLine = JSON.stringify({ type: 'resource', resource: { id: 'connection', kind: 'connection' }, custody: kept });
  assert.deepEqual(await openExportLine(sealedLine, owner), { line: sealedLine, sealed: 'connection' });
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

test('本番が答えに項目を足しても、端末は使う項目だけを読んで項目を開く', async () => {
  const owner = await identity();
  const content = await sealItem(encode('value'), [owner], 1, { bytes: 5 });
  const api: JsonApi = { async json(_path, _options, schema) {
    const value = { kind: 'variable', version: 3, addedLater: true, content: { ...content, addedLater: { nested: 1 } } };
    return (schema ? schema.parse(value) : value) as never;
  } };
  const client = new CustodyClient(api, 'https://foundation.test', crypto.randomUUID(), owner);
  assert.equal(decode(await client.reveal(crypto.randomUUID())), 'value');
});
