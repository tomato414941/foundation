import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { generalDecrypt, importJWK } from 'jose';
import { PublicKey, Sealed } from '../shared/contracts.js';
import { decode, hold, newEncryptionKey, open, seal, unbase64url, unwrap, wrap } from '../shared/encryption.js';

const sample = JSON.parse(await readFile(new URL('./fixtures/encryption.json', import.meta.url), 'utf8'));
const publicKey = PublicKey.parse(sample.publicKey);
const context = 'resource:' + sample.resourceId;

test('保存済みの暗号鍵とシークレットを復号し、共有相手の鍵で開けるように暗号化する', async () => {
  const privateKey = await unwrap(sample.wrappedKey, unbase64url(sample.prf), sample.principalId);
  assert.deepEqual(privateKey, sample.privateKey);
  const content = await open(Sealed.parse(sample.sealed), await hold(privateKey), sample.principalId, context);
  assert.equal(decode(content), sample.plaintext);
  const next = await newEncryptionKey();
  const sealed = await seal(content, [
    { id: sample.principalId, publicKey },
    { id: sample.resourceId, publicKey: next.publicKey },
  ], context);
  for (const [id, key] of [[sample.principalId, privateKey], [sample.resourceId, next.privateKey]] as const) {
    assert.equal(decode(await open(sealed, key, id, context)), sample.plaintext);
    const jwe = { ...sealed, recipients: sealed.recipients.filter(recipient => recipient.header.kid === id) };
    assert.equal(decode((await generalDecrypt(jwe, await importJWK(key, 'ECDH-ES+A256KW'))).plaintext), sample.plaintext);
  }
  const nextPrf = crypto.getRandomValues(new Uint8Array(32));
  const wrapped = await wrap(privateKey, nextPrf, sample.principalId);
  assert.deepEqual(await unwrap(wrapped, nextPrf, sample.principalId), privateKey);
});

test('改変された暗号文と異なる鍵による復号を拒否する', async () => {
  await assert.rejects(unwrap(sample.wrappedKey, new Uint8Array(32), sample.principalId));
  await assert.rejects(unwrap(sample.wrappedKey, unbase64url(sample.prf), sample.resourceId));
  const sealed = Sealed.parse(sample.sealed);
  await assert.rejects(open(sealed, sample.privateKey, sample.principalId, 'resource:other'));
  const damaged = unbase64url(sealed.ciphertext);
  damaged[12] = damaged[12]! ^ 1;
  await assert.rejects(open({ ...sealed, ciphertext: Buffer.from(damaged).toString('base64url') }, sample.privateKey, sample.principalId, context));
  const stranger = await newEncryptionKey();
  await assert.rejects(open(sealed, stranger.privateKey, sample.principalId, context));
});
