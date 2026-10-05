import {
  CompactEncrypt,
  GeneralEncrypt,
  compactDecrypt,
  generalDecrypt,
  generateKeyPair,
  importJWK,
  exportJWK,
} from 'jose';
import type { JWK } from 'jose';
import { PublicKey, Sealed } from './contracts.js';
import type { PublicEncryptionKey, SealedContent } from './contracts.js';
import { openLegacy, unwrapLegacy } from './legacy-encryption.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const agreement = 'ECDH-ES+A256KW';
const encryption = 'A256GCM';
export const encode = (value: string) => encoder.encode(value);
export const decode = (value: Uint8Array) => decoder.decode(value);
export function base64url(bytes: Uint8Array): string {
  let text = '';
  for (let offset = 0; offset < bytes.length; offset += 8192)
    text += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function unbase64url(text: string): Uint8Array {
  return Uint8Array.from(atob(text.replaceAll('-', '+').replaceAll('_', '/')), (character) =>
    character.charCodeAt(0),
  );
}
export async function newEncryptionKey(): Promise<{ publicKey: PublicEncryptionKey; privateKey: JWK }> {
  const pair = await generateKeyPair(agreement, { crv: 'P-256', extractable: true });
  return {
    publicKey: PublicKey.parse(await exportJWK(pair.publicKey)),
    privateKey: await exportJWK(pair.privateKey),
  };
}
export async function seal(
  bytes: Uint8Array,
  recipients: Array<{ id: string; publicKey: PublicEncryptionKey }>,
  context: string,
): Promise<SealedContent> {
  if (!recipients.length || new Set(recipients.map((value) => value.id)).size !== recipients.length)
    throw new Error('Recipients must be distinct and nonempty.');
  const envelope = new GeneralEncrypt(bytes)
    .setProtectedHeader({ enc: encryption })
    .setAdditionalAuthenticatedData(encode(context));
  for (const recipient of recipients)
    envelope
      .addRecipient(await importJWK(recipient.publicKey, agreement))
      .setUnprotectedHeader({ alg: agreement, kid: recipient.id });
  return Sealed.parse(await envelope.encrypt());
}
export async function open(
  sealed: SealedContent,
  privateKey: JWK | CryptoKey,
  id: string,
  context: string,
): Promise<Uint8Array> {
  if (sealed.aad !== base64url(encode(context)))
    throw new Error('The encrypted content belongs to a different item.');
  const recipient = sealed.recipients.find((value) => value.header.kid === id);
  if (!recipient) throw new Error('This principal cannot decrypt the content.');
  if ('format' in sealed) return openLegacy(sealed, privateKey, id);
  const key = privateKey instanceof CryptoKey ? privateKey : await importJWK(privateKey, agreement);
  const result = await generalDecrypt({ ...sealed, recipients: [recipient] }, key, {
    keyManagementAlgorithms: [agreement],
    contentEncryptionAlgorithms: [encryption],
  });
  return result.plaintext;
}
export async function hold(privateKey: JWK): Promise<CryptoKey> {
  const key = await importJWK(privateKey, agreement, { extractable: false });
  if (!(key instanceof CryptoKey)) throw new Error('An asymmetric private key is required.');
  return key;
}
async function wrappingKey(prf: Uint8Array): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', new Uint8Array(prf), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: encode('Foundation'), info: encode('passkey encryption key') },
      base,
      256,
    ),
  );
}
export async function wrap(privateKey: JWK, prf: Uint8Array, principalId: string): Promise<string> {
  return new CompactEncrypt(encode(JSON.stringify(privateKey)))
    .setProtectedHeader({ alg: 'dir', enc: encryption, sub: principalId })
    .encrypt(await wrappingKey(prf));
}
export async function unwrap(value: string, prf: Uint8Array, principalId: string, publicKey?: PublicEncryptionKey | null): Promise<JWK> {
  if (value.startsWith('x25519:')) return unwrapLegacy(value.slice(7), prf, publicKey);
  const result = await compactDecrypt(value, await wrappingKey(prf), {
    keyManagementAlgorithms: ['dir'],
    contentEncryptionAlgorithms: [encryption],
  });
  if (result.protectedHeader.sub !== principalId)
    throw new Error('The key belongs to a different principal.');
  return JSON.parse(decode(result.plaintext)) as JWK;
}
