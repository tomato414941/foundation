import { importJWK } from 'jose';
import type { JWK } from 'jose';
import type { LegacySealedContent, PublicEncryptionKey } from './contracts.js';

const bytes = (value: string) => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
const base64 = (value: Uint8Array) => btoa(String.fromCharCode(...value)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
async function derive(value: Uint8Array, info: string) {
  const base = await crypto.subtle.importKey('raw', new Uint8Array(value), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode(info),
  }, base, 256));
}
async function decrypt(key: Uint8Array, value: Uint8Array, aad?: Uint8Array) {
  if (value.length < 28) throw new Error('The encrypted content is incomplete.');
  const cryptoKey = await crypto.subtle.importKey('raw', new Uint8Array(key), 'AES-GCM', false, ['decrypt']);
  const content = new Uint8Array(value.length - 12);
  content.set(value.subarray(28));
  content.set(value.subarray(12, 28), value.length - 28);
  return new Uint8Array(await crypto.subtle.decrypt({
    name: 'AES-GCM', iv: new Uint8Array(value.subarray(0, 12)), tagLength: 128,
    ...(aad ? { additionalData: new Uint8Array(aad) } : {}),
  }, cryptoKey, content));
}
export async function openLegacy(sealed: LegacySealedContent, privateKey: JWK | CryptoKey, id: string) {
  const recipient = sealed.recipients.find(item => item.header.kid === id);
  if (!recipient) throw new Error('This principal cannot decrypt the content.');
  const wrapped = bytes(recipient.encrypted_key);
  if (wrapped.length !== 92) throw new Error('The encrypted key is incomplete.');
  const key = privateKey instanceof CryptoKey ? privateKey : await importJWK(privateKey, 'ECDH-ES+A256KW');
  if (!(key instanceof CryptoKey) || key.algorithm.name !== 'X25519') throw new Error('An X25519 key is required.');
  const ephemeral = await crypto.subtle.importKey('raw', wrapped.subarray(0, 32), 'X25519', false, []);
  const agreement = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: ephemeral }, key, 256));
  const contentKey = await decrypt(await derive(agreement, 'foundation-envelope'), wrapped.subarray(32), bytes(recipient.header.publicKey.x));
  return decrypt(contentKey, bytes(sealed.ciphertext));
}
export async function unwrapLegacy(value: string, prf: Uint8Array, publicKey?: PublicEncryptionKey | null): Promise<JWK> {
  if (!publicKey || publicKey.kty !== 'OKP') throw new Error('An X25519 public key is required.');
  const packed = bytes(value);
  if (packed.length !== 60) throw new Error('The encrypted key is incomplete.');
  const privateBytes = await decrypt(await derive(prf, 'foundation-key'), packed);
  return { ...publicKey, d: base64(privateBytes) };
}
