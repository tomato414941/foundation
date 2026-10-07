import { z } from 'zod';
import {
  CompactSign, calculateJwkThumbprint, compactVerify, exportJWK, generateKeyPair, importJWK,
} from 'jose';
import type { JWK } from 'jose';
import { Id, PublicKey } from './contracts.js';
import type { PublicEncryptionKey } from './contracts.js';
import { base64url, encode, newEncryptionKey } from './encryption.js';

export const Fingerprint = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const Signature = z.string().min(100).max(4_000_000);
export const PrivateKey = PublicKey.extend({ d: z.string().regex(/^[A-Za-z0-9_-]{43}$/) });
export const PrivateKeys = z.object({ encryption: PrivateKey, signing: PrivateKey }).strict();
export type IdentityKeys = z.infer<typeof PrivateKeys>;
export interface KeyMaterial { encryption: JWK | CryptoKey; signing: JWK | CryptoKey }
export const KeyBinding = z.object({
  id: Id,
  principalId: Id,
  generation: z.number().int().positive(),
  previous: Fingerprint.nullable(),
  encryption: PublicKey,
  signing: PublicKey,
}).strict();
export type BoundKeys = z.infer<typeof KeyBinding>;

export function canonical(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (typeof value === 'string' && !/[\uD800-\uDFFF]/u.test(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + Array.from(value, canonical).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => {
      if (/[\uD800-\uDFFF]/u.test(key)) throw new Error('Use Unicode property names.');
      return JSON.stringify(key) + ':' + canonical((value as Record<string, unknown>)[key]);
    }).join(',') + '}';
  }
  throw new Error('Use finite numbers, Unicode strings, arrays, and plain JSON objects.');
}

export async function fingerprint(key: PublicEncryptionKey | JWK): Promise<string> {
  return calculateJwkThumbprint(PublicKey.parse({ kty: key.kty, crv: key.crv, x: key.x, y: key.y }), 'sha256');
}

export async function hash(value: unknown): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', encode(canonical(value)))));
}

export async function newIdentityKeys(): Promise<IdentityKeys> {
  const [encryption, signing] = await Promise.all([
    newEncryptionKey(), generateKeyPair('ES256', { crv: 'P-256', extractable: true }),
  ]);
  const privateSigningKey = await exportJWK(signing.privateKey);
  return PrivateKeys.parse({ encryption: encryption.privateKey, signing: privateSigningKey });
}

export function publicPart(key: JWK): PublicEncryptionKey {
  return PublicKey.parse({ kty: key.kty, crv: key.crv, x: key.x, y: key.y });
}

export function bindKeys(principalId: string, keys: IdentityKeys): BoundKeys {
  return KeyBinding.parse({
    id: crypto.randomUUID(), principalId, generation: 1, previous: null,
    encryption: publicPart(keys.encryption), signing: publicPart(keys.signing),
  });
}

export async function sign(value: unknown, key: JWK | CryptoKey, purpose: string): Promise<string> {
  const privateKey = key instanceof CryptoKey ? key : await importJWK(key, 'ES256');
  return new CompactSign(encode(canonical(value)))
    .setProtectedHeader({ alg: 'ES256', typ: 'foundation.' + purpose + '+jws' })
    .sign(privateKey);
}

export async function verify(
  value: unknown, signature: string, key: PublicEncryptionKey, purpose: string,
): Promise<void> {
  if (canonical(await signedValue(signature, key, purpose)) !== canonical(value))
    throw new Error('The signature does not authorize this content.');
}

export async function signedValue(signature: string, key: PublicEncryptionKey, purpose: string): Promise<unknown> {
  const result = await compactVerify(signature, await importJWK(PublicKey.parse(key), 'ES256'), {
    algorithms: ['ES256'],
  });
  if (
    result.protectedHeader.typ !== 'foundation.' + purpose + '+jws' ||
    Object.keys(result.protectedHeader).some(field => !['alg', 'typ'].includes(field))
  ) throw new Error('The signature does not authorize this content.');
  const text = new TextDecoder('utf-8', { fatal: true }).decode(result.payload), value: unknown = JSON.parse(text);
  if (canonical(value) !== text) throw new Error('Sign canonical JSON content.');
  return value;
}

export const SignedBinding = z.object({ binding: KeyBinding, signature: Signature }).strict();

export async function signBinding(binding: BoundKeys, keys: IdentityKeys) {
  await validateBinding(binding);
  if (await fingerprint(keys.encryption) !== await fingerprint(binding.encryption) ||
    await fingerprint(keys.signing) !== await fingerprint(binding.signing))
    throw new Error('The private keys do not match this identity.');
  return { binding, signature: await sign(binding, keys.signing, 'key-binding') };
}

export async function validateBinding(input: BoundKeys): Promise<void> {
  const binding = KeyBinding.parse(input);
  if ((binding.generation === 1) !== (binding.previous === null))
    throw new Error('Link each replacement key to its preceding binding.');
  if (await fingerprint(binding.encryption) === await fingerprint(binding.signing))
    throw new Error('Use separate encryption and signing keys.');
  await importJWK(binding.encryption, 'ECDH-ES+A256KW');
  await importJWK(binding.signing, 'ES256');
}

export async function verifyBinding(input: z.infer<typeof SignedBinding>) {
  const { binding, signature } = SignedBinding.parse(input);
  await validateBinding(binding);
  await verify(binding, signature, binding.signing, 'key-binding');
  return binding;
}
