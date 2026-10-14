import { z } from 'zod';
import { Id, Time } from './contracts.js';
import { KeyBinding, Signature, sign, signedValue } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import { decode, unbase64url } from './encryption.js';

// The public keys an identity verified with their holders, as one list it signs, so that each of its devices uses
// what any of them verified. The revision only grows: a device remembers the last one it saw and refuses an older list.
export const KeyringEntry = z.object({ binding: KeyBinding, verifiedAt: Time }).strict();
export type KeyringEntryValue = z.infer<typeof KeyringEntry>;
export const Keyring = z.object({
  origin: z.url(),
  ownerId: Id,
  signerId: Id,
  revision: z.number().int().positive(),
  keys: z.array(KeyringEntry).max(1000),
}).strict();
export type KeyringValue = z.infer<typeof Keyring>;
// The signed list as the server keeps it, with the version a change is written over.
export const StoredKeyring = z.object({ version: z.number().int().positive(), signature: Signature }).strict();
export const KeyringState = z.object({ keyring: StoredKeyring.nullable() }).strict();
export const KeyringWrite = z.object({ version: z.number().int().positive().nullable(), signature: Signature }).strict();

export function signKeyring(keyring: KeyringValue, key: KeyMaterial['signing']) {
  return sign(Keyring.parse(keyring), key, 'keyring');
}
// The list a signature carries, read without checking it: only to learn who claims to have signed it.
export function keyringClaim(signature: string): KeyringValue {
  return Keyring.parse(JSON.parse(decode(unbase64url(signature.split('.')[1] ?? ''))));
}
export async function openKeyring(signature: string, signer: BoundKeys): Promise<KeyringValue> {
  const keyring = Keyring.parse(await signedValue(signature, signer.signing, 'keyring'));
  if (keyring.signerId !== signer.id) throw new Error('Another identity signed this keyring.');
  return keyring;
}
