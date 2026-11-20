import { z } from 'zod';
import type { JWK } from 'jose';
import { JsonObject, Sealed, Time } from './contracts.js';
import type { JsonValue, PublicEncryptionKey } from './contracts.js';
import { open, seal, thumbprint } from './encryption.js';
import type { ProtectedKindName } from './protected.js';

export const contentLimit = 1_000_000;
// An item a key protects, as Foundation keeps it: its value sealed for everyone who may open it, each by the public key
// it has, and what anyone who sees the item reads of it. Each new value is the next revision.
export const SealedItem = z.object({
  revision: z.number().int().positive(),
  updatedAt: Time,
  metadata: JsonObject,
  sealed: Sealed,
}).strict();
export type SealedItemValue = z.infer<typeof SealedItem>;
// A token set is renewed by whoever may open it: renewing changes no one who can open it.
export const renewable = (kind: ProtectedKindName) => kind === 'connection';

export async function sealItem(bytes: Uint8Array, recipients: Array<{ publicKey: PublicEncryptionKey }>, revision: number,
  metadata: Record<string, JsonValue>): Promise<SealedItemValue> {
  if (bytes.byteLength > contentLimit) throw new Error('The content exceeds its storage limit.');
  const sealed = await seal(bytes, await Promise.all(recipients.map(async recipient => ({
    id: await thumbprint(recipient.publicKey), publicKey: recipient.publicKey }))));
  return SealedItem.parse({ revision, updatedAt: new Date().toISOString(), metadata, sealed });
}
// Whether the item is sealed for this public key.
export async function sealedFor(item: SealedItemValue, publicKey: PublicEncryptionKey) {
  const id = await thumbprint(publicKey);
  return item.sealed.recipients.some(recipient => recipient.header.kid === id);
}
export async function openItem(item: SealedItemValue, privateKey: JWK | CryptoKey, publicKey: PublicEncryptionKey) {
  return open(item.sealed, privateKey, await thumbprint(publicKey));
}
