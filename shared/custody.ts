import { z } from 'zod';
import type { JWK } from 'jose';
import { JsonObject, Sealed, Time } from './contracts.js';
import type { JsonValue, PublicEncryptionKey } from './contracts.js';
import { base64, open, seal, thumbprint } from './encryption.js';
import type { ProtectedKindName } from './protected.js';
import type { DeviceKeys } from './client.js';

export const contentLimit = 1_000_000;
// An item a key protects, as Foundation keeps it: its value sealed for everyone who may open it, each by the public key
// it has, and what anyone who sees the item reads of it. Each new value is the next revision.
const sealedItemFields = {
  revision: z.number().int().positive(),
  updatedAt: Time,
  metadata: JsonObject,
  sealed: Sealed,
};
export const SealedItem = z.object(sealedItemFields).strict();
export type SealedItemValue = z.infer<typeof SealedItem>;
// A sealed item as a device reads it: fields Foundation adds later are left out, so that adding one stops no device.
export const SealedItemRead = z.object(sealedItemFields);
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
// A line of a principal's export as the holder keeps it: an item's sealed value is opened and put in its place as
// content, as a stored file's is, so that the file holds what was kept without Foundation. A value not sealed for this
// device's key stays in the line as it was sealed, and its id is returned.
const ExportedItem = z.object({ resource: z.object({ id: z.string() }), custody: SealedItemRead });
export async function openExportLine(line: string, keys: DeviceKeys): Promise<{ line: string; sealed?: string }> {
  const entry = JSON.parse(line) as Record<string, unknown>;
  if (entry.type !== 'resource' || entry.custody === undefined) return { line };
  const { resource, custody } = ExportedItem.parse(entry);
  if (!(await sealedFor(custody, keys.publicKey))) return { line, sealed: resource.id };
  const { custody: _custody, ...opened } = entry;
  return { line: JSON.stringify({ ...opened, content: base64(await openItem(custody, keys.privateKey, keys.publicKey)) }) };
}
