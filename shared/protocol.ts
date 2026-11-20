import { z } from 'zod';
import { Id, Name, Recipient, Sealed, Time } from './contracts.js';
import { Digest } from './digest.js';
import { SealedItem } from './custody.js';
import { ConnectionLabels } from './connections.js';
import { ProtectedKinds } from './protected.js';

const Version = z.number().int().positive();
export const ResourceTransfer = z.object({ to: Id, version: Version, content: SealedItem.optional() }).strict();
// Labels are what people read about an item. They are stored as given and carry no authority.
export const ProtectedWrite = z.object({ id: Id, name: Name, kind: z.enum(ProtectedKinds), ownerId: Id, content: SealedItem,
  labels: ConnectionLabels.optional(), version: Version.optional() }).strict();
export const ProtectedRead = z.object({ kind: z.enum(ProtectedKinds), content: SealedItem, version: Version }).strict();
// An item someone may open that is not sealed for them yet, which this principal can open and seal again.
export const Reprotection = z.object({ id: Id }).strict();
export const KeyUpdates = z.record(Id, z.object({ version: Version, content: SealedItem }).strict());
// An item to seal again, before a change is made, for whoever may open it once it is made.
export const KeySharingItem = z.object({ id: Id, name: Name, version: Version, recipients: z.array(Recipient) }).strict();
export const RenewalOperation = z.object({
  id: Id, resource_id: Id, renewer_id: Id, expected_revision: z.number().int().positive(),
  state: z.enum(['prepared', 'in_flight', 'committed', 'uncertain', 'aborted']),
  fence: z.string().regex(/^\d+$/), result: SealedItem.nullable(),
});
export const PrepareRenewal = z.object({ id: Id, resourceId: Id, expectedRevision: z.number().int().positive() }).strict();
export const Fence = z.object({ fence: z.string().regex(/^\d+$/) }).strict();
export const RenewalResult = Fence.extend({ content: SealedItem }).strict();
export const RegisterRelay = z.object({ id: Id, operationId: Id, stateDigest: Digest, expiresAt: Time }).strict();
export const OAuthRelay = z.object({ id: Id, operationId: Id, context: z.string(),
  sealed: Sealed.nullable(), expiresAt: Time, receivedAt: Time.nullable() }).strict();
export const relayContext = (origin: string, id: string) => 'oauth-callback:' + origin + ':' + id;
export { SealedItem };
