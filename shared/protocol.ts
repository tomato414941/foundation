import { z } from 'zod';
import { Id, Name, Sealed, Time } from './contracts.js';
import { Fingerprint, SignedBinding } from './authority.js';
import { AccessPolicy, ProtectedContent } from './custody.js';
import { EarlierContent } from './custody-legacy.js';
import { ConnectionLabels } from './connections.js';

export const BoundRecipient = SignedBinding.extend({ name: Name });
export const TransferRecipients = z.object({ required: z.array(BoundRecipient), delegates: z.array(BoundRecipient) }).strict();
export const ResourceTransfer = z.object({ to: Id, version: z.number().int().positive(),
  content: ProtectedContent.optional() }).strict();
// Labels are what people read about an item. They are stored as given and carry no authority.
export const ProtectedWrite = z.object({ name: Name, content: ProtectedContent, labels: ConnectionLabels.optional(),
  version: z.number().int().positive().optional() }).strict();
export const ProtectedRead = z.object({ content: ProtectedContent, version: z.number().int().positive() }).strict();
// An item as stored: one still sealed under the earlier policy is read only to be sealed again.
export const StoredRead = z.object({ content: z.union([ProtectedContent, EarlierContent]), version: z.number().int().positive() }).strict();
// An item to seal again, why, and the principals no longer to seal it for.
export const Reprotection = z.object({ id: Id, reason: z.enum(['recipients', 'format']),
  remove: z.array(Id).max(1000).default([]) }).strict();
export const KeyUpdates = z.record(Id, z.object({ version: z.number().int().positive(), content: ProtectedContent }).strict());
export const KeySharingItem = z.object({ id: Id, name: Name, version: z.number().int().positive(),
  content: ProtectedContent, policy: AccessPolicy }).strict();
export const RenewalOperation = z.object({
  id: Id, resource_id: Id, renewer_id: Id, expected_revision: z.number().int().positive(),
  state: z.enum(['prepared', 'in_flight', 'committed', 'uncertain', 'aborted']),
  fence: z.string().regex(/^\d+$/), result: ProtectedContent.nullable(),
});
export const PrepareRenewal = z.object({ id: Id, resourceId: Id, expectedRevision: z.number().int().positive() }).strict();
export const Fence = z.object({ fence: z.string().regex(/^\d+$/) }).strict();
export const RenewalResult = Fence.extend({ content: ProtectedContent }).strict();
export const RegisterRelay = z.object({ id: Id, executionId: Id, index: z.number().int().nonnegative(), stateDigest: Fingerprint, expiresAt: Time }).strict();
export const OAuthRelay = z.object({ id: Id, executionId: Id, context: z.string(),
  sealed: Sealed.nullable(), expiresAt: Time, receivedAt: Time.nullable() }).strict();
export const relayContext = (origin: string, id: string) => 'oauth-callback:' + origin + ':' + id;
export { ProtectedContent };
