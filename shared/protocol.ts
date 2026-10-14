import { z } from 'zod';
import { Id, Name, Sealed, Time } from './contracts.js';
import { Fingerprint, Signature, SignedBinding } from './authority.js';
import { AccessPolicy, DelegatedRun, ProtectedContent } from './custody.js';
import { ExecutionReceipt, SignedEnvironment, Task } from './runtime-protocol.js';
import { ConnectionLabels } from './connections.js';

export const BoundRecipient = SignedBinding.extend({ name: Name });
export const PublishBinding = SignedBinding.extend({ previousSignature: Signature.optional() }).strict();
// Labels are what people read about an item. They are stored as given and carry no authority.
export const ProtectedWrite = z.object({ name: Name, content: ProtectedContent, labels: ConnectionLabels.optional(),
  version: z.number().int().positive().optional() }).strict();
export const ProtectedRead = z.object({ content: ProtectedContent, version: z.number().int().positive() }).strict();
// An item to seal again, why, and the principals no longer to seal it for.
export const Reprotection = z.object({ id: Id, reason: z.enum(['grantExpired', 'recipients']),
  remove: z.array(Id).max(1000).default([]) }).strict();
export const KeyUpdates = z.record(Id, z.object({ version: z.number().int().positive(), content: ProtectedContent }).strict());
export const KeySharingItem = z.object({ id: Id, name: Name, version: z.number().int().positive(),
  content: ProtectedContent, policy: AccessPolicy }).strict();
export const Registration = z.object({ registration: SignedEnvironment, stoppedAt: z.iso.datetime().nullable(),
  heartbeatAt: z.iso.datetime().nullable() }).strict();
export const ClaimedExecution = z.object({ lease: Id, request: DelegatedRun,
  sources: z.array(ProtectedContent).max(100) }).strict().nullable();
export const Lease = z.object({ lease: Id }).strict();
export const Completion = Lease.extend({ receipt: ExecutionReceipt }).strict();
export const RenewalOperation = z.object({
  id: Id, resource_id: Id, executor_id: Id, expected_revision: z.number().int().positive(),
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
export { DelegatedRun, ExecutionReceipt, ProtectedContent, SignedEnvironment, Task };
