import { z } from 'zod';
import { ConnectionRequest, Id, Name, Sealed, Time } from './contracts.js';
import { Fingerprint, KeyBinding, Signature, SignedBinding } from './authority.js';
import { AccessPolicy, DelegatedRun, ProtectedContent } from './custody.js';
import { ExecutionReceipt, SignedEnvironment, Task } from './execution.js';
import { ConnectionLabels } from './connections.js';

export const BoundRecipient = SignedBinding.extend({ name: Name });
export const ConnectionPlan = z.object({ id: Id, index: z.number().int().min(0).max(7),
  input: ConnectionRequest.extend({ ownerId: Id }) }).strict();
export const EnvironmentEnrollment = z.object({ bootstrap: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  binding: SignedBinding, token: z.string().regex(/^fk_[A-Za-z0-9_-]{43}$/) }).strict();
export const EnvironmentBootstrap = z.object({ id: Id, executorId: Id, ownerId: Id, name: Name,
  origin: z.url(), bootstrap: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  commandImage: z.string().regex(/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/),
  callers: z.array(KeyBinding).min(1).max(100) }).strict();
export const PublishBinding = SignedBinding.extend({ previousSignature: Signature.optional() }).strict();
// Labels are what people read about an item. They are stored as given and carry no authority.
export const ProtectedWrite = z.object({ name: Name, content: ProtectedContent, labels: ConnectionLabels.optional(),
  version: z.number().int().positive().optional() }).strict();
export const ProtectedRead = z.object({ content: ProtectedContent, version: z.number().int().positive() }).strict();
export const Reprotection = z.object({ id: Id, reason: z.enum(['grantExpired']) }).strict();
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
export const RegisterRelay = z.object({ id: Id, runId: Id, stateDigest: Fingerprint, expiresAt: Time }).strict();
export const OAuthRelay = z.object({ id: Id, runId: Id, context: z.string(),
  sealed: Sealed.nullable(), expiresAt: Time, receivedAt: Time.nullable() }).strict();
export const relayContext = (origin: string, id: string) => 'oauth-callback:' + origin + ':' + id;
export { DelegatedRun, ExecutionReceipt, ProtectedContent, SignedEnvironment, Task };
