import { z } from 'zod';
import { Id, Name } from './contracts.js';
import { Signature, SignedBinding } from './authority.js';
import { DelegatedRun, ProtectedContent } from './custody.js';
import { ExecutionReceipt, SignedEnvironment, Task } from './execution.js';

export const BoundRecipient = SignedBinding.extend({ name: Name });
export const PublishBinding = SignedBinding.extend({ previousSignature: Signature.optional() }).strict();
export const ProtectedWrite = z.object({ name: Name, content: ProtectedContent,
  version: z.number().int().positive().optional() }).strict();
export const ProtectedRead = z.object({ content: ProtectedContent, version: z.number().int().positive() }).strict();
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
export { DelegatedRun, ExecutionReceipt, ProtectedContent, SignedEnvironment, Task };
