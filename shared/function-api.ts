import { z } from 'zod';
import { FunctionDefinition, Id, Json, JsonObject, Name, Time } from './contracts.js';
import { KeyBinding, Signature, canonical, sign, validateBinding, verify } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import { ProtectedContent } from './custody.js';
import { OutputDestination, TaskState } from './runtime-protocol.js';

export const FunctionPublication = z.object({
  format: z.literal(1), functionId: Id, ownerId: Id, revision: z.number().int().positive(),
  definition: FunctionDefinition, author: KeyBinding, executor: KeyBinding, createdAt: Time,
  signature: Signature,
}).strict();
export type Publication = z.infer<typeof FunctionPublication>;
export async function publishFunction(value: Omit<Publication, 'signature'>, keys: KeyMaterial) {
  return FunctionPublication.parse({ ...value, signature: await sign(value, keys.signing, 'function-publication') });
}
export async function verifyFunction(input: Publication, executor?: BoundKeys) {
  const publication = FunctionPublication.parse(input), { signature, ...value } = publication;
  await validateBinding(value.author);
  await verify(value, signature, value.author.signing, 'function-publication');
  if (executor && canonical(value.executor) !== canonical(executor))
    throw new Error('This function is approved for another executor.');
  return publication;
}
export const FunctionWrite = z.object({ functionId: Id, publication: FunctionPublication,
  contents: z.record(Id, z.object({ version: z.number().int().positive(), content: ProtectedContent }).strict()),
}).strict();
export const CreateFunction = z.object({ name: Name, definition: FunctionDefinition, authorization: FunctionWrite }).strict();
export const UpdateFunction = CreateFunction.extend({ version: z.number().int().positive() });

export const InvocationInput = z.object({ id: Id.optional(), ownerId: Id.optional(), arguments: JsonObject.default({}),
  outputs: z.record(z.string().max(500), OutputDestination).default({}),
}).strict();
export const InvocationError = z.object({ code: z.string().max(100), message: z.string().max(1000) }).strict();
export const Invocation = z.object({
  id: Id, functionId: Id, functionVersion: z.number().int().positive(), ownerId: Id, actorId: Id,
  state: TaskState, result: Json.nullable(), error: InvocationError.nullable(),
  createdAt: Time, startedAt: Time.nullable(), finishedAt: Time.nullable(),
}).strict();
export type InvocationView = z.infer<typeof Invocation>;
export const InvocationRequest = z.object({
  id: Id, functionId: Id, functionVersion: z.number().int().positive(), ownerId: Id, actorId: Id,
  actor: KeyBinding.nullable(), arguments: JsonObject, outputs: InvocationInput.shape.outputs,
  definitionDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/), createdAt: Time, expiresAt: Time,
}).strict();
export const InvocationCompletion = z.object({
  id: Id, requestDigest: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  state: TaskState.exclude(['queued', 'running']), result: Json.nullable(), error: InvocationError.nullable(),
  finishedAt: Time, signature: Signature,
}).strict();
export type Completion = z.infer<typeof InvocationCompletion>;
export const ClaimedInvocation = z.object({ lease: Id, request: InvocationRequest,
  publication: FunctionPublication, sources: z.array(ProtectedContent).max(100),
}).strict().nullable();
