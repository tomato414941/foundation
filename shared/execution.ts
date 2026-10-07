import { z } from 'zod';
import { Command, FunctionDefinition, HttpRequest, Id, Json, Name, Sealed, Time } from './contracts.js';
import { Fingerprint, KeyBinding, Signature, canonical, hash, sign, validateBinding, verify } from './authority.js';
import type { IdentityKeys } from './authority.js';
import { ExecutionKind, Origin, PolicyApproval, RunIntent, runContext } from './custody.js';
import type { ExecutionIntent } from './custody.js';
import { base64url, encode, open, seal } from './encryption.js';

export const EnvironmentManifest = z.object({
  format: z.literal(1), id: Id, origin: Origin, ownerId: Id,
  name: Name, executor: KeyBinding, operatorId: Id,
  driver: z.enum(['attached', 'managed']),
  capabilities: z.array(ExecutionKind).min(1).max(6),
  callers: z.array(KeyBinding).min(1).max(100),
  isolation: z.enum(['process', 'container']),
  commandImage: z.string().regex(/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/).optional(),
  revision: z.number().int().positive(),
}).strict();
export type ExecutorManifest = z.infer<typeof EnvironmentManifest>;
export const SignedEnvironment = z.object({ manifest: EnvironmentManifest, signature: Signature }).strict();
export type RegisteredEnvironment = z.infer<typeof SignedEnvironment>;

export async function signEnvironment(manifest: ExecutorManifest, keys: IdentityKeys) {
  const normalized = EnvironmentManifest.parse(manifest);
  const result = { manifest: normalized,
    signature: await sign(normalized, keys.signing, 'environment') };
  await verifyEnvironment(result);
  return result;
}

export async function verifyEnvironment(input: RegisteredEnvironment) {
  const environment = SignedEnvironment.parse(input), { manifest } = environment;
  await validateBinding(manifest.executor);
  for (const caller of manifest.callers) await validateBinding(caller);
  if (new Set(manifest.callers.map(binding => binding.id)).size !== manifest.callers.length ||
    new Set(manifest.capabilities).size !== manifest.capabilities.length)
    throw new Error('Choose distinct callers and execution capabilities.');
  if (manifest.capabilities.includes('command') && manifest.isolation === 'container' && !manifest.commandImage)
    throw new Error('Choose the container image used for commands.');
  if (manifest.driver === 'managed' && manifest.capabilities.includes('command') && manifest.isolation !== 'container')
    throw new Error('Managed commands require container isolation.');
  await verify(manifest, environment.signature, manifest.executor.signing, 'environment');
  return environment;
}

export async function authorizeEnvironment(environment: RegisteredEnvironment, intent: ExecutionIntent) {
  const { manifest } = await verifyEnvironment(environment);
  if (intent.environmentId !== manifest.id || intent.origin !== manifest.origin ||
    intent.environmentDigest !== await hash(manifest) ||
    canonical(intent.executor) !== canonical(manifest.executor) ||
    !manifest.callers.some(caller => canonical(caller) === canonical(intent.actor)) ||
    !manifest.capabilities.includes(intent.operation))
    throw new Error('This environment does not authorize the requested execution.');
}

export const TaskState = z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled', 'uncertain']);
export const TaskResult = z.object({
  ok: z.boolean(), result: Json.nullable(),
  error: z.object({ code: z.string().max(100), message: z.string().max(1000) }).nullable(),
}).strict();
export type ExecutionResult = z.infer<typeof TaskResult>;
export const ExecutionReceipt = z.object({
  id: Id, intentDigest: Fingerprint, executorId: Id,
  state: z.enum(['succeeded', 'failed', 'cancelled', 'uncertain']),
  finishedAt: Time, sealed: Sealed, signature: Signature,
}).strict();
export type SignedReceipt = z.infer<typeof ExecutionReceipt>;

export async function makeReceipt(
  intent: ExecutionIntent, state: SignedReceipt['state'], result: ExecutionResult, keys: IdentityKeys,
): Promise<SignedReceipt> {
  const body = TaskResult.parse(result);
  if ((state === 'succeeded') !== body.ok) throw new Error('The result must match its completion state.');
  const sealed = await seal(encode(canonical(body)), intent.resultRecipients.map(binding => ({
    id: binding.id, publicKey: binding.encryption,
  })), await runContext(intent, 'result'));
  const value = { id: intent.id, intentDigest: await hash(intent), executorId: intent.executor.id,
    state, finishedAt: new Date().toISOString(), sealed };
  return { ...value, signature: await sign(value, keys.signing, 'receipt') };
}

export async function verifyReceipt(input: SignedReceipt, intent: ExecutionIntent) {
  const receipt = ExecutionReceipt.parse(input), { signature, ...value } = receipt;
  await verify(value, signature, intent.executor.signing, 'receipt');
  if (receipt.id !== intent.id || receipt.intentDigest !== await hash(intent) ||
    receipt.executorId !== intent.executor.id ||
    receipt.sealed.aad !== base64url(encode(await runContext(intent, 'result'))) ||
    canonical(receipt.sealed.recipients.map(recipient => recipient.header.kid).sort()) !==
      canonical(intent.resultRecipients.map(binding => binding.id).sort()))
    throw new Error('The result does not belong to the requested execution.');
  return receipt;
}

export async function readReceipt(
  receipt: SignedReceipt, intent: ExecutionIntent, bindingId: string, keys: IdentityKeys,
) {
  await verifyReceipt(receipt, intent);
  const bytes = await open(receipt.sealed, keys.encryption, bindingId, await runContext(intent, 'result'));
  const result = TaskResult.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  if ((receipt.state === 'succeeded') !== result.ok)
    throw new Error('The encrypted result does not match its completion state.');
  return result;
}

export const Task = z.object({
  id: Id, ownerId: Id, actorId: Id, environmentId: Id, kind: ExecutionKind,
  state: TaskState, intent: RunIntent,
  receipt: ExecutionReceipt.nullable(),
  error: z.string().nullable(), createdAt: Time, startedAt: Time.nullable(), finishedAt: Time.nullable(),
}).strict();
export type TaskView = z.infer<typeof Task>;

export const OutputDestination = z.object({ name: Name, approval: PolicyApproval }).strict();
export const RuntimeOperation = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('http'), request: HttpRequest,
    save: z.record(z.string(), OutputDestination).default({}) }).strict(),
  z.object({ kind: z.literal('command'), ...Command.shape }).strict(),
  z.object({ kind: z.literal('function'), definition: FunctionDefinition,
    arguments: z.record(z.string(), z.string()).default({}),
    outputs: z.record(z.string(), OutputDestination).default({}) }).strict(),
  z.object({ kind: z.enum(['connect', 'refresh', 'revoke']), input: Json }).strict(),
]);
export type ExecutionOperation = z.infer<typeof RuntimeOperation>;
