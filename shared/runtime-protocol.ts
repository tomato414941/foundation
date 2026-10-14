import { z } from 'zod';
import { Command, FunctionDefinition, HttpRequest, Id, Json, JsonObject, Name, Sealed, Time } from './contracts.js';
import { Fingerprint, KeyBinding, Signature, canonical, hash, sign, validateBinding, verify } from './authority.js';
import type { KeyMaterial } from './authority.js';
import { ContentTypes, Operation, Operations, Origin, PolicyApproval, ProtectedContent, RunIntent, contentContext,
  continuesPolicy, produceContent, runContext, verifyContent, verifyPolicyApproval } from './custody.js';
import type { ApprovedPolicy, ExecutionIntent } from './custody.js';
import { base64url, encode, open, seal } from './encryption.js';

export const FUNCTION_RUNTIME_VERSION = 5;
export const HTTP_RUNTIME_VERSION = 1;

export const AwsPrincipal = z.string().regex(/^arn:aws[a-z-]*:iam::\d{12}:(?:role|user)\/(?:[\x21-\x7e]{1,510}\/)?[\w+=,.@-]{1,64}$/);
export const EnvironmentManifest = z.object({
  format: z.literal(3), id: Id, origin: Origin, ownerId: Id,
  name: Name, executor: KeyBinding, operatorId: Id,
  driver: z.enum(['attached', 'managed']),
  capabilities: z.array(Operation).min(1).max(6),
  functionVersion: z.number().int().positive().optional(),
  httpVersion: z.number().int().positive().optional(),
  resultVersion: z.literal(1).optional(),
  isolation: z.enum(['process', 'container']),
  commandImage: z.string().regex(/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/).optional(),
  functionImage: z.string().regex(/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/).optional(),
  // The IAM role or user this executor runs as, when it has one: what an account owner's role must trust.
  awsPrincipal: AwsPrincipal.optional(),
  revision: z.number().int().positive(),
}).strict();
export type ExecutorManifest = z.infer<typeof EnvironmentManifest>;
export const SignedEnvironment = z.object({ manifest: EnvironmentManifest, signature: Signature }).strict();
export type RegisteredEnvironment = z.infer<typeof SignedEnvironment>;

export async function signEnvironment(manifest: ExecutorManifest, keys: KeyMaterial) {
  const normalized = EnvironmentManifest.parse(manifest);
  const result = { manifest: normalized,
    signature: await sign(normalized, keys.signing, 'environment') };
  await verifyEnvironment(result);
  return result;
}

export async function verifyEnvironment(input: RegisteredEnvironment) {
  const environment = SignedEnvironment.parse(input), { manifest } = environment;
  await validateBinding(manifest.executor);
  if (new Set(manifest.capabilities).size !== manifest.capabilities.length)
    throw new Error('Choose distinct execution capabilities.');
  if (manifest.capabilities.includes(Operations.command) && manifest.isolation === 'container' && !manifest.commandImage)
    throw new Error('Choose the container image used for commands.');
  await verify(manifest, environment.signature, manifest.executor.signing, 'environment');
  return environment;
}

export async function authorizeEnvironment(environment: RegisteredEnvironment, intent: ExecutionIntent) {
  const { manifest } = await verifyEnvironment(environment);
  if (intent.environmentId !== manifest.id || intent.origin !== manifest.origin ||
    intent.environmentDigest !== await hash(manifest) ||
    canonical(intent.executor) !== canonical(manifest.executor) ||
    !manifest.capabilities.includes(intent.operation) || (intent.operation === Operations.function && manifest.functionVersion !== FUNCTION_RUNTIME_VERSION))
    throw new Error('This environment does not authorize the requested execution.');
}

export const TaskState = z.enum(['queued', 'running', 'succeeded', 'failed', 'cancelled', 'uncertain']);
export const TaskResult = z.object({
  ok: z.boolean(), result: Json.nullable(),
  error: z.object({ code: z.string().max(100), message: z.string().max(1000) }).nullable(),
}).strict();
export type ExecutionResult = z.infer<typeof TaskResult>;
const receiptFields = {
  id: Id, intentDigest: Fingerprint, executorId: Id,
  state: z.enum(['succeeded', 'failed', 'cancelled', 'uncertain']),
  finishedAt: Time,
};
export const LegacyReceipt = z.object({ ...receiptFields, sealed: Sealed, signature: Signature }).strict();
export const SharedReceipt = z.object({ ...receiptFields, format: z.literal(2), accessDigest: Fingerprint,
  proofDigest: Fingerprint,
  approval: PolicyApproval, content: ProtectedContent, previousDigest: Fingerprint.optional(),
  previous: LegacyReceipt.optional(), signature: Signature }).strict();
export const ExecutionReceipt = z.union([LegacyReceipt, SharedReceipt]);
export type SignedReceipt = z.infer<typeof ExecutionReceipt>;
export type SharedResultReceipt = z.infer<typeof SharedReceipt>;
const ResultPayload = z.object({ result: TaskResult, proof: Signature }).strict();

export const receiptHeader = (receipt: SharedResultReceipt) => {
  const { signature: _signature, content: _content, approval: _approval, previous: _previous, ...header } = receipt;
  return header;
};

export async function makeSharedReceipt(intent: ExecutionIntent, state: SignedReceipt['state'], body: ExecutionResult,
  keys: KeyMaterial, approval: ApprovedPolicy, previous?: z.infer<typeof LegacyReceipt>): Promise<SharedResultReceipt> {
  await verifyPolicyApproval(approval);
  const header = { format: 2 as const, id: intent.id, intentDigest: await hash(intent), executorId: intent.executor.id,
    state, finishedAt: previous?.finishedAt ?? new Date().toISOString(), accessDigest: await hash(approval),
    ...(previous ? { previousDigest: await hash(previous) } : {}) };
  const proof = await sign({ ...header, resultDigest: await hash(body) }, keys.signing, 'execution-result');
  const bytes = encode(canonical({ result: TaskResult.parse(body), proof }));
  if (bytes.byteLength > 1_400_000) throw new ResultTooLarge();
  const content = await produceContent(bytes, approval, intent.id, intent.executor, keys, { bytes: bytes.byteLength });
  const signedHeader = { ...header, proofDigest: await hash(proof) };
  const receipt = SharedReceipt.parse({ ...signedHeader, approval, content, ...(previous ? { previous } : {}),
    signature: await sign(signedHeader, keys.signing, 'receipt') });
  await verifyReceipt(receipt, intent);
  return receipt;
}

export class ResultTooLarge extends Error {
  constructor() { super('The encoded execution result exceeds 1,400,000 bytes.'); }
}

export async function makeReceipt(
  intent: ExecutionIntent, state: SignedReceipt['state'], result: ExecutionResult, keys: KeyMaterial,
): Promise<SignedReceipt> {
  const body = TaskResult.parse(result);
  if ((state === 'succeeded') !== body.ok) throw new Error('The result must match its completion state.');
  if (intent.resultApproval) return makeSharedReceipt(intent, state, body, keys, intent.resultApproval);
  const bytes = encode(canonical(body));
  if (bytes.byteLength > 1_400_000) throw new ResultTooLarge();
  const sealed = await seal(bytes, intent.resultRecipients.map(binding => ({
    id: binding.id, publicKey: binding.encryption,
  })), await runContext(intent, 'result'));
  const value = { id: intent.id, intentDigest: await hash(intent), executorId: intent.executor.id,
    state, finishedAt: new Date().toISOString(), sealed };
  return ExecutionReceipt.parse({ ...value, signature: await sign(value, keys.signing, 'receipt') });
}

export async function verifyReceipt(input: SignedReceipt, intent: ExecutionIntent) {
  const receipt = ExecutionReceipt.parse(input);
  if ('content' in receipt) {
    await verify(receiptHeader(receipt), receipt.signature, intent.executor.signing, 'receipt');
    const approval = await verifyPolicyApproval(receipt.approval), policy = approval.policy;
    if (receipt.id !== intent.id || receipt.intentDigest !== await hash(intent) || receipt.executorId !== intent.executor.id ||
      receipt.accessDigest !== await hash(approval) || approval.authorityId !== intent.actor.id ||
      !policy.authorities.some(authority => canonical(authority) === canonical(intent.actor)) ||
      policy.id !== intent.id || policy.origin !== intent.origin || policy.ownerId !== intent.ownerId ||
      policy.contentType !== ContentTypes.executionResult || policy.grants.length ||
      (intent.resultApproval && canonical(intent.resultApproval) !== canonical(approval)))
      throw new Error('The result does not belong to the requested execution.');
    if (!intent.resultApproval || receipt.previous) {
      if (!receipt.previous || receipt.previousDigest !== await hash(receipt.previous))
        throw new Error('Keep the original execution receipt when sharing a legacy result.');
      await verifyReceipt(receipt.previous, intent);
      if (receipt.state !== receipt.previous.state || receipt.finishedAt !== receipt.previous.finishedAt)
        throw new Error('Keep the original execution outcome when sharing its result.');
    } else if (receipt.previousDigest) throw new Error('Provide the original receipt for its signed digest.');
    await verifyContent(receipt.content);
    if (!continuesPolicy(policy, receipt.content) || receipt.content.policy.revision < policy.revision ||
      receipt.content.policy.grants.length)
      throw new Error('An existing authority must approve sharing this result.');
    return receipt;
  }
  if (intent.resultApproval) throw new Error('Return the protected result approved by this execution.');
  const { signature, ...value } = receipt;
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
  receipt: SignedReceipt, intent: ExecutionIntent, bindingId: string, keys: KeyMaterial,
) {
  await verifyReceipt(receipt, intent);
  if ('content' in receipt) {
    if (!receipt.content.policy.readers.some(reader => reader.id === bindingId))
      throw new Error('This principal cannot decrypt the result.');
    const bytes = await open(receipt.content.sealed, keys.encryption, bindingId,
      await contentContext(receipt.content.policy, receipt.content.materialRevision));
    const payload = ResultPayload.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
    if (await hash(payload.proof) !== receipt.proofDigest) throw new Error('The result proof does not belong to this receipt.');
    const { proofDigest: _proofDigest, ...evidence } = receiptHeader(receipt);
    await verify({ ...evidence, resultDigest: await hash(payload.result) }, payload.proof,
      intent.executor.signing, 'execution-result');
    if ((receipt.state === 'succeeded') !== payload.result.ok)
      throw new Error('The result does not match its completion state.');
    return payload.result;
  }
  const bytes = await open(receipt.sealed, keys.encryption, bindingId, await runContext(intent, 'result'));
  const result = TaskResult.parse(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
  if ((receipt.state === 'succeeded') !== result.ok)
    throw new Error('The encrypted result does not match its completion state.');
  return result;
}

// What a run does, as the API and people name it. Signed intents carry the operation's id instead.
export const RunKind = z.enum(['http', 'command', 'function', 'connect', 'refresh', 'revoke']);
export type RunKindName = z.infer<typeof RunKind>;
export const Task = z.object({
  id: Id, ownerId: Id, actorId: Id, environmentId: Id, kind: RunKind,
  state: TaskState, intent: RunIntent, requestSignature: Signature,
  receipt: ExecutionReceipt.nullable(),
  error: z.string().nullable(), createdAt: Time, startedAt: Time.nullable(), finishedAt: Time.nullable(),
}).strict();
export type TaskView = z.infer<typeof Task>;

export const OutputDestination = z.object({ name: Name, approval: PolicyApproval }).strict();
export const FunctionOperation = z.object({ kind: z.literal('function'), functionId: Id, definition: FunctionDefinition,
  arguments: JsonObject.default({}), outputs: z.record(z.string(), OutputDestination).default({}) }).strict();
export const RuntimeOperation = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('http'), request: HttpRequest,
    save: z.record(z.string(), OutputDestination).default({}) }).strict(),
  z.object({ kind: z.literal('command'), ...Command.shape }).strict(),
  z.object({ kind: z.enum(['connect', 'refresh', 'revoke']), input: Json }).strict(),
]);
export type ExecutionOperation = z.infer<typeof RuntimeOperation>;
export type FunctionExecution = z.infer<typeof FunctionOperation>;
export type ExecutableOperation = ExecutionOperation | FunctionExecution;
