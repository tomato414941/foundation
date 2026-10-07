import { z } from 'zod';
import type { JWK } from 'jose';
import { Id, Sealed, Time } from './contracts.js';
import { base64url, encode, open, seal } from './encryption.js';
import {
  Fingerprint, KeyBinding, Signature, canonical, hash, sign, validateBinding, verify,
} from './authority.js';
import type { BoundKeys, IdentityKeys } from './authority.js';

export const Origin = z.url().refine(value => {
  const url = new URL(value);
  return url.origin === value && !url.username && !url.password &&
    (url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)));
}, 'Use an HTTPS origin, or HTTP on localhost.');
export const ProtectedKind = z.enum(['secret', 'connection', 'app']);
export const ExecutionKind = z.enum(['http', 'command', 'function', 'connect', 'refresh', 'revoke']);
export const ExecutionGrant = z.object({
  actor: KeyBinding,
  executor: KeyBinding,
  operations: z.array(ExecutionKind).min(1).max(6),
  functionDigests: z.array(Fingerprint).max(100).default([]),
  origins: z.array(Origin).max(100).default([]),
  callerProgram: z.boolean().default(false),
  expiresAt: Time,
}).strict();
export type UseGrant = z.infer<typeof ExecutionGrant>;
export const AccessPolicy = z.object({
  format: z.literal(1),
  origin: Origin,
  id: Id,
  ownerId: Id,
  kind: ProtectedKind,
  revision: z.number().int().positive(),
  authorities: z.array(KeyBinding).min(1).max(100),
  readers: z.array(KeyBinding).min(1).max(100),
  grants: z.array(ExecutionGrant).max(100),
}).strict();
export type CustodyPolicy = z.infer<typeof AccessPolicy>;
export const ProtectedContent = z.object({
  policy: AccessPolicy,
  authorityId: Id,
  authorization: Signature,
  materialRevision: z.number().int().positive(),
  updatedAt: Time,
  sealed: Sealed,
  signerId: Id,
  signature: Signature,
}).strict();
export type CustodyContent = z.infer<typeof ProtectedContent>;

export async function validatePolicy(input: CustodyPolicy) {
  const policy = AccessPolicy.parse(input);
  const bindings = [...policy.authorities, ...policy.readers,
    ...policy.grants.flatMap(grant => [grant.actor, grant.executor])];
  const known = new Map<string, string>();
  for (const binding of bindings) {
    await validateBinding(binding);
    const serialized = canonical(binding);
    if (known.has(binding.id) && known.get(binding.id) !== serialized)
      throw new Error('Each key binding must identify the same keys throughout a policy.');
    known.set(binding.id, serialized);
  }
  for (const group of [policy.readers, policy.authorities])
    if (new Set(group.map(binding => binding.id)).size !== group.length)
      throw new Error('Choose distinct key bindings.');
  for (const authority of policy.authorities)
    if (!policy.readers.some(reader => reader.id === authority.id))
      throw new Error('A policy authority must be able to open its content.');
  for (const grant of policy.grants) {
    if (grant.operations.some(operation => ['http', 'command'].includes(operation)) && !grant.callerProgram)
      throw new Error('Explicitly authorize caller-supplied programs before allowing arbitrary execution.');
    if (grant.operations.includes('function') && !grant.functionDigests.length && !grant.callerProgram)
      throw new Error('Choose the exact functions this grant authorizes.');
  }
  return policy;
}

export function policyRecipients(policy: CustodyPolicy): BoundKeys[] {
  return [...new Map([...policy.readers, ...policy.grants.map(grant => grant.executor)]
    .map(binding => [binding.id, binding])).values()];
}

export async function contentContext(policy: CustodyPolicy, materialRevision: number) {
  return canonical({
    purpose: 'resource', origin: policy.origin, id: policy.id, ownerId: policy.ownerId,
    kind: policy.kind, policyDigest: await hash(policy), materialRevision,
  });
}

export async function protect(
  bytes: Uint8Array, input: CustodyPolicy, materialRevision: number,
  signer: BoundKeys, keys: IdentityKeys,
): Promise<CustodyContent> {
  if (bytes.byteLength > 1_000_000) throw new Error('The content exceeds 1,000,000 bytes.');
  const policy = await validatePolicy(input);
  if (!policy.authorities.some(binding => canonical(binding) === canonical(signer)))
    throw new Error('Only a policy authority can replace its content.');
  const sealed = await seal(bytes, policyRecipients(policy).map(binding => ({
    id: binding.id, publicKey: binding.encryption,
  })), await contentContext(policy, materialRevision));
  const value = {
    policy, authorityId: signer.id, authorization: await sign(policy, keys.signing, 'access-policy'),
    materialRevision, updatedAt: new Date().toISOString(), sealed, signerId: signer.id,
  };
  const result = ProtectedContent.parse({ ...value, signature: await sign(value, keys.signing, 'resource') });
  await verifyContent(result);
  return result;
}

export async function verifyContent(input: CustodyContent) {
  const content = ProtectedContent.parse(input);
  const { signature, ...value } = content;
  await validatePolicy(content.policy);
  const authority = content.policy.authorities.find(binding => binding.id === content.authorityId);
  if (!authority) throw new Error('The policy must be signed by an authority.');
  await verify(content.policy, content.authorization, authority.signing, 'access-policy');
  const signer = content.policy.authorities.find(binding => binding.id === content.signerId) ??
    (content.policy.kind === 'connection' ? content.policy.grants.find(grant =>
      grant.executor.id === content.signerId && grant.operations.includes('refresh') &&
      Date.parse(grant.expiresAt) > Date.parse(content.updatedAt),
    )?.executor : undefined);
  if (!signer || Date.parse(content.updatedAt) > Date.now() + 30_000)
    throw new Error('The signer cannot replace this content.');
  await verify(value, signature, signer.signing, 'resource');
  const expected = policyRecipients(content.policy).map(binding => binding.id).sort();
  const addressed = content.sealed.recipients.map(recipient => recipient.header.kid).sort();
  if (canonical(expected) !== canonical(addressed) ||
    content.sealed.aad !== base64url(encode(await contentContext(content.policy, content.materialRevision))))
    throw new Error('Encrypt content for exactly the recipients authorized by its policy.');
  return content;
}

export async function renewContent(
  input: CustodyContent, bytes: Uint8Array, executor: BoundKeys, keys: IdentityKeys,
): Promise<CustodyContent> {
  const content = await verifyContent(input);
  if (content.policy.kind !== 'connection' || !content.policy.grants.some(grant =>
    canonical(grant.executor) === canonical(executor) && grant.operations.includes('refresh') &&
    Date.parse(grant.expiresAt) > Date.now(),
  )) throw new Error('This executor cannot renew this connection.');
  if (bytes.byteLength > 1_000_000) throw new Error('The content exceeds 1,000,000 bytes.');
  const materialRevision = content.materialRevision + 1;
  const sealed = await seal(bytes, policyRecipients(content.policy).map(binding => ({
    id: binding.id, publicKey: binding.encryption,
  })), await contentContext(content.policy, materialRevision));
  const { signature: _signature, ...previous } = content;
  const value = { ...previous, materialRevision, updatedAt: new Date().toISOString(), sealed, signerId: executor.id };
  const result = { ...value, signature: await sign(value, keys.signing, 'resource') };
  await verifyContent(result);
  return result;
}

export async function reveal(
  input: CustodyContent, binding: BoundKeys, privateKey: JWK | CryptoKey,
): Promise<Uint8Array> {
  const content = await verifyContent(input);
  if (!content.policy.readers.some(reader => canonical(reader) === canonical(binding)))
    throw new Error('This identity cannot reveal the content.');
  return open(content.sealed, privateKey, binding.id,
    await contentContext(content.policy, content.materialRevision));
}

export const SourcePin = z.object({
  id: Id, kind: ProtectedKind, policyDigest: Fingerprint,
  materialRevision: z.number().int().positive(),
}).strict();
export const RunIntent = z.object({
  format: z.literal(1), id: Id, origin: Origin, ownerId: Id,
  actor: KeyBinding, environmentId: Id, executor: KeyBinding,
  environmentDigest: Fingerprint,
  operation: ExecutionKind, functionDigest: Fingerprint.nullable(),
  operationDigest: Fingerprint,
  sources: z.array(SourcePin).max(100),
  resultRecipients: z.array(KeyBinding).min(1).max(100),
  createdAt: Time, expiresAt: Time,
}).strict();
export type ExecutionIntent = z.infer<typeof RunIntent>;
export const DelegatedRun = z.object({ intent: RunIntent, signature: Signature, sealed: Sealed }).strict();
export type SealedRun = z.infer<typeof DelegatedRun>;

export async function runContext(intent: ExecutionIntent, purpose: 'input' | 'result') {
  return canonical({ purpose: 'run-' + purpose, origin: intent.origin, id: intent.id,
    intentDigest: await hash(intent) });
}

export async function prepareRun(
  intent: ExecutionIntent, operation: unknown, keys: IdentityKeys,
): Promise<SealedRun> {
  RunIntent.parse(intent);
  if (await hash(operation) !== intent.operationDigest)
    throw new Error('The operation does not match the execution intent.');
  const value = {
    intent,
    sealed: await seal(encode(canonical(operation)), [
      { id: intent.executor.id, publicKey: intent.executor.encryption },
    ], await runContext(intent, 'input')),
  };
  return { ...value, signature: await sign(value, keys.signing, 'run') };
}

export async function verifyRun(input: SealedRun, now = Date.now()): Promise<SealedRun> {
  const run = DelegatedRun.parse(input);
  const { signature, ...value } = run;
  await verify(value, signature, run.intent.actor.signing, 'run');
  const { intent } = run;
  const created = Date.parse(intent.createdAt), expires = Date.parse(intent.expiresAt);
  if (created > now + 30_000 || expires <= now || expires <= created || expires - created > 86_400_000)
    throw new Error('Use an execution intent valid for at most 24 hours.');
  if (new Set(intent.sources.map(source => source.id)).size !== intent.sources.length ||
    new Set(intent.resultRecipients.map(binding => binding.id)).size !== intent.resultRecipients.length)
    throw new Error('Choose distinct inputs and result recipients.');
  if (run.sealed.recipients.length !== 1 || run.sealed.recipients[0]!.header.kid !== intent.executor.id ||
    run.sealed.aad !== base64url(encode(await runContext(intent, 'input'))))
    throw new Error('Encrypt this operation for its selected executor.');
  return run;
}

export async function openRun(input: SealedRun, executor: BoundKeys, keys: IdentityKeys) {
  const run = await verifyRun(input);
  if (canonical(run.intent.executor) !== canonical(executor))
    throw new Error('This operation belongs to another executor.');
  const bytes = await open(run.sealed, keys.encryption, executor.id, await runContext(run.intent, 'input'));
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const operation: unknown = JSON.parse(text);
  if (canonical(operation) !== text || await hash(operation) !== run.intent.operationDigest)
    throw new Error('The decrypted operation does not match its signed intent.');
  return { intent: run.intent, operation };
}

export async function authorizeUse(
  input: CustodyContent, intent: ExecutionIntent,
  options: { destination?: string; now?: number } = {},
) {
  const content = await verifyContent(input), policy = content.policy;
  const pin = intent.sources.find(source => source.id === policy.id);
  if (!pin || intent.origin !== policy.origin || pin.kind !== policy.kind ||
    pin.policyDigest !== await hash(policy) || pin.materialRevision !== content.materialRevision)
    throw new Error('The input changed after this execution was authorized.');
  const matching = policy.grants.filter(grant =>
    canonical(grant.actor) === canonical(intent.actor) &&
    canonical(grant.executor) === canonical(intent.executor) &&
    grant.operations.includes(intent.operation) &&
    Date.parse(grant.expiresAt) > (options.now ?? Date.now()) &&
    Date.parse(grant.expiresAt) >= Date.parse(intent.expiresAt),
  );
  const granted = matching.some(grant => {
    if (intent.operation === 'function' && !grant.callerProgram &&
      (!intent.functionDigest || !grant.functionDigests.includes(intent.functionDigest))) return false;
    if (grant.origins.length && (!options.destination || !grant.origins.includes(new URL(options.destination).origin)))
      return false;
    // Arbitrary programs can disclose their inputs. Such grants must be explicit.
    return !['command', 'http'].includes(intent.operation) || grant.callerProgram;
  });
  if (!granted) throw new Error('This identity cannot use this input on the selected executor.');
  return content;
}

export async function useContent(
  content: CustodyContent, intent: ExecutionIntent, keys: IdentityKeys,
  options: { destination?: string; now?: number } = {},
) {
  await authorizeUse(content, intent, options);
  return open(content.sealed, keys.encryption, intent.executor.id,
    await contentContext(content.policy, content.materialRevision));
}
