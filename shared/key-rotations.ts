import { z } from 'zod';
import { Id, Name, Time, WrappedKey } from './contracts.js';
import { Fingerprint, Signature, SignedBinding, canonical, hash, sign } from './authority.js';
import type { BoundKeys, KeyMaterial } from './authority.js';
import { AccessPolicy, ProtectedContent, protect, reveal, verifyContent } from './custody.js';
import type { CustodyContent, CustodyPolicy } from './custody.js';
import { SignedEnvironment } from './runtime-protocol.js';
import { FunctionSettingsApproval } from './function-api.js';

export const RotationKind = z.enum(['content', 'result', 'credential', 'environment', 'keyring', 'functionSettings']);
export const RotationStart = z.object({
  id: Id, replacement: SignedBinding, previousSignature: Signature,
}).strict();
export const RotationPayload = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('content'), content: ProtectedContent }).strict(),
  z.object({ kind: z.literal('result'), content: ProtectedContent }).strict(),
  z.object({ kind: z.literal('credential'), wrappedKey: WrappedKey }).strict(),
  z.object({ kind: z.literal('environment'), registration: SignedEnvironment }).strict(),
  z.object({ kind: z.literal('keyring'), signature: Signature }).strict(),
  z.object({ kind: z.literal('functionSettings'), approval: FunctionSettingsApproval }).strict(),
]);
export type PreparedRotationPayload = z.infer<typeof RotationPayload>;
export const RotationPreparation = z.object({
  sourceDigest: Fingerprint, payload: RotationPayload, signature: Signature,
}).strict();
export const RotationSource = z.record(z.string(), z.unknown());
export const RotationItem = z.object({
  kind: RotationKind, id: Id, name: Name.nullable(), sourceDigest: Fingerprint,
  state: z.enum(['pending', 'prepared', 'stale']), source: RotationSource.nullable(),
});
export const RotationBlocker = z.object({ kind: z.string(), id: Id, reason: z.string() });
export const RotationView = z.object({
  id: Id, principalId: Id, state: z.enum(['preparing', 'committed', 'cancelled']),
  previous: SignedBinding, replacement: SignedBinding, previousSignature: Signature,
  createdAt: Time, finishedAt: Time.nullable(),
  total: z.number().int().nonnegative(), prepared: z.number().int().nonnegative(),
  blockers: z.array(RotationBlocker), items: z.array(RotationItem), next: z.string().nullable(),
});

// A rotation changes key bindings, never the principals, permissions, destinations or expiry dates.
export function rotationPolicy(policy: CustodyPolicy, previous: BoundKeys, replacement: BoundKeys): CustodyPolicy {
  const replace = (binding: BoundKeys) => {
    if (binding.id !== previous.id) return binding;
    if (canonical(binding) !== canonical(previous)) throw new Error('Use the exact previous key binding.');
    return replacement;
  };
  return AccessPolicy.parse({
    ...policy, revision: policy.revision + 1,
    readers: policy.readers.map(replace), authorities: policy.authorities.map(replace),
    grants: policy.grants.map(grant => 'actor' in grant
      ? { ...grant, actor: replace(grant.actor), executor: replace(grant.executor) }
      : { ...grant, executor: replace(grant.executor) }),
    producers: policy.producers.map(producer => ({ ...producer, executor: replace(producer.executor) })),
  });
}

export async function prepareRotatedContent(
  content: CustodyContent, previous: BoundKeys, replacement: BoundKeys,
  signer: BoundKeys, keys: KeyMaterial, replacementKeys?: KeyMaterial,
) {
  const bytes = await reveal(content, signer, keys.encryption);
  const prepared = await protect(bytes, rotationPolicy(content.policy, previous, replacement),
    content.materialRevision + 1, signer, keys, content.metadata, content);
  if (signer.id !== previous.id) return prepared;
  if (!replacementKeys) throw new Error('Keep the replacement keys before preparing rotated content.');
  const { signature: _signature, ...body } = prepared;
  const value = { ...body, authorityId: replacement.id, signerId: replacement.id,
    authorization: await sign(prepared.policy, replacementKeys.signing, 'access-policy') };
  return verifyContent({ ...value, signature: await sign(value, replacementKeys.signing, 'resource') });
}

// This proof also binds credential wraps to this rotation; possession of an API token alone cannot replace them.
export async function rotationPreparationProof(
  rotationId: string, principalId: string, replacementId: string, itemId: string,
  sourceDigest: string, payload: PreparedRotationPayload,
) {
  return { rotationId, principalId, replacementId, itemId, sourceDigest, payloadDigest: await hash(payload) };
}

export async function signRotationPreparation(
  rotationId: string, principalId: string, replacementId: string, itemId: string,
  sourceDigest: string, payload: PreparedRotationPayload, key: KeyMaterial['signing'],
) {
  return { sourceDigest, payload, signature: await sign(
    await rotationPreparationProof(rotationId, principalId, replacementId, itemId, sourceDigest, payload),
    key, 'key-rotation-preparation') };
}
