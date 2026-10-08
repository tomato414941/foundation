import { canonical, hash, sign } from '../shared/authority.js';
import type { BoundKeys, KeyMaterial } from '../shared/authority.js';
import type { JsonValue } from '../shared/contracts.js';
import { seal } from '../shared/encryption.js';

// An item exactly as the first custody format stored it: kinds and operations by name, and the
// kind bound into the encryption context.
export async function firstFormat(input: {
  origin: string; id: string; ownerId: string; kind: 'secret' | 'connection' | 'app';
  authority: BoundKeys; keys: KeyMaterial; readers: BoundKeys[]; executor: BoundKeys;
  operations: string[]; bytes: Uint8Array; metadata: Record<string, JsonValue>;
}) {
  const policy = { format: 1, origin: input.origin, id: input.id, ownerId: input.ownerId, kind: input.kind, revision: 1,
    authorities: [input.authority], readers: input.readers, producers: [],
    grants: [{ actor: input.authority, executor: input.executor, operations: input.operations, functionDigests: [],
      origins: [], callerProgram: true, expiresAt: new Date(Date.now() + 86_400_000).toISOString() }] };
  const context = canonical({ purpose: 'resource', origin: policy.origin, id: policy.id, ownerId: policy.ownerId,
    kind: policy.kind, policyDigest: await hash(policy), materialRevision: 1 });
  const recipients = [...new Map([...input.readers, input.executor].map(binding => [binding.id, binding])).values()];
  const value = { policy, authorityId: input.authority.id, authorization: await sign(policy, input.keys.signing, 'access-policy'),
    materialRevision: 1, updatedAt: new Date().toISOString(), creationRunId: null, metadata: input.metadata,
    sealed: await seal(input.bytes, recipients.map(binding => ({ id: binding.id, publicKey: binding.encryption })), context),
    signerId: input.authority.id };
  return { ...value, signature: await sign(value, input.keys.signing, 'resource') };
}

