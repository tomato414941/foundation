import type { flowFixture } from './flow-support.js';
import { sign } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import { ContentTypes, contentContext } from '../shared/custody.js';
import { seal } from '../shared/encryption.js';

type Flow = Awaited<ReturnType<typeof flowFixture>>;
// A principal that the earlier policy let use an item for itself, until the time given.
export const use = (binding: BoundKeys, expiresAt: string) => ({ actor: binding, executor: binding, functionDigests: [], origins: [],
  operations: ['85bb00b6-ca1e-478d-94ca-a217f0c73e49', '00bc45aa-7b68-4350-b73e-eda476c6236c'], callerProgram: true, expiresAt });
// An item as the earlier policy sealed it, for its readers and for those its grants let use it, as stored then.
export async function sealedEarlier(f: Flow, kind: 'variable' | 'connection', name: string, bytes: Uint8Array,
  metadata: Record<string, unknown>, grants: ReturnType<typeof use>[] = [], data: Record<string, unknown> = metadata) {
  const parties = [f.owner.binding, f.delegate.binding];
  const policy = { format: 2, origin: f.config.origin, id: crypto.randomUUID(), ownerId: f.owner.actor.id,
    contentType: kind === 'variable' ? ContentTypes.value : ContentTypes.tokenSet, revision: 1,
    authorities: parties, readers: parties, grants, producers: [] };
  const recipients = [...new Map([...parties, ...grants.map(grant => grant.executor)].map(binding => [binding.id, binding])).values()];
  const value = { policy, authorityId: f.owner.binding.id, authorization: await sign(policy, f.owner.keys.signing, 'access-policy'),
    materialRevision: 1, updatedAt: new Date().toISOString(), creationRunId: null, metadata, signerId: f.owner.binding.id,
    sealed: await seal(bytes, recipients.map(binding => ({ id: binding.id, publicKey: binding.encryption })), await contentContext(policy, 1)) };
  await f.resources.insert(f.owner.actor.id, kind, name, { ...data, recipients: parties.map(binding => binding.principalId), custodyRevision: 1 },
    { id: policy.id });
  await f.db.pool.query('INSERT INTO resource_custody(resource_id,content) VALUES($1,$2)',
    [policy.id, JSON.stringify({ ...value, signature: await sign(value, f.owner.keys.signing, 'resource') })]);
  return policy.id;
}
