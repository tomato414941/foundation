import type { CustodyClient } from './client.js';
import { AccessPolicy, ContentTypes, permittedOperations } from './custody.js';
import type { CustodyContent } from './custody.js';

export async function connectionPolicy(custody: CustodyClient, ownerId: string, previous?: CustodyContent, users?: string[]) {
  let policy = previous?.policy ?? await custody.policy(ownerId, ContentTypes.tokenSet, []);
  if (!users) return policy;
  const bindings = await Promise.all([...new Set(users)].map(async id => {
    const { binding } = await custody.inspectIdentity(id);
    await custody.trusted(binding);
    return binding;
  }));
  policy = AccessPolicy.parse({ ...policy, revision: policy.revision + (previous ? 1 : 0),
    grants: [...policy.grants.filter(grant => !('actor' in grant)), ...bindings.map(binding => ({ actor: binding, executor: binding,
      operations: [...permittedOperations(ContentTypes.tokenSet)], origins: [], functionDigests: [], callerProgram: true,
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() }))] });
  return policy;
}
