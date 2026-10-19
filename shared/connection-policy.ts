import type { CustodyClient } from './client.js';
import { AccessPolicy, ContentTypes, permittedOperations } from './custody.js';
import type { CustodyContent } from './custody.js';

// A connection sealed only for keys this identity has since replaced is connected anew as the same item.
export async function connectionPolicy(custody: CustodyClient, ownerId: string,
  previous?: { content: CustodyContent; replaced: boolean }, users?: string[]) {
  const kept = previous && !previous.replaced ? previous.content : undefined;
  let policy = kept?.policy ?? await custody.policy(ownerId, ContentTypes.tokenSet, [],
    previous ? { replacing: previous.content.policy } : {});
  if (!users) return policy;
  const bindings = await Promise.all([...new Set(users)].map(async id => {
    const { binding } = await custody.inspectIdentity(id);
    await custody.trusted(binding);
    return binding;
  }));
  policy = AccessPolicy.parse({ ...policy, revision: policy.revision + (kept ? 1 : 0),
    grants: [...policy.grants.filter(grant => !('actor' in grant)), ...bindings.map(binding => ({ actor: binding, executor: binding,
      operations: [...permittedOperations(ContentTypes.tokenSet)], origins: [], functionDigests: [], callerProgram: true,
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() }))] });
  return policy;
}
