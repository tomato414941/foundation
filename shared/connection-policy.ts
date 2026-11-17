import type { CustodyClient } from './client.js';
import { AccessPolicy, ContentTypes } from './custody.js';
import type { CustodyContent, CustodyPolicy } from './custody.js';

// A connection's users are its readers beyond those who use what its owner holds: they open it on their own machines and
// renew it there until its owner takes them off. The given users replace the earlier ones, by keys this identity verified.
export async function withUsers(custody: CustodyClient, policy: CustodyPolicy, users: string[]) {
  const owners = await custody.ownerSide(policy.ownerId);
  const bindings = await Promise.all([...new Set(users)].filter(id => !owners.has(id)).map(async id => {
    const { binding } = await custody.inspectIdentity(id);
    return custody.trusted(binding);
  }));
  return AccessPolicy.parse({ ...policy, readers: [...policy.readers.filter(reader => owners.has(reader.principalId)), ...bindings] });
}

// A connection sealed only for keys this identity has since replaced is connected anew as the same item.
export async function connectionPolicy(custody: CustodyClient, ownerId: string,
  previous?: { content: CustodyContent; replaced: boolean }, users?: string[]) {
  const kept = previous && !previous.replaced ? previous.content : undefined;
  const policy = kept ? await custody.refreshRecipients(kept.policy) : await custody.policy(ownerId, ContentTypes.tokenSet,
    previous ? { replacing: previous.content.policy } : {});
  if (!users) return policy;
  return withUsers(custody, { ...policy, revision: kept ? kept.policy.revision + 1 : policy.revision }, users);
}
