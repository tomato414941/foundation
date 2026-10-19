import type { Queryable } from './database.js';
import type { Actor, Change } from './authorization.js';
import { principal } from './authorization.js';
import type { ResourceRow } from './resources.js';
import type { Custody } from './custody.js';
import type { BoundKeys } from '../shared/authority.js';
import { canonical } from '../shared/authority.js';
import type { CustodyContent } from '../shared/custody.js';
import { ContentTypes } from '../shared/custody.js';
import { fail } from './errors.js';

export type KeyUpdates = Record<string, { version: number; content: CustodyContent }>;

// Passing a principal to a new owner seals what it holds, and what is held below it, for whoever then acts as it, all at
// once with the transfer. Lines to members and delegates take effect at once instead, and their devices seal the items
// again one by one afterwards.
export class KeySharing {
  constructor(readonly custody: Custody) {}
  async plan(actor: Actor, target: string, owner: string, connection: Queryable = this.custody.resources.db.pool) {
    const { resources, bindings } = this.custody;
    const descendants = await resources.authorization.find(target, 'principal', 'stands', connection);
    // Whoever would open what the principal holds once it has its new owner: the readers its items are sealed for.
    const change: Change = { owners: { [target]: owner } };
    const rows = await resources.db.all<Pick<ResourceRow, 'id' | 'owner_id' | 'name' | 'version'>>(
      `SELECT id,owner_id,name,version FROM resources WHERE kind IN ('variable','connection','app') AND owner_id=ANY($1::uuid[])
       UNION ALL SELECT id,owner_id,'Execution result' AS name,(receipt#>>'{content,materialRevision}')::int AS version
       FROM execution_tasks WHERE owner_id=ANY($1::uuid[]) AND receipt ? 'content' ORDER BY id`,
      [descendants], connection);
    const items = [];
    for (const row of rows) {
      const content = await this.custody.get(row.id, connection);
      const before = new Set((await resources.recipients(row.owner_id, connection)).map(item => item.id));
      const keyed = async (permission: string) => new Set((await resources.db.all<{ id: string }>(
        'SELECT id FROM principals WHERE id=ANY($1::uuid[]) AND public_key IS NOT NULL ORDER BY id',
        [await resources.authorization.holders(principal(row.owner_id), permission, connection, change)], connection)).map(item => item.id));
      const after = await keyed('use'), required = await keyed('stands');
      if (!after.size) fail(409, 'encryption_key_required', 'The owner or remaining members need encryption keys.');
      // The line seals each item for whoever acts as the owner and whoever it newly lets use it, leaving other delegates as they are.
      const readers: BoundKeys[] = await Promise.all([...after].filter(id => required.has(id) || !before.has(id))
        .map(async id => (await bindings.current(id, connection)).binding));
      const removed = (binding: BoundKeys) => before.has(binding.principalId) && (!after.has(binding.principalId) ||
        readers.some(next => next.principalId === binding.principalId && next.id !== binding.id));
      const unique = (values: BoundKeys[]) => [...new Map(values.map(item => [item.id, item])).values()];
      const policy = { ...content.policy, revision: content.policy.revision + 1,
        readers: unique([...content.policy.readers.filter(binding => !removed(binding)), ...readers]),
        authorities: unique([...content.policy.authorities.filter(binding => !removed(binding)), ...readers]),
        grants: content.policy.grants.filter(grant => (!('actor' in grant) || !removed(grant.actor)) && !removed(grant.executor)), producers: [],
        ...(content.policy.observers ? { observers: content.policy.observers.filter(id => !before.has(id) || after.has(id)) } : {}),
      };
      if (canonical({ ...policy, revision: content.policy.revision }) === canonical(content.policy)) continue;
      if (content.policy.contentType === ContentTypes.executionResult) {
        await resources.authorization.requirePrincipal(actor, row.owner_id, 'read', connection);
        await resources.authorization.requirePrincipal(actor, row.owner_id, 'update', connection);
        const { binding } = await bindings.current(actor.id, connection);
        if (!content.policy.authorities.some(authority => canonical(authority) === canonical(binding)))
          fail(403, 'forbidden', 'An existing authority must change the result readers.');
      } else {
        const resource = await resources.get(row.id, connection);
        await resources.authorization.requireResource(actor, resource, 'reveal', connection);
        await resources.authorization.requireResource(actor, resource, 'update', connection);
      }
      items.push({ id: row.id, name: row.name, version: row.version, content, policy });
    }
    return { items, next: null };
  }
  async apply(actor: Actor, target: string, owner: string, updates: KeyUpdates, connection: Queryable) {
    const plan = await this.plan(actor, target, owner, connection);
    for (const item of plan.items) {
      const update = updates[item.id];
      if (!update) fail(409, 'rekey_required', 'Re-encrypt protected items for their new owners and members.');
      if (update.version !== item.version || canonical(update.content.policy) !== canonical(item.policy) ||
        canonical(update.content.metadata) !== canonical(item.content.metadata))
        fail(409, 'changed', 'Use the current recipient plan before changing access.');
      if (item.content.policy.contentType === ContentTypes.executionResult)
        await this.custody.putResult(actor, { ...update, name: item.name }, connection, item.policy.readers);
      else await this.custody.put(actor, { ...update, name: item.name }, connection, item.policy.readers);
    }
  }
}
