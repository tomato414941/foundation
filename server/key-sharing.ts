import type { Queryable } from './database.js';
import type { Actor, Change } from './authorization.js';
import { principal } from './authorization.js';
import type { ResourceRow } from './resources.js';
import type { Custody } from './custody.js';
import type { BoundKeys } from '../shared/authority.js';
import { canonical } from '../shared/authority.js';
import type { CustodyContent } from '../shared/custody.js';
import { fail } from './errors.js';

export type KeyUpdates = Record<string, { version: number; content: CustodyContent }>;

export class KeySharing {
  constructor(readonly custody: Custody) {}
  async plan(actor: Actor, target: string, subject: string, relation: 'owner' | 'member',
    connection: Queryable = this.custody.resources.db.pool, remove = false) {
    const { resources, bindings } = this.custody;
    const descendants = await resources.authorization.find(target, 'principal', 'stands', connection);
    // Whoever would act as an owner once the line is drawn or erased: the readers its items are sealed for.
    const change: Change = relation === 'owner' ? { owners: { [target]: subject } }
      : { [remove ? 'remove' : 'add']: [{ subjectId: subject, relation: 'member', objectId: target }] };
    const rows = await resources.db.all<ResourceRow>(
      "SELECT * FROM resources WHERE kind IN ('variable','connection','app') AND owner_id=ANY($1::uuid[]) ORDER BY id",
      [descendants], connection);
    const items = [];
    for (const row of rows) {
      const content = await this.custody.get(row.id, connection);
      const oldReaders = new Set((await resources.recipients(row.owner_id, connection)).map(item => item.id));
      const next = await resources.db.all<{ id: string }>(
        'SELECT id FROM principals WHERE id=ANY($1::uuid[]) AND public_key IS NOT NULL ORDER BY id',
        [await resources.authorization.holders(principal(row.owner_id), 'stands', connection, change)], connection);
      const readers: BoundKeys[] = await Promise.all(next.map(async item => (await bindings.current(item.id, connection)).binding));
      if (!readers.length) fail(409, 'encryption_key_required', 'The owner or remaining members need encryption keys.');
      const removed = (binding: BoundKeys) => oldReaders.has(binding.principalId) && !readers.some(next => next.id === binding.id);
      const unique = (values: BoundKeys[]) => [...new Map(values.map(item => [item.id, item])).values()];
      const policy = { ...content.policy, revision: content.policy.revision + 1,
        readers: unique([...content.policy.readers.filter(binding => !removed(binding)), ...readers]),
        authorities: unique([...content.policy.authorities.filter(binding => !removed(binding)), ...readers]),
        grants: content.policy.grants.filter(grant => !removed(grant.actor) && !removed(grant.executor)), producers: [],
        ...(content.policy.observers ? { observers: content.policy.observers.filter(id => !oldReaders.has(id) || readers.some(item => item.principalId === id)) } : {}),
      };
      if (canonical({ ...policy, revision: content.policy.revision }) === canonical(content.policy)) continue;
      await resources.authorization.requireResource(actor, row, 'reveal', connection);
      await resources.authorization.requireResource(actor, row, 'update', connection);
      items.push({ id: row.id, name: row.name, version: row.version, content, policy });
    }
    return { items, next: null };
  }
  async apply(actor: Actor, target: string, subject: string, relation: 'owner' | 'member',
    updates: KeyUpdates, connection: Queryable, remove = false) {
    const plan = await this.plan(actor, target, subject, relation, connection, remove);
    for (const item of plan.items) {
      const update = updates[item.id];
      if (!update) fail(409, 'rekey_required', 'Re-encrypt protected items for their new owners and members.');
      if (update.version !== item.version || canonical(update.content.policy) !== canonical(item.policy) ||
        canonical(update.content.metadata) !== canonical(item.content.metadata))
        fail(409, 'changed', 'Use the current recipient plan before changing access.');
      await this.custody.put(actor, { ...update, name: item.name }, connection, item.policy.readers);
    }
  }
}
