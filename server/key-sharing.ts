import type { Queryable } from './database.js';
import type { Actor, Change } from './authorization.js';
import type { ResourceRow } from './resources.js';
import type { Custody } from './custody.js';
import type { SealedItemValue } from '../shared/custody.js';
import { canonical } from '../shared/digest.js';
import { fail } from './errors.js';

export type KeyUpdates = Record<string, { version: number; content: SealedItemValue }>;

// Passing a principal to a new owner seals what it holds, and what is held below it, for whoever may then open it, all
// at once with the transfer. Lines to members and delegates take effect at once instead, and whoever draws one seals the
// items for them right after.
export class KeySharing {
  constructor(readonly custody: Custody) {}
  async plan(actor: Actor, target: string, owner: string, connection: Queryable = this.custody.resources.db.pool) {
    const { resources } = this.custody;
    const descendants = await resources.authorization.find(target, 'principal', 'stands', connection);
    const change: Change = { owners: { [target]: owner } };
    const rows = await resources.db.all<Pick<ResourceRow, 'id' | 'owner_id' | 'kind' | 'name' | 'version'>>(
      `SELECT r.id,r.owner_id,r.kind,r.name,r.version FROM resources r JOIN resource_custody c ON c.resource_id=r.id
       WHERE r.kind IN ('variable','connection','app') AND r.owner_id=ANY($1::uuid[]) ORDER BY r.id`,
      [descendants], connection);
    const items = [];
    for (const row of rows) {
      const recipients = await this.custody.recipients(row, connection, change);
      if (!recipients.length) fail(409, 'encryption_key_required', 'The owner or remaining members need encryption keys.');
      if (await this.custody.sealedFor(await this.custody.get(row.id, connection), recipients)) continue;
      await resources.authorization.requireResource(actor, row, 'reveal', connection);
      await resources.authorization.requireResource(actor, row, 'update', connection);
      items.push({ id: row.id, name: row.name, version: row.version, recipients });
    }
    return { items, next: null };
  }
  async apply(actor: Actor, target: string, owner: string, updates: KeyUpdates, connection: Queryable) {
    const plan = await this.plan(actor, target, owner, connection);
    for (const item of plan.items) {
      const update = updates[item.id];
      if (!update) fail(409, 'rekey_required', 'Seal the protected items for their new owners and members.');
      const row = await this.custody.resources.get(item.id, connection);
      if (update.version !== item.version ||
        canonical(update.content.metadata) !== canonical((await this.custody.get(item.id, connection)).metadata))
        fail(409, 'changed', 'Use the current recipient plan before changing access.');
      await this.custody.put(actor, { id: row.id, name: item.name, kind: row.kind as 'variable' | 'connection' | 'app',
        ownerId: row.owner_id, content: update.content, version: update.version }, connection, item.recipients);
    }
  }
}
