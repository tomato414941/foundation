import type { Actor, Change } from './authorization.js';
import { z } from 'zod';
import type { Queryable } from './database.js';
import type { Resources, ResourceRow } from './resources.js';
import { SealedItem, contentLimit } from '../shared/custody.js';
import type { SealedItemValue } from '../shared/custody.js';
import type { JsonValue, PublicEncryptionKey } from '../shared/contracts.js';
import { Id } from '../shared/contracts.js';
import { thumbprint } from '../shared/encryption.js';
import { AppMetadata, ConnectionMetadata } from '../shared/connections.js';
import type { ConnectionLabelValues } from '../shared/connections.js';
import { ProtectedKinds } from '../shared/protected.js';
import type { ProtectedKindName } from '../shared/protected.js';
import type { Relations } from './relations.js';
import { fail } from './errors.js';

export interface ProtectedWrite {
  id: string;
  name: string;
  kind: ProtectedKindName;
  ownerId: string;
  content: SealedItemValue;
  labels?: ConnectionLabelValues;
  version?: number;
}
export interface Recipient { id: string; name: string; publicKey: PublicEncryptionKey }
// Labels stay with the item until a writer gives new ones.
const keptLabels = (data: Record<string, JsonValue> | undefined): Record<string, JsonValue> =>
  typeof data?.account === 'string' ? { account: data.account } : {};
const metadataOf: Record<ProtectedKindName, z.ZodType> = {
  variable: z.object({ bytes: z.number().int().min(0).max(contentLimit) }).strict(),
  connection: ConnectionMetadata,
  app: AppMetadata,
};

// What a key protects: Foundation keeps it sealed, and decides who may open it. An item is sealed for exactly those who
// may open it, each by the public key it has; Foundation gives it only to them. Only those it is sealed for can seal it
// again, so whoever lets someone new open an item seals it for them at once, and Foundation lists what is left.
export class Custody {
  constructor(readonly resources: Resources, readonly relations: Relations) {}

  metadata(kind: ProtectedKindName, content: SealedItemValue) {
    if (!metadataOf[kind].safeParse(content.metadata).success)
      fail(400, 'invalid_metadata', 'Provide only the public metadata for this protected item.');
    return content.metadata;
  }
  // A connection uses its method, and the application it was made with.
  private async references(actor: Actor, kind: ProtectedKindName, id: string, content: SealedItemValue, connection: Queryable) {
    const values = kind === 'variable' ? [] : [
      ...(Id.safeParse(content.metadata.methodId).success ? [{ id: String(content.metadata.methodId), kind: 'method', permission: 'use' }] : []),
      ...(content.metadata.appId ? [{ id: String(content.metadata.appId), kind: 'app', permission: 'reveal' }] : []),
    ];
    for (const value of values) {
      const row = await this.resources.get(value.id, connection);
      if (row.kind !== value.kind) fail(400, 'wrong_kind', 'Choose a matching connection method and application.');
      await this.resources.authorization.requireResource(actor, row, value.permission, connection);
    }
    await this.resources.references(id, values.map(value => value.id), connection);
  }
  private async replacePending(previous: SealedItemValue, next: SealedItemValue, id: string, connection: Queryable) {
    const pending = await this.resources.db.one<{ id: string; state: string }>(
      "SELECT id,state FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')",
      [id], connection);
    if (!pending) return;
    // A fresh, owner-approved authorization supersedes an ambiguous old token generation. Sealing the existing
    // generation again waits for its update.
    if (pending.state !== 'uncertain' || next.metadata.generation === previous.metadata.generation)
      fail(409, 'connection_busy', 'Resolve the current token update or approve a new connection before changing it.');
    await connection.query("UPDATE connection_operations SET state='aborted',updated_at=now() WHERE id=$1", [pending.id]);
  }

  async get(id: string, connection: Queryable = this.resources.db.pool): Promise<SealedItemValue> {
    const row = await this.resources.db.one<{ content: unknown }>(
      'SELECT content FROM resource_custody WHERE resource_id=$1', [id], connection,
    );
    if (!row) fail(409, 'custody_required', 'Seal this item for those who may open it.');
    return SealedItem.parse(row.content);
  }

  // Principals with a key to seal for, among those given.
  async keyed(ids: string[], connection: Queryable = this.resources.db.pool): Promise<Recipient[]> {
    const rows = await this.resources.db.all<{ id: string; name: string; public_key: PublicEncryptionKey }>(
      'SELECT id,name,public_key FROM principals WHERE id=ANY($1::uuid[]) AND public_key IS NOT NULL ORDER BY id', [ids], connection);
    return rows.map(row => ({ id: row.id, name: row.name, publicKey: row.public_key }));
  }
  // Whom an item is sealed for: everyone who may open it, as the lines stand or as a change would leave them.
  async recipients(item: Pick<ResourceRow, 'id' | 'owner_id' | 'kind'>, connection: Queryable = this.resources.db.pool, change?: Change) {
    return this.keyed(await this.resources.authorization.holders(item, 'reveal', connection, change), connection);
  }
  // Whom a new item of the owner's is sealed for, and an item passed to it: whoever uses what the owner holds.
  async ownerRecipients(ownerId: string, connection: Queryable = this.resources.db.pool) {
    return this.resources.recipients(ownerId, connection);
  }
  // Whether content is sealed for exactly these recipients, each by the key it has now.
  async sealedFor(content: SealedItemValue, recipients: Recipient[]) {
    const expected = new Set(await Promise.all(recipients.map(recipient => thumbprint(recipient.publicKey))));
    const given = content.sealed.recipients.map(recipient => recipient.header.kid);
    return given.length === expected.size && given.every(id => expected.has(id));
  }
  async requireSealedFor(content: SealedItemValue, recipients: Recipient[]) {
    if (!await this.sealedFor(content, recipients))
      fail(409, 'recipients_changed', 'Seal this item for everyone who may open it now, as its recipients list them.');
  }

  // Items someone may open that are not sealed for them yet, with keys they have now, which this principal opens and
  // so can seal again. Only those an item is sealed for can seal it, so Foundation lists them; each is sealed on its own.
  async pending(actor: Actor, principalId: string) {
    if (actor.id !== principalId || actor.requestId) fail(403, 'forbidden', 'Sign in as this principal to seal its items.');
    const own = (await this.keyed([principalId]))[0];
    if (!own) return [];
    const mine = await thumbprint(own.publicKey);
    const items: Array<{ id: string }> = [];
    for (const kind of ProtectedKinds) {
      const ids = await this.resources.authorization.find(principalId, kind, 'reveal');
      const rows = await this.resources.db.all<{ id: string; owner_id: string; kind: ProtectedKindName; kids: string[] }>(
        `SELECT r.id,r.owner_id,r.kind,ARRAY(SELECT x->'header'->>'kid' FROM jsonb_array_elements(c.content->'sealed'->'recipients') x) kids
         FROM resources r JOIN resource_custody c ON c.resource_id=r.id WHERE r.id=ANY($1::uuid[]) ORDER BY r.id`, [ids]);
      for (const row of rows) {
        if (!row.kids.includes(mine)) continue;
        const expected = await Promise.all((await this.recipients(row)).map(recipient => thumbprint(recipient.publicKey)));
        if (expected.some(id => !row.kids.includes(id))) items.push({ id: row.id });
      }
    }
    return items.sort((a, b) => a.id.localeCompare(b.id));
  }

  // The item as sealed, for one who may open it. It goes to them even before it is sealed for their key, to tell them so.
  async read(actor: Actor, id: string) {
    await this.resources.authorization.active(actor);
    const row = await this.resources.get(id);
    if (!await this.resources.authorization.can(actor, row, 'reveal'))
      fail(403, 'forbidden', 'This identity may not open this item.');
    return { kind: row.kind as ProtectedKindName, content: await this.get(id), version: row.version };
  }

  // A change that decides who may open the item once it is made names them, for the item it carries.
  async put(actor: Actor, input: ProtectedWrite, transaction?: Queryable, recipients?: Recipient[]) {
    return this.write(actor, input, transaction, undefined, recipients);
  }

  async transfer(actor: Actor, to: string, input: ProtectedWrite & { version: number }, transaction?: Queryable) {
    if (input.ownerId !== to) fail(400, 'wrong_content', 'Seal the item for the new owner specified by to.');
    return this.write(actor, input, transaction, to);
  }

  private async write(actor: Actor, input: ProtectedWrite, transaction?: Queryable, to?: string, given?: Recipient[]) {
    const { id } = input, content = SealedItem.parse(input.content);
    this.metadata(input.kind, content);
    const persist = async (connection: Queryable) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const current = await this.resources.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1 FOR UPDATE', [id], connection);
      if (to && !current) fail(404, 'not_found', 'The item to transfer no longer exists.');
      let recipients: Recipient[];
      if (current) {
        if (current.kind !== input.kind) fail(400, 'wrong_resource', 'Keep the same resource kind when updating an item.');
        await this.resources.authorization.requireResource(actor, current, to ? 'transfer' : 'update', connection);
        if (!to && current.owner_id !== input.ownerId)
          fail(409, 'transfer_required', 'Use POST /api/resources/' + current.id + '/transfer to change the owner.');
        if (to) await this.resources.principals.get(to, connection);
        if (current.version !== input.version) fail(409, 'changed', 'This item changed. Reload it before saving.');
        const previous = await this.resources.db.one('SELECT 1 FROM resource_custody WHERE resource_id=$1', [id], connection)
          ? await this.get(id, connection) : undefined;
        if (previous) {
          if (content.revision !== previous.revision + 1) fail(409, 'changed', 'Seal the next revision of this item.');
          await this.replacePending(previous, content, id, connection);
        } else if (content.revision !== 1) fail(400, 'invalid_revision', 'Begin a sealed item at revision one.');
        // An item passed on keeps no lines to it: whoever uses what the new owner holds opens it.
        recipients = to ? await this.ownerRecipients(to, connection) : await this.recipients(current, connection);
      } else {
        if (!(await this.resources.authorization.canCreate(actor, input.ownerId, input.kind, connection)))
          fail(403, 'forbidden', 'You cannot create this item for this principal.');
        if (content.revision !== 1) fail(400, 'invalid_revision', 'Begin a sealed item at revision one.');
        recipients = await this.ownerRecipients(input.ownerId, connection);
      }
      await this.requireSealedFor(content, given ?? recipients);
      if (to && current)
        await this.relations.agree(actor, { kind: 'transfer', itemId: id, to }, this.relations.handing(current, to), connection);
      const data = { ...keptLabels(current?.data), ...content.metadata, ...(input.labels ?? {}) };
      let row: ResourceRow;
      if (current) {
        row = await this.resources.update(current, { name: input.name, data }, connection);
        if (to && current.owner_id !== to) {
          row = (await this.resources.db.one<ResourceRow>('UPDATE resources SET owner_id=$2 WHERE id=$1 RETURNING *', [id, to], connection))!;
          await connection.query('DELETE FROM relations WHERE resource_id=$1', [id]);
        }
      } else row = await this.resources.insert(input.ownerId, input.kind, input.name, data, { id }, connection);
      await connection.query(
        'INSERT INTO resource_custody(resource_id,content) VALUES($1,$2) ON CONFLICT(resource_id) DO UPDATE SET content=EXCLUDED.content',
        [id, JSON.stringify(content)],
      );
      await this.references(actor, input.kind, id, content, connection);
      await this.resources.audit.record(row.owner_id, actor.id, 'resource.protect', id, { revision: content.revision }, connection);
      if (to && current && current.owner_id !== to) {
        const agreement: Record<string, string> = actor.agreedBy ? { agreedBy: actor.agreedBy } : {};
        await this.resources.audit.record(to, actor.id, 'resource.receive', id, { from: current.owner_id, ...agreement }, connection);
        await this.resources.audit.record(current.owner_id, actor.id, 'resource.transfer', id, { to, ...agreement }, connection);
      }
      return row;
    };
    return transaction ? persist(transaction) : this.resources.db.transaction(persist);
  }
}
