import { randomUUID } from 'node:crypto';

import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor, ResourceIdentity } from './authorization.js';
import { principal } from './authorization.js';
import type { Audit } from './audit.js';
import type { Principals } from './principals.js';
import { Resource, Name, ResourceKind } from '../shared/contracts.js';
import type {
  ResourceKindName,
  ResourceView,
  ActionName,
  JsonValue,
  PublicEncryptionKey,
  SealedContent,
} from '../shared/contracts.js';
import { fail, required } from './errors.js';

export interface ResourceRow extends ResourceIdentity {
  name: string;
  data: Record<string, JsonValue>;
  sealed: SealedContent | null;
  private_data: string | null;
  version: number;
  created_at: Date;
  updated_at: Date;
}
export class Resources {
  connectionServices?: (actor: Actor, methodId: string) => Promise<Array<{ id: string; name: string }>>;
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly principals: Principals,
  ) {}
  async get(id: string, connection: Queryable = this.db.pool): Promise<ResourceRow> {
    return required(await this.db.one<ResourceRow>('SELECT * FROM resources WHERE id=$1', [id], connection));
  }
  async find(ownerId: string, kind: ResourceKindName, name: string): Promise<ResourceRow | undefined> {
    return this.db.one<ResourceRow>('SELECT * FROM resources WHERE owner_id=$1 AND kind=$2 AND name=$3', [
      ownerId,
      kind,
      name,
    ]);
  }
  async insert(
    ownerId: string,
    kind: ResourceKindName,
    name: string,
    data: Record<string, JsonValue>,
    options: { id?: string; sealed?: SealedContent; privateData?: string; references?: string[] } = {},
    connection: Queryable = this.db.pool,
  ) {
    const id = options.id ?? randomUUID();
    const row = required(
      await this.db.one<ResourceRow>(
        'INSERT INTO resources(id,owner_id,kind,name,data,sealed,private_data) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',
        [
          id,
          ownerId,
          kind,
          Name.parse(name),
          JSON.stringify(data),
          options.sealed ? JSON.stringify(options.sealed) : null,
          options.privateData ?? null,
        ],
        connection,
      ),
    );
    if (options.references) await this.references(id, options.references, connection);
    return row;
  }
  async references(id: string, references: string[], connection: Queryable = this.db.pool) {
    await connection.query('DELETE FROM resource_references WHERE resource_id=$1', [id]);
    for (const referenced of new Set(references))
      await connection.query('INSERT INTO resource_references(resource_id,referenced_id) VALUES($1,$2)', [
        id,
        referenced,
      ]);
  }
  async update(
    row: ResourceRow,
    changes: {
      name?: string;
      data?: Record<string, JsonValue>;
      sealed?: SealedContent;
      privateData?: string;
    },
    connection: Queryable = this.db.pool,
  ) {
    const result = await this.db.one<ResourceRow>(
      `UPDATE resources SET name=$3,data=$4,sealed=$5,private_data=$6,version=version+1,updated_at=now()
      WHERE id=$1 AND version=$2 RETURNING *`,
      [
        row.id,
        row.version,
        changes.name ?? row.name,
        JSON.stringify(changes.data ?? row.data),
        JSON.stringify(changes.sealed ?? row.sealed),
        changes.privateData ?? row.private_data,
      ],
      connection,
    );
    if (!result) fail(409, 'changed', 'This item changed. Reload it before saving.');
    return result;
  }
  async view(actor: Actor, row: ResourceRow, permissions?: ActionName[]): Promise<ResourceView> {
    const data =
      row.kind === 'service' || row.kind === 'method'
          ? { ...row.data, name: row.name }
          : row.kind === 'connection'
            ? {
                ...row.data,
                services: (await this.connectionServices?.(actor, String(row.data.methodId))) ?? [],
              }
            : row.data;
    return Resource.parse({
      id: row.id,
      ownerId: row.owner_id,
      kind: row.kind,
      name: row.name,
      data,
      version: row.version,
      createdAt: iso(row.created_at),
      updatedAt: iso(row.updated_at),
      permissions: permissions ?? (await this.authorization.actions(actor, row)),
    });
  }
  async list(
    actor: Actor,
    ownerId: string,
    input: { kind?: ResourceKindName; query?: string; limit?: number; after?: string; includeOwned?: boolean } = {},
  ) {
    await this.authorization.requirePrincipal(actor, ownerId, 'read');
    const limit = input.limit ?? 100;
    const rows = await this.db.all<ResourceRow>(
      `WITH RECURSIVE owners(id) AS (
        SELECT $1::uuid
        UNION
        SELECT p.id FROM principals p JOIN owners o ON p.owner_id=o.id WHERE $6::boolean
      )
      SELECT * FROM resources WHERE owner_id IN (SELECT id FROM owners) AND ($2::text IS NULL OR kind=$2)
      AND ($3::text IS NULL OR name ILIKE '%' || replace(replace(replace($3,'\\','\\\\'),'%','\\%'),'_','\\_') || '%')
      AND ($4::uuid IS NULL OR id>$4) ORDER BY id LIMIT $5`,
      [ownerId, input.kind ?? null, input.query || null, input.after ?? null, limit + 1, input.includeOwned ?? false],
    );
    const selected = rows.slice(0, limit),
      permissions = await this.authorization.permissions(actor, selected);
    const readable = selected.filter((row) => permissions.get(row.id)?.includes('read'));
    return {
      items: await Promise.all(readable.map((row) => this.view(actor, row, permissions.get(row.id) as ActionName[]))),
      next: rows.length > limit ? selected.at(-1)!.id : null,
    };
  }
  // What others hold that the actor was let read: not what belongs to a principal it acts as or for.
  async shared(actor: Actor) {
    const readable = (
      await Promise.all(ResourceKind.options.map((kind) => this.authorization.find(actor.id, kind, 'read')))
    ).flat();
    const rows = await this.db.all<ResourceRow>(
      'SELECT * FROM resources WHERE id=ANY($1::uuid[]) AND NOT owner_id=ANY($2::uuid[]) ORDER BY name,id',
      [readable, await this.authorization.find(actor.id, 'principal', 'use')],
    );
    const permissions = await this.authorization.permissions(actor, rows);
    return {
      items: await Promise.all(rows.map((row) => this.view(actor, row, permissions.get(row.id) as ActionName[]))),
      next: null,
    };
  }
  // Whoever acts as the owner, with a key to seal for: those who open what it holds.
  async recipients(ownerId: string, connection: Queryable = this.db.pool) {
    const rows = await this.db.all<{ id: string; name: string; public_key: PublicEncryptionKey }>(
      'SELECT id,name,public_key FROM principals WHERE id=ANY($1::uuid[]) AND public_key IS NOT NULL',
      [await this.authorization.holders(principal(ownerId), 'stands', connection)],
      connection,
    );
    return rows.map((row) => ({ id: row.id, name: row.name, publicKey: row.public_key }));
  }
  async rename(actor: Actor, row: ResourceRow, name: string) {
    await this.authorization.requireResource(actor, row, 'rename');
    const updated = await this.update(row, { name: Name.parse(name) });
    await this.audit.record(row.owner_id, actor.id, 'resource.rename', row.id);
    return updated;
  }
  async delete(actor: Actor, row: ResourceRow, connection: Queryable = this.db.pool): Promise<void> {
    if (connection === this.db.pool) return this.db.transaction(transaction => this.delete(actor, row, transaction));
    await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [row.id]);
    await this.authorization.requireResource(actor, row, 'delete', connection);
    const pending = await this.db.one(
      "SELECT 1 FROM connection_operations WHERE resource_id=$1 AND state IN ('prepared','in_flight','uncertain')",
      [row.id], connection);
    if (pending) fail(409, 'connection_busy', 'Resolve the current token update or reconnect before deleting this connection.');
    await connection.query('DELETE FROM resources WHERE id=$1', [row.id]);
    await this.audit.record(
      row.owner_id,
      actor.id,
      'resource.delete',
      row.id,
      { kind: row.kind },
      connection,
    );
  }
}
