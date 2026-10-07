import { randomUUID } from 'node:crypto';

import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor, ResourceIdentity } from './authorization.js';
import type { Audit } from './audit.js';
import type { Principals } from './principals.js';
import { Resource, Name, Action } from '../shared/contracts.js';
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
      permissions: permissions ?? (await this.authorization.resourceActions(actor, row)),
    });
  }
  async list(
    actor: Actor,
    ownerId: string,
    input: { kind?: ResourceKindName; query?: string; limit?: number; after?: string } = {},
  ) {
    await this.authorization.requirePrincipal(actor, ownerId, 'read');
    const limit = input.limit ?? 100;
    const rows = await this.db.all<ResourceRow>(
      `SELECT * FROM resources WHERE owner_id=$1 AND ($2::text IS NULL OR kind=$2)
      AND ($3::text IS NULL OR name ILIKE '%' || replace(replace(replace($3,'\\','\\\\'),'%','\\%'),'_','\\_') || '%')
      AND ($4::uuid IS NULL OR id>$4) ORDER BY id LIMIT $5`,
      [ownerId, input.kind ?? null, input.query || null, input.after ?? null, limit + 1],
    );
    const selected = rows.slice(0, limit),
      permissions = await this.authorization.actionsForResources(actor, selected);
    const readable = selected.filter((row) => permissions.get(row.id)?.includes('read'));
    return {
      items: await Promise.all(readable.map((row) => this.view(actor, row, permissions.get(row.id)))),
      next: rows.length > limit ? selected.at(-1)!.id : null,
    };
  }
  async shared(actor: Actor) {
    const standing = await this.authorization.standsAs(actor.id);
    const rows = await this.db.all<ResourceRow>(
      "SELECT DISTINCT r.* FROM resources r JOIN grants g ON g.resource_id=r.id WHERE g.principal_id=ANY($1::uuid[]) AND 'read'=ANY(g.actions) AND NOT(r.owner_id=ANY($1::uuid[])) ORDER BY r.name,r.id",
      [standing],
    );
    const permissions = await this.authorization.actionsForResources(actor, rows);
    return {
      items: await Promise.all(rows.map((row) => this.view(actor, row, permissions.get(row.id)))),
      next: null,
    };
  }
  async recipients(ownerId: string, connection: Queryable = this.db.pool) {
    const rows = await this.db.all<{ id: string; name: string; public_key: PublicEncryptionKey }>(
      `WITH RECURSIVE recipients(id) AS (
      SELECT $1::uuid UNION SELECT r.subject_id FROM relations r JOIN recipients p ON r.principal_id=p.id WHERE r.relation IN ('owner','member')
    ) SELECT p.id,p.name,p.public_key FROM principals p JOIN recipients r ON p.id=r.id WHERE p.public_key IS NOT NULL`,
      [ownerId],
      connection,
    );
    return rows.map((row) => ({ id: row.id, name: row.name, publicKey: row.public_key }));
  }
  async rename(actor: Actor, row: ResourceRow, name: string) {
    await this.authorization.requireResource(actor, row, 'update');
    if (!(await this.authorization.stands(actor.id, row.owner_id)))
      await this.authorization.requireResource(actor, row, 'share');
    const updated = await this.update(row, { name: Name.parse(name) });
    await this.audit.record(row.owner_id, actor.id, 'resource.rename', row.id);
    return updated;
  }
  async grants(actor: Actor, row: ResourceRow) {
    await this.authorization.requireResource(actor, row, 'share');
    const rows = await this.db.all<{ principal_id: string; actions: ActionName[]; name: string }>(
      'SELECT g.*,p.name FROM grants g JOIN principals p ON p.id=g.principal_id WHERE resource_id=$1 ORDER BY p.name',
      [row.id],
    );
    return rows.map((grant) => ({
      principalId: grant.principal_id,
      principalName: grant.name,
      actions: grant.actions,
    }));
  }
  async grant(actor: Actor, row: ResourceRow, principalId: string, actions: ActionName[]) {
    await this.authorization.requireResource(actor, row, 'share');
    await this.principals.get(principalId);
    if (['secret', 'connection', 'app'].includes(row.kind))
      fail(409, 'rekey_required', 'Sign and encrypt the new access policy to share this item.');
    for (const action of actions) {
      Action.parse(action);
      await this.authorization.requireResource(actor, row, action);
    }
    await this.db.pool.query(
      'INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,$3) ON CONFLICT(resource_id,principal_id) DO UPDATE SET actions=EXCLUDED.actions',
      [row.id, principalId, [...new Set(actions)]],
    );
    await this.audit.record(row.owner_id, actor.id, 'resource.share', row.id, { principalId, actions });
  }
  async revoke(actor: Actor, row: ResourceRow, principalId: string) {
    if (['secret', 'connection', 'app'].includes(row.kind))
      fail(409, 'rekey_required', 'Sign and encrypt the new access policy to remove access.');
    await this.authorization.requireResource(actor, row, 'share');
    await this.db.pool.query('DELETE FROM grants WHERE resource_id=$1 AND principal_id=$2', [
      row.id,
      principalId,
    ]);
    await this.audit.record(row.owner_id, actor.id, 'resource.revoke', row.id, { principalId });
  }
  async transfer(actor: Actor, row: ResourceRow, to: string) {
    await this.authorization.requireResource(actor, row, 'transfer');
    await this.principals.get(to);
    if (['secret', 'connection', 'app'].includes(row.kind))
      fail(409, 'rekey_required', 'Encrypt this item for its new owner before transferring it.');
    if (row.kind === 'environment')
      fail(400, 'not_transferable', 'An environment stays with the principal that created it.');
    await this.db.transaction(async connection => {
      const changed = await connection.query(
        'UPDATE resources SET owner_id=$3,version=version+1,updated_at=now() WHERE id=$1 AND version=$2',
        [row.id, row.version, to]);
      if (!changed.rowCount) fail(409, 'changed', 'Reload this item before transferring it.');
      await connection.query('DELETE FROM grants WHERE resource_id=$1', [row.id]);
      await this.audit.record(to, actor.id, 'resource.receive', row.id, { from: row.owner_id }, connection);
      await this.audit.record(row.owner_id, actor.id, 'resource.transfer', row.id, { to }, connection);
    });
  }
  async delete(actor: Actor, row: ResourceRow, connection: Queryable = this.db.pool) {
    await this.authorization.requireResource(actor, row, 'delete', connection);
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
