import { randomUUID } from 'node:crypto';

import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor, ResourceIdentity } from './authorization.js';
import type { Audit } from './audit.js';
import type { Principals } from './principals.js';
import type { ServerIdentity } from './vault.js';
import { Resource, Name, Sealed, Action } from '../shared/contracts.js';
import type {
  ResourceKindName,
  ResourceView,
  NewResourceInput,
  ActionName,
  JsonValue,
  PublicEncryptionKey,
  SealedContent,
} from '../shared/contracts.js';
import { base64url, encode } from '../shared/encryption.js';
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
    readonly identity: ServerIdentity,
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
      row.kind === 'secret'
        ? { ...row.data, allowUse: await this.authorization.resource({ id: this.identity.id }, row, 'use') }
        : row.kind === 'service' || row.kind === 'method'
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
  async validateSecret(
    ownerId: string,
    id: string,
    sealed: SealedContent,
    allowUse: boolean,
    connection: Queryable = this.db.pool,
  ) {
    if ('format' in sealed) fail(400, 'invalid_envelope', 'Use JWE to save encrypted content.');
    if (sealed.aad !== base64url(encode('resource:' + id)))
      fail(400, 'invalid_envelope', 'Encrypt the content for this resource.');
    const recipients = await this.recipients(ownerId, connection);
    if (!recipients.length)
      fail(409, 'encryption_key_required', 'Add a passkey with encryption support before saving secrets.');
    const addressed = new Set(sealed.recipients.map((recipient) => recipient.header.kid));
    if (
      addressed.size !== sealed.recipients.length ||
      recipients.some((recipient) => !addressed.has(recipient.id))
    )
      fail(400, 'missing_recipient', 'Encrypt the secret for each owner and member with an encryption key.');
    if (allowUse && !addressed.has(this.identity.id))
      fail(400, 'missing_recipient', 'Include Foundation as a recipient to use the secret in tools.');
  }
  async createSecret(actor: Actor, ownerId: string, input: Extract<NewResourceInput, { kind: 'secret' }>) {
    if (!(await this.authorization.canCreate(actor, ownerId, 'secret')))
      fail(403, 'forbidden', 'You cannot create secrets for this principal.');
    return this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (!(await this.authorization.canCreate(actor, ownerId, 'secret', connection)))
        fail(403, 'forbidden', 'You cannot create secrets for this principal.');
      await this.validateSecret(ownerId, input.id, input.sealed, input.allowUse, connection);
      const row = await this.insert(
        ownerId,
        'secret',
        input.name,
        { bytes: input.bytes, recipients: input.sealed.recipients.map((item) => item.header.kid) },
        { id: input.id, sealed: input.sealed },
        connection,
      );
      if (input.allowUse)
        await connection.query(
          "INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,ARRAY['use'])",
          [row.id, this.identity.id],
        );
      await this.audit.record(ownerId, actor.id, 'secret.create', row.id, {}, connection);
      return row;
    });
  }
  async secretContent(actor: Actor, id: string) {
    const row = await this.get(id);
    if (row.kind !== 'secret') fail(400, 'wrong_kind', 'This item is not a secret.');
    await this.authorization.requireResource(actor, row, 'reveal');
    return { sealed: Sealed.parse(row.sealed), context: 'resource:' + row.id };
  }
  async updateSecret(
    actor: Actor,
    row: ResourceRow,
    sealed: SealedContent,
    bytes: number,
    use?: boolean,
    name?: string,
  ) {
    await this.authorization.requireResource(actor, row, 'update');
    const allowUse = use ?? (await this.authorization.resource({ id: this.identity.id }, row, 'use'));
    const updated = await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      await this.authorization.requireResource(actor, row, 'update', connection);
      await this.validateSecret(row.owner_id, row.id, sealed, allowUse, connection);
      const updated = await this.update(
        row,
        {
          sealed,
          ...(name ? { name: Name.parse(name) } : {}),
          data: { bytes, recipients: sealed.recipients.map((recipient) => recipient.header.kid) },
        },
        connection,
      );
      if (use !== undefined) {
        if (use)
          await connection.query(
            "INSERT INTO grants(resource_id,principal_id,actions) VALUES($1,$2,ARRAY['use']) ON CONFLICT(resource_id,principal_id) DO UPDATE SET actions=ARRAY['use']",
            [row.id, this.identity.id],
          );
        else
          await connection.query('DELETE FROM grants WHERE resource_id=$1 AND principal_id=$2', [
            row.id,
            this.identity.id,
          ]);
      }
      return updated;
    });
    await this.audit.record(row.owner_id, actor.id, 'secret.update', row.id);
    return updated;
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
    await this.authorization.requireResource(actor, row, 'share');
    await this.db.pool.query('DELETE FROM grants WHERE resource_id=$1 AND principal_id=$2', [
      row.id,
      principalId,
    ]);
    await this.audit.record(row.owner_id, actor.id, 'resource.revoke', row.id, { principalId });
  }
  async transfer(actor: Actor, row: ResourceRow, to: string, sealed?: SealedContent) {
    await this.authorization.requireResource(actor, row, 'transfer');
    await this.principals.get(to);
    if (row.kind === 'environment')
      fail(400, 'not_transferable', 'An environment stays with the principal that created it.');
    if (row.kind === 'secret') {
      if (!sealed) fail(400, 'envelope_required', 'Encrypt the secret for its new owner.');
    }
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      await this.authorization.requireResource(actor, row, 'transfer', connection);
      if (row.kind === 'secret')
        await this.validateSecret(
          to,
          row.id,
          sealed!,
          await this.authorization.resource({ id: this.identity.id }, row, 'use', connection),
          connection,
        );
      const data =
        sealed && row.kind === 'secret'
          ? { ...row.data, recipients: sealed.recipients.map((recipient) => recipient.header.kid) }
          : row.data;
      const result = await connection.query(
        'UPDATE resources SET owner_id=$3,sealed=$4,data=$5,version=version+1,updated_at=now() WHERE id=$1 AND version=$2',
        [row.id, row.version, to, JSON.stringify(sealed ?? row.sealed), JSON.stringify(data)],
      );
      if (!result.rowCount) fail(409, 'changed', 'This item changed. Reload it before transferring.');
      await connection.query('DELETE FROM grants WHERE resource_id=$1 AND principal_id<>$2', [
        row.id,
        this.identity.id,
      ]);
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
