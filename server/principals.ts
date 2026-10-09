import { randomUUID } from 'node:crypto';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import { actionsOf, createPermission, principal } from './authorization.js';
import type { Audit } from './audit.js';
import { Name, Principal, PublicKey, WrappedKey } from '../shared/contracts.js';
import type { PublicEncryptionKey, WrappedEncryptionKey } from '../shared/contracts.js';
import { fail, required } from './errors.js';
import type { KeySharing } from './key-sharing.js';
import { ResourceKind } from '../shared/contracts.js';

export interface PrincipalRow {
  id: string;
  name: string;
  public_key: PublicEncryptionKey | null;
  owner_id: string | null;
  created_at: Date;
}
export class Principals {
  keySharing!: KeySharing;
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
  ) {}
  async get(id: string, connection: Queryable = this.db.pool): Promise<PrincipalRow> {
    return required(
      await this.db.one<PrincipalRow>('SELECT * FROM principals WHERE id=$1', [id], connection),
    );
  }
  async create(
    name: string,
    publicKey: PublicEncryptionKey | null = null,
    ownerId?: string,
    connection: Queryable = this.db.pool,
    id: string = randomUUID(),
  ): Promise<PrincipalRow> {
    await connection.query('INSERT INTO principals(id,name,public_key,owner_id) VALUES($1,$2,$3,$4)', [
      id,
      Name.parse(name),
      publicKey ? JSON.stringify(PublicKey.parse(publicKey)) : null,
      ownerId ?? null,
    ]);
    return this.get(id, connection);
  }
  async view(actor: Actor, row: PrincipalRow) {
    return (await this.views(actor, [row]))[0]!;
  }
  // Each principal as the actor sees it: who owns it, what the actor may do there, and what the actor may make for it.
  async views(actor: Actor, rows: PrincipalRow[]) {
    const kinds = ResourceKind.options,
      held = await this.authorization.permissions(actor, rows.map((row) => principal(row.id)),
        (type) => [...actionsOf(type), ...kinds.map(createPermission)]);
    const owners = new Map(
      (await this.db.all<{ id: string; name: string }>('SELECT id,name FROM principals WHERE id=ANY($1::uuid[])',
        [rows.map((row) => row.owner_id).filter(Boolean)])).map((owner) => [owner.id, owner]),
    );
    return rows.map((row) => {
      const permissions = held.get(row.id) ?? [];
      return Principal.parse({
        id: row.id,
        name: row.name,
        owner: row.owner_id ? (owners.get(row.owner_id) ?? null) : null,
        publicKey: row.public_key,
        createdAt: iso(row.created_at),
        permissions: actionsOf('principal').filter((action) => permissions.includes(action)),
        createKinds: kinds.filter((kind) => permissions.includes(createPermission(kind))),
      });
    });
  }
  // Every principal the actor may read: itself, those it acts as or for, and those it was let read.
  async accessible(actor: Actor) {
    const rows = await this.db.all<PrincipalRow>(
      'SELECT * FROM principals WHERE id=ANY($1::uuid[]) ORDER BY created_at,id',
      [await this.authorization.find(actor.id, 'principal', 'read')],
    );
    return this.views(actor, rows);
  }
  async rename(actor: Actor, id: string, name: string) {
    await this.authorization.requirePrincipal(actor, id, 'update');
    await this.db.pool.query('UPDATE principals SET name=$2 WHERE id=$1', [id, Name.parse(name)]);
    await this.audit.record(id, actor.id, 'principal.rename', id);
    return this.view(actor, await this.get(id));
  }
  async publishKey(actor: Actor, id: string, key: PublicEncryptionKey, wraps: Record<string, WrappedEncryptionKey> = {}) {
    await this.authorization.requirePrincipal(actor, id, 'manage_credentials');
    return this.db.transaction(async (connection) => {
      const row = required(
        await this.db.one<PrincipalRow>('SELECT * FROM principals WHERE id=$1 FOR UPDATE', [id], connection),
      );
      if (row.public_key) fail(409, 'key_exists', 'This principal already has an encryption key.');
      await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1', [
        id,
        JSON.stringify(PublicKey.parse(key)),
      ]);
      for (const [credentialId, wrap] of Object.entries(wraps))
        await connection.query(
          'UPDATE credentials SET private_wrap=$3 WHERE id=$1 AND principal_id=$2',
          [credentialId, id, WrappedKey.parse(wrap)],
        );
      await this.audit.record(id, actor.id, 'principal.publishKey', id, {}, connection);
    });
  }
}
