import { randomUUID } from 'node:crypto';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import type { Audit } from './audit.js';
import { Name, Principal, PublicKey } from '../shared/contracts.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import { fail, required } from './errors.js';

export interface PrincipalRow { id: string; name: string; public_key: PublicEncryptionKey | null; created_at: Date }
export class Principals {
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit, readonly serverId: string) {}
  async get(id: string, connection: Queryable = this.db.pool): Promise<PrincipalRow> { return required(await this.db.one<PrincipalRow>('SELECT * FROM principals WHERE id=$1', [id], connection)); }
  async create(name: string, publicKey: PublicEncryptionKey | null = null, ownerId?: string, connection: Queryable = this.db.pool, id: string = randomUUID()): Promise<PrincipalRow> {
    await connection.query('INSERT INTO principals(id,name,public_key) VALUES($1,$2,$3)', [id, Name.parse(name), publicKey ? JSON.stringify(PublicKey.parse(publicKey)) : null]);
    if (ownerId) await connection.query('INSERT INTO relations(id,subject_id,principal_id,relation) VALUES($1,$2,$3,$4)', [randomUUID(), ownerId, id, 'owner']);
    return this.get(id, connection);
  }
  async view(actor: Actor, row: PrincipalRow) { return Principal.parse({ id: row.id, name: row.name, publicKey: row.public_key, createdAt: iso(row.created_at), permissions: await this.authorization.principalActions(actor, row.id) }); }
  async accessible(actor: Actor) {
    const standing = await this.authorization.standsAs(actor.id);
    const rows = await this.db.all<PrincipalRow>(`SELECT DISTINCT p.* FROM principals p LEFT JOIN relations r ON r.principal_id=p.id
      WHERE p.id=ANY($1::uuid[]) OR (r.subject_id=ANY($1::uuid[]) AND r.relation='agent') ORDER BY p.created_at,p.id`, [standing]);
    return Promise.all(rows.map(row => this.view(actor, row)));
  }
  async rename(actor: Actor, id: string, name: string) {
    await this.authorization.requirePrincipal(actor, id, 'update');
    if (id === this.serverId) fail(403, 'forbidden', 'The service identity is managed by Foundation.');
    await this.db.pool.query('UPDATE principals SET name=$2 WHERE id=$1', [id, Name.parse(name)]);
    await this.audit.record(id, actor.id, 'principal.rename', id);
    return this.view(actor, await this.get(id));
  }
  async publishKey(actor: Actor, id: string, key: PublicEncryptionKey, wraps: Record<string, string> = {}) {
    await this.authorization.requirePrincipal(actor, id, 'credentials');
    return this.db.transaction(async connection => {
      const row = required(await this.db.one<PrincipalRow>('SELECT * FROM principals WHERE id=$1 FOR UPDATE', [id], connection));
      if (row.public_key) fail(409, 'key_exists', 'This principal already has an encryption key.');
      await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1', [id, JSON.stringify(PublicKey.parse(key))]);
      for (const [credentialId, wrap] of Object.entries(wraps)) await connection.query("UPDATE credentials SET private_wrap=$3 WHERE id=$1 AND principal_id=$2 AND kind='passkey'", [credentialId, id, wrap]);
      await this.audit.record(id, actor.id, 'principal.publishKey', id, {}, connection);
    });
  }
  async relate(actor: Actor, subjectId: string, relation: 'agent' | 'member' | 'payer', principalId: string) {
    if (subjectId === principalId) fail(400, 'invalid_relation', 'Choose a different principal.');
    await this.get(subjectId); await this.get(principalId);
    await this.authorization.requirePrincipal(actor, relation === 'payer' ? subjectId : principalId, 'share');
    await this.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (relation === 'member' && await this.authorization.stands(principalId, subjectId, connection)) fail(409, 'relation_cycle', 'This membership would create a cycle.');
      if (relation === 'payer') {
        const cycle = await this.db.one(`WITH RECURSIVE payers(id) AS (
          SELECT $1::uuid UNION SELECT r.subject_id FROM relations r JOIN payers p ON r.principal_id=p.id WHERE r.relation IN ('owner','payer')
        ) SELECT 1 FROM payers WHERE id=$2`, [subjectId, principalId], connection);
        if (cycle) fail(409, 'relation_cycle', 'This payment relationship would create a cycle.');
        await connection.query("DELETE FROM relations WHERE principal_id=$1 AND relation='payer'", [principalId]);
      }
      await connection.query('INSERT INTO relations(id,subject_id,principal_id,relation) VALUES($1,$2,$3,$4) ON CONFLICT(subject_id,principal_id,relation) DO NOTHING', [randomUUID(), subjectId, principalId, relation]);
      await this.audit.record(principalId, actor.id, 'relation.add', subjectId, { relation }, connection);
    });
  }
  async unrelate(actor: Actor, subjectId: string, relation: 'agent' | 'member' | 'payer', principalId: string) {
    if (!await this.authorization.stands(actor.id, subjectId)) await this.authorization.requirePrincipal(actor, principalId, 'share');
    await this.db.pool.query('DELETE FROM relations WHERE subject_id=$1 AND principal_id=$2 AND relation=$3', [subjectId, principalId, relation]);
    await this.audit.record(principalId, actor.id, 'relation.remove', subjectId, { relation });
  }
  async relations(actor: Actor, id: string, limit = 100, after?: string) {
    await this.authorization.requirePrincipal(actor, id, 'share');
    const rows = await this.db.all<{ id: string; subject_id: string; principal_id: string; subject_name: string; principal_name: string; relation: 'owner'|'agent'|'member'|'payer'; created_at: Date }>(`SELECT r.*,s.name subject_name,p.name principal_name FROM relations r JOIN principals s ON s.id=r.subject_id JOIN principals p ON p.id=r.principal_id
      WHERE (r.subject_id=$1 OR r.principal_id=$1) AND ($2::uuid IS NULL OR r.id>$2) ORDER BY r.id LIMIT $3`, [id, after ?? null, limit + 1]);
    const selected = rows.slice(0, limit);
    return { items: selected.map(row => ({ id: row.id, subjectId: row.subject_id, principalId: row.principal_id, relation: row.relation, subjectName: row.subject_name, principalName: row.principal_name, createdAt: iso(row.created_at) })), next: rows.length > limit ? selected.at(-1)!.id : null };
  }
  async transfer(actor: Actor, id: string, to: string) {
    await this.authorization.requirePrincipal(actor, id, 'transfer');
    await this.get(to);
    await this.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (await this.authorization.stands(id, to, connection)) fail(409, 'relation_cycle', 'This transfer would create an ownership cycle.');
      await connection.query("DELETE FROM relations WHERE principal_id=$1 AND relation='owner'", [id]);
      await connection.query("INSERT INTO relations(id,subject_id,principal_id,relation) VALUES($1,$2,$3,'owner')", [randomUUID(), to, id]);
      await this.audit.record(id, actor.id, 'principal.transfer', to, {}, connection);
    });
  }
  async revoke(actor: Actor, principalId: string, subjectId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'share');
    if (principalId === subjectId) fail(400, 'invalid_relation', 'Choose a different principal.');
    await this.db.transaction(async connection => {
      await connection.query("DELETE FROM relations WHERE subject_id=$1 AND principal_id=$2 AND relation<>'owner'", [subjectId, principalId]);
      await connection.query('DELETE FROM grants WHERE principal_id=$1 AND resource_id IN (SELECT id FROM resources WHERE owner_id=$2)', [subjectId, principalId]);
      await connection.query("UPDATE approval_requests SET state='cancelled',finished_at=now() WHERE from_id=$1 AND to_id=$2 AND state='pending'", [subjectId, principalId]);
      await this.audit.record(principalId, actor.id, 'principal.revoke', subjectId, {}, connection);
    });
  }
}
