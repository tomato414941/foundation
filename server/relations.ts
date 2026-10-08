import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization, Target } from './authorization.js';
import { SCHEMA, objectOf, principal, reaches } from './authorization.js';
import type { Audit } from './audit.js';
import type { Principals } from './principals.js';
import type { KeyUpdates } from './key-sharing.js';
import { Relation, RelationInput } from '../shared/contracts.js';
import type { z } from 'zod';
import { isProtected } from '../shared/protected.js';
import { fail } from './errors.js';

export type Line = z.infer<typeof RelationInput>;
interface LineRow {
  subject_id: string;
  subject_name: string;
  relation: string;
  object_id: string;
  object_name: string;
  object_type: string;
  created_at: Date;
}
// Relations recorded where they are decided, never drawn: whom something belongs to comes of making, approving and
// passing it on, and a principal is its own self.
const RECORDED = new Set(['owner', 'self']);
// Lines that give something of their subject's rather than their object's: a payer takes on a cost, so the payer
// draws it.
const GIVEN_BY_SUBJECT = new Set(['payer']);
const cursor = (row: LineRow) =>
  Buffer.from(JSON.stringify([iso(row.created_at), row.subject_id, row.relation, row.object_id])).toString('base64url');

// The lines drawn between principals and onto what they hold. A line is drawn by one on the side that gives what it
// passes on, who has every permission it passes on: nothing gives more than it has. A subject may always erase a
// line to itself. On what a key protects, the lines are the signed policy's and change only with it.
export class Relations {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly principals: Principals,
  ) {}
  // The principal or thing an id names.
  async target(id: string, connection: Queryable = this.db.pool): Promise<Target & { ownerId: string | null }> {
    const found = await this.db.one<{ type: string; kind: string | null; owner_id: string | null }>(
      `SELECT 'principal' type,NULL kind,owner_id FROM principals WHERE id=$1
      UNION ALL SELECT 'resource',kind,owner_id FROM resources WHERE id=$1`,
      [id],
      connection,
    );
    if (!found) fail(404, 'not_found', 'The object of this relation does not exist.');
    return found.type === 'principal'
      ? { ...principal(id), ownerId: found.owner_id }
      : ({ id, kind: found.kind, owner_id: found.owner_id, ownerId: found.owner_id } as Target & { ownerId: string });
  }
  private drawable(target: Target, relation: string) {
    const type = objectOf(target).type;
    if (!SCHEMA.definitions.get(type)?.relations.has(relation) || RECORDED.has(relation))
      fail(400, 'invalid_relation', 'Choose a relation this object can be given.');
    if ('kind' in target && isProtected(target.kind))
      fail(409, 'rekey_required', 'Sign and encrypt the new access policy to change who may use this item.');
  }
  // Where the audit of a line is kept: the principal it is drawn onto, or the owner of the thing.
  private ledger(target: Target & { ownerId: string | null }) {
    return 'kind' in target ? target.owner_id : target.id;
  }
  async draw(actor: Actor, line: Line, contents: KeyUpdates = {}) {
    if (line.subjectId === line.objectId) fail(400, 'invalid_relation', 'Choose a different principal.');
    await this.principals.get(line.subjectId);
    const object = await this.target(line.objectId);
    this.drawable(object, line.relation);
    await this.authorization.require(actor, GIVEN_BY_SUBJECT.has(line.relation) ? principal(line.subjectId) : object, 'share');
    for (const permission of reaches(objectOf(object).type, line.relation))
      await this.authorization.require(actor, object, permission);
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (line.relation === 'member' && (await this.authorization.holds(line.objectId, principal(line.subjectId), 'stands', connection)))
        fail(409, 'relation_cycle', 'This membership would create a cycle.');
      if (line.relation === 'payer') {
        const cycle = await this.db.one(
          `WITH RECURSIVE above(id) AS (
            SELECT $1::uuid UNION SELECT next.id FROM above a CROSS JOIN LATERAL (
              SELECT subject_id id FROM relations WHERE principal_id=a.id AND relation='payer'
              UNION ALL SELECT owner_id FROM principals WHERE id=a.id AND owner_id IS NOT NULL
            ) next
          ) SELECT 1 FROM above WHERE id=$2`,
          [line.subjectId, line.objectId],
          connection,
        );
        if (cycle) fail(409, 'relation_cycle', 'This payment relationship would create a cycle.');
        await connection.query("DELETE FROM relations WHERE principal_id=$1 AND relation='payer'", [line.objectId]);
      }
      if (line.relation === 'member')
        await this.principals.keySharing.apply(actor, line.objectId, line.subjectId, 'member', contents, connection);
      await connection.query(
        `INSERT INTO relations(subject_id,relation,${'kind' in object ? 'resource_id' : 'principal_id'}) VALUES($1,$2,$3)
        ON CONFLICT DO NOTHING`,
        [line.subjectId, line.relation, line.objectId],
      );
      await this.audit.record(this.ledger(object), actor.id, 'relation.add', line.objectId,
        { subjectId: line.subjectId, relation: line.relation }, connection);
    });
  }
  async erase(actor: Actor, line: Line, contents: KeyUpdates = {}) {
    const object = await this.target(line.objectId);
    this.drawable(object, line.relation);
    if (!(await this.authorization.can(actor, principal(line.subjectId), 'stands')))
      await this.authorization.require(actor, object, 'share');
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (line.relation === 'member')
        await this.principals.keySharing.apply(actor, line.objectId, line.subjectId, 'member', contents, connection, true);
      await connection.query(
        `DELETE FROM relations WHERE subject_id=$1 AND relation=$2 AND ${'kind' in object ? 'resource_id' : 'principal_id'}=$3`,
        [line.subjectId, line.relation, line.objectId],
      );
      await this.audit.record(this.ledger(object), actor.id, 'relation.remove', line.objectId,
        { subjectId: line.subjectId, relation: line.relation }, connection);
    });
  }
  // The lines drawn onto an object, or drawn from a subject, oldest first: for one who may share there.
  async list(actor: Actor, query: { object?: string; subject?: string; limit: number; after?: string }) {
    if (query.object) await this.authorization.require(actor, await this.target(query.object), 'share');
    else await this.authorization.requirePrincipal(actor, query.subject!, 'share');
    let after: [string, string, string, string] | null = null;
    try {
      after = query.after ? JSON.parse(Buffer.from(query.after, 'base64url').toString()) : null;
    } catch {
      fail(400, 'invalid_cursor', 'Start again from the first page.');
    }
    const rows = await this.db.all<LineRow>(
      `SELECT r.subject_id,s.name subject_name,r.relation,coalesce(r.principal_id,r.resource_id) object_id,
        coalesce(p.name,x.name) object_name,coalesce(x.kind,'principal') object_type,r.created_at
      FROM relations r JOIN principals s ON s.id=r.subject_id
      LEFT JOIN principals p ON p.id=r.principal_id LEFT JOIN resources x ON x.id=r.resource_id
      WHERE ($1::uuid IS NULL OR coalesce(r.principal_id,r.resource_id)=$1) AND ($2::uuid IS NULL OR r.subject_id=$2)
        AND ($3::timestamptz IS NULL OR (r.created_at,r.subject_id,r.relation,coalesce(r.principal_id,r.resource_id))
          > ($3::timestamptz,$4::uuid,$5::text,$6::uuid))
      ORDER BY r.created_at,r.subject_id,r.relation,coalesce(r.principal_id,r.resource_id) LIMIT $7`,
      [query.object ?? null, query.subject ?? null, ...(after ?? [null, null, null, null]), query.limit + 1],
    );
    const selected = rows.slice(0, query.limit);
    return {
      items: selected.map((row) =>
        Relation.parse({
          subjectId: row.subject_id,
          subjectName: row.subject_name,
          relation: row.relation,
          objectId: row.object_id,
          objectName: row.object_name,
          objectType: row.object_type,
          createdAt: iso(row.created_at),
        }),
      ),
      next: rows.length > query.limit ? cursor(selected.at(-1)!) : null,
    };
  }
  // Takes back everything a principal was given by another and on what the other holds, and the other's open requests.
  async revoke(actor: Actor, principalId: string, subjectId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'share');
    if (principalId === subjectId) fail(400, 'invalid_relation', 'Choose a different principal.');
    await this.db.transaction(async (connection) => {
      await connection.query(
        'DELETE FROM relations WHERE subject_id=$1 AND (principal_id=$2 OR resource_id IN (SELECT id FROM resources WHERE owner_id=$2))',
        [subjectId, principalId],
      );
      await connection.query(
        "UPDATE approval_requests SET state='cancelled',finished_at=now() WHERE from_id=$1 AND to_id=$2 AND state='pending'",
        [subjectId, principalId],
      );
      await this.audit.record(principalId, actor.id, 'principal.revoke', subjectId, {}, connection);
    });
  }
}

// The lines on a thing as its signed policy says: what was there is replaced.
export async function project(connection: Queryable, resourceId: string, lines: Array<{ subjectId: string; relation: string }>) {
  await connection.query('DELETE FROM relations WHERE resource_id=$1', [resourceId]);
  for (const line of lines)
    await connection.query(
      'INSERT INTO relations(subject_id,relation,resource_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
      [line.subjectId, line.relation, resourceId],
    );
}
