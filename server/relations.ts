import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization, Target } from './authorization.js';
import { SCHEMA, createPermission, objectOf, principal, reaches } from './authorization.js';
import type { Audit } from './audit.js';
import type { Principals } from './principals.js';
import type { Resources } from './resources.js';
import type { Billing } from './billing.js';
import type { KeyUpdates } from './key-sharing.js';
import { Relation, RelationInput } from '../shared/contracts.js';
import type { RelationQuery, ResourceKindName } from '../shared/contracts.js';
import type { z } from 'zod';
import { ProtectedKinds, isProtected } from '../shared/protected.js';
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
// A change one side has agreed to and the other is asked: a line that needs both its ends, or something passed on.
export type Proposed =
  | { kind: 'line'; subjectId: string; relation: string; objectId: string }
  | { kind: 'transfer'; itemId: string; to: string };
// One side of a change: every permission agreeing takes there, and whom to ask when the actor does not hold them.
// Null where it cannot be asked: what is given there is given only by one who holds it.
interface Side {
  needs: Array<[Target, string]>;
  ask: string | null;
}
// A change made on one side that waits on the other: it goes to that side as a request, and is made once it agrees.
export class AgreementNeeded extends Error {
  constructor(
    readonly to: string,
    readonly proposed: Proposed,
  ) {
    super('agreement_needed');
  }
}
const agreed = (actor: Actor): Record<string, string> => (actor.agreedBy ? { agreedBy: actor.agreedBy } : {});
const cursor = (row: LineRow) =>
  Buffer.from(JSON.stringify([iso(row.created_at), row.subject_id, row.relation, row.object_id])).toString('base64url');

// The lines drawn between principals and onto what they hold, and whom each principal and thing belongs to. Each side
// that gives something by a change agrees to it: what a line passes on is given by one who holds all of it, since
// nothing gives more than it has, and what a payer or a new owner takes on is taken on by its side. A change made on
// one side waits on the other as a request. A subject may always erase a line to itself. On what a key protects, the
// lines are the signed policy's and change only with it. A line to a member or an agent takes effect at once: the
// owner's devices seal its items again one by one afterwards, so an item that cannot change now holds nothing back,
// and meanwhile the server gives an item only to those who may still open it.
export class Relations {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly principals: Principals,
    readonly resources: Resources,
    readonly billing: Billing,
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
  // What drawing a line takes. A line passes on what its object holds: sharing there, and every permission it passes on.
  // A payer gives its money: whoever manages the billing of the payer and of whoever its costs reach agrees to give it,
  // and whoever manages the billing of the principal paid for agrees to take it.
  private async drawing(object: Target, line: Line): Promise<Side[]> {
    if (line.relation !== 'payer') {
      const passed = ['share', ...reaches(objectOf(object).type, line.relation)];
      return [{ needs: passed.map((name): [Target, string] => [object, name]), ask: null }];
    }
    const pays = await this.billing.payer(line.subjectId), payers = [...new Set([line.subjectId, pays])];
    return [
      { needs: payers.map((id): [Target, string] => [principal(id), 'manage_billing']), ask: pays },
      { needs: [[object, 'manage_billing']], ask: line.objectId },
    ];
  }
  // What passing a principal or a thing to a new owner takes: one who may pass it on gives it, and the new owner takes it
  // on by one who could make such a thing there.
  handing(item: Target, to: string): Side[] {
    return [
      { needs: [[item, 'transfer']], ask: null },
      { needs: [[principal(to), 'kind' in item ? createPermission(item.kind) : 'create']], ask: to },
    ];
  }
  // Whether every side of a change agrees: the actor for what it holds, and for the other side whoever agreed to the
  // request the change is made under. When the actor holds one side and the other can be asked, the change goes there.
  async agree(actor: Actor, proposed: Proposed, sides: Side[], connection: Queryable = this.db.pool) {
    await this.authorization.active(actor, connection);
    const parties = actor.requestId ? [] : [actor.id, ...(actor.agreedBy ? [actor.agreedBy] : [])];
    const holds = async (party: string, side: Side) => {
      for (const [target, name] of side.needs)
        if (!(await this.authorization.holds(party, target, name, connection))) return false;
      return true;
    };
    const missing: Side[] = [];
    for (const side of sides) {
      let held = false;
      for (const party of parties) held ||= await holds(party, side);
      if (!held) missing.push(side);
    }
    if (!missing.length) return;
    const ask = missing[0]!.ask;
    if (missing.length === sides.length || missing.length > 1 || !ask || actor.approvalId || actor.agreedBy)
      fail(403, 'forbidden', 'You do not have permission to perform this action.');
    throw new AgreementNeeded(ask, proposed);
  }
  async draw(actor: Actor, line: Line) {
    if (line.subjectId === line.objectId) fail(400, 'invalid_relation', 'Choose a different principal.');
    await this.principals.get(line.subjectId);
    const object = await this.target(line.objectId);
    this.drawable(object, line.relation);
    const payer = line.relation === 'payer';
    if (payer && (await this.authorization.can(actor, principal(line.subjectId), 'manage_billing')))
      await this.billing.requireChargeable(line.subjectId);
    await this.agree(actor, { kind: 'line', ...line }, await this.drawing(object, line));
    if (payer) await this.billing.requireChargeable(line.subjectId);
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (line.relation === 'member' && (await this.authorization.holds(line.objectId, principal(line.subjectId), 'stands', connection)))
        fail(409, 'relation_cycle', 'This membership would create a cycle.');
      if (payer) {
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
      await connection.query(
        `INSERT INTO relations(subject_id,relation,${'kind' in object ? 'resource_id' : 'principal_id'}) VALUES($1,$2,$3)
        ON CONFLICT DO NOTHING`,
        [line.subjectId, line.relation, line.objectId],
      );
      await this.audit.record(this.ledger(object), actor.id, 'relation.add', line.objectId,
        { subjectId: line.subjectId, relation: line.relation, ...agreed(actor) }, connection);
    });
  }
  async erase(actor: Actor, line: Line) {
    const object = await this.target(line.objectId);
    this.drawable(object, line.relation);
    // Either side stops a payment, by whoever manages its billing there.
    if (line.relation === 'payer') {
      if (!(await this.authorization.can(actor, principal(line.subjectId), 'manage_billing')))
        await this.authorization.require(actor, object, 'manage_billing');
    } else if (!(await this.authorization.can(actor, principal(line.subjectId), 'stands')))
      await this.authorization.require(actor, object, 'share');
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const owners = !('kind' in object) && (line.relation === 'member' || line.relation === 'agent')
        ? await this.authorization.find(line.objectId, 'principal', 'stands', connection) : [];
      const users = async (id: string) => new Set(await this.authorization.holders(principal(id), 'use', connection));
      const before = await Promise.all(owners.map(users));
      await connection.query(
        `DELETE FROM relations WHERE subject_id=$1 AND relation=$2 AND ${'kind' in object ? 'resource_id' : 'principal_id'}=$3`,
        [line.subjectId, line.relation, line.objectId],
      );
      // Whoever no longer uses what a principal holds no longer opens it, even where an item is still sealed for it: the
      // roles its items record for it go with the line, until the owner's devices seal them again without it.
      for (const [index, id] of owners.entries()) {
        const after = await users(id), lost = [...before[index]!].filter(subject => !after.has(subject));
        if (lost.length) await connection.query(
          'DELETE FROM relations WHERE subject_id=ANY($1::uuid[]) AND resource_id IN (SELECT id FROM resources WHERE owner_id=$2 AND kind=ANY($3::text[]))',
          [lost, id, [...ProtectedKinds]]);
      }
      await this.audit.record(this.ledger(object), actor.id, 'relation.remove', line.objectId,
        { subjectId: line.subjectId, relation: line.relation }, connection);
    });
  }
  // Passes a principal or a thing to a new owner. What a principal's keys protect, here and below it, is sealed again
  // for whoever then acts as it; a thing a key protects is passed on by sealing it for its new owner instead.
  async transfer(actor: Actor, id: string, to: string, contents: KeyUpdates = {}) {
    const item = await this.target(id);
    await this.principals.get(to);
    if ('kind' in item) {
      if (isProtected(item.kind))
        fail(409, 'rekey_required', 'Encrypt this item for its new owner before transferring it.');
      if (item.kind === 'environment')
        fail(400, 'not_transferable', 'An environment stays with the principal that created it.');
    }
    await this.agree(actor, { kind: 'transfer', itemId: id, to }, this.handing(item, to));
    if ('kind' in item) {
      const row = await this.resources.get(id);
      await this.db.transaction(async (connection) => {
        await this.resources.changeOwner(row, to, connection);
        await connection.query('DELETE FROM relations WHERE resource_id=$1', [row.id]);
        await this.audit.record(to, actor.id, 'resource.receive', row.id, { from: row.owner_id, ...agreed(actor) }, connection);
        await this.audit.record(row.owner_id, actor.id, 'resource.transfer', row.id, { to, ...agreed(actor) }, connection);
      });
      return;
    }
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (await this.authorization.holds(id, principal(to), 'stands', connection))
        fail(409, 'relation_cycle', 'This transfer would create an ownership cycle.');
      await this.principals.keySharing.apply(actor, id, to, contents, connection);
      await connection.query('UPDATE principals SET owner_id=$2 WHERE id=$1', [id, to]);
      await this.audit.record(id, actor.id, 'principal.transfer', to, agreed(actor), connection);
    });
  }
  // The lines onto an object, or from a subject, oldest first, of one relation or onto one type of object if asked: for
  // one who may share there. Whom each principal and thing belongs to is among them, since what an owner may do there
  // comes of it, and is shown as the view of what is owned shows it: to one who may read that.
  async list(actor: Actor, query: z.infer<typeof RelationQuery>) {
    if (query.object) await this.authorization.require(actor, await this.target(query.object), 'share');
    else await this.authorization.requirePrincipal(actor, query.subject!, 'share');
    let after: [string, string, string, string] | null = null;
    try {
      after = query.after ? JSON.parse(Buffer.from(query.after, 'base64url').toString()) : null;
    } catch {
      fail(400, 'invalid_cursor', 'Start again from the first page.');
    }
    const rows = await this.db.all<LineRow>(
      `SELECT l.subject_id,s.name subject_name,l.relation,coalesce(l.principal_id,l.resource_id) object_id,
        coalesce(p.name,x.name) object_name,coalesce(x.kind,'principal') object_type,l.created_at
      FROM (
        SELECT subject_id,relation,principal_id,resource_id,created_at FROM relations
        WHERE ($1::uuid IS NULL OR coalesce(principal_id,resource_id)=$1) AND ($2::uuid IS NULL OR subject_id=$2)
          AND ($3::text IS NULL OR relation=$3)
        UNION ALL
        SELECT owner_id,'owner',id,NULL,owned_at FROM principals
        WHERE owner_id IS NOT NULL AND ($1::uuid IS NULL OR id=$1) AND ($2::uuid IS NULL OR owner_id=$2)
          AND ($3::text IS NULL OR $3='owner') AND ($4::text IS NULL OR $4='principal')
        UNION ALL
        SELECT owner_id,'owner',NULL,id,owned_at FROM resources
        WHERE ($1::uuid IS NULL OR id=$1) AND ($2::uuid IS NULL OR owner_id=$2)
          AND ($3::text IS NULL OR $3='owner') AND ($4::text IS NULL OR kind=$4)
      ) l JOIN principals s ON s.id=l.subject_id
      LEFT JOIN principals p ON p.id=l.principal_id LEFT JOIN resources x ON x.id=l.resource_id
      WHERE ($4::text IS NULL OR coalesce(x.kind,'principal')=$4)
        AND ($5::timestamptz IS NULL OR (l.created_at,l.subject_id,l.relation,coalesce(l.principal_id,l.resource_id))
          > ($5::timestamptz,$6::uuid,$7::text,$8::uuid))
      ORDER BY l.created_at,l.subject_id,l.relation,coalesce(l.principal_id,l.resource_id) LIMIT $9`,
      [query.object ?? null, query.subject ?? null, query.relation ?? null, query.objectType ?? null,
        ...(after ?? [null, null, null, null]), query.limit + 1],
    );
    const selected = rows.slice(0, query.limit), owned = selected.filter((row) => row.relation === 'owner');
    const readable = owned.length
      ? await this.authorization.permissions(actor, owned.map((row): Target => row.object_type === 'principal'
        ? principal(row.object_id)
        : { id: row.object_id, owner_id: row.subject_id, kind: row.object_type as ResourceKindName }), () => ['read'])
      : new Map<string, string[]>();
    return {
      items: selected.filter((row) => row.relation !== 'owner' || readable.get(row.object_id)?.includes('read')).map((row) =>
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
        "UPDATE executions SET state='cancelled',response='cancelled',wait=NULL,revision=revision+1 WHERE creator_id=$1 AND responder_id=$2 AND response='pending' AND state IN ('waiting','failed')",
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
