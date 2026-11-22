import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization, Target } from './authorization.js';
import { SCHEMA, createPermission, objectOf, principal, reaches } from './authorization.js';
import type { Audit } from './audit.js';
import type { Principals } from './principals.js';
import type { Resources, ResourceRow } from './resources.js';
import type { KeyUpdates } from './key-sharing.js';
import { Relation, RelationInput } from '../shared/contracts.js';
import type { RelationQuery, ResourceKindName } from '../shared/contracts.js';
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
// A change one side has agreed to and the other is asked: something passed on.
export type Proposed = { kind: 'transfer'; itemId: string; to: string };
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
// nothing gives more than it has, and what a new owner takes on is taken on by its side. A change made on
// one side waits on the other as a request. A subject may always erase a line to itself. A line that lets someone
// open what a key protects takes effect at once: whoever drew it seals those items for them right after, and the
// server gives an item only to those who may open it.
export class Relations {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly principals: Principals,
    readonly resources: Resources,
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
  }
  // Where the audit of a line is kept: the principal it is drawn onto, or the owner of the thing.
  private ledger(target: Target & { ownerId: string | null }) {
    return 'kind' in target ? target.owner_id : target.id;
  }
  // What drawing a line takes. A line passes on what its object holds: sharing there, and every permission it passes on.
  private drawing(object: Target, line: Line): Side[] {
    const passed = ['share', ...reaches(objectOf(object).type, line.relation)];
    return [{ needs: passed.map((name): [Target, string] => [object, name]), ask: null }];
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
  // request the change is made under. When the actor holds one side of a proposed change and the other can be asked,
  // the change goes there.
  async agree(actor: Actor, proposed: Proposed | null, sides: Side[], connection: Queryable = this.db.pool) {
    await this.authorization.active(actor, connection);
    const parties = [actor.id, ...(actor.agreedBy ? [actor.agreedBy] : [])];
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
    if (missing.length === sides.length || missing.length > 1 || !ask || !proposed || actor.approvalId || actor.agreedBy)
      fail(403, 'forbidden', 'You do not have permission to perform this action.');
    throw new AgreementNeeded(ask, proposed);
  }
  async requireDraw(actor: Actor, line: Line, connection: Queryable) {
    if (line.subjectId === line.objectId) fail(400, 'invalid_relation', 'Choose a different principal.');
    await this.principals.get(line.subjectId, connection);
    const object = await this.target(line.objectId, connection);
    this.drawable(object, line.relation);
    await this.agree(actor, null, this.drawing(object, line), connection);
    return object;
  }
  async draw(actor: Actor, line: Line, transaction?: Queryable) {
    const add = async (connection: Queryable) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const object = await this.requireDraw(actor, line, connection);
      if (line.relation === 'member' && (await this.authorization.holds(line.objectId, principal(line.subjectId), 'stands', connection)))
        fail(409, 'relation_cycle', 'This membership would create a cycle.');
      await connection.query(
        `INSERT INTO relations(subject_id,relation,${'kind' in object ? 'resource_id' : 'principal_id'}) VALUES($1,$2,$3)
        ON CONFLICT DO NOTHING`,
        [line.subjectId, line.relation, line.objectId],
      );
      await this.audit.record(this.ledger(object), actor.id, 'relation.add', line.objectId,
        { subjectId: line.subjectId, relation: line.relation, ...agreed(actor) }, connection);
    };
    return transaction ? add(transaction) : this.db.transaction(add);
  }
  async erase(actor: Actor, line: Line, transaction?: Queryable) {
    const remove = async (connection: Queryable) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      const object = await this.target(line.objectId, connection);
      this.drawable(object, line.relation);
      if (!(await this.authorization.can(actor, principal(line.subjectId), 'stands', connection)))
        await this.authorization.require(actor, object, 'share', connection);
      await connection.query(
        `DELETE FROM relations WHERE subject_id=$1 AND relation=$2 AND ${'kind' in object ? 'resource_id' : 'principal_id'}=$3`,
        [line.subjectId, line.relation, line.objectId],
      );
      await this.audit.record(this.ledger(object), actor.id, 'relation.remove', line.objectId,
        { subjectId: line.subjectId, relation: line.relation }, connection);
    };
    return transaction ? remove(transaction) : this.db.transaction(remove);
  }
  // Acceptance rechecks the exact version and both sides' current permissions while the item is locked.
  async transferResource(actor: Actor, id: string, to: string, version: number) {
    return this.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [id]);
      const row = await this.resources.get(id, connection);
      await this.authorization.requireResource(actor, row, 'transfer', connection);
      if (row.version !== version) fail(409, 'changed', 'This item changed. Reload it before transferring it.');
      await this.principals.get(to, connection);
      if (isProtected(row.kind))
        fail(409, 'rekey_required', 'Seal this item on your device for whoever uses what the new owner holds, then submit to, version, and content to this endpoint.', {
          content: { method: 'GET', path: '/api/resources/' + id + '/custody' },
          recipients: { method: 'GET', path: '/api/resources/' + id + '/transfer-recipients?to=' + to },
          submit: { method: 'POST', path: '/api/resources/' + id + '/transfer', fields: ['to', 'version', 'content'] },
        });
      await this.agree(actor, { kind: 'transfer', itemId: id, to }, this.handing(row, to), connection);
      const changed = await this.resources.changeOwner(row, to, connection);
      await connection.query('DELETE FROM relations WHERE resource_id=$1', [row.id]);
      await this.audit.record(to, actor.id, 'resource.receive', row.id, { from: row.owner_id, ...agreed(actor) }, connection);
      await this.audit.record(row.owner_id, actor.id, 'resource.transfer', row.id, { to, ...agreed(actor) }, connection);
      return changed;
    });
  }
  // Passes a principal or a thing to a new owner. What a principal's keys protect, here and below it, is sealed again
  // for whoever then acts as it; a thing a key protects is passed on by sealing it for its new owner instead.
  async transfer(actor: Actor, id: string, to: string, contents: KeyUpdates = {}) {
    const item = await this.target(id);
    if ('kind' in item) return this.transferResource(actor, id, to, (await this.resources.get(id)).version);
    await this.principals.get(to);
    await this.agree(actor, { kind: 'transfer', itemId: id, to }, this.handing(item, to));
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      if (await this.authorization.holds(id, principal(to), 'stands', connection))
        fail(409, 'relation_cycle', 'This transfer would create an ownership cycle.');
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [id]);
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
  // The principals a thing is shared with to open it, beyond whoever uses what its owner holds: they replace the earlier
  // ones. One who acts as the owner shares it, and whoever opens it seals it for the new ones right after.
  async openers(actor: Actor, item: ResourceRow, subjects: string[], connection: Queryable) {
    await this.authorization.requireResource(actor, item, 'share', connection);
    await this.authorization.requireResource(actor, item, 'reveal', connection);
    const users = new Set(await this.authorization.holders(principal(item.owner_id), 'use', connection));
    const wanted = new Set(subjects.filter(id => !users.has(id)));
    for (const id of wanted) await this.principals.get(id, connection);
    const current = new Set((await this.db.all<{ subject_id: string }>(
      "SELECT subject_id FROM relations WHERE resource_id=$1 AND relation='revealer'", [item.id], connection)).map(row => row.subject_id));
    for (const id of wanted) if (!current.has(id)) {
      await connection.query("INSERT INTO relations(subject_id,relation,resource_id) VALUES($1,'revealer',$2) ON CONFLICT DO NOTHING", [id, item.id]);
      await this.audit.record(item.owner_id, actor.id, 'relation.add', item.id, { subjectId: id, relation: 'revealer', ...agreed(actor) }, connection);
    }
    for (const id of current) if (!wanted.has(id)) {
      await connection.query("DELETE FROM relations WHERE subject_id=$1 AND relation='revealer' AND resource_id=$2", [id, item.id]);
      await this.audit.record(item.owner_id, actor.id, 'relation.remove', item.id, { subjectId: id, relation: 'revealer' }, connection);
    }
  }
}

