import { readFileSync } from 'node:fs';
import { parseSchema, rebac } from 'rebac';
import type { Expression, ObjectRef, SubjectRef } from 'rebac';
import type { Database, Queryable } from './database.js';
import type { ActionName, ResourceKindName } from '../shared/contracts.js';
import { Action, ResourceKind } from '../shared/contracts.js';
import { fail } from './errors.js';

// Who may do what, answered in one place from authorization.zed. The relations table keeps the lines drawn; whom a
// principal or a thing belongs to is kept with it and read here as its owner; a principal is its own self. A route
// asks one permission of one target. How the actor came in decides nothing, except that a link made for one request
// opens that request and nothing else.
export const SCHEMA = parseSchema(readFileSync(new URL('./authorization.zed', import.meta.url), 'utf8'));

export interface Actor {
  id: string;
  credentialId?: string;
  sessionId?: string;
  requestId?: string;
  approvalId?: string;
  approvalIndex?: number;
  // Who agreed, for the other side of a change the actor makes, to the request it is made under.
  agreedBy?: string;
}
export interface ResourceIdentity {
  id: string;
  owner_id: string;
  kind: ResourceKindName;
}
export interface PrincipalTarget {
  type: 'principal';
  id: string;
}
export type Target = PrincipalTarget | ResourceIdentity;
export const principal = (id: string): PrincipalTarget => ({ type: 'principal', id });
export const objectOf = (target: Target): ObjectRef =>
  'kind' in target ? { type: target.kind, id: target.id } : { type: 'principal', id: target.id };
// What a view lists of what its reader may do: the permissions of the target's type that are actions.
export const actionsOf = (type: string): ActionName[] =>
  Action.options.filter((action) => SCHEMA.definitions.get(type)?.permissions.has(action));
export const createPermission = (kind: ResourceKindName) => 'create_' + kind;

// The permissions of a type a relation passes on: those whose expression names it, directly or through another
// permission of the same type.
export function reaches(type: string, relation: string): string[] {
  const definition = SCHEMA.definitions.get(type);
  if (!definition) return [];
  const names = (node: Expression, seen: Set<string>): boolean => {
    if (node.op === 'nil') return false;
    if (node.op === 'arrow') return node.through === relation;
    if (node.op === 'this') {
      if (node.relation === relation) return true;
      const permission = definition.permissions.get(node.relation);
      if (!permission || seen.has(node.relation)) return false;
      seen.add(node.relation);
      return names(permission.expression, seen);
    }
    return node.of.some((part) => names(part, seen));
  };
  return [...definition.permissions]
    .filter(([name, { expression }]) => names(expression, new Set([name])))
    .map(([name]) => name);
}

// A line to be drawn or erased, read as if it already had been: what would be true after a change.
export interface Change {
  add?: Array<{ subjectId: string; relation: string; objectId: string }>;
  remove?: Array<{ subjectId: string; relation: string; objectId: string }>;
  owners?: Record<string, string | null>;
}

// The relationships the schema reads, from where each is kept. One question asks each read once.
function relationships(db: Database, connection: Queryable, change: Change = {}) {
  const answers = new Map<string, Promise<unknown>>();
  const once = <T>(key: string, load: () => Promise<T>): Promise<T> => {
    if (!answers.has(key)) answers.set(key, load());
    return answers.get(key) as Promise<T>;
  };
  const ids = async (sql: string, values: unknown[]) =>
    (await db.all<{ id: string }>(sql, values, connection)).map((row) => row.id);
  const principals = (values: string[]) => values.map((id) => ({ type: 'principal', id }));
  const changed = (object: ObjectRef, relation: string, found: string[]) => {
    const removed = new Set(
      (change.remove ?? [])
        .filter((line) => line.objectId === object.id && line.relation === relation)
        .map((line) => line.subjectId),
    );
    const added = (change.add ?? [])
      .filter((line) => line.objectId === object.id && line.relation === relation)
      .map((line) => line.subjectId);
    return [...new Set([...found.filter((id) => !removed.has(id)), ...added])];
  };
  return {
    read: (object: ObjectRef, relation: string) =>
      once('read ' + object.type + ':' + object.id + '#' + relation, async () => {
        if (relation === 'self') return object.type === 'principal' ? principals([object.id]) : [];
        if (relation === 'owner') {
          if (object.type === 'principal' && object.id in (change.owners ?? {})) {
            const owner = change.owners![object.id];
            return owner ? principals([owner]) : [];
          }
          return principals(
            await ids(
              object.type === 'principal'
                ? 'SELECT owner_id id FROM principals WHERE id=$1 AND owner_id IS NOT NULL'
                : 'SELECT owner_id id FROM resources WHERE id=$1',
              [object.id],
            ),
          );
        }
        return principals(
          changed(
            object,
            relation,
            await ids(
              object.type === 'principal'
                ? 'SELECT subject_id id FROM relations WHERE principal_id=$1 AND relation=$2'
                : 'SELECT subject_id id FROM relations WHERE resource_id=$1 AND relation=$2',
              [object.id, relation],
            ),
          ),
        );
      }),
    reverse: (type: string, relation: string, subjects: SubjectRef[]) => {
      const of = [
        ...new Set(subjects.filter((subject) => subject.type === 'principal' && !subject.relation).map((subject) => subject.id)),
      ].sort();
      if (!of.length) return [];
      return once('reverse ' + type + '#' + relation + '@' + of.join(','), async () => {
        if (relation === 'self') return type === 'principal' ? of : [];
        if (type === 'principal')
          return relation === 'owner'
            ? ids('SELECT id FROM principals WHERE owner_id=ANY($1::uuid[])', [of])
            : ids(
                'SELECT DISTINCT principal_id id FROM relations WHERE relation=$1 AND subject_id=ANY($2::uuid[]) AND principal_id IS NOT NULL',
                [relation, of],
              );
        return relation === 'owner'
          ? ids('SELECT id FROM resources WHERE kind=$1 AND owner_id=ANY($2::uuid[])', [type, of])
          : ids(
              `SELECT DISTINCT r.resource_id id FROM relations r JOIN resources x ON x.id=r.resource_id
              WHERE x.kind=$1 AND r.relation=$2 AND r.subject_id=ANY($3::uuid[])`,
              [type, relation, of],
            );
      });
    },
  };
}

export class Authorization {
  constructor(readonly db: Database) {}
  private ask(connection: Queryable, change?: Change) {
    const { read, reverse } = relationships(this.db, connection, change);
    return rebac(SCHEMA, read, { reverse });
  }
  async active(actor: Actor, connection: Queryable = this.db.pool) {
    const exists = await this.db.one<{ active: boolean }>(
      `SELECT EXISTS(SELECT 1 FROM principals WHERE id=$1)
      AND ($2::uuid IS NULL OR EXISTS(SELECT 1 FROM credentials c LEFT JOIN resources e ON e.id=c.environment_id WHERE c.id=$2 AND c.principal_id=$1 AND (c.expires_at IS NULL OR c.expires_at>now()) AND (c.environment_id IS NULL OR e.data->>'state' IN ('starting','running'))))
      AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM sessions WHERE id=$3 AND principal_id=$1 AND expires_at>now()))
      AND ($4::uuid IS NULL OR EXISTS(SELECT 1 FROM approval_requests WHERE id=$4 AND state='running' AND expires_at>now())) AS active`,
      [actor.id, actor.credentialId ?? null, actor.sessionId ?? null, actor.approvalId ?? null],
      connection,
    );
    if (!exists?.active) fail(401, 'unauthenticated', 'Sign in again to continue.');
  }
  // Whether a principal has the permission on the target, by the relations alone.
  async holds(subjectId: string, target: Target, permission: string, connection: Queryable = this.db.pool) {
    return Boolean(await this.ask(connection).check(objectOf(target), permission, principal(subjectId)));
  }
  // Whether the actor may, as it came in.
  async can(actor: Actor, target: Target, permission: string, connection: Queryable = this.db.pool) {
    await this.active(actor, connection);
    return !actor.requestId && (await this.holds(actor.id, target, permission, connection));
  }
  async require(actor: Actor, target: Target, permission: string, connection: Queryable = this.db.pool) {
    if (!(await this.can(actor, target, permission, connection)))
      fail(403, 'forbidden', 'You do not have permission to perform this action.');
  }
  requirePrincipal(actor: Actor, id: string, permission: string, connection: Queryable = this.db.pool) {
    return this.require(actor, principal(id), permission, connection);
  }
  requireResource(actor: Actor, resource: ResourceIdentity, permission: string, connection: Queryable = this.db.pool) {
    return this.require(actor, resource, permission, connection);
  }
  canCreate(actor: Actor, ownerId: string, kind: ResourceKindName, connection: Queryable = this.db.pool) {
    return this.can(actor, principal(ownerId), createPermission(kind), connection);
  }
  // The ids of every object of a type the principal has the permission on.
  async find(subjectId: string, type: string, permission: string, connection: Queryable = this.db.pool) {
    return [...(await this.ask(connection).lookupResources(type, permission, principal(subjectId)))];
  }
  // Every principal with the permission on the target: as the lines stand, or as they would after a change.
  async holders(target: Target, permission: string, connection: Queryable = this.db.pool, change?: Change) {
    return (await this.ask(connection, change).lookupSubjects(objectOf(target), permission))
      .filter((subject) => subject.type === 'principal')
      .map((subject) => subject.id);
  }
  // The permissions the actor holds on each target, among those named for its type: by default, what its view lists.
  async permissions(
    actor: Actor,
    targets: Target[],
    named: (type: string) => string[] = actionsOf,
  ): Promise<Map<string, string[]>> {
    await this.active(actor);
    const result = new Map<string, string[]>();
    if (actor.requestId) return result;
    const ask = this.ask(this.db.pool),
      reached = new Map<string, Set<string>>();
    for (const target of targets) {
      const { type, id } = objectOf(target),
        held: string[] = [];
      for (const name of named(type)) {
        const key = type + '#' + name;
        if (!reached.has(key)) reached.set(key, new Set(await ask.lookupResources(type, name, principal(actor.id))));
        if (reached.get(key)!.has(id)) held.push(name);
      }
      result.set(id, held);
    }
    return result;
  }
  async actions(actor: Actor, target: Target): Promise<ActionName[]> {
    return ((await this.permissions(actor, [target])).get(target.id) ?? []) as ActionName[];
  }
  // The kinds of thing the actor may make for a principal.
  async createKinds(actor: Actor, ownerId: string): Promise<ResourceKindName[]> {
    const held = (await this.permissions(actor, [principal(ownerId)], () => ResourceKind.options.map(createPermission))).get(ownerId) ?? [];
    return ResourceKind.options.filter((kind) => held.includes(createPermission(kind)));
  }
}
