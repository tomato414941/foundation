import { readFileSync } from 'node:fs';
import { rebac, parseSchema } from 'rebac';

// Who may do what, answered in one place from authorization.zed: relations are the only record, and the schema says
// what each permission is computed from. A subject, an action and a resource go in (the AuthZEN shape); a decision
// comes out. Routes ask this and nothing else.
//
// Relations are the lines principals drew, kept in the relations table, and what a holder holds, kept with each
// thing (its holder column, read here as the holder relation). The principal itself is its own `self`. What the
// subject came in by decides nothing.
export const SCHEMA = parseSchema(readFileSync(new URL('./authorization.zed', import.meta.url), 'utf8'));
const PRINCIPAL = SCHEMA.definitions.get('principal');
// A line names a relation the schema declares on its object's type, other than what only the system records.
// Recorded by the system, or by making and approving (owner): never drawn as a line.
const RECORDED_ONLY = new Set(['self', 'holder', 'entry', 'asked', 'owner']);
export const ROLES = ['owner', 'agent', 'viewer', 'editor'];
export function declared(objectType, relation) {
  const definition = SCHEMA.definitions.get(objectType);
  return Boolean(definition?.relations.has(relation)) && !RECORDED_ONLY.has(relation);
}
// What one action's own relation is called: the action, with -s as _s, then _grant.
export const grantOf = action => action.replace(/-/g, '_') + '_grant';
const permissionOf = action => action.replace(/-/g, '_');

export class Authorization {
  // principals: the lines. resources: what holders hold (for the holder relation of a thing).
  constructor(principals, resources) {
    this.principals = principals; this.resources = resources;
    this.authz = rebac(SCHEMA, (object, relation) => this.read(object, relation));
  }
  // The subjects recorded for one relation on one object. Sync, from the same database as everything else.
  read(object, relation) {
    const principal = id => ({ type: 'principal', id });
    if (object.type === 'principal') {
      if (relation === 'self') return [principal(object.id)];
      if (relation === 'entry') return [];
      return this.principals.subjectsOf(relation, 'principal', object.id).map(principal);
    }
    if (object.type === 'request') return relation === 'asked' && object.holder ? [principal(object.holder)] : [];
    if (relation === 'holder') {
      const holder = object.holder ?? this.resources.get(object.id)?.holder_id;
      return holder ? [principal(holder)] : [];
    }
    return this.principals.subjectsOf(relation, 'resource', object.id).map(principal);
  }
  // Decided synchronously: the reader never waits, so the checker answers at once.
  allowed({ subject, action, resource }) {
    if (!subject?.id || !action?.name || !resource?.type) return { decision: false };
    const name = permissionOf(action.name), subjectRef = { type: 'principal', id: subject.id };
    if (resource.type === 'principal') {
      const id = resource.id ?? resource.holder;
      if (id === undefined || !PRINCIPAL.permissions.has(name)) return { decision: false };
      return { decision: this.authz.check({ type: 'principal', id }, name, subjectRef) === true };
    }
    const definition = SCHEMA.definitions.get(resource.type);
    if (resource.id !== undefined) {
      if (!definition?.permissions.has(name)) return { decision: false };
      return { decision: this.authz.check({ type: resource.type, id: resource.id, holder: resource.holder }, name, subjectRef) === true };
    }
    // No thing yet, only its would-be holder: the type's own permission is asked of the holder's things in general
    // (what the holder's lines reach), or, where making one is an action on the holder, that is asked of the holder.
    if (resource.holder === undefined) return { decision: false };
    if (definition?.permissions.has(name)) return { decision: this.authz.check({ type: resource.type, id: resource.holder, holder: resource.holder }, name, subjectRef) === true };
    const making = resource.type + '_' + name;
    if (!PRINCIPAL.permissions.has(making)) return { decision: false };
    return { decision: this.authz.check({ type: 'principal', id: resource.holder }, making, subjectRef) === true };
  }
  can(principalId, name, type, { id, holder } = {}) {
    return this.allowed({ subject: { id: principalId }, action: { name }, resource: { type, ...(id === undefined ? {} : { id }), holder } }).decision;
  }
  // Whether one may draw a line: one who may give lines there (relate on a principal, share on a resource), and who
  // may take there every action the line reaches. Nothing gives more than it has. Owning comes only from making or
  // approving, never from a line drawn.
  mayGive(principalId, relation, objectType, object) {
    if (relation === 'owner') return false;
    const type = objectType === 'principal' ? 'principal' : object.kind;
    const reached = reaches(relation, type);
    if (!reached) return false;
    const where = objectType === 'principal' ? { id: object.id, holder: object.id } : { id: object.id, holder: object.holder_id };
    if (!this.can(principalId, objectType === 'principal' ? 'relate' : 'share', type, where)) return false;
    return reached.every(([, name]) => this.can(principalId, name, type, where));
  }
}

// The actions a line reaches, as [type, action] pairs: the permissions of the object's type whose expression names
// the relation, directly or through the holder. null when the schema declares no such relation there.
export function reaches(relation, type) {
  const definition = SCHEMA.definitions.get(type);
  if (!definition || !declared(type, relation)) return null;
  const names = (node, found = new Set()) => {
    if (node.op === 'this') found.add(node.relation);
    else if (node.op === 'arrow') { for (const name of names(PRINCIPAL.permissions.get(node.to)?.expression ?? { op: 'nil' })) found.add(node.through + '->' + name); }
    else if (node.of) for (const part of node.of) names(part, found);
    return found;
  };
  // Through the holder: a relation on the principal (agent, owner) reaches what the holder's permissions reach.
  const via = type === 'principal' ? [] : [...PRINCIPAL.permissions].filter(([, { expression }]) => names(expression).has(relation)).map(([name]) => 'holder->' + name);
  const found = [...definition.permissions].filter(([, { expression }]) => { const used = names(expression); return used.has(relation) || via.some(name => used.has(name)); }).map(([name]) => [type, name]);
  return found.length ? found : null;
}

// Every rule, flat, for whoever wants to read what is permitted.
export function rules() {
  return [...SCHEMA.definitions].flatMap(([type, { permissions }]) => [...permissions].map(([name, { expression }]) => ({ resource: type, action: name, expression })));
}
