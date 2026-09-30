// Who may do what, answered in one place, in the shape of Zanzibar: lines are the only record, and these rules say
// which lines reach which actions. A subject, an action and a resource go in (the AuthZEN shape); a decision comes
// out. Routes ask this and nothing else.
//
// The subject is a principal. The resource is one a holder holds (with its holder), a principal (its own holder),
// or a request. An action is reached by the holder itself, by whoever acts for or owns the holder, by a role drawn
// onto the resource (viewer, editor), or by that one action drawn onto the resource or onto the holder. Owning a
// principal is managing it (its name, keys, limits, removal), not reaching what it holds. What the subject came in by
// decides nothing: a request link is bound to its one request where it is recognized, before any question is asked.
// A line names a role, a named set of actions, or one action written as the rules name it (connection.disconnect).
export const ROLES = ['owner', 'actor', 'viewer', 'editor'];
export const ACTION = /^[a-z_]+\.[a-z-]+$/;
const SELF = (subject, resource) => subject === resource.holder;
const ACTOR = (subject, resource, principals) => principals.has(subject, 'actor', 'principal', resource.holder);
const OWNER = (subject, resource, principals) => principals.has(subject, 'owner', 'principal', resource.holder);
const LINE = relation => Object.assign((subject, resource, principals) => resource.id !== undefined && principals.has(subject, relation, 'resource', resource.id), { role: relation });

const RULES = {
  // What is done to a principal as a whole, and with all it holds at once.
  principal: {
    read: [SELF, OWNER], rename: [SELF, OWNER], remove: [OWNER], list: [SELF],
    'issue-key': [SELF, OWNER], 'revoke-key': [SELF, OWNER], 'issue-link': [SELF, OWNER],
    // Giving a machine this principal's identity: whoever may act as it. Bounding what it may compute: its owner.
    pass: [SELF, OWNER, ACTOR], limit: [OWNER], relate: [SELF, OWNER], settings: [SELF, OWNER],
    overview: [SELF], export: [SELF], usage: [SELF, ACTOR, OWNER], shown: [SELF], 'audit-log': [SELF],
    // Using what it holds without reading it: injecting into a command, calling the built-in functions.
    inject: [SELF, ACTOR], functions: [SELF, ACTOR], invoke: [SELF, ACTOR],
  },
  // Private bytes may be used without disclosing them to the caller. Managed authorizations expose their facts,
  // not their renewal state. Both can be delivered by an injection.
  secret: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], content: [SELF, LINE('viewer'), LINE('editor')], write: [SELF, ACTOR, LINE('editor')],
    remove: [SELF, ACTOR], rename: [SELF], share: [SELF] },
  connection: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], rename: [SELF], share: [SELF], connect: [SELF], disconnect: [SELF] },
  object: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], write: [SELF, ACTOR, LINE('editor')], remove: [SELF, ACTOR], rename: [SELF], link: [SELF, ACTOR], share: [SELF] },
  // An app is seen by whoever acts for its holder, used to connect by its holder and anyone on a line to it, and given
  // new values by its holder or an editor. Its secret is never read: there is no action for it.
  app: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], use: [SELF, LINE('viewer'), LINE('editor')],
    write: [SELF, LINE('editor')], remove: [SELF], rename: [SELF], share: [SELF] },
  // A service a holder described: seen and changed by whoever acts for the holder - it holds nothing secret - and
  // used by anyone on a line to it.
  service: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], write: [SELF, ACTOR, LINE('editor')], remove: [SELF, ACTOR], rename: [SELF], share: [SELF] },
  // A lent machine: opened and used by the holder or whoever acts for them, and by anyone on an editor line; watched
  // along a viewer line too. Its identity is changed by the holder or whoever acts for them.
  environment: { list: [SELF, ACTOR], open: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], exec: [SELF, ACTOR, LINE('editor')],
    identity: [SELF, ACTOR], remove: [SELF, ACTOR], rename: [SELF], share: [SELF] },
  request: { read: [SELF], grant: [SELF], deny: [SELF], cancel: [SELF] },
};

export class Authorization {
  constructor(principals) { this.principals = principals; }
  allowed({ subject, action, resource }) {
    if (!subject?.id || !action?.name || !resource?.type) return { decision: false };
    const grounds = RULES[resource.type]?.[action.name];
    if (!grounds) return { decision: false };
    const holder = resource.holder ?? (resource.type === 'principal' ? resource.id : undefined);
    if (holder === undefined) return { decision: false };
    const at = { ...resource, holder }, named = resource.type + '.' + action.name, principals = this.principals;
    const one = subject.id;
    return { decision: grounds.some(ground => ground(one, at, principals))
      || principals.has(one, named, 'principal', holder) || (resource.id !== undefined && principals.has(one, named, 'resource', resource.id)) };
  }
  // The same question for a principal as itself.
  can(principalId, name, type, { id, holder } = {}) {
    return this.allowed({ subject: { id: principalId }, action: { name }, resource: { type, ...(id === undefined ? {} : { id }), holder } }).decision;
  }
  // Whether one may draw a line: one who may give lines there (relate on a principal, share on a resource), and who
  // may take there every action the line reaches. Nothing gives more than it has. Owning comes only from making or
  // approving, never from a line drawn.
  mayGive(principalId, relation, objectType, object) {
    if (relation === 'owner') return false;
    const reached = reaches(relation, objectType, object.kind);
    if (!reached) return false;
    const where = objectType === 'principal' ? { holder: object.id } : { id: object.id, holder: object.holder_id };
    if (!this.can(principalId, objectType === 'principal' ? 'relate' : 'share', objectType === 'principal' ? 'principal' : object.kind, objectType === 'principal' ? { id: object.id, holder: object.id } : where)) return false;
    return reached.every(([type, name]) => this.can(principalId, name, type, type === 'principal' ? { id: object.id, holder: object.id } : where));
  }
}

// The actions a line reaches, as [type, action] pairs: one action names itself; a role drawn onto a resource reaches
// what its rules give that role; acting for a principal reaches what the rules give an actor. null when the line
// cannot be drawn there.
export function reaches(relation, objectType, kind) {
  if (ACTION.test(relation)) {
    const [type, name] = [relation.slice(0, relation.indexOf('.')), relation.slice(relation.indexOf('.') + 1)];
    if (!RULES[type]?.[name] || (objectType === 'resource' && type !== kind)) return null;
    return [[type, name]];
  }
  if (objectType === 'resource' && (relation === 'viewer' || relation === 'editor')) {
    return Object.entries(RULES[kind] || {}).filter(([, grounds]) => grounds.some(ground => ground.role === relation)).map(([name]) => [kind, name]);
  }
  if (objectType === 'principal' && relation === 'actor') {
    return Object.entries(RULES).flatMap(([type, actions]) => Object.entries(actions).filter(([, grounds]) => grounds.includes(ACTOR)).map(([name]) => [type, name]));
  }
  return null;
}

// Every rule, flat, for whoever wants to read what is permitted.
export function rules() {
  return Object.entries(RULES).flatMap(([type, actions]) => Object.entries(actions)
    .map(([name, grounds]) => ({ resource: type, action: name, grounds: grounds.map(ground => ground === SELF ? 'self' : ground === ACTOR ? 'actor' : ground === OWNER ? 'owner' : ground.role) })));
}
