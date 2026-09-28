// Who may do what, answered in one place, in the AuthZEN shape: a subject, an action and a resource go in,
// a decision comes out. Routes ask this and nothing else.
//
// The subject is a principal and what it came in by (via): an access key, a login session, or a request link. The
// resource is one a holder holds (with its holder), a principal, or a request. The answer comes from the lines
// between principals: the holder itself, whoever acts for the holder, whoever owns a principal, or a line drawn onto
// the resource. Any one action may also be given on its own (a permission), so nothing is beyond giving. What the
// subject came in by decides nothing, except that a request link reaches its one request and nothing else. Lines
// onto a resource point at its id.
const SELF = (subject, resource) => subject.id === resource.holder;
const ACTOR = (subject, resource, principals) => Boolean(principals.has(subject.id, 'actor', 'principal', resource.holder));
const OWNER = (subject, resource, principals) => Boolean(principals.has(subject.id, 'owner', 'principal', resource.holder));
const LINE = relation => (subject, resource, principals) => Boolean(resource.id !== undefined && principals.has(subject.id, relation, 'resource', resource.id));

const RULES = {
  overview: { read: [SELF] },
  export: { read: [SELF] },
  principal: {
    read: [SELF, OWNER], rename: [SELF, OWNER], remove: [OWNER], list: [SELF],
    'issue-key': [SELF, OWNER], 'revoke-key': [SELF, OWNER], 'issue-link': [SELF, OWNER],
    // Giving a machine this principal's identity: whoever may act as it. Bounding what it may compute: its owner.
    pass: [SELF, OWNER, ACTOR], limit: [OWNER], relate: [SELF, OWNER], settings: [SELF, OWNER],
  },
  // A credential is read (what it is) by whoever acts for the holder; a secret's content only along a line. Using
  // one - deriving what it yields for a command - is an injection. Registering an existing token is the same
  // operation for any client. Connecting and disconnecting are the holder's, and whoever the holder gives them to.
  credential: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], content: [SELF, LINE('viewer'), LINE('editor')], write: [SELF, ACTOR, LINE('editor')],
    remove: [SELF, ACTOR], rename: [SELF], share: [SELF], 'register-token': [SELF, ACTOR], connect: [SELF], disconnect: [SELF] },
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
  usage: { read: [SELF, ACTOR, OWNER] },
  injection: { create: [SELF, ACTOR] },
  function: { list: [SELF, ACTOR], invoke: [SELF, ACTOR] },
  resource: { list: [SELF] },
  audit_log: { list: [SELF] },
  request: { read: [SELF], done: [SELF], deny: [SELF], cancel: [SELF] },
};

export class Authorization {
  constructor(principals) { this.principals = principals; }
  allowed({ subject, action, resource }) {
    if (!subject?.id || !action?.name || !resource?.type) return { decision: false };
    // A request link reaches the one request it was made for, and nothing else.
    if (subject.via?.kind === 'link') return { decision: resource.type === 'request' && resource.id === subject.via.request };
    const grounds = RULES[resource.type]?.[action.name];
    if (!grounds) return { decision: false };
    const holder = resource.holder ?? (resource.type === 'principal' ? resource.id : undefined);
    if (holder === undefined) return { decision: false };
    return { decision: grounds.some(ground => ground(subject, { ...resource, holder }, this.principals))
      || this.principals.permitted(subject.id, resource.type + '.' + action.name, holder, resource.id) };
  }
}

// Every rule, flat, for whoever wants to read what is permitted.
export function rules() {
  return Object.entries(RULES).flatMap(([type, actions]) => Object.entries(actions)
    .map(([name, grounds]) => ({ resource: type, action: name, grounds: grounds.map(ground => ground === SELF ? 'self' : ground === ACTOR ? 'actor' : ground === OWNER ? 'owner' : 'line') })));
}

// Whether an action, written as type.action, is one of the rules: only these may be given.
export const isAction = name => typeof name === 'string' && rules().some(rule => rule.resource + '.' + rule.action === name);
