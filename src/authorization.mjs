// Who may do what, answered in one place, in the AuthZEN shape: a subject, an action and a resource go in,
// a decision comes out. Routes ask this and nothing else.
//
// The subject is a principal and the credential it came in with. The resource is something held (with its
// holder), a principal, or a request. The answer comes from the lines between principals: the holder itself,
// whoever acts for the holder, whoever owns a principal, or a line drawn onto the thing held. A credential
// scoped to one request reaches that request and nothing else.
const SELF = (subject, resource) => subject.id === resource.holder;
const ACTOR = (subject, resource, principals) => Boolean(principals.has(subject.id, 'actor', 'principal', resource.holder));
const OWNER = (subject, resource, principals) => Boolean(principals.has(subject.id, 'owner', 'principal', resource.holder));
const LINE = relation => (subject, resource, principals) => Boolean(resource.id !== undefined && principals.has(subject.id, relation, resource.type, resource.id));
// Some things need a browser: a login session that can follow a service's consent screen and come back.
const BROWSER = ['session', 'link'];

const RULES = {
  overview: { read: [SELF] },
  export: { read: [SELF], browser: true },
  principal: {
    read: [SELF, OWNER], rename: [SELF, OWNER], remove: [OWNER], list: [SELF],
    'issue-credential': [SELF, OWNER], 'revoke-credential': [SELF, OWNER], relate: [SELF, OWNER], settings: [SELF, OWNER],
  },
  secret: { list: [SELF, ACTOR], read: [SELF, ACTOR, LINE('viewer'), LINE('editor')], write: [SELF, ACTOR, LINE('editor')], remove: [SELF, ACTOR], rename: [SELF] },
  object: { list: [SELF, ACTOR], read: [SELF, ACTOR], write: [SELF, ACTOR], remove: [SELF, ACTOR], link: [SELF, ACTOR] },
  connection: { list: [SELF, ACTOR], read: [SELF, ACTOR], create: [SELF], remove: [SELF], browser: ['create', 'remove'] },
  usage: { read: [SELF, ACTOR, OWNER] },
  delivery: { create: [SELF, ACTOR] },
  function: { list: [SELF, ACTOR], invoke: [SELF, ACTOR] },
  record: { list: [SELF] },
  request: { read: [SELF], done: [SELF], deny: [SELF], cancel: [SELF], browser: ['done', 'deny'] },
};

export class Authorization {
  constructor(principals) { this.principals = principals; }
  allowed({ subject, action, resource }) {
    if (!subject?.id || !action?.name || !resource?.type) return { decision: false };
    const scope = subject.credential?.scope;
    if (scope) return { decision: scope === 'request:' + resource.id && resource.type === 'request' };
    const rules = RULES[resource.type];
    const grounds = rules?.[action.name];
    if (!grounds) return { decision: false };
    const browserOnly = rules.browser === true || (Array.isArray(rules.browser) && rules.browser.includes(action.name));
    if (browserOnly && !BROWSER.includes(subject.credential?.kind)) return { decision: false };
    const holder = resource.holder ?? (resource.type === 'principal' ? resource.id : undefined);
    if (holder === undefined) return { decision: false };
    return { decision: grounds.some(ground => ground(subject, { ...resource, holder }, this.principals)) };
  }
}

// Every rule, flat, for whoever wants to read what is permitted.
export function rules() {
  return Object.entries(RULES).flatMap(([type, actions]) => Object.entries(actions).filter(([name]) => name !== 'browser')
    .map(([name, grounds]) => ({ resource: type, action: name, grounds: grounds.map(ground => ground === SELF ? 'self' : ground === ACTOR ? 'actor' : ground === OWNER ? 'owner' : 'line') })));
}
