// Who may do what, answered in one place, in the AuthZEN shape: a subject, an action and a resource go in,
// a decision comes out. Routes ask this and nothing else, so the answer can later come from relations between
// principals, or from a separate decision point, without the routes changing.
//
// The subject is a principal. What Foundation has not yet written down is its relations to what is held, so
// for now the answer still depends on how the principal came in (subject.via), which is what the routes
// decided by until today. That fact is temporary, and nothing else reads it.
//   session   the holder, at their browser
//   link      a product's user, handed exactly one request
//   key       an access key, acting for its holder
//   app-key   a product's own credential, holding accounts for its users
const RULES = {
  state: { read: ['session'] },
  export: { read: ['session'] },
  'key-request': { read: ['session'], approve: ['session'], deny: ['session'] },
  key: { list: ['session'], create: ['session'], rename: ['session'], revoke: ['session'] },
  app: { list: ['session'], register: ['session'], remove: ['session'] },
  connection: { list: ['session', 'key'], create: ['session'], remove: ['session'] },
  usage: { read: ['session', 'key'] },
  object: { list: ['session', 'key'], read: ['session', 'key'], write: ['session', 'key'], remove: ['session', 'key'], link: ['session', 'key'] },
  secret: { list: ['session', 'key'], read: ['session', 'key'], write: ['session', 'key'], rename: ['session'], remove: ['session', 'key'] },
  delivery: { create: ['key'] },
  function: { list: ['key'], invoke: ['key'] },
  request: { read: ['session', 'link'], done: ['session', 'link'], deny: ['session', 'link'] },
  account: { ensure: ['app-key'], read: ['app-key'], remove: ['app-key'], 'issue-key': ['app-key'], 'revoke-key': ['app-key'], usage: ['app-key'] },
  'request-link': { create: ['app-key'] },
};

export function allowed({ subject, action, resource }) {
  const ways = RULES[resource?.type]?.[action?.name];
  return { decision: subject?.type === 'principal' && Boolean(ways?.includes(subject.via)) };
}

// Every rule, flat, for whoever wants to read what is permitted today.
export function rules() {
  return Object.entries(RULES).flatMap(([type, actions]) => Object.entries(actions).map(([name, ways]) => ({ resource: type, action: name, via: [...ways] })));
}
