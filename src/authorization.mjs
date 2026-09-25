// Who may do what, answered in one place, in the AuthZEN shape: a subject, an action and a resource go in,
// a decision comes out. Routes ask this and nothing else, so the answer can later come from relations between
// principals, or from a separate decision point, without the routes changing.
//
// For now the answer is what the routes decided for themselves until today: by which door the subject came in.
//   owner   the holder, at their browser
//   linked  a product's user, handed exactly one request
//   key     an approved access key, acting for its holder
//   app     a product's own credential, holding accounts for its users
const RULES = {
  state: { read: ['owner'] },
  export: { read: ['owner'] },
  'key-request': { read: ['owner'], approve: ['owner'], deny: ['owner'] },
  key: { list: ['owner'], create: ['owner'], rename: ['owner'], revoke: ['owner'] },
  app: { list: ['owner'], register: ['owner'], remove: ['owner'] },
  connection: { list: ['owner', 'key'], create: ['owner'], remove: ['owner'] },
  usage: { read: ['owner', 'key'] },
  object: { list: ['owner', 'key'], read: ['owner', 'key'], write: ['owner', 'key'], remove: ['owner', 'key'], link: ['owner', 'key'] },
  secret: { list: ['owner', 'key'], read: ['owner', 'key'], write: ['owner', 'key'], rename: ['owner'], remove: ['owner', 'key'] },
  delivery: { create: ['key'] },
  function: { list: ['key'], invoke: ['key'] },
  request: { read: ['owner', 'linked'], done: ['owner', 'linked'], deny: ['owner', 'linked'] },
  account: { ensure: ['app'], read: ['app'], remove: ['app'], 'issue-key': ['app'], 'revoke-key': ['app'], usage: ['app'] },
  'request-link': { create: ['app'] },
};

export function allowed({ subject, action, resource }) {
  const doors = RULES[resource?.type]?.[action?.name];
  return { decision: Boolean(doors?.includes(subject?.type)) };
}

// Every rule, flat, for whoever wants to read what is permitted today.
export function rules() {
  return Object.entries(RULES).flatMap(([type, actions]) => Object.entries(actions).map(([name, doors]) => ({ resource: type, action: name, subjects: [...doors] })));
}
