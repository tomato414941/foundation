import { fail } from './errors.mjs';

// A request is its kind and its input, and nothing else names them.
export function requestDefinition(value) {
  if (typeof value.kind !== 'string' || !value.input || typeof value.input !== 'object' || Array.isArray(value.input)) fail(400, 'nothing_requested', '依頼の種類と内容を指定してください。');
  return { kind: value.kind, input: value.input };
}

// A request as anyone sees it: who asks (by name), what for, and where it is answered. The one asked by an
// app's user is sent to that app's own page, which knows who they are.
export function requestView({ requests, connectors, principals, settings }, row, origin, { events = false, code = false } = {}) {
  const value = requests.summary(row, { includeEvents: events, includeCode: code });
  const from = principals.get(row.from_id);
  const connector = value.kind === 'connect' && connectors.ids().includes(value.input.connector) ? connectors.describe(value.input.connector) : undefined;
  const back = row.to_id ? settings.returnUrlFor(row.to_id) : undefined;
  const verification_uri = back ? back + (back.includes('?') ? '&' : '?') + 'foundation_request=' + row.id : origin + '/requests/' + row.id;
  return { ...value, requester_name: from?.name ?? value.input.name ?? '', verification_uri,
    ...(connector ? { connector } : {}), ...(value.kind === 'store' ? { store: value.input.fields } : {}) };
}
