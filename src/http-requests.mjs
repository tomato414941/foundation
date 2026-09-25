import { fail } from './errors.mjs';

// The old flat input is accepted only at the HTTP boundary. Domain code uses one shape.
export function requestDefinition(value) {
  if (value.kind !== undefined || value.input !== undefined) {
    if (value.connector !== undefined || value.store !== undefined) fail(400, 'invalid_request', '依頼の形式を一つに揃えてください。');
    return { kind: value.kind, input: value.input };
  }
  if (value.connector !== undefined && value.store !== undefined) fail(400, 'invalid_request', '接続方法と保管の申告は同時に指定できません。');
  if (value.connector !== undefined) return { kind: 'connect', input: { connector: value.connector } };
  if (value.store !== undefined) return { kind: 'store', input: { fields: value.store } };
  fail(400, 'nothing_requested', '依頼の種類と内容を指定してください。');
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
