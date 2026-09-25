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

export function requestView({ requests, connectors, integrations }, row, origin, { events = false } = {}) {
  const value = requests.summary(row, { includeEvents: events });
  const key = requests.keyOf(row);
  const connector = value.kind === 'connect' && connectors.ids().includes(value.input.connector) ? connectors.describe(value.input.connector) : undefined;
  const back = integrations.returnUrlFor(row.owner_id);
  const verification_uri = back ? back + (back.includes('?') ? '&' : '?') + 'foundation_request=' + row.id : origin + '/requests/' + row.id;
  return { ...value, verification_uri, ...(key ? { key_name: key.name } : {}),
    // Existing clients may use the catalog description or the flat list of fields.
    ...(connector ? { connector } : {}), ...(value.kind === 'store' ? { store: value.input.fields } : {}) };
}
