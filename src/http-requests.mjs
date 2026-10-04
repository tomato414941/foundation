import { routeOf } from './request-calls.mjs';

// How often one asking may look again at what became of its request (RFC 8628 and CIBA: interval, then slow_down).
export const INTERVAL = 5;
const ID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;

// A request as anyone sees it: who asks (by name), the calls it asks for - each with what the API calls it - and where
// it is answered. The one asked by an app's user is sent to that app's own page, which knows who they are. The one
// asked also sees, for every id a call names, who or what it is to them; and, when a call keeps a sealed secret, whom
// to seal it for.
export function requestView({ requests, principals, settings, resources, recipientsOf }, row, origin, { events = false, code = false, asked = false, interval = INTERVAL } = {}) {
  const value = requests.summary(row, { includeEvents: events, includeCode: code });
  const from = principals.get(row.from_id);
  const operations = value.operations.map(call => {
    const operation = routeOf(call)?.operation;
    return { ...call, operation_id: operation?.operationId ?? null, summary: operation?.summary ?? '' };
  });
  const back = row.to_id ? settings.returnUrlFor(row.to_id) : undefined;
  const verification_uri = back ? back + (back.includes('?') ? '&' : '?') + 'foundation_request=' + row.id : origin + '/requests/' + row.id;
  let names, recipients;
  if (asked) {
    names = {};
    for (const id of new Set(JSON.stringify(value.operations).match(ID) ?? [])) {
      const principal = principals.get(id);
      if (principal) { names[id] = { type: 'principal', name: principal.name }; continue; }
      const held = resources.get(id);
      if (held && held.owner_id === row.to_id) names[id] = { type: 'resource', kind: held.kind, name: held.name };
    }
    if (row.to_id && value.operations.some(call => call.inputs?.some(input => input.kind === 'sealed'))) recipients = recipientsOf(row.to_id);
  }
  return { ...value, operations, requester_name: from?.name ?? row.requester_name, verification_uri, interval,
    ...(names ? { names } : {}), ...(recipients ? { recipients } : {}) };
}
