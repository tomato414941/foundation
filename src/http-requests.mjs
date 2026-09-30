import { fail } from './errors.mjs';

// How often one asking may look again at what became of its request (RFC 8628 and CIBA: interval, then slow_down).
export const INTERVAL = 5;

// A request as anyone sees it: who asks (by name), what for, and where it is answered. The one asked by an
// app's user is sent to that app's own page, which knows who they are.
export function requestView({ requests, services, principals, settings, connections, apps, resources }, row, origin, { events = false, code = false, interval = INTERVAL } = {}) {
  const value = requests.summary(row, { includeEvents: events, includeCode: code });
  const from = principals.get(row.from_id), asked = requests.detail(row);
  let service;
  if (['connection', 'app'].includes(row.type)) { try { service = services.describe(asked.service); } catch {} }
  // The scheme a connection will be made by: the one asked for, or the service's first.
  const scheme = row.type === 'connection' && service ? asked.auth_scheme ?? Object.keys(service.auth_schemes)[0] : undefined;
  // The app a connection will be made through, by the name its holder gave it: the one asked for, or Foundation's.
  const app = scheme === 'oauth' && service.auth_schemes.oauth?.takes_apps ? apps.reference(asked.app ?? 'foundation') : undefined;
  const target = service && asked.connection_id ? connections.held(row.to_id, asked.connection_id) : undefined;
  const back = row.to_id ? settings.returnUrlFor(row.to_id) : undefined;
  const verification_uri = back ? back + (back.includes('?') ? '&' : '?') + 'foundation_request=' + row.id : origin + '/requests/' + row.id;
  // What a relation is asked onto, by the name its holder knows it by.
  let object;
  if (row.type === 'relation' && asked.object_type === 'principal') object = { type: 'principal', id: asked.object_id, name: principals.get(asked.object_id)?.name ?? '' };
  if (row.type === 'relation' && asked.object_type === 'resource') { const held = resources.get(asked.object_id); object = { type: 'resource', id: asked.object_id, kind: held?.kind ?? null, name: held?.name ?? '' }; }
  return { ...value, requester_name: from?.name ?? row.requester_name, verification_uri, interval, ...(object ? { object } : {}),
    ...(service ? { service, ...(scheme ? { auth_scheme: scheme } : {}), ...(asked.connection_id ? { connection: target ? connections.view(target) : null } : {}) } : {}),
    ...(app !== undefined ? { app } : {}),
    ...(row.type === 'secret' ? { store: asked.fields } : {}) };
}
