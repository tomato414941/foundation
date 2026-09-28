import { fail } from './errors.mjs';

// A request is its kind and its input, and nothing else names them.
export function requestDefinition(value) {
  if (typeof value.kind !== 'string' || !value.input || typeof value.input !== 'object' || Array.isArray(value.input)) fail(400, 'nothing_requested', '依頼の種類と内容を指定してください。');
  return { kind: value.kind, input: value.input };
}

// A request as anyone sees it: who asks (by name), what for, and where it is answered. The one asked by an
// app's user is sent to that app's own page, which knows who they are.
export function requestView({ requests, services, principals, settings, credentials, apps }, row, origin, { events = false, code = false } = {}) {
  const value = requests.summary(row, { includeEvents: events, includeCode: code });
  const from = principals.get(row.from_id);
  let service;
  if (['connect', 'app'].includes(value.kind)) { try { service = services.describe(value.input.service); } catch {} }
  // The scheme a connection will be made by: the one asked for, or the service's first.
  const scheme = value.kind === 'connect' && service ? value.input.auth_scheme ?? Object.keys(service.auth_schemes)[0] : undefined;
  // The app a connection will be made through, by the name its holder gave it: the one asked for, or Foundation's.
  const app = scheme === 'oauth' && service.auth_schemes.oauth?.takes_apps ? apps.reference(value.input.app ?? 'foundation') : undefined;
  const target = service && value.input.credential_id ? credentials.held(row.to_id, value.input.credential_id) : undefined;
  const back = row.to_id ? settings.returnUrlFor(row.to_id) : undefined;
  const verification_uri = back ? back + (back.includes('?') ? '&' : '?') + 'foundation_request=' + row.id : origin + '/requests/' + row.id;
  return { ...value, requester_name: from?.name ?? value.input.name ?? '', verification_uri,
    ...(service ? { service, ...(scheme ? { auth_scheme: scheme } : {}), ...(value.input.credential_id ? { credential: target ? credentials.view(target) : null } : {}) } : {}),
    ...(app !== undefined ? { app } : {}),
    ...(value.kind === 'store' ? { store: value.input.fields } : {}) };
}
