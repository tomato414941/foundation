import { fail } from './errors.mjs';
import { resourceName } from './resources.mjs';
import { scopeList } from './scopes.mjs';
import { SCHEMES } from './service-definition.mjs';

// What is asked, in the shape of RFC 9396 (authorization_details): a list of details, each a type and what that type
// needs. Foundation defines four types: a relation drawn to the one asking, secrets kept by the one asked, a service
// connected by them, an app registered by them. One detail per request for now.
export const TYPES = ['relation', 'secret', 'connection', 'app'];
export function requestDetails(value) {
  if (!Array.isArray(value) || value.length !== 1 || !value[0] || typeof value[0] !== 'object' || Array.isArray(value[0])) fail(400, 'invalid_authorization_details', 'authorization_details に依頼の内容を1件指定してください。');
  const { type, ...detail } = value[0];
  if (!TYPES.includes(type)) fail(400, 'invalid_authorization_details', '依頼の種類（type）を確認してください。');
  return { type, detail: requestInput(type, detail) };
}

export function requestInput(type, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_authorization_details', '依頼の内容を指定してください。');
  // Connecting: which service and by which scheme, optionally which existing connection it replaces, and the
  // service's scopes the AI needs. app: the app to connect through - one the holder may use, by id - or Foundation's
  // own when left out.
  if (type === 'connection' && Object.keys(input).every(key => ['service', 'auth_scheme', 'connection_id', 'scopes', 'app'].includes(key)) && typeof input.service === 'string'
    && (input.auth_scheme === undefined || SCHEMES.includes(input.auth_scheme))
    && (input.connection_id === undefined || (typeof input.connection_id === 'string' && /^[0-9a-f-]{36}$/.test(input.connection_id)))) {
    const scopes = scopeList(input.scopes), app = appReference(input.app);
    return { service: input.service, ...(input.auth_scheme === undefined ? {} : { auth_scheme: input.auth_scheme }), ...(input.connection_id === undefined ? {} : { connection_id: input.connection_id }),
      ...(scopes.length ? { scopes } : {}), ...(app ? { app } : {}) };
  }
  // Registering an app: the holder types its ID and secret on the request page; the asker learns only its id.
  if (type === 'app' && Object.keys(input).every(key => ['service', 'name'].includes(key)) && typeof input.service === 'string'
    && (input.name === undefined || typeof input.name === 'string')) {
    return { service: input.service, ...(input.name === undefined ? {} : { name: resourceName(input.name) }) };
  }
  // A relation drawn to the one asking: a role or one action, onto a principal or a resource. Left without an object,
  // it is onto the one who answers - how a principal nobody knows yet asks to act for someone.
  if (type === 'relation' && Object.keys(input).every(key => ['relation', 'object_type', 'object_id'].includes(key)) && typeof input.relation === 'string'
    && ((input.object_type === undefined && input.object_id === undefined)
      || (['principal', 'resource'].includes(input.object_type) && typeof input.object_id === 'string' && /^[0-9a-f-]{36}$/.test(input.object_id)))) {
    return { relation: input.relation, ...(input.object_type === undefined ? {} : { object_type: input.object_type, object_id: input.object_id }) };
  }
  if (type === 'secret' && Object.keys(input).every(key => key === 'fields')) return { fields: declarations(input.fields) };
  fail(400, 'invalid_authorization_details', '依頼の種類と内容が一致しません。');
}

export function requestResult(type, result) {
  if (type === 'connection' && typeof result?.connection_id === 'string' && result.connection_id) return { connection_id: result.connection_id };
  if (type === 'secret' && Array.isArray(result?.names) && result.names.length) return { names: result.names.map(resourceName), replaced: (result.replaced ?? []).map(resourceName) };
  if (type === 'relation' && typeof result?.relation === 'string' && ['principal', 'resource'].includes(result.object_type) && typeof result.object_id === 'string') return { relation: result.relation, object_type: result.object_type, object_id: result.object_id };
  if (type === 'app' && typeof result?.app_id === 'string' && result.app_id) return { app_id: result.app_id };
  throw new Error('The result does not match the request');
}

// What an AI asks its owner to keep as secrets. Foundation holds no knowledge of the service involved: the AI
// chooses its name and writes the instructions the owner follows.
// Some things only make sense together: an Apple key is a .p8 and three identifiers, and asking for them
// one screen at a time is four trips for the owner. So a request may declare several, and they are filled
// in and kept in one go. Foundation still knows nothing about what they are for.
export function declarations(input) {
  const many = Array.isArray(input) ? input : [input];
  if (!many.length || many.length > 8) fail(400, 'invalid_declaration', '一度に預けられるのは1〜8件です。');
  const declared = many.map(one => declaration(one));
  const names = new Set(declared.map(one => one.name));
  if (names.size !== declared.length) fail(400, 'invalid_declaration', '同じ保管先を2回指定できません。');
  return declared;
}

export function declaration(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_declaration', '保管するものの申告が必要です。');
  let site;
  if (input.site !== undefined && input.site !== '') {
    try { site = new URL(input.site); } catch { fail(400, 'invalid_site', '作成ページはhttpsのURLで指定してください。'); }
    if (site.protocol !== 'https:' || site.username || site.password || site.href.length > 300 || !site.hostname.includes('.')) fail(400, 'invalid_site', '作成ページはhttpsのURLで指定してください。');
  }
  if (typeof input.label !== 'string' || !input.label.trim() || input.label.trim().length > 60 || /[\x00-\x1f\x7f<>]/.test(input.label)) fail(400, 'invalid_label', '何を入れてもらうかを1〜60文字で指定してください。');
  if (input.multiline !== undefined && typeof input.multiline !== 'boolean') fail(400, 'invalid_declaration', '複数行かどうかは true か false で指定してください。');
  // Reading it back afterwards is asked for up front; the line is drawn when the value is kept.
  if (input.readable !== undefined && typeof input.readable !== 'boolean') fail(400, 'invalid_declaration', '読み返すかどうかは true か false で指定してください。');
  // Replacing is a property of the request, declared up front, so the owner sees it before deciding.
  if (input.replace !== undefined && typeof input.replace !== 'boolean') fail(400, 'invalid_declaration', '置き換えかどうかは true か false で指定してください。');
  return { name: resourceName(input.name), readable: input.readable === true, label: input.label.trim(), site: site?.href ?? '', multiline: input.multiline === true, replace: input.replace === true };
}

// Which app to connect through: Foundation's own ('foundation') or a held one, by id.
export function appReference(value) {
  if (value === undefined || value === null) return undefined;
  if (value === 'foundation') return value;
  if (typeof value !== 'string' || !/^[0-9a-f-]{36}$/.test(value)) fail(400, 'invalid_app', 'アプリはIDで指定してください（Foundationのアプリは foundation）。');
  return value;
}
