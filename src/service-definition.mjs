import { fail } from './errors.mjs';
import { validEnvName } from '../cli/env-name.mjs';
import { destination } from './fetch.mjs';
import { pointerTokens } from './json-pointer.mjs';
import { uriTemplate, templateVariables } from './uri-template.mjs';

// What a service is, as data: the same shape whether Foundation's catalog holds it (catalog/*.json) or a holder
// wrote it for a service the catalog does not know. Every field is read by something - the page, an AI, or the
// scheme that connects - and nothing else may be in it. The catalog alone may name code (an adapter) for a scheme
// that data cannot describe.
//
//   { id?, name, logo?, api?, docs?, console?, auth_schemes?: { oauth?, role? } }
//
// id and logo are the catalog's; a holder's service is known by its resource id. console is where an app or a
// token for the service is made. The OAuth scheme is described in schemes/oauth.mjs.
export const SCHEMES = ['oauth', 'role'];
const ID = /^[a-z][a-z0-9-]{0,39}$/, FIELD = /^[a-z][a-z0-9_]{0,39}$/;

const bad = (message, where) => { throw Object.assign(new Error(where + ': ' + message), { where }); };
const object = (value, where) => { if (!value || typeof value !== 'object' || Array.isArray(value)) bad('must be an object', where); return value; };
const only = (value, keys, where) => { for (const key of Object.keys(value)) if (!keys.includes(key)) bad('unknown field ' + key, where); };
const text = (value, where, max = 200) => { if (typeof value !== 'string' || !value || value.length > max || /[\x00-\x1f\x7f]/.test(value)) bad('must be text of 1 to ' + max, where); return value; };
const bool = (value, where) => { if (typeof value !== 'boolean') bad('must be true or false', where); };
const oneOf = (value, allowed, where) => { if (!allowed.includes(value)) bad('must be one of ' + allowed.join(', '), where); };
const pointer = (value, where) => {
  text(value, where, 500);
  try { return pointerTokens(value); } catch { bad('must be a JSON Pointer', where); }
};
const pointers = (value, where) => { const items = [].concat(value); if (!items.length) bad('must select a value', where); for (const [at, one] of items.entries()) pointer(one, where + '[' + at + ']'); };
// An address Foundation will call: an RFC 6570 template expanded from declared app or token fields. One a holder
// wrote must be a public host as well (it is checked again, resolved, whenever it is called).
let publicOnly = false;
const address = (value, where, known = []) => {
  text(value, where, 500);
  let template;
  try { template = uriTemplate(value); } catch { bad('must be a URI Template (RFC 6570)', where); }
  const variables = templateVariables(template);
  for (const name of variables) if (!known.includes(name)) bad('unknown URL variable ' + name, where);
  const values = Object.fromEntries(variables.map(name => [name, 'placeholder.example']));
  const first = template.tokens[0];
  if (first?.kind === 'expression' && first.operator === '+') for (const variable of first.vars) values[variable.name] = 'https://placeholder.example';
  const sample = template.expand(values);
  let url;
  try { url = new URL(sample); } catch { bad('must be an https URL', where); }
  if (url.protocol !== 'https:' || url.username || url.password) bad('must be an https URL', where);
  if (publicOnly) { try { destination(sample); } catch { bad('must be a public https URL', where); } }
};
const link = (value, where) => address(value, where);
const pattern = (value, where) => { text(value, where); try { new RegExp(value); } catch { bad('must be a regular expression', where); } };
const headers = (value, where) => { object(value, where); for (const [name, template] of Object.entries(value)) { if (!/^[a-z0-9-]{1,60}$/.test(name)) bad('header names are lowercase', where); text(template, where + '.' + name, 500); } };
function fields(value, where) {
  if (!Array.isArray(value) || !value.length || value.length > 8) bad('must list 1 to 8 fields', where);
  const names = new Set();
  for (const [at, field] of value.entries()) {
    const here = where + '[' + at + ']';
    object(field, here); only(field, ['name', 'label', 'required', 'placeholder', 'note', 'pattern', 'leading'], here);
    if (!FIELD.test(field.name ?? '') || names.has(field.name)) bad('needs a unique lowercase name', here);
    names.add(field.name);
    text(field.label, here + '.label', 60);
    if (field.required !== undefined) bool(field.required, here + '.required');
    if (field.leading !== undefined) bool(field.leading, here + '.leading');
    if (field.placeholder !== undefined) text(field.placeholder, here + '.placeholder');
    if (field.note !== undefined) text(field.note, here + '.note', 300);
    if (field.pattern !== undefined) pattern(field.pattern, here + '.pattern');
  }
}
function injection(value, where, known) {
  object(value, where);
  if (!Object.keys(value).length || Object.keys(value).length > 16) bad('must name 1 to 16 variables', where);
  for (const [name, source] of Object.entries(value)) {
    if (!validEnvName(name)) bad('variable names are environment variable names', where);
    const tokens = pointer(source, where + '.' + name);
    if (tokens.length !== 1 || !known.includes(tokens[0])) bad('must select a declared output value', where + '.' + name);
  }
}
function identity(value, where, { from, known }) {
  object(value, where);
  only(value, ['url', 'method', 'headers', 'json', 'token_header', 'id', 'label', 'optional', 'from', 'ok_field'], where);
  if (value.id !== undefined) pointers(value.id, where + '.id');
  if (value.label !== undefined) pointers(value.label, where + '.label');
  if (value.ok_field !== undefined) pointer(value.ok_field, where + '.ok_field');
  if (value.from !== undefined) { oneOf(value.from, from, where + '.from'); if (value.id === undefined) bad('must select an id', where + '.id'); return; }
  address(value.url, where + '.url', known);
  if (value.method !== undefined) oneOf(value.method, ['GET', 'POST'], where + '.method');
  if (value.headers !== undefined) headers(value.headers, where + '.headers');
  if (value.token_header !== undefined) text(value.token_header, where + '.token_header', 60);
  if (value.optional !== undefined) bool(value.optional, where + '.optional');
}
function scopes(value, where) {
  object(value, where); only(value, ['base', 'docs'], where);
  if (!Array.isArray(value.base) || value.base.length > 20) bad('base must list scopes', where);
  for (const scope of value.base) text(scope, where + '.base', 300);
  if (value.docs !== undefined) link(value.docs, where + '.docs');
}
function oauth(value, where, { catalog }) {
  object(value, where);
  if (value.adapter !== undefined) {
    if (!catalog) bad('only Foundation\'s catalog names adapters', where);
    only(value, ['adapter', 'hint'], where); text(value.adapter, where + '.adapter', 40);
    if (value.hint !== undefined) text(value.hint, where + '.hint', 2000);
    return;
  }
  only(value, ['authorize', 'token', 'authorize_params', 'scope_separator', 'pkce', 'client_auth', 'token_format', 'ok_field', 'keep', 'identity', 'subject_prefix',
    'revoke', 'defaults', 'scopes', 'app_fields', 'injection', 'hint'], where);
  if (value.app_fields !== undefined) fields(value.app_fields, where + '.app_fields');
  const appNames = ['client_id', ...(value.app_fields ?? []).map(field => field.name)];
  address(value.authorize, where + '.authorize', appNames); address(value.token, where + '.token', appNames);
  if (value.authorize_params !== undefined) { object(value.authorize_params, where + '.authorize_params'); for (const [key, one] of Object.entries(value.authorize_params)) text(one, where + '.authorize_params.' + key); }
  if (value.scope_separator !== undefined) oneOf(value.scope_separator, [' ', ',', '+'], where + '.scope_separator');
  if (value.pkce !== undefined) bool(value.pkce, where + '.pkce');
  if (value.client_auth !== undefined) oneOf(value.client_auth, ['basic', 'body'], where + '.client_auth');
  if (value.token_format !== undefined) oneOf(value.token_format, ['form', 'json'], where + '.token_format');
  if (value.ok_field !== undefined) pointer(value.ok_field, where + '.ok_field');
  if (value.keep !== undefined) { if (!Array.isArray(value.keep) || value.keep.length > 8) bad('must list fields', where + '.keep'); value.keep.forEach(one => { if (!FIELD.test(one)) bad('field names are lowercase', where + '.keep'); }); }
  if (value.subject_prefix !== undefined) text(value.subject_prefix, where + '.subject_prefix', 20);
  if (value.defaults !== undefined) { object(value.defaults, where + '.defaults'); for (const [key, one] of Object.entries(value.defaults)) text(one, where + '.defaults.' + key); }
  if (value.identity !== undefined) identity(value.identity, where + '.identity', { from: ['token', 'app'], known: [...appNames, 'access_token', ...(value.keep ?? [])] });
  if (value.revoke !== undefined) {
    object(value.revoke, where + '.revoke'); only(value.revoke, ['url', 'style', 'auth'], where + '.revoke');
    address(value.revoke.url, where + '.revoke.url', [...appNames, 'access_token', 'refresh_token']); oneOf(value.revoke.style, ['rfc7009', 'bearer', 'delete'], where + '.revoke.style');
    if (value.revoke.auth !== undefined) oneOf(value.revoke.auth, ['none'], where + '.revoke.auth');
  }
  if (value.scopes !== undefined) scopes(value.scopes, where + '.scopes');
  const known = ['access_token', 'account', 'expires_at', ...(value.keep ?? []), ...(value.app_fields ?? []).map(field => field.name)];
  injection(value.injection, where + '.injection', known);
  if (value.hint !== undefined) text(value.hint, where + '.hint', 2000);
}
function role(value, where, { catalog }) {
  if (!catalog) bad('only Foundation\'s catalog has role schemes', where);
  object(value, where); only(value, ['adapter', 'hint'], where); text(value.adapter, where + '.adapter', 40);
  if (value.hint !== undefined) text(value.hint, where + '.hint', 2000);
}

// Throws on anything that does not hold; the catalog's are checked at start, a holder's when written.
export function checkDefinition(value, { catalog = false } = {}) {
  publicOnly = !catalog;
  object(value, 'definition');
  only(value, ['id', 'name', 'logo', 'api', 'docs', 'console', 'auth_schemes'], 'definition');
  if (catalog) { if (!ID.test(value.id ?? '')) bad('needs an id', 'definition.id'); }
  else for (const key of ['id', 'logo']) if (value[key] !== undefined) bad('only Foundation\'s catalog has ' + key, 'definition.' + key);
  text(value.name, 'definition.name', 80);
  if (value.logo !== undefined && !/^[a-z0-9-]{1,40}$/.test(value.logo)) bad('must be a logo name', 'definition.logo');
  for (const key of ['api', 'docs', 'console']) if (value[key] !== undefined) link(value[key], 'definition.' + key);
  value = { ...value, auth_schemes: value.auth_schemes === undefined ? {} : value.auth_schemes };
  object(value.auth_schemes, 'definition.auth_schemes');
  only(value.auth_schemes, SCHEMES, 'definition.auth_schemes');
  if (value.auth_schemes.oauth !== undefined) oauth(value.auth_schemes.oauth, 'definition.auth_schemes.oauth', { catalog });
  if (value.auth_schemes.role !== undefined) role(value.auth_schemes.role, 'definition.auth_schemes.role', { catalog });
  return value;
}
// A holder's definition, checked as a request is: a refusal says where.
export function definitionInput(value) {
  try { return checkDefinition(value); }
  catch (error) { if (error.where) fail(400, 'invalid_definition', 'サービスの定義を確認してください（' + error.message + '）。', { where: error.where }); throw error; }
}
