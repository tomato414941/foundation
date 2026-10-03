import { fail } from '../errors.mjs';
import { inject } from './oauth.mjs';

// A token the owner made at the service and pastes here: the definition says which fields it takes and what an AI
// is handed. Foundation does not ask the service whose it is; nothing renews it, and it lasts until the owner
// replaces it here or revokes it at the service. A field is given as a value, or as a reference to a secret
// ({ reference: id }), which is resolved - and whether it may still be used, asked - every time the token is used.
export const FIELD_MAX = 8192;
const UUID = /^[0-9a-f-]{36}$/;
const invalid = label => fail(400, 'invalid_fields', `${label}を確認してください。`);
export const isReference = given => Boolean(given) && typeof given === 'object' && !Array.isArray(given) && typeof given.reference === 'string';

export function tokenScheme(definition) {
  const spec = definition.auth_schemes.token;
  // What was given, checked: each value as it will be used. References are resolved to check them, and kept as
  // references. resolve(id) is the caller's: the secret's bytes, where the owner may use them.
  const values = async (input, resolve) => {
    const given = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
    if (Object.keys(given).some(key => !spec.fields.some(field => field.name === key))) fail(400, 'invalid_fields', '入力する項目を確認してください。');
    const fields = {};
    for (const field of spec.fields) {
      const reference = isReference(given[field.name]) ? given[field.name].reference : null;
      if (reference !== null && (!UUID.test(reference) || !resolve)) invalid(field.label);
      const value = reference !== null ? await resolve(reference) : typeof given[field.name] === 'string' ? given[field.name].trim() : '';
      if (!value && field.required === false) continue;
      if (!value || value.length > FIELD_MAX || /[\x00-\x1f\x7f]/.test(value) || (field.pattern && !new RegExp(field.pattern).test(value))) invalid(field.label);
      fields[field.name] = reference !== null ? { reference } : value;
    }
    return fields;
  };
  // The fields as they are used now: each reference resolved.
  const resolved = async (fields, resolve) => Object.fromEntries(await Promise.all(Object.entries(fields).map(async ([name, given]) => [name, isReference(given) ? await resolve(given.reference) : given])));
  // What may be said of it: the fields that are not the token itself, such as the site it works on.
  const facts = fields => Object.fromEntries(spec.fields.filter(field => !field.secret && fields[field.name] !== undefined).map(field => [field.name, fields[field.name]]));
  const result = (fields, used) => ({ subject: null, privateState: { fields }, expiresAt: null, facts: facts(used),
    credentials: { environment: inject(spec.injection, used) } });
  return {
    kind: 'token', available: true, variables: Object.keys(spec.injection), fields: spec.fields, console: spec.console ?? definition.console ?? null,
    authorization: { complete: async ({ fields, resolve }) => { const kept = await values(fields, resolve); return result(kept, await resolved(kept, resolve)); } },
    obtain: async ({ privateState, resolve }) => result(privateState.fields, await resolved(privateState.fields, resolve)),
  };
}
