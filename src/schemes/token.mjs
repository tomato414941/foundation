import { fail } from '../errors.mjs';
import { inject } from './oauth.mjs';

// A token the holder made at the service and pastes here: the definition says which fields it takes and what an AI
// is handed. Foundation does not ask the service whose it is; nothing renews it, and it lasts until the holder
// replaces it here or revokes it at the service.
export const FIELD_MAX = 8192;
const invalid = label => fail(400, 'invalid_fields', `${label}を確認してください。`);

export function tokenScheme(definition) {
  const spec = definition.auth_schemes.token;
  const values = input => {
    const given = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
    if (Object.keys(given).some(key => !spec.fields.some(field => field.name === key))) fail(400, 'invalid_fields', '入力する項目を確認してください。');
    const fields = {};
    for (const field of spec.fields) {
      const value = typeof given[field.name] === 'string' ? given[field.name].trim() : '';
      if (!value && field.required === false) continue;
      if (!value || value.length > FIELD_MAX || /[\x00-\x1f\x7f]/.test(value) || (field.pattern && !new RegExp(field.pattern).test(value))) invalid(field.label);
      fields[field.name] = value;
    }
    return fields;
  };
  // What may be said of it: the fields that are not the token itself, such as the site it works on.
  const facts = fields => Object.fromEntries(spec.fields.filter(field => !field.secret && fields[field.name] !== undefined).map(field => [field.name, fields[field.name]]));
  const result = fields => ({ subject: null, privateState: { fields }, expiresAt: null, facts: facts(fields),
    credentials: { environment: inject(spec.injection, fields) } });
  return {
    kind: 'token', available: true, variables: Object.keys(spec.injection), fields: spec.fields, console: spec.console ?? definition.console ?? null,
    authorization: { complete: async ({ fields }) => result(values(fields)) },
    obtain: async ({ privateState }) => result(privateState.fields),
  };
}
