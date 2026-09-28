import { fail } from './errors.mjs';

// Scopes are the service's own words for what a connection may do. The holder decides which ones their AI gets:
// Foundation passes what was asked to the service's consent screen and never chooses among them. A connector names
// only the few it needs to know who authorized (its base); everything else comes from the request.
export const SCOPES_MAX = 100;
const SCOPE = /^[\x21\x23-\x5b\x5d-\x7e]{1,300}$/;

// What someone asked for: an array of the service's scope identifiers, or nothing.
export function scopeList(value) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > SCOPES_MAX || value.some(scope => typeof scope !== 'string' || !SCOPE.test(scope)))
    fail(400, 'invalid_scopes', `権限は、接続先の権限名の配列で${SCOPES_MAX}件まで指定してください。`);
  return [...new Set(value)].sort();
}

// What a connection asks the service for: its base, what it already asked for, and what is asked now.
// Reconnecting never silently drops a scope.
export function requestedScopes(connector, asked, previousState) {
  if (!connector.scopes) {
    if (asked.length) fail(400, 'scopes_unsupported', 'この接続方法では権限を指定できません。');
    return null;
  }
  const kept = previousState?.requested_scopes ?? [];
  return [...new Set([...connector.scopes.base, ...kept, ...asked])].sort();
}

// What is said about a connection's scopes: those granted (as the service reports them), those asked for, and the
// difference either way. Services may grant fewer than asked, or more.
export function scopeFacts(state) {
  const granted = state.facts?.scopes, requested = state.requested_scopes;
  if (!Array.isArray(granted) || !Array.isArray(requested)) return {};
  return { requested_scopes: requested, missing_scopes: requested.filter(scope => !granted.includes(scope)),
    additional_scopes: granted.filter(scope => !requested.includes(scope)) };
}
