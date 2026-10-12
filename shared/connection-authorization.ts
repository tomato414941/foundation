import type { ConnectionState } from './connections.js';
import { connectionFacts } from './connection-facts.js';
import type { ConnectionFactValues } from './connection-facts.js';

export function connectionAccount(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)) {
  return facts.accountVerified ? facts.accountId : null;
}

export function connectionAuthorization(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)) {
  return {
    format: state.format,
    generation: state.generation, methodId: state.methodId, method: state.method,
    appId: state.appId, appGeneration: state.appGeneration,
    account: facts.accountId,
    accountVerified: facts.accountVerified,
    scopes: [...facts.scopes].sort(),
    ...(state.method.kind === 'oauth' && state.fields && Object.keys(state.fields).length ? { fields: state.fields } : {}),
    ...facts.authorization,
    ...(state.state ? { state: state.state } : {}),
  };
}
