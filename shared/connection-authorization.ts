import type { ConnectionState } from './connections.js';
import { connectionFacts } from './connection-facts.js';
import type { ConnectionFactValues } from './connection-facts.js';
import { visibleConnectionFields } from './connection-fields.js';

export function connectionAccount(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)) {
  return facts.accountVerified ? facts.accountId : null;
}

export function connectionAuthorization(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)) {
  const bindsFields = state.method.kind === 'oauth' || state.method.kind === 'ovh' ||
    state.method.kind === 'token' && Boolean(state.method.config.identity || state.method.config.resolver || state.method.config.bindFields);
  const fields = bindsFields && state.method.kind !== 'aws'
    ? visibleConnectionFields(state.method.config.fields, state.fields ?? {}) : {};
  return {
    format: state.format,
    generation: state.generation, methodId: state.methodId, method: state.method,
    appId: state.appId, appGeneration: state.appGeneration,
    ...('implicitApp' in state && state.implicitApp ? { implicitApp: {
      clientId: state.implicitApp.clientId, generation: state.implicitApp.generation, fields: state.implicitApp.fields,
    } } : {}),
    account: facts.accountId,
    accountVerified: facts.accountVerified,
    scopes: [...facts.scopes].sort(),
    ...(Object.keys(fields).length ? { fields } : {}),
    ...facts.authorization,
    ...(state.state ? { state: state.state } : {}),
  };
}
