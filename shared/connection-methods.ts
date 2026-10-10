import type { MethodDescription } from './contracts.js';

export type ConnectionField = Extract<MethodDescription, { kind: 'token' }>['config']['fields'][number];
export interface ConnectionMethodBehavior {
  requiresApp: boolean;
  browserAuthorization: boolean;
  fields: ConnectionField[];
  outputs: string[];
}

// These capabilities are derived from the saved definition, never added to its signed representation.
export function connectionMethod(method: MethodDescription): ConnectionMethodBehavior {
  switch (method.kind) {
    case 'oauth':
      return {
        requiresApp: method.config.adapter !== 'openrouter',
        browserAuthorization: method.config.grantType !== 'client_credentials',
        fields: method.config.fields,
        outputs: Object.keys(method.config.outputs),
      };
    case 'token':
      return { requiresApp: false, browserAuthorization: false,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'role':
      return { requiresApp: false, browserAuthorization: false, fields: [],
        outputs: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION'] };
  }
}

export function requiresApp(method: MethodDescription) {
  return connectionMethod(method).requiresApp;
}
