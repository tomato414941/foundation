import type { MethodDescription } from './contracts.js';

export type ConnectionField = Extract<MethodDescription, { kind: 'token' }>['config']['fields'][number];
export type ConnectionFamily = 'oauth' | 'token' | 'aws';
export interface ConnectionMethodBehavior {
  family: ConnectionFamily;
  application: 'required' | 'implicit' | 'none';
  requiresApp: boolean;
  browserAuthorization: boolean;
  fields: ConnectionField[];
  outputs: string[];
}

// These capabilities are derived from the saved definition, never added to its signed representation.
export function connectionMethod(method: MethodDescription): ConnectionMethodBehavior {
  switch (method.kind) {
    case 'oauth':
      // Older OpenRouter definitions did not declare their implicit application.
      const application = method.config.application ?? (method.config.adapter === 'openrouter' ? 'implicit' : 'required');
      return {
        family: 'oauth', application, requiresApp: application === 'required',
        browserAuthorization: method.config.grantType !== 'client_credentials',
        fields: method.config.fields,
        outputs: Object.keys(method.config.outputs),
      };
    case 'token':
      return { family: 'token', application: 'none', requiresApp: false, browserAuthorization: false,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'role':
      // The wire kind stays readable by existing clients; role assumption is an AWS option.
      return { family: 'aws', application: 'none', requiresApp: false, browserAuthorization: false, fields: [],
        outputs: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION'] };
  }
}

export function selectScopes(definition: { default: string[]; required?: string[] }, selected?: string[]) {
  return [...new Set([...(definition.required ?? []), ...(selected ?? definition.default)])];
}

export function requiresApp(method: MethodDescription) {
  return connectionMethod(method).requiresApp;
}
