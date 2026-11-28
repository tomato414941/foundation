import type { CatalogConnectionMethod, MethodDescription } from './contracts.js';

export type ConnectionField = Extract<MethodDescription, { kind: 'token' }>['config']['fields'][number];
export type ConnectionFamily = MethodDescription['kind'];
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
      const application = method.config.application;
      return {
        family: 'oauth', application, requiresApp: application === 'required',
        browserAuthorization: method.config.grantType !== 'client_credentials',
        fields: method.config.fields,
        outputs: Object.keys(method.config.outputs),
      };
    case 'token':
      return { family: 'token', application: 'none', requiresApp: false, browserAuthorization: false,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'approval':
      return { family: 'approval', application: 'none', requiresApp: false, browserAuthorization: true,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'ovh': {
      const browser = method.config.authorization === 'consumer_key';
      return { family: 'ovh', application: browser ? 'required' : 'none', requiresApp: browser,
        browserAuthorization: browser, fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    }
    case 'aws':
      return { family: 'aws', application: 'none', requiresApp: false, browserAuthorization: false, fields: [],
        outputs: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION'] };
  }
}

// A method as its catalog entry shows it, without what the catalog adds about it.
export function catalogDefinition(entry: CatalogConnectionMethod): MethodDescription {
  const { id: _id, builtin: _builtin, availability: _availability, registration: _registration, defaultName: _defaultName,
    ...definition } = entry;
  return definition;
}

export function selectScopes(definition: { default: string[]; required?: string[] }, selected?: string[]) {
  return [...new Set([...(definition.required ?? []), ...(selected ?? definition.default)])];
}

export function requiresApp(method: MethodDescription) {
  return connectionMethod(method).requiresApp;
}

export function usesClientCredentials(method: MethodDescription) {
  return method.kind === 'oauth' && method.config.grantType === 'client_credentials';
}

export function browserExchange(method: MethodDescription): 'available' | 'unavailable' | 'unknown' {
  if (method.kind === 'approval') return 'unavailable';
  if (!connectionMethod(method).browserAuthorization || method.kind === 'ovh') return 'available';
  if (method.kind !== 'oauth') return 'available';
  return method.config.browserTokenExchange ?? 'unknown';
}
