import type { CatalogConnectionMethod, MethodDescription } from './contracts.js';
import { hash } from './authority.js';

export type ConnectionField = Extract<MethodDescription, { kind: 'token' }>['config']['fields'][number];
export type ConnectionFamily = MethodDescription['kind'];
export interface ConnectionMethodBehavior {
  family: ConnectionFamily;
  application: 'required' | 'implicit' | 'none';
  requiresApp: boolean;
  browserAuthorization: boolean;
  revocable: boolean;
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
        revocable: method.config.revoke?.tokenOnly === true,
        fields: method.config.fields,
        outputs: Object.keys(method.config.outputs),
      };
    case 'token':
      return { family: 'token', application: 'none', requiresApp: false, browserAuthorization: false, revocable: false,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'approval':
      return { family: 'approval', application: 'none', requiresApp: false, browserAuthorization: true, revocable: false,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'ovh': {
      const browser = method.config.authorization === 'consumer_key';
      return { family: 'ovh', application: browser ? 'required' : 'none', requiresApp: browser,
        browserAuthorization: browser, revocable: false, fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    }
    case 'aws':
      return { family: 'aws', application: 'none', requiresApp: false, browserAuthorization: false, revocable: false, fields: [],
        outputs: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION'] };
  }
}

const without = (value: object, keys: string[]) => Object.fromEntries(Object.entries(value).filter(([key]) => !keys.includes(key)));
// What a method does, without the labels people read about it: its name, explanations, links and how a person is walked
// through connecting. A connection names its method by id and by the digest of these rules, so that relabeling a method
// changes neither, while the server that hands a method over cannot change what it does.
export function methodRules(method: MethodDescription) {
  const config = method.config as { fields?: ConnectionField[]; scopes?: { values?: Array<{ id: string }> } };
  return { ...without(method, ['name', 'docs', 'console', 'preparation']), config: {
    ...without(method.config, ['hint', 'instructions', 'console']),
    ...(config.fields ? { fields: config.fields.map(field => ({ ...without(field, ['label', 'placeholder', 'note']),
      ...(field.choices ? { choices: field.choices.map(choice => without(choice, ['label'])) } : {}) })) } : {}),
    ...(config.scopes ? { scopes: { ...without(config.scopes, ['docs']),
      ...(config.scopes.values ? { values: config.scopes.values.map(value => ({ id: value.id })) } : {}) } } : {}),
  } };
}
export const methodDigest = (method: MethodDescription) => hash(methodRules(method));
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

export function browserExchange(method: MethodDescription): 'available' | 'unavailable' | 'unknown' {
  if (method.kind === 'approval') return 'unavailable';
  if (!connectionMethod(method).browserAuthorization || method.kind === 'ovh') return 'available';
  if (method.kind !== 'oauth') return 'available';
  return method.config.browserTokenExchange ?? 'unknown';
}
