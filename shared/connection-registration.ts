import { AppMaterial, ConnectionMaterial } from './connections.js';
import type { AppState, ConnectionState } from './connections.js';
import type { MethodDescription } from './contracts.js';
import { connectionFields, connectionValues, visibleConnectionFields } from './connection-fields.js';
import { connectionMethod, selectScopes } from './connection-methods.js';
import { AwsConnectionInput } from './aws.js';
import type { AwsConnectionRequest } from './aws.js';
import { OAuth, expandUrl } from './oauth.js';
import { publicUrl, responseJson } from './http.js';
import type { Transport } from './http.js';
import { ovhAccessRules } from './ovh.js';
import { z } from 'zod';

export interface RegistrationInput {
  methodId: string;
  method: MethodDescription;
  appId: string | null;
  app: AppState | null;
  fields: Record<string, string>;
  scopes: string[];
  aws?: AwsConnectionRequest;
}
export function registrationApplication(input: { methodId: string; method: MethodDescription; appId?: string; app?: AppState | null }) {
  if (connectionMethod(input.method).application === 'none') return null;
  const app = input.app ?? AppMaterial.parse({ format: 1, methodId: input.methodId, generation: crypto.randomUUID(), clientId: '', fields: {} });
  if (connectionMethod(input.method).requiresApp && (!input.appId || app.methodId !== input.methodId))
    throw new Error('Choose an application for this connection method.');
  if (input.method.kind === 'oauth' && input.method.config.clientAuth !== 'none' && !app.clientSecret ||
    input.method.kind === 'ovh' && (!app.clientId || !app.clientSecret))
    throw new Error('Enter the application client ID and secret.');
  return app;
}
export function registrationMaterial(input: RegistrationInput, previous?: ConnectionState) {
  const base = { format: 2, methodId: input.methodId, method: input.method, generation: crypto.randomUUID(),
    appId: input.appId, appGeneration: input.appId ? input.app!.generation : null };
  if (input.method.kind === 'aws') return ConnectionMaterial.parse({ ...base, aws: AwsConnectionInput.parse(input.aws) });
  if (input.method.kind === 'oauth') return ConnectionMaterial.parse({ ...base, requestedScopes: input.scopes,
    fields: visibleConnectionFields(input.method.config.fields, input.app!.fields) });
  const definitions = input.method.config.fields;
  const oldFields = Object.fromEntries(definitions.filter(field => previous?.fields?.[field.name] !== undefined)
    .map(field => [field.name, previous!.fields![field.name]!]));
  const entered = Object.fromEntries(Object.entries(input.fields).filter(([name, value]) => value !== '' ||
    definitions.find(field => field.name === name)?.secret === false || oldFields[name] === undefined));
  return ConnectionMaterial.parse({ ...base, fields: connectionFields(definitions, entered, oldFields) });
}
export const OvhAuthorization = z.object({ consumerKey: z.string().min(1).max(16384), validationUrl: z.url() });
export async function authorizeRegistration(input: RegistrationInput, transport: Transport, state: string, verifier: string, redirectUri: string) {
  if (input.method.kind === 'oauth') return { url: await new OAuth(transport).authorize(input.method.config, input.app!, state, verifier, redirectUri, input.scopes) };
  if (input.method.kind !== 'ovh' || input.method.config.authorization !== 'consumer_key')
    throw new Error('Choose a browser authorization method.');
  const redirect = new URL(redirectUri); redirect.searchParams.set('state', state);
  const url = expandUrl(input.method.config.apiBaseUrl, connectionValues(input.method.config.fields, input.app!.fields)).replace(/\/$/, '') + '/auth/credential';
  const response = await transport.send({ url, method: 'POST', headers: { 'content-type': 'application/json', 'X-Ovh-Application': input.app!.clientId },
    body: JSON.stringify({ redirection: redirect.href, accessRules: ovhAccessRules(selectScopes(input.method.config.scopes, input.scopes)) }) });
  if (response.status >= 400) throw new Error('Check the OVHcloud application key and account region.');
  const authorization = OvhAuthorization.parse(responseJson(response)), destination = publicUrl(authorization.validationUrl);
  if (!['ovh.com', 'ovhcloud.com'].some(domain => destination.hostname === domain || destination.hostname.endsWith('.' + domain)))
    throw new Error('OVHcloud returned an unexpected authorization address.');
  return { url: authorization.validationUrl, ovh: authorization };
}
export async function exchangeRegistration(input: RegistrationInput, transport: Transport, parameters: string,
  state: string, verifier: string, redirectUri: string, ovh?: z.infer<typeof OvhAuthorization>) {
  const query = new URLSearchParams(parameters);
  if (query.getAll('state').length !== 1 || query.get('state') !== state) throw new Error('The authorization response does not match this connection.');
  if (query.has('error')) throw new Error('The service authorization was cancelled.');
  const base = { format: 2, methodId: input.methodId, method: input.method, generation: crypto.randomUUID(),
    appId: input.appId, appGeneration: input.appId ? input.app!.generation : null,
    fields: visibleConnectionFields(connectionMethod(input.method).fields, input.app!.fields), requestedScopes: input.scopes };
  if (input.method.kind === 'ovh') return ConnectionMaterial.parse({ ...base, fields: { ...base.fields, consumerKey: OvhAuthorization.parse(ovh).consumerKey } });
  if (input.method.kind !== 'oauth') throw new Error('Choose a browser authorization method.');
  const oauth = await new OAuth(transport).exchange(input.method.config, input.app!, { parameters: query, state }, verifier, redirectUri, input.scopes);
  return ConnectionMaterial.parse({ ...base, oauth });
}
