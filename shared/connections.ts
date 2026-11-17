import { z } from 'zod';
import { ApprovalMethod, AuthKind, AwsMethod, Id, JsonObject, MethodDefinition, OAuthMethod, OvhMethod, TokenMethod } from './contracts.js';
import type { MethodDescription } from './contracts.js';
import { Fingerprint, canonical, hash } from './authority.js';
import { connectionMethod, methodDigest, requiresApp } from './connection-methods.js';
import { decode, encode } from './encryption.js';
import { fail } from './errors.js';
import { AwsConnectionMaterial, AwsConnectionInfo } from './aws.js';
import { connectionAuthorization, connectionAccount } from './connection-authorization.js';
import { ConnectionFacts, connectionFacts } from './connection-facts.js';
import { OvhConnectionInfo } from './ovh.js';
import type { ConnectionFactValues } from './connection-facts.js';
import { documentAccount, publicConnectionFields, visibleConnectionFields } from './connection-fields.js';
export { requiresApp } from './connection-methods.js';

const Fields = z.record(z.string().max(100), z.string().max(16384));
export const AppMaterial = z.object({
  format: z.literal(1), methodId: z.string().min(1), generation: Id,
  clientId: z.string().max(1000), clientSecret: z.string().max(16384).optional(), fields: Fields,
}).strict();
export type AppState = z.infer<typeof AppMaterial>;
export const TokenMaterial = z.object({
  accessToken: z.string().min(1).max(16384), refreshToken: z.string().min(1).max(16384).optional(),
  expiresAt: z.number().nullable(), refreshExpiresAt: z.number().optional(), scopes: z.array(z.string()),
  requestedScopes: z.array(z.string()).optional(),
  account: z.string(), accountVerified: z.boolean().optional(),
  scopesStatus: z.enum(['unknown', 'requested', 'reported']).optional(), extra: Fields, facts: JsonObject,
}).strict();
// A connection as its holders use it. What is sealed of it leaves out its method: the signed metadata names the method by
// id and by the digest of its rules, and the method itself is read from where it is kept.
const materialMetadata = {
  format: z.literal(3), methodId: z.string().min(1), method: MethodDefinition, generation: Id,
  appId: Id.nullable(), appGeneration: Id.nullable(),
  state: z.literal('reconnect').optional(),
};
const unusedMaterial = z.never().optional();
export const ConnectionMaterial = z.union([
  z.object({ ...materialMetadata, method: OAuthMethod, oauth: TokenMaterial.optional(), requestedScopes: z.array(z.string()).optional(),
    implicitApp: AppMaterial.optional(),
    fields: Fields.optional(), aws: unusedMaterial }).strict(),
  z.object({ ...materialMetadata, method: TokenMethod, fields: Fields,
    facts: ConnectionFacts.optional(), oauth: unusedMaterial, aws: unusedMaterial }).strict(),
  z.object({ ...materialMetadata, method: ApprovalMethod, fields: Fields,
    oauth: unusedMaterial, aws: unusedMaterial }).strict(),
  z.object({ ...materialMetadata, method: OvhMethod, fields: Fields, ovh: OvhConnectionInfo.optional(), requestedScopes: z.array(z.string()).optional(),
    oauth: unusedMaterial, aws: unusedMaterial }).strict(),
  z.object({ ...materialMetadata, method: AwsMethod, aws: AwsConnectionMaterial,
    oauth: unusedMaterial, fields: unusedMaterial }).strict(),
]).superRefine((value, ctx) => {
  if ('implicitApp' in value && value.implicitApp &&
    (value.method.kind !== 'oauth' || value.method.config.application !== 'implicit' || value.implicitApp.methodId !== value.methodId))
    ctx.addIssue({ code: 'custom', message: 'Keep the registered client with its implicit OAuth connection.' });
  if (value.method.kind === 'oauth' && value.fields) {
    try { publicConnectionFields(value.method.config.fields, value.fields); }
    catch { ctx.addIssue({ code: 'custom', path: ['fields'], message: 'Keep only declared public settings in the connection.' }); }
  }
  if (requiresApp(value.method) && (!value.appId || !value.appGeneration))
    ctx.addIssue({ code: 'custom', message: 'Bind the application required by this connection.' });
  if (!requiresApp(value.method) && value.appId !== null)
    ctx.addIssue({ code: 'custom', message: 'Use an application only when the connection requires one.' });
  if (Boolean(value.appId) !== Boolean(value.appGeneration))
    ctx.addIssue({ code: 'custom', message: 'Bind the application and its generation together.' });
  if (value.method.kind === 'oauth' && value.method.config.grantType === 'client_credentials' &&
    !('requestedScopes' in value && value.requestedScopes) && !value.oauth?.requestedScopes)
    ctx.addIssue({ code: 'custom', message: 'Keep the selected scopes for client credentials renewal.' });
});
export type ConnectionState = z.infer<typeof ConnectionMaterial>;

export const AppMetadata = z.object({ methodId: z.string().min(1).max(200),
  clientId: z.string().max(1000), generation: Id, fields: Fields.optional() }).strict();
// Signed with the encrypted content. It names the method by id and by the digest of the method's rules; display names
// are not part of it: they travel as labels.
export const ConnectionMetadata = z.object({
  methodId: z.string().min(1).max(200), methodDigest: Fingerprint, methodKind: AuthKind,
  generation: Id, authorizationDigest: Fingerprint, appId: Id.nullable(),
  accountId: z.string().max(2000).nullable(), accountVerified: z.boolean(),
  scopes: z.array(z.string().max(1000)).max(200), scopesStatus: z.enum(['unknown', 'requested', 'reported']),
  outputs: z.array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/)).max(100), state: z.enum(['ready', 'reconnect']),
  fields: Fields.optional(),
  aws: AwsConnectionInfo.optional(),
  ovh: OvhConnectionInfo.optional(),
}).strict();

export async function connectionMetadata(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)) {
  const { outputs } = connectionMethod(state.method);
  const fields = state.method.kind !== 'aws' && state.fields ? visibleConnectionFields(state.method.config.fields, state.fields) : {};
  const authorizationDigest = await hash(connectionAuthorization(state, facts));
  return ConnectionMetadata.parse({
    methodId: state.methodId, methodDigest: await methodDigest(state.method), methodKind: state.method.kind,
    generation: state.generation, authorizationDigest, appId: state.appId,
    accountId: connectionAccount(state, facts),
    accountVerified: facts.accountVerified,
    scopes: facts.scopes, scopesStatus: facts.scopesStatus,
    outputs, state: state.state ?? 'ready',
    ...(Object.keys(fields).length ? { fields } : {}),
    ...facts.details,
  });
}

// The account a connection's sealed document names, which only its holders can read. The server stores it as given; it
// carries no authority. What a connection's method and settings are called is read from the method.
export const ConnectionLabels = z.object({ account: z.string().max(2000) }).strict();
export type ConnectionLabelValues = z.infer<typeof ConnectionLabels>;
export function connectionLabels(state: ConnectionState): ConnectionLabelValues {
  const account = state.method.kind === 'token' && state.method.config.account && state.fields
    ? documentAccount(state.method.config.account, state.fields) : '';
  return { account };
}
// The settings of a connection as people read them: its visible fields, with the labels its method gives them.
export const ConnectionSettings = z.array(z.object({ name: z.string(), label: z.string(), value: z.string() }).strict());
export function connectionSettings(method: MethodDescription, fields: Record<string, string>): z.infer<typeof ConnectionSettings> {
  const definitions = connectionMethod(method).fields;
  return definitions.filter(field => fields[field.name]).map(field => ({ name: field.name, label: field.label,
    value: field.choices?.find(choice => choice.value === fields[field.name])?.label ?? fields[field.name]! }));
}

// What is kept of a connection: everything but its method, which is read from where it is kept.
export function keptConnection(state: ConnectionState) {
  const { methodId: _methodId, method: _method, ...kept } = state;
  return JsonObject.parse(kept);
}
export const sealedConnection = (state: ConnectionState) => encode(canonical(keptConnection(state)));
// A connection kept without its method, with the method it is used with.
export function withMethod(kept: unknown, methodId: unknown, method: MethodDescription) {
  const state = kept && typeof kept === 'object' && !('methodId' in kept) && !('method' in kept)
    ? ConnectionMaterial.safeParse({ ...kept, methodId, method }) : null;
  if (!state?.success) fail(409, 'reconnect_required', 'Reconnect this service with the current connection format.');
  return state.data;
}
// A connection opened with the method its signed metadata names. Whoever uses it first checks the method's rules against
// the digest there; whoever changes it signs the method it then names.
export const openConnection = (bytes: Uint8Array, metadata: Record<string, unknown>, method: MethodDescription) =>
  withMethod(JSON.parse(decode(bytes)), metadata.methodId, method);

