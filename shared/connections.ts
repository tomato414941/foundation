import { z } from 'zod';
import { AuthKind, AwsMethod, Id, JsonObject, MethodDefinition, Name, OAuthMethod, TokenMethod } from './contracts.js';
import { Fingerprint, hash } from './authority.js';
import { PolicyApproval } from './custody.js';
import { connectionMethod, requiresApp } from './connection-methods.js';
import { AwsConnectionInput, AwsConnectionMaterial, AwsConnectionInfo } from './aws.js';
import { connectionAuthorization, connectionAccount } from './connection-authorization.js';
import { connectionFacts } from './connection-facts.js';
import type { ConnectionFactValues } from './connection-facts.js';
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
  account: z.string(), accountName: z.string(), accountVerified: z.boolean().optional(),
  scopesStatus: z.enum(['unknown', 'requested', 'reported']).optional(), extra: Fields, facts: JsonObject,
}).strict();
const materialMetadata = {
  format: z.literal(2), methodId: z.string().min(1), method: MethodDefinition, generation: Id,
  appId: Id.nullable(), appGeneration: Id.nullable(),
  state: z.literal('reconnect').optional(),
};
const unusedMaterial = z.never().optional();
export const ConnectionMaterial = z.union([
  z.object({ ...materialMetadata, method: OAuthMethod, oauth: TokenMaterial,
    fields: unusedMaterial, aws: unusedMaterial }).strict(),
  z.object({ ...materialMetadata, method: TokenMethod, fields: Fields,
    oauth: unusedMaterial, aws: unusedMaterial }).strict(),
  z.object({ ...materialMetadata, method: AwsMethod, aws: AwsConnectionMaterial,
    oauth: unusedMaterial, fields: unusedMaterial }).strict(),
]).superRefine((value, ctx) => {
  if (value.method.kind === 'oauth' && requiresApp(value.method) && (!value.appId || !value.appGeneration))
    ctx.addIssue({ code: 'custom', message: 'Bind the OAuth application required by this connection.' });
  if (value.method.kind !== 'oauth' && value.appId !== null)
    ctx.addIssue({ code: 'custom', message: 'Only OAuth connections use an application.' });
  if (Boolean(value.appId) !== Boolean(value.appGeneration))
    ctx.addIssue({ code: 'custom', message: 'Bind the application and its generation together.' });
  if (value.method.kind === 'oauth' && value.method.config.grantType === 'client_credentials' && !value.oauth?.requestedScopes)
    ctx.addIssue({ code: 'custom', message: 'Keep the selected scopes for client credentials renewal.' });
});
export type ConnectionState = z.infer<typeof ConnectionMaterial>;

export const AppMetadata = z.object({ methodId: z.string().min(1).max(200),
  clientId: z.string().max(1000), generation: Id }).strict();
// Signed with the encrypted content. Display names are not part of it: they travel as labels.
export const ConnectionMetadata = z.object({
  methodId: z.string().min(1).max(200), methodKind: AuthKind,
  generation: Id, authorizationDigest: Fingerprint, appId: Id.nullable(),
  accountId: z.string().max(2000).nullable(), accountVerified: z.boolean(),
  scopes: z.array(z.string().max(1000)).max(200), scopesStatus: z.enum(['unknown', 'requested', 'reported']),
  outputs: z.array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/)).max(100), state: z.enum(['ready', 'reconnect']),
  aws: AwsConnectionInfo.optional(),
}).strict();

export async function connectionMetadata(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)) {
  const outputs = connectionMethod(state.method).outputs;
  const authorizationDigest = await hash(connectionAuthorization(state, facts));
  return ConnectionMetadata.parse({
    methodId: state.methodId, methodKind: state.method.kind,
    generation: state.generation, authorizationDigest, appId: state.appId,
    accountId: connectionAccount(state, facts),
    accountVerified: facts.accountVerified,
    scopes: facts.scopes, scopesStatus: facts.scopesStatus,
    outputs, state: state.state ?? 'ready',
    ...facts.details,
  });
}

// What people read about a connection. The server stores these as given; they carry no authority.
export const ConnectionLabels = z.object({ methodName: Name, account: z.string().max(2000) }).strict();
export type ConnectionLabelValues = z.infer<typeof ConnectionLabels>;
export function connectionLabels(state: ConnectionState, facts: ConnectionFactValues = connectionFacts(state)): ConnectionLabelValues {
  return { methodName: state.method.name, account: facts.accountName };
}

const FlowStart = z.object({
  action: z.literal('start'), flowId: Id, name: Name,
  methodId: z.string().min(1), method: MethodDefinition, appId: Id.nullable(),
  fields: Fields.default({}), scopes: z.array(z.string().max(1000)).max(200).default([]),
  redirectUri: z.url().optional(),
  aws: AwsConnectionInput.optional(),
}).strict().superRefine((value, ctx) => {
  if (value.aws && value.method.kind !== 'aws')
    ctx.addIssue({ code: 'custom', message: 'Choose one authentication configuration for this connection method.' });
});
export const ConnectionAction = z.discriminatedUnion('action', [
  FlowStart,
  z.object({ action: z.literal('exchange'), flowId: Id, parameters: z.string().max(16384) }).strict(),
  z.object({ action: z.literal('commit'), flowId: Id, authorizationDigest: Fingerprint, approval: PolicyApproval }).strict(),
  z.object({ action: z.literal('refresh'), id: Id }).strict(),
  z.object({ action: z.literal('revoke'), id: Id }).strict(),
]);
export type ConnectionCommand = z.infer<typeof ConnectionAction>;
